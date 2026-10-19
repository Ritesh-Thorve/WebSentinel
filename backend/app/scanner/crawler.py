"""WebSentinel same-origin asynchronous web crawler with SSRF and DNS rebinding defenses."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
import ipaddress
import logging
import re
import socket
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup
import httpcore

try:
    from httpcore._backends.auto import AutoBackend
except ImportError:
    try:
        from httpcore._backends.anyio import AnyIOBackend as AutoBackend  # type: ignore[no-redef]
    except ImportError:
        from httpcore import AsyncNetworkBackend as AutoBackend  # type: ignore[assignment,no-redef]

import httpx

from app.config import MAX_SCAN_REQUESTS, settings

logger = logging.getLogger(__name__)

DEFAULT_MAX_PAGES = settings.max_pages
DEFAULT_MAX_REQUESTS = settings.max_requests
DEFAULT_TIMEOUT = settings.request_timeout
DEFAULT_MAX_BODY_BYTES = settings.max_body_bytes
DEFAULT_MAX_REDIRECTS = settings.max_redirects

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "metadata.google.internal",
    "instance-data",
}

BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home.arpa",
)
NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")
JAVASCRIPT_PATH_PATTERN = re.compile(
    r"""(?P<quote>["'`])(?P<path>(?:https?:)?//[^"'`\s<>]+|(?:/|\./|\.\./)[^"'`\s<>]*)(?P=quote)""",
    re.IGNORECASE,
)


class SSRFError(ValueError):
    """Exception raised when an endpoint targets a private, internal, or restricted destination."""


class TargetUnavailableError(RuntimeError):
    """Exception raised when the submitted target returns no fetchable same-origin pages."""


@dataclass(frozen=True)
class CrawlResult:
    pages: list[dict[str, Any]]
    limit_reached: bool
    cancelled: bool = False


@dataclass(frozen=True)
class BrowserDiscoveryResult:
    urls: list[str]
    request_headers: dict[str, dict[str, str]]
    cookies: list[dict[str, Any]]
    requests_used: int
    limit_reached: bool


def is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Determine whether an IP address belongs to a private, loopback, or restricted space."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    elif isinstance(ip, ipaddress.IPv6Address) and ip in NAT64_PREFIX:
        ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if not ip.is_global:
        return True
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_url_safety(url: str) -> None:
    """Validate target URL syntax and enforce destination safety against SSRF."""
    if not isinstance(url, str):
        raise ValueError("Target URL must be a string")

    trimmed = url.strip()
    if not trimmed:
        raise ValueError("Target URL cannot be empty")

    try:
        parsed = urlsplit(trimmed)
    except Exception as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(f"Target scheme must be http or https, got '{parsed.scheme}'")

    if not parsed.netloc:
        raise ValueError("Target network location cannot be empty")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Target hostname cannot be empty")

    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValueError("Target port must be between 1 and 65535")

    lower_host = hostname.lower().strip("[]")
    if lower_host in BLOCKED_HOSTNAMES or lower_host.endswith(BLOCKED_SUFFIXES):
        raise SSRFError(f"Blocked destination: access to host '{hostname}' is restricted")

    try:
        ip = ipaddress.ip_address(lower_host)
    except ValueError:
        ip = None

    if ip is not None:
        if is_blocked_ip(ip):
            raise SSRFError(
                f"Blocked destination: access to restricted IP '{lower_host}' is not allowed"
            )
        return

    try:
        addr_infos = socket.getaddrinfo(lower_host, None)
        if not addr_infos:
            raise SSRFError(f"Blocked destination: target '{hostname}' has no address records")
        for _, _, _, _, sockaddr in addr_infos:
            ip_str = sockaddr[0]
            try:
                resolved_ip = ipaddress.ip_address(ip_str)
            except ValueError:
                raise SSRFError(
                    f"Blocked destination: target '{hostname}' resolved to invalid IP '{ip_str}'"
                )
            if is_blocked_ip(resolved_ip):
                raise SSRFError(
                    f"Blocked destination: target '{hostname}' resolves to restricted IP '{ip_str}'"
                )
    except socket.gaierror:
        # Handled as connection failure at connection time
        pass


class SafeNetworkBackend(AutoBackend):
    """Network backend that resolves DNS, validates IP addresses, and pins connections to prevent DNS rebinding."""

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        lower_host = host.lower().strip("[]")
        if lower_host in BLOCKED_HOSTNAMES or lower_host.endswith(BLOCKED_SUFFIXES):
            raise SSRFError(f"Blocked destination: access to host '{host}' is restricted")

        try:
            ip = ipaddress.ip_address(lower_host)
        except ValueError:
            ip = None

        if ip is not None:
            if is_blocked_ip(ip):
                raise SSRFError(
                    f"Blocked destination: access to restricted IP '{lower_host}' is not allowed"
                )
            candidate_ips = [str(ip)]
        else:
            loop = asyncio.get_running_loop()
            try:
                addr_infos = await loop.getaddrinfo(lower_host, port, type=socket.SOCK_STREAM)
            except socket.gaierror as exc:
                raise httpcore.ConnectError(f"DNS resolution failed for '{host}'") from exc

            if not addr_infos:
                raise httpcore.ConnectError(f"DNS resolution returned no addresses for '{host}'")

            candidate_ips = []
            for _, _, _, _, sockaddr in addr_infos:
                ip_str = sockaddr[0]
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                except ValueError:
                    raise SSRFError(f"Blocked destination: invalid resolved IP '{ip_str}'")

                if is_blocked_ip(ip_obj):
                    raise SSRFError(
                        f"Blocked destination: target '{host}' resolves to restricted IP '{ip_str}'"
                    )
                if ip_str not in candidate_ips:
                    candidate_ips.append(ip_str)

        if not candidate_ips:
            raise SSRFError(f"No valid public IP addresses found for '{host}'")

        last_exc: Exception | None = None
        for target_ip in candidate_ips:
            try:
                return await super().connect_tcp(
                    host=target_ip,
                    port=port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:
                if isinstance(exc, SSRFError):
                    raise
                last_exc = exc

        if last_exc:
            raise last_exc
        raise httpcore.ConnectError(f"Could not connect to '{host}:{port}'")


class SafeTransport(httpx.AsyncHTTPTransport):
    """Transport enforcing strictly verified TLS and pinned safe network connections."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["verify"] = kwargs.get("verify", True)
        if kwargs["verify"] is False:
            raise ValueError("TLS certificate verification must not be disabled")
        super().__init__(*args, **kwargs)
        if hasattr(self, "_pool"):
            self._pool._network_backend = SafeNetworkBackend()


def get_origin(url: str) -> tuple[str, str, int]:
    """Extract (scheme, host, port) origin triple from a URL."""
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    return (scheme, host, port)


def is_same_origin(url: str, base_origin: tuple[str, str, int]) -> bool:
    """Check if a URL matches the base origin."""
    try:
        return get_origin(url) == base_origin
    except Exception:
        return False


def is_http_to_https_upgrade(
    from_url: str, to_url: str, base_origin: tuple[str, str, int]
) -> bool:
    """Allow same-host HTTP to HTTPS upgrade on standard ports."""
    try:
        from_orig = get_origin(from_url)
        to_orig = get_origin(to_url)
        if from_orig[1] == to_orig[1] == base_origin[1]:
            if from_orig[0] == "http" and to_orig[0] == "https":
                if from_orig[2] in (80, 443) and to_orig[2] in (80, 443):
                    return True
        return False
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """Normalize URL by lowercasing host, stripping fragments and default ports."""
    try:
        parsed = urlsplit(url.strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port

        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = host
        elif port is not None:
            netloc = f"{host}:{port}"
        else:
            netloc = host

        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path, parsed.query, ""))
    except Exception:
        return url.strip()


def sanitize_url_for_logging(url: str) -> str:
    """Remove sensitive query parameters, userinfo, and fragments before logging."""
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        if ":" in host:
            host = f"[{host}]"
        if parsed.port:
            netloc = f"{host}:{parsed.port}"
        else:
            netloc = host
        path = parsed.path or "/"
        return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))
    except Exception:
        return "[redacted-url]"


def extract_html_links(html_text: str, base_url: str) -> list[str]:
    """Extract page links and same-origin JavaScript resources using BeautifulSoup."""
    if not html_text:
        return []

    try:
        soup = BeautifulSoup(html_text, "html.parser")
    except Exception:
        return []

    links: list[str] = []
    tag_attributes = [(tag, "href") for tag in soup.find_all("a", href=True)]
    tag_attributes.extend((tag, "src") for tag in soup.find_all("script", src=True))
    for tag, attribute in tag_attributes:
        value = tag.get(attribute)
        if not value or not isinstance(value, str):
            continue
        cleaned = value.strip()
        if not cleaned or cleaned.startswith(
            ("#", "javascript:", "mailto:", "tel:", "data:", "sms:", "callto:")
        ):
            continue

        try:
            absolute = urljoin(base_url, cleaned)
            parsed = urlsplit(absolute)
            if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
                links.append(absolute)
        except Exception:
            continue

    return links


def extract_javascript_links(javascript: str, base_url: str) -> list[str]:
    """Extract static URL and route references from JavaScript source."""
    links: list[str] = []
    for match in JAVASCRIPT_PATH_PATTERN.finditer(javascript):
        path = match.group("path")
        if "${" in path or any(character in path for character in "[]()*|\\$"):
            continue
        try:
            absolute = urljoin(base_url, path)
            parsed = urlsplit(absolute)
            has_parameter_segment = any(
                segment.startswith(":") for segment in parsed.path.split("/")
            )
            if (
                parsed.scheme.lower() in {"http", "https"}
                and parsed.hostname
                and not has_parameter_segment
            ):
                links.append(absolute)
        except Exception:
            continue
    return links


def extract_sitemap_links(xml_text: str, base_url: str) -> list[str]:
    """Extract sitemap URL locations, including child sitemap locations."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    links: list[str] = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1].lower() != "loc" or not element.text:
            continue
        candidate = element.text.strip()
        if candidate:
            links.append(urljoin(base_url, candidate))
    return links


def extract_robots_sitemaps(robots_text: str, base_url: str) -> list[str]:
    """Extract sitemap locations advertised in robots.txt."""
    links: list[str] = []
    for line in robots_text.splitlines():
        name, separator, value = line.partition(":")
        if separator and name.strip().lower() == "sitemap" and value.strip():
            links.append(urljoin(base_url, value.strip()))
    return links


async def fetch_page(
    client: httpx.AsyncClient,
    url: str,
    base_origin: tuple[str, str, int],
    max_body_bytes: int,
    max_redirects: int,
    request_headers: dict[str, str] | None = None,
) -> tuple[dict[str, Any] | None, int, tuple[str, str, int]]:
    """
    Fetch a single URL following same-origin redirects with SSRF/DNS rebinding validation.

    Returns:
        (page_record, requests_made, updated_base_origin)
    """
    current_url = url
    requests_made = 0
    redirect_chain: list[str] = []
    accumulated_cookies: list[str] = []

    while True:
        if requests_made >= max_redirects + 1:
            break

        validate_url_safety(current_url)

        if not is_same_origin(current_url, base_origin):
            return None, requests_made, base_origin

        requests_made += 1
        redirect_chain.append(current_url)

        try:
            safe_headers = {
                name: value
                for name, value in (request_headers or {}).items()
                if name.lower()
                in {"authorization", "cookie", "x-api-key", "x-csrf-token", "x-xsrf-token"}
            }
            req = client.build_request("GET", current_url, headers=safe_headers or None)
            response = await client.send(req, stream=True)
        except SSRFError:
            raise
        except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError, httpx.HTTPError, OSError) as exc:
            logger.warning(
                "Request failed for %s: %s",
                sanitize_url_for_logging(current_url),
                type(exc).__name__,
            )
            return None, requests_made, base_origin

        try:
            chunks: list[bytes] = []
            bytes_read = 0
            async for chunk in response.aiter_bytes():
                remaining = max_body_bytes - bytes_read
                if remaining <= 0:
                    break
                chunks.append(chunk[:remaining])
                bytes_read += len(chunk[:remaining])
                if bytes_read >= max_body_bytes:
                    break
            raw_body = b"".join(chunks)
        except Exception as exc:
            logger.warning(
                "Error reading response body from %s: %s",
                sanitize_url_for_logging(current_url),
                type(exc).__name__,
            )
            raw_body = b""
        finally:
            await response.aclose()

        hop_cookies = response.headers.get_list("set-cookie")
        accumulated_cookies.extend(hop_cookies)

        encoding = response.encoding or "utf-8"
        try:
            body_text = raw_body.decode(encoding, errors="replace")
        except Exception:
            body_text = raw_body.decode("utf-8", errors="replace")
        body_text = body_text[:max_body_bytes]

        normalized_headers = {k.lower(): str(v) for k, v in response.headers.items()}
        content_type = normalized_headers.get("content-type", "")

        if response.status_code in {301, 302, 303, 307, 308} and "location" in normalized_headers:
            loc = normalized_headers["location"].strip()
            if not loc:
                return {
                    "url": current_url,
                    "status_code": response.status_code,
                    "headers": normalized_headers,
                    "body": body_text,
                    "set_cookie_headers": accumulated_cookies,
                    "content_type": content_type,
                }, requests_made, base_origin

            next_url = urljoin(current_url, loc)

            validate_url_safety(next_url)

            if is_http_to_https_upgrade(current_url, next_url, base_origin):
                base_origin = get_origin(next_url)
            elif not is_same_origin(next_url, base_origin):
                return {
                    "url": current_url,
                    "status_code": response.status_code,
                    "headers": normalized_headers,
                    "body": body_text,
                    "set_cookie_headers": accumulated_cookies,
                    "content_type": content_type,
                }, requests_made, base_origin

            if next_url in redirect_chain:
                logger.warning(
                    "Redirect loop detected for %s",
                    sanitize_url_for_logging(next_url),
                )
                return {
                    "url": current_url,
                    "status_code": response.status_code,
                    "headers": normalized_headers,
                    "body": body_text,
                    "set_cookie_headers": accumulated_cookies,
                    "content_type": content_type,
                }, requests_made, base_origin

            current_url = next_url
            continue

        return {
            "url": current_url,
            "status_code": response.status_code,
            "headers": normalized_headers,
            "body": body_text,
            "set_cookie_headers": accumulated_cookies,
            "content_type": content_type,
        }, requests_made, base_origin


async def discover_browser_routes(
    target_url: str,
    base_origin: tuple[str, str, int],
    max_pages: int,
    max_requests: int,
    timeout: float,
    cancel_event: asyncio.Event | None = None,
) -> BrowserDiscoveryResult:
    """Render same-origin pages to discover JavaScript-generated routes and session state."""
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright

    from app.browser_session import chromium_executable, storage_state_path

    state_path = storage_state_path(target_url)
    if not state_path.exists():
        logger.info("No saved browser session for target origin; scanning public routes.")

    host = urlsplit(target_url).hostname
    if not host:
        raise ValueError("Target hostname cannot be empty")
    try:
        target_ip = ipaddress.ip_address(host)
    except ValueError:
        target_ip = None
    if target_ip is not None:
        if is_blocked_ip(target_ip):
            raise SSRFError(f"Blocked destination: access to restricted IP '{host}' is not allowed")
        host_resolver_rule = None
    else:
        ascii_host = host.encode("idna").decode("ascii").lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9.-]+", ascii_host):
            raise ValueError("Target hostname contains characters unsafe for browser resolution")
        try:
            address_infos = socket.getaddrinfo(
                ascii_host,
                base_origin[2],
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise SSRFError(f"Could not safely resolve target hostname '{host}'") from exc
        resolved_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for address_info in address_infos:
            try:
                resolved_address = ipaddress.ip_address(address_info[4][0])
            except ValueError as exc:
                raise SSRFError(f"Target hostname '{host}' resolved to an invalid IP") from exc
            if is_blocked_ip(resolved_address):
                raise SSRFError(
                    f"Blocked destination: target '{host}' resolved to restricted IP "
                    f"'{resolved_address}'"
                )
            if resolved_address not in resolved_addresses:
                resolved_addresses.append(resolved_address)
        if not resolved_addresses:
            raise SSRFError(f"Target hostname '{host}' has no public address records")
        selected_address = resolved_addresses[0]
        address_text = (
            f"[{selected_address}]" if isinstance(selected_address, ipaddress.IPv6Address)
            else str(selected_address)
        )
        host_resolver_rule = (
            f"--host-resolver-rules=MAP {ascii_host} {address_text}"
        )

    browser_urls: set[str] = set()
    request_headers: dict[str, dict[str, str]] = {}
    queued_urls: set[str] = set()
    queue: deque[str] = deque([normalize_url(target_url)])
    request_count = 0
    budget_reached = False
    current_url = normalize_url(target_url)
    origin_url = f"{base_origin[0]}://{base_origin[1]}"

    async with async_playwright() as playwright:
        launch_options: dict[str, Any] = {"headless": True}
        executable = chromium_executable()
        if executable:
            launch_options["executable_path"] = executable
        if host_resolver_rule:
            launch_options["args"] = [host_resolver_rule]
        browser = await playwright.chromium.launch(**launch_options)
        context = None
        cookies: list[dict[str, Any]] = []
        try:
            context_options: dict[str, Any] = {}
            if state_path.exists():
                context_options["storage_state"] = str(state_path)
            context_options["service_workers"] = "block"
            context = await browser.new_context(**context_options)
            page = await context.new_page()

            async def block_websocket(websocket: Any) -> None:
                await websocket.close()

            async def guard_request(route: Any) -> None:
                nonlocal request_count, budget_reached
                request = route.request
                if request_count >= max_requests:
                    budget_reached = True
                    await route.abort()
                    return
                request_count += 1
                if request.method not in {"GET", "HEAD"} or not is_same_origin(request.url, base_origin):
                    await route.abort()
                    return
                try:
                    validate_url_safety(request.url)
                except ValueError:
                    await route.abort()
                    return
                safe_headers = {
                    name: value
                    for name, value in (await request.all_headers()).items()
                    if name.lower()
                    in {"authorization", "cookie", "x-api-key", "x-csrf-token", "x-xsrf-token"}
                }
                request_headers[normalize_url(request.url)] = safe_headers
                browser_urls.add(normalize_url(request.url))
                await route.continue_()

            await context.route("**/*", guard_request)
            await context.route_web_socket("**/*", block_websocket)

            def enqueue(candidates: list[str]) -> None:
                for candidate in candidates:
                    clean_url = normalize_url(candidate)
                    if (
                        is_same_origin(clean_url, base_origin)
                        and clean_url not in browser_urls
                        and clean_url not in queued_urls
                        and len(queued_urls) < max_pages
                    ):
                        queue.append(clean_url)
                        queued_urls.add(clean_url)

            while (
                queue
                and len(browser_urls) < max_pages
                and request_count < max_requests
                and not (cancel_event and cancel_event.is_set())
            ):
                current_url = queue.popleft()
                if current_url in browser_urls:
                    continue
                try:
                    await page.goto(
                        current_url,
                        wait_until="domcontentloaded",
                        timeout=max(1000, int(timeout * 1000)),
                    )
                    try:
                        await page.wait_for_load_state(
                            "networkidle",
                            timeout=min(2000, max(500, int(timeout * 1000))),
                        )
                    except PlaywrightTimeoutError:
                        logger.debug(
                            "Dynamic page remained active: %s",
                            sanitize_url_for_logging(current_url),
                        )
                    discovered = await page.locator(
                        "a[href], area[href], form[action], iframe[src]"
                    ).evaluate_all(
                        """elements => elements.flatMap(element => {
                          const tag = element.tagName.toLowerCase();
                          if (tag === 'form' && (element.method || 'get').toLowerCase() !== 'get') return [];
                          return [tag === 'form' ? element.action : element.href || element.src];
                        })"""
                    )
                except PlaywrightTimeoutError:
                    logger.warning(
                        "Browser discovery timed out for %s",
                        sanitize_url_for_logging(current_url),
                    )
                    continue
                except PlaywrightError as exc:
                    logger.warning(
                        "Browser discovery failed for %s: %s",
                        sanitize_url_for_logging(current_url),
                        type(exc).__name__,
                    )
                    continue
                enqueue([url for url in discovered if isinstance(url, str)])
                if budget_reached:
                    break
            if queue and (
                request_count >= max_requests or len(browser_urls) >= max_pages
            ):
                budget_reached = True
        finally:
            try:
                if context is not None:
                    cookies = await context.cookies(origin_url)
            finally:
                await browser.close()

    return BrowserDiscoveryResult(
        urls=sorted(browser_urls),
        request_headers=request_headers,
        cookies=cookies,
        requests_used=request_count,
        limit_reached=budget_reached,
    )


async def crawl_target(
    target_url: str,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    timeout: float = DEFAULT_TIMEOUT,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    cancel_event: asyncio.Event | None = None,
) -> CrawlResult:
    """
    Asynchronously crawl target_url on the same origin.

    Args:
        target_url: Seed URL to crawl.
        max_pages: Maximum number of page records to return.
        max_requests: Maximum number of HTTP requests allowed during the scan.
        timeout: Network timeout in seconds per request.
        max_body_bytes: Maximum response body size in bytes to buffer.

    Returns:
        CrawlResult with fetched page records and whether a crawl limit was reached.
    """
    if not isinstance(target_url, str):
        raise ValueError("Target URL must be a string")

    trimmed_target = target_url.strip()
    if not trimmed_target:
        raise ValueError("Target URL cannot be empty")

    parsed = urlsplit(trimmed_target)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(f"Target scheme must be http or https, got '{parsed.scheme}'")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("Target network location cannot be empty")
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValueError("Target port must be between 1 and 65535")

    validate_url_safety(trimmed_target)
    max_pages = min(max(1, max_pages), MAX_SCAN_REQUESTS)
    max_requests = min(max(1, max_requests), MAX_SCAN_REQUESTS)

    base_origin = get_origin(trimmed_target)
    start_url = normalize_url(trimmed_target)
    browser_result = await discover_browser_routes(
        target_url=trimmed_target,
        base_origin=base_origin,
        max_pages=max_pages,
        max_requests=max_requests // 2,
        timeout=timeout,
        cancel_event=cancel_event,
    )

    queue: deque[str] = deque([start_url])
    queued_urls = {start_url}
    visited_urls: set[str] = set()
    results: list[dict[str, Any]] = []
    total_requests = browser_result.requests_used
    crawl_limit_reached = browser_result.limit_reached

    def enqueue_browser_urls() -> None:
        nonlocal crawl_limit_reached
        for candidate in browser_result.urls:
            clean_candidate = normalize_url(candidate)
            if (
                is_same_origin(clean_candidate, base_origin)
                and clean_candidate not in visited_urls
                and clean_candidate not in queued_urls
            ):
                if total_requests + len(queue) >= max_requests:
                    crawl_limit_reached = True
                    return
                queue.append(clean_candidate)
                queued_urls.add(clean_candidate)

    def enqueue_candidates(candidates: list[str]) -> None:
        nonlocal crawl_limit_reached
        for candidate in candidates:
            clean_candidate = normalize_url(candidate)
            if (
                is_same_origin(clean_candidate, base_origin)
                and clean_candidate not in visited_urls
                and clean_candidate not in queued_urls
            ):
                if total_requests + len(queue) >= max_requests:
                    crawl_limit_reached = True
                    break
                queue.append(clean_candidate)
                queued_urls.add(clean_candidate)

    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
    timeout_cfg = httpx.Timeout(timeout=timeout, connect=min(5.0, timeout))
    transport = SafeTransport(verify=True, limits=limits)
    cancelled_fetch_attempted = False
    browser_cookies = httpx.Cookies()
    for cookie in browser_result.cookies:
        if isinstance(cookie.get("name"), str) and isinstance(cookie.get("value"), str):
            browser_cookies.set(
                cookie["name"],
                cookie["value"],
                domain=cookie.get("domain"),
                path=cookie.get("path", "/"),
            )

    async with httpx.AsyncClient(
        transport=transport,
        timeout=timeout_cfg,
        follow_redirects=False,
        headers={"User-Agent": "WebSentinel-Crawler/1.0"},
        cookies=browser_cookies,
    ) as client:
        enqueue_browser_urls()
        enqueue_candidates(
            [
                urljoin(start_url, "/robots.txt"),
                urljoin(start_url, "/sitemap.xml"),
            ]
        )
        while (
            queue
            and len(results) < max_pages
            and total_requests < max_requests
            and not (
                cancel_event
                and cancel_event.is_set()
                and cancelled_fetch_attempted
            )
        ):
            url_to_crawl = queue.popleft()
            clean_url = normalize_url(url_to_crawl)

            if clean_url in visited_urls:
                continue
            visited_urls.add(clean_url)

            remaining_requests = max_requests - total_requests
            if remaining_requests <= 0:
                break

            max_hop_redirects = min(DEFAULT_MAX_REDIRECTS, remaining_requests - 1)
            if max_hop_redirects < 0:
                max_hop_redirects = 0

            try:
                record, reqs_used, base_origin = await fetch_page(
                    client=client,
                    url=clean_url,
                    base_origin=base_origin,
                    max_body_bytes=max_body_bytes,
                    max_redirects=max_hop_redirects,
                    request_headers=browser_result.request_headers.get(clean_url),
                )
            except SSRFError:
                raise
            except Exception as exc:
                logger.warning(
                    "Encountered unexpected error crawling %s: %s",
                    sanitize_url_for_logging(clean_url),
                    type(exc).__name__,
                )
                continue

            total_requests += reqs_used
            if cancel_event and cancel_event.is_set():
                cancelled_fetch_attempted = True

            if record is None:
                continue

            results.append(record)
            if cancel_event and cancel_event.is_set():
                break

            ct = record.get("content_type", "").lower()
            body = record.get("body", "")
            body_preview = body[:200].lower()
            current_path = urlsplit(record["url"]).path.lower()
            candidates: list[str] = []
            if "text/html" in ct or "xhtml" in ct or (not ct and "<html" in body_preview):
                candidates.extend(extract_html_links(body, record["url"]))
                soup = BeautifulSoup(body, "html.parser")
                for script in soup.find_all("script"):
                    if script.string:
                        candidates.extend(extract_javascript_links(script.string, record["url"]))
            if (
                "javascript" in ct
                or current_path.endswith((".js", ".mjs"))
            ):
                candidates.extend(extract_javascript_links(body, record["url"]))
            if current_path.endswith("/robots.txt") or current_path == "robots.txt":
                candidates.extend(extract_robots_sitemaps(body, record["url"]))
            if (
                "xml" in ct
                or "sitemap" in current_path
                or body.lstrip().lower().startswith(("<?xml", "<urlset", "<sitemapindex"))
            ):
                candidates.extend(extract_sitemap_links(body, record["url"]))
            enqueue_candidates(candidates)

    if not results:
        if cancel_event and cancel_event.is_set():
            return CrawlResult(pages=[], limit_reached=False, cancelled=True)
        raise TargetUnavailableError("No pages could be fetched from the supplied target.")
    cancelled = bool(cancel_event and cancel_event.is_set())
    return CrawlResult(
        pages=results,
        limit_reached=(
            False
            if cancelled
            else crawl_limit_reached
            or (bool(queue) and (len(results) >= max_pages or total_requests >= max_requests))
        ),
        cancelled=cancelled,
    )
