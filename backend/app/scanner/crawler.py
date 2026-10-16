"""WebSentinel same-origin asynchronous web crawler with SSRF and DNS rebinding defenses."""

from __future__ import annotations

import asyncio
from collections import deque
import ipaddress
import logging
import os
import socket
import ssl
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

logger = logging.getLogger(__name__)

DEFAULT_MAX_PAGES = int(os.getenv("WEBSENTINEL_MAX_PAGES", "10"))
DEFAULT_MAX_REQUESTS = int(os.getenv("WEBSENTINEL_MAX_REQUESTS", "15"))
DEFAULT_TIMEOUT = float(os.getenv("WEBSENTINEL_TIMEOUT", "10.0"))
DEFAULT_MAX_BODY_BYTES = int(os.getenv("WEBSENTINEL_MAX_BODY_BYTES", "1000000"))
DEFAULT_MAX_REDIRECTS = int(os.getenv("WEBSENTINEL_MAX_REDIRECTS", "5"))

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


class SSRFError(ValueError):
    """Exception raised when an endpoint targets a private, internal, or restricted destination."""


def is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Determine whether an IP address belongs to a private, loopback, or restricted space."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
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
        if parsed.port:
            netloc = f"{host}:{parsed.port}"
        else:
            netloc = host
        path = parsed.path or "/"
        return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))
    except Exception:
        return "[redacted-url]"


def extract_html_links(html_text: str, base_url: str) -> list[str]:
    """Extract and resolve navigable same-origin candidate URLs using BeautifulSoup."""
    if not html_text:
        return []

    try:
        soup = BeautifulSoup(html_text, "html.parser")
    except Exception:
        return []

    links: list[str] = []
    for tag in soup.find_all("a", href=True):
        href = tag.get("href")
        if not href or not isinstance(href, str):
            continue
        cleaned = href.strip()
        if not cleaned:
            continue
        if cleaned.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "sms:", "callto:")):
            continue

        try:
            absolute = urljoin(base_url, cleaned)
            parsed = urlsplit(absolute)
            if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
                links.append(absolute)
        except Exception:
            continue

    return links


async def fetch_page(
    client: httpx.AsyncClient,
    url: str,
    base_origin: tuple[str, str, int],
    max_body_bytes: int,
    max_redirects: int,
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
            req = client.build_request("GET", current_url)
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


async def crawl_target(
    target_url: str,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    timeout: float = DEFAULT_TIMEOUT,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> list[dict[str, Any]]:
    """
    Asynchronously crawl target_url on the same origin.

    Args:
        target_url: Seed URL to crawl.
        max_pages: Maximum number of page records to return.
        max_requests: Maximum number of HTTP requests allowed during the scan.
        timeout: Network timeout in seconds per request.
        max_body_bytes: Maximum response body size in bytes to buffer.

    Returns:
        List of crawled page records with url, status_code, headers, body,
        set_cookie_headers, and content_type.
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

    base_origin = get_origin(trimmed_target)
    start_url = normalize_url(trimmed_target)

    queue: deque[str] = deque([start_url])
    visited_urls: set[str] = set()
    results: list[dict[str, Any]] = []
    total_requests = 0

    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
    timeout_cfg = httpx.Timeout(timeout=timeout, connect=min(5.0, timeout))
    transport = SafeTransport(verify=True, limits=limits)

    async with httpx.AsyncClient(
        transport=transport,
        timeout=timeout_cfg,
        follow_redirects=False,
        headers={"User-Agent": "WebSentinel-Crawler/1.0"},
    ) as client:
        while queue and len(results) < max_pages and total_requests < max_requests:
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

            if record is None:
                continue

            results.append(record)
            if len(results) >= max_pages:
                break

            ct = record.get("content_type", "").lower()
            body_preview = record.get("body", "")[:200].lower()
            if "text/html" in ct or "xhtml" in ct or (not ct and "<html" in body_preview):
                found_links = extract_html_links(record["body"], record["url"])
                for link in found_links:
                    candidate_clean = normalize_url(link)
                    if is_same_origin(candidate_clean, base_origin):
                        if candidate_clean not in visited_urls and candidate_clean not in queue:
                            queue.append(candidate_clean)

    return results
