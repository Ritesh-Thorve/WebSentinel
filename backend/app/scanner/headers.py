"""HTTP defensive header security scanner for WebSentinel."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

VALID_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}

NON_HTML_CONTENT_PREFIXES = (
    "image/",
    "video/",
    "audio/",
    "font/",
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/json",
    "application/pdf",
    "application/zip",
    "application/octet-stream",
    "application/xml",
)


def _is_html_response(content_type: str, body: str) -> bool:
    """Determine whether the response content represents an HTML document."""
    ct = content_type.lower().strip()
    if ct:
        if "text/html" in ct or "application/xhtml+xml" in ct:
            return True
        if any(ct.startswith(prefix) for prefix in NON_HTML_CONTENT_PREFIXES):
            return False

    if body:
        lower_body = body[:500].lower()
        if "<html" in lower_body or "<!doctype html" in lower_body or "<body" in lower_body:
            return True

    return True


def _parse_csp_directives(csp_value: str) -> dict[str, list[str]]:
    """Parse Content-Security-Policy string into directive names and token values."""
    directives: dict[str, list[str]] = {}
    for part in csp_value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        dir_name = tokens[0].lower()
        dir_values = [v.strip().lower() for v in tokens[1:]]
        directives[dir_name] = dir_values
    return directives


def _parse_hsts_max_age(hsts_value: str) -> int | None:
    """Extract max-age integer from Strict-Transport-Security header value."""
    for part in hsts_value.split(";"):
        cleaned = part.strip()
        if cleaned.lower().startswith("max-age="):
            val_str = cleaned.split("=", 1)[1].strip()
            try:
                return int(val_str)
            except ValueError:
                return -1
    return None


def _evaluate_referrer_policy(ref_value: str) -> str:
    """Evaluate effective Referrer-Policy according to W3C fallback rules."""
    tokens = [t.strip().lower() for t in ref_value.split(",") if t.strip()]
    if not tokens:
        return "empty"
    for token in reversed(tokens):
        if token in VALID_REFERRER_POLICIES:
            return token
    return "invalid"


def _build_finding(
    title: str,
    severity: str,
    affected_url: str,
    description: str,
    evidence: str,
    recommendation: str,
    confidence: str,
) -> dict[str, str]:
    """Construct a finding dictionary strictly matching the Finding schema."""
    return {
        "title": title,
        "severity": severity,
        "affected_url": affected_url,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "confidence": confidence,
    }


def check_headers(pages: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Inspect HTTP response headers of crawled pages for defensive security headers.

    Inspects Content-Security-Policy, Strict-Transport-Security on HTTPS,
    X-Content-Type-Options, and appropriate Referrer-Policy.

    Args:
        pages: List of crawled page dictionaries containing 'url', 'headers',
               and optional 'status_code', 'content_type', or 'body'.

    Returns:
        List of findings formatted with exact field names matching app.schemas.Finding.
    """
    if not isinstance(pages, list):
        return []

    findings: list[dict[str, str]] = []
    seen_issues: set[tuple[str, str]] = set()

    for page in pages:
        if not isinstance(page, dict):
            continue

        raw_url = str(page.get("url") or page.get("affected_url") or "").strip()
        parsed_url = urlsplit(raw_url)
        scheme = parsed_url.scheme.lower()
        host = parsed_url.netloc.lower() or "default"

        raw_headers = page.get("headers")
        if isinstance(raw_headers, dict):
            norm_headers = {
                str(k).lower().strip(): str(v).strip()
                for k, v in raw_headers.items()
            }
        else:
            norm_headers = {}

        raw_body = str(page.get("body") or "")
        content_type = str(
            page.get("content_type")
            or norm_headers.get("content-type")
            or ""
        )
        status_code = page.get("status_code")

        if isinstance(status_code, int) and status_code in {204, 304}:
            continue

        is_html = _is_html_response(content_type, raw_body)

        page_findings: list[dict[str, str]] = []

        # 1. Content-Security-Policy
        if is_html:
            csp_val = norm_headers.get("content-security-policy")
            if not csp_val:
                page_findings.append(
                    _build_finding(
                        title="Missing Content-Security-Policy Header",
                        severity="low",
                        affected_url=raw_url,
                        description=(
                            "The response does not include a Content-Security-Policy (CSP) header. "
                            "A properly configured CSP helps mitigate Cross-Site Scripting (XSS) "
                            "and unauthorized data injection by restricting content sources."
                        ),
                        evidence="Content-Security-Policy header is absent",
                        recommendation=(
                            "Implement a Content-Security-Policy header defining trusted sources for scripts, "
                            "styles, frames, and objects (e.g., \"default-src 'self'\")."
                        ),
                        confidence="high",
                    )
                )
            else:
                directives = _parse_csp_directives(csp_val)
                script_sources = directives.get("script-src") or directives.get("default-src")

                if script_sources is None:
                    page_findings.append(
                        _build_finding(
                            title="Content-Security-Policy Missing Script Directives",
                            severity="low",
                            affected_url=raw_url,
                            description=(
                                "The Content-Security-Policy does not specify 'script-src' or 'default-src', "
                                "leaving executable script sources unrestricted."
                            ),
                            evidence="CSP lacks script-src and default-src directives",
                            recommendation=(
                                "Add a restrictive 'script-src' or 'default-src' directive to the CSP."
                            ),
                            confidence="high",
                        )
                    )
                else:
                    has_nonce_or_hash = any(
                        token.startswith(
                            (
                                "'nonce-",
                                "\"nonce-",
                                "'sha256-",
                                "\"sha256-",
                                "'sha384-",
                                "\"sha384-",
                                "'sha512-",
                                "\"sha512-",
                            )
                        )
                        for token in script_sources
                    )
                    has_unsafe_inline = any(
                        token in ("'unsafe-inline'", "\"unsafe-inline\"", "unsafe-inline")
                        for token in script_sources
                    )
                    if has_unsafe_inline and not has_nonce_or_hash:
                        page_findings.append(
                            _build_finding(
                                title="Content-Security-Policy Allows 'unsafe-inline' Scripts",
                                severity="low",
                                affected_url=raw_url,
                                description=(
                                    "The Content-Security-Policy includes 'unsafe-inline' without cryptographic "
                                    "nonces or hashes, significantly weakening protection against Cross-Site Scripting."
                                ),
                                evidence="CSP script directives include 'unsafe-inline'",
                                recommendation=(
                                    "Remove 'unsafe-inline' and use cryptographic nonces or hashes for required inline scripts."
                                ),
                                confidence="high",
                            )
                        )

                    has_wildcard_or_http = any(
                        token == "*" or token.startswith("http:")
                        for token in script_sources
                    )
                    if has_wildcard_or_http:
                        page_findings.append(
                            _build_finding(
                                title="Overly Permissive Content-Security-Policy Script Source",
                                severity="low",
                                affected_url=raw_url,
                                description=(
                                    "The Content-Security-Policy allows scripts from wildcard ('*') or unencrypted "
                                    "('http:') sources, which can allow arbitrary script inclusion."
                                ),
                                evidence="CSP script directives allow wildcard '*' or 'http:' sources",
                                recommendation=(
                                    "Restrict script sources to specific trusted domains or 'self' over HTTPS."
                                ),
                                confidence="medium",
                            )
                        )

                    has_unsafe_eval = any(
                        token in ("'unsafe-eval'", "\"unsafe-eval\"", "unsafe-eval")
                        for token in script_sources
                    )
                    if has_unsafe_eval:
                        page_findings.append(
                            _build_finding(
                                title="Content-Security-Policy Allows 'unsafe-eval'",
                                severity="low",
                                affected_url=raw_url,
                                description=(
                                    "The Content-Security-Policy includes 'unsafe-eval', permitting dynamic string "
                                    "code execution methods that increase code injection risk."
                                ),
                                evidence="CSP script directives include 'unsafe-eval'",
                                recommendation=(
                                    "Refactor code to avoid dynamic code evaluation and remove 'unsafe-eval'."
                                ),
                                confidence="high",
                            )
                        )

        # 2. Strict-Transport-Security (HTTPS only)
        if scheme == "https":
            hsts_val = norm_headers.get("strict-transport-security")
            if not hsts_val:
                page_findings.append(
                    _build_finding(
                        title="Missing Strict-Transport-Security Header",
                        severity="low",
                        affected_url=raw_url,
                        description=(
                            "The HTTPS endpoint does not provide a Strict-Transport-Security (HSTS) header. "
                            "HSTS protects against SSL-stripping man-in-the-middle attacks and cookie hijacking."
                        ),
                        evidence="Strict-Transport-Security header is absent on HTTPS response",
                        recommendation=(
                            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses."
                        ),
                        confidence="high",
                    )
                )
            else:
                max_age = _parse_hsts_max_age(hsts_val)
                if max_age is None:
                    page_findings.append(
                        _build_finding(
                            title="Invalid Strict-Transport-Security Header",
                            severity="low",
                            affected_url=raw_url,
                            description=(
                                "The Strict-Transport-Security header is present but lacks a valid max-age directive."
                            ),
                            evidence="Strict-Transport-Security header missing max-age directive",
                            recommendation=(
                                "Specify a positive integer max-age directive (e.g., 'max-age=31536000')."
                            ),
                            confidence="high",
                        )
                    )
                elif max_age == 0:
                    page_findings.append(
                        _build_finding(
                            title="Strict-Transport-Security Disabled via max-age=0",
                            severity="low",
                            affected_url=raw_url,
                            description=(
                                "The Strict-Transport-Security header sets max-age=0, which explicitly unsets "
                                "HSTS policy and removes the domain from browser HSTS caches."
                            ),
                            evidence="Strict-Transport-Security: max-age=0",
                            recommendation=(
                                "Set max-age to a positive duration of at least 31536000 seconds (1 year)."
                            ),
                            confidence="high",
                        )
                    )
                elif max_age < 0:
                    page_findings.append(
                        _build_finding(
                            title="Invalid Strict-Transport-Security max-age Directive",
                            severity="low",
                            affected_url=raw_url,
                            description=(
                                "The Strict-Transport-Security header specifies an invalid non-integer max-age value."
                            ),
                            evidence="Strict-Transport-Security max-age is not a valid integer",
                            recommendation=(
                                "Configure max-age with an integer number of seconds."
                            ),
                            confidence="high",
                        )
                    )

        # 3. X-Content-Type-Options
        xcto_val = norm_headers.get("x-content-type-options")
        if not xcto_val:
            page_findings.append(
                _build_finding(
                    title="Missing X-Content-Type-Options Header",
                    severity="low",
                    affected_url=raw_url,
                    description=(
                        "The response does not specify an X-Content-Type-Options header. Without this header, "
                        "browsers may attempt MIME-sniffing, potentially executing untrusted content as scripts."
                    ),
                    evidence="X-Content-Type-Options header is absent",
                    recommendation="Set 'X-Content-Type-Options: nosniff' on all HTTP responses.",
                    confidence="high",
                )
            )
        elif xcto_val.lower() != "nosniff":
            page_findings.append(
                _build_finding(
                    title="Invalid X-Content-Type-Options Header",
                    severity="low",
                    affected_url=raw_url,
                    description=(
                        "The X-Content-Type-Options header is present but not configured to 'nosniff'."
                    ),
                    evidence=f"X-Content-Type-Options: {xcto_val[:50]}",
                    recommendation="Set 'X-Content-Type-Options: nosniff'.",
                    confidence="high",
                )
            )

        # 4. Appropriate Referrer-Policy
        ref_val = norm_headers.get("referrer-policy")
        if ref_val is not None:
            effective_policy = _evaluate_referrer_policy(ref_val)
            if effective_policy == "empty":
                page_findings.append(
                    _build_finding(
                        title="Empty Referrer-Policy Header",
                        severity="low",
                        affected_url=raw_url,
                        description=(
                            "The Referrer-Policy header is present but empty, which may lead to inconsistent "
                            "referrer behavior across browsers."
                        ),
                        evidence="Referrer-Policy header is empty",
                        recommendation=(
                            "Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'."
                        ),
                        confidence="high",
                    )
                )
            elif effective_policy == "invalid":
                page_findings.append(
                    _build_finding(
                        title="Invalid Referrer-Policy Header",
                        severity="low",
                        affected_url=raw_url,
                        description=(
                            "The Referrer-Policy header contains an unrecognized or invalid policy directive."
                        ),
                        evidence=f"Referrer-Policy: {ref_val[:50]}",
                        recommendation=(
                            "Use a standard Referrer-Policy value such as 'strict-origin-when-cross-origin'."
                        ),
                        confidence="high",
                    )
                )
            elif effective_policy == "unsafe-url":
                page_findings.append(
                    _build_finding(
                        title="Insecure Referrer-Policy: unsafe-url",
                        severity="low",
                        affected_url=raw_url,
                        description=(
                            "The Referrer-Policy header is set to 'unsafe-url', sending the full URL (including "
                            "paths and query parameters) across all outgoing requests, even over unencrypted HTTP."
                        ),
                        evidence=f"Referrer-Policy: {ref_val[:50]}",
                        recommendation=(
                            "Change Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'."
                        ),
                        confidence="high",
                    )
                )
            elif effective_policy == "no-referrer-when-downgrade":
                page_findings.append(
                    _build_finding(
                        title="Weak Referrer-Policy: no-referrer-when-downgrade",
                        severity="low",
                        affected_url=raw_url,
                        description=(
                            "The Referrer-Policy is configured to 'no-referrer-when-downgrade', which transmits "
                            "the full URL path and query parameters to all third-party HTTPS destinations."
                        ),
                        evidence=f"Referrer-Policy: {ref_val[:50]}",
                        recommendation=(
                            "Upgrade Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'."
                        ),
                        confidence="high",
                    )
                )

        # Deduplicate findings for the same issue across pages of the same host
        for finding in page_findings:
            issue_key = (finding["title"], host)
            if issue_key in seen_issues:
                continue
            seen_issues.add(issue_key)
            findings.append(finding)

    return findings
