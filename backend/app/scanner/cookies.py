"""HTTP cookie security scanner for WebSentinel."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

# Recognized session, token, and authentication cookie names and patterns
SESSION_COOKIE_NAMES = {
    "session",
    "sessionid",
    "session_id",
    "sess",
    "sessid",
    "phpsessid",
    "jsessionid",
    "aspsessionid",
    "asp.net_sessionid",
    "sid",
    "connect.sid",
    "auth",
    "authtoken",
    "auth_token",
    "authentication",
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "jwt",
    "login",
    "sso",
    "logged_in",
    "user_session",
    "identity",
    "remember_token",
    "remember_me",
}

SESSION_SUBSTRING_PATTERNS = (
    "sess",
    "phpsessid",
    "jsessionid",
    "aspsessionid",
    "connect.sid",
    "authtoken",
    "auth_token",
    "access_token",
    "id_token",
    "refresh_token",
    "user_session",
)

EXCLUDED_FROM_SESSION_PATTERNS = (
    "csrf",
    "xsrf",
)

VALID_SAMESITE_VALUES = {"lax", "strict", "none"}


def _sanitize_cookie_name(name: str) -> str:
    """Sanitize cookie name to remove control characters and limit length."""
    sanitized = "".join(ch for ch in name if ch.isprintable() and ch not in "\r\n\t;=")
    clean = sanitized.strip()
    return clean[:64] if clean else "unnamed_cookie"


def _is_session_cookie(cookie_name: str) -> bool:
    """Determine whether the cookie name indicates an authentication or session identifier."""
    name_lower = cookie_name.lower()
    if any(excluded in name_lower for excluded in EXCLUDED_FROM_SESSION_PATTERNS):
        return False
    if name_lower in SESSION_COOKIE_NAMES:
        return True
    return any(pattern in name_lower for pattern in SESSION_SUBSTRING_PATTERNS)


def _is_deleted_cookie(attributes: dict[str, str]) -> bool:
    """Detect whether a cookie is being expired or deleted by the server."""
    max_age_str = attributes.get("max-age")
    if max_age_str is not None:
        try:
            if int(max_age_str) <= 0:
                return True
        except ValueError:
            pass

    expires_str = attributes.get("expires", "").lower()
    if any(epoch_indicator in expires_str for epoch_indicator in ("1970", "1969", "epoch")):
        return True

    return False


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


def _split_cookie_string(raw: str) -> list[str]:
    """Split potentially combined Set-Cookie strings without breaking date commas."""
    if "\n" in raw:
        return [line.strip() for line in raw.splitlines() if line.strip()]

    parts = re.split(r",\s*(?=[a-zA-Z0-9_!#$%&'*+\-.^`|~]+=[^;])", raw)
    return [p.strip() for p in parts if p.strip()]


def _extract_set_cookies(page: dict[str, Any]) -> list[str]:
    """Extract individual Set-Cookie header strings from a crawled page dictionary."""
    raw_cookies: list[str] = []

    cookie_list = page.get("set_cookie_headers")
    if isinstance(cookie_list, list):
        for item in cookie_list:
            if isinstance(item, str) and item.strip():
                raw_cookies.extend(_split_cookie_string(item.strip()))
    elif isinstance(cookie_list, str) and cookie_list.strip():
        raw_cookies.extend(_split_cookie_string(cookie_list.strip()))

    headers = page.get("headers")
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).strip().lower() == "set-cookie":
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, str) and item.strip():
                            raw_cookies.extend(_split_cookie_string(item.strip()))
                elif isinstance(v, str) and v.strip():
                    raw_cookies.extend(_split_cookie_string(v.strip()))

    unique_cookies: list[str] = []
    seen: set[str] = set()
    for cookie_entry in raw_cookies:
        if cookie_entry not in seen:
            seen.add(cookie_entry)
            unique_cookies.append(cookie_entry)

    return unique_cookies


def _parse_cookie_directive(raw_header: str) -> tuple[str, dict[str, str], dict[str, str]] | None:
    """Parse a Set-Cookie header directive, strictly omitting cookie values.

    Returns:
        A tuple of (sanitized_cookie_name, lowercase_attributes, raw_attributes),
        or None if the header is empty or malformed.
    """
    parts = raw_header.split(";")
    first_part = parts[0].strip()
    if not first_part:
        return None

    if "=" in first_part:
        raw_name, _ = first_part.split("=", 1)
    else:
        raw_name = first_part

    cookie_name = _sanitize_cookie_name(raw_name)
    if not cookie_name:
        return None

    attributes: dict[str, str] = {}
    raw_attributes: dict[str, str] = {}

    for part in parts[1:]:
        attr_part = part.strip()
        if not attr_part:
            continue
        if "=" in attr_part:
            name, val = attr_part.split("=", 1)
            name_lower = name.strip().lower()
            val_clean = val.strip()
            attributes[name_lower] = val_clean.lower()
            raw_attributes[name_lower] = val_clean
        else:
            name_lower = attr_part.lower()
            attributes[name_lower] = ""
            raw_attributes[name_lower] = ""

    return cookie_name, attributes, raw_attributes


def check_cookies(pages: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Inspect Set-Cookie response headers for missing or inappropriate security attributes.

    Inspects Secure, HttpOnly, and SameSite attributes, prefix requirements (__Host-, __Secure-),
    and contextual transport safety without modifying cookies or issuing requests.

    Args:
        pages: List of crawled page dictionaries containing 'url' and Set-Cookie headers
               (via 'set_cookie_headers' or 'headers').

    Returns:
        List of findings formatted with exact field names matching app.schemas.Finding.
    """
    if not isinstance(pages, list):
        return []

    findings: list[dict[str, str]] = []
    seen_issues: set[tuple[str, str, str]] = set()

    for page in pages:
        if not isinstance(page, dict):
            continue

        raw_url = str(page.get("url") or page.get("affected_url") or "").strip()
        parsed_url = urlsplit(raw_url)
        scheme = parsed_url.scheme.lower()
        host = parsed_url.netloc.lower() or "default"
        is_https = (scheme == "https")

        status_code = page.get("status_code")
        raw_cookies = _extract_set_cookies(page)

        if isinstance(status_code, int) and status_code in {204, 304} and not raw_cookies:
            continue

        page_findings: list[dict[str, str]] = []

        for raw_cookie in raw_cookies:
            parsed = _parse_cookie_directive(raw_cookie)
            if not parsed:
                continue

            cookie_name, attributes, raw_attributes = parsed

            # Skip cookies being cleared or deleted by the server
            if _is_deleted_cookie(attributes):
                continue

            has_secure = "secure" in attributes
            has_httponly = "httponly" in attributes
            has_samesite = "samesite" in attributes
            samesite_raw = raw_attributes.get("samesite", "")
            samesite_val = attributes.get("samesite")
            is_session = _is_session_cookie(cookie_name)

            handled_secure = False

            # 1. Cookie Prefix Verification (__Host- and __Secure-)
            if cookie_name.startswith("__Host-"):
                violations: list[str] = []
                if not has_secure or not is_https:
                    violations.append("requires 'Secure' attribute and HTTPS scheme")
                if "domain" in attributes:
                    violations.append("cannot specify 'Domain' attribute")
                if raw_attributes.get("path") != "/":
                    violations.append("must specify 'Path=/'")

                if violations:
                    handled_secure = True
                    page_findings.append(
                        _build_finding(
                            title="Misconfigured __Host- Cookie Prefix",
                            severity="medium",
                            affected_url=raw_url,
                            description=(
                                f"The cookie '{cookie_name}' uses the '__Host-' prefix but violates "
                                f"host-only cookie constraints ({', '.join(violations)}). "
                                "Modern RFC 6265bis-compliant browsers will reject this cookie."
                            ),
                            evidence=f"Cookie '{cookie_name}' violates __Host- constraints: {', '.join(violations)}",
                            recommendation=(
                                f"Configure '{cookie_name}' with the 'Secure' attribute, set 'Path=/', "
                                "remove any 'Domain' attribute, and serve it exclusively over HTTPS."
                            ),
                            confidence="high",
                        )
                    )
            elif cookie_name.startswith("__Secure-"):
                if not has_secure or not is_https:
                    handled_secure = True
                    page_findings.append(
                        _build_finding(
                            title="Misconfigured __Secure- Cookie Prefix",
                            severity="medium",
                            affected_url=raw_url,
                            description=(
                                f"The cookie '{cookie_name}' uses the '__Secure-' prefix but lacks the "
                                "'Secure' attribute or was delivered over insecure HTTP. "
                                "RFC 6265bis-compliant browsers will reject this cookie."
                            ),
                            evidence=f"Cookie '{cookie_name}' with '__Secure-' prefix lacks 'Secure' attribute or HTTPS scheme",
                            recommendation=(
                                f"Configure '{cookie_name}' with the 'Secure' attribute and deliver it over HTTPS."
                            ),
                            confidence="high",
                        )
                    )

            # 2. Contextual Secure Attribute Inspection
            if not handled_secure:
                if is_https:
                    if not has_secure:
                        if is_session:
                            page_findings.append(
                                _build_finding(
                                    title="Session Cookie Missing Secure Attribute",
                                    severity="medium",
                                    affected_url=raw_url,
                                    description=(
                                        f"The cookie '{cookie_name}' appears to be an authentication or session identifier "
                                        "but lacks the 'Secure' attribute while being transmitted over HTTPS. Browsers may "
                                        "send this cookie over cleartext HTTP requests (such as through mixed-content links "
                                        "or network interception), exposing session credentials."
                                    ),
                                    evidence=f"Cookie '{cookie_name}' set over HTTPS without 'Secure' attribute",
                                    recommendation=(
                                        f"Add the 'Secure' attribute to the '{cookie_name}' cookie to enforce transmission "
                                        "exclusively over encrypted TLS/HTTPS connections."
                                    ),
                                    confidence="high",
                                )
                            )
                        else:
                            page_findings.append(
                                _build_finding(
                                    title="Cookie Missing Secure Attribute",
                                    severity="low",
                                    affected_url=raw_url,
                                    description=(
                                        f"The cookie '{cookie_name}' was transmitted over HTTPS without the 'Secure' attribute. "
                                        "Without the 'Secure' flag, the cookie may be transmitted over unencrypted HTTP connections."
                                    ),
                                    evidence=f"Cookie '{cookie_name}' set over HTTPS without 'Secure' attribute",
                                    recommendation=(
                                        f"Add the 'Secure' attribute to the '{cookie_name}' cookie to ensure it is only transmitted "
                                        "across encrypted connections."
                                    ),
                                    confidence="medium",
                                )
                            )
                else:
                    if has_secure:
                        page_findings.append(
                            _build_finding(
                                title="Inappropriate Secure Cookie Attribute on Insecure Origin",
                                severity="low",
                                affected_url=raw_url,
                                description=(
                                    f"The cookie '{cookie_name}' specifies the 'Secure' attribute but was sent over an unencrypted "
                                    "HTTP connection. Under RFC 6265bis, browsers reject cookies setting the 'Secure' attribute "
                                    "over non-secure channels."
                                ),
                                evidence=f"Cookie '{cookie_name}' specifies 'Secure' attribute over cleartext HTTP",
                                recommendation=(
                                    f"Migrate the application origin to HTTPS before setting the 'Secure' attribute on '{cookie_name}'."
                                ),
                                confidence="high",
                            )
                        )

            # 3. HttpOnly Attribute Inspection
            if not has_httponly:
                if is_session:
                    page_findings.append(
                        _build_finding(
                            title="Session Cookie Missing HttpOnly Attribute",
                            severity="medium",
                            affected_url=raw_url,
                            description=(
                                f"The cookie '{cookie_name}' appears to be an authentication or session identifier but lacks "
                                "the 'HttpOnly' attribute. Omitting 'HttpOnly' permits client-side JavaScript to access "
                                "the cookie via document.cookie, exposing the session to theft via Cross-Site Scripting (XSS)."
                            ),
                            evidence=f"Cookie '{cookie_name}' set without 'HttpOnly' attribute",
                            recommendation=(
                                f"Add the 'HttpOnly' attribute to '{cookie_name}' so that client-side scripts cannot access or read it."
                            ),
                            confidence="high",
                        )
                    )
                else:
                    page_findings.append(
                        _build_finding(
                            title="Cookie Missing HttpOnly Attribute",
                            severity="informational",
                            affected_url=raw_url,
                            description=(
                                f"The cookie '{cookie_name}' does not specify the 'HttpOnly' attribute. If client-side JavaScript "
                                "does not require access to this cookie, configuring 'HttpOnly' provides defense-in-depth "
                                "against script access."
                            ),
                            evidence=f"Cookie '{cookie_name}' set without 'HttpOnly' attribute",
                            recommendation=(
                                f"Review whether client-side scripts require access to '{cookie_name}'. If not, add the 'HttpOnly' attribute."
                            ),
                            confidence="low",
                        )
                    )

            # 4. SameSite Attribute Inspection
            if not has_samesite:
                page_findings.append(
                    _build_finding(
                        title="Cookie Missing SameSite Attribute",
                        severity="low",
                        affected_url=raw_url,
                        description=(
                            f"The cookie '{cookie_name}' does not specify a 'SameSite' attribute. While modern browsers "
                            "default to 'SameSite=Lax', explicit configuration prevents Cross-Site Request Forgery (CSRF) "
                            "and ensures consistent behavior across all clients and legacy browsers."
                        ),
                        evidence=f"Cookie '{cookie_name}' set without 'SameSite' attribute",
                        recommendation=(
                            f"Explicitly configure the 'SameSite' attribute for '{cookie_name}' (recommended: 'SameSite=Lax' "
                            "or 'SameSite=Strict')."
                        ),
                        confidence="medium",
                    )
                )
            else:
                if samesite_val not in VALID_SAMESITE_VALUES:
                    clean_val = samesite_raw[:30]
                    page_findings.append(
                        _build_finding(
                            title="Invalid SameSite Attribute Value",
                            severity="low",
                            affected_url=raw_url,
                            description=(
                                f"The cookie '{cookie_name}' defines an unrecognized 'SameSite' attribute value ('{clean_val}'). "
                                "Valid options are 'Strict', 'Lax', or 'None'."
                            ),
                            evidence=f"Cookie '{cookie_name}' specifies unrecognized SameSite value: '{clean_val}'",
                            recommendation=(
                                f"Update the 'SameSite' attribute on '{cookie_name}' to 'Strict', 'Lax', or 'None'."
                            ),
                            confidence="high",
                        )
                    )
                elif samesite_val == "none":
                    if not has_secure:
                        page_findings.append(
                            _build_finding(
                                title="Insecure SameSite=None Without Secure Attribute",
                                severity="medium",
                                affected_url=raw_url,
                                description=(
                                    f"The cookie '{cookie_name}' is configured with 'SameSite=None' but lacks the 'Secure' "
                                    "attribute. Modern browsers strictly reject cookies configured with 'SameSite=None' "
                                    "unless 'Secure' is also present, causing the cookie to be rejected."
                                ),
                                evidence=f"Cookie '{cookie_name}' specifies SameSite=None without 'Secure' attribute",
                                recommendation=(
                                    f"Add the 'Secure' attribute to '{cookie_name}' when using 'SameSite=None' and ensure "
                                    "transmission over HTTPS."
                                ),
                                confidence="high",
                            )
                        )
                    elif is_session:
                        page_findings.append(
                            _build_finding(
                                title="Session Cookie Configured With SameSite=None",
                                severity="low",
                                affected_url=raw_url,
                                description=(
                                    f"The session cookie '{cookie_name}' specifies 'SameSite=None', allowing it to be sent "
                                    "on cross-site requests. This increases exposure to Cross-Site Request Forgery (CSRF) "
                                    "unless independent anti-CSRF token verification is strictly enforced."
                                ),
                                evidence=f"Cookie '{cookie_name}' specifies SameSite=None",
                                recommendation=(
                                    f"Set 'SameSite=Lax' or 'SameSite=Strict' on '{cookie_name}' unless third-party cross-site "
                                    "embedding is explicitly required."
                                ),
                                confidence="medium",
                            )
                        )

        # Deduplicate findings by title, cookie name, and target host
        for finding in page_findings:
            issue_title = finding["title"]
            evidence_str = finding["evidence"]
            issue_key = (issue_title, evidence_str, host)
            if issue_key in seen_issues:
                continue
            seen_issues.add(issue_key)
            findings.append(finding)

    return findings
