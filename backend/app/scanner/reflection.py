"""Passive parameter reflection scanner for WebSentinel."""

from __future__ import annotations

import html
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, unquote_plus, urlencode, urlsplit, urlunsplit

# Sensitive query parameter names whose values must be redacted in affected_url and never probed
SENSITIVE_PARAM_NAMES = {
    "token",
    "access_token",
    "auth",
    "authtoken",
    "auth_token",
    "key",
    "apikey",
    "api_key",
    "secret",
    "password",
    "pass",
    "pwd",
    "session",
    "sessionid",
    "session_id",
    "sess",
    "jwt",
    "bearer",
    "signature",
    "sig",
    "code",
    "client_secret",
    "csrf",
    "xsrf",
    "state",
    "nonce",
}

SENSITIVE_PARAM_SUBSTRINGS = (
    "token",
    "secret",
    "auth",
    "session",
    "password",
    "apikey",
    "csrf",
    "xsrf",
)

# Common trivial parameter values to ignore to prevent false positives
TRIVIAL_PARAM_VALUES = {
    "true",
    "false",
    "yes",
    "no",
    "on",
    "off",
    "null",
    "undefined",
    "none",
    "all",
    "json",
    "xml",
    "html",
    "text",
    "get",
    "post",
    "put",
    "delete",
}

# HTML characters requiring entity encoding
HTML_SPECIAL_CHARS = ("<", ">", '"', "'", "&")


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


def _sanitize_url(raw_url: str) -> str:
    """Sanitize URL by removing userinfo credentials and redacting sensitive query parameters."""
    if not raw_url or not isinstance(raw_url, str):
        return ""

    try:
        parsed = urlsplit(raw_url.strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()

        if not host:
            return raw_url.strip()[:200]

        port = parsed.port
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443) or port is None:
            netloc = host
        else:
            netloc = f"{host}:{port}"

        # Redact sensitive parameters from query string
        if parsed.query:
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            sanitized_pairs: list[tuple[str, str]] = []
            for k, v in query_pairs:
                k_lower = k.lower().strip()
                if (
                    k_lower in SENSITIVE_PARAM_NAMES
                    or any(sub in k_lower for sub in SENSITIVE_PARAM_SUBSTRINGS)
                ):
                    sanitized_pairs.append((k, "[REDACTED]"))
                elif len(v) > 64:
                    sanitized_pairs.append((k, "[REDACTED]"))
                else:
                    sanitized_pairs.append((k, v))
            clean_query = urlencode(sanitized_pairs, safe="[]/:")
        else:
            clean_query = ""

        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path, clean_query, ""))
    except Exception:
        return raw_url.strip()[:200]


def _normalize_headers(raw_headers: Any) -> dict[str, str]:
    """Normalize headers into lowercase keys with trimmed string values."""
    norm: dict[str, str] = {}
    if isinstance(raw_headers, dict):
        for k, v in raw_headers.items():
            if isinstance(v, list):
                combined = ", ".join(str(item).strip() for item in v if item is not None)
                norm[str(k).lower().strip()] = combined
            elif v is not None:
                norm[str(k).lower().strip()] = str(v).strip()
    elif isinstance(raw_headers, (list, tuple)):
        for item in raw_headers:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                k, v = item
                k_str = str(k).lower().strip()
                v_str = str(v).strip()
                if k_str in norm:
                    norm[k_str] = f"{norm[k_str]}, {v_str}"
                else:
                    norm[k_str] = v_str
    return norm


def _clean_content_type(ct: str) -> str:
    """Extract clean MIME type without parameters."""
    if not ct:
        return ""
    parts = ct.split(";")
    return parts[0].strip().lower()


def _is_html_content_type(ct: str) -> bool:
    """Determine whether the MIME type represents HTML."""
    clean_ct = _clean_content_type(ct)
    return clean_ct in {"text/html", "application/xhtml+xml"}


def _is_json_content_type(ct: str) -> bool:
    """Determine whether the MIME type represents JSON."""
    clean_ct = _clean_content_type(ct)
    return clean_ct in {"application/json", "application/problem+json"} or clean_ct.endswith("+json")


def _is_escaped_in_body(val: str, body: str) -> bool:
    """Check if the special characters in val appear in HTML entity-encoded form in body."""
    standard_escaped = html.escape(val, quote=True)
    if standard_escaped in body:
        return True

    # Check common entity encoding variations for quotes and brackets
    variations = [
        val.replace("<", "&lt;").replace(">", "&gt;"),
        val.replace('"', "&quot;"),
        val.replace("'", "&#x27;"),
        val.replace("'", "&#39;"),
        val.replace("'", "&apos;"),
    ]
    for var in variations:
        if var != val and var in body:
            return True

    return False


def _check_script_context(val: str, body: str) -> bool:
    """Determine whether the value appears inside an inline <script> block."""
    script_pattern = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
    for match in script_pattern.finditer(body):
        script_content = match.group(1)
        if val in script_content:
            return True
    return False


def _check_comment_context(val: str, body: str) -> bool:
    """Determine whether the value appears strictly inside an HTML comment."""
    comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
    found_in_comment = False
    for match in comment_pattern.finditer(body):
        if val in match.group(1):
            found_in_comment = True
            break
    if not found_in_comment:
        return False

    # Verify if it also appears outside comments
    body_without_comments = comment_pattern.sub("", body)
    return val not in body_without_comments


def _is_valid_candidate_value(param_name: str, param_val: str, hostname: str) -> bool:
    """Filter out non-viable, sensitive, or trivial parameter values."""
    name_lower = param_name.lower().strip()
    if (
        name_lower in SENSITIVE_PARAM_NAMES
        or any(sub in name_lower for sub in SENSITIVE_PARAM_SUBSTRINGS)
    ):
        return False

    cleaned_val = param_val.strip()
    if len(cleaned_val) < 3:
        return False

    val_lower = cleaned_val.lower()
    if val_lower in TRIVIAL_PARAM_VALUES:
        return False

    # Ignore pure numeric values
    if cleaned_val.isdigit():
        return False

    # Ignore values that match the target hostname or common URL protocols
    if hostname and (val_lower == hostname.lower() or val_lower in hostname.lower()):
        return False
    if val_lower in {"http", "https", "localhost", "127.0.0.1"}:
        return False

    return True


def check_reflection(pages: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Inspect collected pages for harmless evidence of reflected URL query parameters.

    Analyzes whether ordinary URL query parameter values appear in response bodies
    already collected by the crawler. Considers HTML entity escaping and response
    MIME types to distinguish properly sanitized values from potential unescaped
    reflection. Does not generate network requests, submit forms, or inject executable payloads.

    Args:
        pages: List of crawled page records containing 'url', 'status_code', 'headers',
               'body', and optional 'content_type'.

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
        if not raw_url:
            continue

        parsed = urlsplit(raw_url)
        if not parsed.query:
            continue

        sanitized_url = _sanitize_url(raw_url)
        if not sanitized_url:
            continue

        # Passive inspection strictly considers successful responses
        raw_status = page.get("status_code")
        try:
            status_code = int(raw_status)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue

        if status_code not in {200, 206}:
            continue

        body = str(page.get("body") or "")
        if not body.strip():
            continue

        normalized_headers = _normalize_headers(page.get("headers"))
        content_type = str(
            page.get("content_type") or normalized_headers.get("content-type") or ""
        ).strip()

        hostname = (parsed.hostname or "").lower()
        clean_path = unquote(parsed.path or "/")[:100]

        # Extract and analyze unique query parameters
        try:
            query_params = parse_qsl(parsed.query, keep_blank_values=False)
        except Exception:
            continue

        for param_name, param_val in query_params:
            if not _is_valid_candidate_value(param_name, param_val, hostname):
                continue

            # Check both raw and decoded forms of the candidate value
            decoded_val = unquote_plus(param_val).strip()
            if not decoded_val or len(decoded_val) < 3:
                continue

            has_html_chars = any(ch in decoded_val for ch in HTML_SPECIAL_CHARS)
            is_json_response = _is_json_content_type(content_type)
            is_html_response = _is_html_content_type(content_type) or (
                not content_type and ("<html" in body.lower() or "<!doctype" in body.lower())
            )

            finding: dict[str, str] | None = None
            safe_param = param_name.strip()[:40]

            # Case 1: Parameter containing HTML special characters
            if has_html_chars:
                if _is_escaped_in_body(decoded_val, body) and decoded_val not in body:
                    # Properly HTML-escaped reflection
                    finding = _build_finding(
                        title="Sanitized Reflected Parameter in Response Body",
                        severity="informational",
                        affected_url=sanitized_url,
                        description=(
                            f"The URL query parameter '{safe_param}' was observed reflected in the response body, "
                            "and its special characters appear to be properly entity-encoded (escaped). "
                            "HTML entity encoding prevents the browser from interpreting user input as active markup "
                            "in standard HTML contexts."
                        ),
                        evidence=(
                            f"Parameter '{safe_param}' is reflected with HTML entity encoding in '{clean_path}' "
                            f"(HTTP status {status_code})"
                        ),
                        recommendation=(
                            "Maintain consistent contextual output encoding across all templates and continue "
                            "enforcing Content-Security-Policy (CSP) headers."
                        ),
                        confidence="low",
                    )
                elif decoded_val in body:
                    # Unescaped reflection of special characters
                    finding = _build_finding(
                        title="Potential Reflected Input in Response Body (Unescaped)",
                        severity="medium",
                        affected_url=sanitized_url,
                        description=(
                            f"The URL query parameter '{safe_param}' containing special characters was observed "
                            "reflected directly in the response body without HTML entity encoding. While this passive "
                            "observation does not confirm an executable Cross-Site Scripting (XSS) vulnerability, "
                            "unescaped reflection indicates that user-controlled values are rendered into the DOM "
                            "without sufficient contextual encoding."
                        ),
                        evidence=(
                            f"Parameter '{safe_param}' is reflected unescaped in response body at '{clean_path}' "
                            f"(HTTP status {status_code})"
                        ),
                        recommendation=(
                            "Apply context-aware output encoding (such as HTML entity encoding or JavaScript serialization) "
                            f"before rendering the '{safe_param}' parameter value in HTML responses."
                        ),
                        confidence="medium",
                    )

            # Case 2: Ordinary parameter values (without special HTML characters)
            elif decoded_val in body:
                # Use word boundary check to avoid spurious substring matches inside unrelated words
                escaped_token = re.escape(decoded_val)
                token_regex = re.compile(r"(?:\b|\W)" + escaped_token + r"(?:\b|\W)")
                if not token_regex.search(body):
                    continue

                if is_json_response:
                    finding = _build_finding(
                        title="Reflected Parameter in JSON API Response",
                        severity="informational",
                        affected_url=sanitized_url,
                        description=(
                            f"The URL query parameter '{safe_param}' is reflected in a JSON API response. "
                            "Because the response is served with a JSON MIME type, the browser does not execute "
                            "or parse HTML markup from this payload."
                        ),
                        evidence=(
                            f"Parameter '{safe_param}' reflected in JSON response at '{clean_path}' "
                            f"(HTTP status {status_code})"
                        ),
                        recommendation=(
                            "Ensure 'Content-Type: application/json' and 'X-Content-Type-Options: nosniff' headers "
                            "are strictly enforced to prevent MIME sniffing."
                        ),
                        confidence="low",
                    )
                elif _check_script_context(decoded_val, body):
                    finding = _build_finding(
                        title="Potential Reflected Input in Script Context",
                        severity="low",
                        affected_url=sanitized_url,
                        description=(
                            f"The URL query parameter '{safe_param}' was observed reflected within an inline JavaScript "
                            "(<script>) block. Data reflected inside script blocks requires context-aware JavaScript "
                            "serialization or JSON encoding to prevent script breakout."
                        ),
                        evidence=(
                            f"Parameter '{safe_param}' observed reflected within an inline <script> block at '{clean_path}' "
                            f"(HTTP status {status_code})"
                        ),
                        recommendation=(
                            f"Serialize values rendered for '{safe_param}' using safe JSON encoding and avoid direct string "
                            "interpolation in JavaScript blocks."
                        ),
                        confidence="medium",
                    )
                elif _check_comment_context(decoded_val, body):
                    finding = _build_finding(
                        title="Potential Reflected Input in HTML Comment",
                        severity="informational",
                        affected_url=sanitized_url,
                        description=(
                            f"The URL query parameter '{safe_param}' was observed reflected inside an HTML comment. "
                            "While comments do not execute script directly, reflected values inside comments may lead "
                            "to comment breakout if not properly sanitized."
                        ),
                        evidence=(
                            f"Parameter '{safe_param}' observed reflected inside an HTML comment at '{clean_path}' "
                            f"(HTTP status {status_code})"
                        ),
                        recommendation="Sanitize user-supplied input before rendering it into HTML comments.",
                        confidence="low",
                    )
                elif is_html_response:
                    finding = _build_finding(
                        title="Potential Reflected Input in Response Body",
                        severity="low",
                        affected_url=sanitized_url,
                        description=(
                            f"The URL query parameter '{safe_param}' was observed reflected in the HTML response body. "
                            "Based on passive crawler records without active payload execution, this is an unverified "
                            "reflection observation. Confirm that context-aware output encoding is enforced."
                        ),
                        evidence=(
                            f"Parameter '{safe_param}' observed reflected in the response body at '{clean_path}' "
                            f"(HTTP status {status_code})"
                        ),
                        recommendation=(
                            f"Ensure contextual output encoding is applied to '{safe_param}' before rendering into "
                            "HTML documents."
                        ),
                        confidence="low",
                    )

            if finding:
                issue_key = (finding["title"], finding["affected_url"], safe_param)
                if issue_key not in seen_issues:
                    seen_issues.add(issue_key)
                    findings.append(finding)

    return findings


__all__ = ["check_reflection"]
