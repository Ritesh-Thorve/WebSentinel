"""CORS (Cross-Origin Resource Sharing) security scanner for WebSentinel."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Sensitive query parameter names whose values must be redacted
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
}

SENSITIVE_PARAM_SUBSTRINGS = (
    "token",
    "secret",
    "auth",
    "session",
    "password",
    "apikey",
)


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
    if not raw_url:
        return ""

    try:
        parsed = urlsplit(raw_url.strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()

        if not host:
            return raw_url.strip()

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


def _sanitize_evidence_string(text: str, max_length: int = 200) -> str:
    """Sanitize evidence text by removing control characters, userinfo, and bounding length."""
    if not text:
        return ""

    # Strip control characters (\r, \n, \t, etc.)
    cleaned = "".join(ch for ch in text if ch.isprintable() and ch not in "\r\n\t")
    # Redact embedded userinfo credentials (e.g., http://user:pass@host)
    cleaned = re.sub(r"://[^/@:]+:[^/@:]+@", "://[REDACTED]@", cleaned)

    cleaned = cleaned.strip()
    if len(cleaned) > max_length:
        return cleaned[:max_length] + "..."
    return cleaned


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
                v_str = str(v).strip() if v is not None else ""
                if k_str in norm:
                    norm[k_str] = f"{norm[k_str]}, {v_str}"
                else:
                    norm[k_str] = v_str
    return norm


def _extract_origin_triple(url_or_origin: str) -> tuple[str, str, int] | None:
    """Extract (scheme, host, port) origin triple from a URL or origin string."""
    try:
        parsed = urlsplit(url_or_origin.strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        if not scheme or not host:
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
        return (scheme, host, port)
    except Exception:
        return None


def _is_same_origin(origin_a: tuple[str, str, int], origin_b: tuple[str, str, int]) -> bool:
    """Compare two origin triples for equality."""
    return origin_a == origin_b


def _parse_vary_tokens(vary_header: str) -> set[str]:
    """Parse Vary header string into a set of lowercased directive tokens."""
    if not vary_header:
        return set()
    return {token.strip().lower() for token in vary_header.split(",") if token.strip()}


def check_cors(pages: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Analyze crawled pages for unsafe Cross-Origin Resource Sharing (CORS) configurations.

    Examines Access-Control-Allow-Origin, Access-Control-Allow-Credentials, and Vary
    response headers observed in passive crawl records. Treats reflected origins and
    credentialed access conservatively without issuing active probing requests or
    transmitting credentials.

    Args:
        pages: List of crawled page records containing 'url' (or 'affected_url') and 'headers'.
               May also include 'request_headers' or 'request' records.

    Returns:
        List of findings matching the WebSentinel Finding schema.
    """
    if not isinstance(pages, list):
        return []

    findings: list[dict[str, str]] = []
    seen_issues: set[tuple[str, str, str]] = set()

    for page in pages:
        if not isinstance(page, dict):
            continue

        raw_url = str(page.get("url") or page.get("affected_url") or "").strip()
        sanitized_url = _sanitize_url(raw_url)
        parsed_page_url = urlsplit(raw_url)
        page_scheme = parsed_page_url.scheme.lower()
        page_host = parsed_page_url.netloc.lower() or "default"
        page_origin_triple = _extract_origin_triple(raw_url)

        norm_headers = _normalize_headers(page.get("headers"))

        raw_acao = norm_headers.get("access-control-allow-origin")
        raw_acac = norm_headers.get("access-control-allow-credentials")
        raw_vary = norm_headers.get("vary")

        # Skip responses that do not set any CORS response headers
        if raw_acao is None and raw_acac is None:
            continue

        # Extract request Origin if available from passive crawler records
        req_origin: str | None = None
        req_headers_raw = page.get("request_headers")
        if req_headers_raw is None and isinstance(page.get("request"), dict):
            req_headers_raw = page.get("request", {}).get("headers")

        if req_headers_raw is not None:
            norm_req_headers = _normalize_headers(req_headers_raw)
            raw_req_orig = norm_req_headers.get("origin")
            if raw_req_orig:
                req_origin = raw_req_orig.strip()
        elif page.get("request_origin"):
            req_origin = str(page.get("request_origin")).strip()
        elif page.get("origin"):
            req_origin = str(page.get("origin")).strip()

        # Parse Access-Control-Allow-Credentials
        is_credentials = False
        page_findings: list[dict[str, str]] = []

        if raw_acac is not None:
            acac_cleaned = raw_acac.strip()
            if acac_cleaned.lower() == "true":
                is_credentials = True
            elif acac_cleaned.lower() not in {"false", ""}:
                safe_acac = _sanitize_evidence_string(acac_cleaned)
                page_findings.append(
                    _build_finding(
                        title="Invalid Access-Control-Allow-Credentials Header Value",
                        severity="low",
                        affected_url=sanitized_url,
                        description=(
                            f"The 'Access-Control-Allow-Credentials' response header is set to '{safe_acac}'. "
                            "According to the CORS specification, only the literal case-sensitive value 'true' "
                            "permits credentialed requests. Browsers treat any other value as false."
                        ),
                        evidence=f"Access-Control-Allow-Credentials: {safe_acac}",
                        recommendation=(
                            "Set 'Access-Control-Allow-Credentials: true' if credentials are required, "
                            "or omit the header entirely if credentials should not be exposed."
                        ),
                        confidence="high",
                    )
                )

        # Inspect Access-Control-Allow-Origin
        if raw_acao is None:
            # ACAC present without ACAO
            if is_credentials:
                page_findings.append(
                    _build_finding(
                        title="Incomplete CORS Configuration: Credentials Allowed Without Origin",
                        severity="informational",
                        affected_url=sanitized_url,
                        description=(
                            "The response specifies 'Access-Control-Allow-Credentials: true' without an "
                            "'Access-Control-Allow-Origin' header. Browsers block cross-origin requests by "
                            "default when Access-Control-Allow-Origin is absent, rendering this policy ineffective."
                        ),
                        evidence="Access-Control-Allow-Credentials: true; Access-Control-Allow-Origin header is absent",
                        recommendation=(
                            "Specify an authorized origin in 'Access-Control-Allow-Origin' if cross-origin access "
                            "is intended, or remove 'Access-Control-Allow-Credentials' if not needed."
                        ),
                        confidence="medium",
                    )
                )
        else:
            acao_trimmed = raw_acao.strip()
            safe_acao = _sanitize_evidence_string(acao_trimmed)

            if not acao_trimmed:
                page_findings.append(
                    _build_finding(
                        title="Malformed Access-Control-Allow-Origin Header: Empty Origin",
                        severity="low",
                        affected_url=sanitized_url,
                        description=(
                            "The 'Access-Control-Allow-Origin' response header is present but empty. "
                            "Browsers reject empty origin values, preventing cross-origin requests."
                        ),
                        evidence="Access-Control-Allow-Origin header is empty",
                        recommendation=(
                            "Set 'Access-Control-Allow-Origin' to a valid single origin or remove the header."
                        ),
                        confidence="high",
                    )
                )
            elif "," in acao_trimmed or len(acao_trimmed.split()) > 1:
                page_findings.append(
                    _build_finding(
                        title="Malformed Access-Control-Allow-Origin Header: Multiple Origins",
                        severity="low",
                        affected_url=sanitized_url,
                        description=(
                            "The 'Access-Control-Allow-Origin' header contains multiple values. The CORS specification "
                            "strictly requires a single origin, '*', or 'null'. Browsers will reject headers containing "
                            "multiple origins, which causes cross-origin requests to fail."
                        ),
                        evidence=f"Access-Control-Allow-Origin: {safe_acao}",
                        recommendation=(
                            "Configure the server to return only the single matching authorized origin per request, "
                            "rather than a comma-separated or space-separated list of origins."
                        ),
                        confidence="high",
                    )
                )
            elif acao_trimmed == "*":
                if is_credentials:
                    page_findings.append(
                        _build_finding(
                            title="Conflicting CORS Policy: Wildcard Origin With Credentials",
                            severity="low",
                            affected_url=sanitized_url,
                            description=(
                                "The response specifies 'Access-Control-Allow-Origin: *' combined with "
                                "'Access-Control-Allow-Credentials: true'. According to the W3C and WHATWG Fetch "
                                "specifications, web browsers reject cross-origin requests when wildcard origins are "
                                "combined with credentials. While this prevents unauthorized credential leakage in "
                                "compliant browsers, it represents an invalid CORS configuration that can disrupt "
                                "cross-origin functionality."
                            ),
                            evidence="Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                            recommendation=(
                                "If credentialed access is required, replace the wildcard with an explicit trusted "
                                "origin allowlist in Access-Control-Allow-Origin. If the resource is public, remove "
                                "Access-Control-Allow-Credentials or set it to 'false'."
                            ),
                            confidence="high",
                        )
                    )
                else:
                    page_findings.append(
                        _build_finding(
                            title="CORS Policy Allows Uncredentialed Wildcard Access",
                            severity="informational",
                            affected_url=sanitized_url,
                            description=(
                                "The resource sets 'Access-Control-Allow-Origin: *', permitting any third-party domain "
                                "to read response data via uncredentialed cross-origin requests. Wildcard origin alone "
                                "does not indicate a vulnerability if the resource is intended to be publicly accessible, "
                                "such as public APIs or static content. Verify that this endpoint does not expose "
                                "sensitive, private, or internal information."
                            ),
                            evidence="Access-Control-Allow-Origin: *",
                            recommendation=(
                                "Confirm whether the endpoint is intended to be publicly readable by any external domain. "
                                "If the resource serves private or sensitive user information, replace the wildcard with "
                                "an explicit allowlist of authorized origins."
                            ),
                            confidence="high",
                        )
                    )
            elif acao_trimmed.lower() == "null":
                if is_credentials:
                    page_findings.append(
                        _build_finding(
                            title="Insecure CORS Configuration: Null Origin Allowed With Credentials",
                            severity="medium",
                            affected_url=sanitized_url,
                            description=(
                                "The response specifies 'Access-Control-Allow-Origin: null' and enables credentials "
                                "('Access-Control-Allow-Credentials: true'). Untrusted third-party sites can trigger "
                                "requests with an opaque 'null' origin using sandboxed iframes (<iframe sandbox=\"allow-scripts\">) "
                                "or cross-origin redirects. If this endpoint serves sensitive authenticated data, an "
                                "attacker could potentially access that information."
                            ),
                            evidence="Access-Control-Allow-Origin: null; Access-Control-Allow-Credentials: true",
                            recommendation=(
                                "Do not permit the 'null' origin in Access-Control-Allow-Origin. Validate incoming "
                                "origins against a strict allowlist of explicitly trusted domain names."
                            ),
                            confidence="high",
                        )
                    )
                else:
                    page_findings.append(
                        _build_finding(
                            title="CORS Policy Allows 'null' Origin",
                            severity="low",
                            affected_url=sanitized_url,
                            description=(
                                "The response specifies 'Access-Control-Allow-Origin: null'. While credentials are not "
                                "permitted, allowing the 'null' origin enables sandboxed frames or local file schemes "
                                "to read response data. Trusting the 'null' origin is generally unintended and discouraged."
                            ),
                            evidence="Access-Control-Allow-Origin: null",
                            recommendation=(
                                "Avoid configuring 'null' in Access-Control-Allow-Origin. Specify explicit trusted domain "
                                "names, or use '*' if the endpoint is intended to be unauthenticated and public."
                            ),
                            confidence="high",
                        )
                    )
            else:
                # Explicit origin evaluation
                parsed_acao = urlsplit(acao_trimmed)
                acao_scheme = parsed_acao.scheme.lower()
                acao_origin_triple = _extract_origin_triple(acao_trimmed)

                # Check for malformed origin containing path or trailing slash
                if acao_trimmed.endswith("/") or (parsed_acao.path and parsed_acao.path != "/"):
                    page_findings.append(
                        _build_finding(
                            title="Malformed Access-Control-Allow-Origin Header: Path or Trailing Slash Present",
                            severity="low",
                            affected_url=sanitized_url,
                            description=(
                                f"The 'Access-Control-Allow-Origin' header ('{safe_acao}') contains a path or trailing slash. "
                                "The CORS specification requires origins to consist strictly of scheme, host, and optional "
                                "port without path components. Browsers will fail to match this origin, blocking cross-origin requests."
                            ),
                            evidence=f"Access-Control-Allow-Origin: {safe_acao}",
                            recommendation=(
                                "Format origins strictly as scheme://host[:port] without any trailing slash or path components."
                            ),
                            confidence="high",
                        )
                    )

                # Check if origin is reflected from the request Origin header
                is_reflected = False
                if req_origin:
                    req_orig_clean = req_origin.strip()
                    if acao_trimmed.lower() == req_orig_clean.lower():
                        is_reflected = True

                if is_reflected:
                    safe_req = _sanitize_evidence_string(req_origin or "")
                    if is_credentials:
                        page_findings.append(
                            _build_finding(
                                title="Reflected Origin With Credentials Allowed",
                                severity="medium",
                                affected_url=sanitized_url,
                                description=(
                                    f"The server reflected the incoming request 'Origin' header ('{safe_req}') in "
                                    "'Access-Control-Allow-Origin' alongside 'Access-Control-Allow-Credentials: true'. "
                                    "Based solely on passive crawler records without active arbitrary-origin probing, it cannot "
                                    "be confirmed whether the server strictly validates origins against an allowlist or dynamically "
                                    "mirrors untrusted origins. If arbitrary origins are reflected, third-party sites could issue "
                                    "authenticated cross-origin requests and read sensitive responses."
                                ),
                                evidence=(
                                    f"Access-Control-Allow-Origin: {safe_acao}; "
                                    f"Access-Control-Allow-Credentials: true "
                                    f"(matches request Origin: {safe_req})"
                                ),
                                recommendation=(
                                    "Validate incoming Origin headers against a strict, static server-side allowlist of trusted "
                                    "origins before returning Access-Control-Allow-Origin. Do not dynamically mirror unvalidated "
                                    "origins when credentials are enabled."
                                ),
                                confidence="high",
                            )
                        )
                    else:
                        page_findings.append(
                            _build_finding(
                                title="Reflected Origin in Access-Control-Allow-Origin",
                                severity="low",
                                affected_url=sanitized_url,
                                description=(
                                    f"The server reflected the incoming request 'Origin' header ('{safe_req}') in "
                                    "'Access-Control-Allow-Origin'. While credentials are not permitted on cross-origin requests, "
                                    "dynamically reflecting origins without strict allowlist verification may expose unauthenticated "
                                    "data to arbitrary external domains."
                                ),
                                evidence=(
                                    f"Access-Control-Allow-Origin: {safe_acao} "
                                    f"(matches request Origin: {safe_req})"
                                ),
                                recommendation=(
                                    "Verify that origin reflection is strictly controlled by an allowlist of approved domains."
                                ),
                                confidence="medium",
                            )
                        )
                elif page_scheme == "https" and acao_scheme == "http":
                    # Insecure HTTP origin on HTTPS resource
                    if is_credentials:
                        page_findings.append(
                            _build_finding(
                                title="Insecure HTTP Origin Allowed With Credentials in CORS",
                                severity="medium",
                                affected_url=sanitized_url,
                                description=(
                                    f"The HTTPS endpoint permits credentialed cross-origin requests from an insecure HTTP origin "
                                    f"('{safe_acao}'). An active network attacker positioned on the unencrypted HTTP connection "
                                    "could intercept or tamper with traffic on that origin and leverage CORS permissions to access "
                                    "sensitive credentialed responses from this HTTPS endpoint."
                                ),
                                evidence=f"Access-Control-Allow-Origin: {safe_acao}; Access-Control-Allow-Credentials: true",
                                recommendation=(
                                    "Restrict CORS origins to HTTPS schemes. Do not allow unencrypted HTTP origins to access "
                                    "HTTPS endpoints."
                                ),
                                confidence="high",
                            )
                        )
                    else:
                        page_findings.append(
                            _build_finding(
                                title="Insecure HTTP Origin Allowed in CORS Policy",
                                severity="low",
                                affected_url=sanitized_url,
                                description=(
                                    f"The HTTPS endpoint permits cross-origin requests from an unencrypted HTTP origin ('{safe_acao}'). "
                                    "Communications on unencrypted HTTP can be intercepted or manipulated by network attackers."
                                ),
                                evidence=f"Access-Control-Allow-Origin: {safe_acao}",
                                recommendation=(
                                    "Require HTTPS for all cross-origin access by updating the allowed origin to use the 'https://' scheme."
                                ),
                                confidence="high",
                            )
                        )
                elif is_credentials and acao_origin_triple is not None and page_origin_triple is not None:
                    # Credentialed cross-origin access to an external domain (not same origin)
                    if not _is_same_origin(acao_origin_triple, page_origin_triple):
                        page_findings.append(
                            _build_finding(
                                title="Credentialed Cross-Origin Access Permitted",
                                severity="low",
                                affected_url=sanitized_url,
                                description=(
                                    f"The endpoint permits credentialed cross-origin access from external origin '{safe_acao}' "
                                    "('Access-Control-Allow-Credentials: true'). While credentialed sharing is appropriate for "
                                    "trusted partner or subsidiary domains, any compromise of the allowed origin could permit "
                                    "cross-origin access to authenticated data. Confirm that this external domain is explicitly "
                                    "authorized and requires access."
                                ),
                                evidence=f"Access-Control-Allow-Origin: {safe_acao}; Access-Control-Allow-Credentials: true",
                                recommendation=(
                                    f"Review cross-origin access permissions for '{safe_acao}'. Ensure that credentialed access is "
                                    "strictly required and that the external domain enforces robust security controls."
                                ),
                                confidence="medium",
                            )
                        )

                # Check for missing Vary: Origin header on explicit origin responses
                vary_tokens = _parse_vary_tokens(raw_vary or "")
                if "origin" not in vary_tokens and "*" not in vary_tokens:
                    safe_vary = _sanitize_evidence_string(raw_vary or "absent")
                    page_findings.append(
                        _build_finding(
                            title="CORS Response Missing 'Vary: Origin' Header",
                            severity="low",
                            affected_url=sanitized_url,
                            description=(
                                f"The response specifies an explicit origin in 'Access-Control-Allow-Origin' ('{safe_acao}') "
                                "but does not include 'Vary: Origin'. Intermediate caches, CDNs, and browsers may cache this "
                                "response and incorrectly serve it to subsequent requests from different origins, leading to "
                                "cache poisoning or broken CORS behavior."
                            ),
                            evidence=f"Access-Control-Allow-Origin: {safe_acao}; Vary header: '{safe_vary}'",
                            recommendation=(
                                "Add 'Vary: Origin' to response headers whenever Access-Control-Allow-Origin is set to a "
                                "specific origin or dynamically generated based on the request."
                            ),
                            confidence="high",
                        )
                    )

        # Deduplicate findings across pages for the same issue, evidence, and host
        for finding in page_findings:
            issue_title = finding["title"]
            evidence_str = finding["evidence"]
            issue_key = (issue_title, evidence_str, page_host)
            if issue_key in seen_issues:
                continue
            seen_issues.add(issue_key)
            findings.append(finding)

    return findings
