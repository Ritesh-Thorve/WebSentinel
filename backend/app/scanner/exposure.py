"""Sensitive resource exposure scanner for WebSentinel."""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

# Sensitive query parameter names whose values must be redacted in affected_url
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

# Common soft 404 and error page signatures
SOFT_404_PHRASES = (
    "404 not found",
    "page not found",
    "404 error",
    "error 404",
    "not found on this server",
    "the requested url was not found",
    "cannot get /",
    "route not found",
    "resource not found",
    "the page you are looking for",
    "does not exist",
    "no route matches",
    "page doesn't exist",
    "file not found",
)

# Directory listing title / heading patterns
DIRECTORY_TITLE_REGEX = re.compile(
    r"<title[^>]*>(?:\s*Index\s+of\s+([^<]+)|\s*Directory\s+listing\s+(?:for|--)\s+([^<]+))</title>",
    re.IGNORECASE,
)
DIRECTORY_H1_REGEX = re.compile(
    r"<h1[^>]*>(?:\s*Index\s+of\s+([^<]+)|\s*Directory\s+listing\s+(?:for|--)\s+([^<]+))</h1>",
    re.IGNORECASE,
)

# Configuration filenames
EXACT_CONFIG_FILES = {
    "web.config",
    "web.config.bak",
    "docker-compose.yml",
    "docker-compose.yaml",
    "docker-compose.override.yml",
    "dockerfile",
    "wp-config.php.bak",
    "wp-config.old",
    "wp-config.save",
    "wp-config.php.txt",
    "wp-config.php~",
    "configuration.php.bak",
    "configuration.php.old",
    "settings.py.bak",
    "settings.py.old",
    "appsettings.json",
    "appsettings.development.json",
    "server.xml",
    "context.xml",
}

# Cryptographic key filenames
KEY_FILENAMES = {
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "server.key",
    "private.key",
    "privkey.pem",
    "key.pem",
    "cert.key",
    "ssl.key",
}

# Backup extensions
BACKUP_EXTENSIONS = (
    ".bak",
    ".backup",
    ".old",
    ".orig",
    ".save",
    "~",
    ".swp",
    ".swo",
)

# Database keywords
DB_KEYWORDS = ("dump", "backup", "database", "schema", "users", "data", "db")


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
    """Extract clean MIME type without parameters for safe inclusion in evidence."""
    if not ct:
        return "unspecified"
    parts = ct.split(";")
    mime = parts[0].strip().lower()
    clean = "".join(ch for ch in mime if ch.isprintable() and ch not in "\r\n\t")
    return clean[:50] if clean else "unspecified"


def _is_html_response(content_type: str, body: str) -> bool:
    """Determine whether the response content represents an HTML document."""
    ct = content_type.lower().strip()
    if ct:
        if "text/html" in ct or "application/xhtml+xml" in ct:
            return True

    if body:
        lower_body = body[:1000].lower().strip()
        if (
            "<!doctype html" in lower_body
            or "<html" in lower_body
            or "<head" in lower_body
            or "<body" in lower_body
        ):
            return True

    return False


def _is_soft_404(body: str) -> bool:
    """Check whether the response body indicates a soft 404 or custom error response."""
    if not body:
        return True

    trimmed = body.strip()
    if not trimmed:
        return True

    lower_preview = trimmed[:1000].lower()
    if len(trimmed) < 300:
        if any(phrase in lower_preview for phrase in SOFT_404_PHRASES):
            return True

    if lower_preview.startswith("cannot get /") or lower_preview.startswith("error: not found"):
        return True

    return False


def _detect_directory_listing(body: str) -> str | None:
    """Identify directory listing indicators from response body."""
    if not body:
        return None

    preview = body[:4000]
    lower_preview = preview.lower()

    # Pattern 1: Title matching Index of / Directory listing
    title_match = DIRECTORY_TITLE_REGEX.search(preview)
    if title_match:
        dir_name = title_match.group(1) or title_match.group(2) or ""
        clean_dir = "".join(ch for ch in dir_name.strip() if ch.isprintable())[:60]
        return f"Index of {clean_dir}" if clean_dir else "Index of directory"

    # Pattern 2: H1 heading matching Index of / Directory listing
    h1_match = DIRECTORY_H1_REGEX.search(preview)
    if h1_match:
        dir_name = h1_match.group(1) or h1_match.group(2) or ""
        clean_dir = "".join(ch for ch in dir_name.strip() if ch.isprintable())[:60]
        return f"Index of {clean_dir}" if clean_dir else "Index of directory"

    # Pattern 3: IIS Directory Browsing
    if "[to parent directory]" in lower_preview and (
        "&lt;dir&gt;" in lower_preview or "<dir>" in lower_preview or "directory listing --" in lower_preview
    ):
        return "IIS Directory Listing ([To Parent Directory])"

    # Pattern 4: Apache / Nginx table or pre listing with navigation
    if "index of /" in lower_preview and (
        "parent directory" in lower_preview
        or '<a href="../">' in lower_preview
        or '<a href="/">' in lower_preview
    ):
        return "Index of / with Parent Directory navigation"

    return None


def _check_directory_listing(
    sanitized_url: str,
    path: str,
    content_type: str,
    body: str,
    status_code: int,
) -> dict[str, str] | None:
    """Inspect whether a response represents an enabled directory listing."""
    indicator = _detect_directory_listing(body)
    if not indicator:
        return None

    # Check that it's not a soft 404
    if _is_soft_404(body):
        return None

    evidence_path = path if path else "/"
    return _build_finding(
        title="Directory Listing Enabled",
        severity="low",
        affected_url=sanitized_url,
        description=(
            "The web server has directory indexing enabled on this path. When directory browsing is "
            "enabled and no default index document (such as index.html) is present, the server displays "
            "directory contents, potentially exposing sensitive files, source code, or internal assets."
        ),
        evidence=(
            f"Directory listing indicator ('{indicator}') observed at '{evidence_path}' "
            f"with HTTP status {status_code}"
        ),
        recommendation=(
            "Disable directory browsing in the web server configuration (e.g. 'Options -Indexes' in "
            "Apache, 'autoindex off' in Nginx, or disabling Directory Browsing in IIS)."
        ),
        confidence="medium",
    )


def _check_sensitive_file(
    sanitized_url: str,
    path: str,
    content_type: str,
    body: str,
    status_code: int,
) -> dict[str, str] | None:
    """Inspect whether a requested URL corresponds to an exposed sensitive file."""
    if not path or path == "/":
        return None

    clean_path = path.strip()
    filename = os.path.basename(clean_path.rstrip("/"))
    filename_lower = filename.lower()
    path_lower = clean_path.lower()
    evidence_path = clean_path[:100]
    safe_ct = _clean_content_type(content_type)

    # 1. Environment Configuration Files
    is_sample_env = filename_lower in {
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.dist",
        ".env.test.example",
    }
    is_env_file = (
        filename_lower == ".env"
        or filename_lower.startswith(".env.")
        or path_lower.endswith("/.env")
        or "/.env." in path_lower
    )

    if is_env_file:
        if _is_html_response(content_type, body) or _is_soft_404(body):
            return None

        if is_sample_env:
            return _build_finding(
                title="Exposed Sample Environment File",
                severity="informational",
                affected_url=sanitized_url,
                description=(
                    "A sample environment template file (.env.example or similar) is publicly accessible. "
                    "While sample files usually contain placeholder values, they can reveal expected configuration keys, "
                    "internal service names, and application architecture."
                ),
                evidence=f"Sample environment file accessible at '{evidence_path}' with HTTP status {status_code} and Content-Type '{safe_ct}'",
                recommendation="Remove sample configuration files from public web directories or configure web server rules to deny access to .env* files.",
                confidence="low",
            )

        return _build_finding(
            title="Potentially Exposed Environment Configuration File",
            severity="medium",
            affected_url=sanitized_url,
            description=(
                "An environment configuration file (.env) appears to be publicly accessible. "
                "Environment files typically contain sensitive secrets such as database credentials, "
                "API tokens, encryption keys, and service passwords."
            ),
            evidence=f"Environment configuration file accessible at '{evidence_path}' with HTTP status {status_code} and Content-Type '{safe_ct}'",
            recommendation=(
                "Immediately restrict access to all .env files in the web server configuration, place configuration "
                "files outside the public web root, and rotate any credentials that may have been exposed."
            ),
            confidence="medium",
        )

    # 2. Version Control Metadata
    is_git_file = (
        "/.git/" in path_lower
        or path_lower.endswith("/.git")
        or filename_lower in {".gitignore", ".gitmodules"}
    )
    is_svn_file = "/.svn/" in path_lower or path_lower.endswith("/.svn")
    is_hg_file = "/.hg/" in path_lower or path_lower.endswith("/.hg")
    is_bzr_file = "/.bzr/" in path_lower or path_lower.endswith("/.bzr")

    if is_git_file or is_svn_file or is_hg_file or is_bzr_file:
        if _is_html_response(content_type, body) or _is_soft_404(body):
            return None

        if filename_lower in {".gitignore", ".gitmodules"}:
            return _build_finding(
                title="Exposed Version Control Configuration File",
                severity="informational",
                affected_url=sanitized_url,
                description=(
                    "A version control configuration file (.gitignore or .gitmodules) is publicly accessible. "
                    "This may reveal internal directory structures, hidden paths, or submodule repository URLs."
                ),
                evidence=f"Version control configuration file accessible at '{evidence_path}' with HTTP status {status_code} and Content-Type '{safe_ct}'",
                recommendation="Block access to dotfiles and version control metadata in the web server configuration.",
                confidence="low",
            )

        return _build_finding(
            title="Exposed Version Control Repository Metadata",
            severity="medium",
            affected_url=sanitized_url,
            description=(
                "Version control repository metadata (.git, .svn, .hg) is publicly accessible on the web server. "
                "Exposed repository metadata can allow attackers to download application source code, commit history, "
                "and embedded configuration secrets."
            ),
            evidence=f"Version control artifact accessible at '{evidence_path}' with HTTP status {status_code} and Content-Type '{safe_ct}'",
            recommendation="Deny all access to version control directories (.git, .svn, .hg) in web server rules and ensure these directories are excluded from deployment.",
            confidence="medium",
        )

    # 3. Database Dumps and Exports
    is_db_dump = (
        any(filename_lower.endswith(ext) for ext in (".sql", ".sqlite", ".sqlite3"))
        or (filename_lower.endswith(".db") and any(kw in filename_lower for kw in DB_KEYWORDS))
        or any(filename_lower.endswith(ext) for ext in (".sql.gz", ".sql.bz2", ".sql.tar", ".sql.zip"))
        or filename_lower in {"database.zip", "db.zip", "dump.zip", "backup.sql.zip", "backup_db.zip"}
    )

    if is_db_dump:
        if _is_html_response(content_type, body) or _is_soft_404(body):
            return None

        return _build_finding(
            title="Potentially Exposed Database Backup or Dump File",
            severity="medium",
            affected_url=sanitized_url,
            description=(
                "A database dump or backup file was observed to be publicly accessible. Database exports frequently "
                "contain sensitive schema details, user records, password hashes, and proprietary data."
            ),
            evidence=f"Database backup artifact accessible at '{evidence_path}' with HTTP status {status_code} and Content-Type '{safe_ct}'",
            recommendation="Remove database exports from public document roots and store backups in encrypted, access-controlled offline storage.",
            confidence="medium",
        )

    # 4. Cryptographic Keys and Certificates
    is_public_key = filename_lower in {"id_rsa.pub", "id_dsa.pub", "id_ecdsa.pub", "id_ed25519.pub"}
    is_private_key = (
        filename_lower in KEY_FILENAMES
        or (
            filename_lower.endswith((".key", ".pem", ".pfx", ".pkcs12"))
            and any(sub in filename_lower for sub in ("private", "priv", "server", "ssl", "key"))
        )
    )

    if is_public_key:
        if _is_html_response(content_type, body) or _is_soft_404(body):
            return None

        return _build_finding(
            title="Exposed Public Key File",
            severity="informational",
            affected_url=sanitized_url,
            description=(
                "An SSH or cryptographic public key file was observed to be publicly accessible. While public keys do not "
                "contain secret material, their presence may indicate misplaced credential files or disclose user and host identifiers."
            ),
            evidence=f"Public key artifact accessible at '{evidence_path}' with HTTP status {status_code} and Content-Type '{safe_ct}'",
            recommendation="Remove unnecessary public key files from web-accessible directories.",
            confidence="low",
        )

    if is_private_key:
        if _is_html_response(content_type, body) or _is_soft_404(body):
            return None

        return _build_finding(
            title="Potentially Exposed Cryptographic Key File",
            severity="medium",
            affected_url=sanitized_url,
            description=(
                "A private cryptographic key or certificate container was observed to be publicly accessible. Compromise of "
                "private keys can lead to identity spoofing, decryption of TLS traffic, or unauthorized SSH access."
            ),
            evidence=f"Cryptographic key artifact accessible at '{evidence_path}' with HTTP status {status_code} and Content-Type '{safe_ct}'",
            recommendation="Immediately remove private key files from public directories, revoke any exposed keys and certificates, and generate replacement keypairs.",
            confidence="medium",
        )

    # 5. Application and Server Configuration Files
    is_config_file = (
        filename_lower in EXACT_CONFIG_FILES
        or (
            filename_lower in {"config.json", "config.yml", "config.yaml", "config.ini", "settings.json"}
            and (clean_path.count("/") <= 2 or "/config/" in path_lower or "/settings/" in path_lower)
        )
    )

    if is_config_file:
        if _is_html_response(content_type, body) or _is_soft_404(body):
            return None

        return _build_finding(
            title="Potentially Exposed Application Configuration File",
            severity="medium",
            affected_url=sanitized_url,
            description=(
                "An application or server configuration file was observed to be publicly accessible. Configuration files "
                "often reveal internal infrastructure settings, component versions, connection strings, or architectural details."
            ),
            evidence=f"Configuration file accessible at '{evidence_path}' with HTTP status {status_code} and Content-Type '{safe_ct}'",
            recommendation="Store application and server configuration files outside the web document root and configure web server rules to deny requests to configuration files.",
            confidence="medium",
        )

    # 6. Backup and Temporary Files
    is_backup_file = any(filename_lower.endswith(ext) for ext in BACKUP_EXTENSIONS)

    if is_backup_file:
        if _is_html_response(content_type, body) or _is_soft_404(body):
            return None

        return _build_finding(
            title="Potentially Exposed Backup or Temporary File",
            severity="low",
            affected_url=sanitized_url,
            description=(
                "A backup, editor swap, or temporary file copy was observed to be publicly accessible. Backup files "
                "(such as *.bak, *.old, or *~) often bypass server-side execution handlers and disclose unrendered "
                "source code or sensitive configuration parameters."
            ),
            evidence=f"Backup or temporary artifact accessible at '{evidence_path}' with HTTP status {status_code} and Content-Type '{safe_ct}'",
            recommendation="Remove backup and temporary files from the web server document root and configure the web server to prohibit access to backup file extensions.",
            confidence="medium",
        )

    # 7. Server and Application Log Files
    is_log_file = (
        filename_lower.endswith(".log")
        or filename_lower.endswith(".out")
    ) and any(
        kw in filename_lower
        for kw in ("log", "out", "error", "access", "debug", "app", "catalina", "server", "production", "dev")
    )

    if is_log_file:
        if _is_html_response(content_type, body) or _is_soft_404(body):
            return None

        return _build_finding(
            title="Potentially Exposed Server or Application Log File",
            severity="low",
            affected_url=sanitized_url,
            description=(
                "A server or application log file was observed to be publicly accessible. Log files frequently record "
                "sensitive operational data, stack traces, internal IP addresses, user activity, or system parameters."
            ),
            evidence=f"Server or application log file accessible at '{evidence_path}' with HTTP status {status_code} and Content-Type '{safe_ct}'",
            recommendation="Configure log directories outside the public web root and add web server rules to forbid access to .log and .out files.",
            confidence="medium",
        )

    return None


def check_exposure(pages: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Identify potentially exposed sensitive resources from collected page records.

    Inspects URLs, response status codes, headers, and bodies already gathered by the crawler
    to detect exposed environment files, version control metadata, database backups, cryptographic
    keys, configuration files, logs, and directory listings. Does not initiate external network calls,
    brute-force paths, or inspect response contents for secret values.

    Args:
        pages: List of crawled page records containing 'url', 'status_code', 'headers',
               'body', and optional 'content_type'.

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
        if not raw_url:
            continue

        sanitized_url = _sanitize_url(raw_url)
        if not sanitized_url:
            continue

        # Distinguish missing from potentially exposed: must be successful response
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

        parsed = urlsplit(sanitized_url)
        path = unquote(parsed.path or "/")

        # Check for exposed sensitive files
        file_finding = _check_sensitive_file(
            sanitized_url=sanitized_url,
            path=path,
            content_type=content_type,
            body=body,
            status_code=status_code,
        )
        if file_finding:
            key = (file_finding["title"], file_finding["affected_url"])
            if key not in seen_issues:
                seen_issues.add(key)
                findings.append(file_finding)

        # Check for enabled directory listings
        listing_finding = _check_directory_listing(
            sanitized_url=sanitized_url,
            path=path,
            content_type=content_type,
            body=body,
            status_code=status_code,
        )
        if listing_finding:
            key = (listing_finding["title"], listing_finding["affected_url"])
            if key not in seen_issues:
                seen_issues.add(key)
                findings.append(listing_finding)

    return findings


__all__ = ["check_exposure"]
