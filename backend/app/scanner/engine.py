"""WebSentinel security scanner orchestration layer."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

try:
    from app.schemas import Finding, ScanResponse, ScanSummary
    from app.scanner.crawler import (
        DEFAULT_MAX_BODY_BYTES,
        DEFAULT_MAX_PAGES,
        DEFAULT_MAX_REQUESTS,
        DEFAULT_TIMEOUT,
        SSRFError,
        crawl_target,
        sanitize_url_for_logging,
        validate_url_safety,
    )
    from app.scanner.headers import check_headers
    from app.scanner.cookies import check_cookies
    from app.scanner.cors import check_cors
    from app.scanner.exposure import check_exposure
    from app.scanner.reflection import check_reflection
except ImportError:
    from ..schemas import Finding, ScanResponse, ScanSummary  # type: ignore[no-redef]
    from .crawler import (  # type: ignore[no-redef]
        DEFAULT_MAX_BODY_BYTES,
        DEFAULT_MAX_PAGES,
        DEFAULT_MAX_REQUESTS,
        DEFAULT_TIMEOUT,
        SSRFError,
        crawl_target,
        sanitize_url_for_logging,
        validate_url_safety,
    )
    from .headers import check_headers  # type: ignore[no-redef]
    from .cookies import check_cookies  # type: ignore[no-redef]
    from .cors import check_cors  # type: ignore[no-redef]
    from .exposure import check_exposure  # type: ignore[no-redef]
    from .reflection import check_reflection  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

DEFAULT_TOTAL_TIMEOUT = float(
    os.getenv("WEBSENTINEL_TOTAL_TIMEOUT", os.getenv("WEBSENTINEL_SCAN_TIMEOUT", "60.0"))
)


def compute_summary(findings: list[Finding]) -> ScanSummary:
    """Calculate aggregated severity statistics for validated findings.

    Args:
        findings: List of validated Finding model instances.

    Returns:
        ScanSummary with counts per severity level and total findings.
    """
    counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }
    for finding in findings:
        sev = finding.severity.lower() if isinstance(finding.severity, str) else ""
        if sev in counts:
            counts[sev] += 1
        else:
            logger.warning("Unrecognized severity level observed: %s", sev)

    return ScanSummary(
        total_findings=len(findings),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        informational=counts["informational"],
    )


async def _execute_scan(
    target_url: str,
    max_pages: int,
    max_requests: int,
    timeout: float,
    max_body_bytes: int,
) -> ScanResponse:
    """Execute crawl and run all security check modules, merging findings safely."""
    # 1. Safely collect pages using same-origin crawler with SSRF protection
    pages = await crawl_target(
        target_url=target_url,
        max_pages=max_pages,
        max_requests=max_requests,
        timeout=timeout,
        max_body_bytes=max_body_bytes,
    )

    # 2. Pass collected page records to check modules
    checker_modules = (
        ("headers", check_headers),
        ("cookies", check_cookies),
        ("cors", check_cors),
        ("exposure", check_exposure),
        ("reflection", check_reflection),
    )

    raw_findings: list[Finding] = []

    for module_name, checker_func in checker_modules:
        try:
            results: Any = checker_func(pages)
            if not isinstance(results, list):
                logger.warning(
                    "Module '%s' returned non-list result: %s",
                    module_name,
                    type(results).__name__,
                )
                continue

            for item in results:
                try:
                    if isinstance(item, Finding):
                        raw_findings.append(item)
                    elif isinstance(item, dict):
                        raw_findings.append(Finding.model_validate(item))
                    else:
                        logger.warning(
                            "Module '%s' yielded unsupported finding type: %s",
                            module_name,
                            type(item).__name__,
                        )
                except ValidationError as val_err:
                    logger.warning(
                        "Validation error in finding from module '%s': %s",
                        module_name,
                        type(val_err).__name__,
                    )
        except Exception as exc:
            logger.warning(
                "Check module '%s' failed during scan: %s",
                module_name,
                type(exc).__name__,
            )

    # 3. Deduplicate equivalent findings using a stable key
    deduplicated_findings: list[Finding] = []
    seen_keys: set[tuple[str, str, str]] = set()

    for finding in raw_findings:
        key = (
            finding.title.strip(),
            finding.affected_url.strip(),
            finding.evidence.strip(),
        )
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduplicated_findings.append(finding)

    # 4. Generate accurate severity summary
    summary = compute_summary(deduplicated_findings)

    # 5. Return completed ScanResponse
    return ScanResponse(
        target_url=target_url,
        status="completed",
        findings=deduplicated_findings,
        summary=summary,
    )


async def scan_target(
    target_url: str,
    max_pages: int | None = None,
    max_requests: int | None = None,
    timeout: float | None = None,
    max_body_bytes: int | None = None,
    total_timeout: float | None = None,
) -> ScanResponse:
    """Orchestrate security scan on target URL.

    Args:
        target_url: Web address to scan (must start with http:// or https://).
        max_pages: Maximum pages to crawl.
        max_requests: Maximum HTTP requests allowed.
        timeout: Request timeout in seconds.
        max_body_bytes: Maximum body bytes to process per response.
        total_timeout: Maximum total duration in seconds for the scan.

    Returns:
        ScanResponse with completed status, deduplicated findings, and severity summary.

    Raises:
        ValueError: If target URL syntax is invalid.
        SSRFError: If target points to private/restricted addresses.
        TimeoutError: If scan runtime exceeds total_timeout.
    """
    if not isinstance(target_url, str):
        raise ValueError("Target URL must be a string")

    trimmed = target_url.strip()
    if not trimmed:
        raise ValueError("Target URL cannot be empty")

    parsed = urlsplit(trimmed)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(f"Target scheme must be http or https, got '{parsed.scheme}'")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("Target network location cannot be empty")
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValueError("Target port must be between 1 and 65535")

    validate_url_safety(trimmed)

    eff_max_pages = max_pages if max_pages is not None else DEFAULT_MAX_PAGES
    eff_max_requests = max_requests if max_requests is not None else DEFAULT_MAX_REQUESTS
    eff_timeout = timeout if timeout is not None else DEFAULT_TIMEOUT
    eff_max_body_bytes = max_body_bytes if max_body_bytes is not None else DEFAULT_MAX_BODY_BYTES
    eff_total_timeout = total_timeout if total_timeout is not None else DEFAULT_TOTAL_TIMEOUT

    eff_max_pages = max(1, eff_max_pages)
    eff_max_requests = max(1, eff_max_requests)
    eff_timeout = max(0.1, eff_timeout)
    eff_max_body_bytes = max(1024, eff_max_body_bytes)
    eff_total_timeout = max(0.1, eff_total_timeout)

    logger.info("Starting security scan for target: %s", sanitize_url_for_logging(trimmed))

    try:
        return await asyncio.wait_for(
            _execute_scan(
                target_url=trimmed,
                max_pages=eff_max_pages,
                max_requests=eff_max_requests,
                timeout=eff_timeout,
                max_body_bytes=eff_max_body_bytes,
            ),
            timeout=eff_total_timeout,
        )
    except (asyncio.TimeoutError, TimeoutError):
        logger.warning(
            "Scan runtime limit of %.1fs exceeded for target: %s",
            eff_total_timeout,
            sanitize_url_for_logging(trimmed),
        )
        raise TimeoutError(f"Scan timed out after {eff_total_timeout:.1f} seconds") from None


__all__ = ["scan_target", "compute_summary"]
