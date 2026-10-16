"""API routes for WebSentinel vulnerability scanning."""

import ipaddress
import logging
import socket
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, status

from app.scanner.engine import scan_target
from app.schemas import Finding, ScanRequest, ScanResponse, ScanSummary

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scans"])

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


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Determine whether an IP address belongs to a private or restricted space."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_target_url(target_url: str) -> str:
    """Validate target URL syntax and enforce destination safety."""
    if not isinstance(target_url, str):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Target URL must be a string",
        )

    trimmed = target_url.strip()
    if not trimmed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Target URL cannot be empty",
        )

    try:
        parsed = urlsplit(trimmed)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Malformed target URL",
        ) from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Target scheme must be http or https",
        )

    if not parsed.netloc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Target network location cannot be empty",
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Target hostname cannot be empty",
        )

    try:
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Port must be between 1 and 65535",
            )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid port specification",
        ) from exc

    lower_host = hostname.lower().strip("[]")
    if lower_host in BLOCKED_HOSTNAMES or lower_host.endswith(BLOCKED_SUFFIXES):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Blocked destination: access to local or internal targets is restricted",
        )

    try:
        ip = ipaddress.ip_address(lower_host)
        if _is_blocked_ip(ip):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Blocked destination: access to private or restricted IP addresses is not allowed",
            )
        return trimmed
    except ValueError:
        pass

    try:
        addr_infos = socket.getaddrinfo(lower_host, None)
        for _, _, _, _, sockaddr in addr_infos:
            ip_str = sockaddr[0]
            resolved_ip = ipaddress.ip_address(ip_str)
            if _is_blocked_ip(resolved_ip):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Blocked destination: target resolves to a private or restricted address",
                )
    except socket.gaierror:
        pass
    except HTTPException:
        raise
    except Exception:
        pass

    return trimmed


def _compute_summary(findings: list[Finding]) -> ScanSummary:
    """Calculate summary statistics grouped by severity level."""
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }
    for finding in findings:
        sev = getattr(finding, "severity", None)
        if isinstance(finding, dict):
            sev = finding.get("severity")
        if sev in counts:
            counts[sev] += 1

    return ScanSummary(
        total_findings=len(findings),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        informational=counts["informational"],
    )


@router.post(
    "/api/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Initiate security scan",
    description="Scan a target URL for security vulnerabilities and misconfigurations.",
)
@router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
async def create_scan(request: ScanRequest) -> ScanResponse:
    """Validate target URL and run security inspection asynchronously."""
    validated_url = validate_target_url(request.target_url)

    try:
        scan_result = await scan_target(validated_url)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid target URL",
        ) from exc
    except Exception as exc:
        exc_type = type(exc).__name__.lower()
        exc_msg = str(exc).lower()

        if any(
            keyword in exc_type or keyword in exc_msg
            for keyword in ("blocked", "ssrf", "forbidden", "restricted", "private")
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Blocked destination: access to private or restricted targets is not allowed",
            ) from exc

        if any(
            keyword in exc_type or keyword in exc_msg
            for keyword in ("invalid", "url", "malformed", "syntax")
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid target URL",
            ) from exc

        logger.error("Scan execution failed due to an unexpected error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while processing the scan.",
        ) from None

    if isinstance(scan_result, ScanResponse):
        return scan_result

    findings: list[Finding] = []
    if isinstance(scan_result, list):
        findings = [
            f if isinstance(f, Finding) else Finding.model_validate(f)
            for f in scan_result
        ]
    elif isinstance(scan_result, dict):
        return ScanResponse.model_validate(scan_result)

    summary = _compute_summary(findings)
    return ScanResponse(
        target_url=validated_url,
        status="completed",
        findings=findings,
        summary=summary,
    )
