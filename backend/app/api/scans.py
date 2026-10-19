"""API routes for WebSentinel vulnerability scanning."""

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass
from uuid import uuid4
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, status

from app.scanner.crawler import (
    BLOCKED_HOSTNAMES,
    BLOCKED_SUFFIXES,
    SSRFError,
    TargetUnavailableError,
    is_blocked_ip,
)
from app.scanner.engine import scan_target
from app.schemas import ScanRequest, ScanResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scans"])


@dataclass
class ScanJob:
    scan_id: str
    target_url: str
    cancel_event: asyncio.Event
    response: ScanResponse
    task: asyncio.Task[None] | None = None


scan_jobs: dict[str, ScanJob] = {}


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
        if is_blocked_ip(ip):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Blocked destination: access to private or restricted IP addresses is not allowed",
            )
        return trimmed
    except ValueError:
        pass

    try:
        addr_infos = socket.getaddrinfo(lower_host, None)
        if not addr_infos:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Blocked destination: target '{hostname}' has no address records",
            )
        for _, _, _, _, sockaddr in addr_infos:
            ip_str = sockaddr[0]
            try:
                resolved_ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if is_blocked_ip(resolved_ip):
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


async def _execute_scan_job(job: ScanJob) -> None:
    try:
        result = await scan_target(job.target_url, cancel_event=job.cancel_event)
        result.scan_id = job.scan_id
        job.response = result
    except SSRFError as exc:
        job.response = ScanResponse(
            scan_id=job.scan_id,
            target_url=job.target_url,
            status="failed",
            error=str(exc) or "The target resolves to a restricted address.",
        )
    except TargetUnavailableError as exc:
        job.response = ScanResponse(
            scan_id=job.scan_id,
            target_url=job.target_url,
            status="failed",
            error="The target could not be reached, so its security checks could not be completed.",
        )
    except (asyncio.TimeoutError, TimeoutError) as exc:
        job.response = ScanResponse(
            scan_id=job.scan_id,
            target_url=job.target_url,
            status="failed",
            error=f"Scan timed out before completion: {exc}",
        )
    except ValueError as exc:
        job.response = ScanResponse(
            scan_id=job.scan_id,
            target_url=job.target_url,
            status="failed",
            error=str(exc) or "Invalid target URL",
        )
    except Exception as exc:
        logger.error("Scan execution failed due to an unexpected error: %s", type(exc).__name__)
        job.response = ScanResponse(
            scan_id=job.scan_id,
            target_url=job.target_url,
            status="failed",
            error="An unexpected error occurred while processing the scan.",
        )


@router.post(
    "/api/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start security scan",
    description="Start a scan and return an identifier for progress and cancellation.",
)
@router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    include_in_schema=False,
)
async def create_scan(request: ScanRequest) -> ScanResponse:
    """Validate the target and start a cancellable background scan."""
    validated_url = validate_target_url(request.target_url)
    scan_id = uuid4().hex
    job = ScanJob(
        scan_id=scan_id,
        target_url=validated_url,
        cancel_event=asyncio.Event(),
        response=ScanResponse(
            scan_id=scan_id,
            target_url=validated_url,
            status="running",
        ),
    )
    scan_jobs[scan_id] = job
    job.task = asyncio.create_task(_execute_scan_job(job))
    return job.response


@router.get(
    "/api/scans/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan progress and results",
)
async def get_scan(scan_id: str) -> ScanResponse:
    job = scan_jobs.get(scan_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return job.response


@router.post(
    "/api/scans/{scan_id}/cancel",
    response_model=ScanResponse,
    summary="Stop a scan and return partial results",
)
async def cancel_scan(scan_id: str) -> ScanResponse:
    job = scan_jobs.get(scan_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if job.task is not None and not job.task.done():
        job.cancel_event.set()
        await job.task
    return job.response
