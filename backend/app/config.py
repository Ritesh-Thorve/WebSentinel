"""Validated backend settings loaded from environment variables or backend/.env."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(BACKEND_ROOT / ".env", override=False)

MAX_SCAN_REQUESTS = 500


def _read_number(
    environ: Mapping[str, str],
    name: str,
    default: int | float,
    *,
    minimum: int | float,
    maximum: int | float | None = None,
) -> int | float:
    raw_value = environ.get(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        value = float(raw_value) if isinstance(default, float) else int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid {'number' if isinstance(default, float) else 'integer'}") from exc
    if value < minimum or (maximum is not None and value > maximum):
        upper = f" and at most {maximum}" if maximum is not None else ""
        raise ValueError(f"{name} must be at least {minimum}{upper}")
    return value


def _frontend_origins(environ: Mapping[str, str]) -> tuple[str, ...]:
    configured = environ.get("FRONTEND_ORIGIN", "")
    origins = tuple(origin.strip() for origin in configured.split(",") if origin.strip())
    for origin in origins:
        parsed = urlsplit(origin)
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("FRONTEND_ORIGIN contains an invalid origin port") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError(
                "FRONTEND_ORIGIN must be a comma-separated list of http(s) origins without paths"
            )
    if not origins:
        raise ValueError("FRONTEND_ORIGIN must contain at least one allowed origin; configure it in the environment")
    return origins


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    log_level: str
    frontend_origins: tuple[str, ...]
    max_pages: int
    max_requests: int
    request_timeout: float
    max_body_bytes: int
    max_redirects: int
    total_scan_timeout: float
    chromium_executable: str | None
    browser_state_dir: Path

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> Settings:
        values = os.environ if environ is None else environ
        port = int(_read_number(values, "PORT", 9000, minimum=1, maximum=65535))
        max_pages = int(
            _read_number(values, "WEBSENTINEL_MAX_PAGES", MAX_SCAN_REQUESTS, minimum=1)
        )
        max_requests = int(
            _read_number(
                values,
                "WEBSENTINEL_MAX_REQUESTS",
                MAX_SCAN_REQUESTS,
                minimum=1,
            )
        )
        request_timeout = float(
            _read_number(values, "WEBSENTINEL_TIMEOUT", 10.0, minimum=0.1)
        )
        max_body_bytes = int(
            _read_number(
                values,
                "WEBSENTINEL_MAX_BODY_BYTES",
                1_000_000,
                minimum=1024,
            )
        )
        max_redirects = int(
            _read_number(values, "WEBSENTINEL_MAX_REDIRECTS", 10, minimum=0)
        )
        total_scan_timeout = float(
            _read_number(
                values,
                "WEBSENTINEL_TOTAL_TIMEOUT",
                float(values.get("WEBSENTINEL_SCAN_TIMEOUT", "300.0")),
                minimum=0.1,
            )
        )
        log_level = values.get("LOG_LEVEL", "INFO").strip().upper()
        if log_level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError("LOG_LEVEL must be CRITICAL, ERROR, WARNING, INFO, or DEBUG")
        host = values.get("HOST", "0.0.0.0").strip()
        if not host:
            raise ValueError("HOST cannot be empty")

        configured_state_dir = values.get("WEBSENTINEL_BROWSER_STATE_DIR")
        browser_state_dir = Path(configured_state_dir).expanduser() if configured_state_dir else Path(".auth")
        if not browser_state_dir.is_absolute():
            browser_state_dir = BACKEND_ROOT / browser_state_dir

        return cls(
            host=host,
            port=port,
            log_level=log_level,
            frontend_origins=_frontend_origins(values),
            max_pages=min(max_pages, MAX_SCAN_REQUESTS),
            max_requests=min(max_requests, MAX_SCAN_REQUESTS),
            request_timeout=request_timeout,
            max_body_bytes=max_body_bytes,
            max_redirects=max_redirects,
            total_scan_timeout=total_scan_timeout,
            chromium_executable=values.get("WEBSENTINEL_CHROMIUM_EXECUTABLE") or None,
            browser_state_dir=browser_state_dir,
        )


settings = Settings.from_environment()
