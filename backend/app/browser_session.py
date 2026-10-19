"""Helpers for local, per-origin authenticated browser sessions."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
from urllib.parse import urlsplit

from playwright.async_api import Route, async_playwright

from app.config import settings
from app.scanner.crawler import get_origin, is_same_origin, validate_url_safety


def storage_state_path(target_url: str) -> Path:
    """Return the private local storage-state path for a target origin."""
    parsed = urlsplit(target_url)
    origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    origin_hash = hashlib.sha256(origin.encode()).hexdigest()[:24]
    return settings.browser_state_dir / f"{origin_hash}.json"


def chromium_executable() -> str | None:
    """Return a configured or system Chromium executable, if available."""
    configured = settings.chromium_executable
    if configured:
        return configured
    executable = (
        shutil.which("chromium")
        or shutil.which("chromium-browser")
        or shutil.which("google-chrome")
    )
    if executable:
        return executable
    user_chromium = Path.home() / "bin" / "chromium"
    return str(user_chromium) if user_chromium.is_file() and os.access(user_chromium, os.X_OK) else None


async def save_browser_session(target_url: str) -> Path:
    """Open a visible same-origin browser so the user can log in and save session state."""
    validate_url_safety(target_url)
    state_path = storage_state_path(target_url)
    state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    state_path.parent.chmod(0o700)
    origin = urlsplit(target_url)
    origin_url = f"{origin.scheme}://{origin.netloc}"

    async with async_playwright() as playwright:
        launch_options: dict[str, object] = {"headless": False}
        executable = chromium_executable()
        if executable:
            launch_options["executable_path"] = executable
        browser = await playwright.chromium.launch(**launch_options)
        try:
            context = await browser.new_context()

            async def same_origin_only(route: Route) -> None:
                request = route.request
                if (
                    not is_same_origin(request.url, get_origin(target_url))
                    or request.method not in {"GET", "HEAD", "POST"}
                ):
                    await route.abort()
                    return
                try:
                    validate_url_safety(request.url)
                except ValueError:
                    await route.abort()
                    return
                await route.continue_()

            await context.route("**/*", same_origin_only)
            page = await context.new_page()
            await page.goto(target_url, wait_until="domcontentloaded")
            print(f"Log in to your site in the opened browser: {origin_url}")
            input("After login completes, return here and press Enter to save the session: ")
            await context.storage_state(path=str(state_path), indexed_db=True)
            state_path.chmod(0o600)
        finally:
            await browser.close()

    return state_path
