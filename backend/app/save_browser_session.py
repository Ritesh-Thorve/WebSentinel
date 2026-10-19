"""Open a browser to log in to an owned site and save its local scan session."""

from __future__ import annotations

import argparse
import asyncio

from app.browser_session import save_browser_session


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target_url", help="Public website origin you own and are authorized to scan")
    args = parser.parse_args()
    state_path = asyncio.run(save_browser_session(args.target_url))
    print(f"Browser session saved locally at: {state_path}")


if __name__ == "__main__":
    main()
