# WebSentinel

WebSentinel is a web application security scanner designed to help developers and website owners identify common security weaknesses in their own websites or systems they are authorized to assess. It combines a React frontend for running and viewing scans with a FastAPI backend that discovers pages and performs security checks.

## How it works

1. Enter a website URL in the frontend and start a scan.
2. The backend crawls reachable pages on the target website, following same-origin links and using browser rendering to discover routes exposed by JavaScript. It can also use references in scripts and sitemaps.
3. The scanner checks collected pages for common security issues.
4. View findings and discovered paths in the frontend. Scans can be stopped early; the backend returns findings from the pages already collected. The interface can restore the current scan after a page refresh in the same browser tab.

## What it checks

- **HTTP security headers:** reviews response headers for common browser security protections.
- **Cookie security:** checks cookie attributes that help protect session data.
- **CORS configuration:** identifies potentially unsafe cross-origin access settings.
- **Exposed resources:** looks for accessible files or directories that may reveal sensitive information.
- **Reflected input:** checks whether supplied input appears in server responses.

Results include finding details and severity information to help guide investigation. Findings are automated indicators, not proof that a site is exploitable or completely secure; review them before taking action.

## Important limitations

The scanner only discovers routes it can reach or identify from the site's pages, scripts, requests, and sitemaps. Private, authenticated, dynamically generated, or unlinked paths may not be found. Scanning is subject to request and time limits, and only pages collected before a scan is stopped can appear in partial results.

The backend stores active scan jobs and results in memory. Restarting the backend clears them, and the current implementation is intended to run as a single backend instance.

Only scan websites you own or have explicit permission to test. The backend blocks local and other restricted network destinations as a safety measure.

## Demo
[web_sentinal.webm](https://github.com/user-attachments/assets/cd1682ec-4111-4423-868c-4d6676c76ce5)

