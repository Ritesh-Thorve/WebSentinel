# WebSentinel Backend

FastAPI service for safe, same-origin web application scanning. The API discovers public and browser-rendered routes, then checks security headers, cookies, CORS, exposed resources, and reflected input. Scans are non-destructive; only test sites you own or are authorized to assess.

## Requirements

- Python 3.10 or newer
- Chromium for JavaScript-rendered route discovery. The scanner auto-detects Chromium; otherwise install Playwright's Chromium browser.

## Local setup

Run these commands from the `backend/` directory:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create a local `.env` file in `backend/` for development:

```env
HOST=127.0.0.1
PORT=9000
LOG_LEVEL=INFO
FRONTEND_ORIGIN=http://localhost:5173,http://127.0.0.1:5173
```

Edit values as needed, then launch the API using its environment-configured host, port, and log level:

```bash
python -m app
```

The sample configuration uses `0.0.0.0` so the service is reachable from a container or hosting platform. For local-only access, set `HOST=127.0.0.1` in `.env`. With the sample `PORT`, the local API address is `http://127.0.0.1:9000`; interactive API docs are at `/docs`.

## Environment configuration

`app.config` reads the backend's `.env` file independent of the process working directory, and process environment variables take precedence. Local `.env` files and optional `.env.example` templates are ignored by Git. Invalid values fail at startup with a configuration error.

| Variable | Default | Purpose |
|---|---:|---|
| `HOST` | `0.0.0.0` | Uvicorn bind address. Use `127.0.0.1` for local-only access. |
| `PORT` | `9000` (local fallback) | Uvicorn listen port. A hosting platform-provided `PORT` environment variable takes precedence. |
| `LOG_LEVEL` | `INFO` | `CRITICAL`, `ERROR`, `WARNING`, `INFO`, or `DEBUG`. |
| `FRONTEND_ORIGIN` | Required | Comma-separated exact frontend origins; configure local origins for development and your deployed frontend origin in production. No wildcard origins or paths. |
| `WEBSENTINEL_MAX_PAGES` | `500` | Maximum page records per scan; hard maximum is 500. |
| `WEBSENTINEL_MAX_REQUESTS` | `500` | Shared browser/HTTP request budget; hard maximum is 500. |
| `WEBSENTINEL_TIMEOUT` | `10` | Timeout in seconds per request. |
| `WEBSENTINEL_MAX_BODY_BYTES` | `1000000` | Maximum response body size processed per request. |
| `WEBSENTINEL_MAX_REDIRECTS` | `10` | Maximum same-origin redirects followed per URL. |
| `WEBSENTINEL_TOTAL_TIMEOUT` | `300` | Maximum total scan time in seconds. `WEBSENTINEL_SCAN_TIMEOUT` remains a legacy fallback. |
| `WEBSENTINEL_CHROMIUM_EXECUTABLE` | auto-detect | Optional absolute path to a Chromium executable. |
| `WEBSENTINEL_BROWSER_STATE_DIR` | `.auth` under the backend directory | Optional location for private, per-origin login state. Relative paths resolve from the backend directory. Use a protected persistent volume if deployed authenticated scanning is required. |

The scanner's SSRF defenses are intentionally not configurable: private, loopback, link-local, and other restricted destinations remain blocked. Browser scans are same-origin and read-only; cross-origin requests and state-changing requests are blocked.

## Frontend connection

Configure the backend's `FRONTEND_ORIGIN` with the exact scheme, host, and port of the frontend. For example:

```env
FRONTEND_ORIGIN=https://websentinel.example.com
```

The frontend's `VITE_API_BASE_URL` must point to the deployed API origin. CORS is restricted to configured origins and the API methods/headers used by the application.

For a hosted deployment, set these values in the platform's environment-variable settings (not in committed source), then use `python -m app` as the start command. The process reads the platform's `PORT` variable automatically; you do not need to put the internal port in the public website URL. If the platform does not provide `PORT`, configure its service to route to the local fallback port or use its documented ASGI/serverless adapter.

```env
HOST=0.0.0.0
FRONTEND_ORIGIN=https://websentinel.example.com
LOG_LEVEL=INFO
```

Do not expose the scanner as an unauthenticated public service: CORS is a browser policy, not API authentication. Put the API behind your application's authentication/access-control layer and apply request rate limits at the gateway. The in-memory job store also requires one worker and one replica, as noted below.

## API workflow

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness check |
| `POST` | `/api/scans` | Start a scan; returns `202 Accepted` and a `scan_id` |
| `GET` | `/api/scans/{scan_id}` | Get progress or final/partial findings |
| `POST` | `/api/scans/{scan_id}/cancel` | Stop a scan and return findings from pages already fetched |
| `GET` | `/docs` | OpenAPI/Swagger documentation |

Start a scan:

```bash
curl -X POST http://127.0.0.1:9000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"target_url":"https://example.com"}'
```

Poll the returned `scan_id` until `status` is `completed`, `cancelled`, or `failed`:

```bash
curl http://127.0.0.1:9000/api/scans/SCAN_ID
```

Stop early and receive partial results:

```bash
curl -X POST http://127.0.0.1:9000/api/scans/SCAN_ID/cancel
```

The frontend persists the current scan report in tab-scoped `sessionStorage` so refreshes restore the report or resume polling. Backend scan jobs/results themselves are held in process memory: a backend restart discards them. Run a **single Uvicorn worker and one backend replica** with the current in-memory job store; multiple workers or replicas cannot reliably share scan status or cancellation. Durable/multi-worker deployment requires a shared job store such as Redis or a database, which this backend does not currently implement.

## Browser session for an authorized site

For a site you own, install Chromium if the host does not provide it:

```bash
playwright install chromium
```

Start the visible login flow:

```bash
python -m app.save_browser_session https://example.com
```

Log in through the browser and press Enter in the terminal to save state. Login-state files are secrets: keep `.auth` private, never commit or publish its contents, and use a protected persistent volume if the backend host must retain the session. The interactive login flow allows same-origin POSTs for login forms; automated scanning remains GET/HEAD-only.

The crawler follows same-origin links, renders JavaScript, records GET/HEAD requests, checks JavaScript route references and sitemap locations, and shares the configured request budget. Routes that require user interaction or are not exposed through pages, scripts, requests, or sitemaps cannot be guaranteed discoverable.
