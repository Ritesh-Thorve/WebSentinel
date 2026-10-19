# WebSentinel

Minimal scanner interface: enter a target URL, select **Scan Target**, and review actual backend findings. There is no mock fallback.

## Run the frontend

```sh
bun install
printf 'VITE_API_BASE_URL=http://127.0.0.1:9000\n' > .env.local
bun run dev
```

`.env.local` is a local-only file and is ignored by Git. The frontend reads `VITE_API_BASE_URL` with `import.meta.env.VITE_API_BASE_URL`; the scanner API client uses it as the base for its `/api/scans` create, poll, and cancel requests. If it is empty or invalid, the app stays disconnected and displays an error instead of using fake results. Restart Vite after changing the value.

## Deployment configuration

Before deployment, replace the local value in `.env.local` (or set the equivalent variable in the frontend host's **build-time** environment) to the backend's public HTTPS origin, for example `VITE_API_BASE_URL=https://api.example.com`, then run `bun run build`. Vite embeds `VITE_*` values in browser assets at build time; changing a host's runtime environment after the static assets have been built will not change this URL. This value is public, not a secret—never put private keys or credentials in `VITE_*` variables.

Set the backend's required `FRONTEND_ORIGIN` to the exact deployed frontend origin (scheme and hostname, plus port if nonstandard) in the backend host's environment. Do not use `*`. The backend will fail startup if this value is missing. For local development, set `FRONTEND_ORIGIN=http://localhost:5173,http://127.0.0.1:5173` in `backend/.env`.

The current Vite wrapper configures Nitro's Cloudflare target by default. Before deploying somewhere other than Cloudflare, configure and verify a Nitro target supported by that host; the required output format and runtime are provider-specific. The frontend requires HTTPS when calling a deployed HTTPS backend.

## Backend request and response

The scan form sends **POST /api/scans** with `{"target_url":"https://…"}`. The backend immediately returns a scan ID; the frontend polls **GET /api/scans/{scan_id}** for progress and results. While a scan is active, **Stop Scan** calls **POST /api/scans/{scan_id}/cancel**. The backend finishes processing pages already fetched, then returns a cancelled scan with its partial findings and scanned paths. A scan that reaches the end normally returns its complete findings. The latest scan and its progress ID are saved in this browser tab's `sessionStorage`, so refresh restores completed results or resumes polling an active scan. The saved scan is cleared when the tab session ends. Backend scan jobs/results are held in memory and are lost if the backend restarts.

The result contains `scan_id`, `target_url`, `status`, `findings`, and `summary`. The adapter maps backend `informational` severity to the frontend’s `Info` label and `recommendation` to `remediation`. The scan ID only exists in the current backend process; durable history and reports are not provided.

The browser validates URL syntax, but the backend is responsible for URL safety and performs its own checks. Only scan websites you own or have permission to test.

See [the backend deployment documentation](../backend/README.md) for backend startup, CORS, and hosting requirements.

## Safety and scope

Evidence is redacted and rendered as text. Automated findings do not prove exploitability or that an application is secure.

Removed: dashboard/analytics/charts, workspace shell/navigation/profiles, settings, history, scan-detail pages, export controls, mock fixtures, and confirmation/profile UI. No scheduling, notifications, saved targets, or new scanner features were added.

## Tests

```sh
bun run test
```
