# WebSentinel

Minimal scanner interface: enter a target URL, select **Scan Target**, and review actual backend findings. There is no mock fallback.

## Run the frontend

```sh
bun install
bun run dev
```

Set `VITE_API_BASE_URL` in a local `.env` file to your existing FastAPI backend URL, then restart your local development process. This is public browser configuration, not a secret; never put private keys in Vite variables. Configure the same variable before building for deployment. `VITE_USE_MOCK_API` is no longer used.

## Existing backend contract

The button calls **POST /api/scans** with `target_url`, `name: null`, and the existing default `profile: "standard"`. The minimal screen does not claim target authorization: `authorization_confirmed` is omitted unless explicitly supplied to the typed client. If your existing backend requires this field, it will reject the request; do not bypass authorization to make scanning work.

Creation returns the existing scan object: `id`, `target_url`, `profile`, `status`, `created_at`, and `summary` (critical/high/medium/low/info counts), plus existing optional scan fields. The client reads **GET /api/scans/{scan_id}** and **GET /api/scans/{scan_id}/findings**, polling queued/running scans every five seconds until terminal status. It uses the backend-returned ID. Findings accept an array or `{ items: [...] }`; each finding has an `id` and any available `title`, `severity`, `affected_url`, `description`, `evidence`, and `remediation`. Missing optional fields are omitted, not invented. Invalid responses and network/HTTP failures produce errors.

The existing typed adapter retains health, list, report and cancellation methods for compatibility, but the minimal UI does not call or expose them. No endpoints or scanner algorithms were added.

The backend must allow the frontend origin in CORS. The existing client sends credentials, so use explicit allowed origins and credential support, not wildcard origins. It may return 401/403 if an existing authorized session is required; no login UI was added.

## Safety and scope

Evidence is redacted and rendered as text. Scanning must be restricted to authorized targets. Automated findings do not prove exploitability or that an application is secure. This frontend is not a production safety boundary: the separate backend must independently enforce authorization, authentication, SSRF/IP/DNS protections, redirect validation, resource limits, and database access controls.

Removed: dashboard/analytics/charts, workspace shell/navigation/profiles, settings, history, scan-detail pages, export controls, mock fixtures, and confirmation/profile UI. No scheduling, notifications, saved targets, or new scanner features were added.

No backend URL is supplied with this project, so real scanner end-to-end verification remains blocked until the existing backend is connected.

## Tests

```sh
bun run test
```
