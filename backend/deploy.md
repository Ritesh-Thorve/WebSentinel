# Deploy the WebSentinel backend

This guide deploys the FastAPI backend as a Docker web service. **Render** is the example host; the Docker image can also be deployed to another service that supports Docker containers and an injected `PORT`.

The backend runs Chromium through Playwright for JavaScript-rendered route discovery. The included [Dockerfile](./Dockerfile) installs Chromium and its system dependencies, so the host does not need a separate browser installation.

## Before you deploy

1. Push the repository to GitHub without `.env`, `.auth`, or browser session files. These contain local configuration or authentication secrets and are excluded from the Docker build context.
2. Deploy the frontend and note its public origin, such as `https://websentinel.example.com`.
3. Decide how the public API will be protected. CORS only controls browser access; it does **not** authenticate API clients. Do not expose an unauthenticated scanner to the public internet. Put authentication and rate limiting at a gateway or add them to the application before enabling public access.

## Deploy on Render

1. In Render, create a **New + → Web Service** and connect the GitHub repository.
2. Select **Docker** as the runtime.
3. Set **Root Directory** to `backend`. The Dockerfile and `.dockerignore` are in that directory.
4. Use the default Docker build and start commands. The image starts the service with `python -m app`.
5. Add the environment variables below in the service's **Environment** settings. Do not add them to the repository or Dockerfile.
6. Set the health check path to `/health`.
7. Deploy. When the service is live, copy its public HTTPS URL, for example `https://websentinel-api.onrender.com`.

### Required environment

```env
HOST=0.0.0.0
FRONTEND_ORIGIN=https://websentinel.example.com
LOG_LEVEL=INFO
```

Render supplies `PORT` to the running service. The startup code reads it automatically; do not set a fixed deployment port. The local fallback port is only for development. Set `FRONTEND_ORIGIN` to the exact frontend origin (scheme and host, plus a port only when nonstandard); do not use `*`.

Optional resource controls can be set in the host's environment settings:

| Variable | Default | Note |
|---|---:|---|
| `WEBSENTINEL_MAX_PAGES` | `500` | The application caps this at 500. |
| `WEBSENTINEL_MAX_REQUESTS` | `500` | The application caps this at 500. |
| `WEBSENTINEL_TIMEOUT` | `10` | Seconds per request. |
| `WEBSENTINEL_MAX_BODY_BYTES` | `1000000` | Maximum response body size processed. |
| `WEBSENTINEL_MAX_REDIRECTS` | `10` | Same-origin redirect limit. |
| `WEBSENTINEL_TOTAL_TIMEOUT` | `300` | Maximum scan duration in seconds. |

## Connect the frontend

Set the frontend host's **build-time** variable to the backend public HTTPS URL, without `/health` or `/api/scans`:

```env
VITE_API_BASE_URL=https://websentinel-api.onrender.com
```

Rebuild/redeploy the frontend after changing this value. Vite embeds it into the browser assets at build time. Keep the backend `FRONTEND_ORIGIN` in sync with the deployed frontend's exact origin.

## Verify deployment

Check that the health route responds:

```bash
curl --fail --show-error https://websentinel-api.onrender.com/health
```

Expected response:

```json
{"status":"ok","service":"WebSentinel"}
```

You can then submit a scan from the frontend, or open `/docs` on the API host to inspect the API schema. Only scan systems you own or are authorized to assess.

## Operational limitations

- Run one service instance and one worker. Scan jobs, progress, cancellation, and results live in process memory; multiple instances/workers cannot share them, and a restart loses active and stored backend results.
- Browser-based login state is not part of the image. Do not bake `.auth` or session files into the image. Authenticated scanning requires securely provisioning state through a protected persistent volume and must be tested on the selected host; the interactive login helper is intended for a local machine with a visible browser.
- Check the host's current container, memory, CPU, request-duration, and outbound-network limits. Chromium scans are resource-intensive, and a host may stop or time out long-running scans.
- If a host does not inject `PORT`, follow its Docker port-routing instructions and configure its internal service port accordingly. The backend still must bind to an internal port.
