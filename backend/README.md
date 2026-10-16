# WebSentinel API

WebSentinel is a lightweight, stateless web security scanner backend built with FastAPI. It performs non-destructive security checks (security headers, cookie flags, CORS policies, sensitive file exposure, and reflected inputs) on target URLs.

---

## 1. Quick Start (Run Backend)

```bash
# Create & activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start backend server (runs at http://localhost:9000)
uvicorn app.main:app --reload --port 9000
```

Interactive API documentation will be available at `http://localhost:9000/docs`.

---

## 2. Link from Frontend

### Step 1: Configure CORS
By default, the backend accepts requests from `http://localhost:3000`. If your frontend runs on a different port (e.g., Vite on `http://localhost:5173`), set `FRONTEND_ORIGIN` in `.env`:

```env
FRONTEND_ORIGIN=http://localhost:3000,http://localhost:5173
```

### Step 2: Call the API
In your frontend application (React, Next.js, Vue, or vanilla JS):

```javascript
const API_BASE = "http://localhost:9000";

// Trigger a security scan
async function runScan(targetUrl) {
  const response = await fetch(`${API_BASE}/api/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_url: targetUrl }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || "Scan failed");
  }

  const data = await response.json();
  console.log("Summary:", data.summary);
  console.log("Findings:", data.findings);
  return data;
}
```

---

## 3. API Endpoints

| Method | Endpoint | Description | Sample Request |
|---|---|---|---|
| `GET` | `/health` | Service health status | _None_ |
| `POST` | `/api/scans` | Start non-destructive scan | `{"target_url": "https://example.com"}` |
| `GET` | `/docs` | Interactive Swagger UI | _Open in browser_ |

### Sample Response (`POST /api/scans`)

```json
{
  "target_url": "https://example.com",
  "status": "completed",
  "findings": [
    {
      "title": "Missing Content-Security-Policy",
      "severity": "medium",
      "affected_url": "https://example.com",
      "description": "Content-Security-Policy header is missing...",
      "evidence": "Header 'Content-Security-Policy' was not present",
      "recommendation": "Implement a restrictive Content-Security-Policy",
      "confidence": "high"
    }
  ],
  "summary": {
    "total_findings": 1,
    "critical": 0,
    "high": 0,
    "medium": 1,
    "low": 0,
    "informational": 0
  }
}
```

---

## 4. Test with cURL

```bash
# Check service health
curl http://localhost:9000/health

# Trigger a scan
curl -X POST http://localhost:9000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'
```
