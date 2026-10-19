# WebSentinel

WebSentinel is a web application security scanner with a React frontend and FastAPI backend. Only scan websites you own or are authorized to assess.

## Project setup

- [Frontend setup, environment configuration, and deployment](./frontend/README.md)
- [Backend setup, API, environment configuration, and deployment](./backend/README.md)

The frontend's `VITE_API_BASE_URL` must point to the backend's public API origin and is embedded at build time. The backend's `FRONTEND_ORIGIN` must allow the frontend's exact origin. Configure both on their respective hosts; neither should contain credentials or secrets..
