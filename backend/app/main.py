"""Main FastAPI application module for WebSentinel."""

from contextlib import asynccontextmanager
import os
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.scans import router as scans_router
from app.schemas import HealthResponse


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Handle application startup and shutdown cleanly."""
    yield


app = FastAPI(
    title="WebSentinel API",
    description="Web application security scanner backend",
    version="1.0.0",
    lifespan=lifespan,
)

frontend_origin = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")
allowed_origins = [origin.strip() for origin in frontend_origin.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans_router)


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Return application health status.",
)
async def health_check() -> HealthResponse:
    """Return application health status."""
    return HealthResponse(status="ok", service="WebSentinel")
