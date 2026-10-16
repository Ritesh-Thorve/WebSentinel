"""Data transfer models and validation schemas for WebSentinel."""

from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator

SeverityLevel = Literal["critical", "high", "medium", "low", "informational"]
ConfidenceLevel = Literal["high", "medium", "low"]


class ScanRequest(BaseModel):
    target_url: str = Field(
        ...,
        description="Target web address to inspect (http or https)",
    )

    @field_validator("target_url")
    @classmethod
    def check_url_syntax(cls, value: str) -> str:
        trimmed = value.strip()
        parsed = urlsplit(trimmed)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Target scheme must be http or https")
        if not parsed.netloc or not parsed.hostname:
            raise ValueError("Target host network location cannot be empty")
        return trimmed


class Finding(BaseModel):
    title: str = Field(..., description="Issue title")
    severity: SeverityLevel = Field(..., description="Finding severity category")
    affected_url: str = Field(..., description="Observed URL endpoint")
    description: str = Field(..., description="Details regarding observed behavior")
    evidence: str = Field(..., description="Sanitized and minimal observation proof")
    recommendation: str = Field(..., description="Remediation steps")
    confidence: ConfidenceLevel = Field(..., description="Detection confidence rating")


class ScanSummary(BaseModel):
    total_findings: int = Field(default=0, description="Total count of findings")
    critical: int = Field(default=0, description="Count of critical findings")
    high: int = Field(default=0, description="Count of high findings")
    medium: int = Field(default=0, description="Count of medium findings")
    low: int = Field(default=0, description="Count of low findings")
    informational: int = Field(default=0, description="Count of informational findings")


class ScanResponse(BaseModel):
    target_url: str = Field(..., description="Scanned target address")
    status: str = Field(default="completed", description="Scan execution state")
    findings: list[Finding] = Field(default_factory=list, description="Discovered security findings")
    summary: ScanSummary = Field(default_factory=ScanSummary, description="Aggregated severity metrics")


class HealthResponse(BaseModel):
    status: str = Field(default="ok", description="Health check status flag")
    service: str = Field(default="WebSentinel", description="Service name")
