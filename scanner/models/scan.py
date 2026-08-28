"""Scan configuration, lifecycle state, and target models."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field

from scanner.models.finding import Finding


class ScanProfile(str, Enum):
    QUICK = "quick"          # headers only
    STANDARD = "standard"    # headers + cookies + TLS + CORS
    FULL = "full"            # everything, with crawling


class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    CRAWLING = "CRAWLING"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanConfig(BaseModel):
    target_url: str
    profile: ScanProfile = ScanProfile.STANDARD
    max_depth: int = 2
    max_pages: int = 50
    timeout_seconds: float = 10.0
    rate_limit_rps: float = 5.0
    same_domain_only: bool = True


# Checks each profile enables, by check name (see scanner/checks/*).
PROFILE_CHECKS: dict[ScanProfile, list[str]] = {
    ScanProfile.QUICK: ["headers"],
    ScanProfile.STANDARD: ["headers", "cookies", "tls", "cors", "security_txt"],
    ScanProfile.FULL: [
        "headers",
        "cookies",
        "tls",
        "cors",
        "methods",
        "disclosure",
        "security_txt",
        "forms",
    ],
}


class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    target_url: str
    config: ScanConfig
    status: ScanStatus = ScanStatus.QUEUED
    started_at: datetime | None = None
    completed_at: datetime | None = None
    pages_scanned: int = 0
    requests_made: int = 0
    findings: list[Finding] = Field(default_factory=list)
    risk_score: int = 0
    error: str | None = None

    model_config = {"use_enum_values": True}

    def mark_started(self) -> None:
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.now(timezone.utc)

    def mark_completed(self) -> None:
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc)

    def duration_seconds(self) -> float | None:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
