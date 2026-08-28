"""Pydantic models for findings — the core unit of scanner output."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    INFORMATIONAL = "INFORMATIONAL"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus = FindingStatus.CONFIRMED
    category: str  # e.g. "Security Headers", "Cookies", "TLS"
    owasp: str | None = None  # e.g. "A05:2021 - Security Misconfiguration"
    cwe: str | None = None  # e.g. "CWE-693"
    url: str
    description: str
    evidence: str
    recommendation: str
    detection_method: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": True}
