"""Persistence layer: save/load ScanResult objects to/from SQLite."""
from __future__ import annotations

import json

from scanner.models.finding import Finding
from scanner.models.scan import ScanConfig, ScanResult
from scanner.storage.database import FindingRecord, ScanRecord, get_session, init_db


def save_scan(result: ScanResult) -> None:
    init_db()
    session = get_session()
    try:
        record = ScanRecord(
            id=result.id,
            target_url=result.target_url,
            profile=result.config.profile if isinstance(result.config.profile, str) else result.config.profile.value,
            status=result.status if isinstance(result.status, str) else result.status.value,
            started_at=result.started_at,
            completed_at=result.completed_at,
            pages_scanned=result.pages_scanned,
            requests_made=result.requests_made,
            risk_score=result.risk_score,
            error=result.error,
            config_json=result.config.model_dump_json(),
        )
        for finding in result.findings:
            record.findings.append(
                FindingRecord(
                    id=finding.id,
                    title=finding.title,
                    severity=finding.severity if isinstance(finding.severity, str) else finding.severity.value,
                    confidence=finding.confidence if isinstance(finding.confidence, str) else finding.confidence.value,
                    status=finding.status if isinstance(finding.status, str) else finding.status.value,
                    category=finding.category,
                    owasp=finding.owasp,
                    cwe=finding.cwe,
                    url=finding.url,
                    description=finding.description,
                    evidence=finding.evidence,
                    recommendation=finding.recommendation,
                    detection_method=finding.detection_method,
                    timestamp=finding.timestamp,
                )
            )
        session.merge(record)
        session.commit()
    finally:
        session.close()


def list_scans(limit: int = 20) -> list[ScanRecord]:
    init_db()
    session = get_session()
    try:
        return (
            session.query(ScanRecord)
            .order_by(ScanRecord.started_at.desc())
            .limit(limit)
            .all()
        )
    finally:
        session.close()


def get_scan(scan_id: str) -> ScanResult | None:
    init_db()
    session = get_session()
    try:
        record = session.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if not record:
            return None
        config = ScanConfig.model_validate_json(record.config_json)
        findings = [
            Finding(
                id=f.id,
                title=f.title,
                severity=f.severity,
                confidence=f.confidence,
                status=f.status,
                category=f.category,
                owasp=f.owasp,
                cwe=f.cwe,
                url=f.url,
                description=f.description,
                evidence=f.evidence,
                recommendation=f.recommendation,
                detection_method=f.detection_method,
                timestamp=f.timestamp,
            )
            for f in record.findings
        ]
        return ScanResult(
            id=record.id,
            target_url=record.target_url,
            config=config,
            status=record.status,
            started_at=record.started_at,
            completed_at=record.completed_at,
            pages_scanned=record.pages_scanned,
            requests_made=record.requests_made,
            findings=findings,
            risk_score=record.risk_score,
            error=record.error,
        )
    finally:
        session.close()
