"""SQLAlchemy ORM models and SQLite engine setup."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "scanner.db"


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_url: Mapped[str] = mapped_column(String(2048), index=True)
    profile: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    pages_scanned: Mapped[int] = mapped_column(Integer, default=0)
    requests_made: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    config_json: Mapped[str] = mapped_column(Text)  # serialized ScanConfig

    findings: Mapped[list["FindingRecord"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    confidence: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20))
    category: Mapped[str] = mapped_column(String(100), index=True)
    owasp: Mapped[str | None] = mapped_column(String(100))
    cwe: Mapped[str | None] = mapped_column(String(20))
    url: Mapped[str] = mapped_column(String(2048))
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    detection_method: Mapped[str] = mapped_column(String(255))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan: Mapped[ScanRecord] = relationship(back_populates="findings")


_engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)
SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(_engine)


def get_session() -> Session:
    return SessionLocal()
