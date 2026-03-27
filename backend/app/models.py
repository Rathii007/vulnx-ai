"""
models.py — SQLAlchemy ORM models for the vulnerability scanner.

DATABASE SCHEMA
───────────────
┌──────────────┐        ┌────────────────────┐
│   scans      │ 1───M  │  vulnerabilities    │
├──────────────┤        ├────────────────────┤
│ id (PK)      │        │ id (PK)            │
│ target_url   │        │ scan_id (FK)       │
│ status       │        │ name               │
│ score        │        │ severity           │
│ created_at   │        │ endpoint           │
│ completed_at │        │ payload            │
└──────────────┘        │ explanation        │
                        │ remediation        │
                        │ owasp_category     │
                        └────────────────────┘
"""

import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Text,
    DateTime,
    ForeignKey,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""


class User(Base):
    """Application user for authentication and per-user scan ownership."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), nullable=False, unique=True, index=True)
    email = Column(String(255), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")


class Scan(Base):
    """
    Represents one complete scan run against a target URL.

    status can be:
        - "pending"    → created, not yet started
        - "crawling"   → discovering pages
        - "scanning"   → running vulnerability tests
        - "completed"  → finished successfully
        - "failed"     → something went wrong
        - "cancelled"  → user stopped the scan
    """

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    target_url = Column(String(2048), nullable=False)
    status = Column(String(20), default="pending", nullable=False)
    score = Column(Float, nullable=True)           # 0-100 security score
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False
    )
    completed_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="scans")

    # One scan → many vulnerabilities
    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} target={self.target_url!r} status={self.status}>"


class Vulnerability(Base):
    """
    A single security finding discovered during a scan.

    severity values: "Critical", "High", "Medium", "Low"
    """

    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    name = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    endpoint = Column(String(2048), nullable=True)
    payload = Column(Text, nullable=True)
    confidence = Column(String(20), nullable=True)
    evidence = Column(Text, nullable=True)
    explanation = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    owasp_category = Column(String(100), nullable=True)

    scan = relationship("Scan", back_populates="vulnerabilities")

    def __repr__(self) -> str:
        return f"<Vulnerability name={self.name!r} severity={self.severity}>"
