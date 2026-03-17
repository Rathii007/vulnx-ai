"""
schemas.py — Pydantic models for request / response serialisation.

WHY SEPARATE FROM ORM MODELS?
─────────────────────────────
SQLAlchemy models describe *database rows*.  Pydantic schemas describe
the shape of *HTTP payloads*.  Keeping them separate means the API
contract is decoupled from the storage layer — a core clean-architecture
principle.
"""

from __future__ import annotations

import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ── Requests ────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    """Body of POST /api/scans."""
    target_url: str = Field(
        ...,
        description="Fully-qualified URL of the target website",
        examples=["http://testphp.vulnweb.com"],
    )


class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)


class UserLogin(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=128)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime.datetime

    model_config = {"from_attributes": True}


# ── Responses ───────────────────────────────────────────────────────

class VulnerabilityOut(BaseModel):
    """Single vulnerability in the scan report."""
    id: int
    name: str
    severity: str
    endpoint: Optional[str] = None
    payload: Optional[str] = None
    confidence: Optional[str] = None
    evidence: Optional[str] = None
    explanation: Optional[str] = None
    remediation: Optional[str] = None
    owasp_category: Optional[str] = None

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    """Full scan record returned by the API."""
    id: int
    user_id: Optional[int] = None
    target_url: str
    status: str
    score: Optional[float] = None
    created_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None
    vulnerabilities: list[VulnerabilityOut] = []

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    """Lightweight scan info used for listing."""
    id: int
    target_url: str
    status: str
    score: Optional[float] = None
    created_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None

    model_config = {"from_attributes": True}


class ProgressEvent(BaseModel):
    """Shape of each SSE progress event."""
    scan_id: int
    status: str
    progress: int = Field(ge=0, le=100)
    message: str = ""
