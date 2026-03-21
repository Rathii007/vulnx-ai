"""
main.py — FastAPI application entry-point.

ENDPOINTS
─────────
POST /api/scans             → Start a new vulnerability scan
GET  /api/scans             → List all scans
GET  /api/scans/{id}        → Get scan details + vulnerabilities
GET  /api/scans/{id}/progress → SSE stream for real-time progress
GET  /api/scans/{id}/report/pdf → Download PDF report

The scan itself runs as an ``asyncio`` background task so the POST
request returns immediately with a scan ID.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import time
from typing import AsyncGenerator

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from sentry_sdk import init as sentry_init
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .database import get_db, init_db
from .models import Scan, User, Vulnerability
from .schemas import (
    AISummaryOut,
    ScanCreate,
    ScanOut,
    ScanSummary,
    TokenOut,
    UserLogin,
    UserOut,
    UserRegister,
)
from .ai_assistant import generate_ai_summary
from .scanner import run_scan, get_progress
from .report import calculate_score, generate_pdf
from .security import (
    RateLimitMiddleware,
    create_access_token,
    get_current_user,
    hash_password,
    normalize_and_validate_target_url,
    rate_limit_settings,
    verify_password,
)
from .config import ALLOWED_ORIGINS, ENABLE_METRICS, SENTRY_DSN


# ── In-memory task tracking for scan cancellation ───────────────────
_scan_tasks: dict[int, asyncio.Task] = {}


# ── App creation ────────────────────────────────────────────────────

app = FastAPI(
    title="VulnX API",
    description="Educational web application security scanner",
    version="1.0.0",
)

logger = logging.getLogger("vulnx.api")
REQUEST_COUNT = Counter("scanner_http_requests_total", "Total HTTP requests", ["method", "path", "status"])
REQUEST_LATENCY = Histogram("scanner_http_request_latency_seconds", "HTTP request latency", ["method", "path"])

# Allow the Next.js frontend (localhost:3000) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

rate_limit_max, rate_limit_window = rate_limit_settings()
app.add_middleware(
    RateLimitMiddleware,
    max_requests=rate_limit_max,
    window_seconds=rate_limit_window,
)


@app.middleware("http")
async def request_metrics_middleware(request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = time.perf_counter() - start
    path = request.url.path
    method = request.method
    REQUEST_COUNT.labels(method=method, path=path, status=str(response.status_code)).inc()
    REQUEST_LATENCY.labels(method=method, path=path).observe(elapsed)
    return response


@app.on_event("startup")
async def startup():
    """Create database tables on first run."""
    if SENTRY_DSN:
        sentry_init(dsn=SENTRY_DSN, traces_sample_rate=0.2)
        logger.info("Sentry initialized")
    await init_db()


@app.get("/health/live")
async def health_live():
    return {"status": "ok"}


@app.get("/health/ready")
async def health_ready():
    return {"status": "ready"}


@app.get("/metrics")
async def metrics():
    if not ENABLE_METRICS:
        raise HTTPException(status_code=404, detail="Metrics disabled")
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/api/auth/register", response_model=UserOut, status_code=201)
async def register_user(body: UserRegister, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(
        select(User).where((User.username == body.username) | (User.email == body.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already exists")

    user = User(
        username=body.username.strip(),
        email=body.email.strip().lower(),
        password_hash=hash_password(body.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@app.post("/api/auth/login", response_model=TokenOut)
async def login_user(body: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == body.username.strip()))
    user = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token, expires_in = create_access_token(user_id=user.id, username=user.username)
    return TokenOut(access_token=token, expires_in=expires_in)


@app.get("/api/auth/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


# ── POST /api/scans → start a scan ─────────────────────────────────

@app.post("/api/scans", response_model=ScanOut, status_code=201)
async def create_scan(
    body: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Accept a target URL, persist a Scan row, and kick off the
    vulnerability scan as a background task.
    """
    # Normalise URL
    target = normalize_and_validate_target_url(body.target_url)

    # Create DB record
    scan = Scan(target_url=target, status="pending", user_id=current_user.id)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Launch scan in the background
    task = asyncio.create_task(_background_scan(scan.id, target, body.scan_mode))
    _scan_tasks[scan.id] = task

    return ScanOut(
        id=scan.id,
        user_id=scan.user_id,
        target_url=scan.target_url,
        status=scan.status,
        score=scan.score,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        vulnerabilities=[],
    )


async def _background_scan(scan_id: int, target_url: str, scan_mode: str = "deep"):
    """
    Run the full scan pipeline and persist results.

    This coroutine runs independently of any HTTP request, so it
    creates its own database session.
    """
    from .database import async_session  # local import to avoid circular

    async with async_session() as db:
        # Mark as in-progress
        scan = await db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "scanning"
        await db.commit()

        try:
            findings = await run_scan(scan_id, target_url, scan_mode=scan_mode)

            # Persist vulnerabilities
            for f in findings:
                db.add(Vulnerability(scan_id=scan_id, **f))

            # Calculate score
            scan.score = calculate_score(findings)
            scan.status = "completed"
            scan.completed_at = datetime.datetime.utcnow()

        except asyncio.CancelledError:
            # Scan was cancelled by user
            scan.status = "cancelled"
            scan.completed_at = datetime.datetime.utcnow()
            await db.commit()
            if scan_id in _scan_tasks:
                del _scan_tasks[scan_id]
            return

        except Exception as exc:  # noqa: BLE001
            scan.status = "failed"
            scan.score = None
            # Optionally store the error as a "vulnerability" for debugging
            db.add(Vulnerability(
                scan_id=scan_id,
                name="Scan Error",
                severity="Low",
                explanation=str(exc),
                remediation="Check the target URL and try again.",
            ))

        await db.commit()
        
        # Clean up task reference
        if scan_id in _scan_tasks:
            del _scan_tasks[scan_id]


# ── GET /api/scans → list all scans ────────────────────────────────

@app.get("/api/scans", response_model=list[ScanSummary])
async def list_scans(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
    )
    return result.scalars().all()


# ── GET /api/scans/{id} → scan details ─────────────────────────────

@app.get("/api/scans/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where((Scan.id == scan_id) & (Scan.user_id == current_user.id))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


# ── DELETE /api/scans/{id} → cancel an in-progress scan ─────────────

@app.delete("/api/scans/{scan_id}", status_code=204)
async def cancel_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Cancel a scan that is currently in progress.
    
    Only pending, crawling, and scanning statuses can be cancelled.
    Returns 204 No Content on success.
    """
    result = await db.execute(
        select(Scan)
        .where((Scan.id == scan_id) & (Scan.user_id == current_user.id))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    
    # Only allow cancelling in-progress scans
    if scan.status not in ("pending", "crawling", "scanning"):
        raise HTTPException(
            400,
            f"Cannot cancel scan with status '{scan.status}'. Only pending, crawling, or scanning scans can be cancelled."
        )
    
    # Cancel the background task
    if scan_id in _scan_tasks:
        task = _scan_tasks[scan_id]
        task.cancel()
        logger.info("Cancelled scan task %s", scan_id)
    
    # Task will handle status update when it receives CancelledError
    return Response(status_code=204)


# ── GET /api/scans/{id}/progress → SSE stream ──────────────────────

@app.get("/api/scans/{scan_id}/progress")
async def scan_progress(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Server-Sent Events (SSE) endpoint.

    The frontend opens an ``EventSource`` connection to this URL and
    receives JSON progress objects until the scan completes.
    """

    owner_result = await db.execute(
        select(Scan.id).where((Scan.id == scan_id) & (Scan.user_id == current_user.id))
    )
    if owner_result.scalar_one_or_none() is None:
        raise HTTPException(404, "Scan not found")

    async def event_stream() -> AsyncGenerator[str, None]:
        prev = None
        while True:
            progress = get_progress(scan_id)
            if progress != prev:
                data = json.dumps({
                    "scan_id": scan_id,
                    "status": progress["status"],
                    "progress": progress["progress"],
                    "message": progress["message"],
                })
                yield f"data: {data}\n\n"
                prev = progress
                if progress["status"] in ("completed", "failed", "cancelled"):
                    break
            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


# ── GET /api/scans/{id}/report/pdf → download PDF ──────────────────

@app.get("/api/scans/{scan_id}/report/pdf")
async def download_pdf(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where((Scan.id == scan_id) & (Scan.user_id == current_user.id))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != "completed":
        raise HTTPException(400, "Scan has not completed yet")

    vulns = [
        {
            "name": v.name,
            "severity": v.severity,
            "endpoint": v.endpoint,
            "payload": v.payload,
            "confidence": v.confidence,
            "evidence": v.evidence,
            "explanation": v.explanation,
            "remediation": v.remediation,
            "owasp_category": v.owasp_category,
        }
        for v in scan.vulnerabilities
    ]

    pdf_bytes = generate_pdf(scan.target_url, scan.score or 0.0, vulns)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="scan_{scan_id}_report.pdf"'
        },
    )


@app.get("/api/scans/{scan_id}/ai-summary", response_model=AISummaryOut)
async def ai_summary(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where((Scan.id == scan_id) & (Scan.user_id == current_user.id))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != "completed":
        raise HTTPException(400, "Scan has not completed yet")

    vulnerabilities = [
        {
            "name": v.name,
            "severity": v.severity,
            "endpoint": v.endpoint,
            "confidence": v.confidence,
            "owasp_category": v.owasp_category,
        }
        for v in scan.vulnerabilities
    ]

    try:
        return await generate_ai_summary(
            target_url=scan.target_url,
            score=float(scan.score or 0.0),
            vulnerabilities=vulnerabilities,
        )
    except ValueError as exc:
        # Groq-only mode and missing API key should be surfaced as config errors.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("AI summary generation failed for scan %s", scan_id)
        raise HTTPException(status_code=502, detail="AI provider request failed") from exc
