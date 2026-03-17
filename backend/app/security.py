from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import ipaddress
import os
import socket
import time
from collections import defaultdict, deque
from urllib.parse import urlsplit, urlunsplit

import jwt
from fastapi import Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware

from .config import (
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_ALGORITHM,
    JWT_SECRET_KEY,
    RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
)
from .database import get_db
from .models import User


def _is_public_ip(value: str) -> bool:
    """Return True only for publicly routable IP addresses."""
    ip = ipaddress.ip_address(value)
    return ip.is_global


def _resolve_host_ips(hostname: str) -> set[str]:
    """Resolve host to a set of IP strings (IPv4 + IPv6)."""
    addresses: set[str] = set()
    infos = socket.getaddrinfo(hostname, None)
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        addresses.add(sockaddr[0])
    return addresses


def normalize_and_validate_target_url(raw_url: str) -> str:
    """
    Normalize and validate scan targets to reduce SSRF risk.

    Rules:
    - Only http/https schemes
    - Hostname required
    - Reject localhost and local-only hostnames
    - Reject non-public IP targets (including resolved DNS results)
    """
    url = (raw_url or "").strip().rstrip("/")
    if not url:
        raise HTTPException(status_code=422, detail="Target URL is required")

    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=422, detail="Only http and https targets are allowed")

    if not parsed.hostname:
        raise HTTPException(status_code=422, detail="Target URL must include a valid hostname")

    host = parsed.hostname.lower().strip(".")
    if host in {"localhost"} or host.endswith(".local"):
        raise HTTPException(status_code=400, detail="Localhost and .local targets are not allowed")

    # Validate direct IP hosts.
    try:
        if not _is_public_ip(host):
            raise HTTPException(status_code=400, detail="Private or non-routable targets are not allowed")
    except ValueError:
        # Not an IP literal; resolve DNS and ensure every resolved IP is public.
        try:
            resolved_ips = _resolve_host_ips(host)
        except socket.gaierror:
            raise HTTPException(status_code=422, detail="Could not resolve target hostname")

        if not resolved_ips:
            raise HTTPException(status_code=422, detail="Could not resolve target hostname")

        for addr in resolved_ips:
            try:
                if not _is_public_ip(addr):
                    raise HTTPException(
                        status_code=400,
                        detail="Target resolves to private or non-routable addresses",
                    )
            except ValueError:
                raise HTTPException(status_code=422, detail="Resolved invalid IP address")

    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))


def hash_password(password: str) -> str:
    """Hash password with PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)
    iterations = 120_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return (
        f"{iterations}$"
        f"{base64.b64encode(salt).decode('ascii')}$"
        f"{base64.b64encode(digest).decode('ascii')}"
    )


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against stored PBKDF2 hash."""
    try:
        iterations_str, salt_b64, digest_b64 = password_hash.split("$", 2)
        iterations = int(iterations_str)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(digest_b64.encode("ascii"))
    except (ValueError, TypeError):
        return False

    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def create_access_token(*, user_id: int, username: str) -> tuple[str, int]:
    expires_delta = datetime.timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    expire_at = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    payload = {
        "sub": str(user_id),
        "username": username,
        "exp": expire_at,
        "iat": datetime.datetime.now(datetime.timezone.utc),
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token, int(expires_delta.total_seconds())


def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc


def _extract_bearer_token(request: Request, token_query: str | None) -> str:
    if token_query:
        return token_query
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth_header[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return token


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_query: str | None = Query(default=None, alias="token"),
) -> User:
    token = _extract_bearer_token(request, token_query)
    payload = _decode_token(token)
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    try:
        user_id = int(user_id_str)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid token payload") from exc

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory per-IP rate limiter."""

    def __init__(self, app, max_requests: int, window_seconds: int):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        # Keep health checks unthrottled.
        if request.url.path.startswith("/health"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        bucket = self._buckets[client_ip]

        # Drop timestamps outside the current window.
        while bucket and bucket[0] <= now - self.window_seconds:
            bucket.popleft()

        if len(bucket) >= self.max_requests:
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})

        bucket.append(now)
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Window-Seconds"] = str(self.window_seconds)
        return response


def rate_limit_settings() -> tuple[int, int]:
    return RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS
