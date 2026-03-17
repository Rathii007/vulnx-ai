# VulnScanner

Production-hardened educational web vulnerability scanner with a FastAPI backend and Next.js frontend.

## What Is Included In This Hardened Build

- PostgreSQL-ready database configuration.
- JWT auth (register/login/me endpoints) with per-user scan authorization.
- SSRF-safe target validation and rate limiting.
- Monitoring endpoints (`/health/*`, `/metrics`).
- Optional Sentry error tracking via `SENTRY_DSN`.

## Run Locally (without Docker)

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
set DATABASE_URL=postgresql+asyncpg://scanner:scanner@localhost:5432/scanner
set JWT_SECRET_KEY=change-me-in-production
set ALLOWED_ORIGINS=http://localhost:3000
python run.py
```

### Frontend

```bash
cd frontend
npm install
set NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
npm run dev
```

## Run with Docker Compose

```bash
# from repo root
set ALLOWED_ORIGINS=http://localhost:3000
set NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
set JWT_SECRET_KEY=change-me-in-production
set POSTGRES_PASSWORD=scanner
docker compose up --build
```

## Pre-Deploy Required Environment Variables

Set these before starting the application in your deployment environment:

### Backend environment

- SCANNER_API_KEY=<strong-random-secret>
- DATABASE_URL=postgresql+asyncpg://<user>:<password>@<host>:5432/<db>
- JWT_SECRET_KEY=<strong-random-secret>
- JWT_ALGORITHM=HS256
- JWT_ACCESS_TOKEN_EXPIRE_MINUTES=120
- ALLOWED_ORIGINS=https://your-frontend-domain.com
- ENABLE_METRICS=true
- SENTRY_DSN=<optional>

### Frontend environment

- NEXT_PUBLIC_API_BASE_URL=https://your-backend-domain.com

- Frontend: http://localhost:3000
- Backend: http://localhost:8000
- Health checks:
  - http://localhost:8000/health/live
  - http://localhost:8000/health/ready

## Production Hardening Included

- Configurable strict CORS allow-list.
- JWT authentication with per-user scan authorization.
- Basic per-IP rate limiting middleware.
- Target URL validation with private-network SSRF blocking.
- Health and metrics endpoints for orchestration and monitoring.
- Optional Sentry integration for error tracking.
