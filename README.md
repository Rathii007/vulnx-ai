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
  - Use a comma-separated list for multiple frontends.
  - Do not include a trailing slash.
  - Example: ALLOWED_ORIGINS=https://vulnx-ai.vercel.app,http://localhost:3000
- ENABLE_METRICS=true
- SENTRY_DSN=<optional>

### Frontend environment

- NEXT_PUBLIC_API_BASE_URL=https://your-backend-domain.com

## Deploy (Render + Vercel)

1. Push this repository to GitHub.
2. Deploy backend on Render:
  - Create a new Blueprint service and select this repository.
  - Render will detect `render.yaml` at the repo root and create:
    - `vulnx-backend` (Docker web service from `backend/`)
    - `vulnx-postgres` (PostgreSQL database)
  - After first deploy, confirm backend health at `/health/live`.
3. Deploy frontend on Vercel:
  - Import the same repository.
  - Set project Root Directory to `frontend`.
  - Add env var `NEXT_PUBLIC_API_BASE_URL` with your Render backend URL.
4. Update backend CORS in Render env vars:
  - `ALLOWED_ORIGINS=https://vulnx-ai.vercel.app`
  - If you keep local testing too: `ALLOWED_ORIGINS=https://vulnx-ai.vercel.app,http://localhost:3000`
5. Redeploy backend after changing env vars.

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
