# VulnX

VulnX is an educational web security workbench for launching authorized scans,
monitoring progress in real time, and reviewing actionable findings. It is built
with a FastAPI backend, a Next.js frontend, and SQLite for local development or
PostgreSQL for deployed environments.

It demonstrates authenticated scanning workflows, safe target validation, API
security, data protection, and modern deployment practices for authorized
security learning and experimentation.

> Only scan systems that you own or have explicit permission to test. This
> project is intended for defensive learning and authorized security testing.

## Features

- JWT registration, login, and per-user scan authorization.
- Safe target URL validation with private-network SSRF protection.
- Quick and deep scan modes.
- Real-time scan progress using Server-Sent Events.
- Findings grouped by severity, endpoint, confidence, and OWASP category.
- PDF report generation.
- Optional AI triage through Groq or a local Ollama model.
- Health, readiness, metrics, rate limiting, and optional Sentry integration.
- Docker Compose support for the API, frontend, and PostgreSQL.

## Project Layout

```text
backend/
  app/
    main.py          FastAPI routes and application lifecycle
    scanner.py       Crawl and vulnerability checks
    crawler.py       Target discovery
    ai_assistant.py  Groq/Ollama triage and local fallback
    database.py      Async SQLAlchemy setup
    security.py      Authentication, validation, and rate limiting
    report.py        PDF report generation
  run.py             Local development launcher
frontend/
  src/app/page.tsx   Scanner dashboard
docker-compose.yml   Local multi-service deployment
render.yaml          Render deployment blueprint
```

## Requirements

- Python 3.11 or newer
- Node.js 20 or newer and npm
- Docker Desktop, only if using Docker Compose
- A Groq API key or a local Ollama installation, if AI triage is enabled

## Local Setup

### 1. Configure the backend

From PowerShell:

```powershell
cd D:\scanner\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env.local
```

Edit `backend/.env.local` and set at least a strong `JWT_SECRET_KEY`. For Groq
triage, set:

```env
AI_ENABLED=true
AI_PROVIDER=groq
GROQ_API_KEY=your-key-here
GROQ_MODEL=openai/gpt-oss-20b
```

The local default database is SQLite at `backend/scanner.db`. To use PostgreSQL,
replace `DATABASE_URL` with a `postgresql+asyncpg://...` connection string.

### 2. Start the backend

Keep this terminal open:

```powershell
cd D:\scanner\backend
.\.venv\Scripts\Activate.ps1
python run.py
```

The API runs at http://127.0.0.1:8000.

### 3. Start the frontend

Open a second terminal:

```powershell
cd D:\scanner\frontend
npm install
npm run dev -- --hostname 127.0.0.1
```

Open http://127.0.0.1:3000 in a browser. The frontend reads the API URL from
`NEXT_PUBLIC_API_BASE_URL`, which defaults to `http://localhost:8000`.

### Other operating systems

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env.local
python run.py
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

## Docker Compose

From the repository root:

```powershell
docker compose up --build
```

This starts PostgreSQL on port `5432`, the backend on port `8000`, and the
frontend on port `3000`. Open http://localhost:3000.

To stop the services:

```powershell
docker compose down
```

Add `-v` only when you intentionally want to delete the PostgreSQL volume.

## Configuration

Backend configuration is loaded from `backend/.env` and then
`backend/.env.local`, with `.env.local` taking precedence. Never commit either
file when it contains credentials.

Important variables include:

| Variable | Purpose | Local default |
| --- | --- | --- |
| `DATABASE_URL` | Async database connection | `sqlite+aiosqlite:///./scanner.db` |
| `JWT_SECRET_KEY` | Signs access tokens | Set a private random value |
| `ALLOWED_ORIGINS` | CORS allow-list | `http://localhost:3000` |
| `AI_ENABLED` | Enables AI triage | `true` |
| `AI_PROVIDER` | `groq` or `ollama` | `ollama` in the example |
| `GROQ_API_KEY` | Groq credential | Empty |
| `GROQ_MODEL` | Groq chat model | `openai/gpt-oss-20b` |
| `AI_TIMEOUT_SECONDS` | AI request timeout | `20` |
| `LOG_LEVEL` | Backend log verbosity | `INFO` locally |

If the remote AI provider is unavailable or returns invalid JSON, VulnX uses a
deterministic local rule-based triage fallback and marks the result accordingly.

## API Endpoints

Interactive API documentation is available at http://127.0.0.1:8000/docs in
development mode.

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/health/live` | Liveness check |
| `GET` | `/health/ready` | Readiness check |
| `POST` | `/api/auth/register` | Create an account |
| `POST` | `/api/auth/login` | Get a JWT access token |
| `GET` | `/api/auth/me` | Get the current user |
| `POST` | `/api/scans` | Start a scan |
| `GET` | `/api/scans` | List the current user's scans |
| `GET` | `/api/scans/{id}` | View scan details and findings |
| `GET` | `/api/scans/{id}/progress` | Stream scan progress via SSE |
| `GET` | `/api/scans/{id}/report/pdf` | Download a PDF report |
| `GET` | `/metrics` | Prometheus metrics when enabled |

## Validation

Backend syntax check:

```powershell
cd backend
.\.venv\Scripts\python.exe -m py_compile app\main.py run.py
```

Frontend lint and production build:

```powershell
cd frontend
npm run lint
npm run build
```

## Deployment

The repository includes `render.yaml` for a Render backend/PostgreSQL setup and
the frontend can be deployed separately from the `frontend` directory, for
example on Vercel. Set production secrets in the hosting provider's environment
configuration, configure `ALLOWED_ORIGINS` with the exact frontend origin, and
set `NEXT_PUBLIC_API_BASE_URL` to the deployed backend URL.

Before publishing or deploying:

- Rotate any API key that has been exposed.
- Confirm `.env`, `.env.local`, databases, and virtual environments are ignored.
- Use a strong production `JWT_SECRET_KEY`.
- Restrict CORS to trusted frontend origins.
- Run a fresh scan only against an authorized target.

## Contributing

1. Create a feature branch.
2. Keep changes focused and document configuration changes.
3. Run backend syntax checks and frontend lint/build before opening a pull request.
4. Do not commit credentials, local databases, scan output, or generated build files.
