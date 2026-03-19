"""
config.py — Central configuration for the vulnerability scanner.

All tuneable knobs live here so every other module can import them
from a single place.  Values are intentionally conservative (low
concurrency, shallow crawl depth) to keep educational scans safe and
fast.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

_BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(_BASE_DIR / ".env")
load_dotenv(_BASE_DIR / ".env.local", override=True)


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}

# ── Database ────────────────────────────────────────────────────────
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./scanner.db",
)

# ── API security / deployment settings ─────────────────────────────
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "120"))

RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "120"))

# ── Monitoring / error tracking ─────────────────────────────────────
ENABLE_METRICS = _as_bool(os.getenv("ENABLE_METRICS"), True)
SENTRY_DSN = os.getenv("SENTRY_DSN", "")

# ── AI assistant settings ───────────────────────────────────────────
AI_ENABLED = _as_bool(os.getenv("AI_ENABLED"), True)
AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama").strip().lower()
AI_TIMEOUT_SECONDS = int(os.getenv("AI_TIMEOUT_SECONDS", "20"))
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")

# ── Crawler settings ────────────────────────────────────────────────
MAX_CRAWL_DEPTH = int(os.getenv("MAX_CRAWL_DEPTH", "3"))
MAX_URLS = int(os.getenv("MAX_URLS", "50"))           # hard cap on discovered URLs
CRAWL_CONCURRENCY = int(os.getenv("CRAWL_CONCURRENCY", "5"))

# ── HTTP client defaults ────────────────────────────────────────────
USER_AGENT = (
    "VulnScanner/1.0 (Educational; "
    "+https://github.com/yourusername/vuln-scanner)"
)
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))  # seconds

# ── Scanner settings ───────────────────────────────────────────────
SCAN_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "10"))

# ── Severity weights used by the risk-scoring algorithm ─────────────
SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
}
