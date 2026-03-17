"""
database.py — Async SQLAlchemy engine & session factory for SQLite.

HOW IT WORKS
────────────
1.  We create an *async* engine backed by ``aiosqlite`` so the FastAPI
    event-loop is never blocked by database I/O.
2.  ``async_sessionmaker`` gives us a factory that produces
    ``AsyncSession`` objects — each request gets its own session via
    the ``get_db()`` dependency.
3.  ``init_db()`` is called once at application startup to create all
    tables defined in ``models.py``.
"""

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .config import DATABASE_URL

# ── Engine ──────────────────────────────────────────────────────────
engine = create_async_engine(
    DATABASE_URL,
    echo=False,           # set True for SQL debug logging
    future=True,
)

# ── Session factory ─────────────────────────────────────────────────
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Dependency for FastAPI routes ───────────────────────────────────
async def get_db():
    """Yield an ``AsyncSession`` and guarantee it is closed afterwards."""
    async with async_session() as session:
        yield session


# ── Table creation helper ──────────────────────────────────────────
async def init_db():
    """Create all tables that don't exist yet."""
    from .models import Base  # local import to avoid circular deps

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_apply_runtime_migrations)


def _apply_runtime_migrations(sync_conn):
    inspector = inspect(sync_conn)
    tables = set(inspector.get_table_names())

    if "scans" in tables:
        scan_columns = {column["name"] for column in inspector.get_columns("scans")}
        if "user_id" not in scan_columns:
            sync_conn.execute(text("ALTER TABLE scans ADD COLUMN user_id INTEGER"))

    if "vulnerabilities" not in tables:
        return

    columns = {column["name"] for column in inspector.get_columns("vulnerabilities")}
    if "confidence" not in columns:
        sync_conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN confidence VARCHAR(20)"))
    if "evidence" not in columns:
        sync_conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN evidence TEXT"))
