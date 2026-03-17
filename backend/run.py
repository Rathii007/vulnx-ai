"""
run.py — Convenience launcher for the FastAPI development server.

Usage:
    python run.py

This starts uvicorn with hot-reload enabled so code changes are picked
up automatically during development.
"""

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
