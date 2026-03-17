"""
crawler.py — Asynchronous website crawler for endpoint discovery.

HOW THE CRAWLER WORKS
─────────────────────
1.  Start from the target URL (the "seed").
2.  Fetch the page, parse the HTML with BeautifulSoup.
3.  Extract:
    • Internal links  (<a href="…">)
    • Forms           (<form action="…"> with <input> fields)
    • URL parameters  (?key=value in discovered URLs)
4.  Add newly discovered internal URLs to a queue (BFS).
5.  Repeat until ``MAX_CRAWL_DEPTH`` or ``MAX_URLS`` is reached.

Only same-origin URLs are followed — external links are ignored so the
scanner never accidentally probes a third-party site.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs

import aiohttp
from bs4 import BeautifulSoup

from .config import (
    MAX_CRAWL_DEPTH,
    MAX_URLS,
    CRAWL_CONCURRENCY,
    USER_AGENT,
    REQUEST_TIMEOUT,
)


# ── Data containers ─────────────────────────────────────────────────

@dataclass
class FormData:
    """Represents a single HTML <form> found on a page."""
    action: str                 # resolved URL the form submits to
    method: str                 # GET or POST
    inputs: dict[str, str]      # field-name → default-value (or "")

    def __repr__(self) -> str:
        return f"<Form {self.method} {self.action} inputs={list(self.inputs)}>"


@dataclass
class CrawlResult:
    """Everything the crawler discovered about the target."""
    urls: list[str] = field(default_factory=list)       # all internal URLs
    forms: list[FormData] = field(default_factory=list)  # HTML forms
    parameters: dict[str, list[str]] = field(default_factory=dict)
    # Maps URL → list of parameter names found in that URL's query string


# ── Helpers ─────────────────────────────────────────────────────────

def _is_same_origin(base: str, url: str) -> bool:
    """Return True if *url* shares the same scheme+netloc as *base*."""
    b, u = urlparse(base), urlparse(url)
    return (b.scheme == u.scheme) and (b.netloc == u.netloc)


def _normalise(url: str) -> str:
    """Strip fragment and trailing slash for deduplication."""
    parsed = urlparse(url)
    clean = parsed._replace(fragment="")
    result = clean.geturl().rstrip("/")
    return result


def _extract_params(url: str) -> list[str]:
    """Return query-parameter names from a URL."""
    return list(parse_qs(urlparse(url).query).keys())


# ── Core crawler ────────────────────────────────────────────────────

async def crawl(
    target_url: str,
    *,
    max_depth: int = MAX_CRAWL_DEPTH,
    max_urls: int = MAX_URLS,
    on_progress: Optional[callable] = None,
) -> CrawlResult:
    """
    Crawl *target_url* up to *max_depth* levels, returning a
    ``CrawlResult`` with all discovered endpoints.

    Parameters
    ----------
    target_url : str
        Seed URL to start crawling from.
    max_depth : int
        How many link-hops deep to go.
    max_urls : int
        Hard cap on the total number of URLs to visit.
    on_progress : callable, optional
        ``async def callback(visited: int, total_queued: int)``
        called after each page is fetched, useful for progress bars.
    """

    result = CrawlResult()
    visited: set[str] = set()
    # Queue items: (url, current_depth)
    queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
    await queue.put((_normalise(target_url), 0))

    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    connector = aiohttp.TCPConnector(limit=CRAWL_CONCURRENCY, ssl=False)

    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=connector,
        headers={"User-Agent": USER_AGENT},
    ) as session:

        while not queue.empty() and len(visited) < max_urls:
            url, depth = await queue.get()
            if url in visited:
                continue
            visited.add(url)

            try:
                async with session.get(url, allow_redirects=True) as resp:
                    if "text/html" not in resp.headers.get("Content-Type", ""):
                        continue
                    html = await resp.text(errors="replace")
            except Exception:
                continue  # network errors — skip this URL

            result.urls.append(url)

            # Extract query parameters
            params = _extract_params(url)
            if params:
                result.parameters[url] = params

            # Parse HTML
            soup = BeautifulSoup(html, "html.parser")

            # ── Discover links ──────────────────────────────────
            if depth < max_depth:
                for tag in soup.find_all("a", href=True):
                    href = urljoin(url, tag["href"])
                    href = _normalise(href)
                    if _is_same_origin(target_url, href) and href not in visited:
                        await queue.put((href, depth + 1))

            # ── Discover forms ──────────────────────────────────
            for form_tag in soup.find_all("form"):
                action = urljoin(url, form_tag.get("action", ""))
                method = (form_tag.get("method") or "GET").upper()
                inputs: dict[str, str] = {}
                for inp in form_tag.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        inputs[name] = inp.get("value", "")
                result.forms.append(FormData(action=action, method=method, inputs=inputs))

            # Progress callback
            if on_progress:
                await on_progress(len(visited), queue.qsize() + len(visited))

    return result
