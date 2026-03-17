"""
scanner.py — Core scanning engine that orchestrates all vulnerability tests.

ARCHITECTURE
────────────
The scanner ties together every detection module:

    ┌──────────┐     ┌──────────┐     ┌──────────┐
    │ crawler  │────▸│ scanner  │────▸│ report   │
    └──────────┘     └──────────┘     └──────────┘
                       │  │  │
           ┌───────────┘  │  └───────────┐
           ▼              ▼              ▼
      payloads.py    headers.py    (direct probes)

Workflow
--------
1.  **Crawl** the target to discover endpoints.
2.  Run the following tests *concurrently*:
    a.  XSS injection on parameters & forms
    b.  SQL injection on parameters & forms
    c.  Open Redirect on redirect-like parameters
    d.  Directory listing probes
    e.  Sensitive file exposure probes
    f.  Security header analysis
3.  Collect all findings and return them.

Progress is tracked via an in-memory dict so the API can stream
real-time updates to the frontend.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Optional
from urllib.parse import urlencode, urlparse, urljoin, parse_qs, urlunparse

import aiohttp

from .config import USER_AGENT, REQUEST_TIMEOUT, SCAN_CONCURRENCY
from .crawler import crawl, CrawlResult
from .headers import analyse_headers
from .payloads import (
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    SQLI_ERROR_SIGNATURES,
    OPEN_REDIRECT_PAYLOADS,
    REDIRECT_PARAM_NAMES,
    SENSITIVE_FILE_PATHS,
    DIRECTORY_LISTING_SIGNATURES,
    DIRECTORY_LISTING_PATHS,
)


# ── In-memory progress store (scan_id → dict) ──────────────────────
_progress: dict[int, dict[str, Any]] = {}


def get_progress(scan_id: int) -> dict[str, Any]:
    return _progress.get(scan_id, {"progress": 0, "status": "pending", "message": ""})


def _set_progress(scan_id: int, progress: int, status: str, message: str = ""):
    _progress[scan_id] = {"progress": progress, "status": status, "message": message}


# ── Helpers ─────────────────────────────────────────────────────────

def _inject_param(url: str, param: str, payload: str) -> str:
    """Replace the value of *param* in *url*'s query string with *payload*."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _snippet(text: str, needle: str, radius: int = 90) -> str:
    """Return a compact snippet around *needle* for operator review."""
    if not text or not needle:
        return ""
    index = text.lower().find(needle.lower())
    if index == -1:
        return ""
    start = max(0, index - radius)
    end = min(len(text), index + len(needle) + radius)
    excerpt = re.sub(r"\s+", " ", text[start:end]).strip()
    return excerpt[:220]


def _build_sensitive_signature_match(entry: dict[str, str], body: str) -> Optional[str]:
    signatures = entry.get("signatures", "")
    if not signatures:
        return None
    for signature in signatures.split("|"):
        if signature and signature in body:
            return signature
    return None


async def _fetch(session: aiohttp.ClientSession, url: str, method: str = "GET",
                 data: dict | None = None) -> tuple[int, str, dict]:
    """Fetch a URL and return (status_code, body_text, headers_dict)."""
    try:
        if method.upper() == "POST":
            async with session.post(url, data=data, ssl=False, allow_redirects=False) as r:
                text = await r.text(errors="replace")
                return r.status, text, dict(r.headers)
        else:
            async with session.get(url, ssl=False, allow_redirects=False) as r:
                text = await r.text(errors="replace")
                return r.status, text, dict(r.headers)
    except Exception:
        return 0, "", {}


# ── Individual test functions ───────────────────────────────────────

async def _test_xss(
    session: aiohttp.ClientSession,
    crawl_result: CrawlResult,
) -> list[dict[str, Any]]:
    """
    XSS DETECTION LOGIC
    ────────────────────
    For each discovered URL parameter and form field, inject every XSS
    payload and check if the payload appears *unescaped* in the response
    body.  If it does, the application is reflecting user input without
    sanitisation — a textbook Reflected XSS.
    """
    findings: list[dict[str, Any]] = []

    # Test URL parameters
    for url, params in crawl_result.parameters.items():
        for param in params:
            for payload in XSS_PAYLOADS:
                test_url = _inject_param(url, param, payload)
                status, body, _ = await _fetch(session, test_url)
                if status and payload in body:
                    evidence = _snippet(body, payload)
                    confidence = "medium" if any(token in evidence.lower() for token in ["<script", "onerror=", "onload=", "onmouseover=", "onfocus="]) else "low"
                    findings.append({
                        "name": "Cross-Site Scripting (XSS)",
                        "severity": "Medium",
                        "endpoint": test_url,
                        "payload": payload,
                        "confidence": confidence,
                        "evidence": evidence or "Payload reflected in response body.",
                        "explanation": (
                            "Scanner payload reflection was detected in the response. "
                            "This is a useful signal for reflected XSS, but it still "
                            "requires manual verification to confirm browser execution context."
                        ),
                        "remediation": (
                            "1. Sanitise all user input on the server side.\n"
                            "2. Use context-aware output encoding (HTML-encode for "
                            "HTML context, JS-encode for JavaScript context).\n"
                            "3. Implement a strong Content-Security-Policy header.\n"
                            "4. Use frameworks that auto-escape by default (React, "
                            "Angular, Jinja2 with autoescape)."
                        ),
                        "owasp_category": "A03:2021 – Injection",
                    })
                    break  # one finding per param is enough

    # Test form fields
    for form in crawl_result.forms:
        for input_name in form.inputs:
            for payload in XSS_PAYLOADS:
                test_data = {**form.inputs, input_name: payload}
                status, body, _ = await _fetch(
                    session, form.action, method=form.method, data=test_data
                )
                if status and payload in body:
                    evidence = _snippet(body, payload)
                    findings.append({
                        "name": "Cross-Site Scripting (XSS) via Form",
                        "severity": "Medium",
                        "endpoint": f"{form.action} (field: {input_name})",
                        "payload": payload,
                        "confidence": "low",
                        "evidence": evidence or f"Payload reflected after submitting form field '{input_name}'.",
                        "explanation": (
                            "A scanner payload submitted through a form field was reflected in the response. "
                            "Manual verification is needed to determine whether it is executable XSS or harmless reflection."
                        ),
                        "remediation": (
                            "Sanitise and encode all form inputs before rendering "
                            "them in HTML.  Use parameterised templates."
                        ),
                        "owasp_category": "A03:2021 – Injection",
                    })
                    break

    return findings


async def _test_sqli(
    session: aiohttp.ClientSession,
    crawl_result: CrawlResult,
) -> list[dict[str, Any]]:
    """
    SQL INJECTION DETECTION LOGIC
    ─────────────────────────────
    Inject SQL payloads and look for database error messages in the
    response.  Error messages like "You have an error in your SQL syntax"
    indicate the user input was concatenated directly into a SQL query
    without parameterisation.
    """
    findings: list[dict[str, Any]] = []

    for url, params in crawl_result.parameters.items():
        for param in params:
            for payload in SQLI_PAYLOADS:
                test_url = _inject_param(url, param, payload)
                status, body, _ = await _fetch(session, test_url)
                if not status:
                    continue
                body_lower = body.lower()
                for sig in SQLI_ERROR_SIGNATURES:
                    if sig in body_lower:
                        evidence = _snippet(body, sig)
                        findings.append({
                            "name": "SQL Injection",
                            "severity": "High",
                            "endpoint": test_url,
                            "payload": payload,
                            "confidence": "medium",
                            "evidence": evidence or f"Database error signature matched: {sig}",
                            "explanation": (
                                f"The response contains a SQL error signature "
                                f"('{sig}') after injecting the payload. This is "
                                "consistent with unsafe query construction, but it "
                                "should be manually confirmed before treating it as exploitable SQL injection."
                            ),
                            "remediation": (
                                "1. Use parameterised queries / prepared statements.\n"
                                "2. Use an ORM (e.g. SQLAlchemy, Django ORM).\n"
                                "3. Apply least-privilege database permissions.\n"
                                "4. Validate and whitelist expected input formats."
                            ),
                            "owasp_category": "A03:2021 – Injection",
                        })
                        break
                else:
                    continue
                break  # one finding per param

    # Test forms too
    for form in crawl_result.forms:
        for input_name in form.inputs:
            for payload in SQLI_PAYLOADS:
                test_data = {**form.inputs, input_name: payload}
                status, body, _ = await _fetch(
                    session, form.action, method=form.method, data=test_data
                )
                if not status:
                    continue
                body_lower = body.lower()
                for sig in SQLI_ERROR_SIGNATURES:
                    if sig in body_lower:
                        evidence = _snippet(body, sig)
                        findings.append({
                            "name": "SQL Injection via Form",
                            "severity": "High",
                            "endpoint": f"{form.action} (field: {input_name})",
                            "payload": payload,
                            "confidence": "medium",
                            "evidence": evidence or f"Database error signature matched after submitting field '{input_name}'.",
                            "explanation": (
                                f"A database error signature ('{sig}') appeared after submitting the payload through a form field. "
                                "That is a meaningful signal, but not definitive proof of exploitable injection."
                            ),
                            "remediation": (
                                "Use parameterised queries.  Never concatenate "
                                "user input into SQL strings."
                            ),
                            "owasp_category": "A03:2021 – Injection",
                        })
                        break
                else:
                    continue
                break

    return findings


async def _test_open_redirect(
    session: aiohttp.ClientSession,
    crawl_result: CrawlResult,
) -> list[dict[str, Any]]:
    """
    OPEN REDIRECT DETECTION
    ───────────────────────
    If a URL has a parameter whose name suggests it controls redirection
    (e.g. ?next=, ?redirect=), we inject an external URL and check
    whether the server responds with a 3xx Location header pointing to
    that external URL.
    """
    findings: list[dict[str, Any]] = []

    for url, params in crawl_result.parameters.items():
        for param in params:
            if param.lower() not in REDIRECT_PARAM_NAMES:
                continue
            for payload in OPEN_REDIRECT_PAYLOADS:
                test_url = _inject_param(url, param, payload)
                status, _, headers = await _fetch(session, test_url)
                location = headers.get("Location", "")
                if status in (301, 302, 303, 307, 308) and "evil.com" in location:
                    findings.append({
                        "name": "Open Redirect",
                        "severity": "Medium",
                        "endpoint": test_url,
                        "payload": payload,
                        "confidence": "medium",
                        "evidence": f"Redirect Location header: {location}",
                        "explanation": (
                            "The server redirects to an attacker-controlled URL.  "
                            "This can be used for phishing attacks that appear to "
                            "originate from a trusted domain."
                        ),
                        "remediation": (
                            "1. Validate redirect targets against a whitelist.\n"
                            "2. Use relative URLs for internal redirects.\n"
                            "3. Warn the user before redirecting to external sites."
                        ),
                        "owasp_category": "A01:2021 – Broken Access Control",
                    })
                    break

    return findings


async def _test_directory_listing(
    session: aiohttp.ClientSession,
    target_url: str,
) -> list[dict[str, Any]]:
    """
    DIRECTORY LISTING DETECTION
    ───────────────────────────
    Request common directory paths and look for signatures like
    "Index of /" that indicate the web server has directory indexing
    enabled — exposing the file structure to anyone.
    """
    findings: list[dict[str, Any]] = []

    for path in DIRECTORY_LISTING_PATHS:
        url = urljoin(target_url, path)
        status, body, _ = await _fetch(session, url)
        if status == 200:
            for sig in DIRECTORY_LISTING_SIGNATURES:
                if sig in body:
                    findings.append({
                        "name": "Directory Listing Enabled",
                        "severity": "Medium",
                        "endpoint": url,
                        "payload": None,
                        "confidence": "high",
                        "evidence": _snippet(body, sig) or f"Directory listing signature matched: {sig}",
                        "explanation": (
                            f"The path '{path}' returns a directory listing "
                            f"(detected '{sig}').  This reveals internal file "
                            "names and structure to attackers."
                        ),
                        "remediation": (
                            "Disable directory indexing in your web server config:\n"
                            "• Apache: Options -Indexes\n"
                            "• Nginx: autoindex off;"
                        ),
                        "owasp_category": "A01:2021 – Broken Access Control",
                    })
                    break

    return findings


async def _test_sensitive_files(
    session: aiohttp.ClientSession,
    target_url: str,
) -> list[dict[str, Any]]:
    """
    SENSITIVE FILE EXPOSURE
    ───────────────────────
    Attempt to access files that should never be publicly reachable
    (.env, .git/config, backup archives, etc.).  A 200 OK whose body
    contains the expected signature means the file is exposed.
    """
    findings: list[dict[str, Any]] = []

    for entry in SENSITIVE_FILE_PATHS:
        url = urljoin(target_url, entry["path"])
        status, body, _ = await _fetch(session, url)
        matched_signature = _build_sensitive_signature_match(entry, body)
        if status == 200 and matched_signature:
            findings.append({
                "name": f"Sensitive File Exposed: {entry['path']}",
                "severity": "High",
                "endpoint": url,
                "payload": None,
                "confidence": "medium",
                "evidence": _snippet(body, matched_signature) or f"Matched signature: {matched_signature}",
                "explanation": (
                    f"{entry['description']}.  "
                    "This file is publicly accessible and may leak credentials, "
                    "source code, or internal configuration."
                ),
                "remediation": (
                    f"1. Block access to {entry['path']} in your web server config.\n"
                    "2. Move sensitive files outside the web root.\n"
                    "3. Add rules to .htaccess or nginx config to deny access to "
                    "dot-files and backup archives."
                ),
                "owasp_category": "A01:2021 – Broken Access Control",
            })

    return findings


# ── Main scan orchestrator ──────────────────────────────────────────

async def run_scan(
    scan_id: int,
    target_url: str,
) -> list[dict[str, Any]]:
    """
    Execute a full vulnerability scan against *target_url*.

    Returns a list of vulnerability dicts (ready for DB insertion).
    Progress is tracked in ``_progress[scan_id]``.
    """

    _set_progress(scan_id, 0, "crawling", "Discovering pages and forms…")

    # ── Step 1: Crawl ───────────────────────────────────────────────
    async def _crawl_progress(visited: int, total: int):
        pct = min(int(visited / max(total, 1) * 20), 20)  # 0-20 %
        _set_progress(scan_id, pct, "crawling", f"Visited {visited} pages…")

    crawl_result = await crawl(target_url, on_progress=_crawl_progress)
    _set_progress(scan_id, 20, "scanning", "Running vulnerability tests…")

    # ── Step 2: Run all tests concurrently ──────────────────────────
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    connector = aiohttp.TCPConnector(limit=SCAN_CONCURRENCY, ssl=False)

    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=connector,
        headers={"User-Agent": USER_AGENT},
    ) as session:

        tasks = [
            _test_xss(session, crawl_result),
            _test_sqli(session, crawl_result),
            _test_open_redirect(session, crawl_result),
            _test_directory_listing(session, target_url),
            _test_sensitive_files(session, target_url),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

    _set_progress(scan_id, 80, "scanning", "Analysing security headers…")

    # ── Step 3: Header analysis (separate session) ──────────────────
    header_findings = await analyse_headers(target_url)

    _set_progress(scan_id, 95, "finalising", "Building report…")

    # ── Merge all findings ──────────────────────────────────────────
    all_findings: list[dict[str, Any]] = []
    for result in results:
        if isinstance(result, list):
            all_findings.extend(result)
    all_findings.extend(header_findings)

    _set_progress(scan_id, 100, "completed", f"Found {len(all_findings)} issues.")
    return all_findings
