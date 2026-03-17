"""
headers.py — Security-header analysis module.

WHY SECURITY HEADERS MATTER
────────────────────────────
HTTP response headers are one of the cheapest and most effective
defence layers a website can deploy.  Missing headers are a very
common finding even on well-built sites.

This module checks for the presence (and basic correctness) of several
critical headers and cookie attributes, returning a list of
Vulnerability dicts for any issues found.
"""

from __future__ import annotations
from typing import Any

import aiohttp

from .config import USER_AGENT, REQUEST_TIMEOUT


# ── Header definitions ──────────────────────────────────────────────
# Each entry describes *what* we look for and *why* it matters.

RECOMMENDED_HEADERS: list[dict[str, str]] = [
    {
        "header": "Content-Security-Policy",
        "severity": "Medium",
        "explanation": (
            "Content-Security-Policy (CSP) tells the browser which sources "
            "of content are allowed.  Without it, the site is more "
            "susceptible to XSS and data-injection attacks."
        ),
        "remediation": (
            "Add a Content-Security-Policy header.  Start with a report-only "
            "policy and tighten it over time.  Example:\n"
            "Content-Security-Policy: default-src 'self'; script-src 'self'"
        ),
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    {
        "header": "X-Frame-Options",
        "severity": "Medium",
        "explanation": (
            "X-Frame-Options prevents the page from being embedded in an "
            "<iframe>, which mitigates clickjacking attacks."
        ),
        "remediation": (
            "Add the header: X-Frame-Options: DENY  (or SAMEORIGIN if "
            "you need to embed the page on your own domain)."
        ),
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    {
        "header": "Strict-Transport-Security",
        "severity": "Medium",
        "explanation": (
            "HSTS instructs browsers to only access the site over HTTPS, "
            "preventing SSL-stripping attacks."
        ),
        "remediation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        ),
        "owasp": "A05:2021 – Security Misconfiguration",
        "https_only": "true",
    },
    {
        "header": "X-Content-Type-Options",
        "severity": "Low",
        "explanation": (
            "Without 'X-Content-Type-Options: nosniff', browsers may MIME-"
            "sniff responses away from the declared Content-Type, "
            "potentially executing malicious files."
        ),
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    {
        "header": "Referrer-Policy",
        "severity": "Low",
        "explanation": (
            "Referrer-Policy controls how much referrer information is sent "
            "with requests.  Missing it may leak sensitive URL paths to "
            "third-party sites."
        ),
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
]


# ── Core analysis function ──────────────────────────────────────────

async def analyse_headers(target_url: str) -> list[dict[str, Any]]:
    """
    Fetch *target_url* and check its response headers + cookies.

    Returns a list of vulnerability dicts ready to be stored in the DB.
    """

    findings: list[dict[str, Any]] = []
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)

    try:
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        ) as session:
            async with session.get(target_url, ssl=False, allow_redirects=True) as resp:
                headers = resp.headers
                cookies = resp.cookies
                final_scheme = resp.url.scheme.lower()

                # ── Check recommended headers ───────────────────
                missing_headers: list[str] = []
                remediations: list[str] = []
                for entry in RECOMMENDED_HEADERS:
                    if entry.get("https_only") == "true" and final_scheme != "https":
                        continue
                    if entry["header"] not in headers:
                        missing_headers.append(entry["header"])
                        remediations.append(f"- {entry['remediation']}")

                if missing_headers:
                    findings.append({
                        "name": "Security Header Baseline Gaps",
                        "severity": "Medium",
                        "endpoint": str(resp.url),
                        "payload": None,
                        "confidence": "high",
                        "evidence": "Missing headers: " + ", ".join(missing_headers),
                        "explanation": (
                            "The application is missing one or more recommended browser "
                            "security headers. This is a reliable hardening finding, but "
                            "it should be treated as misconfiguration rather than proof of exploitability."
                        ),
                        "remediation": "\n".join(remediations),
                        "owasp_category": "A05:2021 – Security Misconfiguration",
                    })

                # ── Check cookie security ───────────────────────
                for name in cookies:
                    issues: list[str] = []
                    remediations: list[str] = []
                    # For aiohttp cookies we need to check differently
                    cookie_str = resp.headers.getall("Set-Cookie", [])
                    cookie_header = ""
                    for c in cookie_str:
                        if name in c:
                            cookie_header = c.lower()
                            break

                    if "secure" not in cookie_header:
                        issues.append("missing Secure flag")
                        remediations.append(
                            "Add the Secure flag so the cookie is only sent over HTTPS."
                        )

                    if "httponly" not in cookie_header:
                        issues.append("missing HttpOnly flag")
                        remediations.append(
                            "Add HttpOnly to prevent JavaScript access to this cookie."
                        )

                    if "samesite" not in cookie_header:
                        issues.append("missing SameSite attribute")
                        remediations.append(
                            "Set SameSite=Lax (or Strict) to mitigate CSRF attacks."
                        )

                    if issues:
                        findings.append({
                            "name": f"Insecure Cookie: {name}",
                            "severity": "Medium",
                            "endpoint": target_url,
                            "payload": None,
                            "confidence": "high",
                            "evidence": "Cookie attributes missing: " + ", ".join(issues),
                            "explanation": (
                                f"The cookie '{name}' is set without: "
                                + ", ".join(issues) + ".  "
                                "This may expose it to interception or misuse."
                            ),
                            "remediation": " ".join(remediations),
                            "owasp_category": "A05:2021 – Security Misconfiguration",
                        })

    except Exception as exc:
        findings.append({
            "name": "Header Analysis Error",
            "severity": "Low",
            "endpoint": target_url,
            "payload": None,
            "explanation": f"Could not complete header analysis: {exc}",
            "remediation": "Ensure the target URL is reachable.",
            "owasp_category": "N/A",
        })

    return findings
