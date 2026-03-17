"""
report.py — Risk scoring, OWASP mapping, and PDF report generation.

RISK SCORING ALGORITHM
──────────────────────
The security score is a number from 0 to 100 where:
    100  =  no vulnerabilities found (best)
      0  =  many critical vulnerabilities (worst)

Calculation:
    1.  Sum weighted penalties:  Σ (severity_weight × count)
    2.  Normalise against a maximum expected penalty (50 by default).
    3.  Score = max(0, 100 − normalised_penalty)

This keeps the algorithm simple and transparent for educational use.
"""

from __future__ import annotations

import datetime
from typing import Any

from fpdf import FPDF

from .config import SEVERITY_WEIGHTS


# ── OWASP Top 10 (2021) quick-reference mapping ────────────────────

OWASP_MAP: dict[str, str] = {
    "Cross-Site Scripting (XSS)":          "A03:2021 – Injection",
    "Cross-Site Scripting (XSS) via Form": "A03:2021 – Injection",
    "SQL Injection":                       "A03:2021 – Injection",
    "SQL Injection via Form":              "A03:2021 – Injection",
    "Open Redirect":                       "A01:2021 – Broken Access Control",
    "Directory Listing Enabled":           "A01:2021 – Broken Access Control",
    "Sensitive File Exposed":              "A01:2021 – Broken Access Control",
    "Missing Security Header":            "A05:2021 – Security Misconfiguration",
    "Insecure Cookie":                     "A05:2021 – Security Misconfiguration",
}


# ── Risk scoring ────────────────────────────────────────────────────

def _pdf_text(value: Any) -> str:
    """Normalise text to characters supported by FPDF core fonts."""
    text = "" if value is None else str(value)
    replacements = {
        "–": "-",
        "—": "-",
        "…": "...",
        "•": "-",
        "’": "'",
        "‘": "'",
        "“": '"',
        "”": '"',
        "\u00a0": " ",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text.encode("latin-1", "replace").decode("latin-1")


def _pdf_multiline(pdf: FPDF, text: Any, line_height: int = 6) -> None:
    """Write wrapped text starting from the left margin."""
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(pdf.w - pdf.l_margin - pdf.r_margin, line_height, _pdf_text(text))

def calculate_score(vulnerabilities: list[dict[str, Any]]) -> float:
    """
    Return a security score between 0 (worst) and 100 (best).

    The score penalises each finding by its severity weight and
    normalises the total against a configurable ceiling.
    """
    if not vulnerabilities:
        return 100.0

    total_penalty = sum(
        SEVERITY_WEIGHTS.get(v.get("severity", "Low"), 1)
        for v in vulnerabilities
    )

    # Normalise: 50 penalty points → score 0
    max_penalty = 50.0
    score = max(0.0, 100.0 - (total_penalty / max_penalty) * 100.0)
    return round(score, 1)


# ── PDF report generation ──────────────────────────────────────────

def generate_pdf(
    target_url: str,
    score: float,
    vulnerabilities: list[dict[str, Any]],
) -> bytes:
    """
    Build a downloadable PDF vulnerability report.

    Returns the PDF content as raw bytes.
    """

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Title ───────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 12, _pdf_text("Vulnerability Scan Report"), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(4)

    # ── Meta info ───────────────────────────────────────────────────
    pdf.set_font("Helvetica", "", 11)
    _pdf_multiline(pdf, f"Target:  {target_url}", 7)
    pdf.cell(0, 7, _pdf_text(f"Date:    {datetime.datetime.utcnow():%Y-%m-%d %H:%M UTC}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, _pdf_text(f"Score:   {score} / 100"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, _pdf_text(f"Issues:  {len(vulnerabilities)}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # ── Summary table ───────────────────────────────────────────────
    severity_counts: dict[str, int] = {}
    for v in vulnerabilities:
        sev = v.get("severity", "Low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, _pdf_text("Summary"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    for sev in ("Critical", "High", "Medium", "Low"):
        count = severity_counts.get(sev, 0)
        pdf.cell(0, 7, _pdf_text(f"  {sev}: {count}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # ── Detailed findings ──────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, _pdf_text("Detailed Findings"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    for i, v in enumerate(vulnerabilities, 1):
        pdf.set_font("Helvetica", "B", 11)
        _pdf_multiline(pdf, f"{i}. {v.get('name', 'Unknown')}", 7)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, _pdf_text(f"   Severity:  {v.get('severity', 'N/A')}"), new_x="LMARGIN", new_y="NEXT")
        _pdf_multiline(pdf, f"   Endpoint:  {v.get('endpoint', 'N/A')}")

        payload = v.get("payload")
        if payload:
            _pdf_multiline(pdf, f"   Payload:   {payload}")

        confidence = v.get("confidence")
        if confidence:
            pdf.cell(0, 6, _pdf_text(f"   Confidence: {confidence}"), new_x="LMARGIN", new_y="NEXT")

        evidence = v.get("evidence")
        if evidence:
            _pdf_multiline(pdf, f"   Evidence:  {evidence}")

        owasp = v.get("owasp_category")
        if owasp:
            _pdf_multiline(pdf, f"   OWASP:     {owasp}")

        explanation = v.get("explanation", "")
        if explanation:
            pdf.ln(1)
            pdf.set_font("Helvetica", "I", 10)
            _pdf_multiline(pdf, f"   {explanation}", 5)

        remediation = v.get("remediation", "")
        if remediation:
            pdf.ln(1)
            pdf.set_font("Helvetica", "", 10)
            _pdf_multiline(pdf, f"   Fix: {remediation}", 5)

        pdf.ln(4)

    # ── Footer ──────────────────────────────────────────────────────
    pdf.ln(6)
    pdf.set_font("Helvetica", "I", 9)
    pdf.cell(
        0, 6,
        _pdf_text("Generated by VulnScanner - for educational purposes only."),
        new_x="LMARGIN", new_y="NEXT", align="C",
    )

    return bytes(pdf.output())
