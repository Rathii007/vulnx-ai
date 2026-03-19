from __future__ import annotations

import json
import logging
from typing import Any

import aiohttp

from .config import (
    AI_PROVIDER,
    AI_TIMEOUT_SECONDS,
    GROQ_API_KEY,
    GROQ_BASE_URL,
    GROQ_MODEL,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
)

logger = logging.getLogger("vulnscanner.ai")


def _source_meta(provider: str, fallback_used: bool, model: str | None) -> dict[str, Any]:
    if provider == "groq" and not fallback_used:
        return {
            "source_type": "groq-ai",
            "source_label": "Groq AI",
            "is_remote_ai": True,
        }

    if provider == "ollama" and not fallback_used:
        return {
            "source_type": "local-ollama-ai",
            "source_label": "Local Ollama AI",
            "is_remote_ai": False,
        }

    if provider == "rule-based" or fallback_used:
        label = "Local Rule-Based"
        if model:
            label = f"Local Rule-Based (fallback from {provider})"
        return {
            "source_type": "local-rule-based",
            "source_label": label,
            "is_remote_ai": False,
        }

    return {
        "source_type": "unknown",
        "source_label": f"Unknown Source ({provider})",
        "is_remote_ai": False,
    }


def _severity_counts(vulnerabilities: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for item in vulnerabilities:
        sev = str(item.get("severity", "Low"))
        if sev not in counts:
            counts["Low"] += 1
        else:
            counts[sev] += 1
    return counts


def _rule_based_summary(target_url: str, score: float, vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
    counts = _severity_counts(vulnerabilities)
    total = len(vulnerabilities)

    summary = (
        f"Scan of {target_url} produced {total} findings with score {score:.1f}/100. "
        f"Critical: {counts['Critical']}, High: {counts['High']}, "
        f"Medium: {counts['Medium']}, Low: {counts['Low']}."
    )

    top_risks: list[str] = []
    actions: list[str] = []

    names = [str(v.get("name", "")).lower() for v in vulnerabilities]

    if counts["Critical"] or counts["High"]:
        top_risks.append("Immediate exploitable weaknesses may allow account takeover or data compromise.")
        actions.append("Fix all Critical and High findings first, then retest the same endpoints.")

    if any("sql injection" in name for name in names):
        top_risks.append("Potential SQL injection behavior detected in request handling.")
        actions.append("Enforce parameterized queries and strict server-side input validation.")

    if any("cross-site scripting" in name for name in names):
        top_risks.append("Input reflection suggests possible XSS paths.")
        actions.append("Apply output encoding and add a strict Content-Security-Policy.")

    if any("security header" in name or "insecure cookie" in name for name in names):
        top_risks.append("Security hardening gaps reduce baseline browser protections.")
        actions.append("Set HSTS, CSP, X-Frame-Options, and secure cookie flags.")

    if not top_risks:
        top_risks.append("No high-impact exploit patterns were detected in this scan run.")
        actions.append("Continue periodic scans and verify authentication and authorization controls manually.")

    base = {
        "summary": summary,
        "top_risks": top_risks[:4],
        "actions": actions[:5],
        "fallback_used": True,
        "provider": "rule-based",
        "model": None,
    }
    return {**base, **_source_meta(base["provider"], base["fallback_used"], base["model"]) }


def _build_ollama_prompt(target_url: str, score: float, vulnerabilities: list[dict[str, Any]]) -> str:
    compact_findings = []
    for finding in vulnerabilities[:40]:
        compact_findings.append(
            {
                "name": finding.get("name"),
                "severity": finding.get("severity"),
                "endpoint": finding.get("endpoint"),
                "confidence": finding.get("confidence"),
                "owasp_category": finding.get("owasp_category"),
            }
        )

    payload = {
        "target_url": target_url,
        "score": score,
        "findings": compact_findings,
    }

    return (
        "You are a cybersecurity triage assistant."
        " Analyze the scan JSON and return STRICT JSON only with keys:"
        " summary (string), top_risks (array of short strings), actions (array of short strings)."
        " Keep it concise, practical, and non-alarmist."
        " Focus on highest impact fixes first.\n\n"
        f"SCAN_JSON:\n{json.dumps(payload, ensure_ascii=True)}"
    )


def _build_groq_prompt(target_url: str, score: float, vulnerabilities: list[dict[str, Any]]) -> str:
    """Build a detailed prompt for Groq with comprehensive scoring and finding breakdown."""
    compact_findings = []
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    
    for finding in vulnerabilities[:40]:
        sev = str(finding.get("severity", "Low"))
        if sev in severity_counts:
            severity_counts[sev] += 1
        compact_findings.append(
            {
                "name": finding.get("name"),
                "severity": finding.get("severity"),
                "endpoint": finding.get("endpoint"),
                "confidence": finding.get("confidence"),
                "owasp_category": finding.get("owasp_category"),
            }
        )

    payload = {
        "target_url": target_url,
        "overall_score": score,
        "total_findings": len(vulnerabilities),
        "severity_breakdown": severity_counts,
        "findings": compact_findings,
    }

    return (
        "Analyze this security scan and provide a detailed, structured triage report.\n\n"
        "SCAN DATA:\n"
        f"{json.dumps(payload, ensure_ascii=True)}\n\n"
        "Provide your analysis in this exact JSON format with all fields populated:\n\n"
        "{"
        '  "executive_summary": "2-3 sentence high-level overview of the security posture",'
        '  "risk_rating": "Critical/High/Medium/Low - overall risk assessment",'
        '  "key_findings": "Paragraph explaining the most important security issues found",'
        '  "top_risks": ["risk 1 (with business impact)", "risk 2", "risk 3", "risk 4"],'
        '  "immediate_actions": ["Fix within 24-48 hours", "Action 2"],'
        '  "short_term_actions": ["Complete within 1-2 weeks", "Action 2"],'
        '  "long_term_strategy": ["Strategic improvement (months)", "Item 2"],'
        '  "remediation_guidance": "Detailed explanation of how to address the findings",'
        '  "confidence_notes": "Any caveats or important context about this analysis"'
        "}"
    )


def _extract_json_payload(text: str) -> dict[str, Any]:
    raw = text.strip()

    if raw.startswith("```"):
        lines = raw.splitlines()
        if len(lines) >= 3:
            raw = "\n".join(lines[1:-1]).strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        return json.loads(raw[start : end + 1])


async def _generate_with_ollama(target_url: str, score: float, vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
    prompt = _build_ollama_prompt(target_url, score, vulnerabilities)
    request_body = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
        },
    }

    timeout = aiohttp.ClientTimeout(total=AI_TIMEOUT_SECONDS)
    async with aiohttp.ClientSession(timeout=timeout) as client:
        async with client.post(f"{OLLAMA_BASE_URL}/api/generate", json=request_body, ssl=False) as response:
            response.raise_for_status()
            data = await response.json(content_type=None)

    raw_text = str(data.get("response", "")).strip()
    parsed = _extract_json_payload(raw_text)

    summary = str(parsed.get("summary", "")).strip()
    top_risks = [str(x).strip() for x in parsed.get("top_risks", []) if str(x).strip()]
    actions = [str(x).strip() for x in parsed.get("actions", []) if str(x).strip()]

    if not summary:
        raise ValueError("Model output missing summary")

    base = {
        "summary": summary,
        "top_risks": top_risks[:4],
        "actions": actions[:5],
        "fallback_used": False,
        "provider": "ollama",
        "model": OLLAMA_MODEL,
    }
    return {**base, **_source_meta(base["provider"], base["fallback_used"], base["model"]) }


async def _generate_with_groq(target_url: str, score: float, vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
    if not GROQ_API_KEY:
        raise ValueError("GROQ_API_KEY is not configured")

    user_prompt = _build_groq_prompt(target_url, score, vulnerabilities)
    request_body = {
        "model": GROQ_MODEL,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert cybersecurity analyst providing detailed, professional security triage reports. "
                    "Your goal is to help organizations understand their security posture, prioritize fixes, and improve their defenses. "
                    "Always provide actionable, specific guidance focused on real business impact and risk reduction. "
                    "Return valid JSON ONLY with no additional text."
                ),
            },
            {"role": "user", "content": user_prompt},
        ],
    }

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    timeout = aiohttp.ClientTimeout(total=AI_TIMEOUT_SECONDS)
    async with aiohttp.ClientSession(timeout=timeout) as client:
        async with client.post(
            f"{GROQ_BASE_URL}/chat/completions",
            json=request_body,
            headers=headers,
            ssl=False,
        ) as response:
            response.raise_for_status()
            data = await response.json(content_type=None)

    choices = data.get("choices") or []
    if not choices:
        raise ValueError("Groq response missing choices")

    raw_text = str(((choices[0] or {}).get("message") or {}).get("content", "")).strip()
    parsed = _extract_json_payload(raw_text)

    # Extract detailed fields from Groq response
    executive_summary = str(parsed.get("executive_summary", "")).strip()
    risk_rating = str(parsed.get("risk_rating", "Medium")).strip()
    key_findings = str(parsed.get("key_findings", "")).strip()
    top_risks = [str(x).strip() for x in parsed.get("top_risks", []) if str(x).strip()]
    immediate_actions = [str(x).strip() for x in parsed.get("immediate_actions", []) if str(x).strip()]
    short_term_actions = [str(x).strip() for x in parsed.get("short_term_actions", []) if str(x).strip()]
    long_term_strategy = [str(x).strip() for x in parsed.get("long_term_strategy", []) if str(x).strip()]
    remediation_guidance = str(parsed.get("remediation_guidance", "")).strip()
    confidence_notes = str(parsed.get("confidence_notes", "")).strip()

    if not executive_summary:
        raise ValueError("Model output missing executive_summary")

    base = {
        "executive_summary": executive_summary,
        "risk_rating": risk_rating,
        "key_findings": key_findings,
        "top_risks": top_risks[:4],
        "immediate_actions": immediate_actions[:3],
        "short_term_actions": short_term_actions[:3],
        "long_term_strategy": long_term_strategy[:3],
        "remediation_guidance": remediation_guidance,
        "confidence_notes": confidence_notes,
        "fallback_used": False,
        "provider": "groq",
        "model": GROQ_MODEL,
    }
    return {**base, **_source_meta(base["provider"], base["fallback_used"], base["model"]) }


async def generate_ai_summary(target_url: str, score: float, vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
    # Groq-only mode requested by user for response comparison.
    # Previous non-Groq and fallback behavior is intentionally disabled.

    # if not AI_ENABLED:
    #     return _rule_based_summary(target_url, score, vulnerabilities)

    # if AI_PROVIDER == "ollama":
    #     try:
    #         return await _generate_with_ollama(target_url, score, vulnerabilities)
    #     except (aiohttp.ClientError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
    #         logger.warning("AI provider failed, using fallback summary: %s", exc)
    #         return _rule_based_summary(target_url, score, vulnerabilities)

    if AI_PROVIDER != "groq":
        raise ValueError("Groq-only mode is enabled. Set AI_PROVIDER=groq.")

    # Intentionally no rule-based fallback so you can inspect Groq output directly.
    return await _generate_with_groq(target_url, score, vulnerabilities)
