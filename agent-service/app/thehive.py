"""Minimal TheHive 5 API client — creates a case from an analysis result.

Used in Phase 4. Case creation is invoked only when THEHIVE_API_KEY is configured.
"""
import logging
from typing import Any, Optional

import httpx

from .config import get_settings
from .schemas import AnalysisResult, WazuhAlert

logger = logging.getLogger(__name__)

# AnalysisResult.severity_label -> TheHive severity (1=low .. 4=critical)
_SEVERITY_MAP = {"info": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}


class TheHiveError(RuntimeError):
    pass


def _build_description(alert: WazuhAlert, analysis: AnalysisResult, enrichment: dict) -> str:
    mitre_lines = (
        "\n".join(
            f"- {m.technique_id} {m.technique or ''} ({m.tactic or ''})".rstrip()
            for m in analysis.mitre
        )
        or "- none"
    )
    enrich_lines = (
        "\n".join(f"- `{ip}`: {info}" for ip, info in enrichment.items()) or "- none"
    )
    return (
        f"## Automated triage (RAM v2)\n\n"
        f"**Summary:** {analysis.summary}\n\n"
        f"**Attack type:** {analysis.attack_type}\n\n"
        f"**Severity:** {analysis.severity_label} ({analysis.severity_score}/100)\n\n"
        f"**Recommended action:** {analysis.recommended_action}\n\n"
        f"### MITRE ATT&CK\n{mitre_lines}\n\n"
        f"### VirusTotal enrichment\n{enrich_lines}\n\n"
        f"### Source alert\n"
        f"- Rule level: {alert.rule_level}\n"
        f"- Rule: {alert.description}\n"
        f"- Agent: {alert.agent.name or '?'} ({alert.agent.ip or '?'})\n"
        f"- Alert id: {alert.id or '?'}\n"
    )


def create_case(
    alert: WazuhAlert, analysis: AnalysisResult, enrichment: dict[str, Any]
) -> dict[str, Any]:
    """Create a TheHive case. Raises TheHiveError on failure."""
    settings = get_settings()
    if not settings.thehive_enabled:
        raise TheHiveError("TheHive API key not configured")

    url = settings.thehive_url.rstrip("/") + "/api/v1/case"
    headers = {
        "Authorization": f"Bearer {settings.thehive_api_key}",
        "Content-Type": "application/json",
    }
    tags = ["ram-v2", "wazuh", "automated-triage", analysis.attack_type]
    tags += [m.technique_id for m in analysis.mitre]
    payload = {
        "title": f"[Wazuh] {alert.description}",
        "description": _build_description(alert, analysis, enrichment),
        "severity": _SEVERITY_MAP.get(analysis.severity_label, 2),
        "tlp": 2,
        "tags": tags,
    }

    try:
        resp = httpx.post(url, json=payload, headers=headers, timeout=settings.thehive_timeout)
    except httpx.HTTPError as exc:
        logger.error("TheHive request failed: %s", exc)
        raise TheHiveError(f"request failed: {exc}") from exc

    if resp.status_code not in (200, 201):
        logger.error("TheHive case creation failed: %s %s", resp.status_code, resp.text[:300])
        raise TheHiveError(f"unexpected status {resp.status_code}: {resp.text[:300]}")

    case = resp.json()
    logger.info("Created TheHive case %s (severity=%s)", case.get("_id"), payload["severity"])
    return {"_id": case.get("_id"), "number": case.get("number"), "title": case.get("title")}
