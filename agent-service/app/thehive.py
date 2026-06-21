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


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {get_settings().thehive_api_key}",
        "Content-Type": "application/json",
    }


def _base() -> str:
    return get_settings().thehive_url.rstrip("/") + "/api/v1"


def create_case(
    alert: WazuhAlert,
    analysis: AnalysisResult,
    enrichment: dict[str, Any],
    flag: bool = False,
    extra_tags: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Create a TheHive case. Raises TheHiveError on failure."""
    settings = get_settings()
    if not settings.thehive_enabled:
        raise TheHiveError("TheHive API key not configured")

    tags = ["ram-v2", "wazuh", "automated-triage", analysis.attack_type]
    tags += [m.technique_id for m in analysis.mitre]
    tags += extra_tags or []
    payload = {
        "title": f"[Wazuh] {alert.description}",
        "description": _build_description(alert, analysis, enrichment),
        "severity": _SEVERITY_MAP.get(analysis.severity_label, 2),
        "tlp": 2,
        "flag": flag,
        "tags": tags,
    }

    try:
        resp = httpx.post(f"{_base()}/case", json=payload, headers=_headers(),
                          timeout=settings.thehive_timeout)
    except httpx.HTTPError as exc:
        logger.error("TheHive request failed: %s", exc)
        raise TheHiveError(f"request failed: {exc}") from exc

    if resp.status_code not in (200, 201):
        logger.error("TheHive case creation failed: %s %s", resp.status_code, resp.text[:300])
        raise TheHiveError(f"unexpected status {resp.status_code}: {resp.text[:300]}")

    case = resp.json()
    logger.info("Created TheHive case %s (severity=%s, flag=%s)",
                case.get("_id"), payload["severity"], flag)
    return {"_id": case.get("_id"), "number": case.get("number"), "title": case.get("title")}


def add_comment(case_id: str, message: str) -> bool:
    """Best-effort comment on an existing case (used for dedup occurrence notes)."""
    if not get_settings().thehive_enabled:
        return False
    try:
        resp = httpx.post(f"{_base()}/case/{case_id}/comment", json={"message": message},
                          headers=_headers(), timeout=get_settings().thehive_timeout)
        if resp.status_code in (200, 201):
            return True
        logger.warning("TheHive comment failed: %s %s", resp.status_code, resp.text[:200])
    except httpx.HTTPError as exc:
        logger.warning("TheHive comment request failed: %s", exc)
    return False


def close_case(case_id: str, summary: str) -> bool:
    """Best-effort close (for the optional low-severity pre-resolved case path)."""
    if not get_settings().thehive_enabled:
        return False
    try:
        resp = httpx.patch(
            f"{_base()}/case/{case_id}",
            json={"status": "Closed", "summary": summary, "impactStatus": "NotApplicable"},
            headers=_headers(), timeout=get_settings().thehive_timeout,
        )
        if resp.status_code in (200, 204):
            return True
        logger.warning("TheHive close failed: %s %s", resp.status_code, resp.text[:200])
    except httpx.HTTPError as exc:
        logger.warning("TheHive close request failed: %s", exc)
    return False
