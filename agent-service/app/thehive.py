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
        "\n".join(f"- `{key}`: {str(val)[:400]}" for key, val in enrichment.items())
        or "- none"
    )
    return (
        f"## Automated triage (RAM v2)\n\n"
        f"**Summary:** {analysis.summary}\n\n"
        f"**Attack type:** {analysis.attack_type}\n\n"
        f"**Severity:** {analysis.severity_label} ({analysis.severity_score}/100)\n\n"
        f"**Recommended action:** {analysis.recommended_action}\n\n"
        f"### MITRE ATT&CK\n{mitre_lines}\n\n"
        f"### Investigation evidence (read-only tools)\n{enrich_lines}\n\n"
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
    """Best-effort close for the low-severity auto-close path.

    Delegates to close_case_strict (which sets a valid Closed-stage status —
    TheHive 5 has no literal "Closed" status) and verifies the case actually
    reached the Closed stage. Best-effort: never raises into the caller, but
    logs loudly on failure so an auto-close can't silently leave a case open.
    """
    if not get_settings().thehive_enabled:
        return False
    try:
        close_case_strict(case_id, summary)
        if get_case(case_id).get("stage") == "Closed":
            logger.info("Auto-closed TheHive case %s", case_id)
            return True
        logger.error("TheHive case %s did not reach Closed stage after auto-close", case_id)
    except TheHiveError as exc:
        logger.warning("TheHive auto-close failed for %s: %s", case_id, exc)
    return False


# --------------------------------------------------------------------------- #
# Console-facing operations (analyst-driven, strict).
# Scope is deliberately limited to exactly three case mutations — close,
# severity, comment — plus read-backs used to verify the change landed.
# No tasks / observables / workflow operations are exposed here.
# --------------------------------------------------------------------------- #
def severity_to_int(label: str) -> int:
    """Map a severity label to TheHive's 1..4 scale (default medium)."""
    return _SEVERITY_MAP.get((label or "").lower(), 2)


def _request(method: str, path: str, **kw) -> httpx.Response:
    if not get_settings().thehive_enabled:
        raise TheHiveError("TheHive API key not configured")
    try:
        resp = httpx.request(method, f"{_base()}{path}", headers=_headers(),
                             timeout=get_settings().thehive_timeout, **kw)
    except httpx.HTTPError as exc:
        raise TheHiveError(f"request failed: {exc}") from exc
    return resp


def get_case(case_id: str) -> dict[str, Any]:
    """Read a case back (used to verify a mutation actually landed)."""
    resp = _request("GET", f"/case/{case_id}")
    if resp.status_code != 200:
        raise TheHiveError(f"get case {case_id}: status {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def get_case_comments(case_id: str) -> list[dict[str, Any]]:
    """List a case's comments via the query API (to verify a comment landed)."""
    body = {"query": [{"_name": "getCase", "idOrName": case_id}, {"_name": "comments"}]}
    resp = _request("POST", "/query", json=body)
    if resp.status_code != 200:
        raise TheHiveError(f"list comments {case_id}: status {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    return data if isinstance(data, list) else []


def set_severity(case_id: str, severity: int) -> None:
    """Set ONLY the case severity (1..4). Raises TheHiveError on failure."""
    if severity not in (1, 2, 3, 4):
        raise TheHiveError(f"severity must be 1..4, got {severity}")
    resp = _request("PATCH", f"/case/{case_id}", json={"severity": severity})
    if resp.status_code not in (200, 204):
        raise TheHiveError(f"set severity failed: {resp.status_code}: {resp.text[:200]}")


def post_comment(case_id: str, message: str) -> None:
    """Add a comment to a case. Raises TheHiveError on failure."""
    resp = _request("POST", f"/case/{case_id}/comment", json={"message": message})
    if resp.status_code not in (200, 201):
        raise TheHiveError(f"comment failed: {resp.status_code}: {resp.text[:200]}")


# TheHive 5 closes a case by setting its status to one whose stage is "Closed".
# These are the resolution outcomes; the console exposes them as the close reason.
CLOSED_STATUSES = ("Indeterminate", "TruePositive", "FalsePositive", "Duplicated", "Other")
DEFAULT_CLOSE_STATUS = "Indeterminate"


def close_case_strict(case_id: str, summary: str, status: str = DEFAULT_CLOSE_STATUS) -> None:
    """Close a case (analyst-driven) by setting a Closed-stage status.
    Raises TheHiveError on failure or an out-of-scope status."""
    if status not in CLOSED_STATUSES:
        raise TheHiveError(f"close status must be one of {CLOSED_STATUSES}")
    resp = _request("PATCH", f"/case/{case_id}", json={"status": status, "summary": summary})
    if resp.status_code not in (200, 204):
        raise TheHiveError(f"close failed: {resp.status_code}: {resp.text[:200]}")
