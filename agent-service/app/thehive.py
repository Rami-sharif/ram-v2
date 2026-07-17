"""Minimal TheHive 5 API client — creates a case from an analysis result.

TheHive is a separate case-management app that security analysts use to track
incidents. This file is a "REST API client": it talks to TheHive over HTTP by
sending JSON requests (POST to create, PATCH to update, GET to read) to TheHive's
URL endpoints. Every request carries an "auth header" — an Authorization line
with a secret API key (a bearer token) that proves we're allowed to make the
call. A "case" is TheHive's record of one incident to investigate.

Two styles of function live here, on purpose:
- best-effort (create_case's low-severity path, add_comment, close_case): a
  failure is logged and swallowed, returning False/None, because the calling
  workflow should continue anyway.
- strict (the console-facing _request/get_case/set_severity/close_case_strict):
  a failure raises TheHiveError, because an analyst explicitly asked for the
  action and must be told if it didn't land.

Used in Phase 4. Case creation is invoked only when THEHIVE_API_KEY is configured.
"""
import logging  # stdlib logging for structured, leveled log messages
from typing import Any, Optional  # type hints for flexible dict values and nullable params

import httpx  # HTTP client used to talk to the TheHive REST API

from .config import get_settings  # app settings accessor (TheHive URL, API key, timeout, feature flag)
from .schemas import AnalysisResult, WazuhAlert  # typed models for the alert and the agent's analysis

logger = logging.getLogger(__name__)  # module-level logger namespaced to this file

# AnalysisResult.severity_label -> TheHive severity (1=low .. 4=critical)
_SEVERITY_MAP = {"info": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}  # lookup table for label->int mapping


class TheHiveError(RuntimeError):
    # Custom exception type so callers can catch TheHive-specific failures distinctly from generic errors
    pass


def _build_description(alert: WazuhAlert, analysis: AnalysisResult, enrichment: dict) -> str:
    # Build the markdown-formatted MITRE ATT&CK section from the analysis' technique list
    mitre_lines = (
        "\n".join(
            # One bullet per technique: id, name (optional), tactic (optional); rstrip trims trailing space if name/tactic are blank
            f"- {m.technique_id} {m.technique or ''} ({m.tactic or ''})".rstrip()
            for m in analysis.mitre
        )
        or "- none"  # fallback bullet when there are no MITRE techniques at all
    )
    # Build the markdown-formatted enrichment (investigation evidence) section, truncating long values
    enrich_lines = (
        "\n".join(f"- `{key}`: {str(val)[:400]}" for key, val in enrichment.items())
        or "- none"  # fallback bullet when there is no enrichment data
    )
    # Assemble the full case description body as a single markdown string
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
    # HTTP "headers" are metadata sent alongside every request. TheHive requires
    # two here: Authorization proves who we are, Content-Type says our body is JSON.
    return {
        # "Bearer <token>" is the standard way to present an API key for auth;
        # anyone with this token can act as us, so it's read fresh from settings
        # (which come from a secret env var) rather than hard-coded.
        "Authorization": f"Bearer {get_settings().thehive_api_key}",  # bearer token pulled fresh from settings each call
        "Content-Type": "application/json",
    }


def _base() -> str:
    # The common URL prefix that every endpoint below is appended to, e.g.
    # "https://thehive.example.com" + "/api/v1" -> ".../api/v1/case".
    # rstrip("/") removes a trailing slash on the configured host so we don't
    # accidentally build a URL with a double slash ("//api/v1").
    return get_settings().thehive_url.rstrip("/") + "/api/v1"


def create_case(
    alert: WazuhAlert,
    analysis: AnalysisResult,
    enrichment: dict[str, Any],
    flag: bool = False,
    extra_tags: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Create a TheHive case. Raises TheHiveError on failure."""
    settings = get_settings()  # snapshot current settings once for this call
    if not settings.thehive_enabled:
        # Guard: refuse to proceed if TheHive integration isn't configured (no API key)
        raise TheHiveError("TheHive API key not configured")

    # Base tags every case gets, plus the attack type from the analysis
    tags = ["ram-v2", "wazuh", "automated-triage", analysis.attack_type]
    tags += [m.technique_id for m in analysis.mitre]  # add one tag per MITRE technique id for filtering in TheHive
    tags += extra_tags or []  # append caller-supplied tags (e.g. "escalated", "needs-review"), defaulting to none
    # Build the JSON payload TheHive's case-creation endpoint expects
    payload = {
        "title": f"[Wazuh] {alert.description}",
        "description": _build_description(alert, analysis, enrichment),  # full markdown body built above
        "severity": _SEVERITY_MAP.get(analysis.severity_label, 2),  # map label to TheHive's 1-4 scale, default medium
        "tlp": 2,  # Traffic Light Protocol level (2 = amber), fixed for all automated cases
        "flag": flag,  # marks the case as flagged/escalated when caller passes flag=True
        "tags": tags,
    }

    try:
        # "POST" is the HTTP verb for "create a new thing"; json=payload sends our
        # dict as the JSON request body. timeout caps how long we wait so a hung
        # TheHive can't freeze our pipeline. Network/protocol errors are caught below.
        resp = httpx.post(f"{_base()}/case", json=payload, headers=_headers(),
                          timeout=settings.thehive_timeout)
    except httpx.HTTPError as exc:
        # Wrap any transport-level failure (timeout, connection refused, etc.) into our own error type
        logger.error("TheHive request failed: %s", exc)
        raise TheHiveError(f"request failed: {exc}") from exc

    # HTTP status codes report the outcome: 200/201 mean success (created), while
    # 4xx/5xx mean the request was rejected or the server errored. We only accept
    # 200/201 and treat anything else as a failure.
    if resp.status_code not in (200, 201):
        # Non-success HTTP status means TheHive rejected the request; surface a truncated body for debugging
        logger.error("TheHive case creation failed: %s %s", resp.status_code, resp.text[:300])
        raise TheHiveError(f"unexpected status {resp.status_code}: {resp.text[:300]}")

    case = resp.json()  # parse the created case's JSON representation
    # Log success including the new case id, applied severity, and flag state for observability
    logger.info("Created TheHive case %s (severity=%s, flag=%s)",
                case.get("_id"), payload["severity"], flag)
    # Return only the fields callers actually need, not the full TheHive case object
    return {"_id": case.get("_id"), "number": case.get("number"), "title": case.get("title")}


def add_comment(case_id: str, message: str) -> bool:
    """Best-effort comment on an existing case (used for dedup occurrence notes)."""
    if not get_settings().thehive_enabled:
        return False  # silently no-op when TheHive isn't configured, since this is best-effort
    try:
        # POST the comment; any failure here is swallowed (best-effort contract)
        resp = httpx.post(f"{_base()}/case/{case_id}/comment", json={"message": message},
                          headers=_headers(), timeout=get_settings().thehive_timeout)
        if resp.status_code in (200, 201):
            return True  # comment posted successfully
        # Non-success status: log a warning but don't raise, since callers treat this as best-effort
        logger.warning("TheHive comment failed: %s %s", resp.status_code, resp.text[:200])
    except httpx.HTTPError as exc:
        # Network/transport failure: log and fall through to return False
        logger.warning("TheHive comment request failed: %s", exc)
    return False  # reached only on failure paths above


def close_case(case_id: str, summary: str) -> bool:
    """Best-effort close for the low-severity auto-close path.

    Delegates to close_case_strict (which sets a valid Closed-stage status —
    TheHive 5 has no literal "Closed" status) and verifies the case actually
    reached the Closed stage. Best-effort: never raises into the caller, but
    logs loudly on failure so an auto-close can't silently leave a case open.
    """
    if not get_settings().thehive_enabled:
        return False  # nothing to do if TheHive isn't configured
    try:
        close_case_strict(case_id, summary)  # attempt the actual close via the strict, raising helper
        if get_case(case_id).get("stage") == "Closed":
            # Read the case back to confirm the close actually took effect (not just that the PATCH returned 2xx)
            logger.info("Auto-closed TheHive case %s", case_id)
            return True
        # PATCH succeeded but the case isn't in the Closed stage — treat as a failure and log loudly
        logger.error("TheHive case %s did not reach Closed stage after auto-close", case_id)
    except TheHiveError as exc:
        # Swallow the error per the best-effort contract, but warn so it's visible in logs
        logger.warning("TheHive auto-close failed for %s: %s", case_id, exc)
    return False  # reached whenever the close didn't verifiably succeed


# --------------------------------------------------------------------------- #
# Console-facing operations (analyst-driven, strict).
# Scope is deliberately limited to exactly three case mutations — close,
# severity, comment — plus read-backs used to verify the change landed.
# No tasks / observables / workflow operations are exposed here.
# --------------------------------------------------------------------------- #
def severity_to_int(label: str) -> int:
    """Map a severity label to TheHive's 1..4 scale (default medium)."""
    # Lowercase (guarding against None via `or ""`) before looking up in the shared severity map
    return _SEVERITY_MAP.get((label or "").lower(), 2)


# One shared helper the strict, analyst-driven functions all go through, so the
# auth headers, base URL, timeout, and error-wrapping are written once. `method`
# is the HTTP verb ("GET"/"POST"/"PATCH"), `path` is appended to the API base.
def _request(method: str, path: str, **kw) -> httpx.Response:
    if not get_settings().thehive_enabled:
        # Guard shared by all console-facing operations below
        raise TheHiveError("TheHive API key not configured")
    try:
        # Generic authenticated request helper; **kw forwards json=/params=/etc. from callers
        resp = httpx.request(method, f"{_base()}{path}", headers=_headers(),
                             timeout=get_settings().thehive_timeout, **kw)
    except httpx.HTTPError as exc:
        # Unlike the best-effort functions above, this one always raises on transport failure (strict contract)
        raise TheHiveError(f"request failed: {exc}") from exc
    return resp


def get_case(case_id: str) -> dict[str, Any]:
    """Read a case back (used to verify a mutation actually landed)."""
    resp = _request("GET", f"/case/{case_id}")  # fetch the case by id
    if resp.status_code != 200:
        # Any non-200 is treated as a hard failure here (strict, read-back verification path)
        raise TheHiveError(f"get case {case_id}: status {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def get_case_comments(case_id: str) -> list[dict[str, Any]]:
    """List a case's comments via the query API (to verify a comment landed)."""
    # TheHive's query DSL: first resolve the case, then project its comments
    body = {"query": [{"_name": "getCase", "idOrName": case_id}, {"_name": "comments"}]}
    resp = _request("POST", "/query", json=body)  # run the query
    if resp.status_code != 200:
        raise TheHiveError(f"list comments {case_id}: status {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    # Defensive: only return a list, even if TheHive's query API returns something unexpected
    return data if isinstance(data, list) else []


def set_severity(case_id: str, severity: int) -> None:
    """Set ONLY the case severity (1..4). Raises TheHiveError on failure."""
    if severity not in (1, 2, 3, 4):
        # Validate input range before making any network call
        raise TheHiveError(f"severity must be 1..4, got {severity}")
    # "PATCH" is the HTTP verb for a partial update — change only the fields we
    # send (here just severity), leaving the rest of the case untouched.
    resp = _request("PATCH", f"/case/{case_id}", json={"severity": severity})  # partial update of just the severity field
    if resp.status_code not in (200, 204):
        raise TheHiveError(f"set severity failed: {resp.status_code}: {resp.text[:200]}")


def post_comment(case_id: str, message: str) -> None:
    """Add a comment to a case. Raises TheHiveError on failure."""
    resp = _request("POST", f"/case/{case_id}/comment", json={"message": message})  # create the comment
    if resp.status_code not in (200, 201):
        raise TheHiveError(f"comment failed: {resp.status_code}: {resp.text[:200]}")


# TheHive 5 closes a case by setting its status to one whose stage is "Closed".
# These are the resolution outcomes; the console exposes them as the close reason.
CLOSED_STATUSES = ("Indeterminate", "TruePositive", "FalsePositive", "Duplicated", "Other")  # allowed close statuses
DEFAULT_CLOSE_STATUS = "Indeterminate"  # used when the caller doesn't specify a more precise outcome


def close_case_strict(case_id: str, summary: str, status: str = DEFAULT_CLOSE_STATUS) -> None:
    """Close a case (analyst-driven) by setting a Closed-stage status.
    Raises TheHiveError on failure or an out-of-scope status."""
    if status not in CLOSED_STATUSES:
        # Reject any status outside the allowed set before calling TheHive
        raise TheHiveError(f"close status must be one of {CLOSED_STATUSES}")
    # PATCH both status (drives the stage) and summary (closing rationale) in one call
    resp = _request("PATCH", f"/case/{case_id}", json={"status": status, "summary": summary})
    if resp.status_code not in (200, 204):
        raise TheHiveError(f"close failed: {resp.status_code}: {resp.text[:200]}")
