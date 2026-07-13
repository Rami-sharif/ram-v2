"""Deterministic triage router.

FIXED code — no LLM. Given the agent's structured analysis and the dedup store,
decides what happens to each alert:

  branch (by severity_score, 0-100 scale, env thresholds):
    score <  TRIAGE_MEDIUM_THRESHOLD              -> low    : auto-close (no human queue)
    MEDIUM <= score < TRIAGE_HIGH_THRESHOLD       -> medium : open "needs-review" case
    score >= TRIAGE_HIGH_THRESHOLD                -> high   : case + flag/escalate

  dedup (case-creating branches only): key = agent_name|rule_id|source_ip.
    Alerts with no source_ip are NOT deduped (always create) to avoid falsely
    merging unrelated no-IP events. Within the rolling window, a repeat key
    suppresses the new case and increments occurrence_count on the existing one.

Every decision is logged with its reason. Memory write-back is handled upstream
and is independent of any decision made here.
"""
import logging
from typing import Any, Optional

from psycopg.rows import dict_row

from . import thehive
from .config import get_settings
from .db import get_pool
from .schemas import AnalysisResult, TriageDecision, WazuhAlert

logger = logging.getLogger(__name__)

_MISSING_IP = {"", "none", "null", "-", "n/a", "0.0.0.0", "::"}


def _norm_source_ip(alert: WazuhAlert) -> Optional[str]:
    ip = ((alert.data or {}).get("srcip") or "").strip()
    if ip.lower() in _MISSING_IP:
        return None
    return ip


def dedup_key_for(agent_name: Optional[str], rule_id: Optional[str],
                  source_ip: Optional[str]) -> Optional[str]:
    """The dedup identity of an alert: agent|rule|source_ip. No source_ip means the
    alert was never deduped, so it has no key. Shared with the console's case retry,
    which backfills the dedup row this key points at."""
    if not source_ip:
        return None
    return f"{agent_name or 'unknown'}|{rule_id or ''}|{source_ip}"


def _branch(score: int) -> str:
    s = get_settings()
    if score >= s.triage_high_threshold:
        return "high"
    if score >= s.triage_medium_threshold:
        return "medium"
    return "low"


def _log(decision: TriageDecision, alert: WazuhAlert, case: Optional[dict]) -> None:
    logger.info(
        "TRIAGE decision alert=%s branch=%s score=%s action=%s suppressed=%s "
        "dedup_key=%s case=%s reason=%r",
        alert.id, decision.branch, decision.severity_score, decision.action,
        decision.suppressed, decision.dedup_key,
        (case or {}).get("number"), decision.reason,
    )


def route_and_execute(
    alert: WazuhAlert, analysis: AnalysisResult, enrichment: dict[str, Any]
) -> tuple[TriageDecision, Optional[dict[str, Any]]]:
    """Decide and act. Returns (decision, case_or_None)."""
    s = get_settings()
    score = analysis.severity_score
    branch = _branch(score)

    # ---- LOW: auto-close, never reaches the human queue ----
    if branch == "low":
        case = None
        if s.triage_low_create_resolved_case and s.thehive_enabled:
            try:
                case = thehive.create_case(alert, analysis, enrichment,
                                           flag=False, extra_tags=["auto-closed"])
                thehive.close_case(case["_id"], "Auto-closed by RAM v2 triage (low severity).")
            except thehive.TheHiveError as exc:
                logger.error("Low-branch resolved-case creation failed: %s", exc)
                case = {"error": str(exc)}
        decision = TriageDecision(
            branch="low", action="auto_close", severity_score=score, dedup_eligible=False,
            reason=f"score {score} < medium_threshold {s.triage_medium_threshold}: "
                   f"auto-closed, not queued (memory retains full record)",
        )
        _log(decision, alert, case)
        return decision, case

    # ---- MEDIUM / HIGH: case-creating branches, subject to dedup ----
    flag = branch == "high"
    extra_tags = ["escalated"] if flag else ["needs-review"]
    source_ip = _norm_source_ip(alert)

    # No usable discriminator -> never dedup, always create (safer: no false suppression).
    if source_ip is None:
        case = _create(alert, analysis, enrichment, flag)
        decision = TriageDecision(
            branch=branch, action="create_flagged" if flag else "create_open",
            severity_score=score, dedup_key=None, dedup_eligible=False,
            reason=f"score {score} -> {branch}; dedup skipped (no source_ip discriminator): "
                   f"always create to avoid false suppression",
        )
        _log(decision, alert, case)
        return decision, case

    dedup_key = dedup_key_for(alert.agent.name, alert.rule.id, source_ip)
    return _dedup_and_execute(alert, analysis, enrichment, branch, flag, extra_tags,
                              dedup_key, source_ip)


def _create(alert, analysis, enrichment, flag) -> Optional[dict[str, Any]]:
    """Create the case for a case-creating branch. A failure returns {"error": ...}
    rather than raising: the triage ACTION is unchanged (a high alert stays
    create_flagged whether or not TheHive accepted the case), the analysis is
    preserved, and the error is carried out to the investigation record so an
    analyst can retry the case from the console."""
    if not get_settings().thehive_enabled:
        logger.info("TheHive disabled — case creation skipped")
        return None
    extra_tags = ["escalated"] if flag else ["needs-review"]
    try:
        return thehive.create_case(alert, analysis, enrichment, flag=flag, extra_tags=extra_tags)
    except thehive.TheHiveError as exc:
        logger.error("Case creation failed (analysis preserved, retryable from console): %s", exc)
        return {"error": str(exc)}


def _dedup_and_execute(alert, analysis, enrichment, branch, flag, extra_tags,
                       dedup_key, source_ip) -> tuple[TriageDecision, Optional[dict]]:
    s = get_settings()
    window_h = s.triage_dedup_window_hours

    with get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT *, (now() - last_seen) < (%s * interval '1 hour') AS within_window "
                "FROM triage_dedup WHERE dedup_key = %s FOR UPDATE",
                (window_h, dedup_key),
            )
            row = cur.fetchone()

            if row and row["within_window"]:
                # ---- DUPLICATE: suppress, increment, update existing case ----
                cur.execute(
                    "UPDATE triage_dedup SET occurrence_count = occurrence_count + 1, "
                    "last_seen = now() WHERE dedup_key = %s RETURNING occurrence_count, "
                    "case_id, case_number",
                    (dedup_key,),
                )
                upd = cur.fetchone()
                count, case_id, case_number = (
                    upd["occurrence_count"], upd["case_id"], upd["case_number"],
                )
                decision = TriageDecision(
                    branch=branch, action="suppress_duplicate", severity_score=analysis.severity_score,
                    dedup_key=dedup_key, dedup_eligible=True, suppressed=True,
                    occurrence_count=count, existing_case_number=case_number,
                    reason=f"duplicate of case #{case_number} within {window_h}h window "
                           f"(occurrence {count}); suppressed from queue",
                )
                if case_id:
                    thehive.add_comment(
                        case_id,
                        f"RAM v2: duplicate occurrence #{count} (alert {alert.id}) "
                        f"suppressed from queue at {alert.timestamp or 'now'}.",
                    )
                _log(decision, alert, {"number": case_number})
                return decision, {"_id": case_id, "number": case_number, "suppressed": True}

            # ---- NEW (no record, or window expired): create case, (re)set record ----
            case = _create(alert, analysis, enrichment, flag)
            case_id = (case or {}).get("_id")
            case_number = (case or {}).get("number")
            cur.execute(
                "INSERT INTO triage_dedup "
                "(dedup_key, agent_name, rule_id, source_ip, case_id, case_number, "
                " occurrence_count, first_seen, last_seen) "
                "VALUES (%s, %s, %s, %s, %s, %s, 1, now(), now()) "
                "ON CONFLICT (dedup_key) DO UPDATE SET "
                "  case_id = EXCLUDED.case_id, case_number = EXCLUDED.case_number, "
                "  occurrence_count = 1, first_seen = now(), last_seen = now()",
                (dedup_key, alert.agent.name or "unknown", alert.rule.id, source_ip,
                 case_id, case_number),
            )
            reset = row is not None  # existed but stale window
            decision = TriageDecision(
                branch=branch, action="create_flagged" if flag else "create_open",
                severity_score=analysis.severity_score, dedup_key=dedup_key,
                dedup_eligible=True, occurrence_count=1, existing_case_number=case_number,
                reason=(f"score {analysis.severity_score} -> {branch}; "
                        + ("prior window expired, new case" if reset else "first occurrence")
                        + f"; case #{case_number}"),
            )
            _log(decision, alert, case)
            return decision, case


# --- console-driven retry of a failed case creation -------------------------
# Replays the ORIGINAL triage intent for one investigation: same alert, same
# analysis, same enrichment, same flag — only the moment differs. Nothing here
# touches alert_investigations (still write-once); the caller records the result.
_CASE_CREATING_ACTIONS = ("create_flagged", "create_open")


def parent_case_for(inv: dict[str, Any]) -> Optional[dict[str, Any]]:
    """The case this alert's dedup GROUP belongs to, if there is one.

    Dedup means "these alerts are one incident, tracked in one case". So an alert
    with no case of its own — a suppressed duplicate, or a create_* alert whose own
    creation failed — belongs to whatever case its dedup key points at, including a
    case created later by a retry. Linking to it is always right and creating a
    second case for the same key never is."""
    key = dedup_key_for(inv.get("agent_name"), inv.get("rule_id"), inv.get("source_ip"))
    if not key:
        return None
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT case_id, case_number FROM triage_dedup "
            "WHERE dedup_key = %s AND case_id IS NOT NULL",
            (key,),
        )
        return cur.fetchone()


def can_retry_case(inv: dict[str, Any]) -> bool:
    """True when this investigation MEANT to have a case, has none, and we can build
    a faithful one from what was recorded. Only for alerts whose dedup group has no
    case at all — when the group already has one, the alert must be LINKED to it
    (parent_case_for) rather than given a second case. A suppressed duplicate can
    reach this path: if the original case creation failed and was never retried,
    nothing in the group has a case, and this alert is as good a place to create it
    as any (the dedup row is backfilled, so the whole group then resolves to it)."""
    return bool(
        inv.get("triage_action") in _CASE_CREATING_ACTIONS + ("suppress_duplicate",)
        and not inv.get("case_id")
        and inv.get("alert_payload")
    )


def create_case_for_investigation(inv: dict[str, Any]) -> dict[str, Any]:
    """Retry TheHive case creation for a recorded investigation. Returns the new
    case ({"_id", "number", ...}); raises TheHiveError if TheHive still refuses."""
    alert = WazuhAlert.model_validate(inv["alert_payload"])
    analysis = AnalysisResult.model_validate(inv["analysis"])
    # Escalation follows the original BRANCH, not the action, so a suppressed
    # duplicate of a high alert still creates the flagged case triage intended.
    flag = inv.get("triage_branch") == "high"
    extra_tags = ["escalated"] if flag else ["needs-review"]
    case = thehive.create_case(alert, analysis, inv.get("enrichment") or {},
                               flag=flag, extra_tags=[*extra_tags, "case-retry"])
    logger.info("TRIAGE case retry succeeded investigation=%s case=%s (#%s)",
                inv.get("id"), case.get("_id"), case.get("number"))
    _backfill_dedup(inv, case)
    return case


def _backfill_dedup(inv: dict[str, Any], case: dict[str, Any]) -> None:
    """Point this alert's dedup row at the case we just created. Without this, the
    dedup row left behind by the failed attempt still carries a NULL case_id, so
    every repeat inside the window would be suppressed into a case that does not
    exist. Best-effort: the case is already created, so a dedup failure must not
    fail the retry."""
    key = dedup_key_for(inv.get("agent_name"), inv.get("rule_id"), inv.get("source_ip"))
    if not key:
        return
    try:
        with get_pool().connection() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE triage_dedup SET case_id = %s, case_number = %s "
                "WHERE dedup_key = %s AND case_id IS NULL",
                (case.get("_id"), case.get("number"), key),
            )
            if cur.rowcount:
                logger.info("TRIAGE dedup backfilled key=%s -> case #%s", key, case.get("number"))
    except Exception:  # noqa: BLE001
        logger.exception("Dedup backfill failed after case retry (case %s created)",
                         case.get("number"))
