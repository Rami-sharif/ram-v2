"""Deterministic triage router.

"Triage" (a term borrowed from emergency medicine) means sorting incoming alerts
by urgency so effort goes where it matters. "Routing" is deciding which path an
alert takes. "Deterministic" means these decisions come from FIXED if/else rules,
not from an LLM/AI — so the same analysis always yields the same action, which is
what a security team needs for an auditable, predictable workflow.

FIXED code — no LLM. Given the agent's structured analysis and the dedup store,
decides what happens to each alert:

  branch (by severity_score, 0-100 scale, env thresholds):
    A "severity_score" is the agent's 0-100 danger rating for the alert. We
    compare it against two configurable cutoffs ("thresholds", read from env
    variables) to pick one of three branches. "Escalate" means push it up for
    urgent human attention.
    score <  TRIAGE_MEDIUM_THRESHOLD              -> low    : auto-close (no human queue)
    MEDIUM <= score < TRIAGE_HIGH_THRESHOLD       -> medium : open "needs-review" case
    score >= TRIAGE_HIGH_THRESHOLD                -> high   : case + flag/escalate

  dedup (case-creating branches only): key = agent_name|rule_id|source_ip.
    "Dedup" (deduplication) stops the same recurring problem from opening dozens
    of near-identical cases and flooding analysts. We build a key that identifies
    "the same kind of alert from the same host+IP"; if we've seen that key
    recently we treat the new alert as a repeat of the existing case instead of a
    new one. Alerts with no source_ip are NOT deduped (always create) to avoid
    falsely merging unrelated no-IP events. Within the rolling window (a recent
    time span, e.g. the last few hours), a repeat key suppresses the new case and
    increments occurrence_count on the existing one.

Every decision is logged with its reason. Memory write-back is handled upstream
and is independent of any decision made here.
"""
import logging  # stdlib logging for decision/audit trail
from typing import Any, Optional  # type hints for loosely-typed dicts and nullable fields

from psycopg.rows import dict_row  # cursor row factory so query results come back as dicts

from . import thehive  # TheHive client module used to create/comment on cases
from .config import get_settings  # accessor for triage thresholds, dedup window, feature flags
from .db import get_pool  # shared Postgres connection pool
from .schemas import AnalysisResult, TriageDecision, WazuhAlert  # typed models for inputs/outputs

logger = logging.getLogger(__name__)  # module-level logger

# Values that mean "no real source IP was present" — used to decide dedup eligibility
_MISSING_IP = {"", "none", "null", "-", "n/a", "0.0.0.0", "::"}


def _norm_source_ip(alert: WazuhAlert) -> Optional[str]:
    # Pull the source IP out of the alert's free-form data dict, defaulting to "" if absent, and trim whitespace
    ip = ((alert.data or {}).get("srcip") or "").strip()
    if ip.lower() in _MISSING_IP:
        # Treat known placeholder/empty values as "no IP" so they aren't used as a dedup discriminator
        return None
    return ip


def dedup_key_for(agent_name: Optional[str], rule_id: Optional[str],
                  source_ip: Optional[str]) -> Optional[str]:
    """The dedup identity of an alert: agent|rule|source_ip. No source_ip means the
    alert was never deduped, so it has no key. Shared with the console's case retry,
    which backfills the dedup row this key points at."""
    if not source_ip:
        # No usable IP means this alert can never be deduped — return no key at all
        return None
    # Compose the composite key, defaulting missing agent/rule parts to safe placeholders
    return f"{agent_name or 'unknown'}|{rule_id or ''}|{source_ip}"


# Classify a 0-100 severity score into "low"/"medium"/"high" using the two
# configured thresholds. Order matters: check the highest cutoff first.
def _branch(score: int) -> str:
    s = get_settings()  # read current threshold configuration
    if score >= s.triage_high_threshold:
        return "high"  # at/above the high threshold -> escalate
    if score >= s.triage_medium_threshold:
        return "medium"  # at/above medium but below high -> needs-review case
    return "low"  # below medium -> auto-close branch


def _log(decision: TriageDecision, alert: WazuhAlert, case: Optional[dict]) -> None:
    # Emit one structured log line per decision, capturing everything needed to audit the routing outcome
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
    """Decide and act. Returns (decision, case_or_None).

    This is the entry point the pipeline calls. It picks the branch from the
    score, then either auto-closes (low), or for medium/high creates a case —
    running it through the dedup check first when the alert has a usable IP.
    """
    s = get_settings()  # current settings snapshot for this routing pass
    score = analysis.severity_score  # the agent's computed severity score (0-100)
    branch = _branch(score)  # classify into low/medium/high

    # ---- LOW: auto-close, never reaches the human queue ----
    if branch == "low":
        case = None  # default: no case created for low-severity alerts
        if s.triage_low_create_resolved_case and s.thehive_enabled:
            # Optional feature: still create a case for audit trail purposes, but immediately close it
            try:
                case = thehive.create_case(alert, analysis, enrichment,
                                           flag=False, extra_tags=["auto-closed"])
                # Close right after creation so it never appears as an open/active case
                thehive.close_case(case["_id"], "Auto-closed by RAM v2 triage (low severity).")
            except thehive.TheHiveError as exc:
                # Case creation/close failure must not block triage from completing — record the error and continue
                logger.error("Low-branch resolved-case creation failed: %s", exc)
                case = {"error": str(exc)}
        # Build the decision record; dedup_eligible=False because low branch never dedups
        decision = TriageDecision(
            branch="low", action="auto_close", severity_score=score, dedup_eligible=False,
            reason=f"score {score} < medium_threshold {s.triage_medium_threshold}: "
                   f"auto-closed, not queued (memory retains full record)",
        )
        _log(decision, alert, case)  # audit log entry
        return decision, case

    # ---- MEDIUM / HIGH: case-creating branches, subject to dedup ----
    flag = branch == "high"  # high branch cases get flagged/escalated
    extra_tags = ["escalated"] if flag else ["needs-review"]  # tag reflects the escalation state
    source_ip = _norm_source_ip(alert)  # normalized source IP, or None if not usable

    # No usable discriminator -> never dedup, always create (safer: no false suppression).
    if source_ip is None:
        case = _create(alert, analysis, enrichment, flag)  # always create a fresh case
        decision = TriageDecision(
            branch=branch, action="create_flagged" if flag else "create_open",
            severity_score=score, dedup_key=None, dedup_eligible=False,
            reason=f"score {score} -> {branch}; dedup skipped (no source_ip discriminator): "
                   f"always create to avoid false suppression",
        )
        _log(decision, alert, case)
        return decision, case

    # Build the dedup identity for this alert and delegate to the dedup-aware execution path
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
        # TheHive integration disabled entirely — skip case creation, but triage still proceeds
        logger.info("TheHive disabled — case creation skipped")
        return None
    extra_tags = ["escalated"] if flag else ["needs-review"]  # recompute tags locally for this helper
    try:
        # Attempt case creation; on success returns {"_id", "number", "title"}
        return thehive.create_case(alert, analysis, enrichment, flag=flag, extra_tags=extra_tags)
    except thehive.TheHiveError as exc:
        # Do not raise — preserve the triage decision and let the console retry later
        logger.error("Case creation failed (analysis preserved, retryable from console): %s", exc)
        return {"error": str(exc)}


def _dedup_and_execute(alert, analysis, enrichment, branch, flag, extra_tags,
                       dedup_key, source_ip) -> tuple[TriageDecision, Optional[dict]]:
    s = get_settings()  # settings snapshot for the dedup window length
    window_h = s.triage_dedup_window_hours  # rolling window size in hours

    # Open a DB connection/transaction for the whole dedup check + mutate sequence.
    # Doing the read and the write in ONE transaction is what makes dedup correct:
    # we must not have another alert sneak in between "did I already see this?" and
    # "record that I've seen it".
    with get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            # Look up any existing dedup row for this key and whether it's still within the rolling window.
            # "FOR UPDATE" is a row-level lock: it tells Postgres to hold this row until
            # our transaction finishes, so if two identical alerts arrive at the same
            # instant they line up one-behind-the-other instead of both thinking they're
            # first and each creating a case. This prevents duplicate cases under load.
            cur.execute(
                "SELECT *, (now() - last_seen) < (%s * interval '1 hour') AS within_window "
                "FROM triage_dedup WHERE dedup_key = %s FOR UPDATE",
                (window_h, dedup_key),
            )
            row = cur.fetchone()  # existing dedup row, or None if this key has never been seen

            if row and row["within_window"]:
                # ---- DUPLICATE: suppress, increment, update existing case ----
                # Atomically bump the occurrence counter and refresh last_seen, returning the updated values
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
                # Build the "suppressed duplicate" decision, carrying forward the existing case's identity
                decision = TriageDecision(
                    branch=branch, action="suppress_duplicate", severity_score=analysis.severity_score,
                    dedup_key=dedup_key, dedup_eligible=True, suppressed=True,
                    occurrence_count=count, existing_case_number=case_number,
                    reason=f"duplicate of case #{case_number} within {window_h}h window "
                           f"(occurrence {count}); suppressed from queue",
                )
                if case_id:
                    # Best-effort: leave a note on the existing case so analysts see the repeat occurrence
                    thehive.add_comment(
                        case_id,
                        f"RAM v2: duplicate occurrence #{count} (alert {alert.id}) "
                        f"suppressed from queue at {alert.timestamp or 'now'}.",
                    )
                _log(decision, alert, {"number": case_number})
                # Note: no new case is created; return the existing case marked as suppressed
                return decision, {"_id": case_id, "number": case_number, "suppressed": True}

            # ---- NEW (no record, or window expired): create case, (re)set record ----
            case = _create(alert, analysis, enrichment, flag)  # create a fresh case (or None/{"error":..})
            case_id = (case or {}).get("_id")  # extract id defensively (case may be None or an error dict)
            case_number = (case or {}).get("number")  # extract case number the same way
            # "Upsert" = insert-or-update in one statement. The ON CONFLICT clause
            # means: if a row for this dedup_key already exists (an expired-window
            # repeat), overwrite it and reset its counter/timestamps to start a
            # fresh window; otherwise insert a brand-new row with occurrence_count 1.
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
            # Build the decision for a new (first, or window-reset) case creation
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
# "Retry" here: when TheHive was unreachable the first time, case creation was
# recorded as a failure (never lost). Later, an analyst can click a button in the
# console to try again. These helpers rebuild the exact same case from what we
# saved and re-attempt it.
# Replays the ORIGINAL triage intent for one investigation: same alert, same
# analysis, same enrichment, same flag — only the moment differs. Nothing here
# touches alert_investigations (still write-once); the caller records the result.
_CASE_CREATING_ACTIONS = ("create_flagged", "create_open")  # actions that originally intended to create a case


def parent_case_for(inv: dict[str, Any]) -> Optional[dict[str, Any]]:
    """The case this alert's dedup GROUP belongs to, if there is one.

    Dedup means "these alerts are one incident, tracked in one case". So an alert
    with no case of its own — a suppressed duplicate, or a create_* alert whose own
    creation failed — belongs to whatever case its dedup key points at, including a
    case created later by a retry. Linking to it is always right and creating a
    second case for the same key never is."""
    # Recompute the dedup key from the stored investigation fields
    key = dedup_key_for(inv.get("agent_name"), inv.get("rule_id"), inv.get("source_ip"))
    if not key:
        # No dedup key means this alert was never part of a dedup group — no parent case possible
        return None
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # Look up whatever case (if any) the dedup group currently points at
        cur.execute(
            "SELECT case_id, case_number FROM triage_dedup "
            "WHERE dedup_key = %s AND case_id IS NOT NULL",
            (key,),
        )
        return cur.fetchone()  # None if the group has no case yet


def can_retry_case(inv: dict[str, Any]) -> bool:
    """True when this investigation MEANT to have a case, has none, and we can build
    a faithful one from what was recorded. Only for alerts whose dedup group has no
    case at all — when the group already has one, the alert must be LINKED to it
    (parent_case_for) rather than given a second case. A suppressed duplicate can
    reach this path: if the original case creation failed and was never retried,
    nothing in the group has a case, and this alert is as good a place to create it
    as any (the dedup row is backfilled, so the whole group then resolves to it)."""
    # All three conditions must hold: action intended a case, no case currently linked, and the raw alert is available to replay
    return bool(
        inv.get("triage_action") in _CASE_CREATING_ACTIONS + ("suppress_duplicate",)
        and not inv.get("case_id")
        and inv.get("alert_payload")
    )


def create_case_for_investigation(inv: dict[str, Any]) -> dict[str, Any]:
    """Retry TheHive case creation for a recorded investigation. Returns the new
    case ({"_id", "number", ...}); raises TheHiveError if TheHive still refuses."""
    # Rehydrate the original typed alert and analysis from the stored raw JSON
    alert = WazuhAlert.model_validate(inv["alert_payload"])
    analysis = AnalysisResult.model_validate(inv["analysis"])
    # Escalation follows the original BRANCH, not the action, so a suppressed
    # duplicate of a high alert still creates the flagged case triage intended.
    flag = inv.get("triage_branch") == "high"
    extra_tags = ["escalated"] if flag else ["needs-review"]  # tag matches the recomputed flag state
    # Create the case now, tagging it as a retry for traceability
    case = thehive.create_case(alert, analysis, inv.get("enrichment") or {},
                               flag=flag, extra_tags=[*extra_tags, "case-retry"])
    logger.info("TRIAGE case retry succeeded investigation=%s case=%s (#%s)",
                inv.get("id"), case.get("_id"), case.get("number"))
    _backfill_dedup(inv, case)  # point the dedup row at the newly created case
    return case


def _backfill_dedup(inv: dict[str, Any], case: dict[str, Any]) -> None:
    """Point this alert's dedup row at the case we just created. Without this, the
    dedup row left behind by the failed attempt still carries a NULL case_id, so
    every repeat inside the window would be suppressed into a case that does not
    exist. Best-effort: the case is already created, so a dedup failure must not
    fail the retry."""
    key = dedup_key_for(inv.get("agent_name"), inv.get("rule_id"), inv.get("source_ip"))
    if not key:
        # No dedup key for this alert — nothing to backfill
        return
    try:
        with get_pool().connection() as conn, conn.cursor() as cur:
            # Only update rows that still have a NULL case_id, so we never clobber a case set by another path
            cur.execute(
                "UPDATE triage_dedup SET case_id = %s, case_number = %s "
                "WHERE dedup_key = %s AND case_id IS NULL",
                (case.get("_id"), case.get("number"), key),
            )
            if cur.rowcount:
                # Only log success if a row was actually updated
                logger.info("TRIAGE dedup backfilled key=%s -> case #%s", key, case.get("number"))
    except Exception:  # noqa: BLE001
        # Swallow all errors here: the case creation already succeeded and must not be undone by a dedup hiccup
        logger.exception("Dedup backfill failed after case retry (case %s created)",
                         case.get("number"))
