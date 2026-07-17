"""Audited action tools for the interactive console chat ONLY.

Plain-English intro for newcomers: everything else in the tools/ folder is READ-ONLY
(it only looks things up). This file is different — it holds the tools that actually
CHANGE something: recording a human's verdict, or editing a case over in TheHive
(TheHive is the separate case-management app SOC analysts work in). Because these
tools alter real state, every one of them is "audited": it writes an audit-log row
that permanently records WHO did WHAT and WHEN, so actions can never be anonymous or
denied later.

Two beginner terms used throughout:
  * "audit row" — a tamper-evident log entry (actor, action, before/after values) kept
    for accountability, separate from the change itself.
  * "perform -> verify -> audit" — the safe order for changing an external system: do
    the change, then READ IT BACK to confirm it truly landed, and only then write the
    audit row. This prevents logging a change that silently failed.

These wrap EXISTING functions (store.*, thehive.*) — they do not reimplement any
logic. They are registered into ACTION_REGISTRY, kept entirely separate from the
read-only TOOL_REGISTRY that the automated run_agent uses, so the agent's
automated investigation can never act.

Two invariants, identical to the console's HTTP routes:
  * The acting analyst's username comes from ToolContext (the authenticated
    session), NEVER from the model's arguments — so no audit row is attributed
    to "agent" alone.
  * TheHive mutations follow perform -> verify (read back) -> audit. A failed
    verify returns an error and writes NO audit row.
"""
# Standard library logging, used for audit-trail-adjacent diagnostics (THEHIVE_INTENT lines).
import logging

# memory (for the learning-loop update) and thehive (the case-management API client).
from .. import memory, thehive
# The console's persistence layer: write-once investigations, verdict/triage rows, audit log.
from ..console import store
# Tool/ToolContext dataclasses (register() itself is not used here; see register_action below).
from .registry import Tool, ToolContext

# Module logger for this file.
logger = logging.getLogger(__name__)

# Separate registry for audited, write-capable tools — never merged into TOOL_REGISTRY.
ACTION_REGISTRY: dict[str, Tool] = {}


def register_action(tool: Tool) -> None:
    # Add/overwrite this tool in the audited-action registry, keyed by its name.
    ACTION_REGISTRY[tool.name] = tool


def _identity(ctx: ToolContext) -> tuple[str, dict]:
    """Return (analyst_username, investigation) or raise ValueError if missing.
    Both are set by the interactive chat loop, never by the model."""
    if not ctx.analyst_username:
        # No authenticated analyst in context: refuse rather than let an action go unattributed.
        raise ValueError("no analyst identity in context")
    if not ctx.investigation:
        # No case is focused in this turn: refuse rather than guess which case to act on.
        raise ValueError("no investigation in context")
    return ctx.analyst_username, ctx.investigation


# --- local DB actions (action + audit in one transaction, inside store.*) ----
def _record_verdict_review(args: dict, ctx: ToolContext) -> dict:
    # Resolve the acting analyst and the case they're focused on (raises if either is missing).
    actor, inv = _identity(ctx)
    # The reviewer's decision: must be confirm or override.
    action = (args.get("action") or "").strip()
    if action not in ("confirm", "override"):
        # Reject anything else before touching the store.
        return {"error": "action must be 'confirm' or 'override'"}
    # Snapshot the pre-change verdict fields for the audit "before" state, so the audit
    # row can show exactly what changed. "Severity" is how serious the alert is judged
    # to be (a label like high/critical plus a 0-100 score); "attack_type" is the kind
    # of attack (e.g. brute force = repeatedly guessing a password).
    before = {"severity_label": inv.get("severity_label"),
              "severity_score": inv.get("severity_score"),
              "attack_type": inv.get("attack_type")}
    # Only an override carries a replacement payload; confirm has none.
    payload = None
    if action == "override":
        payload = {"severity_label": args.get("severity_label") or None,
                   "attack_type": args.get("attack_type") or None}
        if args.get("severity_score") not in (None, ""):
            try:
                # Coerce the override score to int since severity_score is always numeric.
                payload["severity_score"] = int(args["severity_score"])
            except (TypeError, ValueError):
                # Reject a non-numeric override score rather than writing bad data.
                return {"error": "severity_score must be an integer"}
    # Persist the verdict review AND its audit row together as one atomic transaction
    # (a database transaction is all-or-nothing: either both rows commit or neither
    # does), so we can never end up with a change that has no matching audit entry.
    review_id = store.add_verdict_review(
        investigation_id=inv["id"], actor_username=actor, action=action,
        override_payload=payload, reason=(args.get("reason") or None), before=before,
    )
    # Learning loop: fold this verdict into the alert's memory row (best-effort).
    try:
        # Feed the human verdict back into semantic memory so future similar alerts benefit.
        memory.record_human_verdict(inv, action=action, override_payload=payload, actor=actor)
    except Exception:  # noqa: BLE001
        # The verdict itself is already recorded; a memory-update failure must not undo that.
        logger.exception("Learning-loop memory update failed (verdict recorded)")
    return {"ok": True, "action": f"verdict_{action}", "review_id": review_id}


def _record_triage_feedback(args: dict, ctx: ToolContext) -> dict:
    # Resolve the acting analyst and the case they're focused on.
    actor, inv = _identity(ctx)
    # The analyst's rating of the deterministic triage decision.
    rating = (args.get("rating") or "").strip()
    if rating not in ("correct", "incorrect"):
        # Reject any other value before writing to the store.
        return {"error": "rating must be 'correct' or 'incorrect'"}
    # Snapshot the pre-change triage fields for the audit "before" state.
    before = {"triage_action": inv.get("triage_action"), "triage_branch": inv.get("triage_branch")}
    # Persist the feedback + its audit row via the store layer.
    feedback_id = store.add_triage_feedback(
        investigation_id=inv["id"], actor_username=actor, rating=rating,
        reason=(args.get("reason") or None), before=before,
    )
    return {"ok": True, "action": "triage_feedback", "rating": rating, "feedback_id": feedback_id}


# --- TheHive case actions (perform -> verify -> audit) ------------------------
def _thehive_close_case(args: dict, ctx: ToolContext) -> dict:
    # Resolve the acting analyst and the focused investigation.
    actor, inv = _identity(ctx)
    # The TheHive case id linked to this investigation, if any.
    case_id = inv.get("case_id")
    if not case_id:
        # Can't close a case that was never linked to TheHive.
        return {"error": "no linked case for this investigation"}
    # The closing resolution status, defaulting to the standard close status if not given.
    resolution = (args.get("resolution") or thehive.DEFAULT_CLOSE_STATUS).strip()
    if resolution not in thehive.CLOSED_STATUSES:
        # Reject any resolution value TheHive wouldn't accept as a valid closed status.
        return {"error": f"resolution must be one of {list(thehive.CLOSED_STATUSES)}"}
    # Closing summary text, defaulting to a generic message if the analyst didn't supply one.
    summary = (args.get("summary") or "Closed by RAM v2 analyst (chat).").strip()
    # Log the intent BEFORE performing the mutation, for traceability even if it later fails.
    logger.info("THEHIVE_INTENT actor=%s action=thehive_close case=%s resolution=%r (chat)",
                actor, case_id, resolution)
    try:
        # Perform: ask TheHive to close the case with this resolution/summary.
        thehive.close_case_strict(case_id, summary, resolution)
        # Verify: read the case back from TheHive to confirm the close actually landed.
        case = thehive.get_case(case_id)
        if case.get("stage") != "Closed":
            # The API call succeeded but TheHive doesn't reflect it as closed: don't audit a lie.
            return {"error": "close not confirmed in TheHive"}
        # Audit: only write the audit row once the change is confirmed to have landed.
        store.write_audit(actor, "thehive_close", target_type="thehive_case", target_id=case_id,
                          after={"status": case.get("status"), "stage": case.get("stage")},
                          detail=f"{resolution}: {summary} (via chat)")
    except thehive.TheHiveError as exc:
        # Any TheHive API error: log it and surface a structured error, write no audit row.
        logger.error("TheHive close failed for case %s: %s", case_id, exc)
        return {"error": f"thehive close failed: {exc}"}
    return {"ok": True, "action": "thehive_close", "case_id": case_id, "resolution": resolution}


def _thehive_set_severity(args: dict, ctx: ToolContext) -> dict:
    # Resolve the acting analyst and the focused investigation.
    actor, inv = _identity(ctx)
    # The TheHive case id linked to this investigation, if any.
    case_id = inv.get("case_id")
    if not case_id:
        # Can't set severity on a case that isn't linked to TheHive.
        return {"error": "no linked case for this investigation"}
    # The requested severity label (info/low/medium/high/critical).
    label = (args.get("severity_label") or "").strip()
    if not label:
        # A label is mandatory for this action.
        return {"error": "severity_label required (info/low/medium/high/critical)"}
    # Convert the human label (e.g. "high") to the integer TheHive stores internally,
    # because TheHive's API expects a number, not our word.
    target = thehive.severity_to_int(label)
    # Log the intent BEFORE performing the mutation, for traceability.
    logger.info("THEHIVE_INTENT actor=%s action=thehive_set_severity case=%s target=%s(%s) (chat)",
                actor, case_id, target, label)
    try:
        # Snapshot the current severity before changing it (for the audit "before" state).
        before = thehive.get_case(case_id).get("severity")
        # Perform: push the new severity to TheHive.
        thehive.set_severity(case_id, target)
        # Verify: read the case back to confirm the severity actually changed.
        landed = thehive.get_case(case_id).get("severity")
        if landed != target:
            # TheHive doesn't reflect the intended severity: don't audit an unconfirmed change.
            return {"error": "severity not confirmed in TheHive"}
        # Audit: write the row only after confirming the change landed.
        store.write_audit(actor, "thehive_set_severity", target_type="thehive_case",
                          target_id=case_id, before={"severity": before},
                          after={"severity": landed}, detail=f"set to {label} ({target}) (via chat)")
    except thehive.TheHiveError as exc:
        # Any TheHive API error: log it and surface a structured error, write no audit row.
        logger.error("TheHive set_severity failed for case %s: %s", case_id, exc)
        return {"error": f"thehive set_severity failed: {exc}"}
    return {"ok": True, "action": "thehive_set_severity", "case_id": case_id, "severity": target}


def _thehive_post_comment(args: dict, ctx: ToolContext) -> dict:
    # Resolve the acting analyst and the focused investigation.
    actor, inv = _identity(ctx)
    # The TheHive case id linked to this investigation, if any.
    case_id = inv.get("case_id")
    if not case_id:
        # Can't comment on a case that isn't linked to TheHive.
        return {"error": "no linked case for this investigation"}
    # The comment text, trimmed of whitespace.
    message = (args.get("message") or "").strip()
    if not message:
        # A non-empty message is mandatory.
        return {"error": "message required"}
    # Prefix the comment with the analyst's name so TheHive shows who really said it.
    stamped = f"[{actor}] {message}"
    # Log the intent BEFORE performing the mutation, for traceability.
    logger.info("THEHIVE_INTENT actor=%s action=thehive_comment case=%s (chat)", actor, case_id)
    try:
        # Perform: post the stamped comment to TheHive.
        thehive.post_comment(case_id, stamped)
        # Verify: re-read the case's comments and confirm our exact stamped text is present.
        landed = any(c.get("message") == stamped for c in thehive.get_case_comments(case_id))
        if not landed:
            # The comment doesn't show up on read-back: don't audit an unconfirmed post.
            return {"error": "comment not confirmed in TheHive"}
        # Audit: write the row only after confirming the comment landed.
        store.write_audit(actor, "thehive_comment", target_type="thehive_case",
                          target_id=case_id, after={"message": stamped})
    except thehive.TheHiveError as exc:
        # Any TheHive API error: log it and surface a structured error, write no audit row.
        logger.error("TheHive comment failed for case %s: %s", case_id, exc)
        return {"error": f"thehive comment failed: {exc}"}
    return {"ok": True, "action": "thehive_comment", "case_id": case_id}


# --- Expose the handlers above to the model as callable tools -----------------
# Each Tool below pairs a name + a plain-English `description` (what the model reads to
# decide when to use it) + a JSON-schema `parameters` block (the argument shapes the
# model must produce) + the `handler` function defined above. register_action() files
# it under ACTION_REGISTRY — the audited, human-chat-only registry.

# Register the verdict-review tool into ACTION_REGISTRY (audited, console-chat only).
register_action(Tool(
    name="record_verdict_review",
    description="Confirm or override the agent's verdict on THIS investigation. Records a "
                "verdict_review and an attributed audit row. Use 'override' to change "
                "severity_label / severity_score / attack_type.",
    parameters={
        # Whether the analyst is confirming or overriding the agent's original verdict.
        "action": {"type": "string", "enum": ["confirm", "override"]},
        # Override-only: replacement severity label.
        "severity_label": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"],
                           "description": "override only"},
        # Override-only: replacement numeric severity score.
        "severity_score": {"type": "integer", "description": "override only, 0-100"},
        # Override-only: replacement attack-type classification.
        "attack_type": {"type": "string", "description": "override only"},
        # Optional free-text justification, recommended for auditability.
        "reason": {"type": "string", "description": "why (recommended)"},
    },
    required=["action"], handler=_record_verdict_review,
))
# Register the triage-feedback tool into ACTION_REGISTRY.
register_action(Tool(
    name="record_triage_feedback",
    description="Mark the deterministic triage decision on THIS investigation correct or "
                "incorrect (stored for tuning). Writes an attributed audit row.",
    parameters={
        # Whether the deterministic triage router got this case right.
        "rating": {"type": "string", "enum": ["correct", "incorrect"]},
        # Optional free-text justification, recommended for auditability.
        "reason": {"type": "string", "description": "why (recommended)"},
    },
    required=["rating"], handler=_record_triage_feedback,
))
# Register the TheHive close-case tool into ACTION_REGISTRY.
register_action(Tool(
    name="thehive_close_case",
    description="Close the TheHive case linked to THIS investigation (perform -> verify -> audit). "
                "resolution is the closing outcome.",
    parameters={
        # The closing status; enum is generated from TheHive's actual set of closed statuses.
        "resolution": {"type": "string",
                       "enum": list(thehive.CLOSED_STATUSES),
                       "description": f"default {thehive.DEFAULT_CLOSE_STATUS}"},
        # Optional free-text closing summary.
        "summary": {"type": "string", "description": "closing summary"},
    },
    handler=_thehive_close_case,
))
# Register the TheHive set-severity tool into ACTION_REGISTRY.
register_action(Tool(
    name="thehive_set_severity",
    description="Set the severity of the TheHive case linked to THIS investigation "
                "(perform -> verify -> audit).",
    parameters={"severity_label": {"type": "string",
                                   "enum": ["info", "low", "medium", "high", "critical"]}},
    required=["severity_label"], handler=_thehive_set_severity,
))
# Register the TheHive comment tool into ACTION_REGISTRY.
register_action(Tool(
    name="thehive_post_comment",
    description="Add a comment to the TheHive case linked to THIS investigation "
                "(perform -> verify -> audit). The analyst's name is prefixed automatically.",
    parameters={"message": {"type": "string"}},
    required=["message"], handler=_thehive_post_comment,
))
