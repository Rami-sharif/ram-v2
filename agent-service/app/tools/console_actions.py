"""Audited action tools for the interactive console chat ONLY.

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
import logging

from .. import thehive
from ..console import store
from .registry import Tool, ToolContext

logger = logging.getLogger(__name__)

ACTION_REGISTRY: dict[str, Tool] = {}


def register_action(tool: Tool) -> None:
    ACTION_REGISTRY[tool.name] = tool


def _identity(ctx: ToolContext) -> tuple[str, dict]:
    """Return (analyst_username, investigation) or raise ValueError if missing.
    Both are set by the interactive chat loop, never by the model."""
    if not ctx.analyst_username:
        raise ValueError("no analyst identity in context")
    if not ctx.investigation:
        raise ValueError("no investigation in context")
    return ctx.analyst_username, ctx.investigation


# --- local DB actions (action + audit in one transaction, inside store.*) ----
def _record_verdict_review(args: dict, ctx: ToolContext) -> dict:
    actor, inv = _identity(ctx)
    action = (args.get("action") or "").strip()
    if action not in ("confirm", "override"):
        return {"error": "action must be 'confirm' or 'override'"}
    before = {"severity_label": inv.get("severity_label"),
              "severity_score": inv.get("severity_score"),
              "attack_type": inv.get("attack_type")}
    payload = None
    if action == "override":
        payload = {"severity_label": args.get("severity_label") or None,
                   "attack_type": args.get("attack_type") or None}
        if args.get("severity_score") not in (None, ""):
            try:
                payload["severity_score"] = int(args["severity_score"])
            except (TypeError, ValueError):
                return {"error": "severity_score must be an integer"}
    review_id = store.add_verdict_review(
        investigation_id=inv["id"], actor_username=actor, action=action,
        override_payload=payload, reason=(args.get("reason") or None), before=before,
    )
    return {"ok": True, "action": f"verdict_{action}", "review_id": review_id}


def _record_triage_feedback(args: dict, ctx: ToolContext) -> dict:
    actor, inv = _identity(ctx)
    rating = (args.get("rating") or "").strip()
    if rating not in ("correct", "incorrect"):
        return {"error": "rating must be 'correct' or 'incorrect'"}
    before = {"triage_action": inv.get("triage_action"), "triage_branch": inv.get("triage_branch")}
    feedback_id = store.add_triage_feedback(
        investigation_id=inv["id"], actor_username=actor, rating=rating,
        reason=(args.get("reason") or None), before=before,
    )
    return {"ok": True, "action": "triage_feedback", "rating": rating, "feedback_id": feedback_id}


# --- TheHive case actions (perform -> verify -> audit) ------------------------
def _thehive_close_case(args: dict, ctx: ToolContext) -> dict:
    actor, inv = _identity(ctx)
    case_id = inv.get("case_id")
    if not case_id:
        return {"error": "no linked case for this investigation"}
    resolution = (args.get("resolution") or thehive.DEFAULT_CLOSE_STATUS).strip()
    if resolution not in thehive.CLOSED_STATUSES:
        return {"error": f"resolution must be one of {list(thehive.CLOSED_STATUSES)}"}
    summary = (args.get("summary") or "Closed by RAM v2 analyst (chat).").strip()
    logger.info("THEHIVE_INTENT actor=%s action=thehive_close case=%s resolution=%r (chat)",
                actor, case_id, resolution)
    try:
        thehive.close_case_strict(case_id, summary, resolution)
        case = thehive.get_case(case_id)
        if case.get("stage") != "Closed":
            return {"error": "close not confirmed in TheHive"}
        store.write_audit(actor, "thehive_close", target_type="thehive_case", target_id=case_id,
                          after={"status": case.get("status"), "stage": case.get("stage")},
                          detail=f"{resolution}: {summary} (via chat)")
    except thehive.TheHiveError as exc:
        logger.error("TheHive close failed for case %s: %s", case_id, exc)
        return {"error": f"thehive close failed: {exc}"}
    return {"ok": True, "action": "thehive_close", "case_id": case_id, "resolution": resolution}


def _thehive_set_severity(args: dict, ctx: ToolContext) -> dict:
    actor, inv = _identity(ctx)
    case_id = inv.get("case_id")
    if not case_id:
        return {"error": "no linked case for this investigation"}
    label = (args.get("severity_label") or "").strip()
    if not label:
        return {"error": "severity_label required (info/low/medium/high/critical)"}
    target = thehive.severity_to_int(label)
    logger.info("THEHIVE_INTENT actor=%s action=thehive_set_severity case=%s target=%s(%s) (chat)",
                actor, case_id, target, label)
    try:
        before = thehive.get_case(case_id).get("severity")
        thehive.set_severity(case_id, target)
        landed = thehive.get_case(case_id).get("severity")
        if landed != target:
            return {"error": "severity not confirmed in TheHive"}
        store.write_audit(actor, "thehive_set_severity", target_type="thehive_case",
                          target_id=case_id, before={"severity": before},
                          after={"severity": landed}, detail=f"set to {label} ({target}) (via chat)")
    except thehive.TheHiveError as exc:
        logger.error("TheHive set_severity failed for case %s: %s", case_id, exc)
        return {"error": f"thehive set_severity failed: {exc}"}
    return {"ok": True, "action": "thehive_set_severity", "case_id": case_id, "severity": target}


def _thehive_post_comment(args: dict, ctx: ToolContext) -> dict:
    actor, inv = _identity(ctx)
    case_id = inv.get("case_id")
    if not case_id:
        return {"error": "no linked case for this investigation"}
    message = (args.get("message") or "").strip()
    if not message:
        return {"error": "message required"}
    stamped = f"[{actor}] {message}"
    logger.info("THEHIVE_INTENT actor=%s action=thehive_comment case=%s (chat)", actor, case_id)
    try:
        thehive.post_comment(case_id, stamped)
        landed = any(c.get("message") == stamped for c in thehive.get_case_comments(case_id))
        if not landed:
            return {"error": "comment not confirmed in TheHive"}
        store.write_audit(actor, "thehive_comment", target_type="thehive_case",
                          target_id=case_id, after={"message": stamped})
    except thehive.TheHiveError as exc:
        logger.error("TheHive comment failed for case %s: %s", case_id, exc)
        return {"error": f"thehive comment failed: {exc}"}
    return {"ok": True, "action": "thehive_comment", "case_id": case_id}


register_action(Tool(
    name="record_verdict_review",
    description="Confirm or override the agent's verdict on THIS investigation. Records a "
                "verdict_review and an attributed audit row. Use 'override' to change "
                "severity_label / severity_score / attack_type.",
    parameters={
        "action": {"type": "string", "enum": ["confirm", "override"]},
        "severity_label": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"],
                           "description": "override only"},
        "severity_score": {"type": "integer", "description": "override only, 0-100"},
        "attack_type": {"type": "string", "description": "override only"},
        "reason": {"type": "string", "description": "why (recommended)"},
    },
    required=["action"], handler=_record_verdict_review,
))
register_action(Tool(
    name="record_triage_feedback",
    description="Mark the deterministic triage decision on THIS investigation correct or "
                "incorrect (stored for tuning). Writes an attributed audit row.",
    parameters={
        "rating": {"type": "string", "enum": ["correct", "incorrect"]},
        "reason": {"type": "string", "description": "why (recommended)"},
    },
    required=["rating"], handler=_record_triage_feedback,
))
register_action(Tool(
    name="thehive_close_case",
    description="Close the TheHive case linked to THIS investigation (perform -> verify -> audit). "
                "resolution is the closing outcome.",
    parameters={
        "resolution": {"type": "string",
                       "enum": list(thehive.CLOSED_STATUSES),
                       "description": f"default {thehive.DEFAULT_CLOSE_STATUS}"},
        "summary": {"type": "string", "description": "closing summary"},
    },
    handler=_thehive_close_case,
))
register_action(Tool(
    name="thehive_set_severity",
    description="Set the severity of the TheHive case linked to THIS investigation "
                "(perform -> verify -> audit).",
    parameters={"severity_label": {"type": "string",
                                   "enum": ["info", "low", "medium", "high", "critical"]}},
    required=["severity_label"], handler=_thehive_set_severity,
))
register_action(Tool(
    name="thehive_post_comment",
    description="Add a comment to the TheHive case linked to THIS investigation "
                "(perform -> verify -> audit). The analyst's name is prefixed automatically.",
    parameters={"message": {"type": "string"}},
    required=["message"], handler=_thehive_post_comment,
))
