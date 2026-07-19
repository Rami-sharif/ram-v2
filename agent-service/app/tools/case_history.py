"""Let the investigation agent see its OWN case history (read-only).

WHAT THIS FILE IS, FOR A NEWCOMER:
Every alert this system finishes investigating is written to a permanent record
(`alert_investigations`) along with the verdict it was given and, if a human analyst later
reviewed it, whether they agreed. Until now that record was only reachable from the analyst
chat in the console — the automated agent investigating a fresh alert could not consult it.
So it could not answer the most natural SOC question of all: "have we seen this exact IP
before, and what did we decide last time?"

This module exposes that history to the automated agent as a READ-ONLY tool. It answers
questions about a SPECIFIC INDICATOR (an exact IP address or file hash). That makes it the
sibling of two other history tools, and the distinction matters because the model has to pick
between them:
  - search_memory              -> "similar situations", matched by MEANING (semantic/vector)
  - search_past_investigations -> "this exact indicator", matched EXACTLY (this file)

Deliberately a separate module from console_lookup.py: that file is documented as
INTERACTIVE_REGISTRY-only (console chat), and mixing register() calls into it would blur a
security boundary a future reader relies on.
"""
import logging  # report lookup failures without crashing the agent loop

from .. import memory  # source_ip_of: default the indicator to this alert's own source IP
from .registry import Tool, ToolContext, register

logger = logging.getLogger(__name__)

# Default / maximum number of prior cases to return. Kept small on purpose: each row is a
# handful of fields, and dispatch()'s cap_result silently DROPS list items once a result
# exceeds tool_max_result_chars — better to return 8 complete rows than 25 mangled ones.
_DEFAULT_LIMIT = 8
_MAX_LIMIT = 15


def _summarize_case(row: dict) -> dict:
    """Compact, model-facing view of one prior investigation.

    Internal database ids are deliberately omitted — the model has no tool to dereference
    them, so exposing them would only invite invented follow-up calls. `case_number` is kept
    because it is the human-facing identifier an analyst would recognise."""
    a = row.get("analysis") or {}
    return {
        "case_number": row.get("case_number"),
        "when": str(row.get("created_at")),
        "host": row.get("agent_name"),
        "source_ip": row.get("source_ip"),
        "rule_id": row.get("rule_id"),
        "severity": row.get("severity_label"),
        "attack_type": row.get("attack_type"),
        "triage_action": row.get("triage_action"),
        # Human ground truth — the whole point of consulting past cases. If an analyst
        # reviewed this verdict, that decision outranks anything the agent infers on its own.
        "analyst_reviewed": bool(a.get("human_reviewed")),
        "analyst_action": a.get("human_action"),
    }


def _search_past_investigations(args: dict, ctx: ToolContext) -> dict:
    # Import the store INSIDE the function, not at module top: the console package imports
    # this tools package, so importing it back at load time would deadlock (circular import).
    # Same pattern and rationale as console_lookup.py.
    from ..console import store

    # Default the indicator to THIS alert's own source IP so the model can call the tool with
    # no arguments at all — the common case ("has this attacker hit us before?") then costs it
    # no argument-construction effort and no wasted iteration.
    indicator = (args.get("indicator") or "").strip()
    if not indicator:
        indicator = memory.source_ip_of(ctx.alert)
    if not indicator:
        # No indicator supplied and the alert carries no source IP — nothing to search on.
        return {"error": "no indicator given and this alert has no source IP to default to"}

    # Clamp the caller-supplied limit into a sane range (see _MAX_LIMIT note above).
    try:
        limit = min(max(int(args.get("limit") or _DEFAULT_LIMIT), 1), _MAX_LIMIT)
    except (TypeError, ValueError):
        limit = _DEFAULT_LIMIT  # unparseable limit is not worth failing the call over

    try:
        rows = store.search_investigations_by_indicator(indicator, limit=limit)
    except Exception as exc:  # noqa: BLE001 - a history lookup must never break the loop
        logger.exception("search_past_investigations failed")
        return {"error": f"case history lookup failed: {exc}"}

    cases = [_summarize_case(r) for r in rows]
    # Surface the reviewed count separately so the model doesn't have to scan the list to
    # notice that human ground truth is available.
    reviewed = sum(1 for c in cases if c["analyst_reviewed"])
    return {
        "indicator": indicator,
        "count": len(cases),
        "analyst_reviewed_count": reviewed,
        "cases": cases,
    }


# Registered into TOOL_REGISTRY (register, NOT register_interactive) so the AUTOMATED
# investigation agent can call it. Read-only: it only SELECTs from the write-once record.
register(Tool(
    name="search_past_investigations",
    description=(
        "Search this company's RECORDED PAST INVESTIGATIONS for an exact indicator — an IP "
        "address or a file hash — to answer 'have we investigated this exact indicator before, "
        "and what did we decide?'. Returns prior cases with the severity and attack type they "
        "were given, and whether a human analyst reviewed that verdict. A prior "
        "ANALYST-REVIEWED case on the same indicator is authoritative ground truth: align your "
        "verdict with it unless THIS alert clearly differs, and say so in your summary. "
        "Call it with no arguments to check this alert's own source IP. "
        "This searches recorded case DECISIONS — not raw Wazuh logs (use get_related_logs or "
        "get_alert_statistics for those), and not semantic similarity (use search_memory to "
        "find similar situations worded differently)."
    ),
    parameters={
        "indicator": {"type": "string",
                      "description": "an IP address or file hash; defaults to this alert's source IP"},
        "limit": {"type": "integer",
                  "description": f"max prior cases to return (default {_DEFAULT_LIMIT}, max {_MAX_LIMIT})"},
    },
    # Deliberately empty: a zero-argument call on the alert's own source IP is the common case.
    required=[],
    handler=_search_past_investigations,
))
