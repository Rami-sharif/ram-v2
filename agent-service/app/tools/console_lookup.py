"""Read-only case-lookup tools for the interactive console chat ONLY.

Registered into INTERACTIVE_REGISTRY (never TOOL_REGISTRY), so the automated
run_agent path can never see them. They query the write-once alert_investigations
table via console.store — NOT raw Wazuh logs, NOT semantic memory, and NEVER via a
raw-SQL tool. They let the dashboard assistant pull up any case the analyst names
in free text without the page having pre-loaded it.

get_investigation_by_case_number additionally FOCUSES the interactive context on
the case it resolves: it sets ctx.investigation so that a follow-up AUDITED action
in the SAME turn (e.g. "...and add a comment") targets that case. The acting
identity still comes from the session (ctx.analyst_username), never the model.
"""
import logging

from .registry import Tool, ToolContext, register_interactive

logger = logging.getLogger(__name__)


def _summarize(rec: dict) -> dict:
    """Compact, model-friendly view of a write-once investigation record."""
    a = rec.get("analysis") or {}
    return {
        "investigation_id": rec.get("id"),
        "case_number": rec.get("case_number"),
        "case_id": rec.get("case_id"),
        "alert_id": rec.get("alert_id"),
        "agent_name": rec.get("agent_name"),
        "source_ip": rec.get("source_ip"),
        "rule_id": rec.get("rule_id"),
        "severity_label": rec.get("severity_label"),
        "severity_score": rec.get("severity_score"),
        "attack_type": rec.get("attack_type"),
        "summary": a.get("summary"),
        "recommended_action": a.get("recommended_action"),
        "triage_action": rec.get("triage_action"),
    }


def _get_investigation_by_case_number(args: dict, ctx: ToolContext) -> dict:
    # Import here to avoid a circular import at module load (tools -> console -> tools).
    from ..console import store

    raw = args.get("case_number")
    try:
        case_number = int(raw)
    except (TypeError, ValueError):
        return {"error": "case_number must be an integer (the TheHive case number)"}
    rec = store.get_investigation_by_case_number(case_number)
    if rec is None:
        return {"found": False, "case_number": case_number}
    # Focus the interactive context on this case so an audited action later in the
    # SAME turn targets it. Identity is untouched (still the session analyst).
    ctx.investigation = rec
    return {"found": True, **_summarize(rec)}


def _search_investigations_by_indicator(args: dict, ctx: ToolContext) -> dict:
    from ..console import store

    indicator = (args.get("indicator") or "").strip()
    if not indicator:
        return {"error": "indicator required (a source IP or a file hash)"}
    rows = store.search_investigations_by_indicator(indicator, limit=25)
    return {
        "indicator": indicator,
        "count": len(rows),
        "matches": [
            {
                "investigation_id": r.get("id"),
                "case_number": r.get("case_number"),
                "source_ip": r.get("source_ip"),
                "agent_name": r.get("agent_name"),
                "rule_id": r.get("rule_id"),
                "severity_label": r.get("severity_label"),
                "attack_type": r.get("attack_type"),
                "created_at": str(r.get("created_at")),
            }
            for r in rows
        ],
    }


register_interactive(Tool(
    name="get_investigation_by_case_number",
    description=(
        "Look up ONE investigation by its TheHive case NUMBER (e.g. 13), not its internal id. "
        "Returns the stored severity, source IP, rule, attack type, and analysis summary for that "
        "case. Use this whenever the analyst references a case by number so you can answer from its "
        "recorded details. After looking a case up here, an audited action (verdict / triage "
        "feedback / TheHive close-severity-comment) in the SAME reply will target this case."
    ),
    parameters={
        "case_number": {"type": "integer", "description": "the TheHive case number to pull up"},
    },
    required=["case_number"],
    handler=_get_investigation_by_case_number,
))

register_interactive(Tool(
    name="search_investigations_by_indicator",
    description=(
        "Search ALL recorded investigations for an indicator — a source IP or a file hash — to "
        "answer 'did this IP/hash appear in another case'. Matches the investigation's source_ip "
        "exactly, or the indicator appearing anywhere in the stored analysis (e.g. a hash). Returns "
        "the matching cases (case number, IP, host, rule, severity). This searches the recorded "
        "investigations table, NOT raw Wazuh logs and NOT semantic memory."
    ),
    parameters={
        "indicator": {"type": "string", "description": "a source IP address or a file hash"},
    },
    required=["indicator"],
    handler=_search_investigations_by_indicator,
))
