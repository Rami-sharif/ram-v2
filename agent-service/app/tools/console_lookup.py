"""Read-only case-lookup tools for the interactive console chat ONLY.

Plain-English intro: the "console" is the human-facing dashboard where an analyst can
chat with the assistant ("pull up case 13", "did this IP show up elsewhere?"). These
two tools let that chat assistant look cases up. They are READ-ONLY (they fetch, never
change) and are kept in a SEPARATE registry from the automated agent's tools, so the
unattended agent can never even see them — a safety boundary between "assistant helping
a logged-in human" and "robot running on its own".

A note on some terms below: "write-once alert_investigations table" is a database table
of finished case records that are never edited after creation (so history stays
trustworthy); "console.store" is the small module that reads/writes those rows; and a
"raw-SQL tool" (which we deliberately do NOT use) would let the model run arbitrary
database queries — too dangerous, so lookups go through fixed, safe functions only.

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
# Standard library logging for tool-level diagnostics.
import logging

# Tool/ToolContext dataclasses and register_interactive() to add these to INTERACTIVE_REGISTRY.
from .registry import Tool, ToolContext, register_interactive

# Module logger for this file.
logger = logging.getLogger(__name__)


def _summarize(rec: dict) -> dict:
    """Compact, model-friendly view of a write-once investigation record."""
    # Prior stored analysis payload, defaulting to {} if the record has none.
    a = rec.get("analysis") or {}
    return {
        # Internal DB id of the investigation row.
        "investigation_id": rec.get("id"),
        # Human-facing TheHive case number the analyst references in conversation.
        "case_number": rec.get("case_number"),
        # Internal TheHive case id used for API calls against that case.
        "case_id": rec.get("case_id"),
        # Originating Wazuh alert id this investigation was created from.
        "alert_id": rec.get("alert_id"),
        # Host/agent name the alert fired on.
        "agent_name": rec.get("agent_name"),
        # Source IP recorded for the investigation, if any.
        "source_ip": rec.get("source_ip"),
        # Wazuh rule id that triggered the alert.
        "rule_id": rec.get("rule_id"),
        # Stored severity label from the original triage.
        "severity_label": rec.get("severity_label"),
        # Stored numeric severity score from the original triage.
        "severity_score": rec.get("severity_score"),
        # Stored attack-type classification.
        "attack_type": rec.get("attack_type"),
        # Analyst-facing summary text from the stored analysis.
        "summary": a.get("summary"),
        # Recommended next action from the stored analysis.
        "recommended_action": a.get("recommended_action"),
        # Deterministic triage-router outcome recorded for this case.
        "triage_action": rec.get("triage_action"),
    }


def _get_investigation_by_case_number(args: dict, ctx: ToolContext) -> dict:
    # Import the store INSIDE the function, not at the top of the file, to avoid a
    # "circular import": the console package imports this tools module and this module
    # imports the console package, and doing both at load time would deadlock. Importing
    # here (only when the function actually runs) sidesteps that chicken-and-egg problem.
    from ..console import store

    # Raw case_number argument as passed by the model (may be a string).
    raw = args.get("case_number")
    try:
        # Coerce to int since TheHive case numbers are always integers.
        case_number = int(raw)
    except (TypeError, ValueError):
        # Reject non-numeric input rather than letting a bad query hit the store layer.
        return {"error": "case_number must be an integer (the TheHive case number)"}
    # Look up the write-once investigation record by its case number.
    rec = store.get_investigation_by_case_number(case_number)
    if rec is None:
        # No investigation exists for that case number.
        return {"found": False, "case_number": case_number}
    # Focus the interactive context on this case so an audited action later in the
    # SAME turn targets it. Identity is untouched (still the session analyst).
    ctx.investigation = rec
    # Return a found flag plus the compact summary view of the record.
    return {"found": True, **_summarize(rec)}


def _search_investigations_by_indicator(args: dict, ctx: ToolContext) -> dict:
    # Import here (not at the top) to avoid a circular import — same reason as above.
    from ..console import store

    # The "indicator" to search for — in security, an indicator (of compromise) is a
    # concrete artifact that ties activity together, here a source IP or a file hash.
    # Trim whitespace so stray spaces don't cause a false "not found".
    indicator = (args.get("indicator") or "").strip()
    if not indicator:
        # Nothing to search on; return a structured error.
        return {"error": "indicator required (a source IP or a file hash)"}
    # Query the store for investigations referencing this indicator, capped at 25 rows.
    rows = store.search_investigations_by_indicator(indicator, limit=25)
    return {
        "indicator": indicator,
        # Number of matches actually found (may be less than the query limit).
        "count": len(rows),
        # Build a compact summary for each matching investigation row.
        "matches": [
            {
                "investigation_id": r.get("id"),
                "case_number": r.get("case_number"),
                "source_ip": r.get("source_ip"),
                "agent_name": r.get("agent_name"),
                "rule_id": r.get("rule_id"),
                "severity_label": r.get("severity_label"),
                "attack_type": r.get("attack_type"),
                # Stringify the timestamp for JSON-safe serialization.
                "created_at": str(r.get("created_at")),
            }
            for r in rows
        ],
    }


# Register the case-by-number lookup tool into INTERACTIVE_REGISTRY (console chat only).
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
        # The only input: the TheHive case number to resolve.
        "case_number": {"type": "integer", "description": "the TheHive case number to pull up"},
    },
    required=["case_number"],
    handler=_get_investigation_by_case_number,
))

# Register the indicator-search tool into INTERACTIVE_REGISTRY (console chat only).
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
        # The only input: the IP or hash to search across all investigations.
        "indicator": {"type": "string", "description": "a source IP address or a file hash"},
    },
    required=["indicator"],
    handler=_search_investigations_by_indicator,
))
