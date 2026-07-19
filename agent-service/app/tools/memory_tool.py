"""Expose semantic memory retrieval as an agent tool (read-only).

For newcomers: as this system handles alerts it saves each alert plus how it was
judged into a "memory" store. This tool lets the AI search that history by MEANING,
not exact keywords — that's what "semantic" / "vector" search means. Each stored
alert is turned into an embedding (a list of numbers that captures its meaning), and
a new query is turned into numbers the same way; the store then returns the past
alerts whose numbers are closest, i.e. the most similar situations. So asking "ssh
brute force from tor" can surface a past alert worded differently but about the same
thing. It's READ-ONLY: it only recalls history, it never writes."""
# Standard library logging, used to record memory-search failures without crashing the tool.
import logging
# Timezone-aware "now", used as the single reference instant for the age-decay re-ranking.
from datetime import datetime, timezone

# The memory module owns the vector-search implementation over past alerts+analyses.
from .. import memory
# Tool/ToolContext dataclasses and the register() function to add this tool to TOOL_REGISTRY.
from .registry import Tool, ToolContext, register

# Module-level logger, named after this module for easy filtering in log output.
logger = logging.getLogger(__name__)


def _search_memory(args: dict, ctx: ToolContext) -> dict:
    # Pull the free-text query out of the model's arguments, defaulting to "" then trimming.
    query = (args.get("query") or "").strip()
    if not query:
        # Nothing to search on; return a structured error the agent can see and react to.
        return {"error": "query required"}
    # Optional filter to restrict results to memories about one host/agent.
    agent_name = args.get("agent_name")
    # Max number of matches to return ("k" is the common name for a top-k result count
    # in search); defaults to 5 if the model didn't specify one.
    k = int(args.get("k") or 5)
    try:
        # Delegate to the actual vector-similarity search implementation.
        rows = memory.search_memories(query, agent_name=agent_name, k=k)
    except Exception as exc:  # noqa: BLE001
        # Any failure (DB down, embedding error, etc.) must not crash the agent loop.
        logger.exception("search_memory failed")
        return {"error": f"memory search failed: {exc}"}
    # Re-rank the raw cosine matches the same way the alert pipeline ranks memories, so this
    # tool honours analyst ground truth instead of treating every past alert as equally
    # trustworthy. feedback_weight boosts memories an analyst confirmed (and boosts a CORRECTED
    # one most, since that is verified ground truth fixing a past mistake); the decay factor
    # sinks stale memories beneath equally-relevant recent ones. Same multiplicative composition
    # used by memory._score_candidate, minus the exact-IOC tier (which needs the live alert).
    now = datetime.now(timezone.utc)  # one reference instant so all rows age identically
    for r in rows:
        r["_rank"] = ((r.get("similarity") or 0.0)
                      * memory.feedback_weight(r.get("analysis"))
                      * memory._decay_factor(r, now))
    rows.sort(key=lambda r: r["_rank"], reverse=True)  # best composite score first

    # Build a compact, model-friendly view of each matched memory row.
    items = []
    for r in rows:
        # Prior stored analysis dict, defaulting to {} if absent.
        a = r.get("analysis") or {}
        items.append({
            # Best-available timestamp (alert time, else creation time). NOTE: the row id is
            # deliberately NOT returned — there is no tool to dereference it, so exposing it
            # would only invite the model to invent follow-up calls it cannot make.
            "when": str(r.get("alert_timestamp") or r.get("created_at")),
            # Similarity score: how close this past alert is to the query (higher = more
            # alike). Rounded to 3 decimals for readability; None if the store omitted it.
            "similarity": round(r["similarity"], 3) if r.get("similarity") is not None else None,
            "alert_text": r["alert_text"],
            # Pull out the prior verdict fields the analyst/agent would care about.
            "severity": a.get("severity_label"), "attack_type": a.get("attack_type"),
            # Human ground truth: whether an analyst reviewed this memory and, if so, whether
            # they confirmed the verdict or overrode it. The system prompt tells the agent to
            # treat these as authoritative, so the flags must actually reach it.
            "analyst_reviewed": bool(a.get("human_reviewed")),
            "analyst_action": a.get("human_action"),
        })
    # Return both a count and the list, so the model can quickly gauge relevance/coverage.
    return {"count": len(items), "matches": items}


# Register this handler as the "search_memory" tool available to the agent loop.
register(Tool(
    name="search_memory",
    # Explains to the model when to reach for this tool: comparing against company history.
    description="Semantic search over stored past alerts+analyses (this company's history) for "
                "SIMILAR SITUATIONS — matches by meaning, so it finds past alerts worded "
                "differently about the same kind of activity. Results are ranked by similarity, "
                "how recent they are, and whether an analyst verified them; each match reports "
                "analyst_reviewed / analyst_action, and a human-reviewed match is authoritative. "
                "To instead check a SPECIFIC indicator (this exact IP or file hash) against past "
                "cases, use search_past_investigations.",
    parameters={
        # Free-text description of what to search for.
        "query": {"type": "string", "description": "what to look for, e.g. 'ssh brute force from tor'"},
        # Optional scoping to a single host's memory.
        "agent_name": {"type": "string", "description": "optional: restrict to one host"},
        # Optional cap on number of returned matches.
        "k": {"type": "integer", "description": "max matches (default 5)"},
    },
    # query is mandatory; agent_name/k are optional filters/limits.
    required=["query"], handler=_search_memory,
))
