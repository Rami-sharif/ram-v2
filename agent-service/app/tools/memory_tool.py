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
    # Build a compact, model-friendly view of each matched memory row.
    items = []
    for r in rows:
        # Prior stored analysis dict, defaulting to {} if absent.
        a = r.get("analysis") or {}
        items.append({
            # Row identifier and best-available timestamp (alert time, else creation time).
            "id": r["id"], "when": str(r.get("alert_timestamp") or r.get("created_at")),
            # Similarity score: how close this past alert is to the query (higher = more
            # alike). Rounded to 3 decimals for readability; None if the store omitted it.
            "similarity": round(r["similarity"], 3) if r.get("similarity") is not None else None,
            "alert_text": r["alert_text"],
            # Pull out the prior verdict fields the analyst/agent would care about.
            "severity": a.get("severity_label"), "attack_type": a.get("attack_type"),
        })
    # Return both a count and the list, so the model can quickly gauge relevance/coverage.
    return {"count": len(items), "matches": items}


# Register this handler as the "search_memory" tool available to the agent loop.
register(Tool(
    name="search_memory",
    # Explains to the model when to reach for this tool: comparing against company history.
    description="Semantic search over stored past alerts+analyses (this company's history). "
                "Use to check whether similar activity has been seen and how it was judged before.",
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
