"""Expose Phase 2 semantic memory retrieval as an agent tool (read-only)."""
import logging

from .. import memory
from .registry import Tool, ToolContext, register

logger = logging.getLogger(__name__)


def _search_memory(args: dict, ctx: ToolContext) -> dict:
    query = (args.get("query") or "").strip()
    if not query:
        return {"error": "query required"}
    agent_name = args.get("agent_name")
    k = int(args.get("k") or 5)
    try:
        rows = memory.search_memories(query, agent_name=agent_name, k=k)
    except Exception as exc:  # noqa: BLE001
        logger.exception("search_memory failed")
        return {"error": f"memory search failed: {exc}"}
    items = []
    for r in rows:
        a = r.get("analysis") or {}
        items.append({
            "id": r["id"], "when": str(r.get("alert_timestamp") or r.get("created_at")),
            "similarity": round(r["similarity"], 3) if r.get("similarity") is not None else None,
            "alert_text": r["alert_text"],
            "severity": a.get("severity_label"), "attack_type": a.get("attack_type"),
        })
    return {"count": len(items), "matches": items}


register(Tool(
    name="search_memory",
    description="Semantic search over stored past alerts+analyses (this company's history). "
                "Use to check whether similar activity has been seen and how it was judged before.",
    parameters={
        "query": {"type": "string", "description": "what to look for, e.g. 'ssh brute force from tor'"},
        "agent_name": {"type": "string", "description": "optional: restrict to one host"},
        "k": {"type": "integer", "description": "max matches (default 5)"},
    },
    required=["query"], handler=_search_memory,
))
