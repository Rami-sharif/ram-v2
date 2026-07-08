"""Tool registry the agent loop reads from.

Adding a tool later = define a handler and call register(Tool(...)). The loop builds
Gemini's function declarations from the registry and dispatches calls by name. Every
handler runs through dispatch(), which (a) strips the bookkeeping `reason` arg,
(b) never lets an exception reach the loop (graceful degradation), and (c) size-caps
the result so a noisy host can't blow up the prompt.
"""
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..config import get_settings
from ..schemas import WazuhAlert

logger = logging.getLogger(__name__)


@dataclass
class ToolContext:
    """Shared context passed to every tool handler.

    The automated read-only path (run_agent) constructs this with only `alert`.
    The interactive console chat additionally sets `analyst_username` (the
    authenticated session identity — NEVER taken from the model's arguments) and
    `investigation` (the write-once record the chat is anchored to) so audited
    action tools can attribute and target their effects. Defaults keep the
    automated path byte-for-byte unchanged.
    """
    alert: WazuhAlert
    analyst_username: Optional[str] = None
    investigation: Optional[dict[str, Any]] = None


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]            # JSON-schema "properties" (excl. reason)
    handler: Callable[[dict, ToolContext], dict]
    required: list[str] = field(default_factory=list)

    def declaration(self) -> dict:
        props = dict(self.parameters)
        # A common, optional reason field captures *why* the model chose this tool.
        props["reason"] = {
            "type": "string",
            "description": "One short sentence: why you are calling this tool now.",
        }
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {"type": "object", "properties": props, "required": self.required},
        }


# The read-only registry the automated agent (run_agent) reads from. Its contents
# are the locked Phase-4 toolset; nothing new is added here (see INTERACTIVE_REGISTRY).
TOOL_REGISTRY: dict[str, Tool] = {}

# Interactive-only read tools (e.g. query_wazuh_logs). Deliberately SEPARATE from
# TOOL_REGISTRY so the automated agent's toolset stays unchanged; only the console
# chat loop merges this in.
INTERACTIVE_REGISTRY: dict[str, Tool] = {}


def register(tool: Tool) -> None:
    TOOL_REGISTRY[tool.name] = tool


def register_interactive(tool: Tool) -> None:
    """Register a read tool available ONLY to the interactive console chat."""
    INTERACTIVE_REGISTRY[tool.name] = tool


def build_declarations(registry: Optional[dict[str, "Tool"]] = None) -> list[dict]:
    reg = TOOL_REGISTRY if registry is None else registry
    return [t.declaration() for t in reg.values()]


def allowed_names(registry: Optional[dict[str, "Tool"]] = None) -> list[str]:
    reg = TOOL_REGISTRY if registry is None else registry
    return list(reg.keys())


def _size(obj: Any) -> int:
    return len(json.dumps(obj, default=str))


def cap_result(result: dict) -> dict:
    """Guard against oversized results. Prefers to DROP list items (preserving
    structure the model can use) over stringifying the whole result."""
    limit = get_settings().tool_max_result_chars
    if _size(result) <= limit:
        return result
    r = dict(result)
    list_keys = [k for k, v in r.items() if isinstance(v, list) and v]
    while _size(r) > limit and list_keys:
        # trim one item off the currently-largest list
        k = max(list_keys, key=lambda k: _size(r[k]) if isinstance(r[k], list) else 0)
        if not r[k]:
            list_keys.remove(k)
            continue
        r[k] = r[k][:-1]
        r["_truncated"] = True
    if _size(r) > limit:  # nothing trimmable; last-resort preview
        return {"_truncated": True, "preview": json.dumps(result, default=str)[:limit]}
    logger.info("Tool result trimmed to fit %d-char cap", limit)
    return r


def dispatch(name: str, args: dict, ctx: ToolContext,
             registry: Optional[dict[str, "Tool"]] = None) -> dict:
    """Run a tool by name. Returns a result dict; failures become {'error': ...}.

    `registry` defaults to TOOL_REGISTRY (the automated read-only path). The
    interactive chat passes its merged registry (read-only + query_wazuh_logs +
    audited action tools)."""
    reg = TOOL_REGISTRY if registry is None else registry
    tool = reg.get(name)
    if tool is None:  # defense-in-depth: the model can only name declared tools anyway
        return {"error": f"unknown tool '{name}'"}
    call_args = {k: v for k, v in args.items() if k != "reason"}
    try:
        result = tool.handler(call_args, ctx)
    except Exception as exc:  # noqa: BLE001 - one bad tool must not lose the alert
        logger.exception("Tool %s raised", name)
        return {"error": f"tool '{name}' failed: {exc}"}
    return cap_result(result)
