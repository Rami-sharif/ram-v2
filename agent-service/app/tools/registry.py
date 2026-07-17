"""Tool registry the agent loop reads from.

What is a "registry"? It's just a central dictionary that maps a tool's name to the
code that runs it. Modules "register" their tools into it at import time, and the
agent loop later looks tools up by name. This lets you add new tools without editing
the agent loop — the loop simply reads whatever is in the registry.

A "tool" here is a capability we expose to the language model (the LLM): the model
can't touch the database or network itself, so we describe a menu of functions it may
call. The model replies "call get_host_alert_history with host=web01", and we run the
matching Python handler and feed the result back to it.

Adding a tool later = define a handler function and call register(Tool(...)). The loop
builds the model's "function declarations" (the machine-readable menu of tools) from
this registry and dispatches calls by name. Every call goes through dispatch(), which
(a) strips the bookkeeping `reason` arg, (b) never lets an exception reach the loop
(graceful degradation — one broken tool must not abort the whole investigation), and
(c) size-caps the result so a noisy host can't blow up the prompt we send the model.
"""
# Used to measure the serialized size of tool results for the size-cap logic.
import json
# Standard library logging for dispatch/result-trimming diagnostics.
import logging
# @dataclass is a decorator that auto-generates boilerplate (like __init__) for a class
# whose main job is holding data — turning ToolContext/Tool into lightweight "structs".
# `field` lets a dataclass attribute have a computed default (see required= below).
from dataclasses import dataclass, field
# Typing helpers for handler signatures and optional fields.
from typing import Any, Callable, Optional

# Settings accessor: used to read the configurable tool-result size cap.
from ..config import get_settings
# The shared alert schema type, used to type-hint ToolContext.alert.
from ..schemas import WazuhAlert

# Module logger for this file.
logger = logging.getLogger(__name__)


# @dataclass here means we can write ToolContext(alert=...) and Python creates the
# constructor for us; the class is essentially a typed bag of shared values.
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
    # The Wazuh alert currently being investigated; always present.
    alert: WazuhAlert
    # Authenticated analyst's username in the console chat; None in the automated path.
    analyst_username: Optional[str] = None
    # The write-once investigation record the console chat is currently focused on.
    investigation: Optional[dict[str, Any]] = None


# One Tool object = one capability the model can call. It bundles the metadata the
# model sees (name/description/parameters) with the Python function that implements it.
@dataclass
class Tool:
    # Unique name the model uses to call this tool (must match the function declaration name).
    name: str
    # Natural-language description shown to the model to help it decide when to call this tool.
    description: str
    parameters: dict[str, Any]            # JSON-schema "properties" (excl. reason)
    # The handler: the actual Python function called as handler(args, ctx). Callable[...]
    # is a type hint meaning "a function taking (dict, ToolContext) and returning dict".
    handler: Callable[[dict, ToolContext], dict]
    # Names of parameters the model MUST supply. default_factory=list gives each Tool its
    # own fresh empty list (you can't use a plain [] default — it would be shared across
    # all instances, a classic Python gotcha). Empty means every parameter is optional.
    required: list[str] = field(default_factory=list)

    # A "method" (a function attached to the class) that renders this tool into the JSON
    # shape the model's API expects — its entry in the tool menu.
    def declaration(self) -> dict:
        # dict(...) makes a shallow copy so adding "reason" below doesn't mutate the
        # tool's own stored parameters dict.
        props = dict(self.parameters)
        # Inject a common, optional "reason" parameter into every tool so the model must
        # state *why* it's calling — useful for auditing and debugging its decisions.
        props["reason"] = {
            "type": "string",
            "description": "One short sentence: why you are calling this tool now.",
        }
        # Assemble the function-declaration object. "parameters" follows JSON Schema:
        # type "object" with named "properties" and a list of "required" ones — the
        # standard way to describe a function's arguments to an LLM.
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {"type": "object", "properties": props, "required": self.required},
        }


# The two module-level registries start empty and are filled as tool modules import.
# Keeping them separate is a deliberate security boundary: the automated agent can only
# ever see TOOL_REGISTRY, so extra/riskier tools can be given to the human chat alone.

# The read-only registry the automated agent (run_agent) reads from. Its contents
# are the locked Phase-4 toolset; nothing new is added here (see INTERACTIVE_REGISTRY).
TOOL_REGISTRY: dict[str, Tool] = {}

# Interactive-only read tools (e.g. query_wazuh_logs). Deliberately SEPARATE from
# TOOL_REGISTRY so the automated agent's toolset stays unchanged; only the console
# chat loop merges this in.
INTERACTIVE_REGISTRY: dict[str, Tool] = {}


def register(tool: Tool) -> None:
    # Add/overwrite this tool in the automated agent's registry, keyed by its name.
    # (Assigning to a dict key both inserts a new entry and replaces an existing one.)
    TOOL_REGISTRY[tool.name] = tool


def register_interactive(tool: Tool) -> None:
    """Register a read tool available ONLY to the interactive console chat."""
    # Add/overwrite this tool in the interactive-only registry, keyed by its name.
    INTERACTIVE_REGISTRY[tool.name] = tool


# Optional[dict] means the argument may be a dict OR None; the "Tool" in quotes is a
# forward reference (the name is fine even though used in a type hint like this).
def build_declarations(registry: Optional[dict[str, "Tool"]] = None) -> list[dict]:
    # Default to the automated registry unless a specific one (e.g. merged interactive) is passed.
    reg = TOOL_REGISTRY if registry is None else registry
    # A list comprehension: call .declaration() on every registered Tool to produce the
    # full menu of function declarations handed to the model.
    return [t.declaration() for t in reg.values()]


def allowed_names(registry: Optional[dict[str, "Tool"]] = None) -> list[str]:
    # Default to the automated registry unless a specific one is passed.
    reg = TOOL_REGISTRY if registry is None else registry
    # Return just the tool names, e.g. for validating that a model-requested call is legal.
    return list(reg.keys())


def _size(obj: Any) -> int:
    # Measure how big a result is by serializing it to a JSON string and counting
    # characters. default=str tells json how to handle types it can't natively encode
    # (e.g. datetimes) by falling back to str(), so this never raises on odd values.
    return len(json.dumps(obj, default=str))


def cap_result(result: dict) -> dict:
    """Guard against oversized results so we don't overflow the model's prompt.

    Why this matters: everything we send the model costs "tokens" and there's a hard
    limit, so a single huge tool result could crowd out the rest of the conversation.
    Rather than blindly truncate text, this prefers to DROP whole list items — keeping
    the JSON structure valid and usable — and only falls back to a raw string preview
    if nothing else works."""
    # Configurable maximum size (in characters) a tool result may occupy in the prompt.
    limit = get_settings().tool_max_result_chars
    if _size(result) <= limit:
        # Already within budget; return unchanged (the common, fast path).
        return result
    # Work on a shallow copy so we don't mutate the caller's original result dict.
    r = dict(result)
    # Find the top-level keys whose value is a non-empty list — these are the only
    # things we can safely shrink by dropping items. `isinstance(v, list) and v`
    # is true only for lists with at least one element.
    list_keys = [k for k, v in r.items() if isinstance(v, list) and v]
    # Keep dropping items until we're under the limit or have nothing left to trim.
    while _size(r) > limit and list_keys:
        # Pick the list currently taking the most space. max(..., key=<fn>) returns the
        # item scoring highest under the function; the lambda measures each list's size.
        k = max(list_keys, key=lambda k: _size(r[k]) if isinstance(r[k], list) else 0)
        if not r[k]:
            # This list is now empty; stop considering it for further trimming.
            list_keys.remove(k)
            continue
        # r[k][:-1] is "all elements except the last", i.e. drop one item to shrink it.
        r[k] = r[k][:-1]
        # Flag that truncation happened so the model/analyst knows the result is partial.
        r["_truncated"] = True
    if _size(r) > limit:  # nothing trimmable; last-resort preview
        # Even after emptying every list it's still too big (e.g. a giant non-list field):
        # give up on structure and return a hard-capped string preview of the original.
        return {"_truncated": True, "preview": json.dumps(result, default=str)[:limit]}
    # Log at info level so oversized-result trimming is visible in operational logs.
    logger.info("Tool result trimmed to fit %d-char cap", limit)
    return r


def dispatch(name: str, args: dict, ctx: ToolContext,
             registry: Optional[dict[str, "Tool"]] = None) -> dict:
    """Run a tool by name. Returns a result dict; failures become {'error': ...}.

    `registry` defaults to TOOL_REGISTRY (the automated read-only path). The
    interactive chat passes its merged registry (read-only + query_wazuh_logs +
    audited action tools)."""
    # Default to the automated registry unless a merged/custom one is supplied.
    reg = TOOL_REGISTRY if registry is None else registry
    # Look up the requested tool by name; .get returns None if it's not in this registry.
    tool = reg.get(name)
    if tool is None:  # defense-in-depth: the model can only name declared tools anyway
        # Unknown tool name; return a structured error instead of raising so the loop
        # can show the model its mistake and carry on.
        return {"error": f"unknown tool '{name}'"}
    # Rebuild the args without the bookkeeping "reason" key (it's metadata for us, not a
    # real parameter the handler expects). This is a dict comprehension filtering keys.
    call_args = {k: v for k, v in args.items() if k != "reason"}
    try:
        # Actually invoke the tool's handler with the cleaned args and shared context.
        result = tool.handler(call_args, ctx)
    except Exception as exc:  # noqa: BLE001 - one bad tool must not lose the alert
        # Catch EVERY exception on purpose ("graceful degradation"): a bug in one tool
        # must never crash the whole investigation. logger.exception records the full
        # traceback for debugging while we return a tidy error to the model.
        logger.exception("Tool %s raised", name)
        return {"error": f"tool '{name}' failed: {exc}"}
    # Apply the size cap before returning the result to the agent loop/prompt.
    return cap_result(result)
