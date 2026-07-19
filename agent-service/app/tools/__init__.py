"""Tool package. Importing it registers every read-only tool into TOOL_REGISTRY.

This __init__.py runs automatically the first time anything does `import app.tools`.
A key Python trick is used here: simply importing a tool module (e.g. `from . import
virustotal`) runs that module top-to-bottom, and its register(Tool(...)) calls have the
side effect of filling the registries. So importing this package is what "wires up" the
whole toolset — no central list of tools to maintain.

The agent loop reads the registry to build the model's function declarations (its tool
menu) and to dispatch calls. To add a tool later: create a handler + register(Tool(...))
in a module, then make sure that module is imported here so its registration runs.
"""
# "Re-exporting": we import these names here so other code can simply do
# `from .tools import extract_public_ips` instead of reaching deep into the netutil
# submodule. It gives the package a clean, convenient public surface.
from .netutil import extract_public_ips, is_public_ip  # re-exported for the agent
# Pull in the core registry primitives: the two registries, the Tool/ToolContext
# dataclasses, and the helper functions the agent loop uses to build/dispatch tool calls.
from .registry import (
    INTERACTIVE_REGISTRY,
    TOOL_REGISTRY,
    Tool,
    ToolContext,
    allowed_names,
    build_declarations,
    dispatch,
    register,
    register_interactive,
)
# Bring in the terminal "submit_analysis" tool name/schema (not a data tool; ends the run).
from .submit import SUBMIT_ANALYSIS, SUBMIT_DECLARATION

# Import side effects register the tools. Each `from . import X` below is here purely
# to RUN that module so its register(...) calls execute. (The `noqa` comments silence
# linter warnings about an "unused import" — the import isn't unused, we want its side
# effect; E402 = import not at top of file, expected because of the ordering above.)
# Importing virustotal runs its register(...) calls, adding VT (VirusTotal file/URL
# reputation) lookups to TOOL_REGISTRY.
from . import virustotal  # noqa: E402,F401
# Importing wazuh_indexer registers both read-only log tools and the interactive query tool.
from . import wazuh_indexer  # noqa: E402,F401  (registers query_wazuh_logs -> INTERACTIVE_REGISTRY)
# Importing memory_tool registers the semantic "search_memory" tool.
from . import memory_tool  # noqa: E402,F401
# Importing case_history registers "search_past_investigations" — the agent's own case history.
from . import case_history  # noqa: E402,F401
# Importing console_lookup registers the read-only case-lookup tools for the console chat.
from . import console_lookup  # noqa: E402,F401  (registers case-lookup read tools -> INTERACTIVE_REGISTRY)
# Importing console_actions registers the audited, write-capable console-chat tools.
from . import console_actions  # noqa: E402,F401  (registers audited action tools -> ACTION_REGISTRY)
# Re-export the action registry itself so callers can access it via `from .tools import ACTION_REGISTRY`.
from .console_actions import ACTION_REGISTRY

# __all__ is Python's convention for a package's public API: it lists the names that
# `from .tools import *` will bring in, and documents which names are meant for outside
# use. Anything not listed is treated as an internal detail.
__all__ = [
    "TOOL_REGISTRY", "INTERACTIVE_REGISTRY", "ACTION_REGISTRY", "Tool", "ToolContext",
    "register", "register_interactive", "build_declarations",
    "allowed_names", "dispatch", "SUBMIT_ANALYSIS", "SUBMIT_DECLARATION",
    "extract_public_ips", "is_public_ip",
]
