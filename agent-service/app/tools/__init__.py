"""Tool package. Importing it registers every read-only tool into TOOL_REGISTRY.

The agent loop reads the registry to build Gemini declarations and dispatch calls.
To add a tool later: create a handler + register(Tool(...)) in a module imported here.
"""
from .netutil import extract_public_ips, is_public_ip  # re-exported for the agent
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
from .submit import SUBMIT_ANALYSIS, SUBMIT_DECLARATION

# Import side effects register the tools.
from . import virustotal  # noqa: E402,F401
from . import wazuh_indexer  # noqa: E402,F401  (registers query_wazuh_logs -> INTERACTIVE_REGISTRY)
from . import memory_tool  # noqa: E402,F401
from . import console_lookup  # noqa: E402,F401  (registers case-lookup read tools -> INTERACTIVE_REGISTRY)
from . import console_actions  # noqa: E402,F401  (registers audited action tools -> ACTION_REGISTRY)
from .console_actions import ACTION_REGISTRY

__all__ = [
    "TOOL_REGISTRY", "INTERACTIVE_REGISTRY", "ACTION_REGISTRY", "Tool", "ToolContext",
    "register", "register_interactive", "build_declarations",
    "allowed_names", "dispatch", "SUBMIT_ANALYSIS", "SUBMIT_DECLARATION",
    "extract_public_ips", "is_public_ip",
]
