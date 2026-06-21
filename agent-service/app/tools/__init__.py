"""Tool package. Importing it registers every read-only tool into TOOL_REGISTRY.

The agent loop reads the registry to build Gemini declarations and dispatch calls.
To add a tool later: create a handler + register(Tool(...)) in a module imported here.
"""
from .netutil import extract_public_ips, is_public_ip  # re-exported for the agent
from .registry import (
    TOOL_REGISTRY,
    Tool,
    ToolContext,
    allowed_names,
    build_declarations,
    dispatch,
    register,
)
from .submit import SUBMIT_ANALYSIS, SUBMIT_DECLARATION

# Import side effects register the tools.
from . import virustotal  # noqa: E402,F401
from . import wazuh_indexer  # noqa: E402,F401
from . import memory_tool  # noqa: E402,F401

__all__ = [
    "TOOL_REGISTRY", "Tool", "ToolContext", "register", "build_declarations",
    "allowed_names", "dispatch", "SUBMIT_ANALYSIS", "SUBMIT_DECLARATION",
    "extract_public_ips", "is_public_ip",
]
