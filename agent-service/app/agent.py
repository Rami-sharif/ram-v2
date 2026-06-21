"""The triage agent.

The LLM (Gemini) reasons over the Wazuh alert, but the *tool order is fixed* by
us — we do not let the model freely choose tools. The fixed plan is:

    1. (optional) virustotal_ip_lookup  — enrich a public IP, if the alert has one
    2. submit_analysis                  — emit the structured triage verdict

Each step is forced via tool_config (mode=ANY + allowed_function_names), so the
model only decides *arguments* (e.g. which IP), never *whether/which* tool to use.
The loop is bounded by settings.agent_max_iterations.
"""
import json
import logging
from typing import Any

from google import genai
from google.genai import types

from .config import get_settings
from .schemas import AnalysisResult, WazuhAlert
from .tools import extract_public_ips, virustotal_ip_lookup

logger = logging.getLogger(__name__)

SYSTEM_INSTRUCTION = (
    "You are a SOC Tier-1 triage analyst. You analyze a single Wazuh alert and "
    "produce a concise, structured verdict. Let the Wazuh rule level guide severity "
    "(higher level = more severe). Use any VirusTotal enrichment provided: a "
    "malicious/suspicious public IP should raise severity and confidence. Map the "
    "activity to MITRE ATT&CK where reasonable. Be specific and actionable. "
    "When asked to submit your analysis, call submit_analysis exactly once."
)

# ---- Tool / function declarations -------------------------------------------
VT_TOOL = {
    "name": "virustotal_ip_lookup",
    "description": (
        "Look up the reputation of a single public IPv4 address on VirusTotal. "
        "Choose the most security-relevant IP from the alert (usually the external "
        "source of the activity). Private/local IPs are skipped automatically."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "Public IPv4 to look up"},
        },
        "required": ["ip"],
    },
}

SUBMIT_TOOL = {
    "name": "submit_analysis",
    "description": "Submit the final structured triage analysis for this alert.",
    "parameters": {
        "type": "object",
        "properties": {
            "severity_score": {
                "type": "integer",
                "description": "Overall severity from 0 (benign) to 100 (critical).",
            },
            "severity_label": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
            },
            "attack_type": {
                "type": "string",
                "description": "Short label, e.g. 'brute force', 'port scan', 'malware c2'.",
            },
            "mitre": {
                "type": "array",
                "description": "MITRE ATT&CK mappings.",
                "items": {
                    "type": "object",
                    "properties": {
                        "tactic": {"type": "string"},
                        "technique": {"type": "string"},
                        "technique_id": {"type": "string", "description": "e.g. T1110"},
                    },
                    "required": ["technique_id"],
                },
            },
            "summary": {"type": "string", "description": "2-4 sentence analyst summary."},
            "recommended_action": {
                "type": "string",
                "description": "Concrete next step for the analyst.",
            },
        },
        "required": [
            "severity_score",
            "severity_label",
            "attack_type",
            "summary",
            "recommended_action",
        ],
    },
}


class AgentError(RuntimeError):
    """Raised when the agent cannot produce a valid analysis."""


def _forced_config(allowed: list[str]) -> types.GenerateContentConfig:
    return types.GenerateContentConfig(
        system_instruction=SYSTEM_INSTRUCTION,
        temperature=0.1,
        tools=[types.Tool(function_declarations=[VT_TOOL, SUBMIT_TOOL])],
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(
                mode="ANY", allowed_function_names=allowed
            )
        ),
    )


def _first_function_call(response: Any):
    candidates = response.candidates or []
    if not candidates:
        return None
    for part in candidates[0].content.parts or []:
        if getattr(part, "function_call", None):
            return part.function_call
    return None


def _build_prompt(alert: WazuhAlert, public_ips: list[str], memory_context: str) -> str:
    alert_json = alert.model_dump(exclude_none=True)
    return (
        "Analyze this Wazuh alert.\n\n"
        f"Rule level: {alert.rule_level}\n"
        f"Description: {alert.description}\n"
        f"Public IPs found in alert: {public_ips or 'none'}\n\n"
        "Prior related alerts on THIS host (most relevant first). Use them to spot "
        "repeat offenders, returning source IPs, and multi-step attack chains; an alert "
        "that recurs or matches a known-bad pattern should raise severity/confidence:\n"
        f"{memory_context}\n\n"
        "Full alert JSON:\n"
        f"{json.dumps(alert_json, indent=2, default=str)}"
    )


def run_agent(
    alert: WazuhAlert, memory_context: str = "No prior related alerts recorded for this host."
) -> tuple[AnalysisResult, dict[str, Any]]:
    """Run the bounded, fixed-order agent loop. Returns (analysis, enrichment)."""
    settings = get_settings()
    client = genai.Client(api_key=settings.gemini_api_key)

    public_ips = extract_public_ips(alert)
    enrichment: dict[str, Any] = {}

    contents: list[types.Content] = [
        types.Content(
            role="user",
            parts=[types.Part(text=_build_prompt(alert, public_ips, memory_context))],
        )
    ]

    # Fixed plan. VT step is included only when there's a public IP to enrich.
    vt_pending = bool(public_ips)

    for iteration in range(1, settings.agent_max_iterations + 1):
        allowed = ["virustotal_ip_lookup"] if vt_pending else ["submit_analysis"]
        logger.info("Agent iteration %s: forcing %s", iteration, allowed[0])

        response = client.models.generate_content(
            model=settings.gemini_model,
            contents=contents,
            config=_forced_config(allowed),
        )
        fc = _first_function_call(response)
        if fc is None:
            raise AgentError(f"Gemini returned no function call on iteration {iteration}")

        if fc.name == "virustotal_ip_lookup":
            ip = dict(fc.args).get("ip", "")
            result = virustotal_ip_lookup(ip)
            enrichment[ip] = result
            contents.append(response.candidates[0].content)
            contents.append(
                types.Content(
                    role="user",
                    parts=[
                        types.Part.from_function_response(
                            name=fc.name, response={"result": result}
                        )
                    ],
                )
            )
            vt_pending = False  # Phase 1: a single enrichment, then analyze.
            continue

        if fc.name == "submit_analysis":
            try:
                analysis = AnalysisResult.model_validate(dict(fc.args))
            except Exception as exc:  # noqa: BLE001 - surface validation issues
                raise AgentError(f"submit_analysis returned invalid data: {exc}") from exc
            logger.info(
                "Analysis complete: %s/%s (%s)",
                analysis.severity_label, analysis.severity_score, analysis.attack_type,
            )
            return analysis, enrichment

        raise AgentError(f"Unexpected function call: {fc.name}")

    raise AgentError("Agent exceeded max iterations without producing an analysis")
