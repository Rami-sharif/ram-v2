"""The read-only investigation agent (Phase 4).

BOUNDED TOOL CHOICE: the model freely picks which tools to call and in what order,
but only from the read-only registry (allowlist) — it cannot act. The loop is capped
at settings.agent_max_iterations; it ends when the model calls submit_analysis, and
if the cap is hit first we force a final submit so the alert is never dropped.

Output shape is LOCKED (Phase 1) so the Phase 3 triage router is unaffected.
"""
import json
import logging
from typing import Any

from google import genai
from google.genai import types

from . import tools
from .config import get_settings
from .schemas import AnalysisResult, WazuhAlert
from .tools import extract_public_ips

logger = logging.getLogger(__name__)

SYSTEM_INSTRUCTION = (
    "You are a SOC investigation analyst with READ-ONLY tools. Investigate the alert like "
    "an analyst: gather only the evidence that is RELEVANT to THIS alert's type, following "
    "suspicious leads. Be selective — do NOT call tools that are irrelevant (e.g. do not "
    "look up file hashes for a pure login/brute-force alert, and do not query user-login "
    "activity for a malware/file alert). Each tool call must include a short 'reason'. "
    "When you have enough evidence, call submit_analysis exactly once with your verdict. "
    "Let the Wazuh rule level and any malicious enrichment drive severity."
)

DEFAULT_MEMORY_CONTEXT = "No prior related alerts recorded for this host."


class AgentError(RuntimeError):
    pass


def _config(allowed: list[str]) -> types.GenerateContentConfig:
    declarations = tools.build_declarations() + [tools.SUBMIT_DECLARATION]
    return types.GenerateContentConfig(
        system_instruction=SYSTEM_INSTRUCTION,
        temperature=0.1,
        tools=[types.Tool(function_declarations=declarations)],
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(
                mode="ANY", allowed_function_names=allowed
            )
        ),
    )


def _first_function_call(response: Any):
    for cand in response.candidates or []:
        for part in (cand.content.parts or []) if cand.content else []:
            if getattr(part, "function_call", None):
                return part.function_call
    return None


def _build_prompt(alert: WazuhAlert, public_ips: list[str], memory_context: str) -> str:
    return (
        "Investigate this Wazuh alert and then submit your analysis.\n\n"
        f"Rule level: {alert.rule_level}\nDescription: {alert.description}\n"
        f"Rule id: {alert.rule.id}\nGroups: {alert.rule.groups}\n"
        f"Host (agent): {alert.agent.name}\n"
        f"Public IPs in alert: {public_ips or 'none'}\n"
        f"Source user: {(alert.data or {}).get('srcuser') or (alert.data or {}).get('dstuser') or 'none'}\n\n"
        "Prior related alerts on this host (auto-retrieved):\n"
        f"{memory_context}\n\n"
        "Full alert JSON:\n"
        f"{json.dumps(alert.model_dump(exclude_none=True), indent=2, default=str)}"
    )


def _fallback_analysis(alert: WazuhAlert) -> AnalysisResult:
    """Last-resort analysis so an alert is never dropped if the model won't submit."""
    score = min(alert.rule_level * 10, 100)
    label = ("critical" if score >= 80 else "high" if score >= 60
             else "medium" if score >= 40 else "low")
    return AnalysisResult(
        severity_score=score, severity_label=label, attack_type="unknown",
        mitre=[], summary="Auto-generated fallback: the agent did not submit an analysis.",
        recommended_action="Manual review required.",
    )


def run_agent(
    alert: WazuhAlert, memory_context: str = DEFAULT_MEMORY_CONTEXT
) -> tuple[AnalysisResult, dict[str, Any], list[dict[str, Any]]]:
    """Run the bounded investigation loop. Returns (analysis, evidence, tool_trace)."""
    settings = get_settings()
    client = genai.Client(api_key=settings.gemini_api_key)
    ctx = tools.ToolContext(alert=alert)
    public_ips = extract_public_ips(alert)

    contents: list[types.Content] = [
        types.Content(role="user",
                      parts=[types.Part(text=_build_prompt(alert, public_ips, memory_context))])
    ]
    all_allowed = tools.allowed_names() + [tools.SUBMIT_ANALYSIS]
    evidence: dict[str, Any] = {}
    trace: list[dict[str, Any]] = []

    for iteration in range(1, settings.agent_max_iterations + 1):
        response = client.models.generate_content(
            model=settings.gemini_model, contents=contents, config=_config(all_allowed)
        )
        fc = _first_function_call(response)
        if fc is None:
            logger.warning("Iteration %s: no function call; forcing submit", iteration)
            break

        if fc.name == tools.SUBMIT_ANALYSIS:
            try:
                analysis = AnalysisResult.model_validate(dict(fc.args))
            except Exception as exc:  # noqa: BLE001
                raise AgentError(f"submit_analysis invalid: {exc}") from exc
            logger.info("Investigation complete (iterations=%s, tools=%d): %s/%s (%s)",
                        iteration, len(trace), analysis.severity_label,
                        analysis.severity_score, analysis.attack_type)
            return analysis, evidence, trace

        # ---- a read-only tool call ----
        args = dict(fc.args)
        reason = args.get("reason", "")
        logger.info("AGENT tool_call alert=%s iter=%s tool=%s args=%s reason=%r",
                    alert.id, iteration, fc.name,
                    {k: v for k, v in args.items() if k != "reason"}, reason)
        result = tools.dispatch(fc.name, args, ctx)
        trace.append({"iteration": iteration, "tool": fc.name,
                      "args": {k: v for k, v in args.items() if k != "reason"},
                      "reason": reason, "error": result.get("error")})
        evidence[f"{iteration}:{fc.name}"] = result
        contents.append(response.candidates[0].content)
        contents.append(types.Content(role="user", parts=[
            types.Part.from_function_response(name=fc.name, response={"result": result})
        ]))

    # ---- cap hit / no submit: force a final analysis ----
    logger.warning("Cap reached without submit; forcing submit_analysis (alert=%s)", alert.id)
    response = client.models.generate_content(
        model=settings.gemini_model, contents=contents, config=_config([tools.SUBMIT_ANALYSIS])
    )
    fc = _first_function_call(response)
    if fc and fc.name == tools.SUBMIT_ANALYSIS:
        try:
            return AnalysisResult.model_validate(dict(fc.args)), evidence, trace
        except Exception:  # noqa: BLE001
            logger.exception("Forced submit invalid; using fallback analysis")
    return _fallback_analysis(alert), evidence, trace
