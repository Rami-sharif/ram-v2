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
    "Let the Wazuh rule level and any malicious enrichment drive severity. "
    "If the prior related alerts include a human decision (marked ANALYST-CORRECTED or "
    "ANALYST-CONFIRMED), treat that analyst verdict as authoritative ground truth for "
    "closely similar alerts: align your severity_label, severity_score and attack_type "
    "with it unless THIS alert clearly differs, and say so in your summary."
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


# --------------------------------------------------------------------------- #
# Dashboard-level interactive chat (Phase 6, console only).
#
# Reuses the bounded tool-choice loop, but: (a) allowed tools = read-only
# registry + query_wazuh_logs + case-lookup tools + audited action tools;
# (b) NO submit_analysis — the loop ends when the model responds in text with no
# tool call; (c) it can ACT (audited) because the analyst's identity rides in the
# ToolContext; (d) NO case is preloaded — the assistant looks up any case the
# analyst names via get_investigation_by_case_number, which also focuses the
# context so a same-turn action targets that case. run_agent is untouched.
# --------------------------------------------------------------------------- #
INTERACTIVE_SYSTEM_INSTRUCTION = (
    "You are a SOC analyst's assistant embedded in the RAM v2 console dashboard. The analyst "
    "chats with you freely and may ask about ANY case by its TheHive case number, compare cases, "
    "or ask general investigation questions. NO case is preloaded for you. "
    "When the analyst references a case (e.g. 'case 13'), call get_investigation_by_case_number to "
    "pull its stored details (severity, source IP, rule, attack type, analysis) before answering — "
    "for a comparison like 'is the IP for case 13 and 14 the same', look each one up and compare. "
    "To check whether an IP or file hash appeared in other cases, use "
    "search_investigations_by_indicator. Use query_wazuh_logs for custom Wazuh log filters/counts. "
    "You may also take a small set of AUDITED actions — record a verdict confirm/override, record "
    "triage feedback, and close / set-severity / comment on a TheHive case — but ONLY on a case you "
    "have just looked up in THIS turn with get_investigation_by_case_number, and ONLY when the "
    "analyst clearly asks. Always look the case up again in the current turn before acting on it, "
    "even if it was discussed earlier. Confirm what you did. Every action is attributed to the "
    "logged-in analyst and audited automatically. Each tool call must include a short 'reason'. "
    "When you have nothing left to do, reply in plain text (no tool call) and the turn ends."
)


def _first_text(response: Any) -> str:
    parts: list[str] = []
    for cand in response.candidates or []:
        for part in (cand.content.parts or []) if cand.content else []:
            if getattr(part, "text", None):
                parts.append(part.text)
    return "\n".join(parts).strip()


def _interactive_config(registry: dict) -> types.GenerateContentConfig:
    """AUTO mode: the model may call an allowed tool OR reply with text (ending the turn)."""
    declarations = tools.build_declarations(registry)
    return types.GenerateContentConfig(
        system_instruction=INTERACTIVE_SYSTEM_INSTRUCTION,
        temperature=0.2,
        tools=[types.Tool(function_declarations=declarations)],
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(mode="AUTO")
        ),
    )


def _text_only_config() -> types.GenerateContentConfig:
    return types.GenerateContentConfig(
        system_instruction=INTERACTIVE_SYSTEM_INSTRUCTION, temperature=0.2
    )


def _collect_referenced(result: Any, acc: list[int]) -> None:
    """Accumulate alert_investigations.id values a chat turn touched, so the stored
    agent message can link them. Reads the compact shapes returned by the two
    case-lookup tools (a single investigation_id, or a matches[] list)."""
    if not isinstance(result, dict):
        return
    iid = result.get("investigation_id")
    if isinstance(iid, int) and iid not in acc:
        acc.append(iid)
    for m in result.get("matches") or []:
        mid = m.get("investigation_id") if isinstance(m, dict) else None
        if isinstance(mid, int) and mid not in acc:
            acc.append(mid)


def _focus_preamble(inv: dict[str, Any]) -> str:
    """Console-supplied context for a chat started from an investigation page: the
    record the analyst is looking at right now. Stated as context, not as an
    instruction — an unqualified 'this alert' / 'this case' means this one."""
    analysis = inv.get("analysis") or {}
    lines = [
        "[console context] The analyst is currently viewing this investigation and, unless they "
        "clearly name another case, their question is about it:",
        f"- investigation_id: {inv.get('id')}",
        f"- case_number: {inv.get('case_number') or 'none (no TheHive case)'}",
        f"- alert_id: {inv.get('alert_id') or '—'}",
        f"- host: {inv.get('agent_name') or '—'}  source_ip: {inv.get('source_ip') or '—'}"
        f"  rule: {inv.get('rule_id') or '—'}",
        f"- agent verdict: {inv.get('severity_label') or '—'} "
        f"(score {inv.get('severity_score')}), attack type: {inv.get('attack_type') or '—'}",
        f"- triage: {inv.get('triage_action') or '—'}",
        f"- summary: {analysis.get('summary') or '—'}",
    ]
    if inv.get("case_number"):
        lines.append("Before taking any audited action on it, look it up in THIS turn with "
                     f"get_investigation_by_case_number(case_number={inv['case_number']}).")
    return "\n".join(lines)


def run_interactive(
    message: str, analyst_username: str, history: list[dict] | None = None,
    focus_investigation: dict[str, Any] | None = None,
) -> tuple[str, list[dict[str, Any]], list[int]]:
    """Run one dashboard chat turn. Returns (reply_text, tool_calls, referenced_ids).

    `focus_investigation` is the record the analyst is chatting FROM (the console
    passes it when the dock is opened on an investigation page); it anchors the turn
    so "is this a real threat?" needs no case number. When absent, no case is
    anchored up front and the assistant looks up any case the analyst names via
    get_investigation_by_case_number, which also focuses ctx.investigation so a
    same-turn audited action targets that case. `history` is the prior conversation
    as [{role: 'analyst'|'agent', message}]. Actions taken here go through the same
    audited tool functions, so every consequential action still produces its own
    audit_log row. `referenced_ids` are the investigation ids this turn discussed."""
    settings = get_settings()
    client = genai.Client(api_key=settings.gemini_api_key)
    # Focus the anchored case (if any) and an empty alert; the case-lookup tool
    # re-focuses ctx.investigation when the analyst references a different case.
    # Identity is fixed to the authenticated session — never taken from the model.
    ctx = tools.ToolContext(
        alert=WazuhAlert(), analyst_username=analyst_username,
        investigation=focus_investigation,
    )
    registry = {**tools.TOOL_REGISTRY, **tools.INTERACTIVE_REGISTRY, **tools.ACTION_REGISTRY}

    contents: list[types.Content] = []
    for h in history or []:
        role = "user" if h.get("role") == "analyst" else "model"
        contents.append(types.Content(role=role, parts=[types.Part(text=h.get("message") or "")]))
    if focus_investigation:
        # Sent alongside this turn only, so the anchor follows the page the analyst
        # is on rather than sticking to the conversation forever.
        contents.append(types.Content(
            role="user", parts=[types.Part(text=_focus_preamble(focus_investigation))]))
    contents.append(types.Content(role="user", parts=[types.Part(text=message)]))

    tool_calls: list[dict[str, Any]] = []
    referenced: list[int] = [focus_investigation["id"]] if focus_investigation else []

    for iteration in range(1, settings.agent_max_iterations + 1):
        response = client.models.generate_content(
            model=settings.gemini_model, contents=contents, config=_interactive_config(registry)
        )
        fc = _first_function_call(response)
        if fc is None:  # model replied with text -> turn ends
            return (_first_text(response) or "(no response)"), tool_calls, referenced

        args = dict(fc.args)
        reason = args.get("reason", "")
        logger.info("CHAT tool_call analyst=%s iter=%s tool=%s args=%s reason=%r",
                    analyst_username, iteration, fc.name,
                    {k: v for k, v in args.items() if k != "reason"}, reason)
        result = tools.dispatch(fc.name, args, ctx, registry=registry)
        _collect_referenced(result, referenced)
        tool_calls.append({"iteration": iteration, "tool": fc.name,
                           "args": {k: v for k, v in args.items() if k != "reason"},
                           "reason": reason, "error": result.get("error"),
                           "ok": result.get("ok", result.get("error") is None)})
        contents.append(response.candidates[0].content)
        contents.append(types.Content(role="user", parts=[
            types.Part.from_function_response(name=fc.name, response={"result": result})
        ]))

    # Cap reached while still calling tools: force a closing text summary.
    logger.info("CHAT cap reached (analyst=%s); requesting closing text", analyst_username)
    response = client.models.generate_content(
        model=settings.gemini_model, contents=contents, config=_text_only_config()
    )
    return (_first_text(response) or "(reached tool limit for this turn)"), tool_calls, referenced
