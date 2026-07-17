"""The read-only investigation agent (Phase 4).

WHAT THIS FILE IS, FOR A NEWCOMER:
An "LLM agent" is a large language model (here Google's Gemini) that we let run in a
loop and give a set of "tools" it can call. This is called "function calling" (or
"tool use"): instead of just chatting, the model can ask us to run a specific function
(e.g. "look up this IP") and then read the result before deciding its next step. We run
that loop ourselves — the model only decides WHICH tool to call and with WHAT arguments;
our code actually executes the tool and feeds the answer back. The model keeps
investigating until it decides it has enough evidence, then calls a special
`submit_analysis` tool to hand back its final verdict.

BOUNDED TOOL CHOICE: the model freely picks which tools to call and in what order,
but only from the read-only registry (an "allowlist" — a fixed set of permitted
functions) — it cannot act (no changing/deleting anything). Keeping the investigator
read-only means a mistaken or manipulated model can never damage systems; the worst it
can do is read data. The loop is capped at settings.agent_max_iterations (an "iteration
cap" — a hard limit on how many back-and-forth tool steps we allow, so a confused model
can't loop forever and run up cost); it ends when the model calls submit_analysis, and
if the cap is hit first we force a final submit so the alert is never dropped.

Output shape is LOCKED (Phase 1) so the Phase 3 triage router is unaffected. ("Locked"
means the fields and format of the result must not change, because other parts of the
system depend on exactly that shape.)
"""
import json  # used to serialize the alert payload into the model prompt
import logging  # stdlib logging for tool-call and decision tracing
from typing import Any  # loose typing for API response objects

from google import genai  # Gemini SDK client
from google.genai import types  # Gemini SDK request/response type constructors

from . import tools  # read-only + action tool registries and dispatcher
from .config import get_settings  # accessor for model name, API key, iteration cap
from .schemas import AnalysisResult, WazuhAlert  # typed models for the agent's output and input alert
from .tools import extract_public_ips  # helper to pull public IPs out of an alert for the prompt

logger = logging.getLogger(__name__)  # module logger

# The "system prompt" (a.k.a. system instruction) is a block of text we give the model
# BEFORE the user's message. It sets the model's role, rules, and tone for the whole
# conversation — think of it as the standing job description the model must always obey.
# Here it tells Gemini to behave like a careful SOC (Security Operations Center) analyst,
# use only relevant tools, respect analyst corrections, and explain findings in plain English.
# System prompt for the bounded read-only investigation loop (run_agent)
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
    "with it unless THIS alert clearly differs, and say so in your summary. "
    "Write the summary and recommended_action in very simple, plain English so a "
    "non-expert can follow. Use short sentences and everyday words. Keep only the "
    "well-known security terms (e.g. severity, MITRE, brute force, ransomware, IP, "
    "hash); avoid rare jargon, and briefly explain any term you must use."
)

DEFAULT_MEMORY_CONTEXT = "No prior related alerts recorded for this host."  # used when no memory retrieval was done


class AgentError(RuntimeError):
    # Raised when the model's submit_analysis call can't be parsed into AnalysisResult
    pass


def _config(allowed: list[str]) -> types.GenerateContentConfig:
    # Build the Gemini generation config for the bounded investigation loop.
    # The "config" bundles everything we send with each request: the system prompt,
    # the list of tools the model is allowed to call, and settings like temperature.
    # A "declaration" is a machine-readable description (name + arguments + what it does)
    # of one tool, so the model knows what functions exist and how to call them.
    declarations = tools.build_declarations() + [tools.SUBMIT_DECLARATION]  # read-only tool schemas + the submit tool
    return types.GenerateContentConfig(
        system_instruction=SYSTEM_INSTRUCTION,
        # "Temperature" controls randomness/creativity. 0.0 is the most focused and
        # repeatable; higher values give more varied wording. We keep it low here so the
        # investigation behaves consistently and predictably run to run.
        temperature=0.1,  # low temperature: favor consistent, deterministic-ish investigation behavior
        tools=[types.Tool(function_declarations=declarations)],
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(
                # mode="ANY" forces the model to respond with a tool call (not free text) and
                # restricts it to `allowed_function_names`. This is how we keep the agent
                # "bounded": it literally cannot call anything outside the allowlist.
                mode="ANY", allowed_function_names=allowed  # ANY = model must call one of the allowed functions
            )
        ),
    )


def _first_function_call(response: Any):
    # A Gemini response is structured, not a plain string: it contains one or more
    # "candidates" (possible answers), each made of "parts" (chunks that are either text
    # or a function_call). This helper digs through that structure to find the tool call.
    # Scan all candidates/parts for the first function call the model made (there should be exactly one per turn)
    for cand in response.candidates or []:
        for part in (cand.content.parts or []) if cand.content else []:
            if getattr(part, "function_call", None):
                return part.function_call  # return as soon as one is found
    return None  # no function call in this response (model replied with plain text instead)


def _build_prompt(alert: WazuhAlert, public_ips: list[str], memory_context: str) -> str:
    # Compose the user-turn prompt: key alert fields up front, then prior memory, then the full raw alert JSON.
    # `memory_context` is the "RAG" part — Retrieval-Augmented Generation. RAG means we
    # first RETRIEVE relevant past information (here, similar past alerts on this host from
    # the semantic-memory layer in memory.py) and paste it into the prompt, so the model
    # can ground its answer in real history instead of guessing from general knowledge.
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
    """Last-resort analysis so an alert is never dropped if the model won't submit.

    LLMs can occasionally misbehave (refuse, error out, or return something invalid).
    Rather than lose the alert, we synthesize a simple, rule-based verdict from the raw
    Wazuh severity so a human still gets something to review. This is a safety net, not
    the normal path."""
    score = min(alert.rule_level * 10, 100)  # derive a rough score from the Wazuh rule level, capped at 100
    # Bucket the derived score into a severity label using the same thresholds conceptually used elsewhere
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
    """Run the bounded investigation loop. Returns (analysis, evidence, tool_trace).

    This is the heart of the agent. In plain terms it does: build a prompt describing the
    alert -> repeatedly ask Gemini for its next tool call -> run that read-only tool and
    feed the result back -> stop when the model submits its verdict (or when we hit the
    iteration cap and force it to conclude). `evidence` is every raw tool result gathered;
    `tool_trace` is a human-readable log of which tools were called and why."""
    settings = get_settings()  # current app settings (model name, API key, iteration cap)
    client = genai.Client(api_key=settings.gemini_api_key)  # Gemini client for this run
    ctx = tools.ToolContext(alert=alert)  # tool execution context scoped to this alert
    public_ips = extract_public_ips(alert)  # pre-extract public IPs to surface in the prompt

    # Seed the conversation with a single user turn containing the investigation prompt
    contents: list[types.Content] = [
        types.Content(role="user",
                      parts=[types.Part(text=_build_prompt(alert, public_ips, memory_context))])
    ]
    all_allowed = tools.allowed_names() + [tools.SUBMIT_ANALYSIS]  # read-only tools plus the submit action
    evidence: dict[str, Any] = {}  # accumulated tool results keyed by "iteration:tool_name"
    trace: list[dict[str, Any]] = []  # human/audit-readable record of each tool call made

    # Each pass of this loop is one "turn": we send the whole conversation so far and get
    # back the model's next move. `agent_max_iterations` caps how many turns we allow so
    # the loop always terminates. `contents` grows every turn — the model has no memory
    # between API calls, so we must resend the full history each time for it to "remember".
    for iteration in range(1, settings.agent_max_iterations + 1):
        # Ask the model for its next action (a tool call), constrained to the allowed set
        response = client.models.generate_content(
            model=settings.gemini_model, contents=contents, config=_config(all_allowed)
        )
        fc = _first_function_call(response)  # extract the function call the model chose
        if fc is None:
            # Model didn't call a function at all (shouldn't normally happen under mode="ANY") — bail to forced submit
            logger.warning("Iteration %s: no function call; forcing submit", iteration)
            break

        if fc.name == tools.SUBMIT_ANALYSIS:
            try:
                # Validate the model's submitted analysis against the locked schema
                analysis = AnalysisResult.model_validate(dict(fc.args))
            except Exception as exc:  # noqa: BLE001
                # Any validation failure is fatal here — the caller must handle AgentError
                raise AgentError(f"submit_analysis invalid: {exc}") from exc
            logger.info("Investigation complete (iterations=%s, tools=%d): %s/%s (%s)",
                        iteration, len(trace), analysis.severity_label,
                        analysis.severity_score, analysis.attack_type)
            return analysis, evidence, trace  # success path: return immediately

        # ---- a read-only tool call ----
        args = dict(fc.args)  # copy the model-supplied arguments
        reason = args.get("reason", "")  # the model's stated justification for this call
        # Log the tool call (excluding the reason from the args dict since it's logged separately)
        logger.info("AGENT tool_call alert=%s iter=%s tool=%s args=%s reason=%r",
                    alert.id, iteration, fc.name,
                    {k: v for k, v in args.items() if k != "reason"}, reason)
        # `dispatch` looks up the named tool in the registry and runs it. This is OUR code
        # executing the function the model requested — the model itself never runs anything.
        result = tools.dispatch(fc.name, args, ctx)  # actually execute the read-only tool
        # Record this step in the trace for later display/audit
        trace.append({"iteration": iteration, "tool": fc.name,
                      "args": {k: v for k, v in args.items() if k != "reason"},
                      "reason": reason, "error": result.get("error")})
        evidence[f"{iteration}:{fc.name}"] = result  # store the raw result for building the case description later
        # We now grow the conversation with two things so the next turn has full context:
        # (1) the model's own message (its function_call), and (2) the tool's answer.
        contents.append(response.candidates[0].content)  # append the model's turn (including its function call)
        # A "function response" is the standard way to hand a tool's output back to the
        # model. On the next turn the model reads this result and decides what to do next.
        # Append the tool's result as a function-response turn so the model can see it on the next iteration
        contents.append(types.Content(role="user", parts=[
            types.Part.from_function_response(name=fc.name, response={"result": result})
        ]))

    # ---- cap hit / no submit: force a final analysis ----
    # If we get here the model used up all its allowed turns without concluding. We make one
    # more request with ONLY submit_analysis allowed, forcing it to hand back a verdict now.
    logger.warning("Cap reached without submit; forcing submit_analysis (alert=%s)", alert.id)
    # One last call, this time only allowing submit_analysis so the model is forced to conclude
    response = client.models.generate_content(
        model=settings.gemini_model, contents=contents, config=_config([tools.SUBMIT_ANALYSIS])
    )
    fc = _first_function_call(response)
    if fc and fc.name == tools.SUBMIT_ANALYSIS:
        try:
            return AnalysisResult.model_validate(dict(fc.args)), evidence, trace  # forced submit succeeded
        except Exception:  # noqa: BLE001
            # Even the forced submit was invalid — fall through to the hardcoded fallback
            logger.exception("Forced submit invalid; using fallback analysis")
    # Absolute last resort: synthesize an analysis from the rule level so the alert is never dropped
    return _fallback_analysis(alert), evidence, trace


# --------------------------------------------------------------------------- #
# Dashboard-level interactive chat (Phase 6, console only).
#
# This is a second, chat-style use of the same tool loop, for a human analyst talking to
# the assistant in the dashboard. The big differences from run_agent above: the analyst
# converses freely, and the assistant is allowed to take a few real ("audited") actions —
# but every action is attributed to the logged-in analyst and recorded, and the model can
# only act on a case it just looked up this turn. "Audited" means each consequential action
# writes an audit-log entry, so there's always a record of who did what.
#
# Reuses the bounded tool-choice loop, but: (a) allowed tools = read-only
# registry + query_wazuh_logs + case-lookup tools + audited action tools;
# (b) NO submit_analysis — the loop ends when the model responds in text with no
# tool call; (c) it can ACT (audited) because the analyst's identity rides in the
# ToolContext; (d) NO case is preloaded — the assistant looks up any case the
# analyst names via get_investigation_by_case_number, which also focuses the
# context so a same-turn action targets that case. run_agent is untouched.
# --------------------------------------------------------------------------- #
# System prompt for the interactive console chat (different capabilities/constraints than run_agent)
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
    "When you have nothing left to do, reply in plain text (no tool call) and the turn ends. "
    "Reply in very simple, plain English with short sentences and everyday words, so a "
    "non-expert can follow. Keep only well-known security terms (severity, MITRE, brute force, "
    "ransomware, IP, hash) and avoid rare jargon; briefly explain any term you must use."
)


def _first_text(response: Any) -> str:
    # Collect all plain-text parts from the response (across candidates) into one string
    parts: list[str] = []
    for cand in response.candidates or []:
        for part in (cand.content.parts or []) if cand.content else []:
            if getattr(part, "text", None):
                parts.append(part.text)
    return "\n".join(parts).strip()  # join multi-part text responses with newlines, trim whitespace


def _interactive_config(registry: dict) -> types.GenerateContentConfig:
    """AUTO mode: the model may call an allowed tool OR reply with text (ending the turn).

    Contrast with run_agent's mode="ANY" (which FORCES a tool call every turn). Here a chat
    should be able to just answer the analyst in words when no tool is needed, so we use
    "AUTO": the model itself decides between calling a tool and replying with plain text."""
    declarations = tools.build_declarations(registry)  # build tool schemas from the merged registry passed in
    return types.GenerateContentConfig(
        system_instruction=INTERACTIVE_SYSTEM_INSTRUCTION,
        temperature=0.2,  # slightly higher than run_agent since this is a conversational assistant
        tools=[types.Tool(function_declarations=declarations)],
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(mode="AUTO")  # AUTO: model may choose to reply in text instead
        ),
    )


def _text_only_config() -> types.GenerateContentConfig:
    # Used to force a closing text reply with no tool-calling capability at all (e.g. once the iteration cap is hit)
    return types.GenerateContentConfig(
        system_instruction=INTERACTIVE_SYSTEM_INSTRUCTION, temperature=0.2
    )


def _collect_referenced(result: Any, acc: list[int]) -> None:
    """Accumulate alert_investigations.id values a chat turn touched, so the stored
    agent message can link them. Reads the compact shapes returned by the two
    case-lookup tools (a single investigation_id, or a matches[] list)."""
    if not isinstance(result, dict):
        return  # nothing to extract from non-dict tool results
    iid = result.get("investigation_id")  # single-investigation lookup shape
    if isinstance(iid, int) and iid not in acc:
        acc.append(iid)  # record it, avoiding duplicates
    for m in result.get("matches") or []:
        # multi-match lookup shape (e.g. search_investigations_by_indicator)
        mid = m.get("investigation_id") if isinstance(m, dict) else None
        if isinstance(mid, int) and mid not in acc:
            acc.append(mid)


def _focus_preamble(inv: dict[str, Any]) -> str:
    """Console-supplied context for a chat started from an investigation page: the
    record the analyst is looking at right now. Stated as context, not as an
    instruction — an unqualified 'this alert' / 'this case' means this one."""
    analysis = inv.get("analysis") or {}  # nested analysis blob, may be absent
    # Build a bullet-point summary of the focused investigation for the model's context
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
        # Nudge the model to re-verify the case via a tool call before acting on it, even though it's "focused"
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
    settings = get_settings()  # current app settings
    client = genai.Client(api_key=settings.gemini_api_key)  # Gemini client for this chat turn
    # Focus the anchored case (if any) and an empty alert; the case-lookup tool
    # re-focuses ctx.investigation when the analyst references a different case.
    # Identity is fixed to the authenticated session — never taken from the model.
    ctx = tools.ToolContext(
        alert=WazuhAlert(), analyst_username=analyst_username,  # empty alert placeholder; analyst identity is trusted, not model-supplied
        investigation=focus_investigation,
    )
    # Merge the read-only, interactive-only, and audited action tool registries for this chat
    registry = {**tools.TOOL_REGISTRY, **tools.INTERACTIVE_REGISTRY, **tools.ACTION_REGISTRY}

    contents: list[types.Content] = []
    for h in history or []:
        # Map our internal role names to Gemini's role names ('analyst'->'user', anything else->'model')
        role = "user" if h.get("role") == "analyst" else "model"
        contents.append(types.Content(role=role, parts=[types.Part(text=h.get("message") or "")]))
    if focus_investigation:
        # Sent alongside this turn only, so the anchor follows the page the analyst
        # is on rather than sticking to the conversation forever.
        contents.append(types.Content(
            role="user", parts=[types.Part(text=_focus_preamble(focus_investigation))]))
    contents.append(types.Content(role="user", parts=[types.Part(text=message)]))  # the analyst's actual message

    tool_calls: list[dict[str, Any]] = []  # audit/trace of tool calls made this turn
    # Seed referenced ids with the focused investigation's id, if any, since the turn is implicitly about it
    referenced: list[int] = [focus_investigation["id"]] if focus_investigation else []

    for iteration in range(1, settings.agent_max_iterations + 1):
        # Ask the model to either call a tool or reply in text
        response = client.models.generate_content(
            model=settings.gemini_model, contents=contents, config=_interactive_config(registry)
        )
        fc = _first_function_call(response)
        if fc is None:  # model replied with text -> turn ends
            return (_first_text(response) or "(no response)"), tool_calls, referenced

        args = dict(fc.args)  # copy the model-supplied arguments
        reason = args.get("reason", "")  # model's stated justification
        logger.info("CHAT tool_call analyst=%s iter=%s tool=%s args=%s reason=%r",
                    analyst_username, iteration, fc.name,
                    {k: v for k, v in args.items() if k != "reason"}, reason)
        result = tools.dispatch(fc.name, args, ctx, registry=registry)  # execute the tool (may be an audited action)
        _collect_referenced(result, referenced)  # note any investigation ids this call touched
        # Record this call in the tool_calls trace, including whether it succeeded
        tool_calls.append({"iteration": iteration, "tool": fc.name,
                           "args": {k: v for k, v in args.items() if k != "reason"},
                           "reason": reason, "error": result.get("error"),
                           "ok": result.get("ok", result.get("error") is None)})
        contents.append(response.candidates[0].content)  # append the model's turn
        # Append the tool's result so the model can factor it into its next move
        contents.append(types.Content(role="user", parts=[
            types.Part.from_function_response(name=fc.name, response={"result": result})
        ]))

    # Cap reached while still calling tools: force a closing text summary.
    logger.info("CHAT cap reached (analyst=%s); requesting closing text", analyst_username)
    # Final call with no tools available at all, forcing the model to summarize in plain text
    response = client.models.generate_content(
        model=settings.gemini_model, contents=contents, config=_text_only_config()
    )
    return (_first_text(response) or "(reached tool limit for this turn)"), tool_calls, referenced
