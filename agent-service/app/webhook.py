"""Webhook processing: turn a raw Wazuh alert payload into an analysis (and,
when enabled, a TheHive case).

Beginner orientation:
- A "webhook" is just an HTTP request that another system (here, the Wazuh
  security monitor) sends us automatically whenever something happens — in this
  case, whenever a new security alert fires. Our web layer receives that request
  and hands its JSON body to the functions in this file.
- This file is the "orchestration pipeline": it doesn't do the deep work itself,
  it calls the other modules in the right order and passes data between them —
  normalize the raw alert, run the AI analysis, remember it, triage (route) it,
  record it for the UI, and return a response.
- A repeated pattern here is "graceful degradation": if a non-essential step
  fails (memory lookup, write-back, triage, console recording), we log the error
  and keep going instead of crashing the whole request. The alert still gets
  analyzed. Only truly unrecoverable errors are allowed to raise.
"""
# Standard logging module, used throughout for structured status/error logs.
import logging
# perf_counter: monotonic wall-clock timer used to record per-alert pipeline latency.
import time
# Any for loosely-typed JSON payloads (the raw webhook body).
from typing import Any

# memory: semantic memory embed/retrieve/write-back; metrics: in-process counters; triage: routing logic.
from . import explain, memory, metrics, triage
# The LLM-driven investigation/analysis loop.
from .agent import run_agent
# Settings accessor, used here to check whether memory is enabled.
from .config import get_settings
# The analyst console's persistence layer, used to record pipeline output for the UI.
from .console import store as console_store
# Pydantic models for the analysis result, incoming alert, and outgoing webhook response.
from .schemas import AnalysisResult, WazuhAlert, WebhookResponse
# Helper to normalize/extract a source IP from an alert, shared with the triage module.
from .triage import _norm_source_ip

# Module-level logger for the webhook pipeline.
logger = logging.getLogger(__name__)


# Embeds the alert's identity and looks up prior related alerts for the same host.
def _retrieve_memory(alert: WazuhAlert):
    """Embed the alert identity once, retrieve prior host history.

    "Embedding" means turning the alert's text into a list of numbers (a vector)
    that captures its meaning, so we can later find past alerts that are
    semantically similar — this is how "semantic memory" works. We compute it
    once here and reuse it for write-back so we never pay for the same embedding
    twice.

    Returns (embedding, memories, context_text). Degrades gracefully: if memory
    is disabled or the DB/embedding fails, returns (None, [], default-context)
    so the alert is still analyzed — failures are logged, never swallowed.
    """
    # Fallback context text used whenever memory can't be used for any reason.
    default_ctx = "No prior related alerts recorded for this host."
    if not get_settings().memory_enabled:
        # Memory disabled globally: skip embedding/retrieval entirely.
        return None, [], default_ctx
    # Build the canonical text identity used both for embedding and for write-back later.
    identity = memory.identity_string(alert)
    try:
        # Compute the embedding vector for this alert's identity.
        embedding = memory.embed(identity)
    except Exception:  # noqa: BLE001
        # Embedding failures (e.g. API outage) must not block analysis; log and degrade gracefully.
        logger.exception("Embedding failed; proceeding without memory")
        return None, [], default_ctx
    try:
        # Look up prior memories for this host using the freshly computed embedding. Pass the
        # alert so the hybrid exact-match (IOC) layer can find cross-host indicator matches.
        memories = memory.retrieve(alert.agent.name or "unknown", embedding, alert=alert)
    except Exception:  # noqa: BLE001
        # Retrieval failures still allow the embedding to be reused for write-back later.
        logger.exception("Memory retrieval failed; proceeding without prior context")
        return embedding, [], default_ctx
    # Log how many prior memories were found, for observability.
    logger.info("Retrieved %d prior memories for host %s", len(memories), alert.agent.name)
    # Return the embedding, raw memory rows, and a prompt-ready formatted context string.
    return embedding, memories, memory.format_memories_for_prompt(memories)


# Unwraps common Wazuh integration envelopes and validates the inner payload into a WazuhAlert.
def normalize_alert(payload: dict[str, Any]) -> WazuhAlert:
    """Wazuh integrations sometimes wrap the alert. Unwrap common envelopes.

    An "envelope" is an outer wrapper object where the real alert lives under a
    known key like "alert"/"_source"/"data" (different Wazuh integrations format
    it differently). We peel off that wrapper so the rest of the code always sees
    the same, flat alert shape. "Validate/coerce into a model" means we hand the
    dict to a Pydantic class that checks the fields exist and have the right
    types, giving us a typed WazuhAlert object instead of a loose dict.
    """
    if isinstance(payload, dict):
        # Try each known envelope key in order, taking the first one that looks like a real alert.
        for key in ("alert", "_source", "data"):
            inner = payload.get(key)
            # only treat as envelope if it looks like a full alert (has rule)
            if isinstance(inner, dict) and "rule" in inner:
                # Replace the outer payload with the unwrapped inner alert and stop looking.
                payload = inner
                break
    # Validate (and coerce) the final payload into the WazuhAlert model.
    return WazuhAlert.model_validate(payload)


# --------------------------------------------------------------------------- #
# Pre-agent dedup gate: skip the whole investigation (agent + embedding) when an
# identical alert was already investigated moments ago, recording a lightweight
# duplicate that reuses the prior verdict. See config.dedup_gate_* and Part A.
# --------------------------------------------------------------------------- #
def _record_gated_duplicate(alert: WazuhAlert, parent: dict[str, Any],
                            source_ip: str, t0: float) -> WebhookResponse:
    """Persist a lightweight duplicate that reuses `parent`'s verdict (no agent, no memory),
    and return a response echoing that verdict. A normal INSERT — write-once is untouched."""
    s = get_settings()
    parent_analysis = parent.get("analysis") or {}
    # Reuse the parent verdict, dropping its explanation blob (belongs to the parent) and
    # stamping gate markers so the console and Part B metrics can identify a gated duplicate.
    analysis_json = dict(parent_analysis)
    analysis_json.pop("explanation", None)
    analysis_json["gate_deduped"] = True
    analysis_json["gate_parent_investigation_id"] = parent["id"]
    analysis_json["gate_window_minutes"] = s.dedup_gate_window_minutes
    # Make the reused nature explicit in the summary the analyst reads.
    analysis_json["summary"] = (
        f"[Auto-deduplicated: same host, rule and source IP as investigation "
        f"#{parent['id']} within {s.dedup_gate_window_minutes:g} min — agent skipped, prior "
        f"verdict reused.] " + (parent_analysis.get("summary") or "")
    )
    memory_ctx = (
        f"Gated as a duplicate of investigation #{parent['id']} (same host+rule+source IP "
        f"within {s.dedup_gate_window_minutes:g} min); the agent was not invoked."
    )
    try:
        console_store.record_investigation(
            alert_id=alert.id, agent_name=alert.agent.name, source_ip=source_ip,
            rule_id=alert.rule.id, severity_score=parent.get("severity_score"),
            severity_label=parent.get("severity_label"), attack_type=parent.get("attack_type"),
            analysis=analysis_json, tool_trace=[], memory_context=memory_ctx,
            retrieved_ids=None, triage_action="suppress_duplicate",
            triage_branch=parent.get("triage_branch"), occurrence_count=None, suppressed=True,
            case_id=parent.get("case_id"), case_number=parent.get("case_number"),
            memory_id=None, case_error=None,
            alert_payload=alert.model_dump(mode="json"), enrichment=None,
            duration_ms=int((time.perf_counter() - t0) * 1000),  # gate path is near-zero, but recorded
        )
    except Exception:  # noqa: BLE001 - recording must never break ingestion (same as the main path)
        metrics.increment("console_record_failures")
        logger.exception("CONSOLE_RECORD_FAILURE (gated) alert_id=%s: duplicate not persisted",
                         alert.id)
    # Echo the reused verdict. AnalysisResult ignores the extra gate/human keys on validation.
    return WebhookResponse(
        status="deduplicated", alert_id=alert.id, rule_level=alert.rule_level,
        enrichment={}, analysis=AnalysisResult.model_validate(parent_analysis),
        case=None, triage=None, tool_trace=[],
        memory={"gate_deduped": True, "parent_investigation_id": parent["id"]},
    )


def _maybe_gate_duplicate(alert: WazuhAlert, t0: float) -> WebhookResponse | None:
    """If this alert duplicates a very recent investigation (same host+rule+source IP within
    the gate window), skip the agent entirely and return a gated-duplicate response. Returns
    None to let the normal pipeline run. Every decision is logged for Part B metrics."""
    s = get_settings()
    if not s.dedup_gate_enabled:
        return None
    source_ip = _norm_source_ip(alert)  # None for placeholder/absent IPs
    if source_ip is None:
        return None  # no discriminator — never gate (avoid false merges), proceed normally
    try:
        parent = console_store.find_recent_investigation_by_identity(
            agent_name=alert.agent.name, rule_id=alert.rule.id, source_ip=source_ip,
            within_minutes=s.dedup_gate_window_minutes,
        )
    except Exception:  # noqa: BLE001 - a gate lookup failure must never drop the alert
        logger.exception("Dedup gate lookup failed (alert=%s); proceeding to full investigation",
                         alert.id)
        return None
    if parent is None:
        # Proceeded: the alert gets a full investigation. Logged so Part B can compute hit rate.
        logger.info("GATE decision=proceeded alert=%s identity=%s|%s|%s",
                    alert.id, alert.agent.name, alert.rule.id, source_ip)
        return None
    # Matched-and-skipped: no Gemini call at all. This log line is the metrics source of truth.
    logger.info("GATE decision=matched_and_skipped alert=%s parent_investigation=%s "
                "identity=%s|%s|%s window_min=%s",
                alert.id, parent["id"], alert.agent.name, alert.rule.id, source_ip,
                s.dedup_gate_window_minutes)
    return _record_gated_duplicate(alert, parent, source_ip, t0)


# Orchestrates the full per-alert pipeline: normalize, analyze, remember, triage, record, respond.
def process_alert(payload: dict[str, Any]) -> WebhookResponse:
    """Run the full pipeline for one alert. Raises on unrecoverable errors.

    This is the top-level orchestrator. Read it as a checklist of steps, each
    handed off to a specialist module:
      1. normalize   - parse/unwrap the raw JSON into a typed alert
      2. memory      - recall similar past alerts for context
      3. analyze     - run the LLM agent to produce the structured analysis
      4. write-back  - save this alert+analysis into memory for the future
      5. triage      - deterministically decide the action (and maybe open a case)
      6. record      - persist a snapshot for the analyst console/UI
      7. respond     - bundle everything into the API response
    Steps 2, 4, 5, and 6 are wrapped so their failures degrade gracefully.
    """
    # Start the pipeline-latency clock (recorded as duration_ms for the metrics dashboard).
    t0 = time.perf_counter()
    # Parse/unwrap the raw JSON body into a validated WazuhAlert.
    alert = normalize_alert(payload)
    # Log the key identifying fields for traceability before any processing starts.
    logger.info(
        "Processing alert id=%s level=%s desc=%s",
        alert.id, alert.rule_level, alert.description,
    )

    # Pre-agent dedup gate: if an identical alert was investigated moments ago, skip the
    # agent (and its embedding) and record a lightweight duplicate reusing the prior verdict.
    # Runs BEFORE any Gemini call. SELECT-only lookup; the write-once record is untouched.
    gated = _maybe_gate_duplicate(alert, t0)
    if gated is not None:
        return gated

    # Memory: embed once, retrieve prior host context (reused for write-back).
    # Recompute the identity string here too, so it's available for write-back regardless of retrieval outcome.
    identity = memory.identity_string(alert)
    # Get the embedding (possibly None), prior memory rows, and formatted context for the prompt.
    embedding, memories, memory_context = _retrieve_memory(alert)

    # Type annotation only, to document the expected return type of run_agent's first element.
    analysis: AnalysisResult
    # Run the LLM investigation loop: the agent reads the alert plus the memory
    # context and, using read-only tools, produces three things:
    #   - analysis:   the structured verdict (severity score, attack type, etc.)
    #   - enrichment: extra evidence it gathered while investigating
    #   - tool_trace: a step-by-step log of which tools it called (for auditing)
    analysis, enrichment, tool_trace = run_agent(alert, memory_context)

    # Write the new alert+analysis back, reusing the embedding (don't embed twice).
    # Will hold the new memory row's id if write-back succeeds, else stays None.
    memory_id: int | None = None
    if embedding is not None:
        try:
            # Persist this alert + its analysis into the memory store for future retrieval.
            memory_id = memory.write_back(alert, identity, analysis, embedding)
        except Exception:  # noqa: BLE001
            # Write-back failure must not lose the analysis already computed; just log it.
            logger.exception("Memory write-back failed (analysis preserved)")

    # Deterministic triage: "deterministic" means fixed rules, not AI — given the
    # same analysis it always makes the same decision (route by severity + dedup),
    # which is what you want for an auditable security workflow. This runs AFTER
    # memory write-back, which has already run above and is independent of this
    # decision.
    # Will hold the TriageDecision if routing succeeds.
    decision = None
    # Will hold TheHive case info (or an error record) if routing creates/attempts a case.
    case: dict[str, Any] | None = None
    try:
        # Run the deterministic severity-based router, which may create/update a TheHive case.
        decision, case = triage.route_and_execute(alert, analysis, enrichment)
    except Exception:  # noqa: BLE001 - routing failure must not lose the analysis/memory
        # Routing failures must not undo the analysis/memory work already completed.
        logger.exception("Triage routing failed (analysis + memory preserved)")

    # Extract just the ids of the retrieved prior memories, for the response payload.
    retrieved_ids = [m["id"] for m in memories]

    # Additive output-recording for the console: save a snapshot of everything
    # this alert produced so the analyst web console can display it later.
    # "Write-once" means the row is inserted once and never edited afterward, so
    # it's a faithful historical record. This runs AFTER the pipeline and is
    # fully isolated — a persistence failure is logged and never affects
    # analysis/memory/triage (graceful degradation again).
    try:
        # Normalize case to an empty dict so .get() calls below don't need None-checks.
        case_info = case or {}
        # Serialize the analysis to plain JSON-compatible types for storage.
        analysis_json = analysis.model_dump(mode="json")
        # Attach a compact "why this verdict" explanation, built in code from the scored
        # memory rows + MITRE + tool results already in hand (no extra LLM call). Stored at
        # INSERT time because alert_investigations is write-once (it can never be UPDATEd in).
        # Best-effort: a failure here must not block recording the investigation.
        try:
            analysis_json["explanation"] = explain.build_explanation(
                alert, analysis, memories, enrichment)
        except Exception:  # noqa: BLE001 - explanation is presentational; never fail ingestion on it
            logger.exception("Explanation build failed (investigation still recorded)")
        # Persist a full snapshot of this alert's processing for the analyst console.
        console_store.record_investigation(
            alert_id=alert.id,
            agent_name=alert.agent.name,
            source_ip=_norm_source_ip(alert),
            rule_id=alert.rule.id,
            severity_score=analysis.severity_score,
            severity_label=analysis_json["severity_label"],
            attack_type=analysis.attack_type,
            analysis=analysis_json,
            tool_trace=tool_trace,
            memory_context=memory_context,
            retrieved_ids=retrieved_ids,
            triage_action=decision.action if decision else None,
            triage_branch=decision.branch if decision else None,
            occurrence_count=decision.occurrence_count if decision else None,
            suppressed=decision.suppressed if decision else None,
            case_id=case_info.get("_id"),
            case_number=case_info.get("number"),
            memory_id=memory_id,
            # A failed case creation is RECORDED, not lost: the error plus the two
            # inputs needed to replay it (the alert as received, and the enrichment
            # that went into the case description) let an analyst retry the case
            # from the investigation page. Written at insert time — the row stays
            # write-once.
            case_error=case_info.get("error"),
            alert_payload=alert.model_dump(mode="json"),
            enrichment=enrichment,
            duration_ms=int((time.perf_counter() - t0) * 1000),  # full pipeline latency for metrics
        )
    except Exception:  # noqa: BLE001 - output-recording must never break ingestion
        # Recording failure must NEVER break ingestion (memory + TheHive already
        # ran). But it must not be silent: emit a distinct, greppable marker with
        # the alert_id and bump a counter surfaced on /health. Use the operator
        # /ops/reconciliation endpoint to find which alerts are missing a record.
        # Bump the in-process failure counter so /health reflects the problem.
        metrics.increment("console_record_failures")
        # Emit a greppable, alert_id-tagged error with full traceback for debugging/reconciliation.
        logger.exception("CONSOLE_RECORD_FAILURE alert_id=%s: investigation not "
                         "persisted (pipeline output preserved)", alert.id)

    # Assemble and return the final API response combining analysis, enrichment,
    # case, triage, and memory info. This object is serialized to JSON and sent
    # back as the HTTP response to whoever POSTed the alert to our webhook.
    return WebhookResponse(
        status="ok",
        alert_id=alert.id,
        rule_level=alert.rule_level,
        enrichment=enrichment,
        analysis=analysis,
        case=case,
        triage=decision,
        tool_trace=tool_trace,
        memory={
            "written_id": memory_id,
            "retrieved": len(memories),
            "retrieved_ids": [m["id"] for m in memories],
            "similar_ids": [m["id"] for m in memories if m.get("is_similar")],
        },
    )
