"""Webhook processing: turn a raw Wazuh alert payload into an analysis (and,
when enabled, a TheHive case)."""
import logging
from typing import Any

from . import memory, metrics, triage
from .agent import run_agent
from .config import get_settings
from .console import store as console_store
from .schemas import AnalysisResult, WazuhAlert, WebhookResponse
from .triage import _norm_source_ip

logger = logging.getLogger(__name__)


def _retrieve_memory(alert: WazuhAlert):
    """Embed the alert identity once, retrieve prior host history.

    Returns (embedding, memories, context_text). Degrades gracefully: if memory
    is disabled or the DB/embedding fails, returns (None, [], default-context)
    so the alert is still analyzed — failures are logged, never swallowed.
    """
    default_ctx = "No prior related alerts recorded for this host."
    if not get_settings().memory_enabled:
        return None, [], default_ctx
    identity = memory.identity_string(alert)
    try:
        embedding = memory.embed(identity)
    except Exception:  # noqa: BLE001
        logger.exception("Embedding failed; proceeding without memory")
        return None, [], default_ctx
    try:
        memories = memory.retrieve(alert.agent.name or "unknown", embedding)
    except Exception:  # noqa: BLE001
        logger.exception("Memory retrieval failed; proceeding without prior context")
        return embedding, [], default_ctx
    logger.info("Retrieved %d prior memories for host %s", len(memories), alert.agent.name)
    return embedding, memories, memory.format_memories_for_prompt(memories)


def normalize_alert(payload: dict[str, Any]) -> WazuhAlert:
    """Wazuh integrations sometimes wrap the alert. Unwrap common envelopes."""
    if isinstance(payload, dict):
        for key in ("alert", "_source", "data"):
            inner = payload.get(key)
            # only treat as envelope if it looks like a full alert (has rule)
            if isinstance(inner, dict) and "rule" in inner:
                payload = inner
                break
    return WazuhAlert.model_validate(payload)


def process_alert(payload: dict[str, Any]) -> WebhookResponse:
    """Run the full pipeline for one alert. Raises on unrecoverable errors."""
    alert = normalize_alert(payload)
    logger.info(
        "Processing alert id=%s level=%s desc=%s",
        alert.id, alert.rule_level, alert.description,
    )

    # Memory: embed once, retrieve prior host context (reused for write-back).
    identity = memory.identity_string(alert)
    embedding, memories, memory_context = _retrieve_memory(alert)

    analysis: AnalysisResult
    analysis, enrichment, tool_trace = run_agent(alert, memory_context)

    # Write the new alert+analysis back, reusing the embedding (don't embed twice).
    memory_id: int | None = None
    if embedding is not None:
        try:
            memory_id = memory.write_back(alert, identity, analysis, embedding)
        except Exception:  # noqa: BLE001
            logger.exception("Memory write-back failed (analysis preserved)")

    # Deterministic triage: decide the action (route + dedup) AFTER memory write-back,
    # which has already run above and is independent of this decision.
    decision = None
    case: dict[str, Any] | None = None
    try:
        decision, case = triage.route_and_execute(alert, analysis, enrichment)
    except Exception:  # noqa: BLE001 - routing failure must not lose the analysis/memory
        logger.exception("Triage routing failed (analysis + memory preserved)")

    retrieved_ids = [m["id"] for m in memories]

    # Additive output-recording for the console: persist the agent's output as a
    # write-once row. This runs AFTER the pipeline and is fully isolated — a
    # persistence failure is logged and never affects analysis/memory/triage.
    try:
        case_info = case or {}
        analysis_json = analysis.model_dump(mode="json")
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
        )
    except Exception:  # noqa: BLE001 - output-recording must never break ingestion
        # Recording failure must NEVER break ingestion (memory + TheHive already
        # ran). But it must not be silent: emit a distinct, greppable marker with
        # the alert_id and bump a counter surfaced on /health. Use the operator
        # /ops/reconciliation endpoint to find which alerts are missing a record.
        metrics.increment("console_record_failures")
        logger.exception("CONSOLE_RECORD_FAILURE alert_id=%s: investigation not "
                         "persisted (pipeline output preserved)", alert.id)

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
