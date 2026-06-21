"""Webhook processing: turn a raw Wazuh alert payload into an analysis (and,
when enabled, a TheHive case)."""
import logging
from typing import Any

from . import memory, triage
from .agent import AgentError, run_agent
from .config import get_settings
from .schemas import AnalysisResult, WazuhAlert, WebhookResponse

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
    analysis, enrichment = run_agent(alert, memory_context)

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

    return WebhookResponse(
        status="ok",
        alert_id=alert.id,
        rule_level=alert.rule_level,
        enrichment=enrichment,
        analysis=analysis,
        case=case,
        triage=decision,
        memory={
            "written_id": memory_id,
            "retrieved": len(memories),
            "retrieved_ids": [m["id"] for m in memories],
            "similar_ids": [m["id"] for m in memories if m.get("is_similar")],
        },
    )
