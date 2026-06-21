"""Webhook processing: turn a raw Wazuh alert payload into an analysis (and,
when enabled, a TheHive case)."""
import logging
from typing import Any

from .agent import AgentError, run_agent
from .config import get_settings
from .schemas import AnalysisResult, WazuhAlert, WebhookResponse
from .thehive import TheHiveError, create_case

logger = logging.getLogger(__name__)


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

    analysis: AnalysisResult
    analysis, enrichment = run_agent(alert)

    case: dict[str, Any] | None = None
    settings = get_settings()
    if settings.thehive_enabled:
        # A TheHive failure must not discard the analysis we already produced.
        try:
            case = create_case(alert, analysis, enrichment)
        except TheHiveError as exc:
            logger.error("Case creation failed (analysis preserved): %s", exc)
            case = {"error": str(exc)}
    else:
        logger.info("TheHive disabled (no API key) — skipping case creation")

    return WebhookResponse(
        status="ok",
        alert_id=alert.id,
        rule_level=alert.rule_level,
        enrichment=enrichment,
        analysis=analysis,
        case=case,
    )
