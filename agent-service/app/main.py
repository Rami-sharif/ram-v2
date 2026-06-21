"""FastAPI entrypoint for the RAM v2 agent service."""
import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .agent import AgentError
from .config import get_settings
from .logging_conf import configure_logging
from .webhook import process_alert

settings = get_settings()
configure_logging(settings.agent_log_level)
logger = logging.getLogger("ramv2.agent")

app = FastAPI(title="RAM v2 — Agent Service", version="0.1.0")


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "gemini_model": settings.gemini_model,
        "thehive_enabled": settings.thehive_enabled,
    }


@app.post("/webhook/wazuh")
async def wazuh_webhook(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001
        logger.warning("Received webhook with invalid JSON body")
        return JSONResponse(status_code=400, content={"status": "error", "detail": "invalid JSON"})

    try:
        result = process_alert(payload)
        return JSONResponse(status_code=200, content=result.model_dump())
    except AgentError as exc:
        logger.error("Agent failed: %s", exc)
        return JSONResponse(status_code=502, content={"status": "error", "detail": str(exc)})
    except Exception as exc:  # noqa: BLE001 - last-resort guard, logged with trace
        logger.exception("Unhandled error processing alert")
        return JSONResponse(status_code=500, content={"status": "error", "detail": str(exc)})
