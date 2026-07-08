"""FastAPI entrypoint for the RAM v2 agent service."""
import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from starlette.middleware.sessions import SessionMiddleware

from . import metrics
from .agent import AgentError
from .config import get_settings
from .console.auth import NeedsLogin, needs_login_handler
from .console.router import router as console_router
from .logging_conf import configure_logging
from .memory_api import router as memory_router
from .ops_api import router as ops_router
from .webhook import process_alert

settings = get_settings()
configure_logging(settings.agent_log_level)
logger = logging.getLogger("ramv2.agent")

app = FastAPI(title="RAM v2 — Agent Service", version="0.2.0")
app.include_router(memory_router)
app.include_router(ops_router)

# --- Analyst console (session-authenticated, human identity) -----------------
# The session layer is purely additive: it only reads/writes a signed cookie and
# never blocks or rewrites other paths. The /webhook/wazuh endpoint and the
# token-protected /memory router are untouched and stay on their own auth.
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret_key,
    max_age=settings.session_max_age_hours * 3600,
    same_site="lax",
    https_only=settings.console_cookie_secure,
)
_static_dir = Path(__file__).resolve().parent / "console" / "static"
app.mount("/console/static", StaticFiles(directory=str(_static_dir)), name="console-static")
app.include_router(console_router)
app.add_exception_handler(NeedsLogin, needs_login_handler)


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "RAM v2 agent service",
        "message": "Use /health for the health check, /webhook/wazuh for alerts, /console for the analyst console, and /memory for operator endpoints.",
        "endpoints": ["/health", "/webhook/wazuh", "/console", "/memory"],
    }


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "gemini_model": settings.gemini_model,
        "thehive_enabled": settings.thehive_enabled,
        # Operational counters (in-process, reset on restart). A non-zero
        # console_record_failures means an alert was processed but its console
        # record failed to persist — reconcile via /ops/reconciliation.
        "metrics": metrics.snapshot(),
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
