"""FastAPI entrypoint for the RAM v2 agent service.

This is the file a web server (uvicorn) loads to start the service. FastAPI is a
Python web framework: you create one `app` object, attach "routes" (functions that
run when a given URL is requested), and the framework turns HTTP requests into
Python function calls and Python return values back into HTTP responses (usually
JSON). This module wires together every route the service exposes.
"""
# Standard logging module, used to set up the app-level logger.
import logging
# `Any` means "a value of any type". Used below for JSON-ish dicts whose exact
# shape we don't pin down (JSON can hold arbitrary nested data).
from typing import Any

# FastAPI: the application class. Request: an object representing one incoming
# HTTP request (headers, body, etc.), used in the webhook handler to read the body.
from fastapi import FastAPI, Request
# JSONResponse lets us return a response while explicitly choosing the HTTP status
# code (200 ok, 400 bad request, 500 error, ...) instead of always getting 200.
from fastapi.responses import JSONResponse
# StaticFiles serves files straight from disk (the console's JavaScript/CSS) so the
# browser can download them — no Python code runs per file, it just streams them.
from fastapi.staticfiles import StaticFiles
# Path is Python's object-oriented way to build/handle filesystem paths portably.
from pathlib import Path
# Middleware wraps every request/response passing through the app. This one manages
# a signed "session" cookie so the analyst console can remember who is logged in.
# (Starlette is the lower-level toolkit FastAPI is built on top of.)
from starlette.middleware.sessions import SessionMiddleware

# In-process operational counters module (surfaced on /health).
from . import metrics
# Exception type raised when the agent loop fails, caught specially in the webhook handler.
from .agent import AgentError
# Settings loader (cached), used throughout for config values.
from .config import get_settings
# Exception + handler pair implementing "redirect to login" for the console.
from .console.auth import NeedsLogin, needs_login_handler
# The analyst console's own router (session-authenticated pages/API).
from .console.router import router as console_router
# Sets up root logger handlers/formatting before anything else logs.
from .logging_conf import configure_logging
# Operator-only memory inspection/edit/delete router.
from .memory_api import router as memory_router
# Operator-only ops/reconciliation router.
from .ops_api import router as ops_router
# The core alert-processing pipeline invoked by the webhook endpoint.
from .webhook import process_alert

# Read all configuration from environment variables. This runs once when the module
# is first imported; get_settings() caches the result so repeated calls are free.
settings = get_settings()
# Set up logging FIRST (before anything else logs) so every later log line is
# formatted and routed consistently. The level (INFO/DEBUG/...) comes from config.
configure_logging(settings.agent_log_level)
# A named logger for this module. Using getLogger(name) lets us control this
# module's log output separately and tags each line with the name "ramv2.agent".
logger = logging.getLogger("ramv2.agent")

# Create the FastAPI application object. `app` is what uvicorn looks for and runs.
# title/version show up in the auto-generated interactive API docs at /docs.
app = FastAPI(title="RAM v2 — Agent Service", version="0.2.0")
# A "router" is a bundle of related routes defined in another file. include_router
# attaches that bundle to the app. This one adds the token-protected /memory routes.
app.include_router(memory_router)
# Attach the token-protected operator /ops routes (health/reconciliation tooling).
app.include_router(ops_router)

# --- Analyst console (session-authenticated, human identity) -----------------
# The session layer is purely additive: it only reads/writes a signed cookie and
# never blocks or rewrites other paths. The /webhook/wazuh endpoint and the
# token-protected /memory router are untouched and stay on their own auth.
# Install the session cookie middleware. Each argument matters:
#   secret_key   — signs the cookie so a user can't forge/tamper with their session.
#   max_age      — how long (in seconds) a login lasts; hours * 3600 converts to seconds.
#   same_site    — "lax" limits when the cookie is sent cross-site (a CSRF safeguard).
#   https_only   — send the cookie only over HTTPS when running behind TLS.
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret_key,
    max_age=settings.session_max_age_hours * 3600,
    same_site="lax",
    https_only=settings.console_cookie_secure,
)
# Build the path to the console's static-asset folder relative to THIS file's location
# (so it works no matter what directory the process was started from).
# __file__ is this file; .resolve().parent is the folder it lives in.
_static_dir = Path(__file__).resolve().parent / "console" / "static"
# "Mount" a sub-application that serves those files under the /console/static URL path.
app.mount("/console/static", StaticFiles(directory=str(_static_dir)), name="console-static")
# Attach the console's HTML-page and API routes (these use the session cookie above).
app.include_router(console_router)
# An "exception handler" turns a specific raised exception into a chosen response.
# Here: whenever console code raises NeedsLogin, respond by redirecting to /login
# instead of showing a 500 error — that's how "you must log in first" is enforced.
app.add_exception_handler(NeedsLogin, needs_login_handler)


# `@app.get("/")` is a decorator: it registers the function right below it as the
# handler for HTTP GET requests to the URL path "/". No auth is required here — it's
# a public landing page describing the service. FastAPI turns the returned dict into
# a JSON response automatically.
@app.get("/")
def root() -> dict[str, Any]:
    # Return a static JSON blob describing the service and pointing to the other endpoints.
    return {
        "status": "ok",
        "service": "RAM v2 agent service",
        "message": "Use /health for the health check, /webhook/wazuh for alerts, /console for the analyst console, and /memory for operator endpoints.",
        "endpoints": ["/health", "/webhook/wazuh", "/console", "/memory"],
    }


# GET /health — a "health check": a cheap endpoint that monitoring tools (and Docker)
# ping to confirm the service is alive. It also reports a few live config flags and
# the in-process counters so operators can spot trouble at a glance.
@app.get("/health")
def health() -> dict[str, Any]:
    # Build the health payload: static ok status plus a few live config values.
    return {
        "status": "ok",
        "gemini_model": settings.gemini_model,
        "thehive_enabled": settings.thehive_enabled,
        # Operational counters (in-process, reset on restart). A non-zero
        # console_record_failures means an alert was processed but its console
        # record failed to persist — reconcile via /ops/reconciliation.
        # Pull the current counter values from the metrics module.
        "metrics": metrics.snapshot(),
    }


# POST /webhook/wazuh — a "webhook" is a URL that another system calls to push data
# to us. Wazuh (the SIEM/monitoring tool) POSTs one JSON alert here every time a rule
# fires; this endpoint is the front door of the whole triage pipeline.
@app.post("/webhook/wazuh")
# `async def` marks this as an asynchronous function. We need `await` to read the
# request body without blocking the server, so the function must be async. `await`
# means "pause here until this finishes, letting the server handle other requests
# meanwhile." The pipeline it calls afterwards is ordinary (synchronous) code.
async def wazuh_webhook(request: Request) -> JSONResponse:
    try:
        # Read and parse the request body as JSON. `await` because reading the network
        # stream may take time; this yields control until the body has arrived.
        payload = await request.json()
    except Exception:  # noqa: BLE001
        # If the body isn't valid JSON, don't crash — log it and reply 400 (bad request).
        logger.warning("Received webhook with invalid JSON body")
        return JSONResponse(status_code=400, content={"status": "error", "detail": "invalid JSON"})

    try:
        # Hand the parsed alert to the real pipeline (enrichment, LLM analysis, triage,
        # case creation, memory). This returns a Pydantic response model.
        result = process_alert(payload)
        # Happy path: reply 200 (OK). model_dump() converts the Pydantic model to a
        # plain dict that JSONResponse can serialize to JSON.
        return JSONResponse(status_code=200, content=result.model_dump())
    except AgentError as exc:
        # A known failure in the LLM/agent step. 502 = "bad gateway" i.e. an upstream
        # dependency (the model) failed, not our own bug.
        logger.error("Agent failed: %s", exc)
        return JSONResponse(status_code=502, content={"status": "error", "detail": str(exc)})
    except Exception as exc:  # noqa: BLE001 - last-resort guard, logged with trace
        # Catch-all so one bad alert can never crash the whole service. logger.exception
        # records the full stack trace; 500 = generic server error.
        logger.exception("Unhandled error processing alert")
        return JSONResponse(status_code=500, content={"status": "error", "detail": str(exc)})
