"""Operator endpoints for inspecting/editing/deleting semantic memory.

These are privileged tools — they can edit and delete the memory that drives all
analysis — so the entire router sits behind a bearer-token check. Kept separate
from the alert-ingestion webhook path.
"""
# hmac.compare_digest gives a constant-time string comparison: it takes the same amount
# of time whether the strings match early or late, so an attacker can't guess the token
# character-by-character by measuring response times ("timing attack").
import hmac
# For logging memory edit/delete operations.
import logging
# datetime serves two roles here: as a query-param type (FastAPI parses ?date_from=... into
# a datetime) and for detecting datetime columns that need converting to strings for JSON.
from datetime import datetime
# Any for loosely-typed dict payloads; Optional for nullable query/body fields.
from typing import Any, Optional

# FastAPI pieces used below:
#   APIRouter   — groups related routes so they can be attached to the app in main.py.
#   Depends     — declares a "dependency" that runs before a route (here: the auth check).
#   Header      — pulls a value out of an HTTP header into a function argument.
#   HTTPException — raise it to return an HTTP error (status code + message).
#   Query       — declares/validates a URL query-string parameter (?limit=50).
from fastapi import APIRouter, Depends, Header, HTTPException, Query

# The memory module implementing the actual DB-backed list/search/get/update/delete logic.
from . import memory
# Settings accessor, used to read the operator bearer token.
from .config import get_settings
# Request body schemas for the search and update endpoints.
from .schemas import MemorySearchRequest, MemoryUpdateRequest

# Module-level logger for memory mutation events.
logger = logging.getLogger(__name__)


# A FastAPI "dependency": a function attached (via Depends) to run BEFORE the actual
# route handlers. If it raises, the route never runs. This one is the gatekeeper for the
# whole /memory router. `authorization: ... = Header(...)` tells FastAPI to inject the
# request's `Authorization` header here (or None if the caller didn't send one).
def require_operator(authorization: Optional[str] = Header(default=None)) -> None:
    """Constant-time bearer-token check for the whole /memory router."""
    # Read the configured operator token from settings.
    token = get_settings().operator_api_token
    if not token:
        # Fail closed: with no token configured, refuse everyone (503 = service
        # unavailable) rather than accidentally leaving the endpoints wide open.
        raise HTTPException(status_code=503, detail="operator token not configured")
    # The Authorization header should look like "Bearer <the-token>"; build that expected value.
    expected = f"Bearer {token}"
    # Reject if the header is missing OR doesn't match. compare_digest does the match in
    # constant time (see the import note) so response timing can't leak the token. 401 =
    # unauthorized.
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="unauthorized")


# Create the router. prefix="/memory" makes every path below start with /memory.
# tags=["memory"] groups them in the API docs. dependencies=[Depends(require_operator)]
# attaches the auth check to EVERY route at once, so no endpoint can forget it.
router = APIRouter(prefix="/memory", tags=["memory"], dependencies=[Depends(require_operator)])


# Helper (the leading underscore is a convention for "module-private"). JSON can't hold
# a Python datetime object, so this makes a row safe to return as JSON.
def _serialize(row: dict[str, Any]) -> dict[str, Any]:
    """JSON-safe row (datetimes -> ISO). Never includes the raw embedding."""
    # dict(row) makes a shallow copy so we transform our own copy, not the caller's.
    out = dict(row)
    # Turn datetime columns into ISO-8601 strings (e.g. "2026-07-15T12:00:00"),
    # a format JSON and browsers both understand.
    for key in ("alert_timestamp", "created_at"):
        if isinstance(out.get(key), datetime):
            out[key] = out[key].isoformat()
    # Return the JSON-safe copy.
    return out


# GET /memory — list/filter memories. Because the router has prefix="/memory", the empty
# path "" here means exactly /memory. Each function argument below becomes a URL query
# parameter (e.g. /memory?agent_name=web01&limit=20).
@router.get("")
def list_memories(
    # Optional filters, all defaulting to "no filter" (None).
    agent_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    rule_id: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    # "Pagination" = returning results in pages instead of all at once. limit = page size
    # (Query bounds it to 1..500 so nobody can request the whole table); offset = how many
    # rows to skip (must be >= 0). Together they walk through large result sets.
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    # Delegate filtering/pagination to the memory module's DB query.
    rows = memory.list_memories(
        agent_name=agent_name, source_ip=source_ip, rule_id=rule_id,
        date_from=date_from, date_to=date_to, limit=limit, offset=offset,
    )
    # Return a count plus JSON-safe serialized rows.
    return {"count": len(rows), "items": [_serialize(r) for r in rows]}


# POST /memory/search — "semantic" search means matching by MEANING, not exact keywords:
# the query text is turned into a vector (list of numbers) and compared to stored vectors.
# The `req: MemorySearchRequest` argument makes FastAPI parse+validate the JSON body for us.
@router.post("/search")
def search_memories(req: MemorySearchRequest) -> dict[str, Any]:
    # Embed the query text and find the top-k most similar memories, optionally scoped to an agent.
    rows = memory.search_memories(req.query, agent_name=req.agent_name, k=req.k)
    # Return a count plus JSON-safe serialized rows.
    return {"count": len(rows), "items": [_serialize(r) for r in rows]}


# GET /memory/{memory_id} — {memory_id} in the path is a "path parameter": the value from
# the URL (e.g. /memory/42) is passed into the memory_id argument, converted to int.
@router.get("/{memory_id}")
def get_memory(memory_id: int) -> dict[str, Any]:
    # Look up the row; None means it doesn't exist.
    row = memory.get_memory(memory_id)
    if row is None:
        # Surface a 404 rather than a raw None/empty response.
        raise HTTPException(status_code=404, detail="memory not found")
    # Return the JSON-safe serialized row.
    return _serialize(row)


# PATCH /memory/{memory_id} — PATCH is the HTTP verb for a PARTIAL update (change some
# fields, leave the rest). Combines a path parameter (memory_id) with a JSON body (req).
@router.patch("/{memory_id}")
def update_memory(memory_id: int, req: MemoryUpdateRequest) -> dict[str, Any]:
    # Require at least one editable field to be present.
    if req.analysis is None and req.alert_text is None:
        raise HTTPException(status_code=400, detail="provide 'analysis' and/or 'alert_text'")
    # Verify the row exists before attempting any edit.
    if memory.get_memory(memory_id) is None:
        raise HTTPException(status_code=404, detail="memory not found")

    # Tracks whether this request triggered a re-embed, reported back to the caller.
    reembedded = False
    # Will hold whichever update's resulting row (identity update takes precedence if both are set).
    row: Optional[dict[str, Any]] = None
    # Identity change MUST re-embed; analysis-only change must NOT.
    if req.alert_text is not None:
        # Changing the identity text invalidates the old embedding, so recompute and store it.
        row = memory.reembed_identity(memory_id, req.alert_text)
        reembedded = True
        logger.info("Memory %s identity edited -> re-embedded", memory_id)
    if req.analysis is not None:
        # Analysis-only edits don't affect the embedding, so update in place without re-embedding.
        row = memory.update_analysis(memory_id, req.analysis)
        logger.info("Memory %s analysis edited (no re-embed)", memory_id)

    # Report whether a re-embed happened and return the latest row state (serialized if present).
    return {"reembedded": reembedded, "memory": _serialize(row) if row else None}


# DELETE /memory/{memory_id} — DELETE is the HTTP verb for removing a resource.
@router.delete("/{memory_id}")
def delete_memory(memory_id: int) -> dict[str, Any]:
    # Attempt the delete; a False return means no such row existed.
    if not memory.delete_memory(memory_id):
        raise HTTPException(status_code=404, detail="memory not found")
    # Log the deletion for audit purposes (privileged, destructive operation).
    logger.info("Memory %s deleted", memory_id)
    # Confirm deletion to the caller.
    return {"status": "deleted", "id": memory_id}
