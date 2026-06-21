"""Operator endpoints for inspecting/editing/deleting semantic memory.

These are privileged tools — they can edit and delete the memory that drives all
analysis — so the entire router sits behind a bearer-token check. Kept separate
from the alert-ingestion webhook path.
"""
import hmac
import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from . import memory
from .config import get_settings
from .schemas import MemorySearchRequest, MemoryUpdateRequest

logger = logging.getLogger(__name__)


def require_operator(authorization: Optional[str] = Header(default=None)) -> None:
    """Constant-time bearer-token check for the whole /memory router."""
    token = get_settings().operator_api_token
    if not token:
        # Fail closed: if no token is configured, the endpoints are unusable.
        raise HTTPException(status_code=503, detail="operator token not configured")
    expected = f"Bearer {token}"
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="unauthorized")


router = APIRouter(prefix="/memory", tags=["memory"], dependencies=[Depends(require_operator)])


def _serialize(row: dict[str, Any]) -> dict[str, Any]:
    """JSON-safe row (datetimes -> ISO). Never includes the raw embedding."""
    out = dict(row)
    for key in ("alert_timestamp", "created_at"):
        if isinstance(out.get(key), datetime):
            out[key] = out[key].isoformat()
    return out


@router.get("")
def list_memories(
    agent_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    rule_id: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    rows = memory.list_memories(
        agent_name=agent_name, source_ip=source_ip, rule_id=rule_id,
        date_from=date_from, date_to=date_to, limit=limit, offset=offset,
    )
    return {"count": len(rows), "items": [_serialize(r) for r in rows]}


@router.post("/search")
def search_memories(req: MemorySearchRequest) -> dict[str, Any]:
    rows = memory.search_memories(req.query, agent_name=req.agent_name, k=req.k)
    return {"count": len(rows), "items": [_serialize(r) for r in rows]}


@router.get("/{memory_id}")
def get_memory(memory_id: int) -> dict[str, Any]:
    row = memory.get_memory(memory_id)
    if row is None:
        raise HTTPException(status_code=404, detail="memory not found")
    return _serialize(row)


@router.patch("/{memory_id}")
def update_memory(memory_id: int, req: MemoryUpdateRequest) -> dict[str, Any]:
    if req.analysis is None and req.alert_text is None:
        raise HTTPException(status_code=400, detail="provide 'analysis' and/or 'alert_text'")
    if memory.get_memory(memory_id) is None:
        raise HTTPException(status_code=404, detail="memory not found")

    reembedded = False
    row: Optional[dict[str, Any]] = None
    # Identity change MUST re-embed; analysis-only change must NOT.
    if req.alert_text is not None:
        row = memory.reembed_identity(memory_id, req.alert_text)
        reembedded = True
        logger.info("Memory %s identity edited -> re-embedded", memory_id)
    if req.analysis is not None:
        row = memory.update_analysis(memory_id, req.analysis)
        logger.info("Memory %s analysis edited (no re-embed)", memory_id)

    return {"reembedded": reembedded, "memory": _serialize(row) if row else None}


@router.delete("/{memory_id}")
def delete_memory(memory_id: int) -> dict[str, Any]:
    if not memory.delete_memory(memory_id):
        raise HTTPException(status_code=404, detail="memory not found")
    logger.info("Memory %s deleted", memory_id)
    return {"status": "deleted", "id": memory_id}
