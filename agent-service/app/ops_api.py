"""Operator-only operational endpoints (machine-to-machine, token-protected).

Kept separate from the alert-ingestion webhook and the analyst console. Reuses
the same operator bearer token as the /memory router (require_operator), so it is
NOT reachable from a browser session — it is an ops/automation surface only.
"""
from fastapi import APIRouter, Depends, Query

from .console import store as console_store
from .memory_api import require_operator

router = APIRouter(prefix="/ops", tags=["ops"], dependencies=[Depends(require_operator)])


@router.get("/reconciliation")
def reconciliation(window_hours: float = Query(default=24.0, gt=0, le=720)) -> dict:
    """Count memory rows vs alert_investigations rows over a recent window.

    Every processed alert (with memory enabled) should produce exactly one memory
    row and exactly one investigation row, so the two counts should match. A
    non-zero divergence flags lost records — e.g. a silent console-record failure
    (finding 2.1) leaves a memory row with no investigation row.
    """
    return console_store.reconcile_counts(window_hours)
