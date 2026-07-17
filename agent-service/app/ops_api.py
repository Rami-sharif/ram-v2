"""Operator-only operational endpoints (machine-to-machine, token-protected).

Kept separate from the alert-ingestion webhook and the analyst console. Reuses
the same operator bearer token as the /memory router (require_operator), so it is
NOT reachable from a browser session — it is an ops/automation surface only.
"""
# FastAPI building blocks:
#   APIRouter — groups these /ops routes so main.py can attach them.
#   Depends   — runs the auth dependency before each route.
#   Query     — declares and validates the URL query parameter.
from fastapi import APIRouter, Depends, Query

# The console's storage module, used here to run the reconciliation query.
from .console import store as console_store
# Import the SAME auth function the /memory router uses, so /ops shares one bearer-token
# gate instead of defining its own. Reusing it keeps the security behaviour identical.
from .memory_api import require_operator

# Build the router: prefix="/ops" puts every route under /ops, and the shared
# require_operator dependency guards ALL of them at once (declared here, not per-endpoint).
router = APIRouter(prefix="/ops", tags=["ops"], dependencies=[Depends(require_operator)])


# GET /ops/reconciliation — compares memory vs investigation row counts.
@router.get("/reconciliation")
# window_hours comes from the URL (?window_hours=...). Query enforces the rules: gt=0
# (must be positive) and le=720 (at most 720 hours = 30 days); default is 24 hours.
def reconciliation(window_hours: float = Query(default=24.0, gt=0, le=720)) -> dict:
    """Count memory rows vs alert_investigations rows over a recent window.

    Every processed alert (with memory enabled) should produce exactly one memory
    row and exactly one investigation row, so the two counts should match. A
    non-zero divergence flags lost records — e.g. a silent console-record failure
    (finding 2.1) leaves a memory row with no investigation row.
    """
    # Delegate the actual counting/comparison SQL to the console store and return its result as-is.
    return console_store.reconcile_counts(window_hours)
