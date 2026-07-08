"""Console data access: users and audit log (Step A). Other console queries
(investigations, feedback) are added in later steps.

The audit_log write is the spine of accountability — every consequential analyst
action calls write_audit() with the named actor.
"""
import logging
from typing import Any, Optional

from psycopg.rows import dict_row
from psycopg.types.json import Json

from ..db import get_pool

logger = logging.getLogger(__name__)


# --- users ------------------------------------------------------------------
def get_user(username: str) -> Optional[dict[str, Any]]:
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, username, password_hash, display_name, role, disabled "
            "FROM users WHERE username = %s",
            (username,),
        )
        return cur.fetchone()


def create_user(username: str, password_hash: str, display_name: str, role: str) -> int:
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, display_name, role) "
            "VALUES (%s, %s, %s, %s) RETURNING id",
            (username, password_hash, display_name, role),
        )
        return cur.fetchone()[0]


# --- alert investigations (write-once agent output) -------------------------
def record_investigation(
    *, alert_id, agent_name, source_ip, rule_id, severity_score, severity_label,
    attack_type, analysis, tool_trace, memory_context, retrieved_ids,
    triage_action, triage_branch, occurrence_count, suppressed, case_id, case_number,
) -> int:
    """Insert the agent's output for one alert. Write-once: the row is never
    UPDATEd (DB trigger enforces this). Human input lives in separate tables."""
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO alert_investigations ("
            " alert_id, agent_name, source_ip, rule_id, severity_score, severity_label,"
            " attack_type, analysis, tool_trace, memory_context, retrieved_ids,"
            " triage_action, triage_branch, occurrence_count, suppressed, case_id, case_number"
            ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (alert_id, agent_name, source_ip, rule_id, severity_score, severity_label,
             attack_type, Json(analysis), Json(tool_trace), memory_context,
             Json(retrieved_ids) if retrieved_ids is not None else None,
             triage_action, triage_branch, occurrence_count, suppressed, case_id, case_number),
        )
        return cur.fetchone()[0]


_QUEUE_COLS = (
    "id, created_at, alert_id, agent_name, source_ip, rule_id, severity_score, "
    "severity_label, attack_type, triage_action, triage_branch, occurrence_count, "
    "suppressed, case_id, case_number"
)


def list_investigations(*, severity_label=None, triage_action=None, agent_name=None,
                        search=None, limit=25, offset=0):
    """Triage queue: filtered, paginated. Returns (rows, total_count)."""
    where, params = [], []
    if severity_label:
        where.append("severity_label = %s"); params.append(severity_label)
    if triage_action:
        where.append("triage_action = %s"); params.append(triage_action)
    if agent_name:
        where.append("agent_name = %s"); params.append(agent_name)
    if search:
        where.append("(alert_id ILIKE %s OR agent_name ILIKE %s OR source_ip ILIKE %s)")
        like = f"%{search}%"; params.extend([like, like, like])
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT count(*) AS n FROM alert_investigations{clause}", params)
        total = cur.fetchone()["n"]
        cur.execute(
            f"SELECT {_QUEUE_COLS} FROM alert_investigations{clause} "
            "ORDER BY created_at DESC LIMIT %s OFFSET %s",
            [*params, limit, offset],
        )
        return cur.fetchall(), total


def get_investigation(inv_id: int):
    """Full investigation record + any layered human input (read-only here)."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM alert_investigations WHERE id = %s", (inv_id,))
        inv = cur.fetchone()
        if inv is None:
            return None
        cur.execute(
            "SELECT actor_username, action, override_payload, reason, created_at "
            "FROM verdict_reviews WHERE investigation_id = %s ORDER BY created_at DESC",
            (inv_id,),
        )
        reviews = cur.fetchall()
        cur.execute(
            "SELECT actor_username, rating, reason, created_at "
            "FROM triage_feedback WHERE investigation_id = %s ORDER BY created_at DESC",
            (inv_id,),
        )
        feedback = cur.fetchall()
    return {"inv": inv, "reviews": reviews, "feedback": feedback}


# --- reconciliation (memory rows vs investigation rows) ---------------------
def reconcile_counts(window_hours: float) -> dict[str, Any]:
    """Count memory rows vs alert_investigations rows over a recent window.

    Each processed alert (memory enabled) should produce exactly one row in each
    table, so the counts should match. divergence = memory_rows - investigation_rows;
    a positive value means investigation records are missing (the finding 2.1
    failure mode — recording failed but memory write-back succeeded). Reported as
    a separable check so it can be polled by an operator without touching ingestion.
    """
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT count(*) AS n FROM soc_memory_vectors "
            "WHERE created_at >= now() - (%s * interval '1 hour')",
            (window_hours,),
        )
        memory_rows = cur.fetchone()["n"]
        cur.execute(
            "SELECT count(*) AS n FROM alert_investigations "
            "WHERE created_at >= now() - (%s * interval '1 hour')",
            (window_hours,),
        )
        investigation_rows = cur.fetchone()["n"]
    divergence = memory_rows - investigation_rows
    return {
        "window_hours": window_hours,
        "memory_rows": memory_rows,
        "investigation_rows": investigation_rows,
        "divergence": divergence,
        "balanced": divergence == 0,
    }


# --- audit ------------------------------------------------------------------
_AUDIT_SQL = (
    "INSERT INTO audit_log (actor_username, action, target_type, target_id, "
    "before, after, detail) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id"
)


def _audit_params(actor_username, action, target_type, target_id, before, after, detail):
    return (actor_username, action, target_type, target_id,
            Json(before) if before is not None else None,
            Json(after) if after is not None else None, detail)


def _audit_on(cur, actor_username, action, *, target_type=None, target_id=None,
              before=None, after=None, detail=None) -> int:
    """Insert an audit row on an EXISTING cursor, so it commits atomically with
    whatever else that transaction is doing."""
    cur.execute(_AUDIT_SQL, _audit_params(
        actor_username, action, target_type, target_id, before, after, detail))
    return cur.fetchone()[0]


def write_audit(actor_username: str, action: str, *, target_type: Optional[str] = None,
                target_id: Optional[str] = None, before: Any = None, after: Any = None,
                detail: Optional[str] = None) -> int:
    """Record a consequential action in its own transaction. Re-raises on failure:
    auditing is a hard requirement — if we can't audit, the action must fail."""
    try:
        with get_pool().connection() as conn, conn.cursor() as cur:
            audit_id = _audit_on(cur, actor_username, action, target_type=target_type,
                                 target_id=target_id, before=before, after=after, detail=detail)
        logger.info("AUDIT actor=%s action=%s target=%s/%s",
                    actor_username, action, target_type, target_id)
        return audit_id
    except Exception:  # noqa: BLE001
        logger.exception("Failed to write audit row (actor=%s action=%s)", actor_username, action)
        raise  # auditing is a hard requirement: if we can't audit, fail the action


# --- analyst actions on investigations (action + audit, one transaction) -----
def add_verdict_review(*, investigation_id: int, actor_username: str, action: str,
                       override_payload: Any, reason: Optional[str], before: Any) -> int:
    """Confirm/override the agent verdict. The verdict_reviews row and its audit
    row are inserted in the SAME transaction — both commit or neither does."""
    after = {"action": action, "override_payload": override_payload, "reason": reason}
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO verdict_reviews (investigation_id, actor_username, action, "
            "override_payload, reason) VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (investigation_id, actor_username, action,
             Json(override_payload) if override_payload is not None else None, reason),
        )
        review_id = cur.fetchone()[0]
        _audit_on(cur, actor_username, f"verdict_{action}", target_type="investigation",
                  target_id=str(investigation_id), before=before, after=after)
    logger.info("AUDIT actor=%s action=verdict_%s investigation=%s", actor_username, action, investigation_id)
    return review_id


def add_triage_feedback(*, investigation_id: int, actor_username: str, rating: str,
                        reason: Optional[str], before: Any) -> int:
    """Record triage correct/incorrect feedback + its audit row in one transaction."""
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO triage_feedback (investigation_id, actor_username, rating, reason) "
            "VALUES (%s, %s, %s, %s) RETURNING id",
            (investigation_id, actor_username, rating, reason),
        )
        feedback_id = cur.fetchone()[0]
        _audit_on(cur, actor_username, "triage_feedback", target_type="investigation",
                  target_id=str(investigation_id), before=before,
                  after={"rating": rating, "reason": reason})
    logger.info("AUDIT actor=%s action=triage_feedback investigation=%s", actor_username, investigation_id)
    return feedback_id


# --- read-only case lookups for the interactive chat ------------------------
# These back the two INTERACTIVE_REGISTRY tools. They query the write-once
# alert_investigations table itself (never raw Wazuh logs, never semantic memory,
# never raw SQL from the LLM) so the assistant can pull up any case by number or
# check whether an indicator appeared in another case.
def get_investigation_by_case_number(case_number: int) -> Optional[dict[str, Any]]:
    """Look up an investigation by its TheHive case_number (NOT its row id).
    Returns the full write-once record (same shape as get_investigation()['inv'])
    or None. If more than one investigation links the same case, the most recent
    wins."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT * FROM alert_investigations WHERE case_number = %s "
            "ORDER BY created_at DESC LIMIT 1",
            (case_number,),
        )
        return cur.fetchone()


def search_investigations_by_indicator(indicator: str, *, limit: int = 25) -> list[dict[str, Any]]:
    """Find investigations across ALL cases whose source_ip equals `indicator`, or
    whose stored analysis mentions it (e.g. a file hash in the analysis JSON).
    Answers 'did this IP/hash appear in another case'. Read-only, capped."""
    like = f"%{indicator}%"
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {_QUEUE_COLS} FROM alert_investigations "
            "WHERE source_ip = %s OR analysis::text ILIKE %s "
            "ORDER BY created_at DESC LIMIT %s",
            (indicator, like, limit),
        )
        return cur.fetchall()


# --- dashboard-level analyst chat (write-once per message) ------------------
# One ongoing thread per analyst (thread_key = username), NOT per investigation.
# The chat table records the CONVERSATION only. Consequential actions taken
# during a chat are audited by their underlying functions (audit_log stays the
# authority). Each message row is immutable (a DB trigger rejects UPDATE).
def add_chat_message(*, thread_key: str, role: str, actor: str, message: str,
                     tool_calls: Any = None, referenced_case_ids: list[int] | None = None) -> int:
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO console_chat (thread_key, role, actor, message, tool_calls, referenced_case_ids) "
            "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            (thread_key, role, actor, message,
             Json(tool_calls if tool_calls is not None else []),
             list(referenced_case_ids or [])),
        )
        return cur.fetchone()[0]


def list_chat(thread_key: str) -> list[dict[str, Any]]:
    """Full conversation for one analyst's thread, oldest-first (replay + render)."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, role, actor, message, tool_calls, referenced_case_ids, created_at "
            "FROM console_chat WHERE thread_key = %s ORDER BY created_at ASC, id ASC",
            (thread_key,),
        )
        return cur.fetchall()
