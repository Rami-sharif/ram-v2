"""Console data access: users and audit log (Step A). Other console queries
(investigations, feedback) are added in later steps.

The audit_log write is the spine of accountability — every consequential analyst
action calls write_audit() with the named actor.
"""
import logging
import secrets
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
    memory_id=None,
) -> int:
    """Insert the agent's output for one alert. Write-once: the row is never
    UPDATEd (DB trigger enforces this). Human input lives in separate tables.
    memory_id links this alert's own semantic-memory row so a later analyst
    verdict can teach it back (the learning loop)."""
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO alert_investigations ("
            " alert_id, agent_name, source_ip, rule_id, severity_score, severity_label,"
            " attack_type, analysis, tool_trace, memory_context, retrieved_ids,"
            " triage_action, triage_branch, occurrence_count, suppressed, case_id, case_number,"
            " memory_id"
            ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (alert_id, agent_name, source_ip, rule_id, severity_score, severity_label,
             attack_type, Json(analysis), Json(tool_trace), memory_context,
             Json(retrieved_ids) if retrieved_ids is not None else None,
             triage_action, triage_branch, occurrence_count, suppressed, case_id, case_number,
             memory_id),
        )
        return cur.fetchone()[0]


_QUEUE_COLS = (
    "id, created_at, alert_id, agent_name, source_ip, rule_id, severity_score, "
    "severity_label, attack_type, triage_action, triage_branch, occurrence_count, "
    "suppressed, case_id, case_number"
)


def list_investigations(*, severity_label=None, triage_action=None, agent_name=None,
                        search=None, exclude_actions=(), limit=25, offset=0):
    """Triage queue: filtered, paginated. Returns (rows, total_count).

    `exclude_actions` drops rows whose triage_action is in the given collection
    (used for the queue's default 'actionable only' view, which hides auto_close).
    Ignored when an explicit `triage_action` filter is supplied."""
    where, params = [], []
    if severity_label:
        where.append("severity_label = %s"); params.append(severity_label)
    if triage_action:
        where.append("triage_action = %s"); params.append(triage_action)
    elif exclude_actions:
        placeholders = ", ".join(["%s"] * len(exclude_actions))
        where.append(f"triage_action NOT IN ({placeholders})")
        params.extend(exclude_actions)
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
            f"SELECT {_QUEUE_COLS}, "
            " (SELECT vr.action FROM verdict_reviews vr "
            "  WHERE vr.investigation_id = alert_investigations.id "
            "  ORDER BY vr.created_at DESC LIMIT 1) AS review_status "
            f"FROM alert_investigations{clause} "
            "ORDER BY created_at DESC LIMIT %s OFFSET %s",
            [*params, limit, offset],
        )
        return cur.fetchall(), total


# --- overview aggregates (read-only, global) --------------------------------
# These back the Overview landing page. Each is a small aggregate over the
# write-once alert_investigations table (severity_label / triage_action are
# already indexed-friendly filters used by the queue), computed globally rather
# than per visible page.
def summary_counts() -> dict[str, int]:
    """Global at-a-glance totals for the Overview KPI row."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT "
            " count(*) AS total, "
            " count(*) FILTER (WHERE lower(severity_label) IN ('high','critical')) AS high, "
            " count(*) FILTER (WHERE triage_action = 'create_flagged') AS flagged, "
            " count(*) FILTER (WHERE case_number IS NOT NULL) AS linked_cases, "
            " count(*) FILTER (WHERE suppressed) AS suppressed "
            "FROM alert_investigations"
        )
        row = cur.fetchone()
    # count(*) FILTER returns None only on an empty table for the filtered ones
    return {k: int(v or 0) for k, v in row.items()}


# Fixed ordering so the severity-mix bar always renders low→critical left-to-right.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def severity_distribution() -> list[dict[str, Any]]:
    """Counts grouped by severity_label, returned in a stable severity order for
    the Overview mix bar. Unknown/empty labels are folded into 'info'."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT lower(coalesce(nullif(severity_label, ''), 'info')) AS label, "
            "count(*) AS n FROM alert_investigations GROUP BY 1"
        )
        found = {r["label"]: int(r["n"]) for r in cur.fetchall()}
    # keep known labels in order; append any unexpected labels after
    ordered = [{"label": s, "n": found.pop(s)} for s in _SEVERITY_ORDER if s in found]
    ordered.extend({"label": k, "n": v} for k, v in found.items())
    return ordered


def agent_accuracy() -> dict[str, Any]:
    """How well the agent tracks analyst judgement (the learning-loop scorecard):
    verdict agreement (confirm vs override), triage feedback, review coverage, and
    the attack types analysts most often correct. Read-only aggregate."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT action, count(*) AS n FROM verdict_reviews GROUP BY action")
        by_action = {r["action"]: r["n"] for r in cur.fetchall()}
        confirms = int(by_action.get("confirm", 0))
        overrides = int(by_action.get("override", 0))
        total_reviews = confirms + overrides

        cur.execute("SELECT rating, count(*) AS n FROM triage_feedback GROUP BY rating")
        by_rating = {r["rating"]: r["n"] for r in cur.fetchall()}
        tri_correct = int(by_rating.get("correct", 0))
        tri_incorrect = int(by_rating.get("incorrect", 0))

        cur.execute("SELECT count(DISTINCT investigation_id) AS n FROM verdict_reviews")
        reviewed = int(cur.fetchone()["n"])
        cur.execute("SELECT count(*) AS n FROM alert_investigations")
        total_inv = int(cur.fetchone()["n"])

        cur.execute(
            "SELECT ai.attack_type AS attack_type, count(*) AS n "
            "FROM verdict_reviews vr JOIN alert_investigations ai ON ai.id = vr.investigation_id "
            "WHERE vr.action = 'override' GROUP BY ai.attack_type ORDER BY n DESC LIMIT 5"
        )
        top_corrected = cur.fetchall()

        cur.execute("SELECT count(*) AS n FROM soc_memory_vectors WHERE (analysis->>'human_reviewed') = 'true'")
        learned = int(cur.fetchone()["n"])

    agreement_pct = round(confirms / total_reviews * 100) if total_reviews else None
    tri_total = tri_correct + tri_incorrect
    triage_pct = round(tri_correct / tri_total * 100) if tri_total else None
    return {
        "confirms": confirms, "overrides": overrides, "total_reviews": total_reviews,
        "agreement_pct": agreement_pct,
        "triage_correct": tri_correct, "triage_incorrect": tri_incorrect, "triage_pct": triage_pct,
        "reviewed": reviewed, "total_investigations": total_inv,
        "coverage_pct": round(reviewed / total_inv * 100) if total_inv else 0,
        "learned_memories": learned,
        "top_corrected": top_corrected,
    }


def needs_attention(limit: int = 8) -> list[dict[str, Any]]:
    """High/critical OR flagged investigations that no analyst has reviewed yet
    (no verdict_reviews row). Most severe, then most recent, first — the
    'what needs me now' list on the Overview."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {_QUEUE_COLS} FROM alert_investigations ai "
            "WHERE (lower(ai.severity_label) IN ('high','critical') "
            "       OR ai.triage_action = 'create_flagged') "
            "AND NOT EXISTS (SELECT 1 FROM verdict_reviews vr "
            "                WHERE vr.investigation_id = ai.id) "
            "ORDER BY ai.severity_score DESC NULLS LAST, ai.created_at DESC "
            "LIMIT %s",
            (limit,),
        )
        return cur.fetchall()


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


# --- conversations (multi-chat) ---------------------------------------------
# Named, isolated chats layered on top of console_chat.thread_key. Each chat is
# its own thread with its own history; the shared SOC alert memory stays global.
# Every read/mutate is scoped to owner_username so an analyst can only reach
# their own conversations (the thread_key is NEVER trusted from the client).
def create_conversation(owner_username: str, title: str = "New chat") -> dict[str, Any]:
    """Mint a fresh thread_key and its conversation row. Returns the new row."""
    thread_key = f"{owner_username}:{secrets.token_hex(8)}"
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "INSERT INTO console_conversations (thread_key, owner_username, title) "
            "VALUES (%s, %s, %s) RETURNING id, thread_key, owner_username, title, created_at, updated_at",
            (thread_key, owner_username, title),
        )
        return cur.fetchone()


def list_conversations(owner_username: str) -> list[dict[str, Any]]:
    """An analyst's conversations, most-recent first, with message counts."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT c.id, c.thread_key, c.title, c.created_at, c.updated_at, "
            "  (SELECT count(*) FROM console_chat m WHERE m.thread_key = c.thread_key) AS message_count "
            "FROM console_conversations c WHERE c.owner_username = %s "
            "ORDER BY c.updated_at DESC, c.id DESC",
            (owner_username,),
        )
        return cur.fetchall()


def get_conversation(conversation_id: int, owner_username: str) -> Optional[dict[str, Any]]:
    """Fetch one conversation IFF it belongs to this analyst (authorization)."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, thread_key, owner_username, title, created_at, updated_at "
            "FROM console_conversations WHERE id = %s AND owner_username = %s",
            (conversation_id, owner_username),
        )
        return cur.fetchone()


def most_recent_conversation(owner_username: str) -> Optional[dict[str, Any]]:
    """The analyst's most-recently-active conversation (drives the dock)."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, thread_key, owner_username, title, created_at, updated_at "
            "FROM console_conversations WHERE owner_username = %s "
            "ORDER BY updated_at DESC, id DESC LIMIT 1",
            (owner_username,),
        )
        return cur.fetchone()


def rename_conversation(conversation_id: int, owner_username: str, title: str) -> bool:
    """Set a conversation's title (owner-scoped). Returns True if a row changed."""
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE console_conversations SET title = %s "
            "WHERE id = %s AND owner_username = %s",
            (title, conversation_id, owner_username),
        )
        return cur.rowcount > 0


def touch_conversation(conversation_id: int) -> None:
    """Bump updated_at so the conversation floats to the top after a new message."""
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE console_conversations SET updated_at = now() WHERE id = %s",
            (conversation_id,),
        )


def delete_conversation(conversation_id: int, owner_username: str) -> bool:
    """Delete a conversation and its messages (owner-scoped, one transaction).
    console_chat allows DELETE (only UPDATE is trigger-blocked)."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT thread_key FROM console_conversations "
            "WHERE id = %s AND owner_username = %s",
            (conversation_id, owner_username),
        )
        row = cur.fetchone()
        if row is None:
            return False
        cur.execute("DELETE FROM console_chat WHERE thread_key = %s", (row["thread_key"],))
        cur.execute("DELETE FROM console_conversations WHERE id = %s", (conversation_id,))
        return True
