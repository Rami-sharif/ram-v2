"""Semantic memory layer (pgvector RAG).

LOCKED pipeline (must stay byte-identical for stored data to remain valid):
  - model gemini-embedding-001, outputDimensionality=768, task_type=SEMANTIC_SIMILARITY
  - client-side L2 unit-normalization, applied symmetrically at insert AND query
  - identity string: "Rule: <desc> | SrcIP: <ip> | Groups: <groups> | Log: <full_log>"

Changing model/dim/normalization/identity-format requires re-embedding every row.
"""
import logging
import math
from datetime import datetime
from typing import Any, Optional

from google import genai
from google.genai import types
from psycopg.rows import dict_row
from psycopg.types.json import Json

from .config import get_settings
from .db import get_pool, vector_literal
from .schemas import AnalysisResult, WazuhAlert

logger = logging.getLogger(__name__)

_client: genai.Client | None = None


def _genai() -> genai.Client:
    global _client
    if _client is None:
        _client = genai.Client(api_key=get_settings().gemini_api_key)
    return _client


# --------------------------------------------------------------------------- #
# Embedding (the single, locked entry point used everywhere)
# --------------------------------------------------------------------------- #
def _l2_normalize(vec: list[float]) -> list[float]:
    norm = math.sqrt(sum(x * x for x in vec))
    if norm == 0.0:
        raise ValueError("cannot normalize a zero-norm embedding")
    return [x / norm for x in vec]


def embed(text: str) -> list[float]:
    """Embed text with the locked pipeline and return an L2-normalized vector."""
    s = get_settings()
    resp = _genai().models.embed_content(
        model=s.embedding_model,
        contents=text,
        config=types.EmbedContentConfig(
            output_dimensionality=s.embedding_dim,
            task_type=s.embedding_task_type,
        ),
    )
    vec = list(resp.embeddings[0].values)
    if len(vec) != s.embedding_dim:
        raise ValueError(f"expected {s.embedding_dim}-dim embedding, got {len(vec)}")
    return _l2_normalize(vec)


# --------------------------------------------------------------------------- #
# Identity string (locked format) + field extraction
# --------------------------------------------------------------------------- #
def source_ip_of(alert: WazuhAlert) -> str:
    return (alert.data or {}).get("srcip") or ""


def identity_string(alert: WazuhAlert) -> str:
    rule_desc = alert.rule.description or ""
    groups = ",".join(alert.rule.groups or [])
    return (
        f"Rule: {rule_desc} | SrcIP: {source_ip_of(alert)} "
        f"| Groups: {groups} | Log: {alert.full_log or ''}"
    )


def parse_alert_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """Parse Wazuh timestamps; return None if absent/unparseable (caller falls
    back to created_at for recency ordering)."""
    if not ts:
        return None
    candidates = (
        lambda s: datetime.fromisoformat(s),
        lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z"),
        lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z"),
    )
    for parse in candidates:
        try:
            return parse(ts)
        except (ValueError, TypeError):
            continue
    logger.warning("Unparseable alert timestamp %r; storing NULL", ts)
    return None


# --------------------------------------------------------------------------- #
# Retrieval (hybrid: top-K similar + last-N recent, scoped by agent_name)
# --------------------------------------------------------------------------- #
_SELECT_COLS = (
    "id, agent_name, source_ip, rule_id, alert_text, analysis, "
    "alert_timestamp, created_at"
)


def retrieve(agent_name: str, query_vec: list[float],
             k: Optional[int] = None, n: Optional[int] = None) -> list[dict[str, Any]]:
    """Return prior memories for this host: top-K most similar first, then
    last-N most recent (by event time, falling back to store time), deduped by id."""
    s = get_settings()
    k = k or s.memory_top_k
    n = n or s.memory_recent_n
    qv = vector_literal(query_vec)

    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {_SELECT_COLS}, 1 - (embedding <=> %s::vector) AS similarity "
            "FROM soc_memory_vectors WHERE agent_name = %s "
            "ORDER BY embedding <=> %s::vector LIMIT %s",
            (qv, agent_name, qv, k),
        )
        similar = cur.fetchall()
        cur.execute(
            f"SELECT {_SELECT_COLS}, NULL::float8 AS similarity "
            "FROM soc_memory_vectors WHERE agent_name = %s "
            "ORDER BY COALESCE(alert_timestamp, created_at) DESC LIMIT %s",
            (agent_name, n),
        )
        recent = cur.fetchall()

    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    for r in similar:  # already ordered by ascending distance == descending similarity
        r["is_similar"] = True
        seen.add(r["id"])
        out.append(r)
    for r in recent:  # event-time desc; only those not already included
        if r["id"] in seen:
            continue
        r["is_similar"] = False
        out.append(r)
    return out


def format_memories_for_prompt(memories: list[dict[str, Any]]) -> str:
    if not memories:
        return "No prior related alerts recorded for this host."
    lines = []
    for m in memories:
        a = m.get("analysis") or {}
        if m.get("is_similar") and m.get("similarity") is not None:
            tag = f"similar={m['similarity']:.3f}"
        else:
            tag = "recent"
        when = m.get("alert_timestamp") or m.get("created_at")
        line = (
            f"- [{tag}] {when} | {m['alert_text']} "
            f"=> severity={a.get('severity_label')}({a.get('severity_score')}), "
            f"attack={a.get('attack_type')}, action={a.get('recommended_action')}"
        )
        # Human ground truth (the learning loop): if an analyst reviewed a similar
        # prior alert, surface their verdict prominently so the agent can weight it.
        if a.get("human_reviewed"):
            hv = a.get("human_verdict") or {}
            if a.get("human_action") == "override":
                line += (
                    f"  ✎ ANALYST-CORRECTED → severity={hv.get('severity_label')}"
                    f"({hv.get('severity_score')}), attack={hv.get('attack_type')}"
                    f" [by {a.get('reviewed_by')}]"
                )
            else:
                line += f"  ✓ ANALYST-CONFIRMED [by {a.get('reviewed_by')}]"
        lines.append(line)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Learning loop: fold an analyst's verdict back into the alert's memory row.
# --------------------------------------------------------------------------- #
def record_human_verdict(investigation: dict[str, Any], *, action: str,
                         override_payload: Optional[dict[str, Any]],
                         actor: str) -> Optional[dict[str, Any]]:
    """Stamp an analyst's confirm/override onto the memory row for this alert, so
    future retrievals of similar alerts carry human ground truth. Reuses
    update_analysis (NO re-embed — the vector is built from the alert identity).
    Best-effort by contract: the caller wraps this and never fails the verdict on
    a memory error. Returns the updated memory row, or None if nothing to update."""
    memory_id = investigation.get("memory_id")
    if not memory_id:
        return None  # pre-loop investigation (no linked memory row) — nothing to teach
    row = get_memory(memory_id)
    if row is None:
        return None
    payload = override_payload or {}
    if action == "override":
        verdict = {
            "severity_label": payload.get("severity_label") or investigation.get("severity_label"),
            "severity_score": payload.get("severity_score")
                if payload.get("severity_score") is not None else investigation.get("severity_score"),
            "attack_type": payload.get("attack_type") or investigation.get("attack_type"),
        }
    else:  # confirm: the agent's own verdict is now analyst-confirmed ground truth
        verdict = {
            "severity_label": investigation.get("severity_label"),
            "severity_score": investigation.get("severity_score"),
            "attack_type": investigation.get("attack_type"),
        }
    analysis = dict(row.get("analysis") or {})
    analysis.update({
        "human_reviewed": True,
        "human_action": action,
        "human_verdict": verdict,
        "reviewed_by": actor,
    })
    logger.info("Learning loop: memory id=%s stamped human_%s by %s", memory_id, action, actor)
    return update_analysis(memory_id, analysis)


# --------------------------------------------------------------------------- #
# Write-back (reuses the embedding already computed for retrieval)
# --------------------------------------------------------------------------- #
def write_back(alert: WazuhAlert, identity: str, analysis: AnalysisResult,
               embedding: list[float]) -> int:
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO soc_memory_vectors "
            "(agent_name, source_ip, rule_id, alert_text, analysis, embedding, alert_timestamp) "
            "VALUES (%s, %s, %s, %s, %s, %s::vector, %s) RETURNING id",
            (
                alert.agent.name or "unknown",
                source_ip_of(alert) or None,
                alert.rule.id,
                identity,
                Json(analysis.model_dump()),
                vector_literal(embedding),
                parse_alert_timestamp(alert.timestamp),
            ),
        )
        new_id = cur.fetchone()[0]
    logger.info("Wrote memory row id=%s (agent=%s, src=%s)",
                new_id, alert.agent.name, source_ip_of(alert))
    return new_id


# --------------------------------------------------------------------------- #
# Operator CRUD (used by the authenticated /memory endpoints, not the webhook)
# --------------------------------------------------------------------------- #
def list_memories(
    agent_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    rule_id: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    reviewed_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    clauses, params = [], []
    if agent_name:
        clauses.append("agent_name = %s"); params.append(agent_name)
    if source_ip:
        clauses.append("source_ip = %s"); params.append(source_ip)
    if rule_id:
        clauses.append("rule_id = %s"); params.append(rule_id)
    if reviewed_only:
        clauses.append("(analysis->>'human_reviewed') = 'true'")
    if date_from:
        clauses.append("COALESCE(alert_timestamp, created_at) >= %s"); params.append(date_from)
    if date_to:
        clauses.append("COALESCE(alert_timestamp, created_at) <= %s"); params.append(date_to)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.extend([limit, offset])
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {_SELECT_COLS} FROM soc_memory_vectors {where} "
            "ORDER BY COALESCE(alert_timestamp, created_at) DESC LIMIT %s OFFSET %s",
            params,
        )
        return cur.fetchall()


def get_memory(memory_id: int) -> Optional[dict[str, Any]]:
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {_SELECT_COLS} FROM soc_memory_vectors WHERE id = %s", (memory_id,)
        )
        return cur.fetchone()


def search_memories(query: str, agent_name: Optional[str] = None,
                    k: int = 5) -> list[dict[str, Any]]:
    """Semantic search: embed the query with the locked pipeline, return nearest."""
    qv = vector_literal(embed(query))
    clause = "WHERE agent_name = %s" if agent_name else ""
    params: list[Any] = [qv]
    if agent_name:
        params.append(agent_name)
    params.extend([qv, k])
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {_SELECT_COLS}, 1 - (embedding <=> %s::vector) AS similarity "
            f"FROM soc_memory_vectors {clause} "
            "ORDER BY embedding <=> %s::vector LIMIT %s",
            params,
        )
        return cur.fetchall()


def update_analysis(memory_id: int, analysis: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Update ONLY the analysis field. The embedding is NOT touched (the vector is
    built from the alert identity, not the analysis)."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"UPDATE soc_memory_vectors SET analysis = %s WHERE id = %s "
            f"RETURNING {_SELECT_COLS}",
            (Json(analysis), memory_id),
        )
        return cur.fetchone()


def reembed_identity(memory_id: int, new_alert_text: str) -> Optional[dict[str, Any]]:
    """Update the identity text AND re-embed it with the exact same pipeline.
    Required whenever an edit touches the identity fields."""
    new_vec = vector_literal(embed(new_alert_text))
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"UPDATE soc_memory_vectors SET alert_text = %s, embedding = %s::vector "
            f"WHERE id = %s RETURNING {_SELECT_COLS}",
            (new_alert_text, new_vec, memory_id),
        )
        return cur.fetchone()


def delete_memory(memory_id: int) -> bool:
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM soc_memory_vectors WHERE id = %s", (memory_id,))
        return cur.rowcount > 0
