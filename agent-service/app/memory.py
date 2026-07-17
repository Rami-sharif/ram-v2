"""Semantic memory layer (pgvector RAG).

WHAT THIS FILE IS, FOR A NEWCOMER:
This is the agent's long-term memory of past alerts, built with "embeddings". An embedding
is a list of numbers (a "vector") that captures the MEANING of a piece of text. Texts that
mean similar things get vectors that point in similar directions, so we can measure how
alike two alerts are just by comparing their vectors — even when they use different words.
We turn each alert into a vector (via Gemini's embedding model), store it in Postgres using
the "pgvector" extension (which adds a vector column type and fast nearest-neighbor search),
and later, for a new alert, fetch the most similar past alerts. Feeding those retrieved
memories into the agent's prompt is "RAG" (Retrieval-Augmented Generation): the model
answers with real history in front of it instead of guessing.

LOCKED pipeline (must stay byte-identical for stored data to remain valid). "Locked" means
these choices are frozen: every stored vector was produced this exact way, and comparisons
only make sense between vectors made identically, so changing any of it invalidates old data:
  - model gemini-embedding-001, outputDimensionality=768 (each vector has 768 numbers),
    task_type=SEMANTIC_SIMILARITY (tells Gemini we want vectors tuned for "how alike is
    the meaning", as opposed to, say, question-answering)
  - client-side L2 unit-normalization, applied symmetrically at insert AND query (see
    _l2_normalize below — scaling every vector to length 1 so distance == angle)
  - identity string: "Rule: <desc> | SrcIP: <ip> | Groups: <groups> | Log: <full_log>"
    (the fixed text template we embed for each alert, so all alerts are compared on the
    same fields in the same order)

Changing model/dim/normalization/identity-format requires re-embedding every row.
"""
import logging  # stdlib logging
import math  # used for the L2 norm (sqrt of sum of squares)
from datetime import datetime  # type hints / parsing for alert and record timestamps
from typing import Any, Optional  # loose typing for dict payloads and nullable fields

from google import genai  # Gemini SDK client, used here for embeddings
from google.genai import types  # Gemini SDK request type constructors (EmbedContentConfig)
from psycopg.rows import dict_row  # cursor row factory returning dict rows
from psycopg.types.json import Json  # wraps Python dicts for JSONB columns

from .config import get_settings  # accessor for embedding model/dim/task_type and memory retrieval sizes
from .db import get_pool, vector_literal  # connection pool + pgvector literal formatter
from .schemas import AnalysisResult, WazuhAlert  # typed models for the alert and its analysis

logger = logging.getLogger(__name__)  # module logger

_client: genai.Client | None = None  # lazily-initialized singleton Gemini client for embeddings


def _genai() -> genai.Client:
    global _client  # modifying the module-level singleton
    if _client is None:
        # Create the client once, on first use, using the configured API key
        _client = genai.Client(api_key=get_settings().gemini_api_key)
    return _client


# --------------------------------------------------------------------------- #
# Embedding (the single, locked entry point used everywhere)
# --------------------------------------------------------------------------- #
def _l2_normalize(vec: list[float]) -> list[float]:
    # "Normalizing" a vector means shrinking/growing it to length 1 while keeping its
    # direction. Why: once every vector has the same length, the ONLY thing that differs is
    # direction, so "how similar" reduces cleanly to the angle between vectors (cosine
    # similarity). Doing this on both stored and query vectors makes the distance math
    # consistent. The L2 norm is just the vector's length: sqrt(x1^2 + x2^2 + ...).
    norm = math.sqrt(sum(x * x for x in vec))  # Euclidean (L2) norm of the vector
    if norm == 0.0:
        # A zero vector can't be normalized (division by zero) — treat as a hard error
        raise ValueError("cannot normalize a zero-norm embedding")
    return [x / norm for x in vec]  # scale every component so the vector has unit length


def embed(text: str) -> list[float]:
    """Embed text with the locked pipeline and return an L2-normalized vector.

    "Embed" = turn text into its meaning-vector. This is the one and only place we call the
    embedding model, so every vector in the system is produced identically (that's the
    "locked pipeline"). Used both when storing a new alert and when searching for similar
    ones — the same text always maps to the same vector."""
    s = get_settings()  # settings holding the locked model name/dimension/task type
    # Call Gemini's embedding endpoint with the exact locked configuration
    resp = _genai().models.embed_content(
        model=s.embedding_model,
        contents=text,
        config=types.EmbedContentConfig(
            output_dimensionality=s.embedding_dim,
            task_type=s.embedding_task_type,
        ),
    )
    vec = list(resp.embeddings[0].values)  # extract the raw embedding vector from the response
    if len(vec) != s.embedding_dim:
        # Sanity check: the API must return exactly the configured dimensionality
        raise ValueError(f"expected {s.embedding_dim}-dim embedding, got {len(vec)}")
    return _l2_normalize(vec)  # normalize before returning, per the locked pipeline contract


# --------------------------------------------------------------------------- #
# Identity string (locked format) + field extraction
# --------------------------------------------------------------------------- #
def source_ip_of(alert: WazuhAlert) -> str:
    # Extract the source IP from the alert's free-form data dict, defaulting to "" if absent
    return (alert.data or {}).get("srcip") or ""


def identity_string(alert: WazuhAlert) -> str:
    # Build the single piece of text that REPRESENTS an alert for embedding. Every alert is
    # boiled down to these same fields in this same order, so two alerts are compared on a
    # like-for-like basis. This exact format is part of the locked pipeline (see module docstring).
    rule_desc = alert.rule.description or ""  # rule description, defaulting to empty string
    groups = ",".join(alert.rule.groups or [])  # comma-join rule groups, defaulting to empty list
    # Build the exact locked identity-string format used for both embedding input and display
    return (
        f"Rule: {rule_desc} | SrcIP: {source_ip_of(alert)} "
        f"| Groups: {groups} | Log: {alert.full_log or ''}"
    )


def parse_alert_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """Parse Wazuh timestamps; return None if absent/unparseable (caller falls
    back to created_at for recency ordering)."""
    if not ts:
        return None  # no timestamp string to parse at all
    # Try several known Wazuh timestamp formats in order, using lambdas so each is tried lazily
    candidates = (
        lambda s: datetime.fromisoformat(s),
        lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z"),
        lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z"),
    )
    for parse in candidates:
        try:
            return parse(ts)  # return on the first format that parses successfully
        except (ValueError, TypeError):
            continue  # try the next format
    # None of the formats matched — log a warning and let the caller fall back to created_at
    logger.warning("Unparseable alert timestamp %r; storing NULL", ts)
    return None


# --------------------------------------------------------------------------- #
# Retrieval (hybrid: top-K similar + last-N recent, scoped by agent_name)
# --------------------------------------------------------------------------- #
# Shared column list reused by every SELECT against soc_memory_vectors, so the shape stays consistent
_SELECT_COLS = (
    "id, agent_name, source_ip, rule_id, alert_text, analysis, "
    "alert_timestamp, created_at"
)


def retrieve(agent_name: str, query_vec: list[float],
             k: Optional[int] = None, n: Optional[int] = None) -> list[dict[str, Any]]:
    """Return prior memories for this host: top-K most similar first, then
    last-N most recent (by event time, falling back to store time), deduped by id.

    This is the "retrieval" step of RAG. We combine two ideas: (1) the K alerts whose
    vectors are CLOSEST to the current alert's vector (most alike in meaning — this is the
    "nearest-neighbor" search), and (2) the N most RECENT alerts on the same host, so the
    agent always sees fresh context even if nothing is semantically similar. `agent_name`
    scopes everything to one host so memories don't bleed across machines."""
    s = get_settings()  # settings for default k/n if not explicitly passed
    k = k or s.memory_top_k  # number of nearest-neighbor results to fetch
    n = n or s.memory_recent_n  # number of most-recent results to fetch
    qv = vector_literal(query_vec)  # format the query vector for use in the SQL string

    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # `<=>` is pgvector's cosine-distance operator: 0 means identical direction (very
        # similar), larger means less similar. We convert to a friendlier "similarity" score
        # with `1 - distance`, so 1.0 == a perfect match and lower == less alike. ORDER BY the
        # distance ascending + LIMIT k gives the k nearest neighbors (the most similar alerts).
        # Top-K by cosine distance (<=>) among rows scoped to this host, with similarity = 1 - distance
        cur.execute(
            f"SELECT {_SELECT_COLS}, 1 - (embedding <=> %s::vector) AS similarity "
            "FROM soc_memory_vectors WHERE agent_name = %s "
            "ORDER BY embedding <=> %s::vector LIMIT %s",
            (qv, agent_name, qv, k),
        )
        similar = cur.fetchall()  # the K nearest-neighbor rows
        # Last-N most recent rows for the same host, ordered by event time (falling back to store time)
        cur.execute(
            f"SELECT {_SELECT_COLS}, NULL::float8 AS similarity "
            "FROM soc_memory_vectors WHERE agent_name = %s "
            "ORDER BY COALESCE(alert_timestamp, created_at) DESC LIMIT %s",
            (agent_name, n),
        )
        recent = cur.fetchall()  # the N most recent rows

    # Merge the two result sets. The same alert can show up in BOTH the "similar" and the
    # "recent" lists, so we track ids we've already added and skip repeats (dedupe).
    out: list[dict[str, Any]] = []  # combined, deduped result list
    seen: set[int] = set()  # ids already included, to avoid duplicates between the two queries
    for r in similar:  # already ordered by ascending distance == descending similarity
        r["is_similar"] = True  # tag each similar-match row for downstream formatting
        seen.add(r["id"])
        out.append(r)
    for r in recent:  # event-time desc; only those not already included
        if r["id"] in seen:
            continue  # skip rows already added via the similarity query
        r["is_similar"] = False  # tag as a recency-based (not similarity-based) match
        out.append(r)
    return out


def format_memories_for_prompt(memories: list[dict[str, Any]]) -> str:
    # Turn the retrieved memory rows into a compact block of plain text that gets pasted into
    # the agent's prompt (the "augmented" part of RAG). The model can't read database rows, so
    # we render each one as a readable bullet line summarizing what happened and how it was rated.
    if not memories:
        return "No prior related alerts recorded for this host."  # explicit "nothing found" message for the prompt
    lines = []
    for m in memories:
        a = m.get("analysis") or {}  # the stored analysis JSON for this memory row
        if m.get("is_similar") and m.get("similarity") is not None:
            tag = f"similar={m['similarity']:.3f}"  # show the similarity score to 3 decimals
        else:
            tag = "recent"  # recency-based match, no similarity score to show
        when = m.get("alert_timestamp") or m.get("created_at")  # prefer event time, fall back to store time
        # Build the base summary line: tag, timestamp, alert text, and the agent's original verdict
        line = (
            f"- [{tag}] {when} | {m['alert_text']} "
            f"=> severity={a.get('severity_label')}({a.get('severity_score')}), "
            f"attack={a.get('attack_type')}, action={a.get('recommended_action')}"
        )
        # Human ground truth (the learning loop): if an analyst reviewed a similar
        # prior alert, surface their verdict prominently so the agent can weight it.
        if a.get("human_reviewed"):
            hv = a.get("human_verdict") or {}  # the analyst's corrected/confirmed verdict, if any
            if a.get("human_action") == "override":
                # Analyst corrected the agent's original verdict — show the corrected values
                line += (
                    f"  ✎ ANALYST-CORRECTED → severity={hv.get('severity_label')}"
                    f"({hv.get('severity_score')}), attack={hv.get('attack_type')}"
                    f" [by {a.get('reviewed_by')}]"
                )
            else:
                # Analyst confirmed the agent's original verdict as-is
                line += f"  ✓ ANALYST-CONFIRMED [by {a.get('reviewed_by')}]"
        lines.append(line)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Learning loop: fold an analyst's verdict back into the alert's memory row.
#
# This is how the system "learns" from humans without any model retraining. When an analyst
# confirms or corrects the agent's verdict, we write that decision onto the stored memory.
# Later, when a SIMILAR alert is retrieved, the agent sees "a human already judged this kind
# of alert THIS way" and can align with it — a cheap, transparent feedback loop.
# --------------------------------------------------------------------------- #
def record_human_verdict(investigation: dict[str, Any], *, action: str,
                         override_payload: Optional[dict[str, Any]],
                         actor: str) -> Optional[dict[str, Any]]:
    """Stamp an analyst's confirm/override onto the memory row for this alert, so
    future retrievals of similar alerts carry human ground truth ("ground truth" = the
    trusted, human-verified answer we compare against). Reuses update_analysis (NO
    re-embed — the vector is built from the alert IDENTITY, which hasn't changed; only the
    verdict/analysis text changes, so the meaning-vector stays valid and we save an API call).
    Best-effort by contract: the caller wraps this and never fails the verdict on
    a memory error. Returns the updated memory row, or None if nothing to update."""
    memory_id = investigation.get("memory_id")  # the linked soc_memory_vectors row, if this investigation has one
    if not memory_id:
        return None  # pre-loop investigation (no linked memory row) — nothing to teach
    row = get_memory(memory_id)  # fetch the current memory row
    if row is None:
        return None  # row vanished (e.g. deleted) — nothing to update
    payload = override_payload or {}  # analyst-supplied override values, if action == "override"
    if action == "override":
        # Build the corrected verdict, preferring the analyst's explicit override fields over the original
        verdict = {
            "severity_label": payload.get("severity_label") or investigation.get("severity_label"),
            "severity_score": payload.get("severity_score")
                if payload.get("severity_score") is not None else investigation.get("severity_score"),
            "attack_type": payload.get("attack_type") or investigation.get("attack_type"),
        }
    else:  # confirm: the agent's own verdict is now analyst-confirmed ground truth
        # No override — just restate the agent's original verdict as now analyst-confirmed
        verdict = {
            "severity_label": investigation.get("severity_label"),
            "severity_score": investigation.get("severity_score"),
            "attack_type": investigation.get("attack_type"),
        }
    analysis = dict(row.get("analysis") or {})  # copy the existing analysis JSON so we don't mutate the fetched row in place
    # Stamp the human-review metadata onto the analysis blob
    analysis.update({
        "human_reviewed": True,
        "human_action": action,
        "human_verdict": verdict,
        "reviewed_by": actor,
    })
    logger.info("Learning loop: memory id=%s stamped human_%s by %s", memory_id, action, actor)
    return update_analysis(memory_id, analysis)  # persist the updated analysis (embedding untouched)


# --------------------------------------------------------------------------- #
# Write-back (reuses the embedding already computed for retrieval)
#
# "Write-back" = after the agent finishes investigating, we save this alert + its verdict
# into memory so it becomes context for FUTURE alerts. This is what makes the memory grow
# over time. We pass in the embedding that was already computed during retrieval instead of
# calling the embedding model a second time — saving an API call and guaranteeing the stored
# and searched vectors are identical.
# --------------------------------------------------------------------------- #
def write_back(alert: WazuhAlert, identity: str, analysis: AnalysisResult,
               embedding: list[float]) -> int:
    with get_pool().connection() as conn, conn.cursor() as cur:
        # Insert a new memory row: alert identity fields, the analysis JSON, and the precomputed embedding
        cur.execute(
            "INSERT INTO soc_memory_vectors "
            "(agent_name, source_ip, rule_id, alert_text, analysis, embedding, alert_timestamp) "
            "VALUES (%s, %s, %s, %s, %s, %s::vector, %s) RETURNING id",
            (
                alert.agent.name or "unknown",
                source_ip_of(alert) or None,  # store NULL rather than "" when there's no source IP
                alert.rule.id,
                identity,  # the locked-format identity string (also used to generate the embedding)
                Json(analysis.model_dump()),  # serialize the analysis model into JSONB
                vector_literal(embedding),  # format the already-normalized embedding for pgvector
                parse_alert_timestamp(alert.timestamp),  # parsed event time, or NULL if unparseable
            ),
        )
        new_id = cur.fetchone()[0]  # the id of the newly inserted row
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
    clauses, params = [], []  # dynamically built WHERE clauses and their bound parameters
    if agent_name:
        clauses.append("agent_name = %s"); params.append(agent_name)  # filter by host name
    if source_ip:
        clauses.append("source_ip = %s"); params.append(source_ip)  # filter by source IP
    if rule_id:
        clauses.append("rule_id = %s"); params.append(rule_id)  # filter by Wazuh rule id
    if reviewed_only:
        # Filter to only rows whose analysis JSON has been stamped human_reviewed=true
        clauses.append("(analysis->>'human_reviewed') = 'true'")
    if date_from:
        clauses.append("COALESCE(alert_timestamp, created_at) >= %s"); params.append(date_from)  # lower time bound
    if date_to:
        clauses.append("COALESCE(alert_timestamp, created_at) <= %s"); params.append(date_to)  # upper time bound
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""  # assemble the WHERE clause, or none if no filters
    params.extend([limit, offset])  # pagination params appended last to match the LIMIT/OFFSET placeholders
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {_SELECT_COLS} FROM soc_memory_vectors {where} "
            "ORDER BY COALESCE(alert_timestamp, created_at) DESC LIMIT %s OFFSET %s",
            params,
        )
        return cur.fetchall()  # paginated, filtered, most-recent-first list of memory rows


def get_memory(memory_id: int) -> Optional[dict[str, Any]]:
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # Fetch a single memory row by primary key
        cur.execute(
            f"SELECT {_SELECT_COLS} FROM soc_memory_vectors WHERE id = %s", (memory_id,)
        )
        return cur.fetchone()  # None if no such row exists


def search_memories(query: str, agent_name: Optional[str] = None,
                    k: int = 5) -> list[dict[str, Any]]:
    """Semantic search: embed the query with the locked pipeline, return nearest.

    Operator-facing search over stored memories by MEANING, not keywords. We embed the typed
    query the same way we embedded the alerts, then find the vectors closest to it — so
    searching "failed logins" can match an alert stored as "brute force attempt" even with no
    shared words."""
    qv = vector_literal(embed(query))  # embed the free-text query and format it for pgvector
    clause = "WHERE agent_name = %s" if agent_name else ""  # optional host scoping
    params: list[Any] = [qv]  # first placeholder: the similarity SELECT's query vector
    if agent_name:
        params.append(agent_name)  # bind the host filter if present
    params.extend([qv, k])  # second query-vector placeholder (for ORDER BY) plus the result limit
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {_SELECT_COLS}, 1 - (embedding <=> %s::vector) AS similarity "
            f"FROM soc_memory_vectors {clause} "
            "ORDER BY embedding <=> %s::vector LIMIT %s",
            params,
        )
        return cur.fetchall()  # nearest-neighbor rows with similarity scores


def update_analysis(memory_id: int, analysis: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Update ONLY the analysis field. The embedding is NOT touched (the vector is
    built from the alert identity, not the analysis)."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # Overwrite the analysis JSONB column and return the updated row in one round trip
        cur.execute(
            f"UPDATE soc_memory_vectors SET analysis = %s WHERE id = %s "
            f"RETURNING {_SELECT_COLS}",
            (Json(analysis), memory_id),
        )
        return cur.fetchone()  # None if no row matched memory_id


def reembed_identity(memory_id: int, new_alert_text: str) -> Optional[dict[str, Any]]:
    """Update the identity text AND re-embed it with the exact same pipeline.
    Required whenever an edit touches the identity fields.

    Contrast with update_analysis (which never re-embeds): the vector is derived from the
    identity text, so if that text changes the OLD vector no longer represents it and future
    similarity searches would be wrong. So here we must recompute the vector to keep the
    stored text and its meaning-vector in sync."""
    new_vec = vector_literal(embed(new_alert_text))  # recompute the embedding for the corrected identity text
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # Update both alert_text and embedding together so they never drift out of sync
        cur.execute(
            f"UPDATE soc_memory_vectors SET alert_text = %s, embedding = %s::vector "
            f"WHERE id = %s RETURNING {_SELECT_COLS}",
            (new_alert_text, new_vec, memory_id),
        )
        return cur.fetchone()  # None if no row matched memory_id


def delete_memory(memory_id: int) -> bool:
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM soc_memory_vectors WHERE id = %s", (memory_id,))  # delete the single row by id
        return cur.rowcount > 0  # True only if a row actually existed and was removed


def delete_memories(memory_ids: list[int]) -> list[int]:
    """Delete several memory rows in one statement. Returns the ids that existed and
    were actually removed (the caller audits each one BEFORE calling this, so a row
    that vanished meanwhile simply never appears in the returned list)."""
    if not memory_ids:
        return []  # nothing to do for an empty id list
    with get_pool().connection() as conn, conn.cursor() as cur:
        # Bulk delete using ANY(%s) against the array of ids, returning the ids that actually matched
        cur.execute(
            "DELETE FROM soc_memory_vectors WHERE id = ANY(%s) RETURNING id",
            (memory_ids,),
        )
        return [r[0] for r in cur.fetchall()]  # flatten the single-column result rows into a plain id list
