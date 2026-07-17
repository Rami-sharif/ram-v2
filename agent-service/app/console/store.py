"""Console data access: users and audit log (Step A). Other console queries
(investigations, feedback) are added in later steps.

This module is the "data access layer" — the ONLY place that talks to the
PostgreSQL database. Every function here opens a database connection, runs one or
more SQL commands, and hands plain Python values back to the rest of the app. The
rest of the code never writes SQL itself; it calls these functions instead. That
keeps all the database knowledge in one file.

A few database ideas used throughout, in plain English:
- A "connection" is an open line to the database. A "cursor" is the little handle
  you use on that connection to run one SQL statement and read its results.
- A "transaction" is a group of writes that either ALL succeed or ALL get undone
  (rolled back). Using Python's `with` block around a connection here means the
  transaction commits automatically at the end if no error was raised, and rolls
  back if one was — so we never leave the database half-updated.
- We use %s "placeholders" in SQL and pass the real values separately. The
  database driver fills them in safely. This prevents "SQL injection", where a
  malicious value like `' OR 1=1 --` could otherwise change what the query does.

The audit_log write is the spine of accountability — every consequential analyst
action calls write_audit() with the named actor (audit = a permanent, tamper-
evident record of who did what and when).
"""
import logging  # module logger, mainly used for audit-trail log lines
import secrets  # used to mint unguessable conversation thread keys
from typing import Any, Optional  # type hints for loosely-typed JSON-ish values and nullable results

# psycopg is the PostgreSQL driver (the library that actually speaks to the DB).
# A "row factory" decides what shape each returned row takes. dict_row makes each
# row a Python dict keyed by column name (row["username"]) instead of a plain
# tuple you'd have to index by position (row[1]) — much easier to read.
from psycopg.rows import dict_row  # row factory so query results come back as dicts, not tuples
# Json() tells psycopg "store this Python value as JSON/JSONB". JSONB is a
# PostgreSQL column type that holds arbitrary structured data (dicts/lists) inside
# one column — handy for the agent's free-form analysis output.
from psycopg.types.json import Json  # wraps Python values so psycopg stores them as JSON/JSONB

# A connection pool is a small set of already-open database connections kept ready
# for reuse. Opening a fresh DB connection is slow, so the whole service borrows
# one from the pool, uses it, and returns it — much faster than reconnecting each
# time. get_pool() hands back that shared pool.
from ..db import get_pool  # shared connection pool for the whole service

logger = logging.getLogger(__name__)  # module-scoped logger


# --- users ------------------------------------------------------------------
def get_user(username: str) -> Optional[dict[str, Any]]:
    # Borrow a connection from the pool and open a cursor on it, both scoped to
    # this `with` block: when the block ends they are automatically returned/closed
    # (and the transaction committed). This one uses a dict-row cursor so the result
    # is a dict keyed by column name.
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # Run a SELECT (a read). %s is a placeholder; the real username is passed
        # separately below so it can't be interpreted as SQL (SQL-injection safe).
        # Returns one user's login/profile columns matching the given username.
        cur.execute(
            "SELECT id, username, password_hash, display_name, role, disabled "
            "FROM users WHERE username = %s",
            (username,),  # parameterized to avoid SQL injection
        )
        # fetchone() returns the first (here, only) matching row, or None if none.
        return cur.fetchone()  # None if no such username exists


def create_user(username: str, password_hash: str, display_name: str, role: str) -> int:
    # Plain (non-dict) cursor here since we only need the returned id, not a dict row
    with get_pool().connection() as conn, conn.cursor() as cur:
        # INSERT adds a new row. RETURNING id asks PostgreSQL to hand back the id it
        # auto-generated for that new row, so we don't need a second query to find it.
        cur.execute(
            "INSERT INTO users (username, password_hash, display_name, role) "
            "VALUES (%s, %s, %s, %s) RETURNING id",
            (username, password_hash, display_name, role),  # password_hash is already hashed by caller
        )
        # With a plain cursor a row is a tuple, so [0] is the first (only) column: id
        return cur.fetchone()[0]  # the new row's id


# --- alert investigations (write-once agent output) -------------------------
# Domain terms, explained once: an "alert" is a security warning raised by a
# detector (here, Wazuh). "Triage" is deciding how urgent each alert is and what
# to do with it. "Severity" is that urgency rating (info/low/medium/high/critical).
# "Write-once" means: once the AI agent's investigation of an alert is saved, that
# row is never edited again — a database trigger blocks UPDATE — so the recorded
# machine verdict stays exactly as it was made. Human follow-up lives in separate
# tables instead of overwriting it.
#
# All arguments are keyword-only (the `*`) to avoid mis-ordering the many
# positional fields; the last four are optional (default None) since they only
# apply in specific cases (memory linking / failed case creation replay data).
def record_investigation(
    *, alert_id, agent_name, source_ip, rule_id, severity_score, severity_label,
    attack_type, analysis, tool_trace, memory_context, retrieved_ids,
    triage_action, triage_branch, occurrence_count, suppressed, case_id, case_number,
    memory_id=None, case_error=None, alert_payload=None, enrichment=None,
    duration_ms=None,
) -> int:
    """Insert the agent's output for one alert. Write-once: the row is never
    UPDATEd (DB trigger enforces this). Human input lives in separate tables.
    memory_id links this alert's own semantic-memory row so a later analyst
    verdict can teach it back (the learning loop).

    case_error / alert_payload / enrichment capture a FAILED case creation and the
    inputs needed to replay it, so a case-creating alert that TheHive refused can
    still be linked later (see console case retry). All three are insert-time
    values, so the write-once guarantee is untouched."""
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute(
            # Single INSERT covering every column of the write-once record
            "INSERT INTO alert_investigations ("
            " alert_id, agent_name, source_ip, rule_id, severity_score, severity_label,"
            " attack_type, analysis, tool_trace, memory_context, retrieved_ids,"
            " triage_action, triage_branch, occurrence_count, suppressed, case_id, case_number,"
            " memory_id, case_error, alert_payload, enrichment, duration_ms"
            ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (alert_id, agent_name, source_ip, rule_id, severity_score, severity_label,
             attack_type, Json(analysis), Json(tool_trace), memory_context,
             # retrieved_ids is optional; only wrap in Json when actually provided
             Json(retrieved_ids) if retrieved_ids is not None else None,
             triage_action, triage_branch, occurrence_count, suppressed, case_id, case_number,
             memory_id, case_error,
             # alert_payload/enrichment are also optional replay/debug data
             Json(alert_payload) if alert_payload is not None else None,
             Json(enrichment) if enrichment is not None else None,
             duration_ms),  # wall-clock ms for the metrics dashboard (nullable)
        )
        return cur.fetchone()[0]  # the new investigation row's id


# The effective case of an investigation is the one triage created, OR — when that
# failed and an analyst retried from the console — the one linked afterwards. Every
# list view resolves it the same way, through this join, so a retried case shows up
# everywhere a triage-created one does.
# Shared FROM clause: joins each investigation to any case link created after
# the fact, so a retried case is visible everywhere a triage-created one is.
# A JOIN stitches two tables together on a matching column. A LEFT JOIN keeps
# every row from the left table (alert_investigations, aliased "ai") even when the
# right table (investigation_case_links, "l") has no match — those columns just
# come back NULL. That's what we want: every investigation shows up whether or not
# a case was linked to it later. (A plain JOIN would instead drop investigations
# that have no link.)
_QUEUE_FROM = (
    "alert_investigations ai "
    "LEFT JOIN investigation_case_links l ON l.investigation_id = ai.id"
)
# Shared column list for queue-style listing queries (queue, needs_attention,
# indicator search) so they all present the same shape of row.
_QUEUE_COLS = (
    "ai.id, ai.created_at, ai.alert_id, ai.agent_name, ai.source_ip, ai.rule_id, "
    "ai.severity_score, ai.severity_label, ai.attack_type, ai.triage_action, "
    "ai.triage_branch, ai.occurrence_count, ai.suppressed, ai.case_error, "
    # coalesce(a, b) returns the first of its arguments that isn't NULL. Here the
    # case_id/case_number is resolved through the join: triage's own value wins,
    # falling back to a later analyst-linked case when triage's is NULL. "AS name"
    # just labels the resulting column so callers can read it back by that name.
    "coalesce(ai.case_id, l.case_id) AS case_id, "
    "coalesce(ai.case_number, l.case_number) AS case_number"
)


def list_investigations(*, severity_label=None, triage_action=None, agent_name=None,
                        search=None, exclude_actions=(), limit=25, offset=0):
    """Triage queue: filtered, paginated. Returns (rows, total_count).

    `exclude_actions` drops rows whose triage_action is in the given collection
    (used for the queue's default 'actionable only' view, which hides auto_close).
    Ignored when an explicit `triage_action` filter is supplied."""
    # We build the SQL WHERE clause (the row filter) piece by piece depending on
    # which filters the caller passed. `where` collects the condition text and
    # `params` collects the matching values, kept in the same order so each %s
    # lines up with its value.
    where, params = [], []  # dynamically built WHERE fragments + their bound params, kept in lockstep
    if severity_label:
        where.append("ai.severity_label = %s"); params.append(severity_label)  # exact-match filter
    if triage_action:
        where.append("ai.triage_action = %s"); params.append(triage_action)  # exact-match filter
    elif exclude_actions:  # only applies when no explicit triage_action filter was given
        placeholders = ", ".join(["%s"] * len(exclude_actions))  # one %s per excluded action
        where.append(f"ai.triage_action NOT IN ({placeholders})")
        params.extend(exclude_actions)
    if agent_name:
        where.append("ai.agent_name = %s"); params.append(agent_name)  # exact-match filter
    if search:
        # ILIKE is case-insensitive pattern matching; the % signs in the value below
        # mean "any characters", so "%foo%" matches foo appearing anywhere in the
        # field. Free-text search across three identifying fields at once.
        where.append("(ai.alert_id ILIKE %s OR ai.agent_name ILIKE %s OR ai.source_ip ILIKE %s)")
        like = f"%{search}%"; params.extend([like, like, like])  # same pattern bound three times
    # Join all active filters with AND; empty when no filters were applied
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # First query: count(*) is how many rows match the filters in total. We need
        # that separately because the second query only fetches ONE page of rows, but
        # the UI still wants to show "showing 25 of 340".
        cur.execute(f"SELECT count(*) AS n FROM {_QUEUE_FROM}{clause}", params)
        total = cur.fetchone()["n"]
        # Second query: fetch the actual page of rows.
        cur.execute(
            f"SELECT {_QUEUE_COLS}, "
            # A "correlated subquery" is a mini-SELECT run for each outer row (it
            # references ai.id from the outer query). This one grabs that row's most
            # recent verdict action, if any — ORDER BY newest, LIMIT 1.
            " (SELECT vr.action FROM verdict_reviews vr "
            "  WHERE vr.investigation_id = ai.id "
            "  ORDER BY vr.created_at DESC LIMIT 1) AS review_status "
            f"FROM {_QUEUE_FROM}{clause} "
            # Pagination: LIMIT caps how many rows come back (one page); OFFSET skips
            # rows already shown on earlier pages. ORDER BY newest-first is applied
            # before LIMIT/OFFSET so paging is stable.
            "ORDER BY ai.created_at DESC LIMIT %s OFFSET %s",  # newest first, paginated
            [*params, limit, offset],  # re-use the same filter params, then pagination args
        )
        return cur.fetchall(), total  # (page of rows, total count across all pages)


# --- overview aggregates (read-only, global) --------------------------------
# These back the Overview landing page. Each is a small aggregate over the
# write-once alert_investigations table (severity_label / triage_action are
# already indexed-friendly filters used by the queue), computed globally rather
# than per visible page.
def summary_counts() -> dict[str, int]:
    """Global at-a-glance totals for the Overview KPI row."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            # count(*) FILTER (WHERE ...) counts only the rows matching that
            # condition. Stacking several of them lets us compute all six totals in
            # ONE pass over the table (one query) instead of six separate count()
            # queries — same answers, much less work for the database.
            "SELECT "
            " count(*) AS total, "
            " count(*) FILTER (WHERE lower(ai.severity_label) IN ('high','critical')) AS high, "
            " count(*) FILTER (WHERE ai.triage_action = 'create_flagged') AS flagged, "
            " count(*) FILTER (WHERE coalesce(ai.case_number, l.case_number) IS NOT NULL) "
            "   AS linked_cases, "
            # case-creating alerts still missing a case: what the retry button exists for
            " count(*) FILTER (WHERE ai.triage_action IN ('create_flagged','create_open') "
            "   AND coalesce(ai.case_id, l.case_id) IS NULL AND NOT coalesce(ai.suppressed, false)) "
            "   AS missing_cases, "
            " count(*) FILTER (WHERE ai.suppressed) AS suppressed "
            f"FROM {_QUEUE_FROM}"
        )
        row = cur.fetchone()
    # count(*) FILTER returns None only on an empty table for the filtered ones
    return {k: int(v or 0) for k, v in row.items()}  # coerce every value to a plain int


# Fixed ordering so the severity-mix bar always renders low→critical left-to-right.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def severity_distribution() -> list[dict[str, Any]]:
    """Counts grouped by severity_label, returned in a stable severity order for
    the Overview mix bar. Unknown/empty labels are folded into 'info'."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            # GROUP BY collapses rows that share the same label into one group, and
            # count(*) then counts each group — giving "how many alerts per severity".
            # "GROUP BY 1" means group by the 1st selected column (the label).
            # nullif(x,'') turns an empty-string label into NULL, and coalesce then
            # substitutes 'info', so blank labels are counted as info. lower() makes
            # the label lowercase so "High" and "high" count together.
            "SELECT lower(coalesce(nullif(severity_label, ''), 'info')) AS label, "
            "count(*) AS n FROM alert_investigations GROUP BY 1"
        )
        found = {r["label"]: int(r["n"]) for r in cur.fetchall()}  # label -> count lookup
    # keep known labels in order; append any unexpected labels after
    ordered = [{"label": s, "n": found.pop(s)} for s in _SEVERITY_ORDER if s in found]  # pop as consumed
    ordered.extend({"label": k, "n": v} for k, v in found.items())  # any leftover/unknown labels
    return ordered


def agent_accuracy() -> dict[str, Any]:
    """How well the agent tracks analyst judgement (the learning-loop scorecard):
    verdict agreement (confirm vs override), triage feedback, review coverage, and
    the attack types analysts most often correct. Read-only aggregate."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # How many verdict reviews were confirms vs overrides
        cur.execute("SELECT action, count(*) AS n FROM verdict_reviews GROUP BY action")
        by_action = {r["action"]: r["n"] for r in cur.fetchall()}
        confirms = int(by_action.get("confirm", 0))  # 0 if no confirms recorded yet
        overrides = int(by_action.get("override", 0))  # 0 if no overrides recorded yet
        total_reviews = confirms + overrides

        # Separately-tracked triage feedback (was the triage decision itself correct)
        cur.execute("SELECT rating, count(*) AS n FROM triage_feedback GROUP BY rating")
        by_rating = {r["rating"]: r["n"] for r in cur.fetchall()}
        tri_correct = int(by_rating.get("correct", 0))
        tri_incorrect = int(by_rating.get("incorrect", 0))

        # count(DISTINCT x) counts each unique value once, so an investigation with
        # several reviews is still counted a single time. That gives "how many
        # investigations have at least one review" (review coverage).
        cur.execute("SELECT count(DISTINCT investigation_id) AS n FROM verdict_reviews")
        reviewed = int(cur.fetchone()["n"])
        # Total investigations ever recorded, for the coverage percentage
        cur.execute("SELECT count(*) AS n FROM alert_investigations")
        total_inv = int(cur.fetchone()["n"])

        # Which attack types get overridden most often — where the agent needs the
        # most help. This JOIN links each override back to its investigation to read
        # that investigation's attack_type, groups by attack_type to count per type,
        # then ORDER BY n DESC + LIMIT 5 keeps only the five most-overridden types.
        cur.execute(
            "SELECT ai.attack_type AS attack_type, count(*) AS n "
            "FROM verdict_reviews vr JOIN alert_investigations ai ON ai.id = vr.investigation_id "
            "WHERE vr.action = 'override' GROUP BY ai.attack_type ORDER BY n DESC LIMIT 5"
        )
        top_corrected = cur.fetchall()

        # analysis is a JSONB column. The ->> operator reaches inside that JSON and
        # pulls out one field as text, so analysis->>'human_reviewed' reads the
        # "human_reviewed" key. Counts memory rows an analyst has vetted (learning loop).
        cur.execute("SELECT count(*) AS n FROM soc_memory_vectors WHERE (analysis->>'human_reviewed') = 'true'")
        learned = int(cur.fetchone()["n"])

    # Percent of reviews that confirmed the agent's verdict; None (not 0) when no reviews exist,
    # so the template can render "no data" instead of a misleading 0%
    agreement_pct = round(confirms / total_reviews * 100) if total_reviews else None
    tri_total = tri_correct + tri_incorrect
    triage_pct = round(tri_correct / tri_total * 100) if tri_total else None  # same "no data" guard
    return {
        "confirms": confirms, "overrides": overrides, "total_reviews": total_reviews,
        "agreement_pct": agreement_pct,
        "triage_correct": tri_correct, "triage_incorrect": tri_incorrect, "triage_pct": triage_pct,
        "reviewed": reviewed, "total_investigations": total_inv,
        "coverage_pct": round(reviewed / total_inv * 100) if total_inv else 0,  # 0% is fine here (no divide-by-zero ambiguity)
        "learned_memories": learned,
        "top_corrected": top_corrected,
    }


# --- metrics dashboard (read-only aggregates over the write-once record) ------
# All SELECT-only, over existing tables — no writes anywhere. Powers GET /console/metrics.
# window_hours=None means "all time". Gated duplicates (analysis.gate_deduped, from the
# Part A pre-agent gate) are EXCLUDED from agent-behaviour metrics — they never ran the
# agent — but counted for the gate hit rate. "Real" = an investigation the agent actually ran.
_REAL = "coalesce((ai.analysis->>'gate_deduped')::boolean, false) = false"
_GATED = "(ai.analysis->>'gate_deduped')::boolean is true"


def _window_clause(window_hours: Optional[float]) -> tuple[str, list]:
    """SQL fragment + params restricting alert_investigations (alias ai) to a recent window,
    or ('', []) for all-time. Kept separate so every metric applies the window identically."""
    if window_hours is None:
        return "", []
    return "ai.created_at >= now() - (%s * interval '1 hour')", [window_hours]


def metrics_summary(window_hours: Optional[float] = None) -> dict[str, Any]:
    """Top-line counts for the window: total alerts recorded, how many the dedup gate skipped
    (+ rate), how many real investigations ran, and how many fell back to the rule-based
    analysis (+ rate). One pass over the table."""
    wc, params = _window_clause(window_hours)
    where = f"WHERE {wc}" if wc else ""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT count(*) AS total, "
            f" count(*) FILTER (WHERE {_GATED}) AS gated, "
            f" count(*) FILTER (WHERE {_REAL}) AS investigations, "
            # rule-based fallback is identifiable by the fixed summary string set in agent.py
            f" count(*) FILTER (WHERE {_REAL} AND ai.analysis->>'summary' "
            "   LIKE 'Auto-generated fallback%%') AS fallbacks "
            f"FROM alert_investigations ai {where}",
            params,
        )
        row = cur.fetchone()
    total, gated = int(row["total"] or 0), int(row["gated"] or 0)
    inv, fb = int(row["investigations"] or 0), int(row["fallbacks"] or 0)
    return {
        "total": total, "gated": gated, "investigations": inv, "fallbacks": fb,
        # None (not 0) when there's no data, so the template can show "—" instead of a fake 0%
        "gate_rate_pct": round(gated / total * 100) if total else None,
        "fallback_rate_pct": round(fb / inv * 100) if inv else None,
    }


def metrics_latency(window_hours: Optional[float] = None) -> dict[str, Any]:
    """p50/p95/max investigation latency (ms) over REAL investigations that recorded a
    duration. Gated duplicates and pre-instrumentation rows (duration_ms NULL) are excluded."""
    wc, params = _window_clause(window_hours)
    conds = [_REAL, "ai.duration_ms IS NOT NULL"]
    if wc:
        conds.append(wc)
    where = "WHERE " + " AND ".join(conds)
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY ai.duration_ms) AS p50, "
            "  percentile_cont(0.95) WITHIN GROUP (ORDER BY ai.duration_ms) AS p95, "
            "  max(ai.duration_ms) AS max_ms, count(*) AS n "
            f"FROM alert_investigations ai {where}",
            params,
        )
        row = cur.fetchone()
    return {
        "p50_ms": int(row["p50"]) if row["p50"] is not None else None,
        "p95_ms": int(row["p95"]) if row["p95"] is not None else None,
        "max_ms": int(row["max_ms"]) if row["max_ms"] is not None else None,
        "n": int(row["n"] or 0),
    }


def metrics_iterations(window_hours: Optional[float] = None, cap: int = 8) -> dict[str, Any]:
    """Tool-call-count distribution across real investigations, plus how many reached the
    agent iteration cap (a sign the loop is running out of room). tool_trace records one
    entry per tool call, so its length is the tool-call count and the max 'iteration' its
    depth."""
    wc, params = _window_clause(window_hours)
    conds = [_REAL]
    if wc:
        conds.append(wc)
    where = "WHERE " + " AND ".join(conds)
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT jsonb_array_length(ai.tool_trace) AS steps, count(*) AS n "
            f"FROM alert_investigations ai {where} GROUP BY 1 ORDER BY 1",
            params,
        )
        dist = cur.fetchall()
        # cap-hit = the deepest tool call in the trace reached the configured iteration cap
        cur.execute(
            "SELECT count(*) AS cap_hits FROM alert_investigations ai "
            f"{where} AND (SELECT max((s->>'iteration')::int) "
            "  FROM jsonb_array_elements(ai.tool_trace) s) >= %s",
            params + [cap],
        )
        cap_hits = int(cur.fetchone()["cap_hits"] or 0)
    return {
        "distribution": [{"steps": int(r["steps"]), "n": int(r["n"])} for r in dist],
        "cap_hits": cap_hits, "cap": cap,
    }


def metrics_tool_failures(window_hours: Optional[float] = None) -> list[dict[str, Any]]:
    """Per-tool call volume and failure rate across real investigations, most-failing first.
    Unnests tool_trace (one row per tool call) and counts entries carrying an error."""
    wc, params = _window_clause(window_hours)
    conds = [_REAL]
    if wc:
        conds.append(wc)
    where = "WHERE " + " AND ".join(conds)
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT s->>'tool' AS tool, count(*) AS calls, "
            "  count(*) FILTER (WHERE s->>'error' IS NOT NULL AND s->>'error' <> '') AS failures "
            "FROM alert_investigations ai, jsonb_array_elements(ai.tool_trace) s "
            f"{where} GROUP BY 1 ORDER BY failures DESC, calls DESC",
            params,
        )
        rows = cur.fetchall()
    return [
        {"tool": r["tool"], "calls": int(r["calls"]), "failures": int(r["failures"]),
         "fail_pct": round(int(r["failures"]) / int(r["calls"]) * 100) if r["calls"] else 0}
        for r in rows
    ]


def _humanize_gap(delta) -> str:
    """A short human phrase for the time between two correlated alerts."""
    if delta is None:
        return "an unknown interval"
    secs = abs(delta.total_seconds())  # order can vary; we only want the magnitude
    if secs < 3600:
        m = max(1, round(secs / 60))
        return f"{m} minute{'s' if m != 1 else ''} apart"
    if secs < 86400:
        h = round(secs / 3600)
        return f"{h} hour{'s' if h != 1 else ''} apart"
    d = round(secs / 86400)
    return f"{d} day{'s' if d != 1 else ''} apart"


def _correlation_reasons(row: dict[str, Any]) -> list[str]:
    """Human-readable evidence for WHY two cases are linked. The primary reason is
    always the semantic-memory retrieval itself (host-scoped, similarity-ranked);
    shared concrete indicators are added as supporting evidence when present."""
    reasons: list[str] = []
    host = row.get("child_host")
    # The mechanism: retrieval is per-host and ranked by embedding similarity, so a
    # link means "same host, and the newer alert's description read like this one".
    reasons.append(
        f"While investigating the newer alert, the agent searched semantic memory for "
        f"host {host or 'this host'} and found this earlier case — their alert descriptions "
        f"were similar enough to be retrieved as context."
    )
    # Shared source IP is the strongest concrete tie: same actor.
    if row.get("child_ip") and row["child_ip"] == row.get("parent_ip"):
        reasons.append(f"Both alerts came from the same source IP {row['child_ip']} — likely the same actor.")
    # Shared detection rule means the same underlying behaviour tripped both.
    if row.get("child_rule") and row["child_rule"] == row.get("parent_rule"):
        reasons.append(f"Both were raised by the same Wazuh detection rule {row['child_rule']}.")
    # Same attack classification reinforces that these are one campaign.
    if (row.get("child_attack") and row.get("parent_attack")
            and row["child_attack"].strip().lower() == row["parent_attack"].strip().lower()):
        reasons.append(f"Both were classified as the same activity: {row['child_attack']}.")
    # The effect: the prior case was in front of the agent as it scored the new one.
    reasons.append(
        f"The agent scored the newer alert with this prior case in view "
        f"({row.get('parent_sev') or '—'} → {row.get('child_sev') or '—'})."
    )
    return reasons


def correlated_cases(limit: int = 12) -> list[dict[str, Any]]:
    """The memory-correlation feed for the Overview carousel.

    An investigation (child) is *correlated* to a prior one (parent) when the
    child retrieved the parent's semantic-memory row during its own analysis:
    child.retrieved_ids contains parent.memory_id. This is the learning loop made
    visible — 'case #33 was investigated in the light of prior case #32'.

    One row per child (its highest-severity parent), newest child first. Each row
    carries `reasons` (why the two are linked) and `gap` (how far apart in time).
    Case numbers resolve through investigation_case_links like every other view.
    """
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            # The whole query is wrapped as a subquery ("FROM ( ... ) sub") so we can
            # first pick one strongest parent per child, then re-sort those results by
            # time. You can't do both orderings in a single level because DISTINCT ON
            # forces its own ordering.
            "SELECT * FROM ("
            # DISTINCT ON (child.id) is a PostgreSQL feature that keeps just the FIRST
            # row for each child.id according to the ORDER BY at the bottom. Since that
            # ORDER BY sorts by parent severity descending, "first" = most severe
            # parent — so a child that retrieved several memories shows its strongest link.
            "  SELECT DISTINCT ON (child.id) "
            "    child.id AS child_id, child.severity_label AS child_sev, "
            "    child.severity_score AS child_score, child.attack_type AS child_attack, "
            "    child.agent_name AS child_host, child.source_ip AS child_ip, "
            "    child.rule_id AS child_rule, child.created_at AS child_time, "
            "    coalesce(child.case_number, cl.case_number) AS child_case, "
            "    parent.id AS parent_id, parent.attack_type AS parent_attack, "
            "    parent.severity_label AS parent_sev, parent.severity_score AS parent_score, "
            "    parent.source_ip AS parent_ip, parent.rule_id AS parent_rule, "
            "    parent.created_at AS parent_time, "
            "    coalesce(parent.case_number, pl.case_number) AS parent_case "
            "  FROM alert_investigations child "
            # retrieved_ids is a JSON array of memory ids the child pulled up. A
            # LATERAL join lets the right side reference the current left row
            # (child.retrieved_ids); jsonb_array_elements_text turns that array into
            # one row per element, so a child that retrieved 3 memories becomes 3 rows.
            "  CROSS JOIN LATERAL jsonb_array_elements_text(child.retrieved_ids) AS r(mem_id) "
            # match each retrieved memory id back to the investigation that created it.
            # ::bigint casts the id text to a number; parent.id <> child.id excludes
            # a row matching itself.
            "  JOIN alert_investigations parent "
            "    ON parent.memory_id = r.mem_id::bigint AND parent.id <> child.id "
            "  LEFT JOIN investigation_case_links cl ON cl.investigation_id = child.id "
            "  LEFT JOIN investigation_case_links pl ON pl.investigation_id = parent.id "
            "  WHERE child.retrieved_ids IS NOT NULL "
            "    AND jsonb_array_length(child.retrieved_ids) > 0 "
            "  ORDER BY child.id, parent.severity_score DESC NULLS LAST"
            ") sub ORDER BY sub.child_time DESC LIMIT %s",
            (limit,),
        )
        rows = cur.fetchall()
    # Enrich each correlation with its explanation and a time-gap phrase.
    for r in rows:
        ct, pt = r.get("child_time"), r.get("parent_time")
        r["gap"] = _humanize_gap((ct - pt) if (ct and pt) else None)
        r["reasons"] = _correlation_reasons(r)
    return rows


def needs_attention(limit: int = 8) -> list[dict[str, Any]]:
    """High/critical OR flagged investigations that no analyst has reviewed yet
    (no verdict_reviews row). Most severe, then most recent, first — the
    'what needs me now' list on the Overview."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {_QUEUE_COLS} FROM {_QUEUE_FROM} "
            # Either severity-driven urgency or an explicit triage flag counts as "needs attention"
            "WHERE (lower(ai.severity_label) IN ('high','critical') "
            "       OR ai.triage_action = 'create_flagged') "
            # ...and no analyst has reviewed it yet. NOT EXISTS(...) is true when the
            # inner query finds NO matching row — here, no verdict_reviews row points
            # at this investigation. (SELECT 1 is a convention: we only care whether a
            # row exists, not what's in it.)
            "AND NOT EXISTS (SELECT 1 FROM verdict_reviews vr "
            "                WHERE vr.investigation_id = ai.id) "
            "ORDER BY ai.severity_score DESC NULLS LAST, ai.created_at DESC "  # most severe, then newest
            "LIMIT %s",
            (limit,),
        )
        return cur.fetchall()


def find_recent_investigation_by_identity(*, agent_name, rule_id, source_ip,
                                          within_minutes: float):
    """Most recent REAL investigation matching this alert's identity (host + rule + source
    IP) within a recent window — the lookup behind the pre-agent dedup gate. SELECT-only, so
    the write-once record is never touched.

    Requires a source_ip (no discriminator ⇒ no gate, mirroring triage's no-false-merge rule).
    Rows that are THEMSELVES gated duplicates are excluded as anchors, so a burst of duplicates
    all resolve to the one real investigation that produced the verdict, never to each other.
    Returns the row with its verdict fields and resolved case, or None."""
    if not source_ip:
        return None  # no usable discriminator — caller proceeds to a full investigation
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT ai.id, ai.severity_score, ai.severity_label, ai.attack_type, ai.analysis, "
            "  ai.triage_branch, ai.created_at, "
            "  coalesce(ai.case_id, l.case_id) AS case_id, "
            "  coalesce(ai.case_number, l.case_number) AS case_number "
            f"FROM {_QUEUE_FROM} "
            # exact host + source IP; IS NOT DISTINCT FROM makes a NULL rule_id match a NULL rule_id
            "WHERE ai.agent_name = %s AND ai.rule_id IS NOT DISTINCT FROM %s "
            "  AND ai.source_ip = %s "
            "  AND ai.created_at >= now() - (%s * interval '1 minute') "
            # never anchor to another gated duplicate — only real (agent-run) investigations
            "  AND coalesce((ai.analysis->>'gate_deduped')::boolean, false) = false "
            "ORDER BY ai.created_at DESC LIMIT 1",  # the most recent matching investigation
            (agent_name, rule_id, source_ip, within_minutes),
        )
        return cur.fetchone()  # None if nothing matched within the window


def get_investigation(inv_id: int):
    """Full investigation record + any layered human input (read-only here).

    The immutable row is returned with its case RESOLVED: if triage failed to create
    a case and an analyst later retried, inv['case_id'] / inv['case_number'] carry the
    linked case (the link row itself is under 'case_link'), so callers see one case
    regardless of which attempt produced it."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # The immutable agent-produced record itself. SELECT * fetches every column
        # of the matching row (fine here because we want the whole record).
        cur.execute("SELECT * FROM alert_investigations WHERE id = %s", (inv_id,))
        inv = cur.fetchone()
        if inv is None:
            return None  # no such investigation
        # Any case linked afterwards by an analyst (e.g. a retried case creation)
        cur.execute(
            "SELECT case_id, case_number, actor_username, created_at "
            "FROM investigation_case_links WHERE investigation_id = %s",
            (inv_id,),
        )
        case_link = cur.fetchone()
        if case_link and not inv.get("case_id"):
            # Resolve the "effective" case onto the row itself so callers don't have
            # to know about the two possible sources
            inv["case_id"] = case_link["case_id"]
            inv["case_number"] = case_link["case_number"]
        # Every verdict review (confirm/override) an analyst has left, newest first
        cur.execute(
            "SELECT actor_username, action, override_payload, reason, created_at "
            "FROM verdict_reviews WHERE investigation_id = %s ORDER BY created_at DESC",
            (inv_id,),
        )
        reviews = cur.fetchall()
        # Every triage correct/incorrect feedback entry, newest first
        cur.execute(
            "SELECT actor_username, rating, reason, created_at "
            "FROM triage_feedback WHERE investigation_id = %s ORDER BY created_at DESC",
            (inv_id,),
        )
        feedback = cur.fetchall()
    return {"inv": inv, "reviews": reviews, "feedback": feedback, "case_link": case_link}


def link_case(*, investigation_id: int, case_id: str, case_number, actor_username: str,
              action: str = "investigation_case_retry", detail: Optional[str] = None,
              before: Any = None) -> int:
    """Attach a TheHive case to an investigation that has none — either a case the
    analyst just created (action=investigation_case_retry) or the existing case its
    dedup group belongs to (action=investigation_case_link).

    This is the ONE update-shaped operation on an investigation, and it deliberately
    lives in its own table: alert_investigations stays write-once (agent output is
    never rewritten) and the link is an attributed human action, so it is inserted
    with its audit row in the SAME transaction.

    The UNIQUE constraint on investigation_id is the race guard: two analysts acting
    at once means the second INSERT fails and its transaction (link + audit) rolls
    back."""
    with get_pool().connection() as conn, conn.cursor() as cur:
        # This INSERT is where the UNIQUE(investigation_id) constraint would raise
        # on a race — letting the DB, not app logic, arbitrate concurrent retries
        cur.execute(
            "INSERT INTO investigation_case_links "
            "(investigation_id, case_id, case_number, actor_username) "
            "VALUES (%s, %s, %s, %s) RETURNING id",
            (investigation_id, case_id, case_number, actor_username),
        )
        link_id = cur.fetchone()[0]
        # Audit row written on the SAME cursor/transaction as the INSERT above,
        # so link + audit succeed or fail together
        _audit_on(cur, actor_username, action, target_type="investigation",
                  target_id=str(investigation_id), before=before,
                  after={"case_id": case_id, "case_number": case_number},
                  detail=detail or f"linked TheHive case #{case_number}")
    logger.info("AUDIT actor=%s action=%s investigation=%s case=%s",
                actor_username, action, investigation_id, case_number)  # human-readable log line mirroring the audit row
    return link_id


def delete_investigation(inv_id: int) -> bool:
    """Remove an investigation and the human input layered on it (verdict reviews,
    triage feedback), in one transaction. The write-once trigger only blocks UPDATE,
    so DELETE is allowed; the two child tables have no ON DELETE CASCADE, so they are
    cleared first. The alert's semantic-memory row is deliberately left alone — it is
    shared SOC knowledge, and is removable on its own from the memory browser.
    The audit row is written by the caller BEFORE this runs (no unaudited deletes)."""
    with get_pool().connection() as conn, conn.cursor() as cur:
        # Delete child rows first (no cascading FK), then the parent row —
        # all in one transaction so a failure partway rolls everything back
        cur.execute("DELETE FROM verdict_reviews WHERE investigation_id = %s", (inv_id,))
        cur.execute("DELETE FROM triage_feedback WHERE investigation_id = %s", (inv_id,))
        cur.execute("DELETE FROM investigation_case_links WHERE investigation_id = %s", (inv_id,))
        cur.execute("DELETE FROM alert_investigations WHERE id = %s", (inv_id,))
        return cur.rowcount > 0  # True only if the parent row actually existed and was removed


def delete_investigations(inv_ids: list[int], *, actor_username: str) -> list[int]:
    """Delete several investigations in ONE transaction, with ONE audit row each.

    Bulk is not an excuse to audit less: a 20-row delete produces 20 audit rows, each
    naming what was destroyed, exactly as if the analyst had deleted them one by one.
    Audit rows are written on the same cursor as the deletes, so either every row and
    its audit commit, or nothing does. Ids that no longer exist are skipped (another
    analyst may have deleted them first) — the returned list is what actually went."""
    if not inv_ids:
        return []  # nothing requested, nothing to do
    deleted: list[int] = []  # ids we actually delete, accumulated as we go
    # Two cursors, ONE connection: the dict cursor reads the rows we are about to
    # destroy (for the audit `before`), the tuple cursor writes audits + deletes
    # (_audit_on returns the new id positionally). Same transaction either way.
    with get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as read_cur:
            # id = ANY(%s) matches any id in the passed list (like SQL's IN, but it
            # takes one array parameter — handy for a variable number of ids).
            # FOR UPDATE locks these rows so nothing else deletes/modifies them
            # while we build the audit trail and issue our own deletes (the lock is
            # held until this transaction ends).
            read_cur.execute(
                "SELECT id, alert_id, agent_name, source_ip, rule_id, severity_label, "
                "       triage_action, case_number "
                "FROM alert_investigations WHERE id = ANY(%s) FOR UPDATE",
                (inv_ids,),
            )
            rows = read_cur.fetchall()
        if not rows:
            return []  # none of the requested ids exist anymore
        found = [r["id"] for r in rows]  # ids that actually still exist
        with conn.cursor() as cur:
            for r in rows:
                # One audit row per investigation, capturing its state right before deletion
                _audit_on(cur, actor_username, "investigation_delete", target_type="investigation",
                          target_id=str(r["id"]),
                          before={k: v for k, v in r.items() if k != "id"},
                          detail=f"bulk delete of {len(found)} investigation(s) from the triage queue")
                deleted.append(r["id"])
            # Bulk-delete all child rows, then the parent rows, using ANY() over the found ids
            cur.execute("DELETE FROM verdict_reviews WHERE investigation_id = ANY(%s)", (found,))
            cur.execute("DELETE FROM triage_feedback WHERE investigation_id = ANY(%s)", (found,))
            cur.execute("DELETE FROM investigation_case_links WHERE investigation_id = ANY(%s)", (found,))
            cur.execute("DELETE FROM alert_investigations WHERE id = ANY(%s)", (found,))
    logger.info("AUDIT actor=%s action=investigation_delete bulk=%s ids=%s",
                actor_username, len(deleted), deleted)  # summary log line for the whole bulk operation
    return deleted


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
        # Count of semantic-memory rows written in the trailing window
        cur.execute(
            "SELECT count(*) AS n FROM soc_memory_vectors "
            "WHERE created_at >= now() - (%s * interval '1 hour')",
            (window_hours,),
        )
        memory_rows = cur.fetchone()["n"]
        # Count of investigation rows written in the same trailing window
        cur.execute(
            "SELECT count(*) AS n FROM alert_investigations "
            "WHERE created_at >= now() - (%s * interval '1 hour')",
            (window_hours,),
        )
        investigation_rows = cur.fetchone()["n"]
    divergence = memory_rows - investigation_rows  # positive means investigation writes are missing
    return {
        "window_hours": window_hours,
        "memory_rows": memory_rows,
        "investigation_rows": investigation_rows,
        "divergence": divergence,
        "balanced": divergence == 0,  # True means the two tables are in sync
    }


# --- audit ------------------------------------------------------------------
# Shared INSERT statement text used by every audit write, defined once to keep
# the column list consistent between _audit_on() and write_audit()
_AUDIT_SQL = (
    "INSERT INTO audit_log (actor_username, action, target_type, target_id, "
    "before, after, detail) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id"
)


def _audit_params(actor_username, action, target_type, target_id, before, after, detail):
    # Wrap before/after in Json() only when present; None stays a SQL NULL
    return (actor_username, action, target_type, target_id,
            Json(before) if before is not None else None,
            Json(after) if after is not None else None, detail)


def _audit_on(cur, actor_username, action, *, target_type=None, target_id=None,
              before=None, after=None, detail=None) -> int:
    """Insert an audit row on an EXISTING cursor, so it commits atomically with
    whatever else that transaction is doing."""
    cur.execute(_AUDIT_SQL, _audit_params(
        actor_username, action, target_type, target_id, before, after, detail))
    return cur.fetchone()[0]  # the new audit_log row's id


def write_audit(actor_username: str, action: str, *, target_type: Optional[str] = None,
                target_id: Optional[str] = None, before: Any = None, after: Any = None,
                detail: Optional[str] = None) -> int:
    """Record a consequential action in its own transaction. Re-raises on failure:
    auditing is a hard requirement — if we can't audit, the action must fail."""
    try:
        # Opens its OWN connection/transaction (unlike _audit_on), for standalone
        # calls that aren't already inside another function's transaction
        with get_pool().connection() as conn, conn.cursor() as cur:
            audit_id = _audit_on(cur, actor_username, action, target_type=target_type,
                                 target_id=target_id, before=before, after=after, detail=detail)
        logger.info("AUDIT actor=%s action=%s target=%s/%s",
                    actor_username, action, target_type, target_id)
        return audit_id
    except Exception:  # noqa: BLE001
        # Log the failure with full traceback, then re-raise so the caller's
        # action is treated as failed rather than silently unaudited
        logger.exception("Failed to write audit row (actor=%s action=%s)", actor_username, action)
        raise  # auditing is a hard requirement: if we can't audit, fail the action


# --- analyst actions on investigations (action + audit, one transaction) -----
def add_verdict_review(*, investigation_id: int, actor_username: str, action: str,
                       override_payload: Any, reason: Optional[str], before: Any) -> int:
    """Confirm/override the agent verdict. The verdict_reviews row and its audit
    row are inserted in the SAME transaction — both commit or neither does."""
    after = {"action": action, "override_payload": override_payload, "reason": reason}  # audit "after" snapshot
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO verdict_reviews (investigation_id, actor_username, action, "
            "override_payload, reason) VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (investigation_id, actor_username, action,
             Json(override_payload) if override_payload is not None else None, reason),
        )
        review_id = cur.fetchone()[0]
        # action becomes "verdict_confirm" / "verdict_override" in the audit log
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
            # ai.* plus the resolved case_id/case_number (triage's own, or a later link)
            "SELECT ai.*, coalesce(ai.case_id, l.case_id) AS case_id, "
            "  coalesce(ai.case_number, l.case_number) AS case_number "
            f"FROM {_QUEUE_FROM} "
            "WHERE coalesce(ai.case_number, l.case_number) = %s "
            "ORDER BY ai.created_at DESC LIMIT 1",  # in the rare multi-match case, prefer the newest
            (case_number,),
        )
        return cur.fetchone()  # None if no investigation is linked to this case number


def search_investigations_by_indicator(indicator: str, *, limit: int = 25) -> list[dict[str, Any]]:
    """Find investigations across ALL cases whose source_ip equals `indicator`, or
    whose stored analysis mentions it (e.g. a file hash in the analysis JSON).
    Answers 'did this IP/hash appear in another case'. Read-only, capped."""
    like = f"%{indicator}%"  # substring pattern for the analysis-JSON text search
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {_QUEUE_COLS} FROM {_QUEUE_FROM} "
            # exact match on source_ip, OR a substring match anywhere in the analysis
            # JSON. analysis::text casts the JSONB to plain text so ILIKE can scan the
            # whole blob (catches e.g. a file hash buried inside the analysis).
            "WHERE ai.source_ip = %s OR ai.analysis::text ILIKE %s "
            "ORDER BY ai.created_at DESC LIMIT %s",  # newest first, capped by `limit`
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
             Json(tool_calls if tool_calls is not None else []),  # default to an empty JSON array, not NULL
             list(referenced_case_ids or [])),  # default to an empty list, not None
        )
        return cur.fetchone()[0]  # the new message row's id


def list_chat(thread_key: str) -> list[dict[str, Any]]:
    """Full conversation for one analyst's thread, oldest-first (replay + render)."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, role, actor, message, tool_calls, referenced_case_ids, created_at "
            "FROM console_chat WHERE thread_key = %s ORDER BY created_at ASC, id ASC",  # oldest first, id as tiebreaker
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
    # Prefixed with owner_username for readability, suffixed with random hex so
    # thread keys never collide and can't be guessed/enumerated by another user
    thread_key = f"{owner_username}:{secrets.token_hex(8)}"
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "INSERT INTO console_conversations (thread_key, owner_username, title) "
            "VALUES (%s, %s, %s) RETURNING id, thread_key, owner_username, title, created_at, updated_at",
            (thread_key, owner_username, title),
        )
        return cur.fetchone()  # the freshly-created conversation row


def list_conversations(owner_username: str) -> list[dict[str, Any]]:
    """An analyst's conversations, most-recent first, with message counts."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT c.id, c.thread_key, c.title, c.created_at, c.updated_at, "
            # correlated subquery: how many messages this conversation's thread has
            "  (SELECT count(*) FROM console_chat m WHERE m.thread_key = c.thread_key) AS message_count "
            "FROM console_conversations c WHERE c.owner_username = %s "  # scoped to this analyst only
            "ORDER BY c.updated_at DESC, c.id DESC",  # most recently active first
            (owner_username,),
        )
        return cur.fetchall()


def get_conversation(conversation_id: int, owner_username: str) -> Optional[dict[str, Any]]:
    """Fetch one conversation IFF it belongs to this analyst (authorization)."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, thread_key, owner_username, title, created_at, updated_at "
            # the owner_username filter IS the authorization check — a mismatched
            # conversation_id/owner_username pair simply returns no row
            "FROM console_conversations WHERE id = %s AND owner_username = %s",
            (conversation_id, owner_username),
        )
        return cur.fetchone()  # None if it doesn't exist or isn't this analyst's


def most_recent_conversation(owner_username: str) -> Optional[dict[str, Any]]:
    """The analyst's most-recently-active conversation (drives the dock)."""
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, thread_key, owner_username, title, created_at, updated_at "
            "FROM console_conversations WHERE owner_username = %s "
            "ORDER BY updated_at DESC, id DESC LIMIT 1",  # most recently touched, id as tiebreaker
            (owner_username,),
        )
        return cur.fetchone()  # None if the analyst has no conversations yet


def rename_conversation(conversation_id: int, owner_username: str, title: str) -> bool:
    """Set a conversation's title (owner-scoped). Returns True if a row changed."""
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE console_conversations SET title = %s "
            "WHERE id = %s AND owner_username = %s",  # owner check prevents renaming someone else's chat
            (title, conversation_id, owner_username),
        )
        return cur.rowcount > 0  # False if no matching row (wrong id or wrong owner)


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
        # First confirm this conversation belongs to the caller, and grab its
        # thread_key (needed to delete the matching console_chat rows)
        cur.execute(
            "SELECT thread_key FROM console_conversations "
            "WHERE id = %s AND owner_username = %s",
            (conversation_id, owner_username),
        )
        row = cur.fetchone()
        if row is None:
            return False  # not found, or belongs to a different analyst — nothing deleted
        cur.execute("DELETE FROM console_chat WHERE thread_key = %s", (row["thread_key"],))  # messages first
        cur.execute("DELETE FROM console_conversations WHERE id = %s", (conversation_id,))  # then the conversation itself
        return True
