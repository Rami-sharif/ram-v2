"""Backfill: re-embed every v1 identity row into the v2 format (Step 2.3).

WHAT THIS DOES, FOR A NEWCOMER:
When the identity-string FORMAT changed from v1 to v2 (added input-side MITRE ids and
normalized the log line — see app/memory.py), every ALREADY-STORED vector became stale:
it was built from the old text, so it no longer represents what identity_string() would
produce today, and similarity searches would compare new-format queries against old-format
rows. This script fixes that by rebuilding each v1 row's identity text and RE-EMBEDDING it
with the exact same locked pipeline, then stamping identity_version=2.

Two sources are used to rebuild a row's identity, best-first:
  1. The raw alert is retained on alert_investigations.alert_payload (a dumped WazuhAlert)
     for rows written after migration 007. When present we reconstruct the WazuhAlert and
     call identity_string() — an EXACT v2 rebuild, including MITRE.
  2. Otherwise we parse the old v1 alert_text back into its fields and rebuild v2 from
     those, normalizing the log. MITRE is unrecoverable here (it was never in v1 text or
     stored separately), so it comes out empty — still a strict improvement (normalized log).

Idempotent: only rows with identity_version < IDENTITY_VERSION are processed, so re-running
is safe. Run inside the agent-service container:
    docker compose exec -T agent-service python -m app.backfill_identity          # apply
    docker compose exec -T agent-service python -m app.backfill_identity --dry-run # preview
"""
import logging  # progress/summary logging
import re  # parsing old v1 identity text back into fields
import sys  # argv (--dry-run) and exit code
from typing import Any, Optional  # typing for row dicts and nullable payloads

from psycopg.rows import dict_row  # dict rows for readable field access

from . import memory  # embed(), identity_string(), normalize_log(), IDENTITY_VERSION
from .db import get_pool, vector_literal  # connection pool + pgvector literal formatter
from .schemas import WazuhAlert  # reconstruct the alert from a retained payload

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("backfill_identity")

# Parse a v1 identity string back into its four fields. Keys are fixed and in order; the
# leading three fields never contain " | SrcIP:"/" | Groups:"/" | Log:" so the non-greedy
# captures are unambiguous, and Log (which may contain anything) is captured greedily last.
_V1_RE = re.compile(
    r"^Rule: (?P<desc>.*?) \| SrcIP: (?P<ip>.*?) \| Groups: (?P<groups>.*?) \| Log: (?P<log>.*)$",
    re.DOTALL,
)


def _rebuild_from_payload(payload: dict[str, Any]) -> str:
    # Exact v2 rebuild: reconstruct the WazuhAlert and run the current identity_string().
    alert = WazuhAlert.model_validate(payload)
    return memory.identity_string(alert)


def _rebuild_from_v1_text(alert_text: str) -> Optional[str]:
    # Fallback rebuild when no raw payload was retained: parse the old v1 text and
    # re-compose in v2 shape (MITRE empty, log normalized). Returns None if the text
    # doesn't match the v1 format (left for the caller to log and skip).
    m = _V1_RE.match(alert_text)
    if not m:
        return None
    return (
        f"Rule: {m['desc']} | MITRE:  | SrcIP: {m['ip']} "
        f"| Groups: {m['groups']} | Log: {memory.normalize_log(m['log'])}"
    )


def _load_rows() -> list[dict[str, Any]]:
    # Every below-current-version row, paired with a retained raw payload when one exists.
    # DISTINCT ON collapses the possible many-investigations-per-memory link to one payload.
    with get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT DISTINCT ON (m.id) m.id, m.alert_text, m.identity_version, "
            "       ai.alert_payload "
            "FROM soc_memory_vectors m "
            "LEFT JOIN alert_investigations ai "
            "       ON ai.memory_id = m.id AND ai.alert_payload IS NOT NULL "
            "WHERE m.identity_version < %s "
            "ORDER BY m.id, ai.id",
            (memory.IDENTITY_VERSION,),
        )
        return cur.fetchall()


def _apply(memory_id: int, new_text: str) -> None:
    # Re-embed the rebuilt identity with the locked pipeline and write text+vector+version
    # together, so alert_text, its embedding, and the format marker never drift apart.
    new_vec = vector_literal(memory.embed(new_text))
    with get_pool().connection() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE soc_memory_vectors "
            "SET alert_text = %s, embedding = %s::vector, identity_version = %s "
            "WHERE id = %s",
            (new_text, new_vec, memory.IDENTITY_VERSION, memory_id),
        )


def main() -> int:
    dry_run = "--dry-run" in sys.argv[1:]  # preview rebuilds without touching the DB
    rows = _load_rows()
    logger.info(
        "%d row(s) below identity v%d%s",
        len(rows), memory.IDENTITY_VERSION, " (dry-run)" if dry_run else "",
    )
    exact = fallback = skipped = 0  # per-source counters for the final summary
    for r in rows:
        mid = r["id"]
        if r.get("alert_payload"):
            new_text = _rebuild_from_payload(r["alert_payload"])  # exact v2, incl. MITRE
            source = "payload"
            exact += 1
        else:
            new_text = _rebuild_from_v1_text(r["alert_text"])  # log-normalized, MITRE empty
            source = "v1-text"
            if new_text is None:
                logger.warning("id=%s: unparseable v1 alert_text, SKIPPED: %r", mid, r["alert_text"])
                skipped += 1
                continue
            fallback += 1
        logger.info("id=%s [%s] -> %s", mid, source, new_text)
        if not dry_run:
            _apply(mid, new_text)  # re-embed + persist
    logger.info(
        "Done: %d exact (payload), %d fallback (v1-text), %d skipped%s",
        exact, fallback, skipped, " — DRY RUN, nothing written" if dry_run else "",
    )
    return 1 if skipped else 0  # non-zero exit if any row could not be migrated


if __name__ == "__main__":
    raise SystemExit(main())
