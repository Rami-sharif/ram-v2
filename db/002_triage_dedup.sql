-- RAM v2 Phase 3 — triage dedup / suppression store
-- One active record per dedup key (agent_name|rule_id|source_ip). Alerts with no
-- source_ip are NOT deduped (handled in code) and never written here.

-- One active suppression record per dedup key; the key itself is the primary key
-- so an upsert on (agent_name|rule_id|source_ip) naturally has exactly one row.
CREATE TABLE IF NOT EXISTS triage_dedup (
    -- Composite dedup identity "agent_name|rule_id|source_ip", serving as the row's own primary key.
    dedup_key        TEXT PRIMARY KEY,
    -- Agent that raised the alert being deduped; stored for readability/debugging.
    agent_name       TEXT,
    -- Wazuh rule id that raised the alert being deduped.
    rule_id          TEXT,
    -- Source IP the dedup key is scoped to (alerts without one are never written here).
    source_ip        TEXT,
    -- TheHive case id already opened for this dedup key, if any.
    case_id          TEXT,
    -- TheHive human-readable case number matching case_id, if any.
    case_number      BIGINT,
    -- How many times this dedup key has recurred since first_seen; starts at 1 on first insert.
    occurrence_count INTEGER     NOT NULL DEFAULT 1,
    -- Timestamp of the first occurrence that created this dedup record.
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Timestamp of the most recent recurrence; updated on each duplicate hit.
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Speeds up queries that need the most recently active dedup records first.
CREATE INDEX IF NOT EXISTS triage_dedup_last_seen ON triage_dedup (last_seen DESC);
