-- RAM v2 Phase 3 — triage dedup / suppression store
-- One active record per dedup key (agent_name|rule_id|source_ip). Alerts with no
-- source_ip are NOT deduped (handled in code) and never written here.

CREATE TABLE IF NOT EXISTS triage_dedup (
    dedup_key        TEXT PRIMARY KEY,
    agent_name       TEXT,
    rule_id          TEXT,
    source_ip        TEXT,
    case_id          TEXT,
    case_number      BIGINT,
    occurrence_count INTEGER     NOT NULL DEFAULT 1,
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS triage_dedup_last_seen ON triage_dedup (last_seen DESC);
