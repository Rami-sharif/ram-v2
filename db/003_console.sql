-- RAM v2 Phase 5 — analyst console schema.
-- TheHive stays the case system of record; these tables back the console only.

-- Per-analyst local accounts -------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name  TEXT,
    role          TEXT NOT NULL DEFAULT 'analyst',
    disabled      BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Audit log: every consequential analyst action, attributed -------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_username TEXT NOT NULL,
    action         TEXT NOT NULL,
    target_type    TEXT,
    target_id      TEXT,
    before         JSONB,
    after          JSONB,
    detail         TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_log_created_at ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS audit_log_actor ON audit_log (actor_username);

-- WRITE-ONCE record of what the agent produced per alert ---------------------
-- The agent's analysis + tool trace are immutable ground truth (audit trail +
-- future tuning dataset). Human input lives in verdict_reviews/triage_feedback.
CREATE TABLE IF NOT EXISTS alert_investigations (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_id         TEXT,
    agent_name       TEXT,
    source_ip        TEXT,
    rule_id          TEXT,
    severity_score   INTEGER,
    severity_label   TEXT,
    attack_type      TEXT,
    analysis         JSONB NOT NULL,
    tool_trace       JSONB NOT NULL DEFAULT '[]'::jsonb,
    memory_context   TEXT,
    retrieved_ids    JSONB,
    triage_action    TEXT,
    triage_branch    TEXT,
    occurrence_count INTEGER,
    suppressed       BOOLEAN,
    case_id          TEXT,
    case_number      BIGINT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alert_investigations_created_at ON alert_investigations (created_at DESC);
CREATE INDEX IF NOT EXISTS alert_investigations_agent ON alert_investigations (agent_name);
CREATE INDEX IF NOT EXISTS alert_investigations_action ON alert_investigations (triage_action);
CREATE INDEX IF NOT EXISTS alert_investigations_score ON alert_investigations (severity_score);

-- Enforce write-once: agent output may be inserted and deleted (retention),
-- but never UPDATEd.
CREATE OR REPLACE FUNCTION reject_update_alert_investigations() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'alert_investigations is write-once: agent output is immutable';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS alert_investigations_no_update ON alert_investigations;
CREATE TRIGGER alert_investigations_no_update
    BEFORE UPDATE ON alert_investigations
    FOR EACH ROW EXECUTE FUNCTION reject_update_alert_investigations();

-- Human verdict review (confirm/override), layered on top -------------------
CREATE TABLE IF NOT EXISTS verdict_reviews (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    investigation_id BIGINT NOT NULL REFERENCES alert_investigations(id),
    actor_username   TEXT NOT NULL,
    action           TEXT NOT NULL CHECK (action IN ('confirm', 'override')),
    override_payload JSONB,
    reason           TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS verdict_reviews_investigation ON verdict_reviews (investigation_id);

-- Triage-decision feedback (stored for tuning; no behavior change this phase) -
CREATE TABLE IF NOT EXISTS triage_feedback (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    investigation_id BIGINT NOT NULL REFERENCES alert_investigations(id),
    actor_username   TEXT NOT NULL,
    rating           TEXT NOT NULL CHECK (rating IN ('correct', 'incorrect')),
    reason           TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS triage_feedback_investigation ON triage_feedback (investigation_id);
