-- RAM v2 Phase 5 — analyst console schema.
-- TheHive stays the case system of record; these tables back the console only.

-- Per-analyst local accounts -------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    -- Auto-generated surrogate primary key for the account.
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Login name; unique so it can double as the natural identifier used elsewhere (e.g. thread_key).
    username      TEXT UNIQUE NOT NULL,
    -- Hashed password (never store plaintext); verified at login time.
    password_hash TEXT NOT NULL,
    -- Optional human-friendly name shown in the UI instead of the raw username.
    display_name  TEXT,
    -- Authorization role, defaults to the least-privileged 'analyst'.
    role          TEXT NOT NULL DEFAULT 'analyst',
    -- Soft-disable flag; disabled accounts can be blocked from login without deleting history.
    disabled      BOOLEAN NOT NULL DEFAULT false,
    -- Account creation timestamp.
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Audit log: every consequential analyst action, attributed -------------------
CREATE TABLE IF NOT EXISTS audit_log (
    -- Auto-generated surrogate primary key for the audit entry.
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Username of the analyst who performed the action (attribution).
    actor_username TEXT NOT NULL,
    -- Short machine-readable name of the action taken (e.g. "confirm", "override").
    action         TEXT NOT NULL,
    -- Type of entity the action targeted (e.g. "investigation"), for generic rendering/filtering.
    target_type    TEXT,
    -- Identifier of the specific target entity affected.
    target_id      TEXT,
    -- Snapshot of the target's state before the action, for diffing/rollback context.
    before         JSONB,
    -- Snapshot of the target's state after the action.
    after          JSONB,
    -- Free-text human-readable detail about the action.
    detail         TEXT,
    -- When the action occurred.
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Speeds up "most recent audit entries first" queries for the audit view.
CREATE INDEX IF NOT EXISTS audit_log_created_at ON audit_log (created_at DESC);
-- Speeds up filtering the audit log by a specific analyst.
CREATE INDEX IF NOT EXISTS audit_log_actor ON audit_log (actor_username);

-- WRITE-ONCE record of what the agent produced per alert ---------------------
-- The agent's analysis + tool trace are immutable ground truth (audit trail +
-- future tuning dataset). Human input lives in verdict_reviews/triage_feedback.
CREATE TABLE IF NOT EXISTS alert_investigations (
    -- Auto-generated surrogate primary key; referenced by verdict_reviews/triage_feedback.
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Source alert's own identifier (e.g. Wazuh alert id), for cross-referencing the raw alert.
    alert_id         TEXT,
    -- Name of the agent that produced this investigation.
    agent_name       TEXT,
    -- Source IP implicated in the alert, if any.
    source_ip        TEXT,
    -- Wazuh rule id that triggered the alert, if any.
    rule_id          TEXT,
    -- Numeric severity score assigned by the agent (drives sorting/thresholds).
    severity_score   INTEGER,
    -- Human-readable severity label (e.g. "high", "low") corresponding to the score.
    severity_label   TEXT,
    -- Agent's classification of the attack/technique observed.
    attack_type      TEXT,
    -- Full agent analysis payload (verdict, reasoning, etc.); immutable once written.
    analysis         JSONB NOT NULL,
    -- Ordered trace of tool calls the agent made while investigating; defaults to empty array.
    tool_trace       JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Text of the semantic-memory context retrieved and given to the agent for this alert.
    memory_context   TEXT,
    -- IDs of the soc_memory_vectors rows that were retrieved as context (best-effort, no FK).
    retrieved_ids    JSONB,
    -- Which triage action the agent decided on (e.g. "open_case", "suppress").
    triage_action    TEXT,
    -- Which branch/path of the triage decision logic was taken, for debugging/analytics.
    triage_branch    TEXT,
    -- How many times this alert (by dedup key) has recurred, mirrored from triage_dedup at write time.
    occurrence_count INTEGER,
    -- Whether this occurrence was suppressed as a duplicate rather than escalated.
    suppressed       BOOLEAN,
    -- TheHive case id opened for this investigation, if one was created.
    case_id          TEXT,
    -- TheHive human-readable case number matching case_id, if any.
    case_number      BIGINT,
    -- When the investigation was recorded (write-once; never updated afterward).
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Speeds up "most recent investigations first" queries for the console queue.
CREATE INDEX IF NOT EXISTS alert_investigations_created_at ON alert_investigations (created_at DESC);
-- Speeds up filtering investigations by which agent produced them.
CREATE INDEX IF NOT EXISTS alert_investigations_agent ON alert_investigations (agent_name);
-- Speeds up filtering investigations by triage action (e.g. show only opened cases).
CREATE INDEX IF NOT EXISTS alert_investigations_action ON alert_investigations (triage_action);
-- Speeds up sorting/filtering investigations by severity score.
CREATE INDEX IF NOT EXISTS alert_investigations_score ON alert_investigations (severity_score);

-- Enforce write-once: agent output may be inserted and deleted (retention),
-- but never UPDATEd.
-- Trigger function body: unconditionally aborts any UPDATE attempt with a clear error.
CREATE OR REPLACE FUNCTION reject_update_alert_investigations() RETURNS trigger AS $$
BEGIN
    -- Abort the UPDATE transaction; the message documents WHY (immutability guarantee).
    RAISE EXCEPTION 'alert_investigations is write-once: agent output is immutable';
END;
$$ LANGUAGE plpgsql;

-- Drop any prior version of the trigger first so this migration is safely re-runnable.
DROP TRIGGER IF EXISTS alert_investigations_no_update ON alert_investigations;
-- Attach the trigger: fires before every row UPDATE and calls the rejection function.
CREATE TRIGGER alert_investigations_no_update
    BEFORE UPDATE ON alert_investigations
    FOR EACH ROW EXECUTE FUNCTION reject_update_alert_investigations();

-- Human verdict review (confirm/override), layered on top -------------------
CREATE TABLE IF NOT EXISTS verdict_reviews (
    -- Auto-generated surrogate primary key for the review entry.
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The investigation this review applies to; FK enforces it must exist.
    investigation_id BIGINT NOT NULL REFERENCES alert_investigations(id),
    -- Analyst who performed the review (attribution).
    actor_username   TEXT NOT NULL,
    -- Whether the analyst confirmed the agent's verdict or overrode it; restricted to these two values.
    action           TEXT NOT NULL CHECK (action IN ('confirm', 'override')),
    -- The analyst's replacement verdict payload when action = 'override'; NULL on confirm.
    override_payload JSONB,
    -- Free-text justification for the confirm/override decision.
    reason           TEXT,
    -- When the review was recorded.
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Speeds up looking up all reviews for a given investigation.
CREATE INDEX IF NOT EXISTS verdict_reviews_investigation ON verdict_reviews (investigation_id);

-- Triage-decision feedback (stored for tuning; no behavior change this phase) -
CREATE TABLE IF NOT EXISTS triage_feedback (
    -- Auto-generated surrogate primary key for the feedback entry.
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The investigation this feedback rates; FK enforces it must exist.
    investigation_id BIGINT NOT NULL REFERENCES alert_investigations(id),
    -- Analyst who gave the feedback (attribution).
    actor_username   TEXT NOT NULL,
    -- Whether the analyst thought the triage decision was correct; restricted to these two values.
    rating           TEXT NOT NULL CHECK (rating IN ('correct', 'incorrect')),
    -- Free-text justification for the rating.
    reason           TEXT,
    -- When the feedback was recorded.
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Speeds up looking up all feedback for a given investigation.
CREATE INDEX IF NOT EXISTS triage_feedback_investigation ON triage_feedback (investigation_id);
