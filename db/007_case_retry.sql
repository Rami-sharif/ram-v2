-- RAM v2 — recover from a failed TheHive case creation.
--
-- A high/flagged alert whose case creation failed (e.g. TheHive licence-gated,
-- down, or rejecting the request) used to land in the console with case_id NULL
-- and no way to ever link a case. Two changes fix that:
--
-- 1. The investigation now RECORDS the failed attempt (case_error) and keeps the
--    inputs needed to retry it (alert_payload, enrichment) — all written at INSERT
--    time, so alert_investigations stays write-once.
-- 2. The retry result lands in its own table (investigation_case_links) rather than
--    UPDATEing the immutable agent output. The console reads the effective case as
--    coalesce(alert_investigations.case_id, investigation_case_links.case_id).

-- Add the three retry-support columns; guarded so re-running is a no-op if present.
ALTER TABLE alert_investigations
    -- Records the error from a failed automatic case-creation attempt (NULL = succeeded/not attempted).
    ADD COLUMN IF NOT EXISTS case_error    TEXT,
    -- Snapshot of the normalized alert as received, kept so a retry can replay it verbatim.
    ADD COLUMN IF NOT EXISTS alert_payload JSONB,
    -- Snapshot of tool enrichment gathered during analysis, replayed into the retried case description.
    ADD COLUMN IF NOT EXISTS enrichment    JSONB;

-- Document each new column's purpose directly on the schema for future readers/tools.
COMMENT ON COLUMN alert_investigations.case_error IS
    'Error from a FAILED TheHive case creation attempt during triage (NULL = no failure). '
    'Its presence with case_id NULL is what makes an investigation retryable.';
COMMENT ON COLUMN alert_investigations.alert_payload IS
    'The normalized Wazuh alert as received — replayed verbatim when an analyst retries case creation.';
COMMENT ON COLUMN alert_investigations.enrichment IS
    'Tool enrichment gathered during analysis — replayed into the retried case description.';

-- Retry result: the case an analyst created for an investigation after the
-- automatic attempt failed. One link per investigation (a second retry on an
-- already-linked investigation is refused by the console, not the DB).
CREATE TABLE IF NOT EXISTS investigation_case_links (
    -- Auto-generated surrogate primary key for the link row.
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The investigation this retried case belongs to; UNIQUE enforces at most one link per investigation.
    investigation_id BIGINT NOT NULL UNIQUE REFERENCES alert_investigations(id),
    -- TheHive case id created by the retry.
    case_id          TEXT NOT NULL,
    -- TheHive human-readable case number matching case_id, if available.
    case_number      BIGINT,
    -- Analyst who performed the retry (attribution).
    actor_username   TEXT NOT NULL,
    -- When the retry succeeded and this link was recorded.
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
