-- RAM v2 — identity-string format versioning
-- Adds a per-row marker recording which identity_string FORMAT produced a row's
-- embedded alert_text, so the two formats are never silently mixed (Step 2.3 of the
-- RAG enhancement). See app/memory.py:IDENTITY_VERSION.
--   v1 = "Rule: <desc> | SrcIP: <ip> | Groups: <groups> | Log: <raw_log>"
--   v2 = "Rule: <desc> | MITRE: <ids> | SrcIP: <ip> | Groups: <groups> | Log: <normalized_log>"
--
-- Existing rows are stamped v1 by the column DEFAULT below (they predate v2). The
-- app.backfill_identity script then re-embeds each v1 row with the v2 pipeline and
-- updates identity_version to 2. New rows written by memory.write_back set 2 explicitly.

ALTER TABLE soc_memory_vectors
    ADD COLUMN IF NOT EXISTS identity_version SMALLINT NOT NULL DEFAULT 1;

COMMENT ON COLUMN soc_memory_vectors.identity_version IS
    'Format version of the embedded alert_text (see app/memory.py:IDENTITY_VERSION). '
    'v1=raw log, no MITRE; v2=normalized log + input-side MITRE ids.';

-- Lets us quickly find rows still on an old identity format (e.g. to re-run a backfill).
CREATE INDEX IF NOT EXISTS soc_memory_vectors_identity_version
    ON soc_memory_vectors (identity_version);
