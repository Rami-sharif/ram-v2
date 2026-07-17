-- RAM v2 — link an investigation to the semantic-memory row written for its alert.
-- This closes the analyst-feedback learning loop: when an analyst confirms or
-- overrides an investigation's verdict, we can update THAT alert's memory row with
-- the human ground truth (via memory.update_analysis, no re-embed), so future
-- similar alerts retrieve the corrected verdict instead of the agent's past guess.
--
-- Nullable + additive: existing investigations stay NULL (simply not correctable);
-- only investigations recorded after this change carry the link and can teach.

-- Add the linking column; guarded so re-running the migration is a no-op if it already exists.
ALTER TABLE alert_investigations
    -- Points at the soc_memory_vectors row for this alert; no FK/NOT NULL since memory
    -- rows may be pruned and older investigations predate this link (stay NULL).
    ADD COLUMN IF NOT EXISTS memory_id BIGINT;

-- Document the new column's purpose directly on the schema for future readers/tools.
COMMENT ON COLUMN alert_investigations.memory_id IS
    'soc_memory_vectors.id written for this alert (no FK: memory rows may be pruned).';
