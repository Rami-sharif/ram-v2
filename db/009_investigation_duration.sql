-- RAM v2 — investigation latency instrumentation (metrics dashboard, Part B)
-- Records the wall-clock time the pipeline spent on each alert, so the metrics dashboard
-- can report p50/p95 investigation latency. Nullable: rows written before this migration
-- (and any where timing wasn't captured) simply read as NULL and are excluded from the
-- percentile calc. This is an INSERT-time value only — the write-once trigger is untouched
-- (the row is still never UPDATEd), and the column is not agent-facing.

ALTER TABLE alert_investigations
    ADD COLUMN IF NOT EXISTS duration_ms INTEGER;

COMMENT ON COLUMN alert_investigations.duration_ms IS
    'Wall-clock milliseconds the webhook pipeline spent producing this record '
    '(gated duplicates are near-zero; real investigations are agent-dominated).';
