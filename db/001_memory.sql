-- RAM v2 Phase 2 — semantic memory layer
-- pgvector-backed store of alert identities + analyses for retrieval.
-- LOCKED: embeddings are gemini-embedding-001 @ 768 dims, L2-normalized client-side.
-- Changing the model/normalization requires re-embedding every row.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS soc_memory_vectors (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_name      TEXT        NOT NULL,
    source_ip       TEXT,
    rule_id         TEXT,
    alert_text      TEXT        NOT NULL,   -- the embedded identity string (byte-identical to what was embedded)
    analysis        JSONB       NOT NULL,
    embedding       vector(768) NOT NULL,
    alert_timestamp TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ANN index for cosine similarity (vectors are unit-normalized, so cosine == dot).
CREATE INDEX IF NOT EXISTS soc_memory_vectors_embedding_hnsw
    ON soc_memory_vectors USING hnsw (embedding vector_cosine_ops);

-- Filter / recency indexes for retrieval and the operator endpoints.
CREATE INDEX IF NOT EXISTS soc_memory_vectors_agent_name ON soc_memory_vectors (agent_name);
CREATE INDEX IF NOT EXISTS soc_memory_vectors_source_ip  ON soc_memory_vectors (source_ip);
CREATE INDEX IF NOT EXISTS soc_memory_vectors_rule_id    ON soc_memory_vectors (rule_id);
CREATE INDEX IF NOT EXISTS soc_memory_vectors_created_at ON soc_memory_vectors (created_at DESC);
