-- RAM v2 Phase 2 — semantic memory layer
-- pgvector-backed store of alert identities + analyses for retrieval.
-- LOCKED: embeddings are gemini-embedding-001 @ 768 dims, L2-normalized client-side.
-- Changing the model/normalization requires re-embedding every row.

-- Enable pgvector so the `vector` column type and ANN operators are available.
CREATE EXTENSION IF NOT EXISTS vector;

-- Main semantic-memory table: one row per embedded alert identity + its stored analysis.
CREATE TABLE IF NOT EXISTS soc_memory_vectors (
    -- Auto-generated surrogate primary key; identity column avoids needing a sequence name.
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Name of the agent that produced this memory row (used to scope/filter retrieval).
    agent_name      TEXT        NOT NULL,
    -- Source IP of the alert, if any; used as a retrieval/filter dimension.
    source_ip       TEXT,
    -- Wazuh rule id of the alert, if any; used as a retrieval/filter dimension.
    rule_id         TEXT,
    alert_text      TEXT        NOT NULL,   -- the embedded identity string (byte-identical to what was embedded)
    -- Full analysis payload (agent's verdict/reasoning) associated with this alert identity.
    analysis        JSONB       NOT NULL,
    -- The 768-dim embedding vector for alert_text; dimension is locked to gemini-embedding-001.
    embedding       vector(768) NOT NULL,
    -- When the underlying alert occurred (as opposed to when this row was written).
    alert_timestamp TIMESTAMPTZ,
    -- When this memory row was written; defaults to insertion time.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ANN index for cosine similarity (vectors are unit-normalized, so cosine == dot).
-- HNSW gives fast approximate nearest-neighbor search over embeddings at query time.
CREATE INDEX IF NOT EXISTS soc_memory_vectors_embedding_hnsw
    ON soc_memory_vectors USING hnsw (embedding vector_cosine_ops);

-- Filter / recency indexes for retrieval and the operator endpoints.
-- Speeds up filtering retrieval candidates by which agent produced them.
CREATE INDEX IF NOT EXISTS soc_memory_vectors_agent_name ON soc_memory_vectors (agent_name);
-- Speeds up filtering/looking up memory rows tied to a specific source IP.
CREATE INDEX IF NOT EXISTS soc_memory_vectors_source_ip  ON soc_memory_vectors (source_ip);
-- Speeds up filtering/looking up memory rows tied to a specific Wazuh rule.
CREATE INDEX IF NOT EXISTS soc_memory_vectors_rule_id    ON soc_memory_vectors (rule_id);
-- Speeds up "most recent" queries/pagination used by operator-facing endpoints.
CREATE INDEX IF NOT EXISTS soc_memory_vectors_created_at ON soc_memory_vectors (created_at DESC);
