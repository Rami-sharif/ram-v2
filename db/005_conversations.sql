-- RAM v2 — multi-conversation support for the analyst assistant.
-- Previously there was ONE ongoing thread per analyst (console_chat.thread_key =
-- username). This adds named, isolated conversations: each chat is its own
-- thread with its own history, while the shared SOC alert memory
-- (soc_memory_vectors) stays global to every chat.
--
-- Design: conversations are a metadata layer ON TOP OF the existing thread_key.
-- console_chat is UNCHANGED (still write-once; still keyed by thread_key). A new
-- conversation simply mints a fresh thread_key ("<username>:<token>"). This avoids
-- any UPDATE on the write-once console_chat table.

CREATE TABLE IF NOT EXISTS console_conversations (
    -- Auto-generated surrogate primary key for the conversation.
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    thread_key     TEXT NOT NULL UNIQUE,            -- matches console_chat.thread_key
    owner_username TEXT NOT NULL,                   -- the analyst who owns this chat
    -- Display title for the conversation, editable by the analyst; defaults for new chats.
    title          TEXT NOT NULL DEFAULT 'New chat',
    -- When the conversation was created.
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()  -- bumped on each new message; sort key
);
-- Speeds up listing an analyst's conversations ordered by most recently active.
CREATE INDEX IF NOT EXISTS console_conversations_owner
    ON console_conversations (owner_username, updated_at DESC);

-- Adopt each pre-existing per-analyst thread as a single conversation, so no
-- history is orphaned. Existing thread_key == username == owner (the old model).
-- Pure INSERT into the NEW table — never touches write-once console_chat.
-- Backfill: derive one conversation row per distinct existing thread_key.
INSERT INTO console_conversations (thread_key, owner_username, title, created_at, updated_at)
-- Select the thread_key (doubling as the legacy owner), a generic title, and the
-- thread's earliest/latest message timestamps to seed created_at/updated_at.
SELECT thread_key, thread_key AS owner_username, 'Conversation' AS title,
       min(created_at) AS created_at, max(created_at) AS updated_at
FROM console_chat
-- One row per thread_key, aggregating its message timestamps.
GROUP BY thread_key
-- Safe to re-run: skip threads that were already adopted into a conversation.
ON CONFLICT (thread_key) DO NOTHING;
