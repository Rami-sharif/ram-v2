-- RAM v2 Phase 6 — dashboard-level analyst chat.
-- A single ongoing assistant thread per ANALYST (not per investigation): the
-- analyst chats freely from the queue page and can ask about ANY case by its
-- TheHive case number, compare cases, or ask general questions. A message is
-- therefore NOT scoped to one investigation; it may reference zero or more
-- investigations (the cases the assistant looked up while answering that turn).
--
-- This table is the conversation log ONLY; consequential actions taken during a
-- chat are recorded in audit_log by their underlying functions (audit_log remains
-- the authority on actions). Write-once per MESSAGE: rows are inserted (and may be
-- deleted for retention) but never UPDATEd, mirroring alert_investigations.

CREATE TABLE IF NOT EXISTS console_chat (
    -- Auto-generated surrogate primary key for the chat message.
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    thread_key          TEXT NOT NULL,                       -- analyst username; groups the ongoing thread
    -- Who authored the message; restricted to the two participants in the chat.
    role                TEXT NOT NULL CHECK (role IN ('analyst', 'agent')),
    actor               TEXT NOT NULL,                       -- analyst username, or 'agent'
    -- The message text/content itself.
    message             TEXT NOT NULL,
    tool_calls          JSONB NOT NULL DEFAULT '[]'::jsonb,  -- [{tool,args,reason,error,ok}] on agent turns
    -- Zero or more alert_investigations.id values this message discussed. Best-effort
    -- (no FK: a case may be deleted for retention). The queue resolves each id
    -- defensively and never 404s on a missing one, mirroring retrieved_ids.
    referenced_case_ids BIGINT[] NOT NULL DEFAULT '{}'::bigint[],
    -- When the message was sent/recorded.
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Speeds up loading a thread's messages in chronological order.
CREATE INDEX IF NOT EXISTS console_chat_thread ON console_chat (thread_key, created_at);

-- Enforce write-once per message: insert/delete allowed, UPDATE rejected.
-- Trigger function body: unconditionally aborts any UPDATE attempt with a clear error.
CREATE OR REPLACE FUNCTION reject_update_console_chat() RETURNS trigger AS $$
BEGIN
    -- Abort the UPDATE transaction; the message documents WHY (immutability guarantee).
    RAISE EXCEPTION 'console_chat is write-once: messages are immutable';
END;
$$ LANGUAGE plpgsql;

-- Drop any prior version of the trigger first so this migration is safely re-runnable.
DROP TRIGGER IF EXISTS console_chat_no_update ON console_chat;
-- Attach the trigger: fires before every row UPDATE and calls the rejection function.
CREATE TRIGGER console_chat_no_update
    BEFORE UPDATE ON console_chat
    FOR EACH ROW EXECUTE FUNCTION reject_update_console_chat();
