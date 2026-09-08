-- A stable identity for a chat, so its name can be sealed.
--
-- Sealed values are bound to the row they belong to through the associated
-- data, which is what stops a ciphertext being moved from one row to another
-- and still opening. Messages have a uuid for that; chats were keyed only by
-- (device_id, chat_key), so there was nothing to bind a sealed name to.
--
-- Derived rather than generated: uuidv5 over the device and the chat key, so
-- both sides can compute it without a round trip and it stays the same across
-- a re-import. Predictability is fine -- associated data is a binding, not a
-- secret.
ALTER TABLE chats ADD COLUMN uid uuid;

-- Names arrive with the history sync, which also carries the rest of what a
-- chat list needs. These columns already existed; this migration is what
-- finally has something to put in them.
COMMENT ON COLUMN chats.name_sealed IS
    'Display name, sealed. For a direct chat it is a person''s name, which is content.';
