-- When the GROUP was created, which is not when we first heard of it.
--
-- A conversation with no message has nothing to sort by, and the sidebar was
-- falling back to chats.created_at — the moment this archive wrote the row. For
-- the groups discovered by a boot-time sync that is all the same instant, so
-- six hundred conversations ended up ordered by nothing at all, in whatever
-- order the listing happened to return them.
--
-- WhatsApp knows when each group was made and says so in the same answer that
-- carries the name, so it costs no extra round trip. A group made last week
-- then sits above one made in 2019, which is what a person means by "recent"
-- for a conversation nobody has spoken in yet.
--
-- Nullable, and stays null for direct conversations and for any group this
-- archive learned about before the sync could ask. The ordering falls back to
-- chats.created_at for those, which is worse but is what was there before.
ALTER TABLE chats ADD COLUMN group_created_at timestamptz;

COMMENT ON COLUMN chats.group_created_at IS
    'When the group itself was created, per WhatsApp. Orders conversations '
    'that have no message; distinct from created_at, which is when this '
    'archive first recorded the row.';

-- The sidebar's ordering, for the conversations that have no message. The
-- existing chats_recent index covers the ones that do.
CREATE INDEX chats_quiet ON chats (device_id, group_created_at DESC NULLS LAST)
    WHERE last_seq = 0;
