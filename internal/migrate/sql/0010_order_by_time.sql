-- A conversation is ordered by when it was sent, not by when it was stored.
--
-- seq is the tenant's insertion counter: a message gets its number when the
-- row is written. That was fine while everything arrived live, and stopped
-- being fine the moment history sync existed — a backfill writes last year's
-- messages with today's sequence numbers, and WhatsApp delivers each chunk
-- newest-first, so ordering by seq shows the history backwards and drops whole
-- blocks of it into the middle of today.
--
-- Measured on a real archive before this migration: within one conversation,
-- 17498 adjacent pairs in seq order had a timestamp EARLIER than the row before
-- them, across 206 chats.
--
-- seq keeps its other jobs. It is still the replay cursor, still the thing that
-- makes "a reader that can see N can see everything below N" true, and still
-- the tie-break here — WhatsApp timestamps are whole seconds and a burst of
-- messages inside one second is ordinary.

-- The index the display path needs. The existing messages_by_chat is
-- (device_id, chat_key, seq DESC) and cannot serve this ordering, which would
-- turn every page of a large conversation into a sort of the whole chat.
--
-- On the expression rather than on ts alone: ts is nullable, and a row that
-- somehow arrives without one should sort by when it was stored rather than
-- ahead of everything. coalesce over two plain columns is immutable, so it is
-- indexable.
CREATE INDEX messages_by_chat_time
    ON messages (device_id, chat_key, (coalesce(ts, created_at)) DESC, seq DESC);

-- The chat list has the same problem one level up: chats.last_ts was written by
-- whichever row was inserted last rather than by the newest one, so a backfill
-- could move a conversation's "latest" timestamp backwards in time. The insert
-- path now takes the GREATEST of the two; this repairs what the old path left.
--
-- No RLS dance needed: this is an UPDATE against a policy-protected table from
-- a migration, and it would silently match nothing. Disabled and re-enabled the
-- way 0009 does, for the same reason.
ALTER TABLE chats DISABLE ROW LEVEL SECURITY;

UPDATE chats c
   SET last_ts = m.newest
  FROM (
      SELECT device_id, chat_key, max(coalesce(ts, created_at)) AS newest
        FROM messages
       GROUP BY device_id, chat_key
  ) m
 WHERE c.device_id = m.device_id
   AND c.chat_key = m.chat_key
   AND (c.last_ts IS NULL OR c.last_ts < m.newest);

ALTER TABLE chats ENABLE ROW LEVEL SECURITY;
ALTER TABLE chats FORCE ROW LEVEL SECURITY;
