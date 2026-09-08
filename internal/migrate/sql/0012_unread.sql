-- A badge that agrees with the conversation under it.
--
-- chats.unread has existed since 0002 and has had exactly one writer: the
-- history sync, copying Conversation.GetUnreadCount(). Nothing incremented it
-- when a message arrived and nothing cleared it when one was read. So the
-- number was whatever the phone last said, frozen — a chat could sit at 3 with
-- forty unread messages under it, or at 3 with none, and the two look the same.
--
-- Two columns make it a fact instead of a memory.
--
-- counts_unread answers "does this row belong in a badge", once, on the row
-- itself. Deriving it in each query instead would mean the rule lives in the
-- increment, in the recount, and in whatever asks next — three copies that
-- drift, which is how this project's predecessor ended up with two disagreeing
-- definitions of a revoked reaction.
--
-- read_through_seq is the position the reader has got to. Storing a position
-- rather than decrementing a counter is what makes the three clearing paths
-- idempotent: a read receipt that arrives twice, an app-state event replayed by
-- a full sync, and an explicit mark from the browser all move a watermark
-- forward, and moving a watermark that has already passed is a no-op. A
-- counter would have to know which of the three it had already heard.

-- STORED, and not by preference. PostgreSQL 18 defaults a generated column to
-- VIRTUAL, which is computed on read and cannot be indexed — so the partial
-- index below would fail to create, and the recount would seq-scan messages for
-- every chat that gets marked read.
ALTER TABLE messages ADD COLUMN counts_unread boolean NOT NULL
    GENERATED ALWAYS AS (
        kind = 'message'
        -- Only messages. An edit, a deletion or a reaction is a row of its own
        -- here, and a badge promising "something new to read" that turns out to
        -- be somebody's thumbs-up is a badge nobody trusts twice.
        AND NOT is_from_me
        -- A history sync writes its own absolute count in the same pass that
        -- ingests the messages, and it writes it FIRST -- storeChatMeta runs
        -- before ingestMessages. Counting backfilled rows too would add
        -- nineteen thousand to a number the phone had just told us was three.
        AND source <> 'history'
        AND type <> 'poll_vote'
        -- Status is not a conversation. It is one pseudo-chat holding dozens of
        -- unrelated people talking past each other, and it is drawn apart from
        -- the chat list for exactly that reason.
        AND chat_key <> 'status@broadcast'
    ) STORED;

COMMENT ON COLUMN messages.counts_unread IS
    'Whether this row belongs in a chat badge. Generated so the rule has one '
    'definition rather than one per query.';

-- The recount's access path: everything unread in a chat above a watermark.
CREATE INDEX messages_unread ON messages (device_id, chat_key, seq)
    WHERE counts_unread;

ALTER TABLE chats ADD COLUMN read_through_seq bigint NOT NULL DEFAULT 0;

COMMENT ON COLUMN chats.read_through_seq IS
    'How far the reader has got, as a sequence number. Clearing moves it '
    'forward, which makes every clearing path idempotent.';

-- ---------------------------------------------------------------------------
-- Backfill: everything already archived counts as read.
--
-- The alternative is starting every conversation at its full history, so the
-- first thing a reader sees after this migration is a sidebar of four-figure
-- badges for messages they read months ago on their phone.
--
-- Both tables leave row-level security for the length of the write, and that
-- is the part worth stating. A migration runs with no app.tenant_id, so a
-- policy-protected table matches nothing -- silently, reporting success. The
-- established dance covers the table being WRITTEN. It is not enough here,
-- because the value being written is READ from messages, which is under FORCE
-- RLS too: leaving that one enabled makes the subquery return no rows, every
-- read_through_seq stays 0, and the first chat anybody opens counts its entire
-- history as unread. Nothing errors and an empty test database never notices.
--
-- 0010_order_by_time.sql has this exact bug: it disables RLS on chats and then
-- reads FROM messages. Its backfill matched nothing on the live archive. The
-- damage self-heals -- the GREATEST in the insert path repairs one chat per
-- message -- which is why it went unseen, and why the guard in rls_test.go was
-- widened in the same commit as this file.
-- ---------------------------------------------------------------------------
ALTER TABLE chats DISABLE ROW LEVEL SECURITY;
ALTER TABLE messages DISABLE ROW LEVEL SECURITY;

UPDATE chats c
   SET read_through_seq = m.newest
  FROM (
      SELECT device_id, chat_key, max(seq) AS newest
        FROM messages
       GROUP BY device_id, chat_key
  ) m
 WHERE c.device_id = m.device_id
   AND c.chat_key = m.chat_key;

ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages FORCE ROW LEVEL SECURITY;
ALTER TABLE chats ENABLE ROW LEVEL SECURITY;
ALTER TABLE chats FORCE ROW LEVEL SECURITY;
