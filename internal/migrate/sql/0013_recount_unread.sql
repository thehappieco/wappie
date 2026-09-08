-- Make the badges agree with the rows, once.
--
-- 0012 gave every conversation a read watermark and left the number beside it
-- alone. Both halves were needed and only one was written, so the counts stayed
-- exactly as the history sync had last reported them — frozen, which is the
-- defect 0012 exists to remove. Measured on the archive this was written
-- against: 305 conversations carrying a badge totalling 14,865, of which 302 had
-- nothing at all above their watermark.
--
-- It is a separate migration rather than an edit to 0012 because 0012 has
-- already run. The files are checksummed and changing an applied one fails the
-- next boot, which is the property that makes a migration history trustworthy.
--
-- Recounted from the messages rather than zeroed. Zeroing would be right for
-- almost every row and wrong for the conversations that genuinely have unread
-- messages above the watermark, and the wrongness would be silent: a badge that
-- should say 4 saying nothing looks exactly like a conversation that is read.
--
-- Both policies come off, and the second one is the whole lesson of 0010: a
-- migration runs with no app.tenant_id, so a table left under FORCE RLS matches
-- nothing. Disabling only the table being WRITTEN leaves the subquery reading
-- messages returning zero rows, every count becomes 0, and the migration
-- reports success. That is precisely how 0010's backfill did nothing for two
-- phases without anybody noticing.
ALTER TABLE chats DISABLE ROW LEVEL SECURITY;
ALTER TABLE messages DISABLE ROW LEVEL SECURITY;

UPDATE chats c
   SET unread = (
       SELECT count(*)
         FROM messages m
        WHERE m.device_id = c.device_id
          AND m.chat_key = c.chat_key
          AND m.counts_unread
          AND m.seq > c.read_through_seq)
 WHERE c.unread <> (
       SELECT count(*)
         FROM messages m
        WHERE m.device_id = c.device_id
          AND m.chat_key = c.chat_key
          AND m.counts_unread
          AND m.seq > c.read_through_seq);

ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages FORCE ROW LEVEL SECURITY;
ALTER TABLE chats ENABLE ROW LEVEL SECURITY;
ALTER TABLE chats FORCE ROW LEVEL SECURITY;
