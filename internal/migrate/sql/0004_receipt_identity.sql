-- Rekey receipts on the message id alone.
--
-- Found with real traffic, not by reasoning: a message this server sent to a
-- phone number was stored with chat_key "5511999999999@s.whatsapp.net", and the
-- delivery receipt for that same message came back addressed
-- "224437861388494@lid". Same conversation, same message id, two different
-- chat keys -- so a join that included chat_key found nothing, and every
-- acknowledgement was invisible to the projection that exists to use them.
--
-- This is the (lid, pn) identity problem crossing a table boundary. WhatsApp
-- addresses a message one way and its receipt the other, and nothing here can
-- reconcile the two until the contact mapping arrives in phase 6.
--
-- The link that does not depend on any of that is the message id, which is what
-- WhatsApp itself resolves a receipt by. A collision would need two different
-- chats on one device to draw the same 22 hex characters, and it would merge two
-- acknowledgements; the alternative is losing all of them, systematically, right
-- now.
--
-- chat_key stays, and is not rewritten to match the message's. It records the
-- addressing the acknowledgement actually arrived under, which is a fact about
-- what WhatsApp sent. Overwriting it with the message's key would be inventing
-- data to make a join look tidy.

-- Two rows differing only by chat_key are the same acknowledgement recorded
-- under two addressings. Keep the earliest, which is when it was first learned.
DELETE FROM receipts a USING receipts b
 WHERE a.device_id = b.device_id
   AND a.wa_id = b.wa_id
   AND a.reader_key = b.reader_key
   AND a.kind = b.kind
   AND (a.ts, a.chat_key) > (b.ts, b.chat_key);

ALTER TABLE receipts DROP CONSTRAINT receipts_pkey;
ALTER TABLE receipts ADD PRIMARY KEY (device_id, wa_id, reader_key, kind);
