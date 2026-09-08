-- 0017: what an API key may do.
--
-- Until now every key was the same key: it could read the sealed archive,
-- which is what the comment on api_keys promised, and it could also send
-- messages as the paired number, accept group invitations, ask the phone for
-- history and stop devices — none of which the comment mentioned, and all of
-- which a leaked key could do from anywhere.
--
-- A scope names the ceiling. 'read' is the archive as ciphertext and nothing
-- that reaches WhatsApp; 'send' adds outbound messages and attachments; 'full'
-- adds the operations that change what a device is doing. Existing keys keep
-- 'full', because that is what they had, and revoking capability by migration
-- is how a monitoring job stops working at three in the morning.
ALTER TABLE api_keys
    ADD COLUMN scope text NOT NULL DEFAULT 'full'
        CHECK (scope IN ('read', 'send', 'full'));
