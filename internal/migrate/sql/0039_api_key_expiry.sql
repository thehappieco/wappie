-- An API key may now carry a deadline. NULL keeps today's meaning: the key
-- lives until somebody revokes it.
--
-- The first use is the hosted assistant connector. The console issues that
-- key with a twenty-minute deadline before the person has finished consenting;
-- only a recorded connection extends it to the lifetime they chose. A consent
-- abandoned halfway therefore leaves nothing behind that could still open the
-- archive, and nothing to clean up by hand.
ALTER TABLE api_keys ADD COLUMN expires_at timestamptz;

-- The janitor asks "which live keys have a deadline that has passed"; the
-- partial index keeps that a scan of the few keys that have one at all.
CREATE INDEX api_keys_expiring ON api_keys (expires_at)
    WHERE revoked_at IS NULL AND expires_at IS NOT NULL;
