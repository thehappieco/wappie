-- Retry bookkeeping for attachment downloads.
--
-- Without it a permanently unavailable attachment -- a 404 from the CDN, a
-- capability URL that has expired, a hash that will never match -- is picked up
-- by every pass of the worker forever, and the queue of things that will never
-- succeed crowds out the ones that would.
--
-- next_attempt_at is when the row becomes eligible again, and the worker backs
-- it off exponentially. attempts is kept rather than reset on success so a row
-- that needed six tries is visible as such afterwards.
ALTER TABLE media
    ADD COLUMN attempts        integer     NOT NULL DEFAULT 0,
    ADD COLUMN next_attempt_at timestamptz,
    -- The size of what is actually stored: WhatsApp's ciphertext, which is the
    -- plaintext padded to a 16 byte boundary plus a 10 byte MAC. Distinct from
    -- file_length, which is what the sender said the plaintext measures --
    -- and which is their claim, not a checked fact.
    ADD COLUMN object_size     bigint,
    -- When a worker took this row. The sweeper below needs it: created_at is
    -- when the attachment arrived, which for a backfilled row is weeks ago,
    -- and sweeping on that would return every claim to the queue the instant
    -- it was made.
    ADD COLUMN claimed_at      timestamptz;

-- The worker's query: rows due for a download, oldest first.
DROP INDEX media_pending;
CREATE INDEX media_pending ON media (tenant_id, next_attempt_at NULLS FIRST, created_at)
    WHERE download_status IN ('pending', 'failed');

-- Rows a worker claimed and never finished, because the process died holding
-- them. Swept back to pending by age.
CREATE INDEX media_claimed ON media (download_status, claimed_at)
    WHERE download_status = 'downloading';
