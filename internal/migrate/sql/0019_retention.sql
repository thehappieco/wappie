-- 0019: how long a tenant keeps what it archived.
--
-- Nothing here expired. Messages, receipts and attachments were kept for as
-- long as the database existed, for every third party who ever wrote to a
-- paired number and never agreed to be archived at all. That is a choice a
-- tenant should make on purpose, and the schema had nowhere to record it.
--
-- Null means forever, which is what every existing tenant had and keeps.
ALTER TABLE tenants
    ADD COLUMN retention_days integer CHECK (retention_days IS NULL OR retention_days >= 1);
