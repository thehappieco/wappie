-- A deleted number is kept for 30 days with its data, and an owner can
-- recover it in that time; then it is purged (decision 0038, as amended by
-- 0039 and 0040). The number keeps its devices row, marked deleted
-- ("excluído"), and a restrictive row-level security policy hides that row
-- from every query that does not opt in, so a query that forgets about
-- deletion fails closed instead of reading, counting or archiving into an
-- excluded number.
--
--   devices.deleted_at, deleted_by, purge_after
--                       when the number was deleted, by which owner, and
--                       when it is purged: deleted_at plus 30 days on the
--                       database's clock, stored once at the deletion. An
--                       excluded number is always paused, so no resume can
--                       restart it. deleted_by is SET NULL, so it never
--                       blocks an account's closing.
--   devices.purge_started_at
--                       set by the purge's first transaction; from then on
--                       the number cannot be recovered.
--   devices.wa_leftover {jid, registration_id[, attempts]}: the fingerprint
--                       of a WhatsApp session that may have survived the
--                       deletion's logout, taken from whatsmeow_device in
--                       the deletion's own transaction and cleared once a
--                       logout is confirmed. The purge removes a session
--                       only by this exact fingerprint, never by the JID
--                       alone, and never sends a logout.
--   devices.pause_seq   counts the pauses asked of a number (a person's or
--                       a key's stop, and Wappie's own pauses), whether or
--                       not it was paused already, so a transfer that failed
--                       undoes its own pause only while nobody has paused
--                       the number since.
--   devices_lid, devices_pn
--                       an identity is unique among live rows only: a
--                       phone linked again while its old row is excluded
--                       gets a new row, and recovering the old one is then
--                       refused. Foreign key and unique checks bypass
--                       row-level security, so the indexes leave the
--                       excluded rows out themselves.
--   device_quarantine   the restrictive policy, ANDed with tenant_isolation
--                       and device_move: an excluded row is visible only
--                       with app.device_quarantine 'on', a transaction-local
--                       scope that trusted server code sets (store's
--                       withQuarantine), as app.device_move_* is set (0036).
--                       It is also a write barrier: archive_device_owner
--                       (0036) reads devices under the caller's policies,
--                       so every insert or update of an excluded number's
--                       archive rows raises WS002, and a stale process
--                       cannot keep archiving into it. Deletes never fire
--                       it, so retention and the purge are unaffected.
--   media.content_key   the content-addressed object key of an attachment
--                       (tenant/xx/sha256 of its ciphertext), stored, so the
--                       reference checks of DeleteObject and of the orphan
--                       pass are two plain lookups that an index serves. An
--                       expression index cannot: its functions are not
--                       leakproof, and under forced row-level security a
--                       non-leakproof qualifier is never an index condition
--                       for a role that does not bypass it. A tenant_id
--                       change by a transfer recomputes it. storage_record_v1
--                       (0034) leaves it out of a media row's canonical
--                       bytes, as it leaves out object_key, so rule 1's
--                       measure is unchanged. Only a real SHA-256 (32 bytes)
--                       has one: a download whose hash is anything else is
--                       refused, so no object sits at any other content
--                       path, and the sender controls the hash, which hex
--                       doubles, so a long one would not fit an index entry
--                       and its message could not be archived.
--   device_notices      what Wappie tells a person in its own pages: a
--                       reader that a number's sync was turned off
--                       (sync_paused), and readers and the other owners
--                       that a number was deleted (number_deleted). One
--                       unseen notice per person, number and kind: a new
--                       pause folds into it. No foreign key to devices: a
--                       number_deleted notice outlives the purge, with its
--                       label and hint nulled. Forced row-level security.
--   item_events         the local log of what happened to a number:
--                       deleted, sync_paused, recovered, purged and
--                       moved_out, one row each, with plain columns and no
--                       JSON (a later release renders the platform
--                       contract's shapes from them). seq orders a
--                       workspace's events, since every writer holds the
--                       workspace's row lock until its commit. The four
--                       ledgered types are exported to a ledger file outside
--                       the database (ledgered_at), so a restore can replay
--                       them; sync_paused rows are written already marked.
--                       No foreign key to devices: the rows outlive the
--                       purge. Forced row-level security.
--
-- And one repair. An API key verifies by itself and its workspace only, and
-- a key whose creator was disabled, or is no longer a member, still worked:
-- removing a member revoked the keys they created, disabling one did not.
-- Every such key is revoked here (a key with no creator is left alone), so
-- none of them can reach a recovered number. One that has expired is revoked
-- as of its expiry, as ExpireAPIKeys records it, so the key list keeps the
-- date it stopped working and no extension can revive it. The revocation is
-- not undone by the down-step: those keys stay revoked, which is the repair.
-- The keys it closed while they still worked are exactly those revoked at
-- the ledger row's applied_at, which this same transaction writes with the
-- same now():
--   SELECT count(*) FROM api_keys
--    WHERE revoked_at = (SELECT applied_at FROM schema_migrations WHERE version = 50);
--
-- No capacity function changes: workspace_device_usage and
-- check_device_capacity read devices under its policies, so an excluded
-- number frees its slot by itself, and the commercial overrides of the same
-- functions count it out the same way.
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 50, so rolling back below it needs this first). Run only with
-- `wappie-api` stopped, and with `wappie-billing` stopped or already on the
-- release being restored: this release's wappie-billing runs core's storage
-- breakdown, which reads media.content_key and devices.deleted_at, so its
-- storage screen would fail from this down-step until it is restarted. Run
-- it after checking this file against `migration50_sha256` in the release's
-- RELEASE.json, as the table owner, and after `whatserverd deletions
-- export-ledger` as the wappie user. It locks the workspace, user and
-- membership tables before it changes anything, in the order wappie-billing's
-- transactions take them, so a billing request still running waits for it
-- instead of deadlocking with it. Its guards run first, inside
-- its one transaction, so a refusal changes nothing: it refuses while any
-- number is excluded (an older binary would show and sync every one of them
-- as live, and SQL cannot remove their objects: recover each, or purge it),
-- and while an event row is not in the ledger yet. The notices and the event
-- rows go with their tables; the ledger file stays as the record. It refuses
-- while schema_migrations holds a version above 50, and it comes down before
-- 0049: 0049's own down-step has no such guard.
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      DO $$
--      BEGIN
--        IF EXISTS (SELECT 1 FROM schema_migrations WHERE version > 50) THEN
--          RAISE EXCEPTION 'a migration after 0050 is applied; run its down-step first';
--        END IF;
--      END $$;
--      LOCK TABLE tenants, users, workspace_memberships IN ACCESS EXCLUSIVE MODE;
--      ALTER TABLE devices DISABLE ROW LEVEL SECURITY;
--      ALTER TABLE item_events DISABLE ROW LEVEL SECURITY;
--      DO $$
--      BEGIN
--        IF EXISTS (SELECT 1 FROM devices WHERE deleted_at IS NOT NULL) THEN
--          RAISE EXCEPTION 'excluded numbers exist: recover them, or run whatserverd devices purge-deleted --device D --now for each';
--        END IF;
--        IF EXISTS (SELECT 1 FROM item_events WHERE ledgered_at IS NULL) THEN
--          RAISE EXCEPTION 'event rows are not in the ledger yet: run whatserverd deletions export-ledger as wappie first';
--        END IF;
--      END $$;
--      DROP POLICY device_quarantine ON devices;
--      DROP FUNCTION device_quarantine_scope();
--      DROP TABLE item_events;
--      DROP TABLE device_notices;
--      DROP INDEX media_object_key;
--      DROP INDEX media_content_key;
--      ALTER TABLE media DROP COLUMN content_key;
--      CREATE OR REPLACE FUNCTION storage_record_v1(kind text, r jsonb) RETURNS jsonb
--      LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN
--       r := r - ARRAY['created_at','updated_at','seq','counts_unread'];
--       IF kind='messages' THEN
--        r := r - ARRAY['target_uid','target_rel','audience_count'];
--        IF coalesce(r->>'raw_sealed','') NOT IN ('','\x') THEN
--         r := r - ARRAY['body_sealed','payload_sealed'];
--        END IF;
--       ELSIF kind='chats' THEN
--        r := r - ARRAY['last_seq','last_ts','last_kind','last_type','unread','read_through_seq','participant_count','archived','pinned','muted_until'];
--       ELSIF kind='media' THEN
--        r := r - ARRAY['object_key','object_size','download_status','download_error','downloaded_at','next_attempt_at','claimed_at','attempts','direct_path','url'];
--       END IF;
--       RETURN jsonb_strip_nulls(r);
--      END $$;
--      DROP INDEX devices_purge_due;
--      DROP INDEX devices_lid;
--      DROP INDEX devices_pn;
--      CREATE UNIQUE INDEX devices_lid ON devices (tenant_id, lid) WHERE lid IS NOT NULL;
--      CREATE UNIQUE INDEX devices_pn  ON devices (tenant_id, pn)  WHERE pn IS NOT NULL;
--      ALTER TABLE devices DROP CONSTRAINT devices_deletion_shape,
--          DROP COLUMN pause_seq, DROP COLUMN wa_leftover, DROP COLUMN purge_started_at, DROP COLUMN purge_after,
--          DROP COLUMN deleted_by, DROP COLUMN deleted_at;
--      ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
--      ALTER TABLE devices FORCE ROW LEVEL SECURITY;
--      DELETE FROM schema_migrations WHERE version = 50;
--      COMMIT;
--
-- It runs first: 0050 down, then 0049 down (the end of the rollback window),
-- 0048 down, and so on.

-- wappie-billing keeps running through this migration. Its transactions lock
-- the workspace row and the membership (FOR UPDATE OF t,m) before they read
-- devices, and the repair at the end takes workspace_memberships in ACCESS
-- EXCLUSIVE mode. Taking both first, in that order, makes a billing request
-- wait at its first statement instead of deadlocking with the ALTERs on
-- devices.
LOCK TABLE tenants, workspace_memberships IN ACCESS EXCLUSIVE MODE;

ALTER TABLE devices
    ADD COLUMN deleted_at       timestamptz,
    ADD COLUMN deleted_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN purge_after      timestamptz,
    ADD COLUMN purge_started_at timestamptz,
    ADD COLUMN wa_leftover      jsonb,
    ADD COLUMN pause_seq        bigint NOT NULL DEFAULT 0,
    ADD CONSTRAINT devices_deletion_shape CHECK (
            (deleted_at IS NULL) = (purge_after IS NULL)
        AND (deleted_at IS NULL OR paused)
        AND (purge_started_at IS NULL OR deleted_at IS NOT NULL)
        AND (wa_leftover IS NULL OR (jsonb_typeof(wa_leftover) = 'object'
                                     AND wa_leftover ? 'jid' AND wa_leftover ? 'registration_id')));
CREATE INDEX devices_purge_due ON devices (tenant_id, purge_after) WHERE deleted_at IS NOT NULL;

DROP INDEX devices_lid;
DROP INDEX devices_pn;
CREATE UNIQUE INDEX devices_lid ON devices (tenant_id, lid) WHERE lid IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX devices_pn  ON devices (tenant_id, pn)  WHERE pn  IS NOT NULL AND deleted_at IS NULL;

CREATE FUNCTION device_quarantine_scope() RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT coalesce(current_setting('app.device_quarantine', true), '') = 'on'
$$;
CREATE POLICY device_quarantine ON devices AS RESTRICTIVE FOR ALL
    USING (deleted_at IS NULL OR device_quarantine_scope())
    WITH CHECK (deleted_at IS NULL OR device_quarantine_scope());

CREATE OR REPLACE FUNCTION storage_record_v1(kind text, r jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN
 r := r - ARRAY['created_at','updated_at','seq','counts_unread'];
 IF kind='messages' THEN
  r := r - ARRAY['target_uid','target_rel','audience_count'];
  IF coalesce(r->>'raw_sealed','') NOT IN ('','\x') THEN
   r := r - ARRAY['body_sealed','payload_sealed'];
  END IF;
 ELSIF kind='chats' THEN
  r := r - ARRAY['last_seq','last_ts','last_kind','last_type','unread','read_through_seq','participant_count','archived','pinned','muted_until'];
 ELSIF kind='media' THEN
  r := r - ARRAY['object_key','object_size','download_status','download_error','downloaded_at','next_attempt_at','claimed_at','attempts','direct_path','url','content_key'];
 END IF;
 RETURN jsonb_strip_nulls(r);
END $$;
ALTER TABLE media ADD COLUMN content_key text GENERATED ALWAYS AS
    (CASE WHEN octet_length(file_enc_sha256) = 32 THEN
     tenant_id::text || '/' || left(encode(file_enc_sha256, 'hex'), 2) || '/' || encode(file_enc_sha256, 'hex') END) STORED;
CREATE INDEX media_object_key  ON media (object_key)  WHERE object_key  IS NOT NULL;
CREATE INDEX media_content_key ON media (content_key) WHERE content_key IS NOT NULL;

CREATE TABLE device_notices (
    id             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id      uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- No foreign key: a number_deleted notice outlives the purge.
    device_id      uuid        NOT NULL,
    user_id        uuid        NOT NULL,
    kind           text        NOT NULL CHECK (kind IN ('sync_paused', 'number_deleted')),
    -- The number's label for the contract, and "…" with the last four digits
    -- of its phone number: snapshots, never the number itself.
    label          text        CHECK (label IS NULL OR char_length(label) BETWEEN 1 AND 80),
    hint           text        CHECK (hint IS NULL OR hint ~ '^…[0-9]{4}$'),
    -- The first pause this notice covers, and the latest one folded into it.
    raised_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_raised_at timestamptz,
    pauses         int         NOT NULL DEFAULT 1 CHECK (pauses >= 1 AND (pauses = 1 OR kind = 'sync_paused')),
    -- The latest actor; for an API key, the person who created it.
    raised_by      uuid        REFERENCES users(id) ON DELETE SET NULL,
    raised_by_kind text        NOT NULL CHECK (raised_by_kind IN ('person', 'key')),
    -- A pause folded into this notice had another actor than the latest.
    several_actors boolean     NOT NULL DEFAULT false CHECK (NOT several_actors OR pauses > 1),
    -- purge_after, for number_deleted.
    until          timestamptz,
    -- The pause ended; the notice stays until it is seen.
    resumed_at     timestamptz CHECK (resumed_at IS NULL OR kind = 'sync_paused'),
    -- The number was purged: label and hint are nulled then.
    purged_at      timestamptz CHECK (purged_at IS NULL OR kind = 'number_deleted'),
    seen_at        timestamptz,
    FOREIGN KEY (tenant_id, user_id) REFERENCES workspace_memberships(tenant_id, user_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX device_notices_one_unseen ON device_notices (tenant_id, device_id, user_id, kind) WHERE seen_at IS NULL;
CREATE INDEX device_notices_unseen ON device_notices (tenant_id, user_id) WHERE seen_at IS NULL;
ALTER TABLE device_notices ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_notices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_notices
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE TABLE item_events (
    seq           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- A UUIDv7 made once in Go: the contract's idempotency key later.
    event_id      uuid        NOT NULL UNIQUE,
    -- A last resort: Wappie purges a workspace's numbers before deleting it.
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type          text        NOT NULL CHECK (type IN ('deleted', 'sync_paused', 'recovered', 'purged', 'moved_out')),
    -- No foreign key: the rows outlive the purge.
    item_id       uuid        NOT NULL,
    -- Local only, never sent.
    dedupe_key    text        NOT NULL,
    -- The database's clock.
    occurred_at   timestamptz NOT NULL,
    actor_kind    text        NOT NULL CHECK (actor_kind IN ('person', 'key', 'app')),
    -- The person's platform sub, or the sub of a key's creator; NULL for the
    -- app, a key with no creator, or a person with no sub.
    actor_sub     uuid,
    -- Local: the person, or a key's creator. Never sent.
    actor_user_id uuid        REFERENCES users(id) ON DELETE SET NULL,
    -- The readers' platform subs, the actor included.
    reader_subs   uuid[]      NOT NULL DEFAULT '{}',
    -- Nulled at the purge.
    label         text        CHECK (label IS NULL OR char_length(label) BETWEEN 1 AND 80),
    hint          text        CHECK (hint IS NULL OR hint ~ '^…[0-9]{4}$'),
    -- deleted, recovered (the deletion it reverses) and purged.
    deleted_at    timestamptz,
    -- deleted and purged.
    purge_after   timestamptz,
    -- moved_out only.
    to_tenant_id  uuid,
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- Exported to the ledger file outside the database.
    ledgered_at   timestamptz,
    -- Written by a restore's replay, never sent.
    replayed_at   timestamptz,
    UNIQUE (tenant_id, dedupe_key),
    CHECK (type IN ('deleted', 'recovered', 'purged', 'moved_out') OR ledgered_at IS NOT NULL),
    CHECK ((type = 'moved_out') = (to_tenant_id IS NOT NULL)),
    CHECK (type NOT IN ('deleted', 'purged') OR (deleted_at IS NOT NULL AND purge_after IS NOT NULL)),
    CHECK (type <> 'recovered' OR deleted_at IS NOT NULL),
    CHECK (replayed_at IS NULL OR ledgered_at IS NOT NULL)
);
CREATE INDEX item_events_unledgered ON item_events (tenant_id, seq) WHERE ledgered_at IS NULL;
CREATE INDEX item_events_item       ON item_events (tenant_id, item_id);
CREATE INDEX item_events_created    ON item_events (tenant_id, created_at);
ALTER TABLE item_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE item_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON item_events
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- api_keys carries no policy (0001); workspace_memberships forces one (0021)
-- and a migration has no workspace, so it is lifted for this statement and
-- put back in this same transaction, as 0049 does for users.
ALTER TABLE workspace_memberships DISABLE ROW LEVEL SECURITY;
UPDATE api_keys k SET revoked_at = least(coalesce(k.expires_at, now()), now())
 WHERE k.revoked_at IS NULL AND k.created_by IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM workspace_memberships m
                    WHERE m.tenant_id = k.tenant_id AND m.user_id = k.created_by AND m.status = 'active');
ALTER TABLE workspace_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_memberships FORCE ROW LEVEL SECURITY;
