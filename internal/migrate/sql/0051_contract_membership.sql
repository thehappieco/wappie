-- The platform contract's membership part on Wappie's side (decisions 0040,
-- 0041 and 0043; release B): the state Wappie keeps of the contract, the
-- documents it receives, the workspaces they name, and what release A's
-- tables need to send their events and snapshots. Nothing here calls the
-- platform, and nothing changes how Wappie behaves until an operator turns
-- the contract to observe (contract_state.mode).
--
--   contract_state      one row: the mode ('off' until an operator switches
--                       it; enforce widens the CHECK), when events start to
--                       count (events_from, set once at the first observe;
--                       events_off, the off periods since; events_paused_at,
--                       the current one), mail_from (the self-hosted
--                       mailer's start: this migration's time, moved by
--                       every start that signs in through the platform),
--                       the platform database's generation and whether it
--                       is confirmed, the feed's cursor, the last
--                       published_through a page with more=false vouched
--                       for, the generation in which every person held
--                       has been subscribed (round_generation), and the
--                       leader's last read of the feed, its failures, the
--                       round's failing PUTs and its last ERROR, for
--                       contract status.
--   contract_accounts   one row per subscription Wappie made. The intent row
--                       (sub, subscribed_at) is committed before each PUT,
--                       so every subscription has a row the sweep can see;
--                       then the last document of the stored generation,
--                       as received (no email and no name: the contract's
--                       document carries none), newer versions only, with
--                       the highest disabled_at, sessions_revoked_at and
--                       credentials_revoked_at ever seen. fresh_at is the
--                       database's clock at the last answer to a PUT or GET
--                       for the sub, whatever its version; never a refusal,
--                       and never a feed page's document (a page vouches
--                       through published_through). No foreign key: a
--                       closed account's row outlives its user.
--   contract_workspaces every workspace a document has named: a platform
--                       workspace for good. Its kind never changes; its
--                       status moves only with a higher wversion. The
--                       snapshot and event queue columns are the senders'.
--                       No owner count: a team's move stays its only
--                       owner's (0043), checked locally.
--
-- The three carry no row-level security, as tenants and platform_identities
-- carry none: they are read before or across workspaces, and hold no content
-- (subs, workspace ids, roles, counts, and the team names inside the stored
-- documents).
--
--   item_events         the type stranded (a number that lost its last key
--                       holder, by a local act: person_sub and cause), the
--                       readers' local user ids beside their subs (never
--                       sent; the self-hosted mailer's), and delivery: a
--                       row is settled (accepted or duplicate on a signed
--                       answer, coalesced into a pause it was folded into,
--                       or not_sent when nobody but the actor reads), or
--                       parked with a reject code, never both. stranded is
--                       written already ledgered, as sync_paused is: a
--                       restore replays deletions, not strandings.
--   item_mails          the self-hosted mailer's queue, one row per event
--                       and recipient: an event of that workspace and a
--                       member of it, so a removed member's mails go with
--                       the membership. Forced row-level security.
--   device_notices      the owners' notices number_stranded and
--                       number_moved_out.
--   devices.pause_cause why a paused number is paused: a person's or a key's
--                       stop (person), Wappie's own pause for a move (move)
--                       or an exclusion (deletion). A paused number always
--                       has one and a live one none; a trigger sets the
--                       default (deletion when excluded, else person) for a
--                       writer that names none, and NULL on a resume.
--   sole_key_holders(t) every (number, person) whose key is the number's
--                       last recoverable one in workspace t: the rule that
--                       refuses removing or disabling them (store's
--                       strandedDevicesTx) and the snapshot's protected
--                       list, written once. SECURITY INVOKER, so the
--                       caller's policies apply.
--   contract_mark_dirty and its triggers
--                       a change a workspace's snapshot shows notifies
--                       wappie_contract_dirty with the workspace's id ('all'
--                       for a person's status or a new platform link, which
--                       reach every workspace of theirs). Notifications are
--                       folded per transaction and sent at its commit.
--   security_events     the kind platform_home_taken: a sign-up refused
--                       because the workspace id the platform named for it
--                       is a workspace Wappie has already.
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 51, so rolling back below it needs this first). Run only with
-- `wappie-api` stopped, and with `wappie-billing` stopped or already on the
-- release being restored, after `whatserverd contract mode off`, after
-- checking this file against `migration51_sha256` in the release's
-- RELEASE.json, as the table owner. It refuses while the contract is on, and
-- while schema_migrations holds a version above 51; a refusal changes
-- nothing. It loses the stored documents, the cursor and the record of
-- platform workspaces (the platform keeps its own; a later release B starts
-- with a new round of subscriptions, and person invitations into those teams
-- open again), the events not sent yet (counted below; the rows stay, as
-- release A's), the strandings' rows, the owners' notices and the home-taken
-- security events (each counted). The personal workspaces created with the
-- platform's ids stay: an id is all they took from it. security_events is
-- insert-only against the application's statements; the owner lifts that
-- trigger for its one delete and puts it back.
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      DO $$
--      BEGIN
--        IF EXISTS (SELECT 1 FROM schema_migrations WHERE version > 51) THEN
--          RAISE EXCEPTION 'a migration after 0051 is applied; run its down-step first';
--        END IF;
--        IF (SELECT mode FROM contract_state) <> 'off' THEN
--          RAISE EXCEPTION 'the contract is on: run whatserverd contract mode off first';
--        END IF;
--      END $$;
--      LOCK TABLE tenants, users, workspace_memberships IN ACCESS EXCLUSIVE MODE;
--      ALTER TABLE item_events DISABLE ROW LEVEL SECURITY;
--      ALTER TABLE device_notices DISABLE ROW LEVEL SECURITY;
--      DO $$
--      BEGIN
--        RAISE NOTICE 'dropping % stranded rows, % owners'' notices, % unsent events, % home-taken security events',
--          (SELECT count(*) FROM item_events WHERE type = 'stranded'),
--          (SELECT count(*) FROM device_notices WHERE kind IN ('number_stranded', 'number_moved_out')),
--          (SELECT count(*) FROM item_events WHERE settled_at IS NULL AND parked_at IS NULL AND type <> 'stranded'),
--          (SELECT count(*) FROM security_events WHERE kind = 'platform_home_taken');
--      END $$;
--      DELETE FROM item_events WHERE type = 'stranded';
--      DELETE FROM device_notices WHERE kind IN ('number_stranded', 'number_moved_out');
--      ALTER TABLE security_events DISABLE TRIGGER security_events_insert_only;
--      DELETE FROM security_events WHERE kind = 'platform_home_taken';
--      ALTER TABLE security_events ENABLE TRIGGER security_events_insert_only;
--      ALTER TABLE security_events DROP CONSTRAINT security_events_kind_check,
--          ADD CONSTRAINT security_events_kind_check CHECK (kind IN ('platform_account_key_changed', 'platform_linked'));
--      DROP TABLE item_mails;
--      DROP TRIGGER contract_dirty_identity ON platform_identities;
--      DROP TRIGGER contract_dirty_tenant ON tenants;
--      DROP FUNCTION contract_mark_tenant_dirty();
--      DROP TRIGGER contract_dirty_user ON users;
--      DROP FUNCTION contract_mark_all_dirty();
--      DROP TRIGGER contract_dirty_member ON workspace_memberships;
--      DROP TRIGGER contract_dirty_grant ON device_key_grants;
--      DROP TRIGGER contract_dirty_permission ON device_permissions;
--      DROP TRIGGER contract_dirty_device_update ON devices;
--      DROP TRIGGER contract_dirty_device ON devices;
--      DROP FUNCTION contract_mark_dirty();
--      DROP FUNCTION sole_key_holders(uuid);
--      ALTER TABLE devices DROP CONSTRAINT devices_pause_cause_shape;
--      DROP TRIGGER devices_pause_cause ON devices;
--      DROP FUNCTION devices_pause_cause();
--      ALTER TABLE devices DROP COLUMN pause_cause;
--      ALTER TABLE device_notices DROP CONSTRAINT device_notices_kind_check,
--          ADD CONSTRAINT device_notices_kind_check CHECK (kind IN ('sync_paused', 'number_deleted'));
--      DROP INDEX item_events_unsent;
--      DROP INDEX item_events_unmailed;
--      ALTER TABLE item_events DROP CONSTRAINT item_events_event_tenant,
--          DROP CONSTRAINT item_events_delivery_shape, DROP CONSTRAINT item_events_stranded_shape,
--          DROP COLUMN mailed_at, DROP COLUMN reject_code, DROP COLUMN parked_at, DROP COLUMN coalesced_into,
--          DROP COLUMN outcome, DROP COLUMN settled_at, DROP COLUMN reader_user_ids, DROP COLUMN cause, DROP COLUMN person_sub,
--          DROP CONSTRAINT item_events_type_check,
--          ADD CONSTRAINT item_events_type_check CHECK (type IN ('deleted', 'sync_paused', 'recovered', 'purged', 'moved_out'));
--      DROP TABLE contract_workspaces;
--      DROP TABLE contract_accounts;
--      DROP TABLE contract_state;
--      ALTER TABLE device_notices ENABLE ROW LEVEL SECURITY;
--      ALTER TABLE device_notices FORCE ROW LEVEL SECURITY;
--      ALTER TABLE item_events ENABLE ROW LEVEL SECURITY;
--      ALTER TABLE item_events FORCE ROW LEVEL SECURITY;
--      DELETE FROM schema_migrations WHERE version = 51;
--      COMMIT;
--
-- It runs first: 0051 down, then 0050 down (whose guard refuses while 51 is
-- applied), then 0049 down, and so on.

-- wappie-billing keeps running through this migration. Its transactions lock
-- the workspace row and the membership (FOR UPDATE OF t,m) first, then count
-- devices, and write none of tenants, users and workspace_memberships. The
-- triggers and foreign keys below need SHARE ROW EXCLUSIVE on those three:
-- taken first, in billing's order, it waits only for a writer, never for a
-- billing read, and nothing later asks for more on them, so the ALTERs on
-- devices wait for a billing request that has counted devices and never
-- deadlock with it.
LOCK TABLE tenants, users, workspace_memberships IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE contract_state (
    id                   boolean     PRIMARY KEY DEFAULT true CHECK (id),
    mode                 text        NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'observe')),
    mode_changed_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- The first switch to observe, set once: no row written before it is
    -- ever sent.
    events_from          timestamptz,
    -- The last switch from observe to off, while off.
    events_paused_at     timestamptz,
    -- The off periods after events_from.
    events_off           tstzmultirange NOT NULL DEFAULT '{}',
    mail_from            timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- The platform database's identity the stored state belongs to.
    generation           uuid,
    generation_confirmed boolean     NOT NULL DEFAULT false,
    feed_cursor          bigint      NOT NULL DEFAULT 0 CHECK (feed_cursor >= 0),
    published_through    timestamptz,
    round_generation     uuid,
    -- The leader's last feed page committed (a read, as the platform counts
    -- one), and the class of the feed calls' failure since, NULL once a page
    -- commits again: what contract status shows and --check warns on.
    feed_read_at         timestamptz,
    feed_error           text,
    feed_error_at        timestamptz,
    -- Since when, and why (the last failed PUT's class), the round's passes
    -- leave held subs with no document of the stored generation; NULL once
    -- a pass leaves none.
    round_error          text,
    round_error_at       timestamptz,
    -- The last contract ERROR the leader recorded, by class: --check
    -- reports one from the last day (the journal is not the service user's
    -- to read).
    error_at             timestamptz,
    error_class          text,
    updated_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((feed_error IS NULL) = (feed_error_at IS NULL)),
    CHECK ((round_error IS NULL) = (round_error_at IS NULL)),
    CHECK ((error_class IS NULL) = (error_at IS NULL)),
    CHECK (mode = 'off' OR events_from IS NOT NULL),
    CHECK ((events_paused_at IS NULL) = (mode = 'observe') OR events_from IS NULL)
);
INSERT INTO contract_state DEFAULT VALUES;

CREATE TABLE contract_accounts (
    sub                    uuid        PRIMARY KEY,
    -- The last PUT's intent: the sweep's clock.
    subscribed_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    generation             uuid,
    version                bigint      CHECK (version >= 1),
    status                 text        CHECK (status IN ('active', 'disabled', 'closed')),
    -- The highest seen, kept across generations.
    disabled_at            timestamptz,
    sessions_revoked_at    timestamptz,
    credentials_revoked_at timestamptz,
    -- The document as received.
    doc                    jsonb       CHECK (doc IS NULL OR jsonb_typeof(doc) = 'object'),
    applied_at             timestamptz,
    -- The last PUT's or GET's answer for this sub, on the database's
    -- clock.
    fresh_at               timestamptz,
    CHECK ((generation IS NULL) = (version IS NULL)),
    CHECK ((doc IS NULL) = (status IS NULL))
);

CREATE TABLE contract_workspaces (
    -- The platform's id; a local workspace has the same id when Wappie
    -- holds it.
    workspace_id    uuid        PRIMARY KEY,
    kind            text        NOT NULL CHECK (kind IN ('personal', 'team')),
    named_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- Gates the status; 0 again at a new generation.
    wversion        bigint      NOT NULL DEFAULT 0 CHECK (wversion >= 0),
    status          text        CHECK (status IN ('open', 'closed')),
    -- The last snapshot_seq sent, in milliseconds, and the last accepted.
    snapshot_seq    bigint      NOT NULL DEFAULT 0,
    snapshot_ok_at  timestamptz,
    snapshot_due_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    snapshot_tries  int         NOT NULL DEFAULT 0,
    -- The event queue's backoff.
    events_due_at   timestamptz,
    events_tries    int         NOT NULL DEFAULT 0,
    -- A not_found on a snapshot or an event: retried for 24 hours, then
    -- parked.
    not_found_since timestamptz,
    parked_at       timestamptz
);

ALTER TABLE item_events DROP CONSTRAINT item_events_type_check;
ALTER TABLE item_events
    ADD CONSTRAINT item_events_type_check
        CHECK (type IN ('deleted', 'sync_paused', 'recovered', 'purged', 'moved_out', 'stranded')),
    -- stranded: the sub it lost (NULL for a person with none), and why.
    ADD COLUMN person_sub      uuid,
    ADD COLUMN cause           text CHECK (cause IN ('disabled', 'revoked')),
    -- The readers' local accounts, beside reader_subs. Never sent.
    ADD COLUMN reader_user_ids uuid[] NOT NULL DEFAULT '{}',
    ADD COLUMN settled_at      timestamptz,
    ADD COLUMN outcome         text CHECK (outcome IN ('accepted', 'duplicate', 'coalesced', 'not_sent')),
    -- The sync_paused event this one was folded into.
    ADD COLUMN coalesced_into  uuid,
    ADD COLUMN parked_at       timestamptz,
    ADD COLUMN reject_code     text CHECK (reject_code IN ('invalid_request', 'not_found', 'local_invalid', 'conflict', 'expired')),
    -- Self-hosted: its recipients were queued in item_mails.
    ADD COLUMN mailed_at       timestamptz,
    ADD CONSTRAINT item_events_stranded_shape CHECK (type = 'stranded' OR (person_sub IS NULL AND cause IS NULL)),
    -- Every term is true or false, never NULL, so no shape slips through as
    -- unknown.
    ADD CONSTRAINT item_events_delivery_shape CHECK (
            (settled_at IS NULL) = (outcome IS NULL)
        AND (outcome IS DISTINCT FROM 'coalesced' OR coalesced_into IS NOT NULL)
        AND (coalesced_into IS NULL OR outcome IS NULL OR outcome = 'coalesced')
        AND NOT (settled_at IS NOT NULL AND parked_at IS NOT NULL)
        AND (parked_at IS NULL) = (reject_code IS NULL)),
    -- What item_mails names an event by, so a mail and its event share a
    -- workspace.
    ADD CONSTRAINT item_events_event_tenant UNIQUE (event_id, tenant_id);
CREATE INDEX item_events_unsent   ON item_events (tenant_id, seq) WHERE settled_at IS NULL AND parked_at IS NULL;
CREATE INDEX item_events_unmailed ON item_events (tenant_id, seq) WHERE mailed_at IS NULL;

ALTER TABLE device_notices DROP CONSTRAINT device_notices_kind_check,
    ADD CONSTRAINT device_notices_kind_check
        CHECK (kind IN ('sync_paused', 'number_deleted', 'number_stranded', 'number_moved_out'));

ALTER TABLE devices ADD COLUMN pause_cause text CHECK (pause_cause IN ('person', 'move', 'deletion'));
CREATE FUNCTION devices_pause_cause() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT NEW.paused THEN
        NEW.pause_cause := NULL;
    ELSIF NEW.pause_cause IS NULL THEN
        NEW.pause_cause := CASE WHEN NEW.deleted_at IS NOT NULL THEN 'deletion' ELSE 'person' END;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER devices_pause_cause BEFORE INSERT OR UPDATE OF paused, pause_cause, deleted_at ON devices
    FOR EACH ROW EXECUTE FUNCTION devices_pause_cause();
-- Every workspace's numbers, as 0036 and 0050 write them.
ALTER TABLE devices DISABLE ROW LEVEL SECURITY;
UPDATE devices SET pause_cause = CASE WHEN deleted_at IS NOT NULL THEN 'deletion' ELSE 'person' END WHERE paused;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;
ALTER TABLE devices ADD CONSTRAINT devices_pause_cause_shape CHECK ((pause_cause IS NOT NULL) = paused);

CREATE FUNCTION sole_key_holders(tenant uuid) RETURNS TABLE (device_id uuid, user_id uuid)
LANGUAGE sql STABLE AS $$
    SELECT DISTINCT doomed.device_id, doomed.user_id
      FROM device_key_grants doomed
      JOIN device_archive_keys k ON k.device_id = doomed.device_id AND k.epoch = doomed.epoch AND k.retired_at IS NULL
      JOIN workspace_memberships m ON m.tenant_id = doomed.tenant_id AND m.user_id = doomed.user_id AND m.status = 'active'
      JOIN users u ON u.id = m.user_id AND u.status = 'active'
     WHERE doomed.tenant_id = $1
       -- A connection's service account is never the one checked: its
       -- grants are copies of someone else's.
       AND m.expires_at IS NULL
       AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = doomed.user_id)
       AND NOT EXISTS (
         SELECT 1 FROM device_key_grants backup
           JOIN workspace_memberships bm ON bm.tenant_id = backup.tenant_id AND bm.user_id = backup.user_id
                AND bm.status = 'active' AND bm.expires_at IS NULL
           JOIN users bu ON bu.id = bm.user_id AND bu.status = 'active'
           JOIN device_permissions bp ON bp.tenant_id = backup.tenant_id AND bp.device_id = backup.device_id
                AND bp.user_id = backup.user_id AND bp.can_read
          WHERE backup.tenant_id = doomed.tenant_id AND backup.device_id = doomed.device_id
            AND backup.epoch = doomed.epoch AND backup.user_id <> doomed.user_id
            AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = backup.user_id))
$$;

CREATE FUNCTION contract_mark_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM pg_notify('wappie_contract_dirty', OLD.tenant_id::text);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        PERFORM pg_notify('wappie_contract_dirty', NEW.tenant_id::text);
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER contract_dirty_device AFTER INSERT OR DELETE ON devices
    FOR EACH ROW EXECUTE FUNCTION contract_mark_dirty();
-- devices changes with every connection: only what a snapshot shows wakes
-- anyone, and a status only when it enters, leaves or moves within the
-- logged-out and banned states. A number enters the snapshot with its
-- first identity (a LID may come alone) or its first connection, so those
-- wake it once; a later connection time never does.
CREATE TRIGGER contract_dirty_device_update AFTER UPDATE ON devices FOR EACH ROW
    WHEN (OLD.label IS DISTINCT FROM NEW.label OR OLD.push_name IS DISTINCT FROM NEW.push_name
       OR OLD.lid IS DISTINCT FROM NEW.lid OR OLD.pn IS DISTINCT FROM NEW.pn
       OR (OLD.last_connected_at IS NULL) IS DISTINCT FROM (NEW.last_connected_at IS NULL)
       OR OLD.paused IS DISTINCT FROM NEW.paused
       OR OLD.pause_cause IS DISTINCT FROM NEW.pause_cause OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at
       OR OLD.purge_after IS DISTINCT FROM NEW.purge_after OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.current_epoch IS DISTINCT FROM NEW.current_epoch
       OR (OLD.status IS DISTINCT FROM NEW.status
           AND (OLD.status IN ('logged_out', 'banned') OR NEW.status IN ('logged_out', 'banned'))))
    EXECUTE FUNCTION contract_mark_dirty();
CREATE TRIGGER contract_dirty_permission AFTER INSERT OR UPDATE OR DELETE ON device_permissions
    FOR EACH ROW EXECUTE FUNCTION contract_mark_dirty();
CREATE TRIGGER contract_dirty_grant AFTER INSERT OR UPDATE OR DELETE ON device_key_grants
    FOR EACH ROW EXECUTE FUNCTION contract_mark_dirty();
CREATE TRIGGER contract_dirty_member AFTER INSERT OR UPDATE OR DELETE ON workspace_memberships
    FOR EACH ROW EXECUTE FUNCTION contract_mark_dirty();
CREATE FUNCTION contract_mark_all_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('wappie_contract_dirty', 'all');
    RETURN NULL;
END $$;
CREATE TRIGGER contract_dirty_user AFTER UPDATE OF status ON users FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION contract_mark_all_dirty();
-- A link gives a person their sub in every workspace's snapshot.
CREATE TRIGGER contract_dirty_identity AFTER INSERT ON platform_identities
    FOR EACH ROW EXECUTE FUNCTION contract_mark_all_dirty();
-- A workspace's own status and storage stop; never its byte counters.
CREATE FUNCTION contract_mark_tenant_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('wappie_contract_dirty', NEW.id::text);
    RETURN NULL;
END $$;
CREATE TRIGGER contract_dirty_tenant AFTER UPDATE OF status, storage_paused_at, storage_limit_bytes ON tenants FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.storage_paused_at IS DISTINCT FROM NEW.storage_paused_at
       OR OLD.storage_limit_bytes IS DISTINCT FROM NEW.storage_limit_bytes)
    EXECUTE FUNCTION contract_mark_tenant_dirty();

ALTER TABLE security_events DROP CONSTRAINT security_events_kind_check,
    ADD CONSTRAINT security_events_kind_check
        CHECK (kind IN ('platform_account_key_changed', 'platform_linked', 'platform_home_taken'));

CREATE TABLE item_mails (
    event_id  uuid        NOT NULL,
    tenant_id uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id   uuid        NOT NULL,
    role      text        NOT NULL CHECK (role IN ('owner', 'reader')),
    queued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- Past a day's cap, the next day's.
    due_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    tries     int         NOT NULL DEFAULT 0,
    sent_at   timestamptz,
    failed_at timestamptz,
    PRIMARY KEY (event_id, user_id),
    -- The event is this workspace's (a foreign key's check ignores the
    -- policies), and the recipient a member of it: a waiting mail goes when
    -- its person's membership ends (README 9.1).
    FOREIGN KEY (event_id, tenant_id) REFERENCES item_events(event_id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES workspace_memberships(tenant_id, user_id) ON DELETE CASCADE
);
ALTER TABLE item_mails ENABLE ROW LEVEL SECURITY;
ALTER TABLE item_mails FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON item_mails
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
