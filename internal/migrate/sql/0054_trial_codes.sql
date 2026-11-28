-- Trial codes, the events item.linked and item.identity_updated, placed_at
-- and the link check on Wappie's side (E0 slice 19; the platform's spec,
-- sections 15.5, 15.10 to 15.12). Nothing here calls the platform. The
-- rows of the two events and placed_at are written whatever the
-- entitlements mode says; a code is made only at send time, and only while
-- K_app is usable and codes are on.
--
--   devices.placed_at   when the number took its place in its workspace:
--                       the latest of its link, its recovery and its move
--                       in (spec 15.5); a relink, a resume and an unpause
--                       never move it. NULL on a row no snapshot lists yet
--                       (a pairing that never completed). Filled here from
--                       created_at, the latest recovery and the latest move
--                       into the number's workspace.
--   item_events.type    linked and identity_updated: never ledgered (written
--                       as if they were, as a pause is), settled not_sent
--                       when the number makes no code at send time.
--   contract_trial_key  K_app's envelope (THCSEAL, under the context
--                       {wappie, prod, trial-codes, platform}): one row,
--                       inserted once by whatserverd contract trial-key
--                       init, restored with the database, never updated or
--                       deleted (a trigger refuses both; replacing an
--                       exposed key needs the table owner, docs/contract.md).
--                       A down-step keeps it.
--   contract_trial_key_state  one row: the codes switch (on, suspended: the
--                       spec's 15.10 exposure step 1), and what wappie-api
--                       last recorded of its open (when, or the error's
--                       class, and the sha256 of the envelope it opened).
--                       contract status reads it and never opens the key.
--   contract_link_checks  the last 24 hours of link checks: when, the
--                       workspace, the act (link, move), whether a signed
--                       answer came, and the first reason an enforcing
--                       release would refuse (or NULL). Ids and enums only.
--   contract_trial_key_mark  a key inserted, or the codes switch changed:
--                       'trial_key' on the mode channel
--                       (wappie_contract_mode), so wappie-api opens the key,
--                       or stops making codes, at once.
--
-- None of the new tables carries row-level security: they are read across
-- workspaces, as contract_state is, and hold no content and no personal data.
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 54, so rolling back below it needs this first). Run only with
-- `wappie-api` stopped, after `whatserverd contract entitlements off` and
-- `whatserverd contract trial-key suspend` (unless no key exists), after
-- checking this file against `migration54_sha256` in the release's
-- RELEASE.json, as the table owner. It refuses while a version above 54 is
-- applied, while entitlements are not off, while codes are on and a key
-- exists, and while any item.linked or item.identity_updated row of a named
-- workspace is still owed; a refusal changes nothing. It deletes the rows
-- of those two types, restores 0051's type check, drops the state, the
-- link checks and placed_at, and keeps contract_trial_key: a later re-up
-- reuses the same K_app, and trials do not restart. That re-up starts with
-- codes suspended (the switch the down-step required): resume them with
-- `whatserverd contract trial-key resume` once any exposure is handled.
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      DO $$
--      BEGIN
--        IF EXISTS (SELECT 1 FROM schema_migrations WHERE version > 54) THEN
--          RAISE EXCEPTION 'a migration after 0054 is applied; run its down-step first';
--        END IF;
--        IF (SELECT mode FROM contract_ent_state) <> 'off' THEN
--          RAISE EXCEPTION 'entitlements are on: run whatserverd contract entitlements off first';
--        END IF;
--        IF EXISTS (SELECT 1 FROM contract_trial_key) AND (SELECT codes FROM contract_trial_key_state) = 'on' THEN
--          RAISE EXCEPTION 'trial codes are on: run whatserverd contract trial-key suspend first';
--        END IF;
--      END $$;
--      LOCK TABLE tenants, users, workspace_memberships IN ACCESS EXCLUSIVE MODE;
--      ALTER TABLE item_events DISABLE ROW LEVEL SECURITY;
--      ALTER TABLE devices DISABLE ROW LEVEL SECURITY;
--      DO $$
--      BEGIN
--        IF EXISTS (SELECT 1 FROM item_events e WHERE e.type IN ('linked', 'identity_updated')
--                     AND e.settled_at IS NULL AND e.parked_at IS NULL
--                     AND EXISTS (SELECT 1 FROM contract_workspaces w WHERE w.workspace_id = e.tenant_id)) THEN
--          RAISE EXCEPTION 'item.linked or item.identity_updated events are still owed: let the leader send them first';
--        END IF;
--        RAISE NOTICE 'dropping % linked and identity_updated rows, % placed numbers, % link checks; the trial key is kept',
--          (SELECT count(*) FROM item_events WHERE type IN ('linked', 'identity_updated')),
--          (SELECT count(*) FROM devices WHERE placed_at IS NOT NULL),
--          (SELECT count(*) FROM contract_link_checks);
--      END $$;
--      DELETE FROM item_events WHERE type IN ('linked', 'identity_updated');
--      ALTER TABLE item_events DROP CONSTRAINT item_events_type_check,
--        ADD CONSTRAINT item_events_type_check
--          CHECK (type IN ('deleted', 'sync_paused', 'recovered', 'purged', 'moved_out', 'stranded'));
--      ALTER TABLE item_events ENABLE ROW LEVEL SECURITY;
--      ALTER TABLE item_events FORCE ROW LEVEL SECURITY;
--      DROP TABLE contract_link_checks;
--      DROP TRIGGER contract_trial_key_state_mark ON contract_trial_key_state;
--      DROP TABLE contract_trial_key_state;
--      ALTER TABLE devices DROP COLUMN placed_at;
--      ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
--      ALTER TABLE devices FORCE ROW LEVEL SECURITY;
--      DELETE FROM schema_migrations WHERE version = 54;
--      COMMIT;
--
-- It runs first: 0054 down, then 0053 down (whose guard refuses while 54 is
-- applied), and so on. A down-step after a kit's step 12 is a class b window
-- of its own, never run on live data alone.

-- wappie-billing keeps running through this migration, as through 0051 to
-- 0053: the three tables billing locks, in a mode its reads never conflict
-- with, in billing's order.
LOCK TABLE tenants, users, workspace_memberships IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE devices ADD COLUMN placed_at timestamptz;

-- The backfill (Q58): the latest of the number's creation, its latest
-- recovery and its latest move into its current workspace, for every
-- number a snapshot lists (contract_snapshot.go's predicate); a pairing that
-- never completed stays NULL. devices_touch is off, so updated_at does not
-- move. Every table it reads is opened for it, and closed again after.
ALTER TABLE devices DISABLE ROW LEVEL SECURITY;
ALTER TABLE item_events DISABLE ROW LEVEL SECURITY;
ALTER TABLE device_transfers DISABLE ROW LEVEL SECURITY;
ALTER TABLE devices DISABLE TRIGGER devices_touch;
UPDATE devices d SET placed_at = greatest(d.created_at,
       (SELECT max(e.occurred_at) FROM item_events e
         WHERE e.type = 'recovered' AND e.item_id = d.id AND e.tenant_id = d.tenant_id),
       (SELECT max(x.completed_at) FROM device_transfers x
         WHERE x.device_id = d.id AND x.target_workspace_id = d.tenant_id))
 WHERE d.lid IS NOT NULL OR d.pn IS NOT NULL OR d.last_connected_at IS NOT NULL;
ALTER TABLE devices ENABLE TRIGGER devices_touch;
ALTER TABLE device_transfers ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_transfers FORCE ROW LEVEL SECURITY;
ALTER TABLE item_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE item_events FORCE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;

-- item.linked and item.identity_updated (spec 15.12). A row settled with no
-- code takes the existing not_sent.
ALTER TABLE item_events DROP CONSTRAINT item_events_type_check,
    ADD CONSTRAINT item_events_type_check
        CHECK (type IN ('deleted', 'sync_paused', 'recovered', 'purged', 'moved_out', 'stranded', 'linked', 'identity_updated'));

-- K_app's envelope. IF NOT EXISTS and OR REPLACE: a down-step keeps the
-- table, its function and its triggers, and a re-up reuses the same key.
CREATE TABLE IF NOT EXISTS contract_trial_key (
    id         boolean     PRIMARY KEY DEFAULT true CHECK (id),
    envelope   bytea       NOT NULL CHECK (octet_length(envelope) > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE OR REPLACE FUNCTION contract_trial_key_never_rotated() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'the trial key is never rotated (spec 15.10)';
END $$;
CREATE OR REPLACE TRIGGER contract_trial_key_never_rotated BEFORE UPDATE OR DELETE ON contract_trial_key
    FOR EACH ROW EXECUTE FUNCTION contract_trial_key_never_rotated();
CREATE OR REPLACE FUNCTION contract_trial_key_mark() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('wappie_contract_mode', 'trial_key');
    RETURN NULL;
END $$;
CREATE OR REPLACE TRIGGER contract_trial_key_mark AFTER INSERT ON contract_trial_key
    FOR EACH ROW EXECUTE FUNCTION contract_trial_key_mark();

CREATE TABLE contract_trial_key_state (
    id              boolean     PRIMARY KEY DEFAULT true CHECK (id),
    -- on: codes are made while the key opens. suspended: none is made
    -- anywhere (events, link checks, the catch-up).
    codes           text        NOT NULL DEFAULT 'on' CHECK (codes IN ('on', 'suspended')),
    codes_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- What wappie-api recorded of its last open: when and which envelope,
    -- or the error's class.
    opened_at       timestamptz,
    envelope_sha256 bytea       CHECK (envelope_sha256 IS NULL OR octet_length(envelope_sha256) = 32),
    open_error      text,
    open_error_at   timestamptz,
    CHECK ((open_error IS NULL) = (open_error_at IS NULL)),
    CHECK ((opened_at IS NULL) = (envelope_sha256 IS NULL))
);
-- A re-up after a down-step finds the key it kept: codes start suspended,
-- as the down-step required them, so an exposed key not yet on the retired
-- list never comes back into use by itself (contract trial-key resume turns
-- them on again).
INSERT INTO contract_trial_key_state (codes)
    SELECT CASE WHEN EXISTS (SELECT 1 FROM contract_trial_key) THEN 'suspended' ELSE 'on' END;
CREATE TRIGGER contract_trial_key_state_mark AFTER UPDATE OF codes ON contract_trial_key_state FOR EACH ROW
    WHEN (NEW.codes IS DISTINCT FROM OLD.codes) EXECUTE FUNCTION contract_trial_key_mark();

CREATE TABLE contract_link_checks (
    at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    workspace_id uuid        NOT NULL,
    act          text        NOT NULL CHECK (act IN ('link', 'move')),
    answered     boolean     NOT NULL,
    -- The first reason an enforcing release would refuse, NULL for none.
    would_refuse text        CHECK (would_refuse IN ('stale', 'no_document', 'not_found', 'new_links_off',
                                                     'no_place', 'allowance', 'used_up'))
);
CREATE INDEX contract_link_checks_at ON contract_link_checks (at);
