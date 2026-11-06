-- The platform contract's token part on Wappie's side (the platform's design
-- of 2026-10-26, section 3; decision 0053; step 7's plan, section 2): the
-- token feed's state, the records Wappie applied, what it keeps of them
-- after their end, its own stops, and the queues its acknowledgement and
-- usage reports drain. Nothing here calls the platform, and nothing changes
-- how Wappie behaves until an operator turns tokens on
-- (contract_token_state.mode).
--
--   contract_token_state   one row, apart from contract_state, so a token
--                          commit never waits behind the account side
--                          (DB25): the mode, the token feed's cursor (under
--                          contract_state.generation, the one generation),
--                          the last published_through a page with more
--                          false vouched for, caught_up_at (token auth
--                          accepts only while it is set), the last page's
--                          read and the failure since, what a reset kept
--                          (reset_trusted_through, the pass's generation,
--                          whether a more-false page committed after the
--                          round in it, and when it finished), the
--                          acknowledgement's and the usage report's times,
--                          and label_cutover_at (this migration's time: an
--                          unsent row written before it keeps its label
--                          only when the label rule gives the same).
--   contract_token_selectors
--                          selector -> token id, workspace and hash, written
--                          once from a token's first good record and never
--                          updated, deleted only past until (its own
--                          guard). No row-level security: the selector
--                          finds the workspace before any is known, as
--                          api_keys and user_logins do; it holds no name,
--                          creator or item.
--   contract_tokens        one row per token Wappie holds, in the token's
--                          workspace (forced row-level security): the
--                          record's members, its immutable ones never
--                          changed (contract_tokens_never_widen), the
--                          earliest expires_at ever applied (-infinity for
--                          a zero one), a revocation never cleared, the
--                          record's generation, version and seq, the last
--                          good record as received, when a signed GET last
--                          equalled or raised its version (fetched_at, on
--                          Wappie's clock), the reset's pass (listed_gen;
--                          unlisted_at, terminal), the hidden identity's
--                          user id (no foreign key: a users delete must not
--                          write this row), access_version (bumped by the
--                          trigger on every narrowing of the row), a
--                          changed reading key, and retention's times.
--   contract_token_pins    the reading key pinned per token, from a good
--                          record only; never updated, deleted only past
--                          until (its own guard).
--   contract_token_perms   one row per (token, number, perm) a record
--                          listed: the grant instance (granted_by,
--                          granted_at), the generation and version that
--                          carried it, and its state (pending: unjudged and
--                          never effective; waiting; applied; refused with
--                          its code). Only for an item id Go parsed as a
--                          canonical UUID of a live number of the token's
--                          workspace.
--   contract_token_removed the narrowest state a reset keeps: the grant
--                          instances never to apply again, by cause, with
--                          no giver. The item is the record's text, so an
--                          unknown one can be kept. No foreign key:
--                          retention deletes them with the token's content
--                          30 days after its end, at its selector's until,
--                          or at its next pass after its workspace's row
--                          is gone; a reset's pass with the content of a
--                          token it unlists.
--   contract_token_sticky  per token id, checked after the hash: its
--                          revocation, its earliest expiry and how it ended
--                          (revoked, expired, unlisted), kept to until (the
--                          stored created_at + 365 days; for a token Wappie
--                          never held, a valid record's created_at + 365
--                          days, but at most Wappie's clock + 365 days,
--                          and no row at all once it has passed), so a
--                          record that comes back later never revives the
--                          token. A bad record's revocation is never dated
--                          by a time of its own: Wappie's clock + 365 days
--                          (clock_until), until the leader's lookup by id
--                          answers; then the token's own created_at + 365
--                          days, or, on a signed not_found in the
--                          generation the record came in, the row goes at
--                          once. Its own guard keeps every member from
--                          widening: until only lowers, as a later valid
--                          record's narrows a bad one's.
--   contract_token_stops   the operator's stops (and Wappie's own
--                          apply_failed), keyed by selector, so a stop may
--                          come before the record. The note stays local.
--                          A stop of a selector Wappie holds goes with it,
--                          past its until; any other at stopped_at + 365
--                          days, or earlier at the earliest created_at +
--                          365 days of a valid record of its selector
--                          (never a bad record's): one seen before the stop
--                          (contract_token_dates), one seen since
--                          (record_until), or the platform's answer to the
--                          leader's lookup by selector, asked once when
--                          neither dates it. A signed not_found leaves it
--                          undated: the operator's own record, outside
--                          decision 0056. An operator's goes only once its
--                          stop and its lift are past. Due before then, it
--                          keeps only its selector and times, as the stop
--                          record: its note is cleared and its stopped_by
--                          set to wappie; one timed past the pass that
--                          deletes its selector takes that selector's until
--                          as its record_until, and one timed past its
--                          selector's date takes that date.
--   contract_token_dates   selector -> the earliest created_at + 365 days
--                          of a valid record of it that Wappie did not keep
--                          (another workspace's, or a token held only in
--                          the sticky set), at most Wappie's clock + 365
--                          days, written by the applier and the lookups
--                          only for a selector no selectors row holds, and
--                          deleted past until (its own guard).
--   contract_token_stops_let_go
--                          one row: through, the latest time of an
--                          operator's stop (its stop or its lift) that
--                          retention deleted, never lowered and never past
--                          Wappie's clock. Retention writes it with its
--                          deletions under the row's lock, and a stop or a
--                          lift takes the row's share lock and is made
--                          after it. So a snapshot that holds it holds
--                          every stop record line at or before it, or
--                          retention let that stop go: tokens suspend
--                          -replay leaves those lines.
--   contract_token_refusals_out, contract_token_held_out
--                          the acknowledgement's queues: ids, versions,
--                          codes and the held state; never read on a
--                          request path. Retention deletes an entry 30
--                          days after it was sent; any, sent or not, with
--                          its token's selector or sticky row at its until;
--                          an unsent held entry of a generation no longer
--                          Wappie's (a reset does too); an unsent held
--                          entry of a token Wappie keeps nothing of, 30
--                          days after it was queued; a refusal of a token
--                          Wappie holds no selector of, sent or not, 30
--                          days after the earlier of its queuing and the
--                          end its sticky row keeps; and, at the pass that
--                          forgets a token (30 days after its end, or a
--                          reset's pass that unlists it, or its
--                          workspace's row gone) and every pass after,
--                          sent or not, its refusals and its held entries'
--                          removed items, and a held entry that then says
--                          nothing.
--   contract_token_used, contract_token_refusals
--                          the usage counters: one row per token and UTC
--                          day it was accepted, and per (token, day,
--                          number, perm, code) refused, to which every
--                          process's flush adds its delta and whose count
--                          the leader reports. Written only for a token
--                          whose selector Wappie keeps (its secret
--                          matched); deleted once reported, at the start of
--                          the second UTC day after their day; reported or
--                          not, 30 days after their day, with the token's
--                          selector, and a refusal on a number with the
--                          token's forget.
--   key_retirements        the operator's record of tokens retire-keys:
--                          counts and key prefixes.
--   users.token_identity   the hidden identity a live token's grants are
--                          sealed to (its public_key is the token's pinned
--                          reading key): a service-shaped row with no
--                          password, recovery or KDF salt (so sign-in
--                          answers its address as a decoy), never a member
--                          of any workspace (create_initial_membership
--                          gives it none, and initial_device_permissions
--                          no permission row), so no listing, protection
--                          or backup ever counts it. Its grants notify
--                          wappie_contract_tokens with its token's id. It
--                          goes at its token's end; a workspace's row
--                          deleted (no foreign key since 0021), at
--                          retention's next pass.
--   devices.ordinal        the number's place in its workspace, 1 to 9999,
--                          the lowest free one at its insert or move-out
--                          (devices_ordinal), kept across a deletion and a
--                          recovery, freed by the purge; NULL past 9999.
--   api_keys.origin, api_keys.revoke_reason
--                          how a key was issued (rest, cli, mcp_setup,
--                          legacy_mcp), backfilled once by api_key_class,
--                          and platform_tokens for a key the retirement
--                          revoked.
--
-- Every change to a token, its perms, its sticky row or its stops (but a
-- stop's record_until and lookup columns alone, which only retention and
-- the lookups read), to the token switches of a workspace
-- (tenants.mcp_text, mcp_media), to the modes (contract_token_state's,
-- contract_state's) or to an account document (the belt) notifies
-- wappie_contract_tokens with the token's id or 'all', so every process
-- re-checks its open sockets at once. No trigger writes contract_tokens
-- from another table (DB25): a NOTIFY takes no row lock.
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 52, so rolling back below it needs this first). Run only with
-- `wappie-api` and `wappie-billing` stopped, after `whatserverd contract
-- tokens off` (or `contract mode off`, which turns tokens off too), after
-- checking this file against `migration52_sha256` in the release's
-- RELEASE.json, as the table owner. It refuses while tokens are on, and while
-- schema_migrations holds a version above 52; a refusal changes nothing. It
-- loses the token records (the platform republishes them from 0 after a
-- re-upgrade, and a reset never widens), the token identities and their
-- grants (counted; users and device_key_grants are forced row-level
-- security, so a plain delete as the owner with no workspace would delete
-- nothing: their policies are lifted around it), the local stops (counted:
-- re-apply them from the stop record after a re-upgrade; with no mark of
-- what retention let go, a line of a stop it let go before the down-step
-- comes back too, as the stop of a selector Wappie does not hold) and the
-- retirement's record (counted); the keys the retirement revoked stay
-- revoked, as 0050's did. Rolling back below 0052 leaves the stop record
-- (WS_TOKEN_STOP_RECORD) with nothing that trims it: an older binary knows
-- nothing of it. Trim it by hand, dropping each line whose at is over 365
-- days old, or delete it once no re-upgrade will replay it
-- (docs/deployment.md, "Rolling back below 0052"). The same goes for the
-- old file when WS_TOKEN_STOP_RECORD is changed or blanked.
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      DO $$
--      BEGIN
--        IF EXISTS (SELECT 1 FROM schema_migrations WHERE version > 52) THEN
--          RAISE EXCEPTION 'a migration after 0052 is applied; run its down-step first';
--        END IF;
--        IF (SELECT mode FROM contract_token_state) <> 'off' THEN
--          RAISE EXCEPTION 'tokens are on: run whatserverd contract tokens off first';
--        END IF;
--      END $$;
--      LOCK TABLE tenants, users, workspace_memberships, devices, device_key_grants, api_keys,
--        contract_state, contract_accounts IN ACCESS EXCLUSIVE MODE;
--      ALTER TABLE users DISABLE ROW LEVEL SECURITY;
--      ALTER TABLE device_key_grants DISABLE ROW LEVEL SECURITY;
--      ALTER TABLE contract_tokens DISABLE ROW LEVEL SECURITY;
--      DO $$
--      BEGIN
--        RAISE NOTICE 'dropping % tokens, % token identities with % grants, % local stops (re-apply them after a re-upgrade), % retirement rows; % keys revoked by the retirement stay revoked',
--          (SELECT count(*) FROM contract_tokens),
--          (SELECT count(*) FROM users WHERE token_identity),
--          (SELECT count(*) FROM device_key_grants g JOIN users u ON u.id = g.user_id WHERE u.token_identity),
--          (SELECT count(*) FROM contract_token_stops WHERE lifted_at IS NULL),
--          (SELECT count(*) FROM key_retirements),
--          (SELECT count(*) FROM api_keys WHERE revoke_reason = 'platform_tokens');
--      END $$;
--      DELETE FROM users WHERE token_identity;
--      DO $$
--      BEGIN
--        IF EXISTS (SELECT 1 FROM users WHERE token_identity) THEN
--          RAISE EXCEPTION 'token identities remain';
--        END IF;
--      END $$;
--      ALTER TABLE users ENABLE ROW LEVEL SECURITY;
--      ALTER TABLE users FORCE ROW LEVEL SECURITY;
--      ALTER TABLE device_key_grants ENABLE ROW LEVEL SECURITY;
--      ALTER TABLE device_key_grants FORCE ROW LEVEL SECURITY;
--      DROP TRIGGER devices_ordinal_insert ON devices;
--      DROP TRIGGER devices_ordinal_move ON devices;
--      DROP FUNCTION devices_ordinal();
--      DROP TRIGGER contract_dirty_device_update ON devices;
--      CREATE TRIGGER contract_dirty_device_update AFTER UPDATE ON devices FOR EACH ROW
--          WHEN (OLD.label IS DISTINCT FROM NEW.label OR OLD.push_name IS DISTINCT FROM NEW.push_name
--             OR OLD.lid IS DISTINCT FROM NEW.lid OR OLD.pn IS DISTINCT FROM NEW.pn
--             OR (OLD.last_connected_at IS NULL) IS DISTINCT FROM (NEW.last_connected_at IS NULL)
--             OR OLD.paused IS DISTINCT FROM NEW.paused
--             OR OLD.pause_cause IS DISTINCT FROM NEW.pause_cause OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at
--             OR OLD.purge_after IS DISTINCT FROM NEW.purge_after OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
--             OR OLD.current_epoch IS DISTINCT FROM NEW.current_epoch
--             OR (OLD.status IS DISTINCT FROM NEW.status
--                 AND (OLD.status IN ('logged_out', 'banned') OR NEW.status IN ('logged_out', 'banned'))))
--          EXECUTE FUNCTION contract_mark_dirty();
--      DROP TRIGGER contract_token_identity_notify ON device_key_grants;
--      DROP TRIGGER tenants_token_switch_notify ON tenants;
--      DROP TRIGGER contract_state_token_notify ON contract_state;
--      DROP TRIGGER contract_accounts_token_notify ON contract_accounts;
--      CREATE OR REPLACE FUNCTION create_initial_membership() RETURNS trigger AS $$
--      DECLARE personal uuid; previous_context text;
--      BEGIN
--       previous_context := current_setting('app.tenant_id',true);
--       IF EXISTS(SELECT 1 FROM tenants WHERE id=NEW.tenant_id) THEN
--        INSERT INTO workspace_memberships(tenant_id,user_id,role) VALUES(NEW.tenant_id,NEW.id,NEW.role);
--       END IF;
--       IF NEW.role <> 'service' THEN
--        personal := CASE WHEN EXISTS(SELECT 1 FROM tenants WHERE id=NEW.tenant_id) THEN uuidv7() ELSE NEW.tenant_id END;
--        INSERT INTO tenants(id,name,kind,personal_owner_id)
--        VALUES(personal,left(coalesce(nullif(NEW.name,''),split_part(NEW.email,'@',1)),80),'personal',NEW.id);
--        PERFORM set_config('app.tenant_id',personal::text,true);
--        INSERT INTO workspace_memberships(tenant_id,user_id,role) VALUES(personal,NEW.id,'owner');
--        PERFORM set_config('app.tenant_id',coalesce(previous_context,''),true);
--       END IF;
--       RETURN NEW;
--      END $$ LANGUAGE plpgsql;
--      CREATE OR REPLACE FUNCTION initial_device_permissions() RETURNS trigger AS $$
--      BEGIN
--          INSERT INTO device_permissions(tenant_id,device_id,user_id,can_read,can_send)
--          VALUES(NEW.tenant_id,NEW.device_id,NEW.user_id,true,true) ON CONFLICT DO NOTHING;
--          RETURN NEW;
--      END $$ LANGUAGE plpgsql;
--      DROP FUNCTION api_key_class(api_keys);
--      DROP TABLE key_retirements, contract_token_refusals, contract_token_used, contract_token_held_out,
--        contract_token_refusals_out, contract_token_stops_let_go, contract_token_dates, contract_token_stops,
--        contract_token_sticky, contract_token_removed, contract_token_perms, contract_token_pins, contract_tokens,
--        contract_token_selectors, contract_token_state;
--      DROP FUNCTION contract_tokens_never_widen(), contract_token_notify(), contract_tokens_notify_all(),
--        contract_token_identity_notify(), contract_token_pins_guard(), contract_token_selectors_guard(),
--        contract_token_sticky_guard(), contract_token_dates_guard();
--      ALTER TABLE users DROP CONSTRAINT users_token_identity_shape, DROP COLUMN token_identity;
--      ALTER TABLE devices DROP COLUMN ordinal;
--      ALTER TABLE api_keys DROP COLUMN origin, DROP COLUMN revoke_reason;
--      DELETE FROM schema_migrations WHERE version = 52;
--      COMMIT;
--
-- The tables' own triggers, policies and constraints go with them. It runs
-- first: 0052 down, then 0051 down (whose guard refuses while 52 is
-- applied), and so on.

-- wappie-billing keeps running through this migration, as through 0051: the
-- triggers below need SHARE ROW EXCLUSIVE on tenants, taken first in
-- billing's order, so the ALTERs on devices wait for a billing request that
-- has counted devices and never deadlock with it.
LOCK TABLE tenants, users, workspace_memberships IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE contract_token_state (
    id                    boolean     PRIMARY KEY DEFAULT true CHECK (id),
    mode                  text        NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'on')),
    mode_changed_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- The token feed's after, under contract_state.generation.
    feed_cursor           bigint      NOT NULL DEFAULT 0 CHECK (feed_cursor >= 0),
    -- Trusted only from a page with more false, at most ContractClockSkew
    -- ahead.
    published_through     timestamptz,
    -- The last commit of a more-false page; token auth accepts only while
    -- it is set. tokens on and a stale start clear it.
    caught_up_at          timestamptz,
    -- The last page committed, on Wappie's clock, and the token feed's
    -- failure class since.
    read_at               timestamptz,
    error                 text,
    error_at              timestamptz,
    -- What a reset kept: the old generation's last trusted
    -- published_through, the new generation's pass, when a more-false page
    -- committed after the round ran in it, and when the pass finished.
    reset_trusted_through timestamptz,
    pass_generation       uuid,
    pass_ready_at         timestamptz,
    pass_done_at          timestamptz,
    -- The acknowledgement: the last through accepted, when, and the
    -- failure since; the hashes of the waiting and suspended sets last
    -- accepted, so each goes whole and only when it changed.
    ack_through           bigint      NOT NULL DEFAULT 0 CHECK (ack_through >= 0),
    ack_sent_at           timestamptz,
    ack_error             text,
    ack_error_at          timestamptz,
    waiting_sent_hash     bytea,
    suspended_sent_hash   bytea,
    usage_sent_at         timestamptz,
    usage_error           text,
    usage_error_at        timestamptz,
    -- The last page whose commit took over a second from its receipt, and
    -- how long, for contract status --check (the design's 1 s bound).
    slow_commit_at        timestamptz,
    slow_commit_ms        integer     CHECK (slow_commit_ms >= 0),
    label_cutover_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((error IS NULL) = (error_at IS NULL)),
    CHECK ((ack_error IS NULL) = (ack_error_at IS NULL)),
    CHECK ((usage_error IS NULL) = (usage_error_at IS NULL)),
    CHECK ((slow_commit_at IS NULL) = (slow_commit_ms IS NULL))
);
INSERT INTO contract_token_state DEFAULT VALUES;

CREATE TABLE contract_token_selectors (
    selector  text        PRIMARY KEY CHECK (selector ~ '^[0-9a-f]{16}$'),
    token_id  uuid        NOT NULL UNIQUE,
    tenant_id uuid        NOT NULL,
    hash      bytea       NOT NULL CHECK (length(hash) = 32),
    until     timestamptz NOT NULL
);
-- A selector names one token for good: never updated, and deleted only past
-- until, by retention.
CREATE FUNCTION contract_token_selectors_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.until <= clock_timestamp() THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% keeps its rows until they end', TG_TABLE_NAME USING ERRCODE = 'P0001';
END $$;
CREATE TRIGGER contract_token_selectors_guard BEFORE UPDATE OR DELETE ON contract_token_selectors
    FOR EACH ROW EXECUTE FUNCTION contract_token_selectors_guard();

CREATE TABLE contract_tokens (
    id                  uuid        PRIMARY KEY REFERENCES contract_token_selectors(token_id),
    tenant_id           uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                text        NOT NULL,
    created_by          uuid        NOT NULL,
    created_at          timestamptz NOT NULL,
    terms               jsonb,
    -- The earliest ever applied; -infinity for a zero one.
    expires_at          timestamptz NOT NULL,
    revoked_at          timestamptz,
    revoked_reason      text        CHECK (revoked_reason IN ('revoked', 'creator_left', 'creator_disabled', 'creator_closed',
                                                              'creator_recovered', 'operator', 'app_removed', 'app_held')),
    -- Of the record applied; versions only rise within a generation, and a
    -- reset clears both.
    generation          uuid,
    version             bigint      CHECK (version >= 1),
    seq                 bigint,
    record              jsonb       CHECK (record IS NULL OR jsonb_typeof(record) = 'object'),
    applied_at          timestamptz,
    fetched_at          timestamptz,
    listed_gen          uuid,
    unlisted_at         timestamptz,
    identity_user_id    uuid        UNIQUE,
    identity_dropped_at timestamptz,
    access_version      bigint      NOT NULL DEFAULT 1,
    key_changed_at      timestamptz,
    ended_at            timestamptz,
    forgotten_at        timestamptz,
    UNIQUE (id, tenant_id),
    CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL)),
    CHECK ((generation IS NULL) = (version IS NULL))
);
ALTER TABLE contract_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE contract_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contract_tokens
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
-- The backstop of the applier's own comparison: a token's row only ever
-- narrows. Any narrowing bumps its access_version, so an open request's
-- actor and a socket's version stop matching.
CREATE FUNCTION contract_tokens_never_widen() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
                                       OR NEW.revoked_reason IS DISTINCT FROM OLD.revoked_reason) THEN
        RAISE EXCEPTION 'a token''s revocation is never cleared or changed' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.expires_at > OLD.expires_at THEN
        RAISE EXCEPTION 'a token''s expires_at never rises' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.tenant_id <> OLD.tenant_id OR NEW.created_by <> OLD.created_by OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'a token''s workspace, creator and creation time never change' USING ERRCODE = 'P0001';
    END IF;
    IF (OLD.unlisted_at IS NOT NULL AND NEW.unlisted_at IS DISTINCT FROM OLD.unlisted_at)
       OR (OLD.key_changed_at IS NOT NULL AND NEW.key_changed_at IS DISTINCT FROM OLD.key_changed_at)
       OR (OLD.identity_dropped_at IS NOT NULL AND NEW.identity_dropped_at IS DISTINCT FROM OLD.identity_dropped_at) THEN
        RAISE EXCEPTION 'a token''s unlisting, changed key and dropped identity are never cleared' USING ERRCODE = 'P0001';
    END IF;
    IF (OLD.identity_user_id IS NOT NULL AND NEW.identity_user_id IS DISTINCT FROM OLD.identity_user_id)
       OR (OLD.identity_user_id IS NULL AND NEW.identity_user_id IS NOT NULL AND OLD.identity_dropped_at IS NOT NULL) THEN
        RAISE EXCEPTION 'a token''s identity is set once, and never again once dropped' USING ERRCODE = 'P0001';
    END IF;
    IF (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL) OR NEW.expires_at < OLD.expires_at
       OR (OLD.unlisted_at IS NULL AND NEW.unlisted_at IS NOT NULL)
       OR (OLD.key_changed_at IS NULL AND NEW.key_changed_at IS NOT NULL)
       OR (OLD.identity_dropped_at IS NULL AND NEW.identity_dropped_at IS NOT NULL) THEN
        NEW.access_version := OLD.access_version + 1;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER contract_tokens_never_widen BEFORE UPDATE ON contract_tokens
    FOR EACH ROW EXECUTE FUNCTION contract_tokens_never_widen();

CREATE TABLE contract_token_pins (
    token_id      uuid        PRIMARY KEY,
    -- No foreign key: retention deletes the pin past until, whatever became
    -- of the workspace.
    tenant_id     uuid        NOT NULL,
    key           bytea       NOT NULL CHECK (length(key) = 32),
    fingerprint   text        NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{32}$'),
    registered_at timestamptz NOT NULL,
    pinned_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- The token's created_at + 365 days.
    until         timestamptz NOT NULL
);
ALTER TABLE contract_token_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE contract_token_pins FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contract_token_pins
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
-- Not platform_insert_only(), which refuses every DELETE (0048): retention
-- could never run.
CREATE FUNCTION contract_token_pins_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.until <= clock_timestamp() THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% keeps its rows until they end', TG_TABLE_NAME USING ERRCODE = 'P0001';
END $$;
CREATE TRIGGER contract_token_pins_guard BEFORE UPDATE OR DELETE ON contract_token_pins
    FOR EACH ROW EXECUTE FUNCTION contract_token_pins_guard();

CREATE TABLE contract_token_perms (
    token_id      uuid        NOT NULL,
    tenant_id     uuid        NOT NULL,
    device_id     uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    perm          text        NOT NULL CHECK (perm IN ('read', 'send', 'manage')),
    granted_by    uuid        NOT NULL,
    granted_at    timestamptz NOT NULL,
    generation    uuid        NOT NULL,
    state         text        NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'waiting', 'applied', 'refused')),
    code          text        CHECK (code IN ('giver_not_reader', 'local_role', 'item_unknown', 'reading_key_changed', 'invalid_record')),
    -- The record version that carried this grant.
    version       bigint      NOT NULL CHECK (version >= 1),
    judged_at     timestamptz,
    held_at_reset boolean     NOT NULL DEFAULT false,
    PRIMARY KEY (token_id, device_id, perm),
    FOREIGN KEY (token_id, tenant_id) REFERENCES contract_tokens(id, tenant_id) ON DELETE CASCADE,
    CHECK ((state = 'refused') = (code IS NOT NULL))
);
ALTER TABLE contract_token_perms ENABLE ROW LEVEL SECURITY;
ALTER TABLE contract_token_perms FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contract_token_perms
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- An instance is its (token, item, perm, granted_at): its giver is never
-- read, so it is not kept.
CREATE TABLE contract_token_removed (
    token_id   uuid        NOT NULL,
    tenant_id  uuid        NOT NULL,
    item       text        NOT NULL,
    perm       text        NOT NULL,
    granted_at timestamptz NOT NULL,
    cause      text        NOT NULL CHECK (cause IN ('dropped', 'item_deleted', 'item_moved', 'item_unknown', 'refused', 'reset')),
    at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (token_id, item, perm, granted_at)
);
ALTER TABLE contract_token_removed ENABLE ROW LEVEL SECURITY;
ALTER TABLE contract_token_removed FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contract_token_removed
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE TABLE contract_token_sticky (
    token_id            uuid        PRIMARY KEY,
    revoked_at          timestamptz,
    earliest_expires_at timestamptz,
    ended               text        CHECK (ended IN ('revoked', 'expired', 'unlisted')),
    until               timestamptz NOT NULL,
    -- Set while until is Wappie's clock + 365 days, from a bad record of a
    -- token Wappie holds no selector of: the leader's lookup by id asks the
    -- platform for the token's own date. Any other write clears it.
    -- clock_gen is the generation that record came in.
    clock_until         boolean     NOT NULL DEFAULT false,
    clock_gen           uuid,
    -- While clock_until: when to ask again (infinity: never, after a
    -- not_found of another generation), and how many signed answers in a
    -- row Wappie could not use.
    lookup_after        timestamptz,
    lookup_bad          integer     NOT NULL DEFAULT 0 CHECK (lookup_bad >= 0),
    CHECK (NOT clock_until OR clock_gen IS NOT NULL)
);
CREATE INDEX contract_token_sticky_lookups ON contract_token_sticky (lookup_after) WHERE clock_until;
-- What a sticky row says only narrows: a revocation and an ending are never
-- cleared or changed, the earliest expiry and until never rise, and the row
-- goes only past until.
CREATE FUNCTION contract_token_sticky_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.until <= clock_timestamp() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION '% keeps its rows until they end', TG_TABLE_NAME USING ERRCODE = 'P0001';
    END IF;
    IF (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
       OR (OLD.ended IS NOT NULL AND NEW.ended IS DISTINCT FROM OLD.ended)
       OR (OLD.earliest_expires_at IS NOT NULL AND (NEW.earliest_expires_at IS NULL OR NEW.earliest_expires_at > OLD.earliest_expires_at))
       OR NEW.until > OLD.until THEN
        RAISE EXCEPTION 'a sticky token only narrows' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER contract_token_sticky_guard BEFORE UPDATE OR DELETE ON contract_token_sticky
    FOR EACH ROW EXECUTE FUNCTION contract_token_sticky_guard();

CREATE TABLE contract_token_stops (
    selector   text        NOT NULL CHECK (selector ~ '^[0-9a-f]{16}$'),
    cause      text        NOT NULL CHECK (cause IN ('operator', 'apply_failed')),
    stopped_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- The OS user, or wappie for apply_failed and for an operator's stop
    -- retention kept past its date (its note cleared too).
    stopped_by text        NOT NULL,
    note       text        NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    lifted_at  timestamptz,
    -- The earliest created_at + 365 days of a valid record of the selector
    -- (never a bad one's) that came while the stop stood, from the feed or
    -- the lookup by selector: only ever lowered, kept by a re-stop.
    -- Retention reads it only while no selectors row names the selector: a
    -- stop of a selector Wappie holds goes with that row; an operator's
    -- timed past the pass that deletes the row takes the row's until here,
    -- and one timed past its selector's date (contract_token_dates) that
    -- date.
    record_until timestamptz,
    -- The leader's lookup by selector of a stop that nothing dates, while
    -- no selectors row names it: when to ask again (infinity once a signed
    -- not_found settled it), and how many signed answers in a row Wappie
    -- could not use. Only the lookups write them, and they wake no socket.
    lookup_after timestamptz,
    lookup_bad   integer     NOT NULL DEFAULT 0 CHECK (lookup_bad >= 0),
    PRIMARY KEY (selector, cause)
);
-- A selector Wappie saw in a valid record and does not hold (another
-- workspace's token, or one it keeps only in the sticky set), with the
-- earliest created_at + 365 days of those records, at most Wappie's clock +
-- 365 days: a stop of that selector goes then at the latest, whenever it
-- was made. No row-level security, as the selectors and the stops: it holds
-- no workspace, name, creator or item. Token auth never reads it.
CREATE TABLE contract_token_dates (
    selector text        PRIMARY KEY CHECK (selector ~ '^[0-9a-f]{16}$'),
    until    timestamptz NOT NULL
);
-- A date only lowers, and goes only past until.
CREATE FUNCTION contract_token_dates_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.until <= clock_timestamp() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION '% keeps its rows until they end', TG_TABLE_NAME USING ERRCODE = 'P0001';
    END IF;
    IF NEW.selector <> OLD.selector OR NEW.until > OLD.until THEN
        RAISE EXCEPTION 'a selector''s date only lowers' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER contract_token_dates_guard BEFORE UPDATE OR DELETE ON contract_token_dates
    FOR EACH ROW EXECUTE FUNCTION contract_token_dates_guard();
CREATE TABLE contract_token_stops_let_go (
    id      boolean     PRIMARY KEY DEFAULT true CHECK (id),
    through timestamptz
);
INSERT INTO contract_token_stops_let_go DEFAULT VALUES;

CREATE TABLE contract_token_refusals_out (
    token_id  uuid        NOT NULL,
    version   bigint      NOT NULL CHECK (version >= 1),
    item      text        NOT NULL,
    perm      text        NOT NULL,
    code      text        NOT NULL,
    queued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    sent_at   timestamptz,
    PRIMARY KEY (token_id, version, item, perm)
);
CREATE TABLE contract_token_held_out (
    token_id    uuid        NOT NULL,
    generation  uuid        NOT NULL,
    revoked     boolean     NOT NULL DEFAULT false,
    expires_at  timestamptz,
    -- [{item, perm}], each once.
    removed     jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(removed) = 'array'),
    reading_key text        CHECK (reading_key ~ '^[0-9a-f]{32}$'),
    queued_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    sent_at     timestamptz,
    PRIMARY KEY (token_id, generation)
);

CREATE TABLE contract_token_used (
    token_id    uuid NOT NULL,
    day         date NOT NULL,
    reported_at timestamptz,
    PRIMARY KEY (token_id, day)
);
CREATE TABLE contract_token_refusals (
    token_id       uuid   NOT NULL,
    day            date   NOT NULL,
    device_id      uuid,
    perm           text,
    code           text   NOT NULL,
    count          bigint NOT NULL CHECK (count >= 1),
    reported_count bigint NOT NULL DEFAULT 0,
    UNIQUE NULLS NOT DISTINCT (token_id, day, device_id, perm, code),
    CHECK ((device_id IS NULL) = (perm IS NULL))
);

CREATE TABLE key_retirements (
    applied_at       timestamptz PRIMARY KEY DEFAULT clock_timestamp(),
    revoked          int         NOT NULL CHECK (revoked >= 0),
    services_removed int         NOT NULL CHECK (services_removed >= 0),
    services_kept    int         NOT NULL CHECK (services_kept >= 0),
    report           jsonb       NOT NULL CHECK (jsonb_typeof(report) = 'object'),
    by               text        NOT NULL
);

-- The notices every process re-checks its sockets on: a token's id, or all.
CREATE FUNCTION contract_token_notify() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    r jsonb;
    id text;
BEGIN
    IF TG_OP = 'DELETE' THEN r := to_jsonb(OLD); ELSE r := to_jsonb(NEW); END IF;
    id := coalesce(r->>'token_id', CASE WHEN TG_TABLE_NAME = 'contract_tokens' THEN r->>'id' END);
    IF id IS NULL AND r ? 'selector' THEN
        SELECT token_id::text INTO id FROM contract_token_selectors WHERE selector = r->>'selector';
    END IF;
    PERFORM pg_notify('wappie_contract_tokens', coalesce(id, 'all'));
    RETURN NULL;
END $$;
CREATE FUNCTION contract_tokens_notify_all() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('wappie_contract_tokens', 'all');
    RETURN NULL;
END $$;
CREATE TRIGGER contract_tokens_notify AFTER INSERT OR UPDATE OR DELETE ON contract_tokens
    FOR EACH ROW EXECUTE FUNCTION contract_token_notify();
CREATE TRIGGER contract_token_perms_notify AFTER INSERT OR UPDATE OR DELETE ON contract_token_perms
    FOR EACH ROW EXECUTE FUNCTION contract_token_notify();
CREATE TRIGGER contract_token_sticky_notify AFTER INSERT OR UPDATE ON contract_token_sticky
    FOR EACH ROW EXECUTE FUNCTION contract_token_notify();
CREATE TRIGGER contract_token_stops_notify AFTER INSERT OR DELETE ON contract_token_stops
    FOR EACH ROW EXECUTE FUNCTION contract_token_notify();
-- record_until and the lookup columns are retention's and the lookups':
-- a change of them and nothing else wakes no socket.
CREATE TRIGGER contract_token_stops_notify_update AFTER UPDATE ON contract_token_stops FOR EACH ROW
    WHEN ((OLD.selector, OLD.cause, OLD.stopped_at, OLD.stopped_by, OLD.note, OLD.lifted_at)
          IS DISTINCT FROM (NEW.selector, NEW.cause, NEW.stopped_at, NEW.stopped_by, NEW.note, NEW.lifted_at))
    EXECUTE FUNCTION contract_token_notify();
-- caught_up_at moves at every page with more false; token auth reads only
-- whether it is set.
CREATE TRIGGER contract_token_state_notify AFTER UPDATE OF mode, caught_up_at ON contract_token_state FOR EACH ROW
    WHEN (OLD.mode IS DISTINCT FROM NEW.mode OR (OLD.caught_up_at IS NULL) IS DISTINCT FROM (NEW.caught_up_at IS NULL))
    EXECUTE FUNCTION contract_tokens_notify_all();
CREATE TRIGGER contract_state_token_notify AFTER UPDATE OF mode ON contract_state FOR EACH ROW
    WHEN (OLD.mode IS DISTINCT FROM NEW.mode) EXECUTE FUNCTION contract_tokens_notify_all();
-- The belt: a creator's document dropping the workspace, or a later disable
-- or recovery, stops their tokens.
CREATE TRIGGER contract_accounts_token_notify AFTER UPDATE OF doc ON contract_accounts FOR EACH ROW
    WHEN (OLD.doc IS DISTINCT FROM NEW.doc) EXECUTE FUNCTION contract_tokens_notify_all();
-- The workspace's text and attachments switches, read by token auth in SQL.
CREATE TRIGGER tenants_token_switch_notify AFTER UPDATE OF mcp_text, mcp_media ON tenants FOR EACH ROW
    WHEN (OLD.mcp_text IS DISTINCT FROM NEW.mcp_text OR OLD.mcp_media IS DISTINCT FROM NEW.mcp_media)
    EXECUTE FUNCTION contract_tokens_notify_all();

-- A snapshot's items[].tokens follows within the debounce (0051's
-- contract_mark_dirty, a NOTIFY only).
CREATE TRIGGER contract_dirty_token_perm AFTER INSERT OR UPDATE OR DELETE ON contract_token_perms
    FOR EACH ROW EXECUTE FUNCTION contract_mark_dirty();
CREATE TRIGGER contract_dirty_token AFTER UPDATE ON contract_tokens FOR EACH ROW
    WHEN (OLD.revoked_at IS DISTINCT FROM NEW.revoked_at OR OLD.expires_at IS DISTINCT FROM NEW.expires_at
       OR OLD.unlisted_at IS DISTINCT FROM NEW.unlisted_at OR OLD.identity_user_id IS DISTINCT FROM NEW.identity_user_id
       OR OLD.identity_dropped_at IS DISTINCT FROM NEW.identity_dropped_at)
    EXECUTE FUNCTION contract_mark_dirty();
CREATE TRIGGER contract_dirty_token_delete AFTER DELETE ON contract_tokens
    FOR EACH ROW EXECUTE FUNCTION contract_mark_dirty();

-- A number's ordinal: per workspace, 1 to 9999, deleted numbers included, so
-- a deleted number's is never handed out again until its purge.
ALTER TABLE devices ADD COLUMN ordinal smallint CHECK (ordinal BETWEEN 1 AND 9999),
    ADD CONSTRAINT devices_ordinal_unique UNIQUE (tenant_id, ordinal);
-- Every workspace's numbers, deleted ones included, as 0051 wrote the pause
-- causes; updated_at stays as it was.
ALTER TABLE devices DISABLE ROW LEVEL SECURITY;
ALTER TABLE devices DISABLE TRIGGER devices_touch;
UPDATE devices d SET ordinal = n.o
  FROM (SELECT id, CASE WHEN rn <= 9999 THEN rn END AS o
          FROM (SELECT id, row_number() OVER (PARTITION BY tenant_id ORDER BY created_at, id) AS rn FROM devices) x) n
 WHERE d.id = n.id;
ALTER TABLE devices ENABLE TRIGGER devices_touch;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;
-- The lowest free ordinal of NEW.tenant_id, at an insert and a move-out,
-- under the workspace's row FOR UPDATE, taken first. A move already holds it
-- (TransferPersonal locks both workspaces before its UPDATE), and an insert
-- takes it anyway (0024's enforce_device_capacity, whose BEFORE trigger
-- fires after this one by name, then the foreign key's KEY SHARE after
-- both); any other lock taken first here, such as an advisory lock, would
-- be held by an insert while it waits on a move's workspace row, and asked
-- for by the move under that row: a deadlock.
-- Under row-level security the one query would miss deleted numbers
-- (device_quarantine) and, in a session of another workspace than
-- NEW.tenant_id, that workspace's (tenant_isolation; a move-out's own scope,
-- device_move, shows both of its workspaces), so it sets both settings for
-- that query and restores them; SECURITY DEFINER would not help, as FORCE
-- binds the owner too.
CREATE FUNCTION devices_ordinal() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    prior_tenant     text := current_setting('app.tenant_id', true);
    prior_quarantine text := current_setting('app.device_quarantine', true);
    free             integer;
BEGIN
    PERFORM 1 FROM tenants WHERE id = NEW.tenant_id FOR UPDATE;
    PERFORM set_config('app.tenant_id', NEW.tenant_id::text, true);
    PERFORM set_config('app.device_quarantine', 'on', true);
    SELECT s INTO free FROM generate_series(1, 9999) s
     WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.tenant_id = NEW.tenant_id AND d.ordinal = s AND d.id <> NEW.id)
     ORDER BY s LIMIT 1;
    PERFORM set_config('app.tenant_id', coalesce(prior_tenant, ''), true);
    PERFORM set_config('app.device_quarantine', coalesce(prior_quarantine, ''), true);
    NEW.ordinal := free;
    RETURN NEW;
END $$;
CREATE TRIGGER devices_ordinal_insert BEFORE INSERT ON devices
    FOR EACH ROW EXECUTE FUNCTION devices_ordinal();
CREATE TRIGGER devices_ordinal_move BEFORE UPDATE OF tenant_id ON devices FOR EACH ROW
    WHEN (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id) EXECUTE FUNCTION devices_ordinal();
-- 0051's, waking on the ordinal and no longer on the push name, which no
-- snapshot shows (10.27).
DROP TRIGGER contract_dirty_device_update ON devices;
CREATE TRIGGER contract_dirty_device_update AFTER UPDATE ON devices FOR EACH ROW
    WHEN (OLD.label IS DISTINCT FROM NEW.label OR OLD.ordinal IS DISTINCT FROM NEW.ordinal
       OR OLD.lid IS DISTINCT FROM NEW.lid OR OLD.pn IS DISTINCT FROM NEW.pn
       OR (OLD.last_connected_at IS NULL) IS DISTINCT FROM (NEW.last_connected_at IS NULL)
       OR OLD.paused IS DISTINCT FROM NEW.paused
       OR OLD.pause_cause IS DISTINCT FROM NEW.pause_cause OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at
       OR OLD.purge_after IS DISTINCT FROM NEW.purge_after OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.current_epoch IS DISTINCT FROM NEW.current_epoch
       OR (OLD.status IS DISTINCT FROM NEW.status
           AND (OLD.status IN ('logged_out', 'banned') OR NEW.status IN ('logged_out', 'banned'))))
    EXECUTE FUNCTION contract_mark_dirty();

ALTER TABLE api_keys ADD COLUMN origin text CHECK (origin IN ('rest', 'cli', 'mcp_setup', 'legacy_mcp')),
    ADD COLUMN revoke_reason text CHECK (revoke_reason IN ('platform_tokens'));
-- A key's class (the plan's 7.1), by shape first and then by creator, whose
-- foreign key is ON DELETE SET NULL: an MCP connection's key, any status;
-- a setup in flight (30 minutes, a minute's slack); an old local MCP token,
-- whatever created_by holds; a key with no creator (the CLI's); and every
-- other. The backfill below, the retirement's dry run and its apply use it.
-- users is read under the caller's policies: the apply runs per workspace.
CREATE FUNCTION api_key_class(k api_keys) RETURNS text LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN EXISTS (SELECT 1 FROM mcp_connections c WHERE c.api_key_id = k.id) THEN 'mcp'
        WHEN k.name LIKE 'MCP · %' AND k.scope = 'read' AND k.devices_restricted AND k.expires_at IS NOT NULL
             AND k.expires_at <= k.created_at + interval '31 minutes' THEN 'mcp_setup'
        WHEN k.name LIKE 'MCP · %' AND k.scope = 'read' AND k.devices_restricted AND k.expires_at IS NULL
             AND (k.acts_as IS NULL OR EXISTS (SELECT 1 FROM users u JOIN workspace_memberships m ON m.user_id = u.id AND m.tenant_id = k.tenant_id
                                                WHERE u.id = k.acts_as AND u.role = 'service' AND m.expires_at IS NULL
                                                  AND (u.name LIKE 'mcp-%' OR u.email LIKE 'mcp-%'))) THEN 'legacy_mcp'
        WHEN k.created_by IS NULL THEN 'cli'
        ELSE 'rest'
    END
$$;
-- Once, over every workspace's keys, each under its workspace, so the class
-- reads its service accounts through the policies (lifting them would need
-- ACCESS EXCLUSIVE on users and workspace_memberships after devices', which
-- a billing request between the two would deadlock with). A connection's
-- key was issued in the setup's shape.
DO $$
DECLARE
    ws uuid;
BEGIN
    FOR ws IN SELECT DISTINCT tenant_id FROM api_keys ORDER BY tenant_id LOOP
        PERFORM set_config('app.tenant_id', ws::text, true);
        UPDATE api_keys k SET origin = CASE api_key_class(k) WHEN 'mcp' THEN 'mcp_setup' WHEN 'mcp_setup' THEN 'mcp_setup'
            WHEN 'legacy_mcp' THEN 'legacy_mcp' WHEN 'cli' THEN 'cli' ELSE 'rest' END
         WHERE k.tenant_id = ws;
    END LOOP;
    PERFORM set_config('app.tenant_id', '', true);
END $$;

-- The token identity (the plan's 5.1). After the devices' ALTERs, as
-- wappie-billing's order asks: a billing request that has counted devices
-- holds them, and reads users after.
ALTER TABLE users ADD COLUMN token_identity boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT users_token_identity_shape CHECK (NOT token_identity OR (role = 'service' AND auth_source = 'local'
        AND auth_hash IS NULL AND recovery_hash IS NULL AND kdf_salt IS NULL AND kdf_params IS NULL AND status = 'active'));
-- 0031's, with no membership and no personal workspace for a token identity:
-- it is never a member (3.6).
CREATE OR REPLACE FUNCTION create_initial_membership() RETURNS trigger AS $$
DECLARE personal uuid; previous_context text;
BEGIN
 IF NEW.token_identity THEN
  RETURN NEW;
 END IF;
 previous_context := current_setting('app.tenant_id',true);
 IF EXISTS(SELECT 1 FROM tenants WHERE id=NEW.tenant_id) THEN
  INSERT INTO workspace_memberships(tenant_id,user_id,role) VALUES(NEW.tenant_id,NEW.id,NEW.role);
 END IF;
 IF NEW.role <> 'service' THEN
  personal := CASE WHEN EXISTS(SELECT 1 FROM tenants WHERE id=NEW.tenant_id) THEN uuidv7() ELSE NEW.tenant_id END;
  INSERT INTO tenants(id,name,kind,personal_owner_id)
  VALUES(personal,left(coalesce(nullif(NEW.name,''),split_part(NEW.email,'@',1)),80),'personal',NEW.id);
  PERFORM set_config('app.tenant_id',personal::text,true);
  INSERT INTO workspace_memberships(tenant_id,user_id,role) VALUES(personal,NEW.id,'owner');
  PERFORM set_config('app.tenant_id',coalesce(previous_context,''),true);
 END IF;
 RETURN NEW;
END $$ LANGUAGE plpgsql;
-- 0023's, for members only: a grant to a token identity (or to anyone with no
-- membership) brings no permission row, which would fail on 0023's foreign
-- key or hand out can_send. A token's Read is its record's, never a row here.
CREATE OR REPLACE FUNCTION initial_device_permissions() RETURNS trigger AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM workspace_memberships m WHERE m.tenant_id=NEW.tenant_id AND m.user_id=NEW.user_id) THEN
        INSERT INTO device_permissions(tenant_id,device_id,user_id,can_read,can_send)
        VALUES(NEW.tenant_id,NEW.device_id,NEW.user_id,true,true) ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
-- A token identity's grant given or taken: its token's id, found by the
-- identity it keeps after a drop, so a cascade from the identity's delete
-- notifies too. Nothing is written: a NOTIFY takes no row lock (DB25).
CREATE FUNCTION contract_token_identity_notify() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    r   device_key_grants;
    tok uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN r := OLD; ELSE r := NEW; END IF;
    SELECT id INTO tok FROM contract_tokens WHERE identity_user_id = r.user_id;
    IF tok IS NOT NULL THEN
        PERFORM pg_notify('wappie_contract_tokens', tok::text);
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER contract_token_identity_notify AFTER INSERT OR DELETE ON device_key_grants
    FOR EACH ROW EXECUTE FUNCTION contract_token_identity_notify();
