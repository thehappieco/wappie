-- The platform contract at enforce on Wappie's side, step E1 (decision
-- DS54; the enforce design of 2026-11-18): what applying the stored account
-- documents records. Nothing here applies anything, and nothing changes how
-- Wappie behaves while the contract is off or at observe: the apply refuses
-- unless contract_state.mode is 'enforce', which 0051's CHECK does not hold
-- until E2 widens it, in this same file, before it is ever released.
--
--   contract_accounts   how far each sub's document was applied:
--                       applied_generation and applied_version (the
--                       document applied last), applied_disabled_at,
--                       applied_sessions_revoked_at and
--                       applied_credentials_revoked_at (the times applied),
--                       apply_held with apply_held_since (a part left for
--                       later: strands_unconfirmed, personal_mismatch,
--                       closing_unconfirmed, no_tenant), and apply_last_at.
--                       The existing applied_at is when the document was
--                       stored, and stays so.
--   contract_workspaces applied_wversion (NULL: never applied) and
--                       applied_status: closed only where the apply
--                       suspended the workspace, so a reopen lifts only a
--                       suspension the contract made. A restart nulls
--                       applied_wversion, as it resets wversion, and keeps
--                       applied_status.
--   users.disabled_by   operator or contract, set exactly on a disabled
--                       account (users_disabled_by_shape) by the trigger
--                       users_disabled_by: a disable is the contract's only
--                       inside the apply (app.contract_apply = 'on', a
--                       transaction-local setting), and the operator's
--                       otherwise, so a document never lifts an operator's
--                       disable. Every account disabled before this
--                       migration is the operator's.
--   contract_closings   one row per closed account the apply saw: sub, its
--                       local account and personal workspace, and when the
--                       closing was seen, confirmed by a fresh signed GET,
--                       its personal numbers due for purge, the account
--                       forgotten, and the platform's unsubscribe sent. No
--                       foreign key: the row outlives the account, and is
--                       kept 13 months (sub and times only).
--   api_keys.revoke_reason
--                       adds contract (a suspension's or a recovery's stop)
--                       and orphan_service (a key acting as a service user
--                       with no membership in its workspace).
--   mcp_connections.revoke_reason
--                       adds credentials_revoked.
--   device_notices.raised_by_kind
--                       adds app: an owner's number_stranded notice of a
--                       membership the platform ended, with nobody behind it.
--   device_transfers.actor_id, mcp_outbound.decided_by
--                       ON DELETE SET NULL (actor_id loses NOT NULL), so a
--                       closed account can be forgotten.
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 55, so rolling back below it needs this first). Run only with
-- `wappie-api` and `wappie-billing` stopped, after checking this file against
-- `migration55_sha256` in the release's RELEASE.json, as the table owner. It
-- refuses while the contract is at enforce, and while schema_migrations holds
-- a version above 55; a refusal changes nothing. It loses the apply's
-- markers and the closing records (counted); the keys and connections ended
-- with this migration's reasons stay ended, without a reason; a transfer
-- record whose actor was forgotten, and an owner's notice the app raised, are
-- deleted (counted); a disable the contract made stays, as an operator's
-- would; a workspace the contract suspended stays suspended (counted).
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      DO $$
--      BEGIN
--        IF EXISTS (SELECT 1 FROM schema_migrations WHERE version > 55) THEN
--          RAISE EXCEPTION 'a migration after 0055 is applied; run its down-step first';
--        END IF;
--        IF (SELECT mode FROM contract_state) = 'enforce' THEN
--          RAISE EXCEPTION 'the contract is at enforce: run whatserverd contract mode observe first';
--        END IF;
--      END $$;
--      LOCK TABLE tenants, users, workspace_memberships, api_keys, mcp_connections, device_transfers, mcp_outbound,
--        device_notices, contract_accounts, contract_workspaces IN ACCESS EXCLUSIVE MODE;
--      ALTER TABLE device_transfers DISABLE ROW LEVEL SECURITY;
--      ALTER TABLE device_notices DISABLE ROW LEVEL SECURITY;
--      ALTER TABLE users DISABLE ROW LEVEL SECURITY;
--      DO $$
--      BEGIN
--        RAISE NOTICE 'dropping % closing records, % applied accounts, % transfer records with no actor, % notices the app raised; % keys and % connections stay ended without a reason; % accounts the contract disabled and % workspaces it suspended stay so',
--          (SELECT count(*) FROM contract_closings),
--          (SELECT count(*) FROM contract_accounts WHERE applied_version IS NOT NULL),
--          (SELECT count(*) FROM device_transfers WHERE actor_id IS NULL),
--          (SELECT count(*) FROM device_notices WHERE raised_by_kind = 'app'),
--          (SELECT count(*) FROM api_keys WHERE revoke_reason IN ('contract', 'orphan_service')),
--          (SELECT count(*) FROM mcp_connections WHERE revoke_reason = 'credentials_revoked'),
--          (SELECT count(*) FROM users WHERE disabled_by = 'contract'),
--          (SELECT count(*) FROM contract_workspaces WHERE applied_status = 'closed');
--      END $$;
--      DELETE FROM device_transfers WHERE actor_id IS NULL;
--      DELETE FROM device_notices WHERE raised_by_kind = 'app';
--      UPDATE api_keys SET revoke_reason = NULL WHERE revoke_reason IN ('contract', 'orphan_service');
--      UPDATE mcp_connections SET revoke_reason = NULL WHERE revoke_reason = 'credentials_revoked';
--      DROP TRIGGER users_disabled_by ON users;
--      DROP FUNCTION users_disabled_by();
--      ALTER TABLE users DROP CONSTRAINT users_disabled_by_shape, DROP COLUMN disabled_by;
--      ALTER TABLE users ENABLE ROW LEVEL SECURITY;
--      ALTER TABLE users FORCE ROW LEVEL SECURITY;
--      ALTER TABLE device_notices DROP CONSTRAINT device_notices_raised_by_kind_check,
--          ADD CONSTRAINT device_notices_raised_by_kind_check CHECK (raised_by_kind IN ('person', 'key'));
--      ALTER TABLE device_notices ENABLE ROW LEVEL SECURITY;
--      ALTER TABLE device_notices FORCE ROW LEVEL SECURITY;
--      ALTER TABLE mcp_outbound DROP CONSTRAINT mcp_outbound_decided_by_fkey,
--          ADD CONSTRAINT mcp_outbound_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES users(id);
--      ALTER TABLE device_transfers DROP CONSTRAINT device_transfers_actor_id_fkey,
--          ADD CONSTRAINT device_transfers_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES users(id),
--          ALTER COLUMN actor_id SET NOT NULL;
--      ALTER TABLE device_transfers ENABLE ROW LEVEL SECURITY;
--      ALTER TABLE device_transfers FORCE ROW LEVEL SECURITY;
--      ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_revoke_reason_check,
--          ADD CONSTRAINT mcp_connections_revoke_reason_check CHECK (revoke_reason IN (
--          'console', 'reader', 'reuse_detected', 'relay_failed', 'pending_expired', 'expired', 'service_removed',
--          'service_disabled', 'member_removed', 'member_disabled', 'access_lost', 'ai_key_deleted', 'replaced', 'idle'));
--      ALTER TABLE api_keys DROP CONSTRAINT api_keys_revoke_reason_check,
--          ADD CONSTRAINT api_keys_revoke_reason_check CHECK (revoke_reason IN ('platform_tokens'));
--      DROP TABLE contract_closings;
--      ALTER TABLE contract_workspaces DROP COLUMN applied_status, DROP COLUMN applied_wversion;
--      ALTER TABLE contract_accounts DROP CONSTRAINT contract_accounts_apply_held_shape,
--          DROP COLUMN apply_last_at, DROP COLUMN apply_held_since, DROP COLUMN apply_held,
--          DROP COLUMN applied_credentials_revoked_at, DROP COLUMN applied_sessions_revoked_at,
--          DROP COLUMN applied_disabled_at, DROP COLUMN applied_version, DROP COLUMN applied_generation;
--      DELETE FROM schema_migrations WHERE version = 55;
--      COMMIT;
--
-- It runs first: 0055 down, then 0053 down (whose guard refuses while 55 is
-- applied), and so on. Migration 0054 is R4's; 0056 is R7's.

-- wappie-billing keeps running through this migration, as through 0051 and
-- 0053: tenants, users and workspace_memberships in SHARE ROW EXCLUSIVE
-- first, in billing's order, so the ALTERs wait for a billing request that
-- has counted devices and never deadlock with it.
LOCK TABLE tenants, users, workspace_memberships IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE contract_accounts
    ADD COLUMN applied_generation             uuid,
    ADD COLUMN applied_version                bigint,
    ADD COLUMN applied_disabled_at            timestamptz,
    ADD COLUMN applied_sessions_revoked_at    timestamptz,
    ADD COLUMN applied_credentials_revoked_at timestamptz,
    ADD COLUMN apply_held                     text CHECK (apply_held IN
        ('strands_unconfirmed', 'personal_mismatch', 'closing_unconfirmed', 'no_tenant')),
    ADD COLUMN apply_held_since               timestamptz,
    ADD COLUMN apply_last_at                  timestamptz,
    ADD CONSTRAINT contract_accounts_apply_held_shape CHECK ((apply_held IS NULL) = (apply_held_since IS NULL));

ALTER TABLE contract_workspaces
    ADD COLUMN applied_wversion bigint,
    ADD COLUMN applied_status   text CHECK (applied_status IN ('open', 'closed'));

-- Who disabled an account. The backfill is every disabled account as the
-- operator's: no document has been applied before this migration. The
-- touch trigger stays off for it, so no row's updated_at moves.
ALTER TABLE users ADD COLUMN disabled_by text CHECK (disabled_by IN ('operator', 'contract'));
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
ALTER TABLE users DISABLE TRIGGER users_touch;
UPDATE users SET disabled_by = 'operator' WHERE status = 'disabled';
ALTER TABLE users ENABLE TRIGGER users_touch;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE users ADD CONSTRAINT users_disabled_by_shape CHECK ((status = 'disabled') = (disabled_by IS NOT NULL));

-- A disable is the contract's only inside the apply's transaction, which
-- sets app.contract_apply; an operator's disable is never taken over by the
-- contract (one disabled already stays the operator's), and an operator's
-- disable of an account the contract disabled becomes the operator's. An
-- enable clears it.
CREATE FUNCTION users_disabled_by() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status <> 'disabled' THEN
        NEW.disabled_by := NULL;
    ELSIF coalesce(current_setting('app.contract_apply', true), '') = 'on' THEN
        NEW.disabled_by := CASE WHEN TG_OP = 'UPDATE' AND OLD.status = 'disabled' THEN OLD.disabled_by ELSE 'contract' END;
    ELSE
        NEW.disabled_by := 'operator';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER users_disabled_by BEFORE INSERT OR UPDATE OF status ON users
    FOR EACH ROW EXECUTE FUNCTION users_disabled_by();

CREATE TABLE contract_closings (
    sub                uuid        PRIMARY KEY,
    user_id            uuid,
    personal_workspace uuid,
    seen_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    confirmed_at       timestamptz,
    purge_due_at       timestamptz,
    forgotten_at       timestamptz,
    unsubscribed_at    timestamptz,
    CHECK ((confirmed_at IS NULL) = (purge_due_at IS NULL)),
    CHECK (forgotten_at IS NULL OR confirmed_at IS NOT NULL),
    CHECK (unsubscribed_at IS NULL OR forgotten_at IS NOT NULL)
);

ALTER TABLE api_keys DROP CONSTRAINT api_keys_revoke_reason_check,
    ADD CONSTRAINT api_keys_revoke_reason_check CHECK (revoke_reason IN ('platform_tokens', 'contract', 'orphan_service'));

ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_revoke_reason_check,
    ADD CONSTRAINT mcp_connections_revoke_reason_check CHECK (revoke_reason IN (
    'console', 'reader', 'reuse_detected', 'relay_failed', 'pending_expired', 'expired', 'service_removed',
    'service_disabled', 'member_removed', 'member_disabled', 'access_lost', 'ai_key_deleted', 'replaced', 'idle',
    'credentials_revoked'));

ALTER TABLE device_notices DROP CONSTRAINT device_notices_raised_by_kind_check,
    ADD CONSTRAINT device_notices_raised_by_kind_check CHECK (raised_by_kind IN ('person', 'key', 'app'));

ALTER TABLE device_transfers ALTER COLUMN actor_id DROP NOT NULL,
    DROP CONSTRAINT device_transfers_actor_id_fkey,
    ADD CONSTRAINT device_transfers_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE mcp_outbound DROP CONSTRAINT mcp_outbound_decided_by_fkey,
    ADD CONSTRAINT mcp_outbound_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES users(id) ON DELETE SET NULL;
