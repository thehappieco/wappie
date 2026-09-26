-- Content connections (milestone 2b of the hosted assistant connector).
--
-- A connection held by an attested reader may now open message text, chat and
-- contact names and filenames inside the enclave. Such a connection is of
-- kind 'content' and rides on a service account of its own: created for it
-- in the consent, its public key the per-connection key the browser verified
-- in an attestation, and its grants sealed to that key. Nothing here opens
-- anything; the columns record which account the connection reads as, how the
-- reader holds its key, and why a connection ended.
--
--   kind               'metadata' for every hosted and 2a connection, or
--                      'content'.
--   service_user_id    the connection's own service account; never reused,
--                      so UNIQUE.
--   key_mode           'ephemeral': the key lives in enclave memory only
--                      (the persisted mode is a later milestone).
--   consent_version    the consent text the person saw, for content.
--   revoke_reason      why a connection ended, for the console and the log.
--   reader_notified_at when the reader confirmed a revocation notice; the
--                      notice repeats until it does.
--   resealed_at        when the reader last lost the key (status 'reseal').
--   renewed_at         when the person last renewed the key.
--
-- 'reseal' is a content connection that is consented but whose reader holds
-- no key (it restarted): the connection id and the token family survive, and
-- the person renews in the console with their password.
--
-- workspace_memberships.expires_at is set only for connection service
-- accounts: thirty minutes while the consent is being given, then the
-- connection's expiry. A membership past it counts as absent everywhere.
-- invites.provisional marks the thirty-minute service invitation the console
-- issues for a content consent.
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 42, so rolling back below it needs this first). Run only with
-- `wappie-api` stopped, WS_MCP_CONTENT_ENABLED=false and the enclave stopped,
-- after checking this file against `migration42_sha256` in the release's
-- RELEASE.json. device_key_grants, device_permissions and
-- workspace_memberships force row-level security, so the block sets each
-- workspace in turn and works for the table owner as well as for a superuser.
-- Content first: every content connection is revoked with its key, and every
-- connection service account (a content row's, or any membership with a
-- deadline) loses its keys, grants, permissions and membership. The
-- provisional invitations are deleted before their column goes (invites has
-- no row-level security): an unused one left behind would redeem, on the
-- older binary, as an ordinary service invitation, into a service account
-- with no deadline.
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      DO $$
--      DECLARE t uuid; services uuid[];
--      BEGIN
--        FOR t IN SELECT id FROM tenants LOOP
--          PERFORM set_config('app.tenant_id', t::text, true);
--          SELECT coalesce(array_agg(s.user_id), '{}') INTO services FROM (
--            SELECT service_user_id AS user_id FROM mcp_connections WHERE tenant_id = t AND kind = 'content'
--            UNION SELECT user_id FROM workspace_memberships WHERE tenant_id = t AND expires_at IS NOT NULL) s;
--          UPDATE api_keys SET revoked_at = now()
--           WHERE tenant_id = t AND revoked_at IS NULL
--             AND (id IN (SELECT api_key_id FROM mcp_connections WHERE tenant_id = t AND kind = 'content')
--                  OR acts_as = ANY (services));
--          DELETE FROM device_key_grants WHERE tenant_id = t AND user_id = ANY (services);
--          DELETE FROM device_permissions WHERE tenant_id = t AND user_id = ANY (services);
--          DELETE FROM workspace_memberships WHERE tenant_id = t AND user_id = ANY (services);
--        END LOOP;
--        PERFORM set_config('app.tenant_id', '', true);
--      END $$;
--      UPDATE mcp_connections SET status = 'revoked', revoked_at = now()
--       WHERE kind = 'content' AND status IN ('pending', 'active', 'reseal');
--      DELETE FROM invites WHERE provisional;
--      ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_kind_coherent;
--      ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_status_check;
--      ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_status_check
--          CHECK (status IN ('pending', 'active', 'revoked', 'expired'));
--      ALTER TABLE mcp_connections DROP COLUMN kind, DROP COLUMN service_user_id, DROP COLUMN key_mode,
--          DROP COLUMN consent_version, DROP COLUMN revoke_reason, DROP COLUMN reader_notified_at,
--          DROP COLUMN resealed_at, DROP COLUMN renewed_at;
--      ALTER TABLE workspace_memberships DROP COLUMN expires_at;
--      ALTER TABLE invites DROP CONSTRAINT invites_provisional_service;
--      ALTER TABLE invites DROP COLUMN provisional;
--      DELETE FROM schema_migrations WHERE version = 42;
--      COMMIT;
--
-- The revoked rows stay in mcp_connections as history, like any revoked
-- connection. The service accounts' users rows stay too, as a removed
-- member's do.
ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_status_check;
ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_status_check
    CHECK (status IN ('pending', 'active', 'reseal', 'revoked', 'expired'));
ALTER TABLE mcp_connections
    ADD COLUMN kind               text NOT NULL DEFAULT 'metadata' CHECK (kind IN ('metadata', 'content')),
    ADD COLUMN service_user_id    uuid UNIQUE REFERENCES users(id),
    ADD COLUMN key_mode           text CHECK (key_mode IN ('ephemeral')),
    ADD COLUMN consent_version    int  CHECK (consent_version BETWEEN 1 AND 1000),
    ADD COLUMN revoke_reason      text CHECK (revoke_reason IN ('console', 'reader', 'reuse_detected', 'relay_failed',
        'pending_expired', 'expired', 'service_removed', 'service_disabled', 'member_removed', 'member_disabled', 'access_lost')),
    ADD COLUMN reader_notified_at timestamptz,
    ADD COLUMN resealed_at        timestamptz,
    ADD COLUMN renewed_at         timestamptz;
ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_kind_coherent CHECK (
    (kind = 'metadata' AND service_user_id IS NULL AND key_mode IS NULL AND consent_version IS NULL AND status <> 'reseal')
 OR (kind = 'content' AND service_user_id IS NOT NULL AND key_mode IS NOT NULL AND consent_version IS NOT NULL AND reader <> 'hosted'));
-- The revocation notices a reader has not confirmed yet, looked up every
-- thirty seconds per reader.
CREATE INDEX mcp_connections_unnotified ON mcp_connections (reader, revoked_at)
    WHERE reader_notified_at IS NULL AND status IN ('revoked', 'expired');

-- Only connection service accounts carry a deadline: provisional first, then
-- the connection's expiry.
ALTER TABLE workspace_memberships ADD COLUMN expires_at timestamptz;
ALTER TABLE invites ADD COLUMN provisional boolean NOT NULL DEFAULT false;
ALTER TABLE invites ADD CONSTRAINT invites_provisional_service CHECK (NOT provisional OR role = 'service');
