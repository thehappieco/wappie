-- Any MCP client (reader 0.6.0, docs/mcp-enclave.md §19.20).
--
-- The attested reader admits any client that identifies itself with a client
-- metadata document on an https host of its own, in two trust tiers, and
-- tools without OAuth connect with a token made in the console. The tier and
-- the client binding that count are the ones the reader attests and seals;
-- the columns here are what this server knows of them, so the console lists
-- them, the caps count them, and a forgotten field fails closed.
--
--   client_kind         'cimd', 'dcr', 'token' or 'ai'; 'legacy' for a row
--                       written before this migration, and the default, so a
--                       binary that predates it still inserts.
--   client_id           the CIMD URL; NULL for every other kind (a DCR id is
--                       random and a token has none).
--   client_host         the client's verified host; for a loopback client,
--                       the document's host, never the vouching redirect.
--   client_local        the redirect was loopback: an app on the person's
--                       own computer.
--   trust               'tested' or 'unknown', with no default: NULL marks a
--                       row an older binary wrote, which the console shows as
--                       Legacy, never as Tested. A token is always unknown.
--   claimed_name        what the client called itself, kept apart from the
--                       verified client_name and only ever shown in quotes.
--   history_days        the history window the person chose for an unknown
--                       client or a token (7, 30 or 90); NULL for all of it.
--   first_used_at       the first status check that answered active.
--
--   mcp_connection_seen which workspace managers marked a connection seen,
--                       for the new-assistant banner. Forced row-level
--                       security, as mcp_send_chats; mcp_connections keeps
--                       none (0040).
--   mcp_connection_notices
--                       the new-assistant notices a connection raised: its
--                       activation, and each reading limit the reader said
--                       it reached (the budget_hit codes, §19.19), with when
--                       it was first and last raised, how often, and when
--                       its e-mail went. An e-mail goes once per connection
--                       and event, and at most twenty a day per workspace.
--                       Forced row-level security as well. Not in the
--                       contract's sketch of 0046: the e-mail's caps need a
--                       record that outlives a restart.
--   mcp_revoke_links    the SHA-256 of each revoke-only link a notice e-mail
--                       carried, one per e-mail: any of a live connection's
--                       links revokes it, once, and all of them are spent
--                       when it ends, so a later e-mail never turns an
--                       earlier one's button into a dead end while the
--                       assistant still reads. No row-level security, as
--                       mcp_connections (0040) and sessions: it is looked up
--                       by the hash of a 256-bit secret, before anyone knows
--                       the workspace. In place of the contract sketch's
--                       revoke_link_sha256 column (docs/mcp-enclave.md
--                       §19.20), which held only the latest link.
--
-- Existing rows become client_kind 'ai' (AI authorizations) or stay 'legacy'
-- with trust 'tested': every one of them was made under 0.5.0's two-host
-- allowlist. A trigger sets client_kind 'ai' on any AI row inserted, so an
-- old binary's AI insert passes the coherence check.
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 46, so rolling back below it needs this first; the migration
-- may also stay, since an old binary inserts under it). Run only with
-- `wappie-api` stopped, WS_MCP_CIMD_MODE=allowlist and the enclave on a
-- release before 0.6.0 with its sealed as-* collections deleted
-- (docs/mcp-enclave.md §19.27), after checking this file against
-- `migration46_sha256` in the release's RELEASE.json. Like 0042's to 0045's,
-- the tenant-scoped steps run workspace by workspace, so the table owner can
-- run it under FORCE RLS as well as a superuser. Unknown-tier connections and
-- tokens that are still live end first, with 0043's cascade (each revoked
-- with its key, and a content one's service account losing its keys, grants,
-- permissions and membership): their tier lives only in these columns, and an
-- older binary would read them as connections of the allowlist. No
-- revoke_reason fits a rollback; the rows are listed as revoked without one,
-- and the revocation notice reaches the enclave as for any other end.
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      DO $$
--      DECLARE t uuid; services uuid[];
--      BEGIN
--        FOR t IN SELECT id FROM tenants LOOP
--          PERFORM set_config('app.tenant_id', t::text, true);
--          SELECT coalesce(array_agg(service_user_id) FILTER (WHERE service_user_id IS NOT NULL), '{}') INTO services
--            FROM mcp_connections WHERE tenant_id = t AND trust = 'unknown' AND status IN ('pending', 'active', 'reseal');
--          UPDATE api_keys SET revoked_at = now()
--           WHERE tenant_id = t AND revoked_at IS NULL
--             AND (id IN (SELECT api_key_id FROM mcp_connections WHERE tenant_id = t AND trust = 'unknown'
--                           AND status IN ('pending', 'active', 'reseal'))
--                  OR acts_as = ANY (services));
--          DELETE FROM device_key_grants WHERE tenant_id = t AND user_id = ANY (services);
--          DELETE FROM device_permissions WHERE tenant_id = t AND user_id = ANY (services);
--          DELETE FROM workspace_memberships WHERE tenant_id = t AND user_id = ANY (services);
--        END LOOP;
--        PERFORM set_config('app.tenant_id', '', true);
--      END $$;
--      UPDATE mcp_connections SET status = 'revoked', revoked_at = now()
--       WHERE trust = 'unknown' AND status IN ('pending', 'active', 'reseal');
--      DROP TABLE mcp_revoke_links;
--      DROP TABLE mcp_connection_notices;
--      DROP TABLE mcp_connection_seen;
--      DROP TRIGGER mcp_connections_ai_kind ON mcp_connections;
--      DROP FUNCTION mcp_connections_ai_kind();
--      ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_client_coherent;
--      ALTER TABLE mcp_connections DROP COLUMN client_kind, DROP COLUMN client_id, DROP COLUMN client_host,
--          DROP COLUMN client_local, DROP COLUMN trust, DROP COLUMN claimed_name, DROP COLUMN history_days,
--          DROP COLUMN first_used_at;
--      DELETE FROM schema_migrations WHERE version = 46;
--      COMMIT;
--
-- The revoked rows stay as history, with the verified client_name they were
-- given (a host or a tested client's name, never a claimed one). The order
-- below 46 stands: 0046 down, then 0045 down, 0044 down, 0043 down, 0042,
-- 0041.
ALTER TABLE mcp_connections
    ADD COLUMN client_kind        text     NOT NULL DEFAULT 'legacy'
                                           CHECK (client_kind IN ('legacy', 'cimd', 'dcr', 'token', 'ai')),
    ADD COLUMN client_id          text     CHECK (client_id IS NULL OR (octet_length(client_id) <= 512 AND client_id LIKE 'https://%')),
    ADD COLUMN client_host        text     CHECK (client_host IS NULL OR client_host ~ '^[a-z0-9.-]{4,253}$'),
    ADD COLUMN client_local       boolean  NOT NULL DEFAULT false,
    ADD COLUMN trust              text     CHECK (trust IS NULL OR trust IN ('tested', 'unknown')),
    ADD COLUMN claimed_name       text     CHECK (claimed_name IS NULL OR char_length(claimed_name) <= 100),
    ADD COLUMN history_days       smallint CHECK (history_days IS NULL OR history_days IN (7, 30, 90)),
    ADD COLUMN first_used_at      timestamptz;
UPDATE mcp_connections SET client_kind = 'ai' WHERE kind = 'ai';
UPDATE mcp_connections SET trust = 'tested' WHERE kind <> 'ai';
-- Any binary, old or new, inserts AI rows coherently.
CREATE FUNCTION mcp_connections_ai_kind() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF NEW.kind = 'ai' THEN NEW.client_kind := 'ai'; END IF; RETURN NEW; END $$;
CREATE TRIGGER mcp_connections_ai_kind BEFORE INSERT ON mcp_connections
    FOR EACH ROW EXECUTE FUNCTION mcp_connections_ai_kind();
ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_client_coherent CHECK (
    (client_kind = 'ai') = (kind = 'ai')
    AND (client_kind <> 'cimd' OR client_id IS NOT NULL)
    AND (client_kind <> 'token' OR (trust = 'unknown' AND client_id IS NULL AND redirect_host = 'token')));

CREATE TABLE mcp_connection_seen (
    connection_id uuid        NOT NULL REFERENCES mcp_connections(id) ON DELETE CASCADE,
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id       uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    seen_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (connection_id, user_id));
ALTER TABLE mcp_connection_seen ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_connection_seen FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_connection_seen
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE TABLE mcp_connection_notices (
    connection_id uuid        NOT NULL REFERENCES mcp_connections(id) ON DELETE CASCADE,
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event         text        NOT NULL CHECK (event IN ('activated', 'daily_messages', 'daily_attachments',
                                                        'first_hour_messages', 'first_hour_attachments', 'network')),
    first_at      timestamptz NOT NULL DEFAULT now(),
    last_at       timestamptz NOT NULL DEFAULT now(),
    count         integer     NOT NULL DEFAULT 1 CHECK (count > 0),
    mailed_at     timestamptz,
    PRIMARY KEY (connection_id, event));
-- The day's e-mails of a workspace are counted under its lock.
CREATE INDEX mcp_connection_notices_mailed ON mcp_connection_notices (tenant_id, mailed_at)
    WHERE mailed_at IS NOT NULL;
ALTER TABLE mcp_connection_notices ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_connection_notices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_connection_notices
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- A revoke-only link names one connection: its hash is looked up, never
-- scanned for, and a connection's links go when it ends.
CREATE TABLE mcp_revoke_links (
    sha256        text        PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    connection_id uuid        NOT NULL REFERENCES mcp_connections(id) ON DELETE CASCADE,
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event         text        NOT NULL CHECK (event IN ('activated', 'daily_messages', 'daily_attachments',
                                                        'first_hour_messages', 'first_hour_attachments', 'network')),
    created_at    timestamptz NOT NULL DEFAULT now());
CREATE INDEX mcp_revoke_links_connection ON mcp_revoke_links (connection_id);
