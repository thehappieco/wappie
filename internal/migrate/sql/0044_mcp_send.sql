-- Sending (stage S of the attested reader, docs/mcp-enclave.md §17).
--
-- A content connection given under consent version 3 may draft WhatsApp
-- messages for the person who consented to confirm in the console, send
-- notes to the number's own chat and, from S3, send directly to a closed list
-- of chats. The consent that binds is the one sealed in the bundle, under a
-- device check only a holder of each number's key can make; the columns here
-- are what this server knows of it, so the console lists it, the relay hands
-- it to the reader to compare with the sealed one, and every draft and send
-- route refuses a connection without it. This server can only narrow it.
--
--   send_mode       'draft' or 'direct' (S3) on a content connection of
--                   consent version 3 or later; NULL on every other row.
--   send_self       the own-chat sends were consented to.
--   send_groups     groups are eligible for drafts.
--   send_paused_at  when the pause was switched on; NULL while not paused.
--
--   mcp_send_chats  direct send's closed list (S3): the chats a direct
--                   connection may reach. A removal sets removed_at; rows are
--                   never deleted while the connection lives.
--   mcp_outbound    the ledger: every draft, own-chat send, direct send and
--                   refusal of a connection. A draft carries its sealed text
--                   (Kind 0x0E, opened only by the console) while it waits;
--                   nothing else here is ever message text. Rows go 365 days
--                   after they were written.
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 44, so rolling back below it needs this first). Run only with
-- `wappie-api` stopped, WS_MCP_SEND_ENABLED=false, the enclave on a release
-- without sending (0.4.x, docs/mcp-enclave.md §17.17), 0045 already down, and
-- after checking this file against `migration44_sha256` in the release's
-- RELEASE.json. Like 0042's and 0043's, the tenant-scoped steps run workspace
-- by workspace, so the table owner can run it under FORCE RLS as well as a
-- superuser. Connections that consented to sending end first, with 0043's
-- cascade: every one is revoked with its key, and its service account loses
-- its keys, grants, permissions and membership, because its ledger and pause
-- go with the tables and a connection consented to sending must not outlive
-- its audit. No revoke_reason fits a rollback; the rows are listed as revoked
-- without one, and the revocation notice reaches the enclave as for any other
-- end.
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      DO $$
--      DECLARE t uuid; services uuid[];
--      BEGIN
--        FOR t IN SELECT id FROM tenants LOOP
--          PERFORM set_config('app.tenant_id', t::text, true);
--          SELECT coalesce(array_agg(service_user_id), '{}') INTO services
--            FROM mcp_connections WHERE tenant_id = t AND send_mode IS NOT NULL;
--          UPDATE api_keys SET revoked_at = now()
--           WHERE tenant_id = t AND revoked_at IS NULL
--             AND (id IN (SELECT api_key_id FROM mcp_connections WHERE tenant_id = t AND send_mode IS NOT NULL)
--                  OR acts_as = ANY (services));
--          DELETE FROM device_key_grants WHERE tenant_id = t AND user_id = ANY (services);
--          DELETE FROM device_permissions WHERE tenant_id = t AND user_id = ANY (services);
--          DELETE FROM workspace_memberships WHERE tenant_id = t AND user_id = ANY (services);
--        END LOOP;
--        PERFORM set_config('app.tenant_id', '', true);
--      END $$;
--      UPDATE mcp_connections SET status = 'revoked', revoked_at = now()
--       WHERE send_mode IS NOT NULL AND status IN ('pending', 'active', 'reseal');
--      DROP TABLE mcp_outbound;
--      DROP TABLE mcp_send_chats;
--      ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_send_coherent;
--      ALTER TABLE mcp_connections DROP COLUMN send_mode, DROP COLUMN send_self,
--          DROP COLUMN send_groups, DROP COLUMN send_paused_at;
--      DELETE FROM schema_migrations WHERE version = 44;
--      COMMIT;
--
-- The revoked rows stay in mcp_connections as history and read as content
-- connections of version 3 once the columns are gone; an older binary reads
-- them (0042's `consent_version BETWEEN 1 AND 1000`) and never creates one.
-- The order below 44 stands: 0045 down, 0044 down, 0043 down, 0042, 0041.
ALTER TABLE mcp_connections
    ADD COLUMN send_mode      text CHECK (send_mode IN ('draft', 'direct')),
    ADD COLUMN send_self      boolean NOT NULL DEFAULT false,
    ADD COLUMN send_groups    boolean NOT NULL DEFAULT false,
    ADD COLUMN send_paused_at timestamptz;
ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_send_coherent CHECK (
    (send_mode IS NULL AND NOT send_self AND NOT send_groups AND send_paused_at IS NULL)
 OR (send_mode IS NOT NULL AND kind = 'content' AND consent_version >= 3));

-- Direct send's closed list (S3). A removal sets removed_at; rows are never deleted.
CREATE TABLE mcp_send_chats (
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connection_id uuid        NOT NULL REFERENCES mcp_connections(id) ON DELETE CASCADE,
    device_id     uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    chat_key      text        NOT NULL CHECK (length(chat_key) BETWEEN 1 AND 128),
    created_at    timestamptz NOT NULL DEFAULT now(),
    removed_at    timestamptz,
    PRIMARY KEY (connection_id, device_id, chat_key)
);

-- The ledger: every draft, send and refusal of a connection. Never message text.
CREATE TABLE mcp_outbound (
    id            uuid        PRIMARY KEY,   -- a draft's is the enclave's; Go's own (uuidv7) otherwise
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connection_id uuid        NOT NULL REFERENCES mcp_connections(id) ON DELETE CASCADE,
    device_id     uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    chat_key      text        CHECK (length(chat_key) BETWEEN 1 AND 128),
    reply_to_uid  uuid,
    kind          text        NOT NULL CHECK (kind IN ('draft', 'self', 'send')),
    status        text        NOT NULL CHECK (status IN
        ('pending', 'sending', 'sent', 'uncertain', 'discarded', 'expired', 'revoked', 'refused')),
    code          text        CHECK (code ~ '^[a-z][a-z0-9_]{0,39}$'),
    sealed        bytea       CHECK (length(sealed) <= 20480),
    epoch         integer     CHECK (epoch BETWEEN 1 AND 65535),
    client_ref    text        CHECK (client_ref ~ '^[A-Za-z0-9_-]{22}$'),
    edited        boolean     NOT NULL DEFAULT false,
    decided_by    uuid        REFERENCES users(id),
    message_uid   uuid,
    wa_id         text        CHECK (length(wa_id) <= 128),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz,
    decided_at    timestamptz,
    UNIQUE (connection_id, client_ref),
    CHECK (kind = 'draft' OR sealed IS NULL),
    CHECK (sealed IS NULL OR status = 'pending'),
    CHECK (kind <> 'draft' OR status <> 'pending' OR (sealed IS NOT NULL AND epoch IS NOT NULL AND expires_at IS NOT NULL)),
    CHECK (status <> 'pending' OR kind = 'draft'),
    CHECK (status <> 'refused' OR code IS NOT NULL),
    CHECK (kind = 'self' OR chat_key IS NOT NULL)
);
CREATE INDEX mcp_outbound_connection ON mcp_outbound (connection_id, created_at DESC, id DESC);
CREATE INDEX mcp_outbound_pending ON mcp_outbound (expires_at) WHERE status = 'pending';
CREATE INDEX mcp_outbound_message ON mcp_outbound (tenant_id, message_uid) WHERE message_uid IS NOT NULL;
CREATE INDEX mcp_outbound_tenant_sends ON mcp_outbound (tenant_id, created_at) WHERE kind <> 'draft';

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['mcp_send_chats', 'mcp_outbound'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$
            CREATE POLICY tenant_isolation ON %I
                USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
        $f$, t);
    END LOOP;
END $$;
