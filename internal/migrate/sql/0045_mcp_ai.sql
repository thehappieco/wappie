-- AI integrations on request (stage B1 of the attested reader,
-- docs/mcp-enclave.md §18).
--
-- A person may let the attested reader send attachments of the numbers they
-- read to the AI providers they choose, with their own API keys, one provider
-- and model per function (audio and voice notes, video, images, documents).
-- The authorization that binds is the sealed AI bundle, whose configuration
-- tags only a holder of each number's key can make; what is here is what this
-- server knows of it, and the three things it keeps for the person: their
-- keychain, the results and the usage counters. None of it is content.
--
--   mcp_connections   kind 'ai': an AI authorization, with its own service
--                     account like a content connection, redirect_host
--                     'console', consent_version 1 (the AI card's own
--                     numbering), never media and never sending.
--     ai_config       the authorization's configuration as the console sealed
--                     it: devices, epochs and namespaces, the key hashes and
--                     labels, the functions with their providers and models,
--                     who may ask, the budget and the tags. On 'ai' rows only.
--     ai_paused_at    when a person paused it; NULL while not paused.
--     ai_off          the functions a person switched off on it.
--     ai_cap_cents    a monthly cap a person set below the sealed budget.
--     ai_alerts       what the reader reported (a key rejected, a model gone,
--                     no quota), kept until a renewal.
--   revoke_reason     adds 'ai_key_deleted': the keychain item it named went.
--
--   ai_keychain       a person's API keys, sealed in their browser under a key
--                     only their account's private key derives: an opaque
--                     envelope, emptied when the item is deleted.
--   ai_derived        transcripts, descriptions and summaries: one sealed
--                     record per message and function, sealed with a key
--                     derived from the number's archive key, and a dedupe tag
--                     keyed the same way. They count toward the storage quota,
--                     go with their message, and move with their device.
--   ai_usage_daily    plain counters per day, authorization, number,
--                     function, provider, model, key, origin and requester.
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 45, so rolling back below it needs this first). Run only with
-- `wappie-api` stopped, WS_AI_ENABLED=false, the enclave on a release without
-- AI (below 0.5.0, or 0.5.0 if B1 slipped), after checking this file against
-- `migration45_sha256` in the release's RELEASE.json, and before 0044's. Like
-- 0042's to 0044's, the tenant-scoped steps run workspace by workspace, so the
-- table owner can run it under FORCE RLS as well as a superuser. Every 'ai'
-- row ends with 0043's cascade (its key revoked, its service account's keys,
-- grants, permissions and membership removed) and is then deleted, since the
-- restored kind CHECK has no room for it; the results are deleted row by row
-- inside the loop, so the storage trigger gives their bytes back to each
-- workspace's quota and removes their storage_inventory rows before the table
-- goes; the usage and the keychain go with their tables.
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      DO $$
--      DECLARE t uuid; services uuid[];
--      BEGIN
--        FOR t IN SELECT id FROM tenants LOOP
--          PERFORM set_config('app.tenant_id', t::text, true);
--          SELECT coalesce(array_agg(service_user_id), '{}') INTO services
--            FROM mcp_connections WHERE tenant_id = t AND kind = 'ai';
--          UPDATE api_keys SET revoked_at = now()
--           WHERE tenant_id = t AND revoked_at IS NULL
--             AND (id IN (SELECT api_key_id FROM mcp_connections WHERE tenant_id = t AND kind = 'ai')
--                  OR acts_as = ANY (services));
--          DELETE FROM device_key_grants WHERE tenant_id = t AND user_id = ANY (services);
--          DELETE FROM device_permissions WHERE tenant_id = t AND user_id = ANY (services);
--          DELETE FROM workspace_memberships WHERE tenant_id = t AND user_id = ANY (services);
--          DELETE FROM ai_derived WHERE tenant_id = t;   -- its trigger gives the bytes back to the quota
--        END LOOP;
--        PERFORM set_config('app.tenant_id', '', true);
--      END $$;
--      DROP TABLE ai_usage_daily;
--      DROP TABLE ai_derived;
--      DROP TABLE ai_keychain;
--      DELETE FROM mcp_connections WHERE kind = 'ai';
--      ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_ai_coherent;
--      ALTER TABLE mcp_connections DROP COLUMN ai_config, DROP COLUMN ai_paused_at, DROP COLUMN ai_off,
--          DROP COLUMN ai_cap_cents, DROP COLUMN ai_alerts;
--      ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_revoke_reason_check;
--      ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_revoke_reason_check CHECK (revoke_reason IN (
--          'console', 'reader', 'reuse_detected', 'relay_failed', 'pending_expired', 'expired', 'service_removed',
--          'service_disabled', 'member_removed', 'member_disabled', 'access_lost'));
--      ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_kind_coherent;
--      ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_kind_coherent CHECK (
--          (kind = 'metadata' AND service_user_id IS NULL AND key_mode IS NULL AND consent_version IS NULL AND status <> 'reseal')
--       OR (kind = 'content' AND service_user_id IS NOT NULL AND key_mode IS NOT NULL AND consent_version IS NOT NULL AND reader <> 'hosted'));
--      ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_kind_check;
--      ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_kind_check CHECK (kind IN ('metadata', 'content'));
--      DELETE FROM schema_migrations WHERE version = 45;
--      COMMIT;
--
-- The 'ai' rows are deleted rather than kept as history: nothing an older
-- binary reads can hold them. A row that ended with 'ai_key_deleted' goes with
-- them. The order below 45 stands: 0045 down, 0044 down, 0043 down, 0042, 0041.
ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_kind_check;
ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_kind_check
    CHECK (kind IN ('metadata', 'content', 'ai'));
ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_kind_coherent;
ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_kind_coherent CHECK (
    (kind = 'metadata' AND service_user_id IS NULL AND key_mode IS NULL AND consent_version IS NULL AND status <> 'reseal')
 OR (kind IN ('content', 'ai') AND service_user_id IS NOT NULL AND key_mode IS NOT NULL
     AND consent_version IS NOT NULL AND reader <> 'hosted'));
ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_revoke_reason_check;
ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_revoke_reason_check CHECK (revoke_reason IN (
    'console', 'reader', 'reuse_detected', 'relay_failed', 'pending_expired', 'expired', 'service_removed',
    'service_disabled', 'member_removed', 'member_disabled', 'access_lost', 'ai_key_deleted'));
ALTER TABLE mcp_connections
    ADD COLUMN ai_config    jsonb       CHECK (octet_length(ai_config::text) <= 32768),
    ADD COLUMN ai_paused_at timestamptz,
    ADD COLUMN ai_off       text[]      NOT NULL DEFAULT '{}'
                                        CHECK (ai_off <@ ARRAY['audio', 'video', 'image', 'document']),
    ADD COLUMN ai_cap_cents integer     CHECK (ai_cap_cents BETWEEN 1 AND 100000),
    ADD COLUMN ai_alerts    jsonb       NOT NULL DEFAULT '{}' CHECK (octet_length(ai_alerts::text) <= 4096);
ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_ai_coherent CHECK (
    (kind = 'ai' AND ai_config IS NOT NULL AND NOT media AND redirect_host = 'console' AND consent_version = 1)
 OR (kind <> 'ai' AND ai_config IS NULL AND ai_paused_at IS NULL AND ai_off = '{}'
     AND ai_cap_cents IS NULL AND ai_alerts = '{}'));

-- A person's API keys, sealed in their browser (§18.6). Go stores an opaque envelope.
CREATE TABLE ai_keychain (
    id         uuid        PRIMARY KEY,             -- chosen by the browser and bound in the envelope
    tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider   text        NOT NULL CHECK (provider IN ('anthropic', 'openai', 'google')),
    label      text        NOT NULL CHECK (length(label) BETWEEN 1 AND 60),
    suffix     text        NOT NULL CHECK (suffix ~ '^[!-~]{4}$'),
    envelope   bytea       NOT NULL CHECK (length(envelope) <= 4096),   -- emptied on deletion
    created_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);
CREATE INDEX ai_keychain_user ON ai_keychain (tenant_id, user_id) WHERE deleted_at IS NULL;

-- Transcripts, descriptions and summaries: one sealed record per message and function (§18.8).
CREATE TABLE ai_derived (
    message_uid      uuid        NOT NULL REFERENCES messages(uid) ON DELETE CASCADE,
    feature          text        NOT NULL CHECK (feature IN ('audio', 'video', 'image', 'document')),
    tenant_id        uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id        uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    epoch            integer     NOT NULL CHECK (epoch BETWEEN 1 AND 65535),
    result_sealed    bytea       NOT NULL CHECK (length(result_sealed) <= 524323),
    dedupe_tag       bytea       NOT NULL CHECK (length(dedupe_tag) = 32),
    authorization_id uuid        REFERENCES mcp_connections(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (message_uid, feature)
);
CREATE INDEX ai_derived_tag ON ai_derived (tenant_id, device_id, feature, dedupe_tag);
CREATE INDEX ai_derived_authorization ON ai_derived (authorization_id) WHERE authorization_id IS NOT NULL;
CREATE TRIGGER storage_account AFTER INSERT OR UPDATE OR DELETE ON ai_derived
    FOR EACH ROW EXECUTE FUNCTION storage_account_record('message_uid', 'feature');
CREATE TRIGGER archive_device_owner BEFORE INSERT OR UPDATE ON ai_derived
    FOR EACH ROW EXECUTE FUNCTION archive_device_owner();

-- Plain counters for display, and the lower bound the enclave reads at install (§18.10). Never content.
CREATE TABLE ai_usage_daily (
    tenant_id        uuid    NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    day              date    NOT NULL,                  -- UTC
    authorization_id uuid    NOT NULL REFERENCES mcp_connections(id) ON DELETE CASCADE,
    device_id        uuid    NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    feature          text    NOT NULL CHECK (feature IN ('audio', 'video', 'image', 'document')),
    provider         text    NOT NULL CHECK (provider IN ('anthropic', 'openai', 'google')),
    model            text    NOT NULL CHECK (model ~ '^[a-z0-9][a-z0-9._:-]{0,63}$'),
    keychain_id      uuid    NOT NULL,                  -- the key that paid, as ai_config named it then; no foreign key
    origin           text    NOT NULL CHECK (origin IN ('console', 'connector', 'auto')),
    requester_id     uuid    NOT NULL,
    items            integer NOT NULL DEFAULT 0 CHECK (items >= 0),
    reused           integer NOT NULL DEFAULT 0 CHECK (reused >= 0),
    failures         integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
    input_tokens     bigint  NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens    bigint  NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    seconds          integer NOT NULL DEFAULT 0 CHECK (seconds >= 0),
    cost_microcents  bigint  NOT NULL DEFAULT 0 CHECK (cost_microcents >= 0),
    PRIMARY KEY (tenant_id, day, authorization_id, device_id, feature, provider, model, keychain_id, origin, requester_id)
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['ai_keychain', 'ai_derived', 'ai_usage_daily'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$
            CREATE POLICY tenant_isolation ON %I
                USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
        $f$, t);
    END LOOP;
END $$;
CREATE POLICY device_move ON ai_derived USING (device_move_scope(tenant_id)) WITH CHECK (device_move_scope(tenant_id));
