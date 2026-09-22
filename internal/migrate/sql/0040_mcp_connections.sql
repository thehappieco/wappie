-- Hosted assistant connections: one row per consent a workspace gave a remote
-- MCP client (claude.ai, ChatGPT), riding on one read-only API key.
--
-- No RLS on this table, for the same reason api_keys carries none
-- (0001_foundation.sql). The reader process that serves the assistant looks a
-- connection up by its opaque id over loopback, before and without any tenant
-- in hand, so a tenant-scoped policy would be circular; the console's queries
-- carry tenant_id explicitly, as they do for api_keys, and every write on
-- behalf of a person still runs inside a tenant transaction because the
-- owner/admin check reads policy-protected tables.
--
-- There are no secrets here. The sealed bundle, the OAuth tokens and the key
-- itself live with the reader; this ledger records who consented, to what, and
-- where the connection stands, which is what the console shows and what a
-- revocation needs.
CREATE TABLE mcp_connections (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The reader's pending authorization request this consent answers.
    request_id    text        NOT NULL UNIQUE,
    -- The key the assistant reaches the archive with. One key, one connection:
    -- revoking either revokes both.
    api_key_id    uuid        NOT NULL UNIQUE REFERENCES api_keys(id) ON DELETE CASCADE,
    created_by    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_name   text        NOT NULL,
    redirect_host text        NOT NULL,
    device_count  int         NOT NULL,
    -- Which reader public key the bundle was sealed to, so a rotation is
    -- visible from here.
    reader_kid    text        NOT NULL,
    -- pending: consented, the assistant has not finished its handshake.
    -- active: the reader confirmed the handshake. revoked: a person or the
    -- janitor ended it. expired: it reached the lifetime the person chose.
    status        text        NOT NULL CHECK (status IN ('pending', 'active', 'revoked', 'expired')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    activated_at  timestamptz,
    revoked_at    timestamptz,
    expires_at    timestamptz NOT NULL,
    last_seen_at  timestamptz
);

CREATE INDEX mcp_connections_tenant ON mcp_connections (tenant_id, created_at DESC);
