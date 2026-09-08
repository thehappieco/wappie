-- Foundation: tenants, users, the key-management tables and devices.
--
-- Message and media tables arrive in a later migration; this one establishes
-- identity, tenancy and the cryptographic bookkeeping everything else hangs on.

DO $$
BEGIN
  IF current_setting('server_version_num')::int < 180000 THEN
    RAISE EXCEPTION 'whatserver2 requires PostgreSQL 18 or newer (for uuidv7())';
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Tenants
--
-- No RLS on this table or on api_keys. Both are consulted before a tenant is
-- known — resolving an API key to a tenant is precisely the step that decides
-- which tenant id to set — so a tenant-scoped policy here would be circular.
-- They are protected by holding no plaintext secrets: api_keys stores only a
-- hash, and tenants holds no content at all.
-- ---------------------------------------------------------------------------
CREATE TABLE tenants (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    name          text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    -- Bumped on archive key rotation. Content is always sealed to the current
    -- epoch; older epochs stay readable until a re-seal job retires them.
    current_epoch integer     NOT NULL DEFAULT 1 CHECK (current_epoch >= 1),
    status        text        NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active', 'suspended')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Archive keys
--
-- Only the PUBLIC half of the tenant archive keypair lives here. The private
-- half is generated in the founder's browser and never transmitted. This is
-- what makes the server structurally unable to read its own archive: it holds
-- the key to seal and no key to open.
-- ---------------------------------------------------------------------------
CREATE TABLE tenant_archive_keys (
    tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    epoch      integer     NOT NULL CHECK (epoch >= 1),
    -- X25519 public key, HPKE DHKEM(X25519, HKDF-SHA256).
    public_key bytea       NOT NULL CHECK (length(public_key) = 32),
    -- Envelope suite id. 1 = HPKE base, X25519/HKDF-SHA256/AES-256-GCM.
    -- 2 is reserved for the ML-KEM768+X25519 hybrid.
    suite      smallint    NOT NULL DEFAULT 1 CHECK (suite > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    -- Set when a re-seal job has finished moving every row off this epoch.
    retired_at timestamptz,
    PRIMARY KEY (tenant_id, epoch)
);

-- ---------------------------------------------------------------------------
-- Users
--
-- The password never reaches this server in any form. The browser derives a
-- master key with Argon2id and splits it: one branch becomes the auth key sent
-- over TLS (stored here only as a slow hash), the other never leaves the
-- browser and unwraps the user's private key.
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email         text        NOT NULL CHECK (position('@' in email) > 1),
    -- argon2id over the client-derived auth key. Never the password itself.
    auth_hash     text        NOT NULL,
    -- Salt for the CLIENT-side Argon2id. Public by design; it is a salt.
    kdf_salt      bytea       NOT NULL CHECK (length(kdf_salt) = 16),
    -- Versioned so parameters can be raised later: on next login the client
    -- re-derives with the current parameters and re-wraps in place.
    kdf_params    jsonb       NOT NULL,
    -- X25519 public key of this user account.
    public_key    bytea       NOT NULL CHECK (length(public_key) = 32),
    -- The user's private key, wrapped under a key derived from their password.
    -- Opaque here: the server stores and returns it, and cannot open it.
    wrapped_usk   bytea       NOT NULL,
    -- The same private key wrapped under a 24-word recovery code. Null when
    -- the user declined recovery, which is why the UI tracks how many working
    -- access paths a tenant has left.
    recovery_wrap bytea,
    role          text        NOT NULL DEFAULT 'member'
                              CHECK (role IN ('owner', 'admin', 'member')),
    status        text        NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active', 'disabled')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

-- ---------------------------------------------------------------------------
-- Key grants
--
-- This table is the archive access control list. Each row is the tenant's
-- private archive key sealed to one user's public key, for one epoch.
--
-- Deleting a row is revocation level 1: the user can no longer OBTAIN the key.
-- It guarantees nothing if they already unlocked once, because the key was in
-- their browser and could have been copied. Revocation level 2 is an epoch
-- rotation plus a re-seal job, and only that is retroactive.
-- ---------------------------------------------------------------------------
CREATE TABLE tenant_key_grants (
    tenant_id  uuid        NOT NULL,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    epoch      integer     NOT NULL,
    -- HPKE ciphertext of the tenant private key under the user's public key.
    sealed_tsk bytea       NOT NULL,
    granted_by uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, epoch),
    FOREIGN KEY (tenant_id, epoch)
        REFERENCES tenant_archive_keys(tenant_id, epoch) ON DELETE CASCADE
);

CREATE INDEX tenant_key_grants_by_tenant ON tenant_key_grants (tenant_id, epoch);

-- ---------------------------------------------------------------------------
-- Content keys
--
-- Sealing every message directly with HPKE would mean one X25519 operation per
-- message on open. Measured on a mid-range Android that is 12-33 seconds to
-- open a 10k-message history — unusable. Instead a symmetric content key is
-- sealed once and covers a batch, so the same history costs about ten
-- asymmetric operations.
--
-- Rotation: a new key every 1000 seals or 15 minutes, whichever comes first,
-- plus a dedicated key per history sync run.
-- ---------------------------------------------------------------------------
CREATE TABLE content_keys (
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Per-tenant counter, carried in the envelope header. Scoped per tenant so
    -- it does not leak system-wide volume to clients.
    id           integer     NOT NULL CHECK (id >= 1),
    epoch        integer     NOT NULL,
    -- The content key sealed to the tenant archive public key.
    sealed_key   bytea       NOT NULL,
    -- Hard cap enforced in application code: a random 96-bit GCM nonce stays
    -- comfortably collision-free below 2^20 uses of one key.
    sealed_count integer     NOT NULL DEFAULT 0 CHECK (sealed_count >= 0),
    created_at   timestamptz NOT NULL DEFAULT now(),
    closed_at    timestamptz,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, epoch)
        REFERENCES tenant_archive_keys(tenant_id, epoch) ON DELETE CASCADE
);

-- Finding the open key for a tenant is on the hot ingest path.
CREATE INDEX content_keys_open ON content_keys (tenant_id, epoch, id DESC)
    WHERE closed_at IS NULL;

-- ---------------------------------------------------------------------------
-- Invites
--
-- The server never sees the invite secret, only a hash of it. The secret
-- travels out of band and lets the inviter verify that the invitee's public key
-- was not substituted in transit — the one attack that would otherwise let a
-- malicious server have the archive key sealed to itself.
-- ---------------------------------------------------------------------------
CREATE TABLE invites (
    -- SHA-256 of the invite secret. Knowing this does not permit redemption.
    invite_id     bytea       PRIMARY KEY CHECK (length(invite_id) = 32),
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role          text        NOT NULL DEFAULT 'member'
                              CHECK (role IN ('owner', 'admin', 'member')),
    created_by    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at    timestamptz NOT NULL,
    -- Set when the invitee posts their public key; the inviter then verifies
    -- the binding and issues the grant.
    claimed_by    uuid        REFERENCES users(id) ON DELETE CASCADE,
    claimed_at    timestamptz,
    -- HMAC proving the claimed public key came from the holder of the secret.
    claim_binding bytea       CHECK (claim_binding IS NULL OR length(claim_binding) = 32),
    completed_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX invites_by_tenant ON invites (tenant_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- API keys
--
-- Stored as prefix plus slow hash. The prefix makes lookup an index probe
-- instead of the v1 approach, which iterated every key in a map doing a
-- constant-time compare on each — constant time per comparison, but the
-- iteration itself was not.
-- ---------------------------------------------------------------------------
CREATE TABLE api_keys (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- First 8 characters of the presented key. Lookup selector, not a secret.
    prefix     text        NOT NULL CHECK (length(prefix) = 8),
    -- argon2id of the full key. The key itself is shown once, at creation.
    key_hash   text        NOT NULL,
    name       text        NOT NULL DEFAULT '',
    created_by uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at timestamptz,
    UNIQUE (prefix)
);

CREATE INDEX api_keys_active ON api_keys (prefix) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Devices
--
-- Identity is a (lid, pn) pair with LID primary.
--
-- The v1 server canonicalised every @lid JID to a phone number on ingest and
-- backfilled old rows on every reconnect. Upstream has since made LID the
-- routing identity for direct messages, and LID exists specifically to withhold
-- the phone number — so for some contacts a phone number will never be
-- available. Rewriting keys toward PN is therefore no longer possible, let
-- alone correct. Both identifiers are stored, neither is rewritten, and display
-- names are resolved at read time.
-- ---------------------------------------------------------------------------
CREATE TABLE devices (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    lid           text,
    pn            text,
    label         text        NOT NULL DEFAULT '',
    push_name     text        NOT NULL DEFAULT '',
    status        text        NOT NULL DEFAULT 'new'
                              CHECK (status IN ('new', 'pairing', 'online', 'offline',
                                                'logged_out', 'banned')),
    status_reason text        NOT NULL DEFAULT '',
    -- Receipt policy for this device. 'passive' is the default: never announce
    -- presence, never mark read unless explicitly asked. Delivery receipts
    -- still leave as type "inactive", which official clients do not render —
    -- suppressing them entirely needs a patched whatsmeow.
    receipt_mode  text        NOT NULL DEFAULT 'passive'
                              CHECK (receipt_mode IN ('passive', 'active')),
    last_connected_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
    -- Deliberately no constraint tying status to having an identity.
    --
    -- "A connected device must know who it is" reads as obviously true and is
    -- false against the actual protocol: whatsmeow opens the connection first
    -- and pairs over it, which is how the QR is delivered in the first place.
    -- So events.Connected legitimately fires while lid and pn are both still
    -- null. A CHECK here would reject the status write for every device on its
    -- very first connection.
    --
    -- The invariant that is real -- an identity, once learned, is never
    -- unlearned -- is enforced by the COALESCE in Devices.SetIdentity, not
    -- here. Either half may be permanently absent: LID exists precisely to
    -- withhold the phone number.
);

CREATE UNIQUE INDEX devices_lid ON devices (tenant_id, lid) WHERE lid IS NOT NULL;
CREATE UNIQUE INDEX devices_pn  ON devices (tenant_id, pn)  WHERE pn IS NOT NULL;
CREATE INDEX devices_by_tenant ON devices (tenant_id, status);

-- ---------------------------------------------------------------------------
-- Row level security
--
-- Every tenant-scoped table below denies all rows unless app.tenant_id is set
-- for the current transaction. A handler that forgets to filter returns nothing
-- instead of another tenant's data.
--
-- FORCE is required: without it the table owner — which is the application role
-- here — bypasses its own policies, and the protection would be theatre. The
-- application must also never connect as a superuser, since superusers bypass
-- RLS regardless. See TestRLSDeniesWithoutTenant.
-- ---------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'tenant_archive_keys', 'users', 'tenant_key_grants',
        'content_keys', 'invites', 'devices'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        -- NULLIF is not decoration. current_setting(..., true) returns NULL
        -- only if the GUC was never set on this connection at all; once a
        -- transaction has set it, the value resets to the EMPTY STRING rather
        -- than to unset. On a pooled connection that has served even one
        -- tenant transaction, a later unscoped query would then evaluate
        -- ''::uuid and raise 22P02 instead of returning nothing. Failing with
        -- a type error would be survivable, but it would also mean the
        -- fail-closed guarantee depended on an exception rather than on the
        -- policy. NULLIF makes the empty string mean the same as unset: the
        -- comparison is NULL, which is not true, so no row qualifies.
        EXECUTE format($f$
            CREATE POLICY tenant_isolation ON %I
                USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
        $f$, t);
    END LOOP;
END $$;

CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER tenants_touch BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER users_touch BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER devices_touch BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
