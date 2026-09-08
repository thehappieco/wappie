-- The archive key moves from the tenant to the device.
--
-- Why, in one sentence: with a per-tenant key, "this operator may read that
-- WhatsApp account and not this one" is a rule the *server* enforces, and the
-- premise of this whole system is that server-enforced rules do not survive a
-- compromised server. A key per device makes the separation arithmetic instead:
-- whoever holds the key for one account is structurally unable to open another.
--
-- WHAT THIS DESTROYS. Content keys sealed to a tenant key cannot be re-sealed
-- to a device key, because re-sealing means opening, and this server has never
-- been able to open them. So the tenant key material is dropped and every
-- content key with it. Messages, chats and contacts are LEFT IN PLACE and
-- become permanently unreadable; `whatserverd reset-archive` removes them, as a
-- deliberate act by an operator rather than a side effect of a boot.
--
-- Also here, because they are the same decision seen from the other end: users,
-- sessions and per-device key grants. A grant is the device's private key
-- sealed to one person's public key, which is what lets somebody read an
-- archive by logging in rather than by keeping a 32-byte secret in a text file.
-- The account that lost this archive lost it exactly that way.

-- ---------------------------------------------------------------------------
-- Device archive keys
--
-- Only the public half. The private half is generated on a client at pairing
-- time and never transmitted, which is what makes this server unable to read
-- what it stores. There is no column here that could hold one by mistake.
-- ---------------------------------------------------------------------------
CREATE TABLE device_archive_keys (
    tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id  uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    epoch      integer     NOT NULL CHECK (epoch >= 1),
    public_key bytea       NOT NULL CHECK (length(public_key) = 32),
    -- 1 = HPKE base, X25519/HKDF-SHA256/AES-256-GCM.
    -- 2 is reserved for the ML-KEM768 + X25519 hybrid.
    suite      smallint    NOT NULL DEFAULT 1 CHECK (suite > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    -- Set when a re-seal has finished moving every row off this epoch.
    retired_at timestamptz,
    PRIMARY KEY (device_id, epoch)
);

CREATE INDEX device_archive_keys_by_tenant ON device_archive_keys (tenant_id);

-- Which epoch a device is sealing under now. Zero means no key yet, which is
-- fatal to ingest on purpose: storing plaintext instead would be a silent
-- failure of the only guarantee this system makes.
ALTER TABLE devices ADD COLUMN current_epoch integer NOT NULL DEFAULT 0
    CHECK (current_epoch >= 0);

-- ---------------------------------------------------------------------------
-- Key grants: the archive access control list
--
-- Each row is one device's private archive key, sealed to one user's public
-- key. Deleting a row is revocation level 1 — the user can no longer OBTAIN the
-- key. It guarantees nothing if they already unlocked once, because the key was
-- in their browser and could have been copied. Level 2 is an epoch rotation
-- plus a re-seal, and only that is retroactive.
-- ---------------------------------------------------------------------------
CREATE TABLE device_key_grants (
    tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id  uuid        NOT NULL,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    epoch      integer     NOT NULL,
    -- HPKE ciphertext of the device private key under the user's public key.
    sealed_dsk bytea       NOT NULL,
    granted_by uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id, epoch),
    FOREIGN KEY (device_id, epoch)
        REFERENCES device_archive_keys(device_id, epoch) ON DELETE CASCADE
);

CREATE INDEX device_key_grants_by_device ON device_key_grants (device_id, epoch);

-- ---------------------------------------------------------------------------
-- Content keys become per device
--
-- The existing rows are dropped rather than migrated: each is sealed to a
-- tenant key that is about to stop existing, and nothing here can open one to
-- re-seal it.
--
-- The policy comes off first, and that is not a formality. A migration runs
-- with no app.tenant_id set, so under row-level security this DELETE matches
-- nothing at all -- silently, reporting success -- and the NOT NULL column
-- below then fails on rows the migration believed it had removed. An empty
-- database never notices; a real one fails at the worst moment.
ALTER TABLE content_keys DISABLE ROW LEVEL SECURITY;
DELETE FROM content_keys;

ALTER TABLE content_keys DROP CONSTRAINT content_keys_tenant_id_epoch_fkey;
ALTER TABLE content_keys DROP CONSTRAINT content_keys_pkey;
ALTER TABLE content_keys ADD COLUMN device_id uuid NOT NULL
    REFERENCES devices(id) ON DELETE CASCADE;
ALTER TABLE content_keys ADD PRIMARY KEY (device_id, id);
ALTER TABLE content_keys ADD FOREIGN KEY (device_id, epoch)
    REFERENCES device_archive_keys(device_id, epoch) ON DELETE CASCADE;

DROP INDEX content_keys_open;
-- Finding the open key for a device is on the hot ingest path.
CREATE INDEX content_keys_open ON content_keys (device_id, epoch, id DESC)
    WHERE closed_at IS NULL;

ALTER TABLE content_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE content_keys FORCE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- The tenant-scoped key material goes away
-- ---------------------------------------------------------------------------
DROP TABLE tenant_key_grants;
DROP TABLE tenant_archive_keys;
ALTER TABLE tenants DROP COLUMN current_epoch;

-- ---------------------------------------------------------------------------
-- Accounts
--
-- An address identifies a person across the whole installation, so signing in
-- needs an email and a password and nothing else. The previous shape scoped
-- addresses to a tenant, which would have meant asking somebody which company
-- they belong to before letting them type a password.
-- ---------------------------------------------------------------------------
ALTER TABLE users DROP CONSTRAINT users_tenant_id_email_key;
ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);

-- The login lookup happens before any tenant is known, so it cannot run under
-- row-level security -- the same reason api_keys carries no policy. Only the
-- routing lives here; everything secret stays in users, behind RLS.
--
-- Maintained by a trigger rather than by application code: two writes that can
-- drift apart is how an account ends up unable to log in to a tenant it plainly
-- belongs to.
CREATE TABLE user_logins (
    email     text PRIMARY KEY,
    user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE OR REPLACE FUNCTION sync_user_login() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO user_logins (email, user_id, tenant_id)
        VALUES (NEW.email, NEW.id, NEW.tenant_id);
    ELSIF TG_OP = 'UPDATE' AND NEW.email IS DISTINCT FROM OLD.email THEN
        UPDATE user_logins SET email = NEW.email WHERE user_id = NEW.id;
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER users_sync_login AFTER INSERT OR UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION sync_user_login();

-- The first account of a tenant has nobody to invite it: bootstrap issues an
-- invite with no creator, which is the only one that can ever exist.
ALTER TABLE invites ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE invites ADD COLUMN email text;

-- Redeeming an invite is what tells the server which tenant the caller is
-- joining, so it happens before any tenant is known and cannot run under
-- row-level security -- the same reason api_keys and sessions carry no policy.
--
-- Nothing here is secret: invite_id is a SHA-256 of the code, and knowing a
-- hash does not permit redemption. Listing a tenant's invites filters by
-- tenant_id explicitly, as it does for api_keys.
DROP POLICY tenant_isolation ON invites;
ALTER TABLE invites NO FORCE ROW LEVEL SECURITY;
ALTER TABLE invites DISABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- Sessions
--
-- A browser session, distinct from an API key: an API key belongs to a program
-- and lives until revoked, a session belongs to a person and expires. Looked up
-- by token before the tenant is known, so no policy here either -- and nothing
-- in it is secret beyond the hash, which is what the column stores.
-- ---------------------------------------------------------------------------
CREATE TABLE sessions (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- sha256 of the token. Fast on purpose: the token is 32 random bytes, so
    -- there is nothing to slow an attacker down for, unlike a password.
    token_hash   bytea       NOT NULL CHECK (length(token_hash) = 32),
    user_agent   text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    UNIQUE (token_hash)
);

CREATE INDEX sessions_by_user ON sessions (user_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- API keys may be narrowed to particular devices
--
-- Defence in depth and nothing more: this is a rule the server applies, so it
-- limits what a program can ask THIS server for. It is not what keeps content
-- unreadable -- that is the key -- and the two should not be confused.
-- An empty list means every device of the tenant.
-- ---------------------------------------------------------------------------
CREATE TABLE api_key_devices (
    api_key_id uuid NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    device_id  uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (api_key_id, device_id)
);

-- ---------------------------------------------------------------------------
-- Row-level security for the new tenant-scoped tables
-- ---------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['device_archive_keys', 'device_key_grants'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$
            CREATE POLICY tenant_isolation ON %I
                USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
        $f$, t);
    END LOOP;
END $$;
