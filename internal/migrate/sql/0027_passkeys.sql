-- Passkeys belong to a global person, independent of workspace membership.
-- Only public authenticator material and a client-encrypted private-key wrap
-- are persisted. PRF outputs and private keys never belong in this schema.
CREATE TABLE user_passkeys (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
    credential jsonb NOT NULL,
    label text NOT NULL CHECK (length(label) BETWEEN 1 AND 80),
    rp_id text NOT NULL,
    prf_salt bytea NOT NULL CHECK (octet_length(prf_salt) = 32),
    wrapped_usk bytea NOT NULL CHECK (octet_length(wrapped_usk) = 61),
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX user_passkeys_by_user ON user_passkeys(user_id) WHERE revoked_at IS NULL;
ALTER TABLE user_passkeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_passkeys FORCE ROW LEVEL SECURITY;
CREATE POLICY own_passkeys ON user_passkeys
    USING (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid)
    WITH CHECK (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

-- Anonymous login challenges need global lookup, like sessions. Each flow is
-- random, short-lived, bound to its origin, and deleted atomically on use.
CREATE TABLE passkey_challenges (
    id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('register', 'login')),
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    session_id uuid REFERENCES sessions(id) ON DELETE CASCADE,
    origin text NOT NULL,
    data jsonb NOT NULL,
    label text NOT NULL DEFAULT '',
    expires_at timestamptz NOT NULL,
    CHECK ((kind = 'register' AND user_id IS NOT NULL AND session_id IS NOT NULL)
        OR (kind = 'login' AND user_id IS NULL AND session_id IS NULL))
);
CREATE INDEX passkey_challenges_expiry ON passkey_challenges(expires_at);

ALTER TABLE sessions ADD COLUMN passkey_id uuid REFERENCES user_passkeys(id);
CREATE INDEX sessions_by_passkey ON sessions(passkey_id) WHERE passkey_id IS NOT NULL AND revoked_at IS NULL;
