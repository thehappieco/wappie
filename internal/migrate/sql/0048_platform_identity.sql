-- Sign-in through an external identity provider (docs/platform-sign-in.md).
--
-- An installation configured with WS_PLATFORM_ISSUER lets people sign in with
-- an account at that provider (The Happie Co's id. for the hosted cloud). The
-- provider delivers a per-product key, sk_p, to the person's page; Wappie's
-- own account key (the X25519 key every grant is sealed to) stays what it is
-- and is wrapped once more under a key derived from sk_p. Nothing here opens
-- anything: the server keeps the pins, the links and the opaque wraps. With
-- the issuer unset, the self-hosted default, nothing writes to these tables
-- and every account is 'local' as before.
--
--   users.auth_source        'local' (a password account, or a service), or
--                            'platform': an account that signs in through
--                            the provider. A linked account keeps its legacy
--                            password columns during the rollback window;
--                            an account created through the provider has
--                            none of them.
--   platform_key_pins        the first product key seen for each
--                            (sub, product_key_id), insert only: a later
--                            sign-in that presents another key for the same
--                            pair is refused as account_key_changed and the
--                            pin is kept. No foreign key: the pin outlives
--                            the account.
--   platform_identities      the link sub <-> users.id, one row each way,
--                            insert only except the provider's e-mail and when
--                            it changed. linked_from is 'new' for an account
--                            created through the provider (users.id = sub)
--                            or 'legacy' for an existing account linked by
--                            the browser ceremony (users.id is kept).
--   platform_wraps           the account key under a key derived from sk_p,
--                            61 bytes, version byte 1, one per account and
--                            product key epoch, insert only.
--   platform_login_tickets   what a sign-in that has no session yet may do
--                            next: create the account ('new'), link a legacy
--                            one ('new' or 'link'), or store the wrap for a
--                            new epoch ('rewrap'). Single use, five minutes,
--                            stored as the SHA-256 of 32 random bytes, bound
--                            to the sub and the pinned key; at most five
--                            failed link attempts.
--   security_events          refusals and links worth an operator's eye. No
--                            token, key or address is ever stored here.
--   sessions.step_up_*       a recent re-authentication at the provider, for
--                            the step-ups of a later release; unused here.
--
-- None of the new tables carries row-level security: each is read before a
-- workspace is known, as sessions and user_logins are, and none holds a
-- secret (the ticket is stored hashed, the wraps open only with sk_p).
--
-- users_service_has_no_password (0020) becomes users_credentials_by_source:
-- a service has no password, a local person has all of it, and a platform
-- person has either all of it (a linked account in its rollback window) or
-- none of it.
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 48, so rolling back below it needs this first). Run only with
-- `wappie-api` stopped and WS_PLATFORM_ISSUER unset, after checking this file
-- against `migration48_sha256` in the release's RELEASE.json, as the table
-- owner or a superuser. It refuses while any account created through the
-- provider exists (one with no password to fall back to): delete those
-- accounts explicitly first. A linked account becomes a local one again and
-- signs in with its old password; its passkeys and sessions, revoked at the
-- link, stay revoked. The pins go with their table, so a later 0048 trusts
-- the provider's key again at each account's next first sign-in.
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      ALTER TABLE users DISABLE ROW LEVEL SECURITY;
--      DO $$
--      BEGIN
--        IF EXISTS (SELECT 1 FROM users WHERE auth_source = 'platform' AND auth_hash IS NULL) THEN
--          RAISE EXCEPTION 'accounts created through the identity provider exist; delete them before this down-step';
--        END IF;
--      END $$;
--      UPDATE users SET auth_source = 'local' WHERE auth_source = 'platform';
--      ALTER TABLE users ENABLE ROW LEVEL SECURITY;
--      ALTER TABLE users FORCE ROW LEVEL SECURITY;
--      DROP TABLE platform_login_tickets;
--      DROP TABLE platform_wraps;
--      DROP TABLE platform_identities;
--      DROP TABLE platform_key_pins;
--      DROP TABLE security_events;
--      DROP FUNCTION platform_insert_only();
--      DROP FUNCTION platform_identity_guard();
--      ALTER TABLE sessions DROP COLUMN step_up_at, DROP COLUMN step_up_not_before;
--      ALTER TABLE users DROP CONSTRAINT users_credentials_by_source;
--      ALTER TABLE users ADD CONSTRAINT users_service_has_no_password CHECK (
--          (role = 'service' AND auth_hash IS NULL AND wrapped_usk IS NULL)
--          OR (role <> 'service' AND auth_hash IS NOT NULL AND kdf_salt IS NOT NULL
--              AND kdf_params IS NOT NULL AND wrapped_usk IS NOT NULL));
--      ALTER TABLE users DROP COLUMN auth_source;
--      DELETE FROM schema_migrations WHERE version = 48;
--      COMMIT;
--
-- It runs first: 0048 down, then 0047 down (the fewer steps), 0046 down, and
-- so on.
ALTER TABLE users ADD COLUMN auth_source text NOT NULL DEFAULT 'local'
    CHECK (auth_source IN ('local', 'platform'));
ALTER TABLE users DROP CONSTRAINT users_service_has_no_password;
ALTER TABLE users ADD CONSTRAINT users_credentials_by_source CHECK (
    (role = 'service' AND auth_source = 'local' AND auth_hash IS NULL AND wrapped_usk IS NULL)
 OR (role <> 'service' AND auth_source = 'local' AND auth_hash IS NOT NULL AND kdf_salt IS NOT NULL
     AND kdf_params IS NOT NULL AND wrapped_usk IS NOT NULL)
 OR (role <> 'service' AND auth_source = 'platform' AND auth_hash IS NOT NULL AND kdf_salt IS NOT NULL
     AND kdf_params IS NOT NULL AND wrapped_usk IS NOT NULL)
 OR (role <> 'service' AND auth_source = 'platform' AND auth_hash IS NULL AND kdf_salt IS NULL
     AND kdf_params IS NULL AND wrapped_usk IS NULL AND recovery_wrap IS NULL AND recovery_hash IS NULL)
);

CREATE TABLE platform_key_pins (
    sub            uuid        NOT NULL,
    product_key_id text        NOT NULL CHECK (product_key_id ~ '^[a-z][a-z0-9-]{0,31}:[1-9][0-9]{0,9}$'),
    product_key    bytea       NOT NULL CHECK (octet_length(product_key) = 32),
    pinned_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (sub, product_key_id)
);

CREATE TABLE platform_identities (
    sub              uuid        PRIMARY KEY,
    user_id          uuid        NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    email            text        NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    linked_from      text        NOT NULL CHECK (linked_from IN ('new', 'legacy')),
    linked_at        timestamptz NOT NULL DEFAULT now(),
    email_changed_at timestamptz
);

CREATE TABLE platform_wraps (
    user_id        uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_key_id text        NOT NULL CHECK (product_key_id ~ '^[a-z][a-z0-9-]{0,31}:[1-9][0-9]{0,9}$'),
    wrap           bytea       NOT NULL CHECK (octet_length(wrap) = 61 AND get_byte(wrap, 0) = 1),
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, product_key_id)
);

CREATE TABLE platform_login_tickets (
    ticket_hash    bytea       PRIMARY KEY CHECK (octet_length(ticket_hash) = 32),
    kind           text        NOT NULL CHECK (kind IN ('new', 'link', 'rewrap')),
    sub            uuid        NOT NULL,
    product_key_id text        NOT NULL,
    product_key    bytea       NOT NULL CHECK (octet_length(product_key) = 32),
    email          text        NOT NULL,
    name           text        NOT NULL DEFAULT '' CHECK (length(name) <= 80),
    -- The linked account a 'rewrap' ticket is for; NULL for the others.
    user_id        uuid        REFERENCES users(id) ON DELETE CASCADE,
    attempts       int         NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    CHECK ((kind = 'rewrap') = (user_id IS NOT NULL))
);
CREATE INDEX platform_login_tickets_expiry ON platform_login_tickets (expires_at);

CREATE TABLE security_events (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    kind       text        NOT NULL CHECK (kind IN ('platform_account_key_changed', 'platform_linked')),
    user_id    uuid,
    sub        uuid,
    detail     jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(detail) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX security_events_by_time ON security_events (created_at);

ALTER TABLE sessions ADD COLUMN step_up_at timestamptz, ADD COLUMN step_up_not_before timestamptz;

-- Insert only. A row of these tables is never changed or removed by the
-- application; a removal is let through only when it cascades from an
-- account's deletion (a trigger nested in the foreign key's).
CREATE FUNCTION platform_insert_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 AND TG_TABLE_NAME = 'platform_wraps' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% is insert-only', TG_TABLE_NAME USING ERRCODE = 'P0001';
END $$ LANGUAGE plpgsql;
CREATE TRIGGER platform_key_pins_insert_only BEFORE UPDATE OR DELETE ON platform_key_pins
    FOR EACH ROW EXECUTE FUNCTION platform_insert_only();
CREATE TRIGGER platform_wraps_insert_only BEFORE UPDATE OR DELETE ON platform_wraps
    FOR EACH ROW EXECUTE FUNCTION platform_insert_only();
CREATE TRIGGER security_events_insert_only BEFORE UPDATE OR DELETE ON security_events
    FOR EACH ROW EXECUTE FUNCTION platform_insert_only();

-- The link: sub, user_id and how and when it was made never change; the
-- provider's current e-mail may.
CREATE FUNCTION platform_identity_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF pg_trigger_depth() > 1 THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'platform_identities is insert-only' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.sub <> OLD.sub OR NEW.user_id <> OLD.user_id OR NEW.linked_from <> OLD.linked_from
       OR NEW.linked_at <> OLD.linked_at THEN
        RAISE EXCEPTION 'a platform link never changes' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER platform_identities_guard BEFORE UPDATE OR DELETE ON platform_identities
    FOR EACH ROW EXECUTE FUNCTION platform_identity_guard();
