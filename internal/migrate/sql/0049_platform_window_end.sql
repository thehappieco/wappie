-- The end of the rollback window: step 6 of the sign-in through an identity
-- provider (docs/platform-sign-in.md, "The rollback window"). The owner
-- brought it forward on 2026-10-12, ahead of D4's fourteen days after the
-- cutover: no real customers, and the old passwords are not to be kept.
--
-- A legacy account linked to the provider (0048) kept what it signed in with
-- before the link, so that with the provider switched off it could sign in
-- with its old password again. Every account that signs in through the
-- provider (one with a platform_identities row) loses all of it here:
--
--   users.auth_hash, users.kdf_salt, users.kdf_params
--                            the old password's verifier, and the salt and
--                            parameters the browser derived it with
--   users.wrapped_usk        the account key under the old password (the
--                            legacy password wrap)
--   users.recovery_wrap, users.recovery_hash
--                            the account key under the recovery code, and
--                            the code's verifier
--   user_passkeys            its Wappie passkeys, each with an envelope of
--                            the account key: revoked by the link, deleted
--                            here, and so are its passkey_challenges (a
--                            registration or a step-up in progress)
--   sessions                 every live session that did not come through
--                            the provider ends: a password, a recovery code
--                            or a passkey started it (or a workspace switch
--                            from one), and none of them opens the account
--                            any more. No session names a deleted passkey
--                            (sessions.passkey_id has no ON DELETE).
--
-- users_credentials_by_source (0048) already allows a platform person with
-- none of the password columns. An account created through the provider has
-- none of them, no passkey and no session a legacy credential started, so no
-- row of it changes. A service account and an unlinked password account have
-- no link and are not touched. The account key itself stays: users.public_key
-- is unchanged, and platform_wraps holds the key under the provider's, which
-- is how every linked account opens it from now on.
--
-- Data only: no table, column, constraint, index, policy or trigger changes.
-- users and user_passkeys force row-level security and a migration has no
-- workspace, so their policies are lifted for the statements below and put
-- back in this same transaction, as 0021 does; sessions, passkey_challenges
-- and platform_identities carry none. Each statement selects only what is
-- still there, so a replay on a database where this already ran changes
-- nothing. An account linked after it, which needs WS_LOCAL_LOGIN on or
-- link_only, keeps its legacy credentials as 0048 left them.
--
-- Down-step (data-only migration: the schema is 48's, so the ledger row is
-- all there is, and once it is gone `migrate.Run` in a binary that knows 48
-- but not 49 starts again). Run only with `wappie-api` stopped, after
-- checking this file against `migration49_sha256` in the release's
-- RELEASE.json, as the table owner or a superuser:
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      DELETE FROM schema_migrations WHERE version = 49;
--      COMMIT;
--
-- What this migration nulled and deleted does not come back: no down-step
-- restores a password, a recovery code, a passkey or an ended session. Under
-- the older binary a linked account still signs in through the provider only,
-- as one created there does, and with the provider switched off
-- (WS_PLATFORM_ISSUER unset) it cannot sign in at all. 0048's down-step, which
-- comes after this one, refuses while any account that signs in through the
-- provider exists, linked or created there, since none of them has a password
-- to fall back to (its message names those created there only).
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
ALTER TABLE user_passkeys DISABLE ROW LEVEL SECURITY;

UPDATE sessions
   SET revoked_at = coalesce(revoked_at, now()), passkey_id = NULL
 WHERE user_id IN (SELECT user_id FROM platform_identities)
   AND (passkey_id IS NOT NULL OR (NOT via_provider AND revoked_at IS NULL));

DELETE FROM passkey_challenges WHERE user_id IN (SELECT user_id FROM platform_identities);

DELETE FROM user_passkeys WHERE user_id IN (SELECT user_id FROM platform_identities);

UPDATE users
   SET auth_hash = NULL, kdf_salt = NULL, kdf_params = NULL, wrapped_usk = NULL,
       recovery_wrap = NULL, recovery_hash = NULL
 WHERE id IN (SELECT user_id FROM platform_identities)
   AND (auth_hash IS NOT NULL OR kdf_salt IS NOT NULL OR kdf_params IS NOT NULL
        OR wrapped_usk IS NOT NULL OR recovery_wrap IS NOT NULL OR recovery_hash IS NOT NULL);

ALTER TABLE user_passkeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_passkeys FORCE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
