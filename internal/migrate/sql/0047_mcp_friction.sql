-- Fewer steps between an assistant and the archive (docs/mcp-enclave.md
-- §19.30): a re-confirmation in place of the password on content consents
-- and renewals, a switch per workspace in place of the operator's lists,
-- reconnects that replace the connection they repeat, a renewal round, and
-- notice e-mails in each person's language.
--
--   sessions.authenticated_at
--                       when the person behind a session last proved
--                       themselves: the sign-in that started its family (a
--                       workspace switch copies it, since selecting a space
--                       proves nothing), or a later step-up with a passkey
--                       or the password. A content consent, a renewal, the
--                       service invitation they write and every grant of a
--                       number's key need it within the last ten minutes, on
--                       the database's clock.
--                       Existing sessions take their family's first sign-in.
--   passkey_challenges  a third kind, 'step_up': a WebAuthn assertion with
--                       user verification for a signed-in session, which
--                       names its account and session like a registration.
--   users.locale        the language the console was last set to by the
--                       person, for the e-mails sent to them: en, pt, es, fr
--                       or de; NULL until the console says, which is English.
--   tenants.mcp_text, mcp_media, mcp_send, mcp_ai
--                       what the workspace's owner lets assistants do in it:
--                       read message text, open attachments, prepare drafts
--                       (and notes to the number's own chat), and run AI
--                       integrations. NULL is the deployment's default
--                       (WS_MCP_WORKSPACE_DEFAULT: on for Wappie Cloud, off
--                       for a self-hosted server). The operator's switches
--                       and deny list still come first, and each rides on the
--                       one before it as the operator's do. tenants carries
--                       no policy (0001), so every workspace's switches are
--                       read in one query.
--   tenants.mcp_switched_at, mcp_switched_by
--                       when, and by whom, the switches were last changed.
--   mcp_connections.replaces
--                       the consent asked to replace the person's earlier
--                       connections of the same client in this workspace:
--                       on activation they are revoked ('replaced').
--   mcp_connections.reseal_mailed_at
--                       when the renewal notice that covered this
--                       connection's last reseal went; the next reseal makes
--                       it due again.
--   revoke_reason       adds 'replaced' (a reconnect took the connection's
--                       place) and 'idle' (unused past its tier's idle time,
--                       when the assistant's refresh token has died too).
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 47, so rolling back below it needs this first). Run only with
-- `wappie-api` stopped, after checking this file against `migration47_sha256`
-- in the release's RELEASE.json, and with the older binary's
-- WS_MCP_CONTENT_TENANTS, WS_MCP_MEDIA_TENANTS, WS_MCP_SEND_TENANTS and
-- WS_AI_TENANTS back in its environment: before 0047 they are what lets a
-- workspace have text, and that binary refuses to start without them while
-- the switches are on. Its data changes touch only mcp_connections,
-- passkey_challenges and schema_migrations, none of them under row-level
-- security; users, which forces it, only loses a column, as sessions and
-- tenants do. So the table owner runs it as it is, outside any workspace's
-- transaction. The connections that ended as replaced or idle keep their
-- status and lose the reason: no older reason fits them. A step-up flow in
-- progress is dropped; the person asks again. It refuses while the ledger
-- holds a version above 47: a later migration's down-step may read what this
-- one drops, so each of those comes down first.
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      DO $$
--      BEGIN
--        IF EXISTS (SELECT 1 FROM schema_migrations WHERE version > 47) THEN
--          RAISE EXCEPTION 'a migration after 0047 is applied; run its down-step first';
--        END IF;
--      END $$;
--      UPDATE mcp_connections SET revoke_reason = NULL WHERE revoke_reason IN ('replaced', 'idle');
--      ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_revoke_reason_check;
--      ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_revoke_reason_check CHECK (revoke_reason IN (
--          'console', 'reader', 'reuse_detected', 'relay_failed', 'pending_expired', 'expired', 'service_removed',
--          'service_disabled', 'member_removed', 'member_disabled', 'access_lost', 'ai_key_deleted'));
--      ALTER TABLE mcp_connections DROP COLUMN replaces, DROP COLUMN reseal_mailed_at;
--      ALTER TABLE tenants DROP COLUMN mcp_text, DROP COLUMN mcp_media, DROP COLUMN mcp_send, DROP COLUMN mcp_ai,
--          DROP COLUMN mcp_switched_at, DROP COLUMN mcp_switched_by;
--      ALTER TABLE users DROP COLUMN locale;
--      DELETE FROM passkey_challenges WHERE kind = 'step_up';
--      ALTER TABLE passkey_challenges DROP CONSTRAINT passkey_challenges_check;
--      ALTER TABLE passkey_challenges ADD CONSTRAINT passkey_challenges_check CHECK (
--          (kind = 'register' AND user_id IS NOT NULL AND session_id IS NOT NULL)
--       OR (kind = 'login' AND user_id IS NULL AND session_id IS NULL));
--      ALTER TABLE passkey_challenges DROP CONSTRAINT passkey_challenges_kind_check;
--      ALTER TABLE passkey_challenges ADD CONSTRAINT passkey_challenges_kind_check CHECK (kind IN ('register', 'login'));
--      ALTER TABLE sessions DROP COLUMN authenticated_at;
--      DELETE FROM schema_migrations WHERE version = 47;
--      COMMIT;
--
-- Every later down-step runs before this one; below 47 the order stands: 0047
-- down, then 0046 down, 0045 down, and so on.

ALTER TABLE sessions ADD COLUMN authenticated_at timestamptz;
UPDATE sessions s SET authenticated_at = f.first
  FROM (SELECT family_id, min(created_at) AS first FROM sessions GROUP BY family_id) f
 WHERE f.family_id = s.family_id;
ALTER TABLE sessions ALTER COLUMN authenticated_at SET DEFAULT now();
ALTER TABLE sessions ALTER COLUMN authenticated_at SET NOT NULL;

ALTER TABLE passkey_challenges DROP CONSTRAINT passkey_challenges_kind_check;
ALTER TABLE passkey_challenges ADD CONSTRAINT passkey_challenges_kind_check CHECK (kind IN ('register', 'login', 'step_up'));
ALTER TABLE passkey_challenges DROP CONSTRAINT passkey_challenges_check;
ALTER TABLE passkey_challenges ADD CONSTRAINT passkey_challenges_check CHECK (
    (kind IN ('register', 'step_up') AND user_id IS NOT NULL AND session_id IS NOT NULL)
 OR (kind = 'login' AND user_id IS NULL AND session_id IS NULL));

ALTER TABLE users ADD COLUMN locale text CHECK (locale IN ('en', 'pt', 'es', 'fr', 'de'));

ALTER TABLE tenants
    ADD COLUMN mcp_text        boolean,
    ADD COLUMN mcp_media       boolean,
    ADD COLUMN mcp_send        boolean,
    ADD COLUMN mcp_ai          boolean,
    ADD COLUMN mcp_switched_at timestamptz,
    ADD COLUMN mcp_switched_by uuid REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE mcp_connections
    ADD COLUMN replaces         boolean NOT NULL DEFAULT false,
    ADD COLUMN reseal_mailed_at timestamptz;
ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_revoke_reason_check;
ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_revoke_reason_check CHECK (revoke_reason IN (
    'console', 'reader', 'reuse_detected', 'relay_failed', 'pending_expired', 'expired', 'service_removed',
    'service_disabled', 'member_removed', 'member_disabled', 'access_lost', 'ai_key_deleted', 'replaced', 'idle'));
