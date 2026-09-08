-- 0020: accounts for systems.
--
-- A third party that needs to read the archive used to get the device key
-- as text, by hand, from whoever had it — the one thing the grant scheme
-- exists to avoid. A service account is an account with a keypair and no
-- password: the system keeps the private half, the owner grants it devices
-- from the console exactly as for a person, and an API key that acts as the
-- account carries its grants. Revoking is revoking the grant.
--
-- No password means no auth hash, no salt, no wrapped key. Those columns
-- become nullable, with a check that ties "null" to "service" so a person
-- can never end up without them.
ALTER TABLE users DROP CONSTRAINT users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check
    CHECK (role IN ('owner', 'admin', 'member', 'service'));
ALTER TABLE users ALTER COLUMN auth_hash DROP NOT NULL;
ALTER TABLE users ALTER COLUMN kdf_salt DROP NOT NULL;
ALTER TABLE users ALTER COLUMN kdf_params DROP NOT NULL;
ALTER TABLE users ALTER COLUMN wrapped_usk DROP NOT NULL;
ALTER TABLE users ADD CONSTRAINT users_service_has_no_password CHECK (
    (role = 'service' AND auth_hash IS NULL AND wrapped_usk IS NULL)
    OR (role <> 'service' AND auth_hash IS NOT NULL AND kdf_salt IS NOT NULL
        AND kdf_params IS NOT NULL AND wrapped_usk IS NOT NULL)
);

ALTER TABLE invites DROP CONSTRAINT invites_role_check;
ALTER TABLE invites ADD CONSTRAINT invites_role_check
    CHECK (role IN ('owner', 'admin', 'member', 'service'));

-- The account a key acts as. Null is a key with no account: reach without
-- any grant, the way every key was before.
ALTER TABLE api_keys ADD COLUMN acts_as uuid REFERENCES users(id) ON DELETE CASCADE;
