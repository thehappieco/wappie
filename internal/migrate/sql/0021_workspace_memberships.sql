-- Memberships carry workspace roles; users keep their existing identity and
-- key material. No user IDs, grants, passwords or archive keys are replaced.
CREATE TABLE workspace_memberships (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'service')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX workspace_memberships_by_user ON workspace_memberships(user_id);

-- The legacy tenant_id now routes credential storage only. Deleting the
-- original workspace must not delete a person's identity, other memberships
-- or grants in other spaces. Keep the UUID for existing RLS/login routing.
ALTER TABLE users DROP CONSTRAINT users_tenant_id_fkey;
ALTER TABLE user_logins DROP CONSTRAINT user_logins_tenant_id_fkey;

-- Migrations have no tenant context; explicitly lift RLS while copying all
-- existing memberships, then restore it in this same transaction.
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
INSERT INTO workspace_memberships (tenant_id, user_id, role, created_at)
SELECT tenant_id, id, role, created_at FROM users;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

ALTER TABLE workspace_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workspace_memberships
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
-- Identity context is used only to discover the authenticated user's spaces.
CREATE POLICY own_memberships ON workspace_memberships FOR SELECT
    USING (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

CREATE FUNCTION create_initial_membership() RETURNS trigger AS $$
BEGIN
    INSERT INTO workspace_memberships (tenant_id, user_id, role)
    VALUES (NEW.tenant_id, NEW.id, NEW.role);
    RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER users_initial_membership AFTER INSERT ON users
    FOR EACH ROW EXECUTE FUNCTION create_initial_membership();

-- A workspace may read its members' public identity/key envelopes. Identity
-- writes retain the original tenant policy; joining is not permission to
-- change another person's credentials.
CREATE POLICY workspace_identity_read ON users FOR SELECT USING (
    EXISTS (SELECT 1 FROM workspace_memberships m
            WHERE m.user_id = users.id
              AND m.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
              AND m.status = 'active')
);
