ALTER TABLE workspace_memberships ADD COLUMN access_version bigint NOT NULL DEFAULT 1;

CREATE FUNCTION bump_membership_access() RETURNS trigger AS $$
BEGIN
    NEW.access_version := OLD.access_version + 1;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER membership_access_changed BEFORE UPDATE ON workspace_memberships
    FOR EACH ROW EXECUTE FUNCTION bump_membership_access();

-- Existing sockets must forget cached grants when any grant is removed.
CREATE FUNCTION invalidate_grant_access() RETURNS trigger AS $$
BEGIN
    UPDATE workspace_memberships SET access_version = access_version + 1
    WHERE tenant_id = OLD.tenant_id AND user_id = OLD.user_id;
    RETURN OLD;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER grant_access_removed AFTER DELETE ON device_key_grants
    FOR EACH ROW EXECUTE FUNCTION invalidate_grant_access();

-- Directory lookups include disabled memberships so administrators can restore
-- them. Authentication still explicitly requires an active membership.
DROP POLICY workspace_identity_read ON users;
CREATE POLICY workspace_identity_read ON users FOR SELECT USING (
    EXISTS (SELECT 1 FROM workspace_memberships m
            WHERE m.user_id = users.id
              AND m.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
);
