CREATE TABLE device_permissions (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    can_read boolean NOT NULL DEFAULT false,
    can_send boolean NOT NULL DEFAULT false,
    can_manage boolean NOT NULL DEFAULT false,
    PRIMARY KEY(tenant_id,device_id,user_id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES workspace_memberships(tenant_id,user_id) ON DELETE CASCADE
);
ALTER TABLE device_key_grants DISABLE ROW LEVEL SECURITY;
INSERT INTO device_permissions(tenant_id,device_id,user_id,can_read,can_send)
SELECT DISTINCT tenant_id,device_id,user_id,true,true FROM device_key_grants;
ALTER TABLE device_key_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_key_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE device_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_permissions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_permissions
 USING (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);

CREATE FUNCTION permission_access_changed() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        UPDATE workspace_memberships SET access_version=access_version+1 WHERE tenant_id=OLD.tenant_id AND user_id=OLD.user_id;
        RETURN OLD;
    END IF;
    UPDATE workspace_memberships SET access_version=access_version+1 WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER permissions_changed AFTER UPDATE OR DELETE ON device_permissions
 FOR EACH ROW EXECUTE FUNCTION permission_access_changed();

-- A newly granted archive remains usable by existing clients. Explicit
-- permissions subsequently override these defaults; grants cannot restore a
-- deliberately disabled action through an upsert.
CREATE FUNCTION initial_device_permissions() RETURNS trigger AS $$
BEGIN
    INSERT INTO device_permissions(tenant_id,device_id,user_id,can_read,can_send)
    VALUES(NEW.tenant_id,NEW.device_id,NEW.user_id,true,true) ON CONFLICT DO NOTHING;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER grant_initial_permissions AFTER INSERT ON device_key_grants
 FOR EACH ROW EXECUTE FUNCTION initial_device_permissions();
