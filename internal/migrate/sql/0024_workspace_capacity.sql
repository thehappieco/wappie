-- Hosting can set a capacity; self-hosted installations remain unlimited.
CREATE TABLE workspace_capacity (
 tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
 max_devices integer CHECK(max_devices >= 0),
 updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE workspace_capacity ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_capacity FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workspace_capacity
 USING (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
CREATE FUNCTION check_device_capacity() RETURNS trigger AS $$
DECLARE capacity integer; used bigint;
BEGIN
 PERFORM 1 FROM tenants WHERE id=NEW.tenant_id FOR UPDATE;
 SELECT max_devices INTO capacity FROM workspace_capacity WHERE tenant_id=NEW.tenant_id;
 IF capacity IS NOT NULL THEN
   SELECT count(*) INTO used FROM devices WHERE tenant_id=NEW.tenant_id;
   IF used >= capacity THEN
     RAISE EXCEPTION 'workspace device capacity reached' USING ERRCODE='P0001', CONSTRAINT='workspace_device_capacity';
   END IF;
 END IF;
 RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER enforce_device_capacity BEFORE INSERT ON devices FOR EACH ROW EXECUTE FUNCTION check_device_capacity();
