DO $$
DECLARE tenant uuid;
BEGIN
 FOR tenant IN SELECT id FROM tenants WHERE name IN ('Piloto A','Piloto B') LOOP
  PERFORM set_config('app.tenant_id',tenant::text,true);
  INSERT INTO workspace_capacity(tenant_id,max_devices) VALUES(tenant,2) ON CONFLICT DO NOTHING;
 END LOOP;
END $$;
