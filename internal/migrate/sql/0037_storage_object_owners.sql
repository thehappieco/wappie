-- Physical ciphertext can remain under its existing key when a number moves
-- between workspaces. Logical usage stays tenant-scoped; this internal index
-- only answers whether another workspace still protects the same physical key.
-- It exposes no content and is never returned by an API. Like tenants itself,
-- maintenance must be able to consult this index across workspace boundaries.
CREATE TABLE storage_object_owners (
 object_key text NOT NULL,
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 PRIMARY KEY(object_key,tenant_id)
);
CREATE INDEX storage_object_owners_tenant ON storage_object_owners(tenant_id);

CREATE FUNCTION storage_lock_object(k text) RETURNS void LANGUAGE sql AS $$
 SELECT pg_advisory_xact_lock(hashtextextended('wappie-storage-object:'||k,0));
$$;

CREATE FUNCTION storage_guard_object_owner() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='UPDATE' THEN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.object_key<>OLD.object_key THEN
   RAISE EXCEPTION 'replace storage ownership with an insert and delete, never change its key';
  END IF;
  -- Byte-only changes cannot remove an owner. Avoid collecting physical locks
  -- during reconciliation of existing shared objects in different workspaces.
  RETURN NEW;
 ELSIF TG_OP='DELETE' THEN
  PERFORM storage_lock_object(OLD.object_key);
  RETURN OLD;
 END IF;
 -- The caller already holds the workspace lock. An existing owner cannot be
 -- removed concurrently, so a same-key reservation update needs no new lock.
 IF NOT EXISTS(SELECT 1 FROM storage_objects WHERE tenant_id=NEW.tenant_id AND object_key=NEW.object_key) THEN
  PERFORM storage_lock_object(NEW.object_key);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER storage_owner_guard BEFORE INSERT OR UPDATE OR DELETE ON storage_objects
 FOR EACH ROW EXECUTE FUNCTION storage_guard_object_owner();

CREATE FUNCTION storage_mirror_object_owner() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='DELETE' THEN
  DELETE FROM storage_object_owners WHERE object_key=OLD.object_key AND tenant_id=OLD.tenant_id;
 ELSE
  INSERT INTO storage_object_owners(object_key,tenant_id) VALUES(NEW.object_key,NEW.tenant_id) ON CONFLICT DO NOTHING;
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER storage_owner_mirror AFTER INSERT OR DELETE ON storage_objects
 FOR EACH ROW EXECUTE FUNCTION storage_mirror_object_owner();

-- Populate every tenant explicitly, preserving FORCE RLS on the logical
-- ledger. The migration transaction and trigger DDL exclude concurrent writers.
DO $$ DECLARE t uuid; prior_scope text; BEGIN
 prior_scope:=current_setting('app.tenant_id',true);
 FOR t IN SELECT id FROM tenants LOOP
  PERFORM set_config('app.tenant_id',t::text,true);
  INSERT INTO storage_object_owners(object_key,tenant_id) SELECT object_key,tenant_id FROM storage_objects WHERE tenant_id=t;
 END LOOP;
 PERFORM set_config('app.tenant_id',coalesce(prior_scope,''),true);
END $$;
