-- Storage ownership may change; the cryptographic namespace must never change.
-- This UUID is deliberately not a tenant FK: deleting an old Team must not
-- delete or invalidate an archive now owned by Personal.
ALTER TABLE devices ADD COLUMN archive_tenant_id uuid;
ALTER TABLE devices DISABLE ROW LEVEL SECURITY;
UPDATE devices SET archive_tenant_id=tenant_id;
ALTER TABLE devices ALTER COLUMN archive_tenant_id SET NOT NULL;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;
CREATE FUNCTION device_archive_namespace() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='INSERT' THEN NEW.archive_tenant_id:=NEW.tenant_id;
 ELSIF NEW.archive_tenant_id IS DISTINCT FROM OLD.archive_tenant_id THEN
  RAISE EXCEPTION 'archive namespace is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER device_archive_namespace BEFORE INSERT OR UPDATE ON devices FOR EACH ROW EXECUTE FUNCTION device_archive_namespace();

-- Like app.tenant_id, these transaction-local scopes are set by trusted server
-- code only, after checking the live owner, destination and workspace locks.
-- Neither setting is exposed to clients. They permit one atomic ownership move
-- under FORCE RLS without copying ciphertext through application memory.
CREATE FUNCTION device_move_scope(t uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NULLIF(current_setting('app.device_move_id',true),'') IS NOT NULL AND
 t IN (NULLIF(current_setting('app.device_move_source',true),'')::uuid,
       NULLIF(current_setting('app.device_move_target',true),'')::uuid)
$$;
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['devices','device_archive_keys','device_key_grants','content_keys','chats','messages','media','events','receipts','contacts','group_participants','group_changes','device_permissions','reader_preferences','storage_inventory','storage_objects'] LOOP
  EXECUTE format('CREATE POLICY device_move ON %I USING(device_move_scope(tenant_id)) WITH CHECK(device_move_scope(tenant_id))',tab);
 END LOOP;
END $$;

-- Stale workers from a previous workspace cannot recreate rows after a move.
-- The regular workspace scope still supplies all read/write authorization.
-- The archive tables covered by storage accounting already take this lock.
-- Extend the same workspace-before-row order to keys, access and the journal.
-- A row ownership check alone can read the old committed owner while a move
-- is in flight, then insert an obsolete-tenant row after the move has scanned
-- the table. FK locks occur too late to prevent that schedule.
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['device_archive_keys','device_key_grants','content_keys','device_permissions','reader_preferences','events'] LOOP
  EXECUTE format('CREATE TRIGGER archive_owner_lock BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH STATEMENT EXECUTE FUNCTION storage_lock_workspace()',tab);
 END LOOP;
END $$;
CREATE FUNCTION archive_device_owner() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d uuid; t uuid; BEGIN
 IF device_move_scope(NEW.tenant_id) THEN RETURN NEW; END IF;
 IF TG_TABLE_NAME='media' THEN
  SELECT device_id INTO d FROM messages WHERE uid=NEW.message_uid;
 ELSE d:=NEW.device_id; END IF;
 SELECT tenant_id INTO t FROM devices WHERE id=d;
 IF t IS NULL OR t<>NEW.tenant_id THEN
  RAISE EXCEPTION 'device no longer belongs to this workspace' USING ERRCODE='WS002';
 END IF;
 RETURN NEW;
END $$;
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['device_archive_keys','device_key_grants','content_keys','chats','messages','media','events','receipts','contacts','group_participants','group_changes','device_permissions','reader_preferences'] LOOP
  EXECUTE format('CREATE TRIGGER archive_device_owner BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION archive_device_owner()',tab);
 END LOOP;
END $$;

CREATE FUNCTION workspace_device_usage(t uuid) RETURNS bigint LANGUAGE sql STABLE AS $$
 SELECT count(*) FROM devices WHERE tenant_id=t
$$;
CREATE TRIGGER enforce_moved_device_capacity BEFORE UPDATE OF tenant_id ON devices
 FOR EACH ROW WHEN (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id) EXECUTE FUNCTION check_device_capacity();

CREATE TABLE device_transfers (
 device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 source_workspace_id uuid NOT NULL,
 target_workspace_id uuid NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(device_id,target_workspace_id)
);
ALTER TABLE device_transfers ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_transfers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_transfers USING (
 NULLIF(current_setting('app.tenant_id',true),'')::uuid IN (source_workspace_id,target_workspace_id)
) WITH CHECK (NULLIF(current_setting('app.tenant_id',true),'')::uuid=source_workspace_id);
