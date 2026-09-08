-- An empty whitelist after deleting its last device must never become "all".
ALTER TABLE api_keys ADD COLUMN devices_restricted boolean NOT NULL DEFAULT false;
ALTER TABLE api_keys ADD COLUMN access_version bigint NOT NULL DEFAULT 1;
UPDATE api_keys k SET devices_restricted=true WHERE EXISTS(SELECT 1 FROM api_key_devices x WHERE x.api_key_id=k.id);
CREATE FUNCTION key_device_access_changed() RETURNS trigger AS $$
BEGIN
 IF TG_OP IN ('DELETE','UPDATE') THEN
  UPDATE api_keys SET devices_restricted=true,access_version=access_version+1 WHERE id=OLD.api_key_id;
 END IF;
 IF TG_OP IN ('INSERT','UPDATE') THEN
  UPDATE api_keys SET devices_restricted=true,access_version=access_version+1 WHERE id=NEW.api_key_id;
  RETURN NEW;
 END IF;
 RETURN OLD;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER key_device_permissions_changed AFTER INSERT OR UPDATE OR DELETE ON api_key_devices
 FOR EACH ROW EXECUTE FUNCTION key_device_access_changed();
