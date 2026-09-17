-- Rule 1: canonical field-name/scalar encoding, using UTF-8 JSON lengths
-- for names and scalar values, and actual byte lengths for binary fields. Raw message ciphertext is the
-- source of truth: body/payload and media projections are excluded when raw
-- exists. Without raw, the sealed body/payload and attachment fields are the
-- canonical source. Chat list/unread/journal/index/session infrastructure is
-- excluded. Unique object keys count actual ciphertext bytes exactly once.
ALTER TABLE tenants ADD COLUMN storage_limit_bytes bigint CHECK(storage_limit_bytes > 0),
 ADD COLUMN storage_archive_bytes bigint NOT NULL DEFAULT 0 CHECK(storage_archive_bytes >= 0),
 ADD COLUMN storage_object_bytes bigint NOT NULL DEFAULT 0 CHECK(storage_object_bytes >= 0),
 ADD COLUMN storage_over_since timestamptz,
 ADD COLUMN storage_paused_at timestamptz,
 ADD COLUMN storage_rule_version integer NOT NULL DEFAULT 1 CHECK(storage_rule_version = 1);

CREATE TABLE storage_inventory (
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 source text NOT NULL,
 identity text NOT NULL,
 bytes bigint NOT NULL CHECK(bytes >= 0),
 PRIMARY KEY(tenant_id,source,identity)
);
-- Objects survive loss of their last reference until deletion is confirmed.
-- A pending object is charged before upload; retrying its key is idempotent.
CREATE TABLE storage_objects (
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 object_key text NOT NULL,
 bytes bigint NOT NULL CHECK(bytes >= 0),
 PRIMARY KEY(tenant_id,object_key)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['storage_inventory','storage_objects'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = NULLIF(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;

CREATE FUNCTION storage_record_v1(kind text, r jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN
 r := r - ARRAY['created_at','updated_at','seq','counts_unread'];
 IF kind='messages' THEN
  r := r - ARRAY['target_uid','target_rel','audience_count'];
  IF coalesce(r->>'raw_sealed','') NOT IN ('','\x') THEN
   r := r - ARRAY['body_sealed','payload_sealed'];
  END IF;
 ELSIF kind='chats' THEN
  r := r - ARRAY['last_seq','last_ts','last_kind','last_type','unread','read_through_seq','participant_count','archived','pinned','muted_until'];
 ELSIF kind='media' THEN
  r := r - ARRAY['object_key','object_size','download_status','download_error','downloaded_at','next_attempt_at','claimed_at','attempts','direct_path','url'];
 END IF;
 RETURN jsonb_strip_nulls(r);
END $$;

-- A canonical record is a sequence of named fields. Binary values count their
-- actual bytes, never hexadecimal expansion or duplicate TOAST/index storage.
CREATE FUNCTION storage_record_bytes_v1(r jsonb) RETURNS bigint
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE k text; v jsonb; total bigint:=0; scalar text;
BEGIN
 IF r IS NULL THEN RETURN 0; END IF;
 FOR k,v IN SELECT * FROM jsonb_each(r) LOOP
  total:=total+octet_length(k);
  scalar:=v#>>'{}';
  IF k LIKE '%\_sealed' ESCAPE '\' OR k IN ('file_sha256','file_enc_sha256','waveform','sidecar') THEN
   IF left(scalar,2)='\x' THEN total:=total+octet_length(decode(substr(scalar,3),'hex'));
   ELSE total:=total+octet_length(v::text); END IF;
  ELSE total:=total+octet_length(v::text); END IF;
 END LOOP;
 RETURN total;
END $$;

CREATE FUNCTION storage_delta(t uuid, archive_delta bigint, object_delta bigint) RETURNS void
LANGUAGE plpgsql AS $$ DECLARE p tenants%ROWTYPE; total numeric; BEGIN
 IF current_setting('app.storage_reconcile',true)='true' THEN RETURN; END IF;
 SELECT * INTO p FROM tenants WHERE id=t FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF; -- parent tenant cascade
 total := p.storage_archive_bytes::numeric+p.storage_object_bytes+archive_delta+object_delta;
 IF archive_delta+object_delta > 0 AND
  (p.storage_paused_at IS NOT NULL OR (p.storage_limit_bytes IS NOT NULL AND
    ((p.storage_over_since IS NOT NULL AND p.storage_over_since+interval '72 hours'<=clock_timestamp())
     OR total > p.storage_limit_bytes::numeric*1.05))) THEN
  RAISE EXCEPTION 'workspace storage is paused' USING ERRCODE='WS001';
 END IF;
 UPDATE tenants SET storage_archive_bytes=storage_archive_bytes+archive_delta,
  storage_object_bytes=storage_object_bytes+object_delta,
  storage_over_since=CASE WHEN storage_limit_bytes IS NOT NULL AND total>=storage_limit_bytes
   THEN coalesce(storage_over_since,clock_timestamp()) ELSE NULL END,
  storage_paused_at=CASE WHEN storage_limit_bytes IS NOT NULL AND (total>=storage_limit_bytes::numeric*1.05 OR storage_over_since+interval '72 hours'<=clock_timestamp())
   THEN coalesce(storage_paused_at,clock_timestamp()) ELSE storage_paused_at END
 WHERE id=t;
END $$;

CREATE FUNCTION storage_account_record() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r jsonb; k text; t uuid; n bigint:=0; prev bigint:=0; canonical jsonb;
BEGIN
 IF TG_OP='DELETE' THEN r:=to_jsonb(OLD); ELSE r:=to_jsonb(NEW); END IF;
 t:=(r->>'tenant_id')::uuid;
 -- Lock before reading the inventory so concurrent deltas cannot lose updates.
 PERFORM 1 FROM tenants WHERE id=t FOR UPDATE;
 SELECT jsonb_agg(r->col ORDER BY ord)::text INTO k
 FROM unnest(TG_ARGV) WITH ORDINALITY AS a(col,ord);
 SELECT bytes INTO prev FROM storage_inventory WHERE tenant_id=t AND source=TG_TABLE_NAME AND identity=k;
 prev:=coalesce(prev,0);
 IF TG_OP<>'DELETE' THEN
  canonical:=storage_record_v1(TG_TABLE_NAME,r);
  IF TG_TABLE_NAME='media' AND EXISTS(SELECT 1 FROM messages WHERE uid=(r->>'message_uid')::uuid AND octet_length(raw_sealed)>0) THEN canonical:=NULL; END IF;
  n:=storage_record_bytes_v1(canonical);
 END IF;
 PERFORM storage_delta(t,n-prev,0);
 IF TG_OP='DELETE' THEN
  DELETE FROM storage_inventory WHERE tenant_id=t AND source=TG_TABLE_NAME AND identity=k;
 ELSE
  INSERT INTO storage_inventory VALUES(t,TG_TABLE_NAME,k,n)
  ON CONFLICT(tenant_id,source,identity) DO UPDATE SET bytes=excluded.bytes;
 END IF;
 IF TG_TABLE_NAME='messages' AND TG_OP='UPDATE' THEN
  UPDATE media SET tenant_id=tenant_id WHERE message_uid=(r->>'uid')::uuid;
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER storage_account AFTER INSERT OR UPDATE OR DELETE ON messages FOR EACH ROW EXECUTE FUNCTION storage_account_record('uid');
CREATE TRIGGER storage_account AFTER INSERT OR UPDATE OR DELETE ON chats FOR EACH ROW EXECUTE FUNCTION storage_account_record('device_id','chat_key');
CREATE TRIGGER storage_account AFTER INSERT OR UPDATE OR DELETE ON media FOR EACH ROW EXECUTE FUNCTION storage_account_record('message_uid');
CREATE TRIGGER storage_account AFTER INSERT OR UPDATE OR DELETE ON receipts FOR EACH ROW EXECUTE FUNCTION storage_account_record('device_id','chat_key','wa_id','reader_key','kind');
CREATE TRIGGER storage_account AFTER INSERT OR UPDATE OR DELETE ON contacts FOR EACH ROW EXECUTE FUNCTION storage_account_record('device_id','contact_key');
CREATE TRIGGER storage_account AFTER INSERT OR UPDATE OR DELETE ON group_participants FOR EACH ROW EXECUTE FUNCTION storage_account_record('device_id','chat_key','participant_key');
CREATE TRIGGER storage_account AFTER INSERT OR UPDATE OR DELETE ON group_changes FOR EACH ROW EXECUTE FUNCTION storage_account_record('id');

CREATE FUNCTION storage_account_object() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='INSERT' THEN PERFORM storage_delta(NEW.tenant_id,0,NEW.bytes);
 ELSIF TG_OP='DELETE' THEN PERFORM storage_delta(OLD.tenant_id,0,-OLD.bytes);
 ELSE PERFORM storage_delta(NEW.tenant_id,0,NEW.bytes-OLD.bytes); END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER storage_account AFTER INSERT OR UPDATE OR DELETE ON storage_objects FOR EACH ROW EXECUTE FUNCTION storage_account_object();
CREATE FUNCTION storage_media_object() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.object_key IS NOT NULL THEN
  INSERT INTO storage_objects VALUES(NEW.tenant_id,NEW.object_key,coalesce(NEW.object_size,0))
  ON CONFLICT(tenant_id,object_key) DO UPDATE SET bytes=greatest(storage_objects.bytes,excluded.bytes);
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER storage_object AFTER INSERT OR UPDATE ON media FOR EACH ROW EXECUTE FUNCTION storage_media_object();

-- Scope each tenant explicitly, respecting FORCE RLS. Updates populate the
-- versioned inventory; defaults are unlimited, so existing archives survive.
DO $$ DECLARE t uuid; tab text; BEGIN
 FOR t IN SELECT id FROM tenants LOOP
 PERFORM set_config('app.tenant_id',t::text,true);
 FOREACH tab IN ARRAY ARRAY['messages','chats','media','receipts','contacts','group_participants','group_changes'] LOOP
 EXECUTE format('UPDATE %I SET tenant_id=tenant_id WHERE tenant_id=$1',tab) USING t;
 END LOOP;
 END LOOP;
END $$;

CREATE TABLE storage_history (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 reason text NOT NULL,
 used_bytes bigint NOT NULL,
 limit_bytes bigint,
 warning_percent integer NOT NULL
);
ALTER TABLE storage_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE storage_history FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON storage_history USING (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
CREATE INDEX storage_history_tenant ON storage_history(tenant_id,id DESC);
CREATE FUNCTION storage_policy_history() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prev integer:=0; warn integer:=0; n integer; why text; prior_scope text;
BEGIN
 FOREACH n IN ARRAY ARRAY[80,90,100] LOOP
  IF OLD.storage_limit_bytes IS NOT NULL AND OLD.storage_archive_bytes::numeric+OLD.storage_object_bytes>=OLD.storage_limit_bytes::numeric*n/100 THEN prev:=n; END IF;
  IF NEW.storage_limit_bytes IS NOT NULL AND NEW.storage_archive_bytes::numeric+NEW.storage_object_bytes>=NEW.storage_limit_bytes::numeric*n/100 THEN warn:=n; END IF;
 END LOOP;
 IF NEW.storage_limit_bytes IS DISTINCT FROM OLD.storage_limit_bytes THEN why:='limit_changed';
 ELSIF NEW.storage_paused_at IS DISTINCT FROM OLD.storage_paused_at THEN
  IF NEW.storage_paused_at IS NULL THEN why:='resumed'; ELSE why:='paused'; END IF;
 ELSIF warn<>prev THEN why:='warning_changed'; END IF;
 IF why IS NOT NULL THEN
  -- Tenant policy updates are global maintenance, so establish this event's
  -- scope locally and restore the previous scope before returning.
  prior_scope:=current_setting('app.tenant_id',true);
  PERFORM set_config('app.tenant_id',NEW.id::text,true);
  INSERT INTO storage_history(tenant_id,reason,used_bytes,limit_bytes,warning_percent)
   VALUES(NEW.id,why,NEW.storage_archive_bytes+NEW.storage_object_bytes,NEW.storage_limit_bytes,warn);
  PERFORM set_config('app.tenant_id',coalesce(prior_scope,''),true);
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER storage_policy_history AFTER UPDATE OF storage_limit_bytes,storage_archive_bytes,storage_object_bytes,storage_paused_at ON tenants FOR EACH ROW EXECUTE FUNCTION storage_policy_history();

-- Acquire the workspace lock before PostgreSQL takes any archive row locks.
-- AFTER row triggers alone invert the lock order against message sequence
-- allocation and can deadlock concurrent chat/read-marker updates.
CREATE FUNCTION storage_lock_workspace() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 PERFORM 1 FROM tenants WHERE id=NULLIF(current_setting('app.tenant_id',true),'')::uuid FOR UPDATE;
 RETURN NULL;
END $$;
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['messages','chats','media','receipts','contacts','group_participants','group_changes','storage_objects'] LOOP
  EXECUTE format('CREATE TRIGGER storage_lock BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH STATEMENT EXECUTE FUNCTION storage_lock_workspace()',tab);
 END LOOP;
END $$;
