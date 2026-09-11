-- Existing spaces keep their IDs, numbers, encryption grants and subscriptions.
ALTER TABLE users ADD COLUMN name text NOT NULL DEFAULT '' CHECK (length(name) <= 80);
ALTER TABLE users ADD COLUMN avatar text NOT NULL DEFAULT '' CHECK (octet_length(avatar) <= 44000);
ALTER TABLE tenants ADD COLUMN kind text NOT NULL DEFAULT 'team' CHECK (kind IN ('personal','team'));
ALTER TABLE tenants ADD COLUMN personal_owner_id uuid UNIQUE REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE tenants ADD CONSTRAINT personal_workspace_owner CHECK ((kind='personal') = (personal_owner_id IS NOT NULL));

-- A manager must still see a disabled member's profile in the directory.
-- Authentication and device access independently require active membership.
DROP POLICY workspace_identity_read ON users;
CREATE POLICY workspace_identity_read ON users FOR SELECT USING (
 EXISTS(SELECT 1 FROM workspace_memberships m WHERE m.user_id=users.id
 AND m.tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
);

ALTER TABLE users DISABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_memberships DISABLE ROW LEVEL SECURITY;
WITH personal AS (
 INSERT INTO tenants(name,kind,personal_owner_id)
 SELECT left(coalesce(nullif(name,''),split_part(email,'@',1)),80),'personal',id FROM users WHERE role <> 'service'
 RETURNING id,personal_owner_id
)
INSERT INTO workspace_memberships(tenant_id,user_id,role)
SELECT id,personal_owner_id,'owner' FROM personal;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE workspace_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_memberships FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION create_initial_membership() RETURNS trigger AS $$
DECLARE personal uuid; previous_context text;
BEGIN
 previous_context := current_setting('app.tenant_id',true);
 IF EXISTS(SELECT 1 FROM tenants WHERE id=NEW.tenant_id) THEN
  INSERT INTO workspace_memberships(tenant_id,user_id,role) VALUES(NEW.tenant_id,NEW.id,NEW.role);
 END IF;
 IF NEW.role <> 'service' THEN
  personal := CASE WHEN EXISTS(SELECT 1 FROM tenants WHERE id=NEW.tenant_id) THEN uuidv7() ELSE NEW.tenant_id END;
  INSERT INTO tenants(id,name,kind,personal_owner_id)
  VALUES(personal,left(coalesce(nullif(NEW.name,''),split_part(NEW.email,'@',1)),80),'personal',NEW.id);
  PERFORM set_config('app.tenant_id',personal::text,true);
  INSERT INTO workspace_memberships(tenant_id,user_id,role) VALUES(personal,NEW.id,'owner');
  PERFORM set_config('app.tenant_id',coalesce(previous_context,''),true);
 END IF;
 RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE FUNCTION personal_membership_guard() RETURNS trigger AS $$
DECLARE owner_id uuid;
BEGIN
 SELECT personal_owner_id INTO owner_id FROM tenants WHERE id=NEW.tenant_id;
 IF owner_id IS NOT NULL AND NEW.role <> 'service' AND
    (NEW.user_id <> owner_id OR NEW.role <> 'owner' OR NEW.status <> 'active') THEN
  RAISE EXCEPTION 'personal workspace permits only its owner and service identities' USING ERRCODE='P0001', CONSTRAINT='personal_workspace_membership';
 END IF;
 RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER protect_personal_membership BEFORE INSERT OR UPDATE ON workspace_memberships FOR EACH ROW EXECUTE FUNCTION personal_membership_guard();

ALTER TABLE invites ADD COLUMN id uuid NOT NULL DEFAULT uuidv7() UNIQUE;
ALTER TABLE invites ADD COLUMN revoked_at timestamptz;
ALTER TABLE invites ADD COLUMN secret_ciphertext bytea;
CREATE TABLE email_signup_verifications (
 token_hash bytea PRIMARY KEY CHECK(length(token_hash)=32),
 email text NOT NULL,
 expires_at timestamptz NOT NULL,
 completed_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX signup_verifications_expiry ON email_signup_verifications(expires_at);
CREATE INDEX signup_verifications_email_time ON email_signup_verifications(email,created_at DESC);
