-- A person's reading preference is independent of a number's shared WhatsApp
-- transport policy. Existing users start discreet without changing bot/API intent.
CREATE TABLE reader_preferences (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    receipt_mode text NOT NULL DEFAULT 'passive' CHECK (receipt_mode IN ('passive','active')),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant_id,user_id,device_id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES workspace_memberships(tenant_id,user_id) ON DELETE CASCADE
);
ALTER TABLE reader_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE reader_preferences FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON reader_preferences
    USING (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
