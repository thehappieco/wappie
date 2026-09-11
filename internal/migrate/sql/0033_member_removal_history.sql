-- Attribution survives removing a membership without retaining access to the
-- former member's global profile or keeping a disabled membership in the UI.
CREATE TABLE workspace_member_history (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email text NOT NULL,
    removed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant_id,user_id)
);
ALTER TABLE workspace_member_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_member_history FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workspace_member_history
    USING (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
