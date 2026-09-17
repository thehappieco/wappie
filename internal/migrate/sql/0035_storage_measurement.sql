-- Existing archives need an explicit baseline before a hosted quota is enabled.
ALTER TABLE tenants ADD COLUMN storage_reconciled_at timestamptz;
ALTER TABLE tenants ALTER COLUMN storage_reconciled_at SET DEFAULT clock_timestamp();

CREATE TABLE storage_samples (
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 sampled_at timestamptz NOT NULL,
 -- Bucket uniqueness and actual observation time are separate: rounding the
 -- observation itself can claim 24 hours of history after only 23 hours.
 measured_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 used_bytes bigint NOT NULL CHECK(used_bytes>=0),
 PRIMARY KEY(tenant_id,sampled_at)
);
ALTER TABLE storage_samples ENABLE ROW LEVEL SECURITY;
ALTER TABLE storage_samples FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON storage_samples USING (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
