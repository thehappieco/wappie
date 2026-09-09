-- One browser login can issue immutable tokens for several workspaces.
-- Existing sessions each start their own family; no account or tenant is
-- merged, and another browser's independently proven login remains separate.
ALTER TABLE sessions ADD COLUMN family_id uuid NOT NULL DEFAULT uuidv7();
CREATE INDEX sessions_by_family ON sessions(user_id, family_id) WHERE revoked_at IS NULL;
