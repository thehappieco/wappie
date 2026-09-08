-- A person without an active workspace can recover their account and redeem
-- an invitation. A NULL workspace carries no device or membership authority.
ALTER TABLE sessions ALTER COLUMN tenant_id DROP NOT NULL;
