-- Small, normalized raster avatars belong to the workspace, never to a
-- member's personal identity or encrypted message history.
ALTER TABLE tenants ADD COLUMN avatar text NOT NULL DEFAULT ''
    CHECK (octet_length(avatar) <= 44000);
