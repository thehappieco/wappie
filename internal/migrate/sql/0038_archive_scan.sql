-- Device-wide archive reads use the same effective timestamp and sequence
-- tie-break as chat pages, without requiring a chat key prefix.
CREATE INDEX messages_by_device_time
    ON messages (device_id, (coalesce(ts, created_at)) DESC, seq DESC);
