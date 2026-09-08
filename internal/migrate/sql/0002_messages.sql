-- Messages, chats, media and the event journal.
--
-- The shape here follows one decision: edits, deletions and reactions are rows,
-- not columns. A schema that overwrote the text on edit, or set a deleted flag,
-- would destroy exactly the information this product exists to show.

-- ---------------------------------------------------------------------------
-- Sequence
--
-- Cursors are a monotonic per-tenant counter, not a timestamp. Timestamps tie,
-- and they come from the sender's clock: two messages in the same second are
-- unorderable, and a phone with a wrong clock reorders history. The counter is
-- allocated on insert with UPDATE ... RETURNING, which serialises per tenant --
-- which is what monotonicity requires anyway.
--
-- It is per tenant rather than global so gaps do not leak system-wide volume to
-- a client reading its own stream.
-- ---------------------------------------------------------------------------
ALTER TABLE tenants ADD COLUMN last_seq bigint NOT NULL DEFAULT 0;

-- ---------------------------------------------------------------------------
-- Chats
--
-- Identity is (lid, pn) with either half possibly absent, so chat_key holds
-- whichever is primary and the two columns beside it hold what is known. The v1
-- server keyed on a phone number it rewrote LIDs into; that is no longer
-- possible, since LID exists precisely to withhold the number.
--
-- The last_* columns are a projection maintained on write. v1 computed the same
-- thing with a triple join and two aggregate subqueries on every sidebar load,
-- with no covering index -- O(n) over the whole message table, every time.
-- ---------------------------------------------------------------------------
CREATE TABLE chats (
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id   uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    chat_key    text        NOT NULL,
    chat_lid    text,
    chat_pn     text,
    is_group    boolean     NOT NULL DEFAULT false,

    -- Display name. Sealed: for a direct chat it is a person's name, which is
    -- content, not routing. Null until a name is learned.
    name_sealed bytea,
    name_key_id integer,

    -- Disappearing-message timer currently set on the chat, in seconds.
    ephemeral_expiration integer NOT NULL DEFAULT 0,

    -- Projection of the newest message, for ordering the chat list.
    last_seq    bigint      NOT NULL DEFAULT 0,
    last_ts     timestamptz,
    last_kind   text,
    last_type   text,

    unread      integer     NOT NULL DEFAULT 0 CHECK (unread >= 0),
    archived    boolean     NOT NULL DEFAULT false,
    pinned      boolean     NOT NULL DEFAULT false,
    muted_until timestamptz,

    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, chat_key)
);

-- The sidebar query: most recent chats for one device. Covering, so it is an
-- index-only scan.
CREATE INDEX chats_recent ON chats (device_id, last_seq DESC)
    INCLUDE (chat_key, last_ts, last_type, unread)
    WHERE NOT archived;

CREATE INDEX chats_by_tenant ON chats (tenant_id);

-- ---------------------------------------------------------------------------
-- Messages
--
-- One row per event: a message, an edit, a deletion, a reaction. Control rows
-- carry target_wa_id, and target_uid once resolved.
-- ---------------------------------------------------------------------------
CREATE TABLE messages (
    uid         uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id   uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,

    -- The cursor. Assigned on insert, strictly increasing per tenant.
    seq         bigint      NOT NULL,

    -- WhatsApp's own id, unique within a chat.
    wa_id       text        NOT NULL,

    chat_key    text        NOT NULL,
    sender_key  text,
    sender_lid  text,
    sender_pn   text,

    -- When the sender says it was sent. Display only; ordering uses seq.
    ts          timestamptz,
    is_from_me  boolean     NOT NULL DEFAULT false,
    is_group    boolean     NOT NULL DEFAULT false,

    kind        text        NOT NULL CHECK (kind IN ('message','edit','delete','reaction')),
    type        text        NOT NULL,

    -- What a control row acts on. target_rel is resolved during ingest, once:
    -- removing a reaction produces a delete whose target is the reaction, not
    -- the message, and a reader that cannot tell the difference renders a
    -- deleted message where a withdrawn reaction belongs. v1 recomputed this at
    -- render time, in two places that disagreed.
    target_wa_id text,
    target_uid   uuid,
    target_rel   text CHECK (target_rel IS NULL OR target_rel IN ('message','reaction')),

    reply_to    text,

    is_forwarded     boolean NOT NULL DEFAULT false,
    forwarding_score integer NOT NULL DEFAULT 0,

    -- Disappearing messages are kept, not deleted. expires_at records when the
    -- sender intended it to vanish so a reader can be told plainly that it was
    -- meant to be ephemeral -- rather than the archive quietly presenting it as
    -- an ordinary message.
    expiration  integer     NOT NULL DEFAULT 0,
    -- Computed on insert rather than as a generated column: timestamptz plus
    -- interval is only STABLE, not IMMUTABLE, because it depends on the
    -- session time zone, and Postgres refuses it in a generated expression.
    -- Doing the arithmetic in Go keeps it explicit and avoids a UTC assumption
    -- baked invisibly into the schema.
    expires_at  timestamptz,
    view_once   boolean     NOT NULL DEFAULT false,
    ephemeral   boolean     NOT NULL DEFAULT false,

    source      text        NOT NULL CHECK (source IN ('live','history','outbox')),

    -- Sealed content. content_key_id names the key all of this row's sealed
    -- values share, so a reader unwraps one key per row rather than one per
    -- field.
    content_key_id integer,
    body_sealed    bytea,
    raw_sealed     bytea,

    created_at  timestamptz NOT NULL DEFAULT now(),

    -- Idempotency. History sync redelivers messages already seen, and an
    -- at-least-once event stream will too.
    UNIQUE (device_id, chat_key, wa_id)
);

-- Paging a conversation: newest first within one chat.
CREATE INDEX messages_by_chat ON messages (device_id, chat_key, seq DESC);

-- Resume: everything after a cursor, for one tenant.
CREATE INDEX messages_by_seq ON messages (tenant_id, seq);

-- Resolving a control row's target, and finding every control row that acts on
-- a given message.
CREATE INDEX messages_by_target ON messages (device_id, chat_key, target_wa_id)
    WHERE target_wa_id IS NOT NULL;

CREATE INDEX messages_by_uid_target ON messages (target_uid) WHERE target_uid IS NOT NULL;

-- Sweeping messages whose intended expiry has passed, for the UI marker.
CREATE INDEX messages_expiring ON messages (tenant_id, expires_at)
    WHERE expires_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Media
--
-- The blob itself lives in object storage, still in WhatsApp's own encrypted
-- form. Only media_key needs sealing: without it the stored ciphertext is
-- noise. The v1 server stored the blob encrypted and then wrote the key in the
-- clear in the column beside it, which defeated the entire scheme.
-- ---------------------------------------------------------------------------
CREATE TABLE media (
    message_uid   uuid        PRIMARY KEY REFERENCES messages(uid) ON DELETE CASCADE,
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Readable: a client has to know what an attachment is before deciding to
    -- fetch it, and these describe the container rather than the content.
    media_type    text        NOT NULL,
    mimetype      text        NOT NULL DEFAULT '',
    file_length   bigint      NOT NULL DEFAULT 0,
    -- Hashes of ciphertext. They reveal nothing about the plaintext and are
    -- what makes storage content-addressed.
    file_sha256     bytea,
    file_enc_sha256 bytea,
    -- Capability URLs on WhatsApp's CDN. Useless without the key.
    direct_path   text,
    url           text,

    width         integer,
    height        integer,
    seconds       integer,
    -- The amplitude sketch drawn behind a voice note. Readable: it is 64 bytes
    -- of envelope shape, needed to draw the placeholder before the audio is
    -- fetched, and it carries no speech.
    waveform      bytea,
    -- Per-chunk MACs for streaming video.
    sidecar       bytea,
    is_gif        boolean     NOT NULL DEFAULT false,

    -- Sealed. The file name is content, not metadata: "acordo-divorcio.pdf"
    -- says more than most message bodies.
    content_key_id  integer,
    media_key_sealed bytea,
    thumb_sealed     bytea,
    filename_sealed  bytea,

    download_status text NOT NULL DEFAULT 'pending'
        CHECK (download_status IN ('pending','downloading','done','failed','gone')),
    download_error  text NOT NULL DEFAULT '',
    object_key      text,
    downloaded_at   timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX media_pending ON media (tenant_id, created_at)
    WHERE download_status IN ('pending','failed');

-- Content addressing: the same blob arriving twice is fetched once.
CREATE INDEX media_by_content ON media (file_enc_sha256) WHERE file_enc_sha256 IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Event journal
--
-- Deliberately thin: sequence, kind, and which message it concerns. It does not
-- duplicate the sealed payload.
--
-- The alternative -- materialising a rendered body here -- was v1's approach to
-- avoiding work at replay time, and it produced two renderers that drifted
-- apart. Replay instead joins back to messages and runs the same single
-- renderer the live path runs, so there is nothing to diverge.
-- ---------------------------------------------------------------------------
CREATE TABLE events (
    seq         bigint      NOT NULL,
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id   uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind        text        NOT NULL,
    chat_key    text,
    message_uid uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, seq)
);

CREATE INDEX events_replay ON events (tenant_id, seq) INCLUDE (device_id, kind, message_uid);

-- ---------------------------------------------------------------------------
-- Row level security
-- ---------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['chats', 'messages', 'media', 'events'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$
            CREATE POLICY tenant_isolation ON %I
                USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
        $f$, t);
    END LOOP;
END $$;

CREATE TRIGGER chats_touch BEFORE UPDATE ON chats
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
