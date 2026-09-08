-- Contacts: who the identifiers belong to.
--
-- Until now a conversation with anyone whose chat carried no name showed as a
-- phone number, because nothing on the live path carries one and the history
-- sync only names groups. Names for people arrive from three other places --
-- the push name a contact sets for themselves, the name in the address book
-- synced through app state, and a business profile -- and none had anywhere to
-- land.
--
-- Every name here is sealed. A name is content by the same definition that
-- seals a message body: an attacker with a database dump learns who the
-- identifiers are, which is most of what a social graph is for.
CREATE TABLE contacts (
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id   uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,

    -- Identity is the (lid, pn) pair, as everywhere else: either half may be
    -- absent, and LID exists precisely so a phone number never has to appear.
    contact_key text        NOT NULL,
    contact_lid text,
    contact_pn  text,
    is_group    boolean     NOT NULL DEFAULT false,

    -- Derived, so a sealed value has something to bind to and both sides can
    -- compute it without a round trip. See store.ContactUID.
    uid         uuid        NOT NULL,

    content_key_id       integer,
    -- What the contact calls themselves. Arrives with any message they send.
    push_name_sealed     bytea,
    -- What this account saved them as, from the address book. Absent for
    -- anyone not in it, which is most of a busy WhatsApp.
    full_name_sealed     bytea,
    business_name_sealed bytea,

    -- Profile picture.
    --
    -- WhatsApp serves these over plain HTTP, unencrypted -- unlike message
    -- media, where the CDN hands over ciphertext this server stores verbatim
    -- and cannot read. There is no ciphertext to preserve here, so the bytes
    -- are sealed on the way in like a message body. A face is content.
    --
    -- Stored in the row rather than in object storage: a profile picture is
    -- tens of kilobytes, and a second blob path for something that small would
    -- be machinery with nothing to buy.
    avatar_id         text,
    avatar_sealed     bytea,
    avatar_key_id     integer,
    avatar_checked_at timestamptz,

    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, contact_key)
);

CREATE INDEX contacts_by_tenant ON contacts (tenant_id);

-- The avatar worker's queue: contacts never checked, oldest first.
CREATE INDEX contacts_avatar_pending ON contacts (device_id, avatar_checked_at NULLS FIRST);

ALTER TABLE contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE contacts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contacts
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE TRIGGER contacts_touch BEFORE UPDATE ON contacts
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
