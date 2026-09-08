-- Who is in a group, and who did what to it.
--
-- Two tables because they answer two different questions and one of them cannot
-- be derived from the other. Participants is the composition NOW; changes is
-- what happened, in order, with a time and an author. "Who removed Fulano" is
-- only answerable from the second, and only from the moment this archive
-- started listening — WhatsApp does not deliver a group's past, and no
-- arrangement here can recover it. The UI says so plainly rather than
-- presenting an empty history as a peaceful one.
--
-- JIDs are readable, and that is a deliberate continuation rather than a new
-- exposure. A participant is routing in exactly the sense sender_key and
-- reader_key already are: a database dump already reveals who spoke in which
-- group. The NAMES stay sealed, in contacts, where they were.
--
-- The alternative — sealing the whole membership as one blob per chat — was
-- considered and rejected: the server could then not count participants, so
-- the tick denominator would have to be reassembled in every client, and a
-- claim as consequential as "everyone read this" would rest on arithmetic
-- nobody could check server-side.

CREATE TABLE group_participants (
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id  uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    chat_key   text NOT NULL,

    -- Identity is the (lid, pn) pair with LID primary, as everywhere else.
    -- Either half may be absent and neither is ever rewritten.
    participant_key text NOT NULL,
    participant_lid text,
    participant_pn  text,

    is_admin       boolean NOT NULL DEFAULT false,
    is_super_admin boolean NOT NULL DEFAULT false,

    -- When this archive first saw them in the group, and when it saw them
    -- leave. Not when they joined: that is a fact about the group's past, and
    -- claiming to know it would be inventing one.
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    left_at       timestamptz,

    PRIMARY KEY (device_id, chat_key, participant_key)
);

CREATE INDEX group_participants_by_chat ON group_participants (device_id, chat_key)
    WHERE left_at IS NULL;
CREATE INDEX group_participants_by_tenant ON group_participants (tenant_id);

-- The history. Append only: a membership change is something that happened, and
-- the whole reason for the table is that WhatsApp does not keep it.
CREATE TABLE group_changes (
    id         bigserial PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id  uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    chat_key   text NOT NULL,

    ts timestamptz NOT NULL,

    -- Who made the change. Absent for a snapshot, and absent when WhatsApp
    -- does not say — which it often does not for an invite link. Left null
    -- rather than guessed.
    actor_key text,
    actor_lid text,
    actor_pn  text,

    action text NOT NULL CHECK (action IN (
        'snapshot', 'add', 'remove', 'promote', 'demote',
        'name', 'topic', 'ephemeral', 'announce', 'locked')),

    -- Who it was done to, for the membership actions.
    subject_key text,
    subject_lid text,
    subject_pn  text,

    -- What it was changed to, for the settings actions. Readable for the same
    -- reason the action is: it is the shape of the change, not its content.
    -- A group's NAME is not stored here — that is content and lives sealed on
    -- the chat row.
    detail text,

    created_at timestamptz NOT NULL DEFAULT now()
);

-- The panel's query: one group's history, newest first.
CREATE INDEX group_changes_by_chat ON group_changes (device_id, chat_key, ts DESC);
CREATE INDEX group_changes_by_tenant ON group_changes (tenant_id);

-- Idempotency for the event path. WhatsApp redelivers app-state and group
-- events on every resync, and the same removal recorded twice reads as two
-- removals of one person — which, in a table whose entire purpose is to say
-- what happened, is worse than not recording it at all.
CREATE UNIQUE INDEX group_changes_once ON group_changes
    (device_id, chat_key, ts, action, coalesce(subject_key, ''), coalesce(actor_key, ''));

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['group_participants', 'group_changes'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$
            CREATE POLICY tenant_isolation ON %I
                USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
        $f$, t);
    END LOOP;
END $$;
