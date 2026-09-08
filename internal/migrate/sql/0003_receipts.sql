-- Receipts: who acknowledged what, and when.
--
-- Phase 3 is the edit and delete history, and the question that makes it worth
-- having is "who saw which version". Answering it needs the acknowledgements
-- stored, so this migration adds them.
--
-- Note the direction of the privacy trade. This server never *sends* a read
-- receipt unless something explicitly asks -- that is what incognito means here
-- -- but receipts arriving from the other side are ordinary inbound traffic and
-- are not suppressed by staying quiet. So the feature works in passive mode,
-- which is the only mode that matters for this product.
--
-- A receipt is routing metadata, not content: it names a party, a message id
-- and a time, and carries nothing to seal. It is therefore readable in a
-- database dump, exactly like the rest of the routing columns. docs/decisions
-- lists that under the honest limits rather than pretending otherwise.

CREATE TABLE receipts (
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id   uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,

    -- The tenant cursor, shared with messages. One sequence per receipt
    -- *event*, not per row: WhatsApp acknowledges many message ids in a single
    -- stanza, and splitting that into one sequence each would take the tenant
    -- row lock once per id -- two hundred times for one message in a two
    -- hundred person group.
    seq         bigint      NOT NULL,

    chat_key    text        NOT NULL,
    -- The message acknowledged, by WhatsApp's id. An edit is a message with an
    -- id of its own, so a receipt naming an edit's id is direct evidence that
    -- that specific version reached the reader -- which is what lets the
    -- projection distinguish inference from proof.
    --
    -- Deliberately not a foreign key to messages.uid. A receipt can arrive
    -- before its message does, or for a message this archive will never store,
    -- and a reference that has to be reconciled later is a second source of
    -- truth that can go stale. (device_id, chat_key, wa_id) is already the
    -- unique key of messages, so the join needs nothing more.
    wa_id       text        NOT NULL,

    -- Who acknowledged. In a group this is each participant in turn; in a
    -- direct chat it is the peer. When is_from_me is set it is one of our own
    -- other devices telling us we read something elsewhere.
    reader_key  text        NOT NULL,
    reader_lid  text,
    reader_pn   text,
    is_from_me  boolean     NOT NULL DEFAULT false,

    kind        text        NOT NULL CHECK (kind IN ('delivered','read','played','retry','error')),
    ts          timestamptz NOT NULL,

    created_at  timestamptz NOT NULL DEFAULT now(),

    -- Idempotency, and the natural access path. WhatsApp resends receipts on
    -- resync, and the same acknowledgement twice is one fact.
    PRIMARY KEY (device_id, chat_key, wa_id, reader_key, kind)
);

-- Replay: everything after a cursor, for one tenant.
CREATE INDEX receipts_by_seq ON receipts (tenant_id, seq);


ALTER TABLE receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON receipts
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
