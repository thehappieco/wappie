-- The platform contract's settings part on Wappie's side (step 12a,
-- decisions DS1 to DS17): the settings mode, the command feed's cursor and
-- ledger, the sections' and the persons' seqs and due times, what a numbers
-- row shows of a number (why it logged out, when and by whom it was paused),
-- and the triggers that wake the settings sender. Nothing here calls the
-- platform, and nothing changes how Wappie behaves until an operator turns
-- settings to read (contract_settings_state.mode). All of 12a's schema is
-- here, its commands' included, so its later releases migrate nothing.
--
--   contract_settings_state  one row: the mode ('off' until an operator
--                       switches it; read follows the feed and answers every
--                       command kind_not_accepted; on runs the kinds this
--                       binary knows), the command feed's cursor under
--                       contract_state.generation (one generation for every
--                       feed), when the feed was first and last read, the
--                       feed's and the results' failures, the last
--                       invalid_command answered, and label_cutover_at,
--                       this migration's time: a notice's label stored
--                       before it is kept only when today's label rule gives
--                       the same. Apart from contract_state, so a take never
--                       waits behind the account side.
--   contract_commands   the ledger: every command taken, keyed by its id,
--                       kept exactly 30 days from taken_at (decision 0056),
--                       with its body as received (bytea: its mac is the
--                       app's proof), the sha256 of its canonical form
--                       without generation, cseq, secret and mac, the
--                       carrying answer's signed time, the columns decoded
--                       once ValidateIn passed (NULL on a row refused before
--                       that), the executor's retries, the result (written
--                       in the act's transaction) and its delivery.
--                       take_seq is the executor's order.
--   contract_command_wseq   the highest wseq each producer finished in each
--                       workspace in the current generation, and the command
--                       that set it; a reset deletes every row.
--   contract_workspaces.sections_seq   the sections' and the acts' half of
--                       the workspace's one clock; snapshot_seq is the
--                       snapshot's. Each takes the greatest of the clock in
--                       milliseconds and both columns plus one.
--   contract_sections   per recorded workspace and section, the last
--                       state_seq given, and the sender's due time,
--                       backoff, not_found run and park, as the snapshot's.
--                       A recorded workspace gets its numbers row at once
--                       (contract_sections_named).
--   contract_persons    per followed sub, the person's clock (seq), the
--                       last seq given to a document (sent_seq), the
--                       sender's due time and backoff, and the latest
--                       issued_at of a person.sign_out_everywhere that ran.
--                       A followed sub gets its row at once
--                       (contract_persons_followed); the trim deletes a row
--                       whose sub is no longer followed.
--   devices.logout_cause    phone or deletion, set by devices_logout_cause
--                       from the reason when a number moves into
--                       logged_out, and kept while it stays there; NULL on
--                       any other status. Rows logged out before 0052 are
--                       classed by their reason alone.
--   devices.paused_at, paused_by_kind, paused_by_user, unpaused_at
--                       when the current pause began and who made it (the
--                       app for a move's or a deletion's; a person or a
--                       legacy key's creator from its event, through
--                       devices_paused_by_event, or from the console's
--                       stop), and when the number was last unpaused. A
--                       second stop with the same cause keeps the first
--                       pause's. NULL while not known. Paused rows are
--                       filled from what this migration finds.
--   contract_settings_mark and its triggers
--                       wappie_contract_settings carries a workspace's id
--                       when something its numbers section shows changes,
--                       'c:' and the id for a connection that only flipped
--                       between online and offline (the sender waits 30 s),
--                       'u:' and a user's id for that person's notices, and
--                       'due' when a section or a person is made due sooner,
--                       new, or released from its park.
--   security_events     the kind contract_command_invalid: a command whose
--                       MAC failed, of another app, or an id seen with
--                       another body. It names no person: user_id and sub
--                       are NULL, and detail holds the command's id, cseq
--                       and why.
--   item_events.label   nulled on every row not settled yet: those rows
--                       were written before the label rule this release
--                       sends by; their hints stay.
--
-- None of the new contract_* tables carries row-level security: they are
-- read across workspaces, as contract_state is, and hold no content.
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 52, so rolling back below it needs this first). Run only with
-- `wappie-api` stopped, after `whatserverd contract settings off`, after
-- checking this file against `migration52_sha256` in the release's
-- RELEASE.json, as the table owner. It refuses while settings are not off,
-- and while schema_migrations holds a version above 52; a refusal changes
-- nothing. It loses the ledger (counted, with the commands without a result
-- and the results not delivered), the sections' and persons' state, the
-- sign-out-everywhere times and the invalid-command security events (each
-- counted). The item_events labels it nulled stay NULL; 51 needs none.
-- security_events is insert-only against the application's statements; the
-- owner lifts that trigger for its one delete and puts it back.
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      DO $$
--      BEGIN
--        IF EXISTS (SELECT 1 FROM schema_migrations WHERE version > 52) THEN
--          RAISE EXCEPTION 'a migration after 0052 is applied; run its down-step first';
--        END IF;
--        IF (SELECT mode FROM contract_settings_state) <> 'off' THEN
--          RAISE EXCEPTION 'settings are on: run whatserverd contract settings off first';
--        END IF;
--      END $$;
--      LOCK TABLE tenants, users, workspace_memberships IN ACCESS EXCLUSIVE MODE;
--      DO $$
--      BEGIN
--        RAISE NOTICE 'dropping % ledger rows (% without a result, % results not delivered), % sections, % persons (% signed out everywhere), % invalid-command security events',
--          (SELECT count(*) FROM contract_commands), (SELECT count(*) FROM contract_commands WHERE outcome IS NULL),
--          (SELECT count(*) FROM contract_commands WHERE outcome IS NOT NULL AND delivery IS NULL),
--          (SELECT count(*) FROM contract_sections), (SELECT count(*) FROM contract_persons),
--          (SELECT count(*) FROM contract_persons WHERE signed_out_everywhere_at IS NOT NULL),
--          (SELECT count(*) FROM security_events WHERE kind = 'contract_command_invalid');
--      END $$;
--      ALTER TABLE security_events DISABLE TRIGGER security_events_insert_only;
--      DELETE FROM security_events WHERE kind = 'contract_command_invalid';
--      ALTER TABLE security_events ENABLE TRIGGER security_events_insert_only;
--      ALTER TABLE security_events DROP CONSTRAINT security_events_kind_check,
--          ADD CONSTRAINT security_events_kind_check CHECK (kind IN ('platform_account_key_changed', 'platform_linked', 'platform_home_taken'));
--      DROP TRIGGER contract_settings_notice ON device_notices;
--      DROP FUNCTION contract_settings_mark_notice();
--      DROP TRIGGER contract_settings_tenant ON tenants;
--      DROP FUNCTION contract_settings_mark_tenant();
--      DROP TRIGGER contract_settings_capacity ON workspace_capacity;
--      DROP TRIGGER contract_settings_connection ON devices;
--      DROP FUNCTION contract_settings_mark_connection();
--      DROP TRIGGER contract_settings_device_update ON devices;
--      DROP TRIGGER contract_settings_device ON devices;
--      DROP FUNCTION contract_settings_mark();
--      DROP TRIGGER devices_paused_by_event ON item_events;
--      DROP FUNCTION devices_paused_by_event();
--      ALTER TABLE devices DROP CONSTRAINT devices_paused_by_shape;
--      DROP TRIGGER devices_pause_times ON devices;
--      DROP FUNCTION devices_pause_times();
--      ALTER TABLE devices DROP CONSTRAINT devices_logout_cause_shape;
--      DROP TRIGGER devices_logout_cause ON devices;
--      DROP FUNCTION devices_logout_cause();
--      ALTER TABLE devices DROP COLUMN unpaused_at, DROP COLUMN paused_by_user, DROP COLUMN paused_by_kind,
--          DROP COLUMN paused_at, DROP COLUMN logout_cause;
--      DROP TRIGGER contract_persons_followed ON contract_accounts;
--      DROP FUNCTION contract_persons_followed();
--      DROP TRIGGER contract_sections_named ON contract_workspaces;
--      DROP FUNCTION contract_sections_named();
--      DROP TABLE contract_persons;
--      DROP TABLE contract_sections;
--      DROP FUNCTION contract_settings_due();
--      DROP TABLE contract_command_wseq;
--      DROP TABLE contract_commands;
--      DROP TABLE contract_settings_state;
--      ALTER TABLE contract_workspaces DROP COLUMN sections_seq;
--      DELETE FROM schema_migrations WHERE version = 52;
--      COMMIT;
--
-- It runs first: 0052 down, then 0051 down (whose guard refuses while 52 is
-- applied), then 0050 down, and so on.
--
-- The label cutover holds only if no older binary writes after this
-- migration: apply it with wappie-api stopped. A restore of a backup taken
-- before 0052 runs the item_events cut again when it migrates.

-- wappie-billing keeps running through this migration, as through 0051: its
-- transactions lock the workspace row and the membership (FOR UPDATE OF
-- t,m) first, then count devices. This takes the three tables billing locks
-- in a mode its reads never conflict with, in billing's order, so the ALTERs
-- on devices wait for a billing request that has counted devices and never
-- deadlock with it; nothing later asks for more on them.
LOCK TABLE tenants, users, workspace_memberships IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE contract_settings_state (
    id               boolean     PRIMARY KEY DEFAULT true CHECK (id),
    -- off: nothing runs. read: the sections go with accepts [], the feed is
    -- followed, every command is answered kind_not_accepted. on: the kinds
    -- this binary runs. A binary that does not know a mode reads it as read.
    mode             text        NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'read', 'on')),
    mode_changed_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- The command feed's cursor, under contract_state.generation (one
    -- generation for every feed). The next request's after.
    feed_cursor      bigint      NOT NULL DEFAULT 0 CHECK (feed_cursor >= 0),
    -- The first page committed: the platform watches the feed from then on,
    -- for good. Set once.
    first_read_at    timestamptz,
    read_at          timestamptz,
    feed_error       text,
    feed_error_at    timestamptz,
    results_error    text,
    results_error_at timestamptz,
    -- The last invalid_command answered: the platform alerts for 24 hours.
    invalid_at       timestamptz,
    -- This release's code first runs after this migration: a label stored
    -- before it is kept only when today's rule gives the same.
    label_cutover_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((feed_error IS NULL) = (feed_error_at IS NULL)),
    CHECK ((results_error IS NULL) = (results_error_at IS NULL)),
    CHECK (read_at IS NULL OR first_read_at IS NOT NULL)
);
INSERT INTO contract_settings_state DEFAULT VALUES;

CREATE TABLE contract_commands (
    id              uuid        PRIMARY KEY,
    -- The take order: the executor's order. A restored platform starts cseq
    -- again below the ones taken before, so cseq orders nothing across
    -- generations.
    take_seq        bigint      GENERATED ALWAYS AS IDENTITY,
    -- The kind's producer; a row that could not be read is the leader's
    -- ('wappie'). wappie-cloud's kinds share the ledger later.
    producer        text        NOT NULL DEFAULT 'wappie' CHECK (producer IN ('wappie', 'wappie-cloud')),
    -- The page's generation at take, moved to the current one when the
    -- command is delivered again in it.
    generation      uuid        NOT NULL,
    cseq            bigint      NOT NULL CHECK (cseq >= 1),
    -- What the command decoded, written only once ValidateIn passed. NULL on
    -- every row refused before: its fields may be anything, and one failed
    -- insert would fail the whole page.
    workspace_id    uuid,
    wseq            bigint      CHECK (wseq >= 1),
    kind            text,
    section         text,
    actor           uuid,
    actor_role      text        CHECK (actor_role IN ('owner', 'admin', 'member')),
    -- Built from the decoded, validated ids.
    target          jsonb       CHECK (target IS NULL OR jsonb_typeof(target) = 'object'),
    -- As received: a member Wappie does not know is kept whatever it holds
    -- (jsonb refuses \u0000).
    params          bytea,
    based_on_seq    bigint,
    based_on_docs   jsonb       CHECK (based_on_docs IS NULL OR jsonb_typeof(based_on_docs) = 'object'),
    issued_at       timestamptz,
    first_issued_at timestamptz,
    expires_at      timestamptz,
    retry_of        uuid,
    confirm         text,
    -- The command as received, its mac included: the app's proof. bytea:
    -- text refuses invalid UTF-8 and NUL.
    body            bytea       NOT NULL,
    -- sha256 of its JCS without generation, cseq, secret and mac; of the
    -- raw bytes when it has none.
    body_key        bytea       NOT NULL CHECK (length(body_key) = 32),
    -- The carrying answer's X-Happie-Timestamp: expiry is judged on it.
    signed_at       timestamptz NOT NULL,
    -- 30 days from here, never less and never more (decision 0056).
    taken_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    again           boolean     NOT NULL DEFAULT false,
    -- The executor's retries after a store error that is not a verdict:
    -- the row waits until run_after; after 5 it is answered.
    run_tries       int         NOT NULL DEFAULT 0 CHECK (run_tries >= 0),
    run_after       timestamptz,
    run_error       text,
    -- The result, written in the act's transaction.
    outcome         text        CHECK (outcome IN ('ran', 'refused', 'in_progress')),
    code            text,
    retry_after     int         CHECK (retry_after BETWEEN 1 AND 3600),
    state_seq       bigint      CHECK (state_seq >= 1),
    detail          jsonb       CHECK (detail IS NULL OR jsonb_typeof(detail) = 'object'),
    result_at       timestamptz,
    -- Delivery: accepted, duplicate, rejected (with its code: the
    -- platform's, or local_invalid when Wappie's own check refused it
    -- before a post), or dropped for an old generation's command. A rejected
    -- row is parked; delivered_at is when its delivery settled.
    delivery        text        CHECK (delivery IN ('accepted', 'duplicate', 'rejected', 'dropped')),
    delivered_at    timestamptz,
    reject_code     text        CHECK (reject_code IN ('invalid_request', 'not_found', 'conflict', 'local_invalid')),
    post_tries      int         NOT NULL DEFAULT 0 CHECK (post_tries >= 0),
    post_error      text,
    -- Every term is true or false, never NULL, so no shape slips through as
    -- unknown.
    CHECK ((workspace_id IS NULL) = (wseq IS NULL)),
    -- Decoded all together, or not at all.
    CHECK ((kind IS NULL) = (actor IS NULL) AND (kind IS NULL) = (issued_at IS NULL) AND (kind IS NULL) = (section IS NULL)),
    CHECK (workspace_id IS NULL OR kind IS NOT NULL),
    CHECK (kind IS NOT NULL OR (outcome IS NOT DISTINCT FROM 'refused' AND code IS NOT DISTINCT FROM 'invalid_command')),
    CHECK ((outcome IS NULL) = (result_at IS NULL)),
    CHECK ((outcome IS NOT DISTINCT FROM 'refused') = (code IS NOT NULL)),
    CHECK (delivery IS NULL OR outcome IS NOT NULL),
    CHECK ((delivery IS NULL) = (delivered_at IS NULL)),
    CHECK ((delivery IS NOT DISTINCT FROM 'rejected') = (reject_code IS NOT NULL)),
    CHECK ((run_error IS NULL) = (run_tries = 0))
);
CREATE INDEX contract_commands_open        ON contract_commands (take_seq) WHERE outcome IS NULL OR outcome = 'in_progress';
CREATE INDEX contract_commands_undelivered ON contract_commands (result_at) WHERE outcome IS NOT NULL AND delivery IS NULL;
CREATE INDEX contract_commands_taken       ON contract_commands (taken_at);
-- The executor's hold-back: an earlier open row of the same workspace and
-- producer.
CREATE INDEX contract_commands_order       ON contract_commands (workspace_id, producer, take_seq) WHERE outcome IS NULL;

CREATE TABLE contract_command_wseq (
    workspace_id uuid   NOT NULL,
    producer     text   NOT NULL CHECK (producer IN ('wappie', 'wappie-cloud')),
    generation   uuid   NOT NULL,
    -- The highest wseq this producer finished there in this generation, and
    -- the command that set it.
    wseq         bigint NOT NULL CHECK (wseq >= 1),
    id           uuid   NOT NULL,
    PRIMARY KEY (workspace_id, producer)
);

ALTER TABLE contract_workspaces ADD COLUMN sections_seq bigint NOT NULL DEFAULT 0 CHECK (sections_seq >= 0);

CREATE TABLE contract_sections (
    workspace_id    uuid        NOT NULL REFERENCES contract_workspaces(workspace_id) ON DELETE CASCADE,
    -- Every Wappie section, so a later step needs no migration for its names.
    section         text        NOT NULL CHECK (section IN ('numbers', 'integrations', 'mcp', 'installations')),
    -- The last state_seq given to this section: the outcome's
    -- compare-and-set.
    state_seq       bigint      NOT NULL DEFAULT 0 CHECK (state_seq >= 0),
    ok_at           timestamptz,
    due_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    tries           int         NOT NULL DEFAULT 0 CHECK (tries >= 0),
    error           text,
    not_found_since timestamptz,
    parked_at       timestamptz,
    PRIMARY KEY (workspace_id, section)
);
INSERT INTO contract_sections (workspace_id, section) SELECT workspace_id, 'numbers' FROM contract_workspaces;
-- A workspace recorded after the leader started is due at once. It only
-- inserts, so it waits only on a concurrent insert of the same key.
CREATE FUNCTION contract_sections_named() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO contract_sections (workspace_id, section) VALUES (NEW.workspace_id, 'numbers') ON CONFLICT DO NOTHING;
    RETURN NULL;
END $$;
CREATE TRIGGER contract_sections_named AFTER INSERT ON contract_workspaces
    FOR EACH ROW EXECUTE FUNCTION contract_sections_named();

CREATE TABLE contract_persons (
    sub                      uuid        PRIMARY KEY,
    -- The person's clock: reads and acts take greatest(the clock in
    -- milliseconds, seq + 1) under this row's lock.
    seq                      bigint      NOT NULL DEFAULT 0 CHECK (seq >= 0),
    -- The last seq given to a document: the outcome's compare-and-set.
    sent_seq                 bigint      NOT NULL DEFAULT 0 CHECK (sent_seq >= 0),
    ok_at                    timestamptz,
    due_at                   timestamptz NOT NULL DEFAULT clock_timestamp(),
    tries                    int         NOT NULL DEFAULT 0 CHECK (tries >= 0),
    error                    text,
    not_found_since          timestamptz,
    parked_at                timestamptz,
    -- The latest issued_at of a person.sign_out_everywhere that ran: kept
    -- here because the ledger keeps 30 days only.
    signed_out_everywhere_at timestamptz
);
INSERT INTO contract_persons (sub) SELECT sub FROM contract_accounts;
-- A sub followed at a sign-in after the leader started is due at once. No
-- foreign key: the trim deletes a row whose sub is no longer followed.
CREATE FUNCTION contract_persons_followed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO contract_persons (sub) VALUES (NEW.sub) ON CONFLICT DO NOTHING;
    RETURN NULL;
END $$;
CREATE TRIGGER contract_persons_followed AFTER INSERT ON contract_accounts
    FOR EACH ROW EXECUTE FUNCTION contract_persons_followed();

ALTER TABLE devices
    ADD COLUMN logout_cause   text CHECK (logout_cause IN ('phone', 'deletion')),
    ADD COLUMN paused_at      timestamptz,
    -- Who paused: the app (a move's or a deletion's pause), or a person or
    -- a legacy API key (its creator, paused_by_user). NULL: not known. A
    -- removed account leaves no id behind, as on deleted_by: set NULL,
    -- which fires no pause trigger and keeps the kind.
    ADD COLUMN paused_by_kind text CHECK (paused_by_kind IN ('person', 'key', 'app')),
    ADD COLUMN paused_by_user uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN unpaused_at    timestamptz;

-- Every workspace's numbers, with the tables the backfills read, as 0051
-- reads them; each is opened again after.
ALTER TABLE devices DISABLE ROW LEVEL SECURITY;
ALTER TABLE item_events DISABLE ROW LEVEL SECURITY;
ALTER TABLE device_notices DISABLE ROW LEVEL SECURITY;
ALTER TABLE device_transfers DISABLE ROW LEVEL SECURITY;
ALTER TABLE devices DISABLE TRIGGER devices_touch;
-- Rows logged out before 0052 cannot tell a phone logout followed by a
-- deletion (no session left, so 'no session at deletion') from a
-- deletion's own logout: both read as deletion.
UPDATE devices SET logout_cause = CASE WHEN status_reason IN ('no session at deletion', 'unlinked when deleted')
                                       THEN 'deletion' ELSE 'phone' END
 WHERE status = 'logged_out';
-- A deletion's pause began at the deletion.
UPDATE devices SET paused_at = deleted_at, paused_by_kind = 'app'
 WHERE paused AND pause_cause = 'deletion' AND deleted_at IS NOT NULL;
-- A move's pause began when the move into this workspace completed.
UPDATE devices d SET paused_at = t.completed_at, paused_by_kind = 'app'
  FROM device_transfers t
 WHERE d.paused AND d.pause_cause = 'move' AND t.device_id = d.id AND t.target_workspace_id = d.tenant_id;
-- A person's pause: the newest pause or recovery event of the number in its
-- workspace, unless one of its pause notices was marked resumed after it.
-- A resume that found no unseen notice to mark leaves no trace, so a pause
-- that told nobody after it takes the older event's actor and time (DS7).
UPDATE devices d SET paused_at = e.occurred_at, paused_by_kind = e.actor_kind,
       paused_by_user = CASE WHEN e.actor_kind IN ('person', 'key') THEN e.actor_user_id END
  FROM (SELECT DISTINCT ON (item_id, tenant_id) item_id, tenant_id, occurred_at, actor_kind, actor_user_id
          FROM item_events WHERE type IN ('sync_paused', 'recovered')
         ORDER BY item_id, tenant_id, occurred_at DESC) e
 WHERE e.item_id = d.id AND e.tenant_id = d.tenant_id AND d.paused AND d.pause_cause = 'person'
   AND NOT EXISTS (SELECT 1 FROM device_notices n WHERE n.device_id = d.id AND n.kind = 'sync_paused'
                    AND n.resumed_at > e.occurred_at);
ALTER TABLE devices ENABLE TRIGGER devices_touch;
ALTER TABLE device_transfers ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_transfers FORCE ROW LEVEL SECURITY;
ALTER TABLE device_notices ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_notices FORCE ROW LEVEL SECURITY;
ALTER TABLE item_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE item_events FORCE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;

-- The logout cause is decided once, when a number moves into logged_out,
-- from the reason its writer gave: a deletion's two reasons (store's
-- reasonNoSession and reasonUnlinkedWhenGone) are the deletion's, any other
-- (a phone's unlink, a missing session) the phone's. A row already logged
-- out keeps its cause whatever reason follows: a deletion after a phone
-- logout finds no session (whatsmeow deleted it at the logout) and writes
-- 'no session at deletion', and a recovery keeps that reason.
CREATE FUNCTION devices_logout_cause() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status <> 'logged_out' THEN
        NEW.logout_cause := NULL;
    ELSIF TG_OP = 'UPDATE' AND OLD.status = 'logged_out' THEN
        NEW.logout_cause := OLD.logout_cause;
    ELSIF NEW.status_reason IN ('no session at deletion', 'unlinked when deleted') THEN
        NEW.logout_cause := 'deletion';
    ELSE
        NEW.logout_cause := 'phone';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER devices_logout_cause BEFORE INSERT OR UPDATE OF status, status_reason, logout_cause ON devices
    FOR EACH ROW EXECUTE FUNCTION devices_logout_cause();
ALTER TABLE devices ADD CONSTRAINT devices_logout_cause_shape CHECK ((logout_cause IS NOT NULL) = (status = 'logged_out'));

-- When a pause began, and the app as its actor for a move's or a
-- deletion's. A new pause, or one that changed hands (a recovery, a
-- person's stop on a moved number), starts now; a second stop with the same
-- cause keeps the first pause's time and actor. A resume clears all three
-- and stamps unpaused_at, which only this trigger writes. It runs after
-- devices_pause_cause (by name), so it sees the cause that one fills, and a
-- statement that sets only paused_by_kind and paused_by_user does not fire
-- it.
CREATE FUNCTION devices_pause_times() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT NEW.paused THEN
        NEW.paused_at := NULL;
        NEW.paused_by_kind := NULL;
        NEW.paused_by_user := NULL;
        IF TG_OP = 'UPDATE' THEN
            NEW.unpaused_at := CASE WHEN OLD.paused THEN clock_timestamp() ELSE OLD.unpaused_at END;
        END IF;
    ELSIF TG_OP = 'INSERT' OR NOT OLD.paused OR NEW.pause_cause IS DISTINCT FROM OLD.pause_cause THEN
        -- A person's actor comes from its event (devices_paused_by_event)
        -- or from the console's stop.
        NEW.paused_at := clock_timestamp();
        NEW.paused_by_kind := CASE WHEN NEW.pause_cause IN ('move', 'deletion') THEN 'app' END;
        NEW.paused_by_user := NULL;
        IF TG_OP = 'UPDATE' THEN
            NEW.unpaused_at := OLD.unpaused_at;
        END IF;
    ELSE
        -- Still paused, same cause: a second stop counts (pause_seq), but
        -- the pause, its time and its actor stay the first one's.
        NEW.paused_at := OLD.paused_at;
        NEW.paused_by_kind := OLD.paused_by_kind;
        NEW.paused_by_user := OLD.paused_by_user;
        NEW.unpaused_at := OLD.unpaused_at;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER devices_pause_times BEFORE INSERT OR UPDATE OF paused, pause_seq, pause_cause, paused_at, unpaused_at ON devices
    FOR EACH ROW EXECUTE FUNCTION devices_pause_times();
ALTER TABLE devices ADD CONSTRAINT devices_paused_by_shape CHECK (
        (paused OR (paused_at IS NULL AND paused_by_kind IS NULL AND paused_by_user IS NULL))
    AND (paused_by_user IS NULL OR coalesce(paused_by_kind IN ('person', 'key'), false))
    AND (paused_by_kind IS NULL OR paused_at IS NOT NULL));

-- A person's or a key's pause, and a recovery, name their actor in their
-- event. Each writer of these two types updates the number first in the
-- same transaction (Pause, Recover, the replay's recovery, the console's
-- stop), so this takes no new lock, and paused_at <= occurred_at holds (the
-- event reads the clock after). A replayed recovery carries the original
-- time, before the new pause, so it fills nothing. An event skipped by ON
-- CONFLICT DO NOTHING fires nothing.
CREATE FUNCTION devices_paused_by_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE devices SET paused_by_kind = NEW.actor_kind,
           paused_by_user = CASE WHEN NEW.actor_kind IN ('person', 'key') THEN NEW.actor_user_id END
     WHERE id = NEW.item_id AND tenant_id = NEW.tenant_id AND paused AND pause_cause = 'person'
       AND paused_at <= NEW.occurred_at;
    RETURN NULL;
END $$;
CREATE TRIGGER devices_paused_by_event AFTER INSERT ON item_events FOR EACH ROW
    WHEN (NEW.type IN ('sync_paused', 'recovered')) EXECUTE FUNCTION devices_paused_by_event();

-- The settings sender's channel. A workspace's numbers section shows its
-- numbers' connections, pauses and deletions, its pending registrations,
-- its capacity and its storage stop; 0051's dirty trigger ignores online,
-- offline and later connection times, and step 7 replaces it, so these are
-- the settings part's own. Notifications fold per transaction.
CREATE FUNCTION contract_settings_mark() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM pg_notify('wappie_contract_settings', OLD.tenant_id::text);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        PERFORM pg_notify('wappie_contract_settings', NEW.tenant_id::text);
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER contract_settings_device AFTER INSERT OR DELETE ON devices
    FOR EACH ROW EXECUTE FUNCTION contract_settings_mark();
-- Everything a numbers row or pending shows, but a connection that only
-- flips between online and offline (contract_settings_connection), and a
-- later connection time alone: SetStatus stamps it at every online, and the
-- row shows it as of measured_at.
CREATE TRIGGER contract_settings_device_update AFTER UPDATE ON devices FOR EACH ROW
    WHEN ((OLD.status IS DISTINCT FROM NEW.status
           AND (OLD.status NOT IN ('online', 'offline') OR NEW.status NOT IN ('online', 'offline')))
       OR (OLD.last_connected_at IS NULL) IS DISTINCT FROM (NEW.last_connected_at IS NULL)
       OR OLD.logout_cause IS DISTINCT FROM NEW.logout_cause OR OLD.paused IS DISTINCT FROM NEW.paused
       OR OLD.pause_cause IS DISTINCT FROM NEW.pause_cause OR OLD.paused_at IS DISTINCT FROM NEW.paused_at
       OR OLD.paused_by_kind IS DISTINCT FROM NEW.paused_by_kind OR OLD.paused_by_user IS DISTINCT FROM NEW.paused_by_user
       OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at OR OLD.purge_after IS DISTINCT FROM NEW.purge_after
       OR OLD.purge_started_at IS DISTINCT FROM NEW.purge_started_at OR OLD.current_epoch IS DISTINCT FROM NEW.current_epoch
       OR OLD.lid IS DISTINCT FROM NEW.lid OR OLD.pn IS DISTINCT FROM NEW.pn OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id)
    EXECUTE FUNCTION contract_settings_mark();
-- A connection that flips between online and offline: each whatsmeow
-- disconnect writes offline, and a flapping number would send a document
-- every 2 s. The sender makes these due after its connection debounce.
CREATE FUNCTION contract_settings_mark_connection() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('wappie_contract_settings', 'c:' || NEW.tenant_id::text);
    RETURN NULL;
END $$;
CREATE TRIGGER contract_settings_connection AFTER UPDATE OF status ON devices FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status AND OLD.status IN ('online', 'offline') AND NEW.status IN ('online', 'offline'))
    EXECUTE FUNCTION contract_settings_mark_connection();
CREATE TRIGGER contract_settings_capacity AFTER INSERT OR UPDATE OR DELETE ON workspace_capacity
    FOR EACH ROW EXECUTE FUNCTION contract_settings_mark();
-- A workspace's own status and storage stop; never its byte counters (the
-- hourly send covers the quota verdict).
CREATE FUNCTION contract_settings_mark_tenant() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('wappie_contract_settings', NEW.id::text);
    RETURN NULL;
END $$;
CREATE TRIGGER contract_settings_tenant AFTER UPDATE OF status, storage_paused_at, storage_limit_bytes ON tenants FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.storage_paused_at IS DISTINCT FROM NEW.storage_paused_at
       OR OLD.storage_limit_bytes IS DISTINCT FROM NEW.storage_limit_bytes)
    EXECUTE FUNCTION contract_settings_mark_tenant();
-- A notice raised, changed or deleted: a recovery deletes number_deleted
-- notices and housekeeping deletes notices, so the person's document drops
-- them at once.
CREATE FUNCTION contract_settings_mark_notice() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM pg_notify('wappie_contract_settings', 'u:' || OLD.user_id::text);
    ELSE
        PERFORM pg_notify('wappie_contract_settings', 'u:' || NEW.user_id::text);
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER contract_settings_notice AFTER INSERT OR UPDATE OR DELETE ON device_notices
    FOR EACH ROW EXECUTE FUNCTION contract_settings_mark_notice();
-- A section or a person made due sooner or due now, new, or released from
-- its park wakes the leader's sender at once, whichever process wrote it;
-- its own later due times notify nobody.
CREATE FUNCTION contract_settings_due() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('wappie_contract_settings', 'due');
    RETURN NULL;
END $$;
CREATE TRIGGER contract_sections_due_new AFTER INSERT ON contract_sections FOR EACH ROW EXECUTE FUNCTION contract_settings_due();
CREATE TRIGGER contract_sections_due_sooner AFTER UPDATE OF due_at, parked_at ON contract_sections FOR EACH ROW
    WHEN (NEW.due_at < OLD.due_at OR NEW.due_at <= clock_timestamp() OR (OLD.parked_at IS NOT NULL AND NEW.parked_at IS NULL))
    EXECUTE FUNCTION contract_settings_due();
CREATE TRIGGER contract_persons_due_new AFTER INSERT ON contract_persons FOR EACH ROW EXECUTE FUNCTION contract_settings_due();
CREATE TRIGGER contract_persons_due_sooner AFTER UPDATE OF due_at, parked_at ON contract_persons FOR EACH ROW
    WHEN (NEW.due_at < OLD.due_at OR NEW.due_at <= clock_timestamp() OR (OLD.parked_at IS NOT NULL AND NEW.parked_at IS NULL))
    EXECUTE FUNCTION contract_settings_due();

ALTER TABLE security_events DROP CONSTRAINT security_events_kind_check,
    ADD CONSTRAINT security_events_kind_check
        CHECK (kind IN ('platform_account_key_changed', 'platform_linked', 'platform_home_taken', 'contract_command_invalid'));

-- The label cutover for the events not sent yet (parked ones included):
-- every row then is written by this release's code or before it, and the
-- platform allowed cutting the older ones once. A settled row is the
-- platform's already. Their hints stay.
ALTER TABLE item_events DISABLE ROW LEVEL SECURITY;
UPDATE item_events SET label = NULL WHERE label IS NOT NULL AND settled_at IS NULL;
ALTER TABLE item_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE item_events FORCE ROW LEVEL SECURITY;
