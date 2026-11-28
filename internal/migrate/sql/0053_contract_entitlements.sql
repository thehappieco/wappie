-- The platform contract's entitlements and usage part on Wappie's side, in
-- observe only (E0; the platform's spec, section 15; slices 17 and 18 of
-- the E0 build design). Nothing here calls the platform, and nothing
-- changes how Wappie behaves: both switches are 'off' until an operator
-- turns them on (whatserverd contract entitlements observe, and usage on),
-- and even then E0 enforces nothing of a document. All of E0-a's and
-- E0-b's schema is here, so a later release of either migrates nothing.
--
--   contract_ent_state  one row: the follower's mode ('off' until an
--                       operator switches it; observe follows the feed and
--                       logs what each document would do; enforce is
--                       refused by this release's command), the usage
--                       sender's own switch, the feed's cursor under
--                       contract_state.generation (one generation for every
--                       feed), the last trusted published_through (from a
--                       page with more false only), the feed's read times and
--                       failure, the acknowledgement's state (the last one
--                       sent, its failure, whether one is due at once) and
--                       the pacing of the GETs after a bad document whose
--                       workspace_id cannot be read. The one-minute reset
--                       floor is the follower's, in memory.
--   contract_ent_docs   per workspace the app keeps a document for or must
--                       GET: the last applied document as received (bytea),
--                       its version under the generation it came in (both
--                       NULL after a reset: "forgets the stored versions"),
--                       its decoded mode, state and dates, when it was
--                       applied (NULL while kept for a workspace no account
--                       document names yet), the freshness hold of a bad
--                       document, the GET's freshness, due time and backoff,
--                       a signed not_found, slice 19's codes_after memory
--                       and trigger, when a document first said enforce
--                       (kept for good), the timeline step last logged, and
--                       the last side of cap_bytes logged. No foreign key:
--                       a document is kept for a workspace not named yet.
--   contract_ent_refusals   bad documents owed to an acknowledgement, by
--                       (generation, seq); a reset deletes them.
--   contract_ent_brakes the local brake (the spec's 15.5; Wappie's Q54): a
--                       workspace held at observe, by an operator or by E0
--                       itself on an enforce document (enforce_in_e0), and
--                       whether the platform was told.
--   contract_usage_seq  each platform workspace's usage_seq, rising across
--                       restarts and clock steps; the one row a measurement
--                       locks. No foreign key, so the measurement's lock
--                       never reaches contract_workspaces.
--   contract_usage      per recorded workspace, the usage sender's cadence:
--                       due time, its trigger and when that trigger first
--                       came, the 1 % trigger's coalescing, backoff, the
--                       last report's seq, times, kept, total (never
--                       logged) and the recent events its snapshot saw, and
--                       a stop after a GET's not_found.
--   contract_usage_reports  each report sent, as sent, written before its
--                       PUT, kept at least 8 hours after its measured_at
--                       (the spec's 15.8).
--   contract_ent_mode   AFTER UPDATE OF mode, usage on contract_ent_state:
--                       'entitlements' on the mode channel
--                       (wappie_contract_mode), so the leader starts or
--                       stops the follower and the usage sender at once.
--   contract_mark_usage AFTER INSERT on item_events of a deletion, recovery,
--                       purge or move out: the workspace's id on
--                       wappie_contract_usage. A notice only, no table
--                       write, so none of them ever waits on a measurement.
--
-- None of the new tables carries row-level security: they are read and
-- written across workspaces, as contract_state is, and hold no content and
-- no personal data (ids, counts, dates and states).
--
-- Down-step (additive migration; `migrate.Run` refuses a binary that does not
-- know version 53, so rolling back below it needs this first). Run only with
-- `wappie-api` stopped, after `whatserverd contract entitlements off` and
-- `whatserverd contract entitlements usage off`, after checking this file
-- against `migration53_sha256` in the release's RELEASE.json, as the table
-- owner. It refuses while the follower or usage is not off, and while
-- schema_migrations holds a version above 53; a refusal changes nothing.
-- It loses the cursor, the documents, the refusals owed, the brakes, the
-- usage sequence and the reports kept (each counted). After a later re-up,
-- usage_seq starts again from the clock in milliseconds, which still rises
-- if the clock moved forward.
--
--      BEGIN;
--      SELECT pg_advisory_xact_lock(6289348710053007958);
--      DO $$
--      BEGIN
--        IF EXISTS (SELECT 1 FROM schema_migrations WHERE version > 53) THEN
--          RAISE EXCEPTION 'a migration after 0053 is applied; run its down-step first';
--        END IF;
--        IF (SELECT mode FROM contract_ent_state) <> 'off' THEN
--          RAISE EXCEPTION 'entitlements are on: run whatserverd contract entitlements off first';
--        END IF;
--        IF (SELECT usage FROM contract_ent_state) <> 'off' THEN
--          RAISE EXCEPTION 'usage is on: run whatserverd contract entitlements usage off first';
--        END IF;
--      END $$;
--      LOCK TABLE tenants, users, workspace_memberships IN ACCESS EXCLUSIVE MODE;
--      DO $$
--      BEGIN
--        RAISE NOTICE 'dropping % documents (% applied), % refusals owed, % brakes, % usage seqs, % usage reports',
--          (SELECT count(*) FROM contract_ent_docs), (SELECT count(*) FROM contract_ent_docs WHERE applied_at IS NOT NULL),
--          (SELECT count(*) FROM contract_ent_refusals WHERE acked_at IS NULL), (SELECT count(*) FROM contract_ent_brakes),
--          (SELECT count(*) FROM contract_usage_seq), (SELECT count(*) FROM contract_usage_reports);
--      END $$;
--      DROP TRIGGER contract_mark_usage ON item_events;
--      DROP FUNCTION contract_mark_usage();
--      DROP TABLE contract_usage_reports;
--      DROP TABLE contract_usage;
--      DROP TABLE contract_usage_seq;
--      DROP TRIGGER contract_ent_mode ON contract_ent_state;
--      DROP FUNCTION contract_ent_mode();
--      DROP TABLE contract_ent_brakes;
--      DROP TABLE contract_ent_refusals;
--      DROP TABLE contract_ent_docs;
--      DROP TABLE contract_ent_state;
--      DELETE FROM schema_migrations WHERE version = 53;
--      COMMIT;
--
-- It runs first: 0053 down, then 0052 down (whose guard refuses while 53 is
-- applied), then 0051 down, and so on.

-- wappie-billing keeps running through this migration, as through 0051 and
-- 0052: this takes the three tables billing locks in a mode its reads never
-- conflict with, in billing's order. Nothing here alters a table billing
-- reads; the trigger on item_events waits only for its writers.
LOCK TABLE tenants, users, workspace_memberships IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE contract_ent_state (
    id                    boolean     PRIMARY KEY DEFAULT true CHECK (id),
    -- off: nothing of the part runs. observe: the feed is followed and
    -- acknowledged, the GETs sent, and what each document would do logged;
    -- nothing is enforced. enforce: a later release's; this one's command
    -- refuses it, and a binary that does not know a mode reads it as
    -- observe.
    mode                  text        NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'observe', 'enforce')),
    mode_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- The usage sender's own switch, so usage can stay off while the
    -- follower runs.
    usage                 text        NOT NULL DEFAULT 'off' CHECK (usage IN ('off', 'on')),
    usage_at              timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- The feed's cursor under contract_state.generation: the next
    -- request's after.
    feed_cursor           bigint      NOT NULL DEFAULT 0 CHECK (feed_cursor >= 0),
    -- Stored only from a page with more false.
    published_through     timestamptz,
    first_read_at         timestamptz,
    last_page_at          timestamptz,
    feed_error            text,
    feed_error_at         timestamptz,
    -- The last acknowledgement accepted, and whether the next goes at once.
    acked_through         bigint      CHECK (acked_through >= 0),
    acked_at              timestamptz,
    ack_due_at            timestamptz,
    ack_urgent            boolean     NOT NULL DEFAULT false,
    ack_error             text,
    ack_error_at          timestamptz,
    -- After a bad document whose workspace_id cannot be read: the next of
    -- the GETs it made due, one every 10 s.
    unreadable_get_next_at timestamptz,
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((feed_error IS NULL) = (feed_error_at IS NULL)),
    CHECK ((ack_error IS NULL) = (ack_error_at IS NULL)),
    CHECK ((acked_through IS NULL) = (acked_at IS NULL)),
    CHECK (last_page_at IS NULL OR first_read_at IS NOT NULL)
);
INSERT INTO contract_ent_state DEFAULT VALUES;

CREATE TABLE contract_ent_docs (
    workspace_id          uuid        PRIMARY KEY,
    -- NULL after a reset, which forgets the stored versions.
    generation            uuid,
    version               bigint      CHECK (version >= 1),
    -- The feed seq it came with; NULL when it came from a GET.
    seq                   bigint      CHECK (seq >= 1),
    -- The feed item's doc as received, or a GET's re-encoded; NULL while
    -- none is held (a placeholder whose GET is due).
    doc                   bytea,
    doc_from_get          boolean     NOT NULL DEFAULT false,
    mode                  text        CHECK (mode IN ('observe', 'enforce')),
    state                 text        CHECK (state IN ('active', 'trial', 'over_quota', 'expired', 'closed')),
    trial_ends_at         timestamptz,
    usage_after           timestamptz,
    codes_after           timestamptz,
    computed_at           timestamptz,
    received_at           timestamptz,
    -- NULL while kept for a workspace no account document names.
    applied_at            timestamptz,
    -- A bad document of this workspace: the feed's freshness holds at
    -- feed_fresh_at, the trusted published_through when the hold began.
    feed_held_back        boolean     NOT NULL DEFAULT false,
    feed_fresh_at         timestamptz,
    -- The signed time of the last valid GET answer of this generation.
    get_fresh_at          timestamptz,
    get_due_at            timestamptz,
    get_tries             integer     NOT NULL DEFAULT 0 CHECK (get_tries >= 0),
    get_error             text,
    get_error_at          timestamptz,
    -- A signed not_found on the GET: the last document stays, frozen.
    not_found_since       timestamptz,
    -- Slice 19's: the last codes_after answered (a reset forgets it), and
    -- the first document after a reset.
    codes_after_answered  timestamptz,
    first_after_reset     boolean     NOT NULL DEFAULT false,
    -- When a document of this workspace first said enforce: kept for good,
    -- a reset keeps it. In E0 only a fault sets it.
    ever_enforce_at       timestamptz,
    -- The last step at logged as would fire or frozen.
    timeline_logged_through timestamptz,
    -- The last side of cap_bytes logged (would stop, would lift).
    cap_side              text        CHECK (cap_side IN ('within', 'over')),
    -- A placeholder holds no version and no mode; a document always its
    -- mode, its version only until a reset forgets it.
    CHECK (CASE WHEN doc IS NULL THEN version IS NULL AND mode IS NULL ELSE mode IS NOT NULL END),
    CHECK (doc IS NOT NULL OR applied_at IS NULL),
    CHECK ((get_error IS NULL) = (get_error_at IS NULL)),
    CHECK (generation IS NULL OR version IS NOT NULL),
    CHECK (feed_held_back OR feed_fresh_at IS NULL)
);
CREATE INDEX contract_ent_docs_get_due ON contract_ent_docs (get_due_at) WHERE get_due_at IS NOT NULL;

CREATE TABLE contract_ent_refusals (
    generation   uuid        NOT NULL,
    seq          bigint      NOT NULL CHECK (seq >= 1),
    -- NULL when the document's workspace_id cannot be read.
    workspace_id uuid,
    code         text        NOT NULL CHECK (code IN ('invalid_document', 'another_app', 'another_generation')),
    seen_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    acked_at     timestamptz,
    PRIMARY KEY (generation, seq)
);

CREATE TABLE contract_ent_brakes (
    workspace_id uuid        PRIMARY KEY,
    held_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    platform_told boolean    NOT NULL,
    by_kind      text        NOT NULL CHECK (by_kind IN ('operator', 'enforce_in_e0'))
);

-- A switch of either mode wakes every process's contract loop, whoever
-- wrote it: the leader starts or stops the follower and the usage sender
-- within its tick at worst.
CREATE FUNCTION contract_ent_mode() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.mode IS DISTINCT FROM OLD.mode OR NEW.usage IS DISTINCT FROM OLD.usage THEN
        PERFORM pg_notify('wappie_contract_mode', 'entitlements');
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER contract_ent_mode AFTER UPDATE OF mode, usage ON contract_ent_state
    FOR EACH ROW EXECUTE FUNCTION contract_ent_mode();

CREATE TABLE contract_usage_seq (
    workspace_id uuid   PRIMARY KEY,
    usage_seq    bigint NOT NULL DEFAULT 0 CHECK (usage_seq >= 0)
);

CREATE TABLE contract_usage (
    workspace_id     uuid        PRIMARY KEY REFERENCES contract_workspaces(workspace_id) ON DELETE CASCADE,
    due_at           timestamptz,
    -- What made it due, the earliest deadline's: crossing, usage_after,
    -- event, percent or floor.
    due_trigger      text        CHECK (due_trigger IN ('crossing', 'usage_after', 'event', 'percent', 'floor')),
    -- When that trigger first made it due: a report's lateness counts from
    -- it, never from a backoff's due_at.
    due_first_at     timestamptz,
    -- The 1 % trigger's coalescing: not before 15 minutes after the last
    -- report sent.
    pct_after        timestamptz,
    tries            integer     NOT NULL DEFAULT 0 CHECK (tries >= 0),
    error            text,
    error_at         timestamptz,
    last_seq         bigint,
    last_measured_at timestamptz,
    last_sent_at     timestamptz,
    last_kept        boolean,
    -- Never logged.
    last_total_bytes bigint      CHECK (last_total_bytes >= 0),
    -- The deletion, recovery, purge and move-out events the last report's
    -- snapshot saw among those written in the slack before its
    -- measured_at: an event outside them is one it missed.
    last_event_ids   uuid[]      NOT NULL DEFAULT '{}',
    -- The last report sent after its trigger's deadline, and which.
    late_at          timestamptz,
    late_trigger     text,
    -- A GET answered not_found: no report until a document reaches the feed.
    stopped_since    timestamptz,
    CHECK ((error IS NULL) = (error_at IS NULL))
);

CREATE TABLE contract_usage_reports (
    workspace_id uuid        NOT NULL,
    usage_seq    bigint      NOT NULL CHECK (usage_seq >= 1),
    measured_at  timestamptz NOT NULL,
    body         bytea       NOT NULL,
    -- Written before the PUT goes, so a report whose answer was lost is
    -- kept all the same; set once an answer delivered it.
    sent_at      timestamptz,
    PRIMARY KEY (workspace_id, usage_seq)
);
CREATE INDEX contract_usage_reports_measured ON contract_usage_reports (measured_at);

-- A deletion, a recovery, a purge or a move out makes the workspace's usage
-- due: a notice only, folded per transaction.
CREATE FUNCTION contract_mark_usage() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('wappie_contract_usage', NEW.tenant_id::text);
    RETURN NULL;
END $$;
CREATE TRIGGER contract_mark_usage AFTER INSERT ON item_events FOR EACH ROW
    WHEN (NEW.type IN ('deleted', 'recovered', 'purged', 'moved_out')) EXECUTE FUNCTION contract_mark_usage();
