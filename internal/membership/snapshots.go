package membership

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/label"
	"whatserver2/internal/store"
)

// The access snapshots (README 8 and 8.1; the plan's 4.10 and DB9): the
// leader's one sender, which sends every recorded platform workspace's
// snapshot, a personal one and one Wappie has no workspace for (empty)
// included, after each change it shows (2 s after the first of a run),
// after a document that changes its members, an hour after its last
// accepted one, and at the leader's start, in the order they are due, at
// the round's pace. The due times are the database's (contract_workspaces),
// so a document stored by any process, a restart and a recovery make a
// snapshot due for whichever process leads, and 0051's triggers wake it.

// The sender's defaults.
const (
	// snapshotEvery is how long after an accepted snapshot the next is
	// due: README 8's hourly, five minutes before the hour, so that a
	// snapshot an hour old is already late when contract status --check
	// warns of it (at 60 minutes), well before the platform counts it
	// stale (at 90, measured from its own receipt).
	snapshotEvery = 55 * time.Minute
	// snapshotDebounce is how long after a change it shows a snapshot is
	// sent (README 8: "debounced to 2 s"), counted from the first change
	// of a run.
	snapshotDebounce = 2 * time.Second
	// snapshotBackoffMin and snapshotBackoffMax bound the wait after a
	// snapshot that was not accepted: 5 s doubled with each failure in a
	// row, up to an hour (the plan's 4.10).
	snapshotBackoffMin = 5 * time.Second
	snapshotBackoffMax = time.Hour
	// snapshotIdle is the longest the sender waits without looking at the
	// due times, should a notice be lost.
	snapshotIdle = time.Minute
	// labelsEvery is how often a workspace's label counts are logged.
	labelsEvery = time.Hour
	// snapshotBodyLimit is the platform's limit on the call (README 3).
	snapshotBodyLimit = 1 << 20
)

// SnapshotOf is the wire's snapshot (README 8) of Wappie's read model,
// with snapshot_seq seq. Everyone listed is enrolled: a person exists in
// Wappie only after the sign-in that pins their key (the reply's Q4).
func SnapshotOf(s store.ContractSnapshot, seq int64) kc.Snapshot {
	out := kc.Snapshot{V: kc.SnapshotV, SnapshotSeq: seq, Items: make([]kc.Item, 0, len(s.Items))}
	for _, it := range s.Items {
		item := kc.Item{
			ID: it.ID.String(), Kind: kc.ItemNumber, Label: it.Label, Hint: it.Hint, State: it.State,
			OtherBackups: it.OtherBackups, People: make([]kc.Person, 0, len(it.People)), Protected: make([]string, 0, len(it.Protected)),
		}
		if it.Reason != "" {
			reason := it.Reason
			item.Reason = &reason
		}
		if it.PurgeAt != nil {
			at := kc.T(*it.PurgeAt)
			item.PurgeAt = &at
		}
		for _, p := range it.People {
			can := []string{}
			for _, f := range []struct {
				on   bool
				name string
			}{{p.Read, kc.CanRead}, {p.Send, kc.CanSend}, {p.Manage, kc.CanManage}} {
				if f.on {
					can = append(can, f.name)
				}
			}
			item.People = append(item.People, kc.Person{Sub: p.Sub.String(), Can: can, Reads: p.Reads, Waiting: p.Waiting,
				Enrolled: true, HoldsKey: p.HoldsKey})
		}
		for _, sub := range it.Protected {
			item.Protected = append(item.Protected, sub.String())
		}
		out.Items = append(out.Items, item)
	}
	return out
}

// checkSnapshot says why Wappie would not send snap, or "": more items or
// people than README 8 allows, a snapshot the kit's Validate refuses (its
// labels and hints included, as the platform's strict intake checks them),
// or a body over the call's limit. Its words name a rule, never a value.
func checkSnapshot(snap kc.Snapshot) string {
	why, _ := snapshotRule(snap) //nolint:errcheck // the rule's words alone; send logs the kit's refusal
	return why
}

// snapshotRule is checkSnapshot's verdict with the kit's refusal, which
// names the member that failed, never its value.
func snapshotRule(snap kc.Snapshot) (string, error) {
	if len(snap.Items) > kc.MaxItems {
		return "items", nil
	}
	for _, it := range snap.Items {
		if len(it.People) > kc.MaxPeople {
			return "people", nil
		}
	}
	if err := snap.Validate(); err != nil {
		return "invalid", err
	}
	body, err := json.Marshal(snap)
	if err != nil {
		return "encode", err
	}
	if len(body) > snapshotBodyLimit {
		return "too_large", nil
	}
	return "", nil
}

// snapshotResult sorts a PutAccess's error into the outcome the store
// records (README 8, "The answer"): a signed accepted; a signed not_found;
// a signed invalid_request, which parks; anything else, retried.
func snapshotResult(err error) (store.ContractSnapshotOutcome, string) {
	switch {
	case err == nil:
		return store.SnapshotAccepted, ""
	case RefusalCode(err) == kc.CodeNotFound:
		return store.SnapshotNotFound, "refused:" + kc.CodeNotFound
	case RefusalCode(err) == kc.CodeInvalid:
		return store.SnapshotRefused, "refused:" + kc.CodeInvalid
	}
	return store.SnapshotFailed, feedClass(err)
}

// notices is what the leader's watcher hands the snapshot sender, never
// waiting on it: the workspaces a committed change touched, or all of
// them, and a wake when someone made a snapshot due sooner.
type notices struct {
	mu   sync.Mutex
	ids  map[uuid.UUID]bool
	all  bool
	wake chan struct{}
}

func newNotices() *notices { return &notices{ids: map[uuid.UUID]bool{}, wake: make(chan struct{}, 1)} }

// dirty takes a dirty notice's payload: a workspace's id, or "all". Any
// other payload is no workspace's and is dropped.
func (n *notices) dirty(payload string) {
	n.mu.Lock()
	if payload == "all" {
		n.all = true
	} else if id, err := uuid.Parse(payload); err == nil {
		n.ids[id] = true
	} else {
		n.mu.Unlock()
		return
	}
	n.mu.Unlock()
	kick(n.wake)
}

// due wakes the sender: a due time moved sooner.
func (n *notices) due() { kick(n.wake) }

// take returns and forgets the dirty workspaces.
func (n *notices) take() ([]uuid.UUID, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ids := make([]uuid.UUID, 0, len(n.ids))
	for id := range n.ids {
		ids = append(ids, id)
	}
	all := n.all
	n.ids, n.all = map[uuid.UUID]bool{}, false
	return ids, all
}

// give puts back what take returned, when it could not be written.
func (n *notices) give(ids []uuid.UUID, all bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, id := range ids {
		n.ids[id] = true
	}
	n.all = n.all || all
}

// snapshotSender is one leader's sender of access snapshots.
type snapshotSender struct {
	l       *Leader
	notices *notices
	// logged is when each workspace's label counts were last logged.
	logged map[uuid.UUID]time.Time
	// warned spaces the WARNs of failed sends.
	warned time.Time
}

func (l *Leader) times() store.ContractSnapshotTimes {
	return store.ContractSnapshotTimes{
		Every:      or(l.SnapshotEvery, snapshotEvery),
		BackoffMin: or(l.SnapshotBackoffMin, snapshotBackoffMin),
		BackoffMax: or(l.SnapshotBackoffMax, snapshotBackoffMax),
	}
}

// run sends snapshots until ctx ends: every recorded workspace's at once
// (a leader's start), then each as it falls due, the dirty notices
// applied before each look at the due times.
func (s *snapshotSender) run(ctx context.Context) {
	l, c := s.l, s.l.Members.Contract
	minBack := or(l.BackoffMin, feedBackoffMin)
	pause := func(d time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-s.notices.wake:
		case <-time.After(d):
		}
		return true
	}
	for {
		err := c.SnapshotsDue(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return
		}
		l.log().Warn("contract: could not make the snapshots due at the leader's start", "error", err)
		if !pause(minBack) {
			return
		}
	}
	pace := pacer{every: l.Members.pace()}
	for ctx.Err() == nil {
		if ids, all := s.notices.take(); all || len(ids) > 0 {
			if err := c.SnapshotsDirty(ctx, ids, all, or(l.SnapshotDebounce, snapshotDebounce)); err != nil {
				if ctx.Err() != nil {
					return
				}
				s.notices.give(ids, all)
				l.log().Warn("contract: could not make the changed workspaces' snapshots due", "error", err)
				if !pause(minBack) {
					return
				}
				continue
			}
		}
		next, ok, err := c.NextSnapshot(ctx)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			l.log().Warn("contract: could not read the snapshots due", "error", err)
			if !pause(minBack) {
				return
			}
		case ok && next.Due:
			if err := pace.wait(ctx); err != nil {
				return
			}
			if !s.send(ctx, next) && !pause(minBack) {
				// Its outcome could not be stored, so it is still due: not
				// again at once.
				return
			}
		default:
			wait := snapshotIdle
			if ok {
				wait = min(wait, next.Wait)
			}
			if !pause(wait) {
				return
			}
		}
	}
}

// send measures one workspace, gives the snapshot its snapshot_seq, checks
// it, sends it and records what the platform answered. It reports false
// when no outcome could be stored, and the snapshot is due as it was.
func (s *snapshotSender) send(ctx context.Context, next store.ContractSnapshotDue) bool {
	l, m := s.l, s.l.Members
	c, ws := m.Contract, next.Workspace
	read, err := c.Snapshot(ctx, ws)
	if err != nil {
		if ctx.Err() != nil {
			return true
		}
		l.log().Warn("contract: could not read a workspace's snapshot", "workspace", ws, "error", err)
		// Recorded against the due time and the seq it was chosen with.
		_, ok := s.record(ctx, ws, next.Seq, next.DueAt, store.SnapshotFailed, "database")
		return ok
	}
	seq, ok, err := c.SnapshotSeq(ctx, ws, read.MeasuredAt)
	switch {
	case err != nil:
		if ctx.Err() != nil {
			return true
		}
		l.log().Warn("contract: could not give a snapshot its seq", "workspace", ws, "error", err)
		_, ok := s.record(ctx, ws, next.Seq, next.DueAt, store.SnapshotFailed, "database")
		return ok
	case !ok:
		// Parked meanwhile: nothing goes.
		return true
	}
	snap := SnapshotOf(read, seq)
	if why, rule := snapshotRule(snap); why != "" {
		rec, ok := s.record(ctx, ws, seq, read.MeasuredAt, store.SnapshotFailed, "local_invalid:"+why)
		if rec.Tries <= 1 {
			attrs := []any{"workspace", ws, "reason", why, "items", len(snap.Items)}
			if rule != nil {
				attrs = append(attrs, "rule", rule.Error())
			}
			l.log().Error("contract: a workspace's snapshot is not sent: Wappie would not send it", attrs...)
			if err := c.RecordError(ctx, store.ContractErrorSnapshotInvalid); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not record an ERROR", "error", err)
			}
		}
		return ok
	}
	err = m.Client.PutAccess(ctx, ws.String(), snap)
	if ctx.Err() != nil {
		// The leader is stopping: whatever came back, the next leader
		// sends again at its start.
		return true
	}
	outcome, class := snapshotResult(err)
	rec, stored := s.record(ctx, ws, seq, read.MeasuredAt, outcome, class)
	switch {
	case !rec.Recorded:
	case outcome == store.SnapshotAccepted:
		l.log().Debug("contract: snapshot accepted", "workspace", ws, "seq", seq, "items", len(snap.Items))
		s.labels(ws, read)
	case rec.Parked:
		attrs := []any{"workspace", ws, "class", class}
		if rec.NotFoundSince != nil {
			attrs = append(attrs, "not_found_since", rec.NotFoundSince.UTC().Format(time.RFC3339))
		}
		l.log().Error("contract: a workspace's snapshot is parked", attrs...)
		if err := c.RecordError(ctx, store.ContractErrorSnapshotParked); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record an ERROR", "error", err)
		}
	default:
		if time.Since(s.warned) >= warnEvery {
			s.warned = time.Now()
			l.log().Warn("contract: a snapshot was not accepted", append([]any{"workspace", ws, "tries", rec.Tries}, callAttrs(err)...)...)
		}
	}
	return stored
}

// record stores an outcome, and logs a failure to store it (false): the
// snapshot is then due as it was, and sent again.
func (s *snapshotSender) record(ctx context.Context, ws uuid.UUID, seq int64, measured time.Time,
	outcome store.ContractSnapshotOutcome, class string) (store.ContractSnapshotRecord, bool) {
	c := s.l.Members.Contract
	rec, err := c.SnapshotSent(ctx, ws, seq, measured, outcome, class, s.l.times())
	if err != nil {
		if ctx.Err() == nil {
			s.l.log().Warn("contract: could not record a snapshot's outcome", "workspace", ws, "error", err)
		}
		return rec, false
	}
	return rec, true
}

// labels logs, at most every labelsEvery for a workspace, how many of its
// numbers' labels fall in each class (the plan's 4.8): counts, never a
// label.
func (s *snapshotSender) labels(ws uuid.UUID, read store.ContractSnapshot) {
	if last, ok := s.logged[ws]; ok && time.Since(last) < labelsEvery {
		return
	}
	s.logged[ws] = time.Now()
	attrs := []any{"workspace", ws, "items", len(read.Items)}
	for _, class := range label.Classes() {
		attrs = append(attrs, string(class), read.Labels[class])
	}
	s.l.log().Info("contract: snapshot labels", attrs...)
}
