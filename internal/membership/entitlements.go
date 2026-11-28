package membership

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/obs"
	"whatserver2/internal/store"
)

// The entitlements part in the leader, in observe only (E0 slice 17; the
// platform's spec, section 15; docs/contract.md, "Entitlements and
// usage"): the follower of the fourth feed, its acknowledgement, the GET
// computed now, and the logs of what each document would do. They run
// while the contract is on and contract_ent_state.mode is observe: the
// leader's watcher starts them when it reads it (at its start, every mode
// check and each notice) and stops them when it reads off. Nothing here
// enforces a document: Wappie's own storage pause, its 72 h and 105 %
// accounting, its trial clock and its capacity writers stay as they are,
// and a trim is never run. A document that says enforce, which the
// platform never sends before Wappie's E2, holds its workspace at observe
// (the local brake) and logs an ERROR the operator reports at once.
//
// A reset is the account side's too: a signed gone on the feed, a page of
// another generation, or a GET's document of another generation resets
// the account, command and entitlements state in one transaction
// (Contract.RestartFromEntitlements), at most once a minute from this
// side.

// The entitlements part's defaults.
const (
	// entBackoffMin and entBackoffMax bound the wait after a feed call
	// that got no page.
	entBackoffMin = 2 * time.Second
	entBackoffMax = time.Minute
	// entSilentAfter is how long without a page before one ERROR.
	entSilentAfter = 15 * time.Minute
	// entAckEvery and entAckAtLeast: an acknowledgement goes at once after
	// a page that changed a switch, a timeline or a trim, or refused a
	// document; otherwise at most once a second, and at least once a
	// minute while the feed runs (the spec's 15.7).
	entAckEvery   = time.Second
	entAckAtLeast = time.Minute
	// entAckFailingAfter is how long the acknowledgements may fail before
	// one ERROR: the platform's doctor alerts after 10 minutes.
	entAckFailingAfter = 10 * time.Minute
	// entGetBackoffMin and entGetBackoffMax bound the wait after a GET
	// that got no document.
	entGetBackoffMin = 5 * time.Second
	entGetBackoffMax = time.Hour
	// entGetPace is the pace of the GETs a bad document whose workspace_id
	// cannot be read makes due: one every 10 s (the spec's 15.7).
	entGetPace = 10 * time.Second
	// entTimelineEvery is how often the steps whose time came are logged.
	entTimelineEvery = 30 * time.Second
	// entCapEvery is how often each workspace's total is compared with its
	// document's cap_bytes.
	entCapEvery = time.Minute
	// entIdle is the longest the ack and GET loops wait without looking,
	// should a kick be lost.
	entIdle = 30 * time.Second
)

// EntitlementsConfig is the entitlements part's timings in the leader: the
// defaults above when zero; tests shorten them.
type EntitlementsConfig struct {
	// Wait is the feed long-poll's wait in seconds (kc.MaxWait when zero).
	Wait                         int
	BackoffMin, BackoffMax       time.Duration
	SilentAfter                  time.Duration
	ResetFloor                   time.Duration
	AckEvery, AckAtLeast         time.Duration
	AckFailingAfter              time.Duration
	GetBackoffMin, GetBackoffMax time.Duration
	GetPace                      time.Duration
	TimelineEvery, CapEvery      time.Duration
	Idle                         time.Duration
	// Usage is the usage sender's (usage.go).
	Usage UsageConfig
}

func (c EntitlementsConfig) wait() int {
	if c.Wait > 0 {
		return min(c.Wait, kc.MaxWait)
	}
	return kc.MaxWait
}

// entitlementsWork is one leader's entitlements part: its loops while the
// mode is observe, and the kicks between them.
type entitlementsWork struct {
	l   *Leader
	cfg EntitlementsConfig
	// accounts and settings are cut by a reset made here, as the command
	// follower's.
	accounts  *follower
	settings  *settingsWork
	ack, gets chan struct{}
	// usage is the usage sender, which runs beside the loops while its
	// own switch is on.
	usage *usageWork

	mu sync.Mutex
	// cut ends the long-poll in flight, or the pause after it; cuts counts
	// the interrupts, so one that came while none was in flight is not
	// lost.
	cut  context.CancelFunc
	cuts uint64
	// lastReset is the floor's: the last reset this part made.
	lastReset time.Time
	// stop ends the running loops; nil while they do not run.
	stop context.CancelFunc
	wg   sync.WaitGroup
}

func newEntitlementsWork(l *Leader, accounts *follower, settings *settingsWork) *entitlementsWork {
	w := &entitlementsWork{l: l, cfg: l.Entitlements, accounts: accounts, settings: settings,
		ack: make(chan struct{}, 1), gets: make(chan struct{}, 1)}
	w.usage = newUsageWork(w)
	return w
}

// set starts the loops under ctx when st's mode is observe and they do not
// run, or stops them and waits for them when it is off; the usage sender
// follows its own switch beside them, on only while they observe. Only the
// leader's watcher calls it, and the leader's end (halt).
func (w *entitlementsWork) set(ctx context.Context, st store.EntState) {
	if st.UsageEffective() != store.UsageOn {
		w.usage.set(ctx, store.UsageOff)
	}
	defer func() {
		if st.UsageEffective() == store.UsageOn {
			w.usage.set(ctx, store.UsageOn)
		}
	}()
	w.mu.Lock()
	running := w.stop != nil
	switch {
	case st.Effective() == store.EntObserve && !running:
		run, stop := context.WithCancel(obs.WithLogger(ctx, w.l.log()))
		w.stop = stop
		w.mu.Unlock()
		w.l.log().Info("contract: entitlements started", "mode", store.EntObserve)
		w.wg.Go(func() { w.follow(run) })
		w.wg.Go(func() { w.acks(run) })
		w.wg.Go(func() { w.getLoop(run) })
		w.wg.Go(func() { w.timeline(run) })
		w.wg.Go(func() { w.caps(run) })
	case st.Effective() == store.EntOff && running:
		stop := w.stop
		w.stop = nil
		w.mu.Unlock()
		stop()
		w.wg.Wait()
		w.l.log().Info("contract: entitlements stopped")
	default:
		w.mu.Unlock()
	}
}

// halt stops the loops, if they run, and waits for them.
func (w *entitlementsWork) halt() { w.set(context.Background(), store.EntState{Mode: store.EntOff}) }

// interrupt ends the long-poll in flight, or its pause: another generation
// was seen, or the account side reset.
func (w *entitlementsWork) interrupt() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cuts++
	if w.cut != nil {
		w.cut()
	}
}

// pause waits d before the next feed call, or less when ctx ends or
// interrupt cuts it.
func (w *entitlementsWork) pause(ctx context.Context, d time.Duration) {
	wait, cut := context.WithTimeout(ctx, d)
	defer cut()
	w.mu.Lock()
	w.cut = cut
	w.mu.Unlock()
	<-wait.Done()
}

// reset is a reset this part asks for: seen the generation read, gen the
// one seen instead (nil after a gone). A second within the floor waits it
// out, logs one ERROR and records it. It reports whether it reset.
func (w *entitlementsWork) reset(ctx context.Context, seen uuid.UUID, gen *uuid.UUID, why string) (bool, error) {
	l, m := w.l, w.l.Members
	floor := or(w.cfg.ResetFloor, resetFloor)
	w.mu.Lock()
	last := w.lastReset
	w.mu.Unlock()
	if wait := floor - time.Since(last); !last.IsZero() && wait > 0 {
		l.log().Error("contract: a second reset from the entitlements feed within a minute waits", "why", why,
			"wait", wait.Round(time.Second))
		if err := m.Contract.RecordError(ctx, store.ContractErrorEntResetLoop); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record an ERROR", "error", err)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return false, ctx.Err()
		case <-t.C:
		}
	}
	done, err := m.Contract.RestartFromEntitlements(ctx, seen, gen)
	if err != nil || !done {
		return false, err
	}
	w.mu.Lock()
	w.lastReset = time.Now()
	w.mu.Unlock()
	attrs := []any{"why", why, "old", seen}
	if gen != nil {
		attrs = append(attrs, "generation", *gen)
	}
	l.log().Warn("contract: the platform's generation changed: every sub is subscribed again and the feed read from 0", attrs...)
	if w.accounts != nil {
		w.accounts.interrupt()
		kick(w.accounts.round)
	}
	if w.settings != nil {
		w.settings.interrupt()
	}
	kick(w.gets)
	return true, nil
}

// follow follows the entitlements feed until ctx ends.
func (w *entitlementsWork) follow(ctx context.Context) {
	l, m := w.l, w.l.Members
	minBack, maxBack := or(w.cfg.BackoffMin, entBackoffMin), or(w.cfg.BackoffMax, entBackoffMax)
	backoff := minBack
	var warned time.Time
	lastPage := time.Now()
	failing, told := false, false
	fail := func(class string, attrs ...any) {
		if ctx.Err() != nil {
			return
		}
		failing = true
		if err := m.Contract.EntFeedFailed(ctx, class); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record the entitlements feed's failure", "error", err)
		}
		if time.Since(warned) >= warnEvery {
			warned = time.Now()
			l.log().Warn("contract: the entitlements feed got no page", append([]any{"class", class}, attrs...)...)
		}
		if !told && time.Since(lastPage) >= or(w.cfg.SilentAfter, entSilentAfter) {
			told = true
			l.log().Error("contract: no entitlements feed page for a long time", "since", lastPage.UTC().Format(time.RFC3339), "class", class)
			if err := m.Contract.RecordError(ctx, store.ContractErrorEntFeedSilent); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not record an ERROR", "error", err)
			}
		}
		w.pause(ctx, backoff)
		backoff = min(backoff*2, maxBack)
	}
	for ctx.Err() == nil {
		w.mu.Lock()
		cuts := w.cuts
		w.mu.Unlock()
		st, err := m.Contract.EntState(ctx)
		if err != nil {
			fail("database", "error", err)
			continue
		}
		if st.Generation == nil {
			// The account side adopts the platform's generation first.
			w.pause(ctx, noGeneration)
			continue
		}
		seen, after := *st.Generation, st.FeedCursor
		poll, cut := context.WithCancel(ctx)
		w.mu.Lock()
		w.cut = cut
		missed := w.cuts != cuts
		w.mu.Unlock()
		if missed {
			cut()
			continue
		}
		asked := time.Now()
		page, err := m.Client.Entitlements(poll, after, w.cfg.wait())
		interrupted := poll.Err() != nil && ctx.Err() == nil
		cut()
		if ctx.Err() != nil {
			return
		}
		if interrupted && err != nil {
			continue
		}
		switch {
		case err == nil:
		case RefusalCode(err) == kc.CodeGone:
			// Signed: the cursor is past the platform's head: its database
			// was restored.
			if _, err := w.reset(ctx, seen, nil, "entitlements_gone"); err != nil {
				fail("store", "error", err)
			}
			continue
		default:
			fail(feedClass(err), callAttrs(err)...)
			continue
		}
		gen, err := uuid.Parse(page.Generation)
		if err != nil || (gen == seen && !entPageMoves(page, after)) {
			fail("unverified")
			continue
		}
		if failing {
			failing, backoff, told = false, minBack, false
			l.log().Info("contract: the entitlements feed answers again")
			if n, err := m.Contract.EntRecovered(ctx); err == nil && n > 0 {
				kick(w.gets)
			}
		}
		lastPage = time.Now()
		if gen != seen {
			if _, err := w.reset(ctx, seen, &gen, "entitlements_generation"); err != nil {
				fail("store", "error", err)
			}
			continue
		}
		if err := w.take(ctx, seen, after, page); err != nil {
			fail("store", "error", err)
			continue
		}
		if len(page.Items) == 0 && !page.More && time.Since(asked) < time.Duration(w.cfg.wait())*time.Second/2 {
			w.pause(ctx, minBack)
		}
	}
}

// entPageMoves reports whether a page asked from cursor is one the spec
// describes, which the kit does not check: its next_after never behind the
// cursor, its documents after it, and a page with more ending at its last
// item's seq.
func entPageMoves(page kc.EntitlementsFeed, cursor int64) bool {
	n := len(page.Items)
	switch {
	case page.NextAfter < cursor:
		return false
	case n > 0 && (page.Items[0].Seq <= cursor || page.NextAfter < page.Items[n-1].Seq):
		return false
	case page.More:
		return n > 0 && page.NextAfter == page.Items[n-1].Seq
	}
	return true
}

// judgeEntPage judges each item of a page of generation gen, Wappie's own,
// alone (kc.EntitlementsFeedItem.Document): a document to store, or a
// refusal with its workspace when that reads as a UUID.
func judgeEntPage(page kc.EntitlementsFeed, seen uuid.UUID, after int64) store.EntPage {
	p := store.EntPage{SeenGeneration: seen, After: after, NextAfter: page.NextAfter, More: page.More,
		PublishedThrough: page.PublishedThrough.Time}
	for _, it := range page.Items {
		d, ref := it.Document(App, page.Generation)
		if ref == nil {
			if doc, ok := store.NewEntDoc(d, []byte(it.Doc), false); ok {
				p.Items = append(p.Items, store.EntPageItem{Seq: it.Seq, Doc: &doc})
				continue
			}
			ref = &kc.EntitlementsRefused{Seq: it.Seq, Code: kc.RefusedInvalidDocument}
		}
		r := store.EntRefusal{Seq: ref.Seq, Code: ref.Code}
		if ref.WorkspaceID != nil {
			if ws, err := uuid.Parse(*ref.WorkspaceID); err == nil {
				r.Workspace = &ws
			}
		}
		p.Items = append(p.Items, store.EntPageItem{Seq: it.Seq, Refused: &r})
	}
	return p
}

// take stores a page of the generation seen, asked from after, and logs
// what each document would do.
func (w *entitlementsWork) take(ctx context.Context, seen uuid.UUID, after int64, page kc.EntitlementsFeed) error {
	m := w.l.Members
	res, err := m.Contract.CommitEntPage(ctx, judgeEntPage(page, seen, after))
	if err != nil || !res.Committed {
		// Not committed: the generation or the cursor moved; the state is
		// read again.
		return err
	}
	if res.Ahead {
		w.l.log().Warn("contract: the entitlements feed's published_through is ahead of the clock; the last trusted one is kept")
	}
	refused := false
	for _, r := range res.Items {
		w.logged(ctx, r)
		refused = refused || r.Action == store.EntRefuse
	}
	kick(w.ack)
	if refused {
		kick(w.gets)
	}
	return nil
}

// logged logs what one stored or refused document would do, ids, enums
// and times only, never a figure or the document.
func (w *entitlementsWork) logged(ctx context.Context, r store.EntItemResult) {
	log := w.l.log()
	switch r.Action {
	case store.EntRefuse:
		ws := "null"
		if r.Refused.Workspace != nil {
			ws = r.Refused.Workspace.String()
		}
		log.Warn("contract: entitlements document refused", "seq", r.Seq, "workspace", ws, "code", r.Refused.Code)
	case store.EntApply, store.EntKeep:
		logApplied(log, r)
		if r.Doc.Doc.Mode == kc.ModeEnforce {
			// E0 enforces nothing: the store held the workspace at observe
			// in the document's transaction. The platform never sends
			// enforce before Wappie's E2: an incident to report at once.
			log.Error("contract: entitlements enforce document held (E0)", "workspace", r.Workspace, "version", r.Doc.Version,
				"trim_present", len(r.Doc.Doc.Trim) > 0)
			if err := w.l.Members.Contract.RecordError(ctx, store.ContractErrorEntEnforceInE0); err != nil && ctx.Err() == nil {
				log.Warn("contract: could not record an ERROR", "error", err)
			}
		}
	}
}

// logApplied logs a document applied or kept, and each switch it holds off
// that the document it replaced held on (or every switch off, when it
// replaced none): what the document would stop, from its computed_at.
// A workspace held at observe says so (held_at_observe), and changes
// nothing else: E0 enforces nothing.
func logApplied(log *slog.Logger, r store.EntItemResult) {
	d := r.Doc.Doc
	held := []any{}
	if r.Braked {
		held = append(held, "held_at_observe", true)
	}
	seq := any(r.Seq)
	if r.Seq == 0 {
		seq = "get"
	}
	log.Info("contract: entitlements applied", append([]any{"seq", seq, "workspace", r.Workspace, "version", d.Version,
		"mode", d.Mode, "state", d.State.Name, "kept", r.Action == store.EntKeep}, held...)...)
	var prev *kc.EntitlementsDoc
	if r.Prev != nil {
		var p kc.EntitlementsDoc
		if json.Unmarshal(r.Prev, &p) == nil {
			prev = &p
		}
	}
	for _, name := range kc.EntitlementSwitches() {
		if d.Switches.Get(name) != kc.SwitchOff || (prev != nil && prev.Switches.Get(name) == kc.SwitchOff) {
			continue
		}
		log.Info("contract: entitlements would stop", append([]any{"workspace", r.Workspace, "version", d.Version,
			"switch", name, "at", d.ComputedAt.UTC().Format(time.RFC3339)}, held...)...)
	}
}

// acks sends the acknowledgement: at once when urgent, otherwise at most
// once every AckEvery and at least once every AckAtLeast while the feed
// runs, until ctx ends.
func (w *entitlementsWork) acks(ctx context.Context) {
	l, m := w.l, w.l.Members
	every, atLeast := or(w.cfg.AckEvery, entAckEvery), or(w.cfg.AckAtLeast, entAckAtLeast)
	backoff := or(w.cfg.GetBackoffMin, entGetBackoffMin)
	var failingSince time.Time
	told := false
	for ctx.Err() == nil {
		st, err := m.Contract.EntState(ctx)
		if err != nil {
			pause(ctx, backoff, w.ack)
			continue
		}
		wait := or(w.cfg.Idle, entIdle)
		if st.FirstReadAt != nil {
			since := time.Duration(1<<62 - 1)
			if st.AckedAt != nil {
				since = time.Since(*st.AckedAt)
			}
			behind := st.AckedThrough == nil || *st.AckedThrough != st.FeedCursor
			switch {
			case st.AckUrgent, behind && since >= every, since >= atLeast:
				wait = 0
			case behind:
				wait = every - since
			default:
				wait = min(wait, atLeast-since)
			}
		}
		if wait > 0 {
			if !pause(ctx, wait, w.ack) {
				return
			}
			continue
		}
		a, ok, err := m.Contract.EntAckDue(ctx)
		if err != nil || !ok {
			pause(ctx, backoff, w.ack)
			continue
		}
		if err := m.paced(ctx); err != nil {
			return
		}
		ack := kc.EntitlementsApplied{Generation: a.Generation.String(), Through: a.Through}
		for _, r := range a.Refused {
			e := kc.EntitlementsRefused{Seq: r.Seq, Code: r.Code}
			if r.Workspace != nil {
				ws := r.Workspace.String()
				e.WorkspaceID = &ws
			}
			ack.Refused = append(ack.Refused, e)
		}
		err = m.Client.EntitlementsApplied(ctx, ack)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			class := feedClass(err)
			if rerr := m.Contract.EntAckFailed(ctx, class); rerr != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not record the acknowledgement's failure", "error", rerr)
			}
			if failingSince.IsZero() {
				failingSince = time.Now()
			}
			if !told && time.Since(failingSince) >= or(w.cfg.AckFailingAfter, entAckFailingAfter) {
				told = true
				l.log().Error("contract: entitlements acknowledgements fail", "since", failingSince.UTC().Format(time.RFC3339), "class", class)
				if rerr := m.Contract.RecordError(ctx, store.ContractErrorEntAckFailing); rerr != nil && ctx.Err() == nil {
					l.log().Warn("contract: could not record an ERROR", "error", rerr)
				}
			}
			if RefusalCode(err) == kc.CodeGone {
				// Another generation or past the head: the follower meets it.
				w.interrupt()
			}
			pause(ctx, backoff, nil)
			continue
		}
		failingSince, told = time.Time{}, false
		if err := m.Contract.EntAcked(ctx, a); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record the acknowledgement", "error", err)
		}
		l.log().Info("contract: entitlements acknowledged", "through", a.Through, "refused", len(a.Refused))
	}
}

// getLoop sends the GET computed now of each workspace whose GET is due,
// until ctx ends: after a bad document, a naming with no document, a
// reset; one every GetPace while an unreadable bad document's pacing
// holds.
func (w *entitlementsWork) getLoop(ctx context.Context) {
	m := w.l.Members
	paceEvery := or(w.cfg.GetPace, entGetPace)
	for ctx.Err() == nil {
		due, err := m.Contract.EntGetsDue(ctx, roundBatch)
		if err != nil {
			if ctx.Err() == nil {
				w.l.log().Warn("contract: could not read the entitlements GETs due", "error", err)
			}
			if !pause(ctx, or(w.cfg.GetBackoffMin, entGetBackoffMin), w.gets) {
				return
			}
			continue
		}
		if len(due) == 0 {
			if !pause(ctx, or(w.cfg.Idle, entIdle), w.gets) {
				return
			}
			continue
		}
		for _, d := range due {
			if d.Paced {
				if d.Next != nil {
					if wait := time.Until(*d.Next); wait > 0 {
						if !pause(ctx, wait, nil) {
							return
						}
					}
				}
				ok, err := m.Contract.EntGetPaced(ctx, paceEvery)
				if err != nil || !ok {
					break
				}
			}
			if !w.get(ctx, d) {
				return
			}
			if d.Paced {
				// One at a time: the due list is read again after it.
				break
			}
		}
	}
}

// get sends ws's GET and stores its answer; false when ctx ended.
func (w *entitlementsWork) get(ctx context.Context, d store.EntGetDue) bool {
	l, m := w.l, w.l.Members
	backoff := min(or(w.cfg.GetBackoffMin, entGetBackoffMin)<<min(d.Tries, 20), or(w.cfg.GetBackoffMax, entGetBackoffMax))
	if err := m.paced(ctx); err != nil {
		return false
	}
	doc, signedAt, err := m.Client.EntitlementsDoc(ctx, d.Workspace.String())
	if ctx.Err() != nil {
		return false
	}
	switch {
	case err == nil:
		raw, merr := json.Marshal(doc)
		ed, ok := store.NewEntDoc(doc, raw, true)
		if merr != nil || !ok {
			w.failed(ctx, d.Workspace, "unverified", backoff)
			return true
		}
		res, err := m.Contract.EntGotDoc(ctx, ed, signedAt)
		if err != nil {
			w.failed(ctx, d.Workspace, "store", backoff)
			return true
		}
		switch res.Action {
		case store.EntReset:
			// A document of another generation: a reset, then the GET
			// again (the reset makes every GET due).
			st, err := m.Contract.EntState(ctx)
			if err == nil && st.Generation != nil {
				if _, err := w.reset(ctx, *st.Generation, &ed.Generation, "entitlements_get_generation"); err != nil && ctx.Err() == nil {
					l.log().Warn("contract: could not reset after a GET of another generation", "error", err)
				}
			}
			w.interrupt()
		case store.EntApply, store.EntKeep:
			w.logged(ctx, res.EntItemResult)
			kick(w.ack)
		}
	case errors.Is(err, kc.ErrForeignDocument):
		l.log().Warn("contract: entitlements foreign document", "workspace", d.Workspace)
		w.failed(ctx, d.Workspace, "foreign", backoff)
	case RefusalCode(err) == kc.CodeNotFound:
		l.log().Info("contract: entitlements not_found", "workspace", d.Workspace)
		if _, err := m.Contract.EntNotFound(ctx, d.Workspace, backoff); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record an entitlements not_found", "error", err)
		}
	default:
		w.failed(ctx, d.Workspace, feedClass(err), backoff)
	}
	return true
}

// failed logs and records a GET that got no document it could store.
func (w *entitlementsWork) failed(ctx context.Context, ws uuid.UUID, class string, backoff time.Duration) {
	w.l.log().Warn("contract: entitlements GET failed", "workspace", ws, "class", class)
	if err := w.l.Members.Contract.EntGetFailed(ctx, ws, class, backoff); err != nil && ctx.Err() == nil {
		w.l.log().Warn("contract: could not record an entitlements GET's failure", "error", err)
	}
}

// The actions of a step (entStepAction), as the vectors name them.
const (
	stepFire    = "fire"
	stepWait    = "wait"
	stepHold    = "hold"
	entStepNone = "none"
)

// entStepAction is what a stop of cause (timeline, item_trial, places) due
// from at would do now, with freshness freshAt (the spec's 15.6): when it
// stops (nil: never), and fire (its time came and freshness was under 24
// hours old then), wait (its time has not come), hold (frozen) or none.
// An item's trial stop never comes under a plan that grants (plan or
// live_move); Wappie's item and place stops come 72 hours after at; a
// pending place stop is cancelled once the item is in its place again.
func entStepAction(app, cause string, at, now time.Time, freshAt *time.Time, planSource string, inPlace bool) (*time.Time, string) {
	stops := at
	switch cause {
	case "item_trial":
		if planSource == kc.SourcePlan || planSource == kc.SourceLiveMove {
			return nil, entStepNone
		}
		if app == App {
			stops = at.Add(72 * time.Hour)
		}
	case "places":
		if inPlace {
			return nil, entStepNone
		}
		stops = at.Add(72 * time.Hour)
	}
	switch {
	case now.Before(stops):
		return &stops, stepWait
	case freshAt != nil && stops.Sub(*freshAt) < store.EntFreshFor:
		return &stops, stepFire
	}
	return &stops, stepHold
}

// timeline logs, every TimelineEvery, each step whose time came of every
// document held, as would fire or frozen, once: nothing is enforced.
func (w *entitlementsWork) timeline(ctx context.Context) {
	for ctx.Err() == nil {
		w.logSteps(ctx, time.Now())
		if !pause(ctx, or(w.cfg.TimelineEvery, entTimelineEvery), nil) {
			return
		}
	}
}

// logSteps logs the steps whose time came by now, once each.
func (w *entitlementsWork) logSteps(ctx context.Context, now time.Time) {
	log := w.l.log()
	_, rows, err := w.l.Members.Contract.EntRows(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Warn("contract: could not read the entitlements documents", "error", err)
		}
		return
	}
	for _, r := range rows {
		if r.Doc == nil || r.AppliedAt == nil {
			continue
		}
		var d kc.EntitlementsDoc
		if json.Unmarshal(r.Doc, &d) != nil {
			continue
		}
		var through *time.Time
		for _, step := range d.Timeline {
			at := step.At.Time
			if at.After(now) || (r.TimelineLoggedThrough != nil && !at.After(*r.TimelineLoggedThrough)) {
				continue
			}
			_, action := entStepAction(App, "timeline", at, now, r.Fresh, d.Plan.Source, false)
			age := "none"
			if r.Fresh != nil {
				age = at.Sub(*r.Fresh).Round(time.Second).String()
			}
			msg := "contract: entitlements step would fire"
			if action == stepHold {
				msg = "contract: entitlements step frozen"
			}
			for _, name := range step.Off {
				attrs := []any{"workspace", r.Workspace, "version", d.Version, "switch", name,
					"at", at.UTC().Format(time.RFC3339), "fresh_age", age}
				if r.BrakeKind != "" {
					attrs = append(attrs, "held_at_observe", true)
				}
				log.Info(msg, attrs...)
			}
			through = &at
		}
		if through != nil {
			if err := w.l.Members.Contract.EntTimelineLogged(ctx, r.Workspace, *through); err != nil && ctx.Err() == nil {
				log.Warn("contract: could not record the steps logged", "error", err)
			}
		}
	}
}

// The sides of cap_bytes (contract_ent_docs.cap_side).
const (
	capWithin = "within"
	capOver   = "over"
)

// capSide is the side of cap a total is on: over only past it (the spec's
// 15.3: "stores nothing new past it").
func capSide(total, capBytes int64) string {
	if total > capBytes {
		return capOver
	}
	return capWithin
}

// caps compares, every CapEvery, each applied document's cap_bytes with
// its workspace's total, and logs a crossing either way (the spec's 15.5:
// observe "logs a crossing"), never a figure.
func (w *entitlementsWork) caps(ctx context.Context) {
	for ctx.Err() == nil {
		w.checkCaps(ctx)
		if !pause(ctx, or(w.cfg.CapEvery, entCapEvery), nil) {
			return
		}
	}
}

// checkCaps is one pass of caps.
func (w *entitlementsWork) checkCaps(ctx context.Context) {
	log := w.l.log()
	_, rows, err := w.l.Members.Contract.EntRows(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Warn("contract: could not read the entitlements documents", "error", err)
		}
		return
	}
	for _, r := range rows {
		if r.Doc == nil || r.AppliedAt == nil {
			continue
		}
		var d kc.EntitlementsDoc
		if json.Unmarshal(r.Doc, &d) != nil {
			continue
		}
		total, ok, err := w.l.Members.Contract.EntTotal(ctx, r.Workspace)
		if err != nil || !ok {
			continue
		}
		side := capSide(total, d.Storage.CapBytes)
		if side == r.CapSide {
			continue
		}
		if r.CapSide != "" || side == capOver {
			msg, direction := "contract: entitlements cap would stop", "up"
			if side == capWithin {
				msg, direction = "contract: entitlements cap would lift", "down"
			}
			log.Info(msg, "workspace", r.Workspace, "version", d.Version, "direction", direction)
		}
		if err := w.l.Members.Contract.EntCapSide(ctx, r.Workspace, side); err != nil && ctx.Err() == nil {
			log.Warn("contract: could not record the cap's side", "error", err)
		}
	}
}
