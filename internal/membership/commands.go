package membership

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// The command follower (the spec's 14.8; the plan's 3.1 and 5.4): the
// leader's one long-poll of the command feed, from the cursor of its own
// under the one generation the account feed adopted. Each page is decided
// item by item, in the spec's order (14.6), and written to the ledger in
// one transaction with the cursor; the next request's after is the
// acknowledgement, so a command is acknowledged only once its row is
// committed. Only the page's generation resets: a command of another
// generation than its page is the platform's fault, refused
// invalid_command, never a reset (one would bring it back for good).

// follow follows the command feed until ctx ends.
func (sw *settingsWork) follow(ctx context.Context) {
	l, m := sw.l, sw.l.Members
	minBack, maxBack := or(sw.cfg.CommandBackoffMin, commandBackoffMin), or(sw.cfg.CommandBackoffMax, commandBackoffMax)
	backoff := minBack
	var warned, lastReset time.Time
	failing := false
	resetFloor := or(sw.cfg.ResetFloor, resetFloor)
	fail := func(class string, attrs ...any) {
		if ctx.Err() != nil {
			return
		}
		failing = true
		if err := m.Contract.CommandFeedFailed(ctx, class); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record the command feed's failure", "error", err)
		}
		if time.Since(warned) >= warnEvery {
			warned = time.Now()
			l.log().Warn("contract: the command feed got no page", append([]any{"class", class}, attrs...)...)
		}
		sw.pause(ctx, backoff)
		backoff = min(backoff*2, maxBack)
	}
	reset := func(seen uuid.UUID, gen *uuid.UUID, why string) {
		if wait := resetFloor - time.Since(lastReset); !lastReset.IsZero() && wait > 0 {
			// No notice cuts this wait: a fault must not reset in a loop.
			// Two resets within the floor are one: the platform's feeds
			// disagree, or a gone lasts, and every sub, snapshot and section
			// goes again each time, so --check is told.
			l.log().Error("contract: a second reset from the command feed within a minute waits", "why", why,
				"wait", wait.Round(time.Second))
			if err := m.Contract.RecordError(ctx, store.ContractErrorCommandResetLoop); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not record an ERROR", "error", err)
			}
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
		done, err := m.Contract.RestartFromCommands(ctx, seen, gen)
		if err != nil {
			fail("store", "error", err)
			return
		}
		if !done {
			// The generation moved meanwhile: another reset came first,
			// and this one starts no floor.
			return
		}
		lastReset = time.Now()
		attrs := []any{"why", why, "old", seen}
		if gen != nil {
			attrs = append(attrs, "generation", *gen)
		}
		l.log().Warn("contract: the platform's generation changed: every sub is subscribed again and the feed read from 0", attrs...)
		sw.accounts.interrupt()
		kick(sw.accounts.round)
	}
	for ctx.Err() == nil {
		// An interrupt from here to the request's start (the account side
		// reset) would cut nothing: it is counted, and the state read again.
		sw.mu.Lock()
		cuts := sw.cuts
		sw.mu.Unlock()
		st, err := m.Contract.State(ctx)
		if err != nil {
			fail("database", "error", err)
			continue
		}
		sst, err := m.Contract.SettingsState(ctx)
		if err != nil {
			fail("database", "error", err)
			continue
		}
		if st.Generation == nil {
			// The account side adopts the platform's generation first.
			sw.pause(ctx, noGeneration)
			continue
		}
		if sw.cfg.stateRead != nil {
			sw.cfg.stateRead(sw.interrupt)
		}
		seen, after := *st.Generation, sst.FeedCursor
		poll, cut := context.WithCancel(ctx)
		sw.mu.Lock()
		sw.cut = cut
		missed := sw.cuts != cuts
		sw.mu.Unlock()
		if missed {
			cut()
			continue
		}
		asked := time.Now()
		page, err := m.Client.Commands(poll, after, sw.cfg.commandWait())
		interrupted := poll.Err() != nil && ctx.Err() == nil
		cut()
		if ctx.Err() != nil {
			return
		}
		if interrupted && err != nil {
			// A reset elsewhere: the state is read again first.
			continue
		}
		switch {
		case err == nil:
		case RefusalCode(err) == kc.CodeGone:
			// Signed: the cursor is past the platform's head (the spec's
			// 14.8): its database was restored.
			reset(seen, nil, "commands_gone")
			continue
		default:
			fail(feedClass(err), callAttrs(err)...)
			continue
		}
		gen, err := uuid.Parse(page.Feed.Generation)
		if err != nil || (gen == seen && !commandPageMoves(page.Feed, after)) {
			// The kit validated it; a page of this generation that is not one
			// the spec describes is no page all the same. A page of another
			// generation is a reset, whatever its cursor.
			fail("unverified")
			continue
		}
		if failing {
			failing, backoff = false, minBack
			l.log().Info("contract: the command feed answers again")
			sw.recovered(ctx)
		}
		if gen != seen {
			reset(seen, &gen, "commands_generation")
			continue
		}
		if err := sw.take(ctx, seen, after, page); err != nil {
			fail("store", "error", err)
			continue
		}
		if commandPageEarly(page.Feed, time.Since(asked), sw.cfg.commandWait()) {
			sw.pause(ctx, minBack)
		}
	}
}

// recovered makes every section that backs off due now, its tries
// forgotten, once the platform answers again after a failure (the
// Recovered of the snapshots and the event queues), and wakes the sender:
// after an outage no section waits out a backoff of up to an hour.
func (sw *settingsWork) recovered(ctx context.Context) {
	n, err := sw.l.Members.Contract.SectionsRecovered(ctx)
	switch {
	case err != nil:
		if ctx.Err() == nil {
			sw.l.log().Warn("contract: could not make the failing sections due", "error", err)
		}
	case n > 0:
		sw.l.log().Info("contract: failing sections due again", "sections", n)
		kick(sw.sections.wake)
	}
}

// pause waits d before the next command feed call, or less when ctx ends
// or interrupt cuts it.
func (sw *settingsWork) pause(ctx context.Context, d time.Duration) {
	wait, cut := context.WithTimeout(ctx, d)
	defer cut()
	sw.mu.Lock()
	sw.cut = cut
	sw.mu.Unlock()
	<-wait.Done()
}

// take decides every item of a page of the generation seen, asked from
// after, and stores the page; a failure is returned, for the backoff. It
// logs one ERROR for a page that refused anything invalid_command, and
// records it for contract status --check, after the commit.
func (sw *settingsWork) take(ctx context.Context, seen uuid.UUID, after int64, page CommandPage) error {
	l, m := sw.l, sw.l.Members
	kinds := map[uuid.UUID]string{}
	kindOf := func(ws uuid.UUID) (string, error) {
		if k, ok := kinds[ws]; ok {
			return k, nil
		}
		w, ok, err := m.Contract.Workspace(ctx, ws)
		if err != nil {
			return "", err
		}
		if !ok {
			w.Kind = ""
		}
		kinds[ws] = w.Kind
		return w.Kind, nil
	}
	p := store.ContractCommandPage{SeenGeneration: seen, After: after, NextAfter: page.Feed.NextAfter, SignedAt: page.SignedAt}
	whys := map[string]int{}
	verify := func(raw json.RawMessage) (kc.Command, error) { return m.Client.VerifyCommand(page, raw) }
	for _, it := range page.Feed.Items {
		take, unreadable, err := decideCommand(App, verify, page.Feed.Generation, page.SignedAt, it, kindOf)
		if err != nil {
			return err
		}
		if unreadable != nil {
			p.Unreadable = append(p.Unreadable, *unreadable)
			whys[unreadable.Why]++
			continue
		}
		if take.Why == whyGeneration {
			l.log().Error("contract: a command of another generation than its page; refused invalid_command",
				"id", take.ID, "cseq", take.Cseq)
		}
		if take.Verdict == store.CommandInvalid {
			whys[take.Why]++
		}
		p.Items = append(p.Items, take)
	}
	res, err := m.Contract.TakeCommands(ctx, p)
	if err != nil || !res.Committed {
		// Not committed: the generation or the cursor moved; the state is
		// read again.
		return err
	}
	if res.Invalid > 0 || len(p.Unreadable) > 0 {
		attrs := []any{"invalid", res.Invalid, "no_id", len(p.Unreadable), "security", res.Security}
		for why, n := range whys {
			attrs = append(attrs, "why_"+why, n)
		}
		l.log().Error("contract: commands refused invalid_command", attrs...)
		if err := m.Contract.RecordError(ctx, store.ContractErrorCommandInvalid); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record an ERROR", "error", err)
		}
	}
	if res.New > 0 {
		kick(sw.executor)
	}
	if res.Refused+res.Replayed+res.OtherBody > 0 {
		kick(sw.results)
	}
	return nil
}

// commandPageMoves reports whether a command feed page asked from cursor
// is one the spec's 14.8 describes (its 6.3), which the kit does not check:
// its next_after never behind the cursor; its commands after the cursor
// and none past next_after, so a page with commands moves the cursor past
// them all (one that did not would be asked again at once, and taken again
// each time); and a page with more ending at its last item's cseq.
func commandPageMoves(page kc.CommandFeed, cursor int64) bool {
	n := len(page.Items)
	switch {
	case page.NextAfter < cursor:
		return false
	case n > 0 && (page.Items[0].CSeq <= cursor || page.NextAfter < page.Items[n-1].CSeq):
		return false
	case page.More:
		return n > 0 && page.NextAfter == page.Items[n-1].CSeq
	}
	return true
}

// commandPageEarly reports whether a page is an empty final one that came
// back in under half the wait it asked for, as early for the account feed.
func commandPageEarly(page kc.CommandFeed, took time.Duration, wait int) bool {
	return len(page.Items) == 0 && !page.More && took < time.Duration(wait)*time.Second/2
}

// The reasons a command is refused at take, as the log and the security
// log name them: never a body or a person.
const (
	whyAnotherApp = "another_app"
	whyMalformed  = "malformed"
	whyMAC        = "mac"
	whyGeneration = "generation"
	whyInvalid    = "invalid"
	whyCseq       = "cseq"
	whyRetention  = "retention"
	whyExpiry     = "expiry"
)

// decideCommand decides one item of a page of generation pageGen, signed
// at signedAt, which app holds (the follower's own generation), with
// verify checking each command's MAC under the page's secrets for app: a
// pure function of the app, in the spec's order (14.6; the plan's 3.1),
// steps 1 to 6:
// a body that is not one well-formed object the kit can canonicalize, of
// another app, or whose MAC holds under none of the page's secrets (each
// forged: the security log); a command of another generation than its
// page; one whose MAC holds but that does not decode as a command, or that
// ValidateIn refuses for its workspace's kind (Validate
// alone for a workspace Wappie has not recorded, ValidateIn("") for a
// person's), or whose cseq is not its item's; one issued more than 30 days
// before the page was signed, unless delivered again, or carried by a page
// signed after its expires_at (expired). A command refused before
// ValidateIn passed keeps no decoded field; an item with no id that is a
// UUID gets no row (unreadable). Step 7, the wseq memory, is the take's,
// under its lock. kindOf reads a recorded workspace's kind, "" for none;
// its error fails the page.
func decideCommand(app string, verify func(json.RawMessage) (kc.Command, error), pageGen string, signedAt time.Time,
	it kc.CommandFeedItem, kindOf func(uuid.UUID) (string, error)) (store.ContractCommandTake, *store.ContractUnreadable, error) {
	raw := []byte(it.Command)
	take := store.ContractCommandTake{Cseq: it.CSeq, Body: raw, BodyKey: bodyKey(raw), Again: it.Again}
	// A generic decode, its members named exactly, as the kit reads the
	// command it verifies: never encoding/json's match of a name in any
	// case, under which an "ID" would stand for the id.
	var members map[string]json.RawMessage
	_ = json.Unmarshal(raw, &members) //nolint:errcheck // a body that does not decode has neither
	headID, headApp := stringMember(members, "id"), stringMember(members, "app")
	// Only an id that is a UUID as the platform writes one names a row.
	id, idErr := uuid.Parse(headID)
	named := idErr == nil && id.String() == headID
	refuse := func(why string, forged bool) (store.ContractCommandTake, *store.ContractUnreadable, error) {
		if !named {
			return store.ContractCommandTake{}, &store.ContractUnreadable{Cseq: it.CSeq, Why: why, Forged: forged}, nil
		}
		take.ID, take.Verdict, take.Why, take.Forged = id, store.CommandInvalid, why, forged
		return take, nil, nil
	}
	c, err := verify(it.Command)
	switch {
	case errors.Is(err, kc.ErrCommandMAC):
		return refuse(whyMAC, true)
	case err == nil:
	case !macCovers(raw):
		return refuse(whyMalformed, true)
	case headApp != app:
		return refuse(whyAnotherApp, true)
	default:
		// The kit canonicalized it, its app is this one and its MAC held:
		// what failed is its typed decode. The platform signed it, so it is
		// step 4's invalid_command, not a forgery: a copy of a taken id
		// finishes an open row.
		return refuse(whyInvalid, false)
	}
	switch {
	case c.ID != headID:
		return refuse(whyInvalid, false)
	case kc.ValidUUID(c.Generation) && c.Generation != pageGen:
		return refuse(whyGeneration, false)
	}
	if c.CSeq != it.CSeq {
		return refuse(whyCseq, false)
	}
	var ws *uuid.UUID
	kind := ""
	if c.WorkspaceID != nil {
		if parsed, err := uuid.Parse(*c.WorkspaceID); err == nil && parsed.String() == *c.WorkspaceID {
			ws = &parsed
			if kind, err = kindOf(parsed); err != nil {
				return store.ContractCommandTake{}, nil, err
			}
		}
	}
	check := c.ValidateIn(kind)
	if ws != nil && kind == "" {
		// No document named it: no Wappie kind depends on its kind.
		check = c.Validate()
	}
	if check != nil {
		return refuse(whyInvalid, false)
	}
	fields, err := commandFields(app, c, ws)
	if err != nil {
		return refuse(whyInvalid, false)
	}
	take.ID, take.Decoded = id, fields
	switch {
	case !it.Again && signedAt.Sub(c.IssuedAt.Time) > kc.CommandRetention:
		take.Verdict, take.Why = store.CommandExpired, whyRetention
	case c.ExpiresAt != nil && signedAt.After(c.ExpiresAt.Time):
		take.Verdict, take.Why = store.CommandExpired, whyExpiry
	}
	return take, nil, nil
}

// stringMember is the string member name of an object decoded generically,
// "" when it has none or it is not a string.
func stringMember(members map[string]json.RawMessage, name string) string {
	var s string
	if json.Unmarshal(members[name], &s) != nil {
		return ""
	}
	return s
}

// commandFields are the ledger's columns of a command that passed
// ValidateIn: its ids as decoded and validated, its params as received.
func commandFields(app string, c kc.Command, ws *uuid.UUID) (*store.ContractCommandFields, error) {
	actor, err := uuid.Parse(c.Actor)
	if err != nil {
		return nil, err
	}
	target, err := json.Marshal(c.Target)
	if err != nil {
		return nil, err
	}
	docs, err := json.Marshal(c.BasedOn.Docs)
	if err != nil {
		return nil, err
	}
	f := &store.ContractCommandFields{
		Producer: kc.SectionProducer(app, c.Section), Workspace: ws, WSeq: c.WSeq, Kind: c.Kind, Section: c.Section,
		Actor: actor, Target: target, Params: []byte(c.Params), BasedOnSeq: &c.BasedOn.StateSeq, BasedOnDocs: docs,
		IssuedAt: c.IssuedAt.Time, FirstIssuedAt: c.FirstIssuedAt.Time, Confirm: c.Confirm,
	}
	if c.ActorRole != nil {
		f.ActorRole = *c.ActorRole
	}
	if c.ExpiresAt != nil {
		at := c.ExpiresAt.Time
		f.ExpiresAt = &at
	}
	if c.RetryOf != nil {
		retry, err := uuid.Parse(*c.RetryOf)
		if err != nil {
			return nil, err
		}
		f.RetryOf = &retry
	}
	return f, nil
}
