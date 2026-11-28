package membership

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/kms"
	"github.com/thehappieco/kit/thcseal"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/store"
)

// K_app and trial codes (the platform's spec, section 15.10; E0 slice 19).
// K_app is 32 random bytes sealed under Wappie's KMS key with the purpose
// trial-codes, its envelope in contract_trial_key; whatserverd contract
// trial-key init makes and seals it, and only wappie-api opens it (the
// leader and the pairing hook both run there). A code is made only when it
// is sent, from the number's own phone number and LID, and none is stored.
// With no key, a key that does not open, an envelope on the retired list,
// or codes suspended, a number has no code: its events settle not_sent and
// its link checks ask for the place alone (spec 15.12 "An item with no
// code"). When a key becomes usable, the catch-up sends one
// item.identity_updated for each number owed one, a few a second, each
// once (P2).

// TrialKeyContext is K_app's encryption context: SealContext's but for
// its purpose (the key policy allows GenerateDataKey and Decrypt under it).
var TrialKeyContext = kms.Context{Service: "wappie", Env: "prod", Purpose: "trial-codes", Ref: "platform"}

// The trial key's timings in the leader, the defaults when zero.
const (
	// trialRetry is how often an absent or failing key is tried again.
	trialRetry = 10 * time.Minute
	// trialPoll is how often the key's state is read beside the notices
	// (a switch of the codes, a key installed).
	trialPoll = time.Minute
	// trialDaily is how often the catch-up looks at every number while
	// the key is usable.
	trialDaily = 24 * time.Hour
	// trialPace spaces the catch-up's events: a few a second (P2).
	trialPace = 300 * time.Millisecond
	// trialErrorEvery spaces the ERROR of a key that does not open.
	trialErrorEvery = time.Hour
)

// The reasons a number has no code, as the logs and the store name them.
const (
	trialNoKey       = "no_key"
	trialSuspended   = "suspended"
	trialRetired     = "retired"
	trialNoIdentity  = "no_identity"
	trialOpenFailing = "does_not_open"
	// trialNotLoaded: this process has not loaded the key since it last
	// led (wappie-api's start, a leader just taken). Not a verdict: the
	// event sender holds a row rather than settle it not_sent.
	trialNotLoaded = "not_loaded"
)

// TrialKeyConfig is how wappie-api opens K_app: Wappie's KMS key (the
// contract's), and the retired list of envelopes recorded as exposed
// (WS_TRIAL_KEY_RETIRED, outside the database: a restore never brings an
// exposed key back into use).
type TrialKeyConfig struct {
	Open           OpenWrapper
	Region, KeyARN string
	// Retired are the lowercase hex sha256 of each retired envelope.
	Retired []string
}

// TrialTimings are the trial key's timings in the leader; tests shorten
// them.
type TrialTimings struct {
	Retry, Poll, Daily, Pace time.Duration
}

// trialKeys is the process's K_app, as wappie-api last opened it.
type trialKeys struct {
	// load serializes the loads (the leader's loop and its catch-up's
	// re-reads) and guards the loader's own fields: the KMS client, and
	// told, which spaces the ERRORs and the suspension's INFO.
	load      sync.Mutex
	wrapper   kms.Wrapper
	toldError time.Time
	toldWhy   string
	// mu guards what senders read, held only to read or publish it, never
	// across a store or KMS call: a move's check and the event sender
	// never wait on a load.
	mu sync.Mutex
	// loaded: a load has published a verdict since this process last led
	// (none yet, or the leader stopped: trialNotLoaded).
	loaded bool
	// key is the open key; sum its envelope's sha256, made its row's time.
	key  *kc.TrialKey
	sum  [32]byte
	made time.Time
	// why is why codes are not made now, "" while usable.
	why    string
	usable bool
}

// trialOpen is an open key, as a load publishes it.
type trialOpen struct {
	key  *kc.TrialKey
	sum  [32]byte
	made time.Time
}

// trialLoad is what a load found.
type trialLoad struct {
	// Usable: a key opened, codes on, not retired; Became: it was not at
	// the load before, or another key was.
	Usable, Became bool
	Why            string
	Made           time.Time
}

// LoadTrialKey reads K_app's row and the codes switch, opens the envelope
// when it is not the one held (never one on the retired list), and records
// the open or its failure's class for contract status. It reports whether
// codes are made now, and whether they were not before. The store and KMS
// calls run outside the lock trialCodesNow reads under; the verdict is
// published at the end.
func (m *Members) LoadTrialKey(ctx context.Context) (trialLoad, error) {
	t := &m.trial
	t.load.Lock()
	defer t.load.Unlock()
	st, err := m.Contract.TrialKeyState(ctx)
	if err != nil {
		return trialLoad{}, err
	}
	t.mu.Lock()
	held := trialOpen{key: t.key, sum: t.sum, made: t.made}
	was, wasMade := t.usable, t.made
	t.mu.Unlock()
	next, why := held, ""
	switch {
	case !st.Installed:
		next, why = trialOpen{}, trialNoKey
	case m.retired(st.StoredSHA256):
		next, why = trialOpen{}, trialRetired
		m.trialFailed(ctx, t, trialRetired)
	default:
		if held.key == nil || !bytesEqual(held.sum[:], st.StoredSHA256) {
			opened, class := m.openTrialKey(ctx, t)
			if class != "" {
				next, why = trialOpen{}, trialOpenFailing
				m.trialFailed(ctx, t, class)
				break
			}
			next = opened
		}
		if st.Codes != store.TrialCodesOn {
			why = trialSuspended
		}
	}
	if why == trialSuspended && t.toldWhy != trialSuspended {
		m.log().Info("contract: trial codes suspended; links go with no code", "since", st.CodesAt.UTC().Format(time.RFC3339))
	}
	if why != trialOpenFailing && why != trialRetired {
		t.toldError = time.Time{}
	}
	t.toldWhy = why
	usable := next.key != nil && why == ""
	t.mu.Lock()
	t.key, t.sum, t.made, t.why, t.usable, t.loaded = next.key, next.sum, next.made, why, usable, true
	t.mu.Unlock()
	return trialLoad{Usable: usable, Became: usable && (!was || !next.made.Equal(wasMade)), Why: why, Made: next.made}, nil
}

// forgetTrialKey drops the process's K_app when its leader stops: a
// process that does not lead loads no key, so it never makes codes from a
// state it no longer reads (a suspension it would not see). Until the next
// leader's first load, a number has no code (trialNotLoaded), and the
// event sender holds such events rather than settle them.
func (m *Members) forgetTrialKey() {
	t := &m.trial
	t.load.Lock()
	defer t.load.Unlock()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.key, t.sum, t.made, t.why, t.usable, t.loaded = nil, [32]byte{}, time.Time{}, "", false, false
}

// openTrialKey opens the installed envelope, and records the open; it
// returns the key, or the failure's class. Called under t.load.
func (m *Members) openTrialKey(ctx context.Context, t *trialKeys) (trialOpen, string) {
	envelope, made, ok, err := m.Contract.TrialKeyEnvelope(ctx)
	if err != nil {
		return trialOpen{}, "store"
	}
	if !ok {
		return trialOpen{}, "store"
	}
	if t.wrapper == nil {
		if m.Trial.Open == nil || m.Trial.KeyARN == "" {
			return trialOpen{}, "no_kms"
		}
		w, err := m.Trial.Open(ctx, m.Trial.Region, m.Trial.KeyARN)
		if err != nil {
			return trialOpen{}, ErrorClass(err)
		}
		t.wrapper = w
	}
	plain, err := thcseal.Open(ctx, t.wrapper, TrialKeyContext, envelope)
	if err != nil {
		return trialOpen{}, ErrorClass(err)
	}
	key, err := kc.NewTrialKey(plain)
	clear(plain)
	if err != nil {
		return trialOpen{}, "key_shape"
	}
	if err := m.Contract.TrialKeyOpened(ctx, envelope); err != nil && ctx.Err() == nil {
		m.log().Warn("contract: could not record the trial key's open", "error", err)
	}
	m.log().Info("contract: trial key opened")
	return trialOpen{key: &key, sum: sha256.Sum256(envelope), made: made}, ""
}

// trialFailed records a key that cannot be used: its class in the state
// row, an ERROR at most once an hour, and the class for contract status.
// Called under t.load.
func (m *Members) trialFailed(ctx context.Context, t *trialKeys, class string) {
	if err := m.Contract.TrialKeyOpenFailed(ctx, class); err != nil && ctx.Err() == nil {
		m.log().Warn("contract: could not record the trial key's failure", "error", err)
	}
	if !t.toldError.IsZero() && time.Since(t.toldError) < trialErrorEvery {
		return
	}
	t.toldError = time.Now()
	m.log().Error("contract: trial key not used; links go with no code", "class", class)
	if err := m.Contract.RecordError(ctx, store.ContractErrorTrialKey); err != nil && ctx.Err() == nil {
		m.log().Warn("contract: could not record an ERROR", "error", err)
	}
}

// retired reports whether the envelope whose sha256 is sum is on the
// retired list.
func (m *Members) retired(sum []byte) bool {
	h := hex.EncodeToString(sum)
	return slices.ContainsFunc(m.Trial.Retired, func(r string) bool { return strings.EqualFold(strings.TrimSpace(r), h) })
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

// trialCodesNow is the codes of a number now, from its phone number and
// LID as devices stores them, and why it has none ("" when it has):
// trialNotLoaded until this process's leader has loaded the key, a state
// that settles nothing.
func (m *Members) trialCodesNow(pn, lid string) (kc.TrialCodes, string) {
	t := &m.trial
	t.mu.Lock()
	key, why, usable, loaded := t.key, t.why, t.usable, t.loaded
	t.mu.Unlock()
	switch {
	case !loaded:
		return nil, trialNotLoaded
	case !usable:
		return nil, why
	}
	codes := trialCodes(*key, App, pn, lid)
	if len(codes) == 0 {
		return nil, trialNoIdentity
	}
	return codes, ""
}

// trialCodes is a number's trial codes under key (spec 15.10): the e164
// code of "+" and its phone-number JID's user part, and the wa_lid code of
// its LID's user part, each only when the identifier makes one
// (kc.TrialCode normalizes, and refuses one that makes none). Made only at
// send time, from the paired session's own identity; never stored.
func trialCodes(key kc.TrialKey, app, pn, lid string) kc.TrialCodes {
	codes := kc.TrialCodes{}
	add := func(kind, jid string, ident func(types.JID) string) {
		if jid == "" {
			return
		}
		j, err := types.ParseJID(jid)
		if err != nil || j.User == "" {
			return
		}
		code, err := kc.TrialCode(key, app, kind, ident(j))
		if err != nil {
			return
		}
		codes = append(codes, code)
	}
	add(kc.TrialKindE164, pn, func(j types.JID) string { return "+" + j.User })
	add(kc.TrialKindWALID, lid, func(j types.JID) string { return j.User })
	return codes
}

// trialWork is one leader's trial key: loaded at its start, again at each
// notice ("trial_key": a key installed, the codes switched) and every
// Poll, tried again every Retry while absent or failing, and the catch-up
// when the key becomes usable, another key is, and every Daily while it
// is. ready closes after the first load (whatever it found): the event
// sender starts then, so a row owed at a restart goes with its codes.
type trialWork struct {
	l     *Leader
	wake  chan struct{}
	ready chan struct{}
}

func newTrialWork(l *Leader) *trialWork {
	return &trialWork{l: l, wake: make(chan struct{}, 1), ready: make(chan struct{})}
}

// run loads and catches up until ctx ends.
func (w *trialWork) run(ctx context.Context) {
	m, cfg := w.l.Members, w.l.Trial
	var daily, under time.Time
	first := true
	for ctx.Err() == nil {
		wait := or(cfg.Poll, trialPoll)
		got, err := m.LoadTrialKey(ctx)
		if first {
			first = false
			close(w.ready)
		}
		switch {
		case err != nil:
			if ctx.Err() == nil {
				w.l.log().Warn("contract: could not read the trial key's state", "error", err)
			}
		case got.Usable && (!got.Made.Equal(under) || !time.Now().Before(daily)):
			// Usable since the last catch-up ended, another key, or a day.
			if w.catchUp(ctx, got.Made) {
				under, daily = got.Made, time.Now().Add(or(cfg.Daily, trialDaily))
			} else {
				under = time.Time{}
				wait = 0
			}
		case got.Why == trialOpenFailing || got.Why == trialNoKey || got.Why == trialRetired:
			// Absent or failing: tried again every Retry, or at once on a
			// notice (a key installed).
			wait = or(cfg.Retry, trialRetry)
		}
		if err == nil && !got.Usable {
			// Suspended, retired, absent or failing: the catch-up runs
			// again once a key is usable.
			under = time.Time{}
		}
		if got.Usable && !under.IsZero() {
			wait = min(wait, max(time.Until(daily), 0))
		}
		select {
		case <-ctx.Done():
			return
		case <-w.wake:
		case <-time.After(wait):
		}
	}
}

// catchUp sends one item.identity_updated for each number owed one under
// the key made at made (spec 15.12 "An item with no code"; P2): a number
// linked before slice 19, while the key was missing or suspended, or whose
// own event could not be written or was never owed. One at a time, Pace
// apart, each in its own transaction; a number whose identity makes no
// code is left out. Before each number it reads the key again on a notice
// or every Poll, and stops when the key is no longer usable or another one
// is (a suspension is the spec's 15.10 exposure step 1: no code anywhere),
// reporting false; true when it went through the list (or could not read
// it: tried again the next day).
func (w *trialWork) catchUp(ctx context.Context, made time.Time) bool {
	m := w.l.Members
	items, err := m.Contract.CodesCatchUp(ctx, made)
	if err != nil {
		if ctx.Err() == nil {
			w.l.log().Warn("contract: could not list the numbers owed their codes", "error", err)
		}
		return true
	}
	pace, poll := or(w.l.Trial.Pace, trialPace), or(w.l.Trial.Poll, trialPoll)
	recorded := map[uuid.UUID]int{}
	defer func() {
		for ws, n := range recorded {
			w.l.log().Info("contract: codes caught up", "workspace", ws, "count", n)
		}
	}()
	read := time.Now()
	for _, it := range items {
		var reload bool
		select {
		case <-w.wake:
			reload = true
		default:
			reload = time.Since(read) >= poll
		}
		if reload {
			read = time.Now()
			got, err := m.LoadTrialKey(ctx)
			if err == nil && (!got.Usable || !got.Made.Equal(made)) {
				w.l.log().Info("contract: the codes' catch-up stopped: the trial key changed", "reason", got.Why)
				return false
			}
		}
		if codes, _ := m.trialCodesNow(it.PN, it.LID); len(codes) == 0 {
			continue
		}
		ok, err := m.Contract.RecordCatchUp(ctx, it.Workspace, it.Device, made)
		if err != nil {
			if ctx.Err() == nil {
				w.l.log().Warn("contract: could not record a number's codes", "workspace", it.Workspace, "device", it.Device, "error", err)
			}
			continue
		}
		if ok {
			recorded[it.Workspace]++
		}
		t := time.NewTimer(pace)
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-t.C:
		}
	}
	return true
}

// errNoTrialKey is a trial key command's refusal with no KMS configured.
var errNoTrialKey = errors.New("membership: the trial key needs WS_CONTRACT_KMS_KEY_ARN and WS_CONTRACT_KMS_REGION")

// SealTrialKey makes K_app (32 bytes from crypto/rand, checked by the kit)
// and seals it under TrialKeyContext with w, never opening it again: the
// plaintext is cleared before it returns. whatserverd contract trial-key
// init installs the envelope (spec 15.10: only wappie-api opens it).
func SealTrialKey(ctx context.Context, w kms.Wrapper, random func([]byte) (int, error)) ([]byte, error) {
	if w == nil {
		return nil, errNoTrialKey
	}
	plain := make([]byte, kc.TrialKeyLen)
	defer clear(plain)
	if _, err := random(plain); err != nil {
		return nil, err
	}
	if _, err := kc.NewTrialKey(plain); err != nil {
		return nil, err
	}
	return thcseal.Seal(ctx, w, TrialKeyContext, plain)
}

// ProbeTrialKey is trial-key check --probe: KMS under TrialKeyContext with
// a throwaway data key (GenerateDataKey, then its Decrypt), as
// contract-secret seal --check-kms does; it never reads the envelope. It
// names the step that failed.
func ProbeTrialKey(ctx context.Context, w kms.Wrapper) (string, error) {
	if w == nil {
		return "describe", errNoTrialKey
	}
	probe := make([]byte, kc.TrialKeyLen)
	envelope, err := thcseal.Seal(ctx, w, TrialKeyContext, probe)
	if err != nil {
		return "generate", err
	}
	back, err := thcseal.Open(ctx, w, TrialKeyContext, envelope)
	if err != nil {
		return "decrypt", err
	}
	clear(back)
	return "", nil
}
