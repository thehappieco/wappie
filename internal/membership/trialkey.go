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
	mu sync.Mutex
	// key is the open key; sum its envelope's sha256, made its row's time.
	key     *kc.TrialKey
	sum     [32]byte
	made    time.Time
	wrapper kms.Wrapper
	// why is why codes are not made now, "" while usable.
	why string
	// usable is the last load's verdict; told spaces the ERRORs and the
	// suspension's INFO.
	usable    bool
	toldError time.Time
	toldWhy   string
}

// trialLoad is what a load found.
type trialLoad struct {
	// Usable: a key opened, codes on, not retired; Became: it was not at
	// the load before.
	Usable, Became bool
	Why            string
	Made           time.Time
}

// LoadTrialKey reads K_app's row and the codes switch, opens the envelope
// when it is not the one held (never one on the retired list), and records
// the open or its failure's class for contract status. It reports whether
// codes are made now, and whether they were not before.
func (m *Members) LoadTrialKey(ctx context.Context) (trialLoad, error) {
	t := &m.trial
	st, err := m.Contract.TrialKeyState(ctx)
	if err != nil {
		return trialLoad{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	was := t.usable
	out := trialLoad{}
	switch {
	case !st.Installed:
		t.key, t.why = nil, trialNoKey
	case m.retired(st.StoredSHA256):
		t.key, t.why = nil, trialRetired
		m.trialFailed(ctx, t, trialRetired)
	default:
		if t.key == nil || !bytesEqual(t.sum[:], st.StoredSHA256) {
			if class := m.openTrialKey(ctx, t); class != "" {
				t.key, t.why = nil, trialOpenFailing
				m.trialFailed(ctx, t, class)
				break
			}
		}
		t.why = ""
		if st.Codes != store.TrialCodesOn {
			t.why = trialSuspended
		}
	}
	if t.why == trialSuspended && t.toldWhy != trialSuspended {
		m.log().Info("contract: trial codes suspended; links go with no code", "since", st.CodesAt.UTC().Format(time.RFC3339))
	}
	if t.why != trialOpenFailing && t.why != trialRetired {
		t.toldError = time.Time{}
	}
	t.toldWhy = t.why
	t.usable = t.key != nil && t.why == ""
	out.Usable, out.Became, out.Why, out.Made = t.usable, t.usable && !was, t.why, t.made
	return out, nil
}

// openTrialKey opens the installed envelope into t, and records the open;
// it returns the failure's class, "" on success.
func (m *Members) openTrialKey(ctx context.Context, t *trialKeys) string {
	envelope, made, ok, err := m.Contract.TrialKeyEnvelope(ctx)
	if err != nil {
		return "store"
	}
	if !ok {
		return "store"
	}
	if t.wrapper == nil {
		if m.Trial.Open == nil || m.Trial.KeyARN == "" {
			return "no_kms"
		}
		w, err := m.Trial.Open(ctx, m.Trial.Region, m.Trial.KeyARN)
		if err != nil {
			return ErrorClass(err)
		}
		t.wrapper = w
	}
	plain, err := thcseal.Open(ctx, t.wrapper, TrialKeyContext, envelope)
	if err != nil {
		return ErrorClass(err)
	}
	key, err := kc.NewTrialKey(plain)
	clear(plain)
	if err != nil {
		return "key_shape"
	}
	t.key, t.sum, t.made = &key, sha256.Sum256(envelope), made
	if err := m.Contract.TrialKeyOpened(ctx, envelope); err != nil && ctx.Err() == nil {
		m.log().Warn("contract: could not record the trial key's open", "error", err)
	}
	m.log().Info("contract: trial key opened")
	return ""
}

// trialFailed records a key that cannot be used: its class in the state
// row, an ERROR at most once an hour, and the class for contract status.
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
// LID as devices stores them, and why it has none ("" when it has).
func (m *Members) trialCodesNow(pn, lid string) (kc.TrialCodes, string) {
	t := &m.trial
	t.mu.Lock()
	key, why := t.key, t.why
	usable := t.usable
	t.mu.Unlock()
	switch {
	case key == nil && why == "":
		return nil, trialNoKey
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
// when the key becomes usable and every Daily while it is.
type trialWork struct {
	l    *Leader
	wake chan struct{}
}

func newTrialWork(l *Leader) *trialWork { return &trialWork{l: l, wake: make(chan struct{}, 1)} }

// run loads and catches up until ctx ends.
func (w *trialWork) run(ctx context.Context) {
	m, cfg := w.l.Members, w.l.Trial
	var daily time.Time
	for ctx.Err() == nil {
		wait := or(cfg.Poll, trialPoll)
		got, err := m.LoadTrialKey(ctx)
		switch {
		case err != nil:
			if ctx.Err() == nil {
				w.l.log().Warn("contract: could not read the trial key's state", "error", err)
			}
		case got.Usable && (got.Became || !time.Now().Before(daily)):
			w.catchUp(ctx, got.Made)
			daily = time.Now().Add(or(cfg.Daily, trialDaily))
		case got.Why == trialOpenFailing || got.Why == trialNoKey || got.Why == trialRetired:
			// Absent or failing: tried again every Retry, or at once on a
			// notice (a key installed).
			wait = or(cfg.Retry, trialRetry)
		}
		if got.Usable {
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
// own event could not be written. One at a time, Pace apart, each in its
// own transaction; a number whose identity makes no code is left out.
func (w *trialWork) catchUp(ctx context.Context, made time.Time) {
	m := w.l.Members
	items, err := m.Contract.CodesCatchUp(ctx, made)
	if err != nil {
		if ctx.Err() == nil {
			w.l.log().Warn("contract: could not list the numbers owed their codes", "error", err)
		}
		return
	}
	pace := or(w.l.Trial.Pace, trialPace)
	recorded := map[uuid.UUID]int{}
	for _, it := range items {
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
			return
		case <-t.C:
		}
	}
	for ws, n := range recorded {
		w.l.log().Info("contract: codes caught up", "workspace", ws, "count", n)
	}
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
