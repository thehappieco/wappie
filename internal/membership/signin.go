package membership

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// The contract's part in signing people in (the plan's 4.5): a PUT at
// every sign-in through id. of a person Wappie holds, the platform's
// personal workspace as a new account's home, and the DELETE of a refused
// sign-up's subscription, never of a person Wappie holds (DB21). Every PUT
// is preceded by its committed intent row (store.Contract.Intend), so every
// subscription Wappie makes has a row the sweep can see. Only a validated
// document makes a sub fresh (DB8): a signed refusal, of any code, and an
// unverified answer confirm nothing.

// The refusals a sign-up gets from the contract.
var (
	// ErrPlatformUnavailable: no signed document for a new account (no
	// transport, no answer, an unverified one, or a signed refusal, a
	// not_found included: a platform fault, README 6.1). The account is
	// refused, retryably, and never given a home of Wappie's choosing.
	ErrPlatformUnavailable = errors.New("membership: no signed document from the platform")
	// ErrAccountNotActive: the platform's document of a new account says
	// disabled or closed. Creating the person would be acting on it, not
	// observing (DB3): the account is refused and unsubscribed.
	ErrAccountNotActive = errors.New("membership: the platform's account is not active")
)

// SignIns is what the sign-in routes ask of the contract (authapi).
type SignIns interface {
	// Observed reports whether a new account's home is the platform's.
	Observed(ctx context.Context) (bool, error)
	// SignIn subscribes a person Wappie holds, at observe.
	SignIn(ctx context.Context, sub uuid.UUID)
	// SignUp subscribes a new account and reads its home.
	SignUp(ctx context.Context, sub uuid.UUID) (SignUp, error)
	// Unsubscribe follows a refused sign-up's sub no more, unless held.
	Unsubscribe(ctx context.Context, s SignUp)
	// Refresh asks for a stale person's document after a step-up.
	Refresh(ctx context.Context, sub uuid.UUID)
}

var _ SignIns = (*Members)(nil)

// Members speaks the contract for people: the sign-in calls, the round,
// the sweep and freshness (the plan's 4.5, 4.6 and 4.9). Every process
// that serves sign-ins has one, whatever its configuration: the mode is
// the database's, and with no transport every call is no answer, which is
// fail-static (README 7.2) and refuses only new accounts.
type Members struct {
	// Client calls the platform; nil when no transport is configured.
	Client *Client
	// Contract is the contract's state in the database.
	Contract *store.Contract
	Log      *slog.Logger
	// Bound bounds each call made while a person waits: a sign-in's PUT,
	// a freshness GET, a refused sign-up's DELETE (5 s when zero).
	Bound time.Duration
	// Pace is the time between two of the leader's calls, whichever of the
	// round's PUTs, the sweep's DELETEs and the senders' snapshots and
	// batches of events they are (100 ms when zero: 10 a second together,
	// a fifth of the platform's limit, README 4).
	Pace time.Duration
	// ModeCache is how long the contract's state read is trusted (5 s
	// when zero; a negative one reads it every time).
	ModeCache time.Duration
	// Enforce makes RequireFresh's verdicts refusals. Release B never sets
	// it (the plan's DB4): observe only logs them.
	Enforce bool

	mu    sync.Mutex
	state store.ContractState
	read  time.Time
	// calls is the freshness hook's budget of GETs (budget.go).
	calls *callBudget
	// pacing gives the leader's calls their turns (Pace).
	pacing pacer
}

// SignUp is a new account's subscription: its home and document when the
// platform answered, and what its refusal path needs.
type SignUp struct {
	Sub uuid.UUID
	// Home is the document's personal workspace and Doc the document;
	// both zero before the contract's first observe (Wappie's own home).
	Home uuid.UUID
	Doc  *store.ContractDoc
	// intent is the intent row the PUT was sent after; subscribed, that
	// the PUT got a document, so the platform follows the sub.
	intent     time.Time
	subscribed bool
}

// callBound is a sign-in's bound on each call (the plan's 4.5).
const callBound = 5 * time.Second

func (m *Members) bound() time.Duration {
	if m.Bound > 0 {
		return m.Bound
	}
	return callBound
}

func (m *Members) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

// connected reports whether calls can be made: a transport and a secret.
func (m *Members) connected() bool { return m.Client != nil && m.Client.Loaded() }

// SignIn is the PUT of a returning person's sign-in through id. (README
// 6.1), while the contract is on (observe, and every mode after it): after
// the provider's sign-in and the pin, before Wappie's own refusals. It
// never refuses: a document that is not active, and no document while the
// last trusted published_through is over an hour old, are logged "would
// refuse" (README 7.1, "Sign-in"), and the sign-in goes on (DB4).
func (m *Members) SignIn(ctx context.Context, sub uuid.UUID) {
	if !m.on(ctx) {
		return
	}
	doc, err := m.subscribe(ctx, sub, true)
	if err == nil {
		if doc.Status != kc.AccountActive {
			m.log().Warn("contract: sign-in would refuse", "sub", sub, "reason", "account_"+doc.Status)
		}
		return
	}
	vouched, verr := m.Contract.Vouched(ctx, store.FreshFor, sub)
	switch {
	case verr != nil:
		m.log().Warn("contract: could not read a sign-in's freshness", "sub", sub, "error", verr)
	case !vouched:
		m.log().Warn("contract: sign-in would refuse", "sub", sub, "reason", "stale")
	}
}

// SignUp subscribes a new account's sub and reads its home (the plan's 4.5
// and DB2), once the contract was ever observed, in every mode since:
// before it, the zero SignUp, and Wappie chooses the home as before the
// contract. With no signed document it is ErrPlatformUnavailable; with one
// that is not active, ErrAccountNotActive, and the caller unsubscribes.
// Nothing is stored here: SignupPlatform stores the document with the
// account, in its transaction.
func (m *Members) SignUp(ctx context.Context, sub uuid.UUID) (SignUp, error) {
	s := SignUp{Sub: sub}
	observed, err := m.Observed(ctx)
	if err != nil || !observed {
		return s, err
	}
	if !m.connected() {
		m.log().Warn("contract: a new account has no document: no transport or no secret", "sub", sub)
		return s, ErrPlatformUnavailable
	}
	if s.intent, err = m.Contract.Intend(ctx, sub); err != nil {
		return s, err
	}
	doc, err := m.put(ctx, sub)
	if err != nil {
		return s, ErrPlatformUnavailable
	}
	s.subscribed = true
	if doc.Status != kc.AccountActive {
		m.log().Warn("contract: refused a new account: its document is not active", "sub", sub, "status", doc.Status)
		return s, ErrAccountNotActive
	}
	if len(doc.Workspaces) == 0 || doc.Workspaces[0].Kind != kc.KindPersonal {
		m.log().Error("contract: a new account's document names no personal workspace", "sub", sub, "version", doc.Version)
		return s, ErrPlatformUnavailable
	}
	s.Home, s.Doc = doc.Workspaces[0].ID, &doc
	return s, nil
}

// Unsubscribe is a refused sign-up's DELETE (the plan's DB21), outside
// every transaction, bounded: only when its PUT got a document, and only
// while the sub is still not held, read afresh, so a second tab or a
// double submit that created the person keeps its subscription. After the
// platform's signed unsubscribe the intent row is removed when it is still
// the one the PUT was sent after; when it is not (a newer PUT or a link
// came meanwhile), the sub is subscribed again at once. Every failure is
// left to the sweep.
func (m *Members) Unsubscribe(ctx context.Context, s SignUp) {
	if !s.subscribed || !m.connected() {
		return
	}
	// The DELETE outlives a person who gave up on the page.
	ctx = context.WithoutCancel(ctx)
	held, err := m.Contract.Held(ctx, s.Sub)
	switch {
	case err != nil:
		m.log().Warn("contract: a refused sign-up's subscription is left to the sweep", "sub", s.Sub, "error", err)
		return
	case held:
		return
	}
	call, cancel := context.WithTimeout(ctx, m.bound())
	err = m.Client.Unsubscribe(call, s.Sub.String())
	cancel()
	if err != nil {
		m.log().Warn("contract: a refused sign-up's unsubscribe got no answer; left to the sweep", append([]any{"sub", s.Sub}, callAttrs(err)...)...)
		return
	}
	m.forget(ctx, s.Sub, s.intent)
}

// forget removes sub's intent row after the platform's signed unsubscribe,
// by compare-and-set on the intent seen, and subscribes it again when that
// removes nothing.
func (m *Members) forget(ctx context.Context, sub uuid.UUID, seen time.Time) bool {
	removed, err := m.Contract.ForgetIntent(ctx, sub, seen)
	if err != nil {
		m.log().Warn("contract: could not remove an unsubscribed intent; left to the sweep", "sub", sub, "error", err)
		return false
	}
	if !removed {
		m.resubscribe(ctx, sub)
	}
	return removed
}

// resubscribe PUTs sub again after an unsubscribe raced a newer PUT or a
// link: the platform must follow whoever came meanwhile. The document is
// stored only for a sub Wappie holds by then; an unheld one's row is the
// sweep's again OrphanAfter later.
func (m *Members) resubscribe(ctx context.Context, sub uuid.UUID) {
	held, err := m.Contract.Held(ctx, sub)
	if err != nil {
		m.log().Warn("contract: could not subscribe a sub again", "sub", sub, "error", err)
		return
	}
	if _, err := m.subscribe(ctx, sub, held); err != nil {
		m.log().Warn("contract: could not subscribe a sub again; the round or the sweep will", "sub", sub)
	}
}

// Refresh is the step-up's GET (the reply's Q1, "Optional"), while the
// contract is on: when sub is not fresh, its document is asked for and
// stored, so an act right after a step-up finds the person fresh. Its
// failure changes nothing.
func (m *Members) Refresh(ctx context.Context, sub uuid.UUID) {
	if !m.on(ctx) {
		return
	}
	fresh, err := m.Contract.Fresh(ctx, store.FreshFor, sub)
	if err != nil {
		m.log().Warn("contract: could not read a sub's freshness", "sub", sub, "error", err)
		return
	}
	if !fresh[sub] {
		_, _ = m.get(ctx, sub) //nolint:errcheck // get logs; a step-up goes on without it
	}
}

// subscribe sends the PUT for sub after its intent row and, with save,
// stores the document as an answer, which makes the sub fresh. A document
// that cannot be stored (of another generation, not storable, of another
// workspace kind) is no document.
func (m *Members) subscribe(ctx context.Context, sub uuid.UUID, save bool) (store.ContractDoc, error) {
	if !m.connected() {
		return store.ContractDoc{}, ErrUnavailable
	}
	if _, err := m.Contract.Intend(ctx, sub); err != nil {
		m.log().Warn("contract: could not record a subscription's intent; nothing sent", "sub", sub, "error", err)
		return store.ContractDoc{}, err
	}
	doc, err := m.put(ctx, sub)
	if err != nil || !save {
		return doc, err
	}
	return doc, m.keep(ctx, doc)
}

// put sends the PUT, bounded, and reads its document.
func (m *Members) put(ctx context.Context, sub uuid.UUID) (store.ContractDoc, error) {
	call, cancel := context.WithTimeout(ctx, m.bound())
	d, err := m.Client.Subscribe(call, sub.String())
	cancel()
	if err == nil {
		var doc store.ContractDoc
		if doc, err = DocOf(d); err == nil {
			return doc, nil
		}
	}
	// A signed not_found on a PUT is a platform fault, retried like no
	// answer; it never means the account is closed (README 6.1).
	m.log().Warn("contract: a PUT got no document", append([]any{"sub", sub}, callAttrs(err)...)...)
	return store.ContractDoc{}, err
}

// get sends the GET for sub, bounded, outside every write transaction
// (README 7.1), and stores its document as an answer. A signed not_found
// says the platform follows sub no more: its version is forgotten, so the
// round subscribes it again (the plan's DB21).
func (m *Members) get(ctx context.Context, sub uuid.UUID) (store.ContractDoc, error) {
	return m.fetch(ctx, time.Now().Add(m.bound()), sub)
}

// fetch is get with the GET bounded by deadline, which an act's GETs share
// (getAll); the answer is stored, and a not_found forgotten, on ctx, so a
// document that came in time is kept however late in the window.
func (m *Members) fetch(ctx context.Context, deadline time.Time, sub uuid.UUID) (store.ContractDoc, error) {
	if !m.connected() {
		return store.ContractDoc{}, ErrUnavailable
	}
	call, cancel := context.WithDeadline(ctx, deadline)
	d, err := m.Client.Account(call, sub.String())
	cancel()
	var doc store.ContractDoc
	if err == nil {
		doc, err = DocOf(d)
	}
	if err != nil {
		m.log().Warn("contract: a GET got no document", append([]any{"sub", sub}, callAttrs(err)...)...)
		if RefusalCode(err) == kc.CodeNotFound {
			m.unfollowed(ctx, sub)
		}
		return store.ContractDoc{}, err
	}
	return doc, m.keep(ctx, doc)
}

// unfollowed forgets a held sub's version after a GET's not_found and
// wakes the leader, whose round subscribes it again.
func (m *Members) unfollowed(ctx context.Context, sub uuid.UUID) {
	if err := m.Contract.Unfollowed(ctx, sub); err != nil {
		m.log().Warn("contract: could not forget an unfollowed sub's version", "sub", sub, "error", err)
		return
	}
	if err := m.Contract.Wake(ctx, "round"); err != nil {
		m.log().Warn("contract: could not wake the contract's loops", "error", err)
	}
}

// errNotStored is an answer's document that could not be stored.
type errNotStored struct{ outcome store.ContractDocOutcome }

func (e errNotStored) Error() string {
	return "membership: the document was not stored: " + string(e.outcome)
}

// keep stores an answer's document; only stored or kept counts. A document
// newly stored is compared with Wappie's tables, as a feed page's is.
func (m *Members) keep(ctx context.Context, doc store.ContractDoc) error {
	out, err := m.Contract.StoreDocuments(ctx, store.ContractAnswer, doc)
	if err != nil {
		m.log().Warn("contract: could not store a document", "sub", doc.Sub, "error", err)
		return err
	}
	switch o := out[0]; o {
	case store.ContractDocStored:
		m.observe(ctx, doc.Sub, doc.Version)
	case store.ContractDocKept:
	default:
		m.log().Warn("contract: an answer's document was not stored", "sub", doc.Sub, "outcome", string(o))
		if o == store.ContractDocInvalid || o == store.ContractDocKindChanged {
			m.recordError(ctx, o)
		}
		return errNotStored{outcome: o}
	}
	return nil
}

// recordError keeps the class of a document's ERROR (store logged it) for
// contract status --check.
func (m *Members) recordError(ctx context.Context, o store.ContractDocOutcome) {
	class := store.ContractErrorDocumentInvalid
	if o == store.ContractDocKindChanged {
		class = store.ContractErrorKindChanged
	}
	if err := m.Contract.RecordError(ctx, class); err != nil {
		m.log().Warn("contract: could not record an ERROR", "error", err)
	}
}

// callAttrs describes a call's failure for a log line: its outcome, a
// signed refusal's code, and the class of no answer, never a message
// (DB22).
func callAttrs(err error) []any {
	o := Classify(err)
	attrs := []any{"outcome", o.String()}
	switch o {
	case Answered:
	case Refused:
		attrs = append(attrs, "code", RefusalCode(err))
	case Unverified:
	case Unavailable:
		attrs = append(attrs, "class", unavailableClass(err))
	}
	return attrs
}

func unavailableClass(err error) string {
	switch {
	case errors.Is(err, ErrNoSecret):
		return "no_secret"
	case errors.Is(err, ErrPeer):
		return "peer"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrUnavailable):
		return "no_transport"
	}
	return ErrorClass(err)
}

// String names a SignUp in a log without its document.
func (s SignUp) String() string {
	return fmt.Sprintf("membership.SignUp{Sub: %s, Home: %s}", s.Sub, s.Home)
}
