package membership

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	kc "github.com/thehappieco/kit/contract"
)

// ErrNoSecret means no contract secret is loaded yet (or none could be):
// the contract is unavailable and fail-static until one is (README 7.2).
var ErrNoSecret = errors.New("membership: no contract secret is loaded")

// Outcome is what a call's result may count for (README 5): only an answer
// confirms anything. A signed refusal is the platform's, but it confirms no
// membership and refreshes nothing; an unverified answer is ignored
// whatever its status; and no answer is no answer.
type Outcome int

// The outcomes, from Classify.
const (
	// Answered: a signed, valid answer, and for Subscribe and Account a
	// document of that sub (the kit checks both).
	Answered Outcome = iota + 1
	// Refused: a signed refusal (*contract.Refusal), with its code.
	Refused
	// Unverified: an answer whose signature did not hold, or that is not
	// valid (contract.ErrUnverified): no cursor moves, no row is marked.
	Unverified
	// Unavailable: no answer: the transport, a peer that failed its
	// checks, no secret loaded, a timeout.
	Unavailable
)

func (o Outcome) String() string {
	switch o {
	case Answered:
		return "answered"
	case Refused:
		return "refused"
	case Unverified:
		return "unverified"
	case Unavailable:
		return "unavailable"
	}
	return "unknown"
}

// Classify sorts a call's error into its Outcome.
func Classify(err error) Outcome {
	var refusal *kc.Refusal
	switch {
	case err == nil:
		return Answered
	case errors.As(err, &refusal):
		return Refused
	case errors.Is(err, kc.ErrUnverified):
		return Unverified
	}
	return Unavailable
}

// RefusalCode is a signed refusal's code, or "" for any other outcome.
func RefusalCode(err error) string {
	var refusal *kc.Refusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}

// Client is the one way Wappie calls the platform. It holds the kit's
// client by pointer (a contract.Client held by value inside a struct
// prints its secrets), swapped whole when the secrets are reloaded: a call
// in flight finishes on the client it started with, signed and checked
// with the secrets it started with.
type Client struct {
	http *http.Client
	base string
	now  func() time.Time
	kit  atomic.Pointer[kc.Client]
}

// NewClient is a client on httpc (HTTP, over the socket or loopback TCP),
// with no secret until Use is given one. now is the clock the requests are
// stamped with and the answers checked against (time.Now when nil).
func NewClient(httpc *http.Client, base string, now func() time.Time) *Client {
	return &Client{http: httpc, base: base, now: now}
}

// Use checks the secrets (contract.CheckSecrets: 43 base64url characters
// of 32 bytes each, the other different) and makes them the client's:
// current signs, and answers signed with current or other are accepted.
// The old client stays for the calls already under way.
func (c *Client) Use(current, other string) error {
	if err := kc.CheckSecrets(current, other); err != nil {
		return err
	}
	c.kit.Store(&kc.Client{
		App: App, Secret: current, Accept: kc.Secrets(current, other),
		Base: c.base, HTTP: c.http, Now: c.now,
	})
	return nil
}

// Loaded reports whether a secret is in use.
func (c *Client) Loaded() bool { return c.kit.Load() != nil }

// Rotating reports whether an other secret is accepted too.
func (c *Client) Rotating() bool {
	k := c.kit.Load()
	return k != nil && len(k.Accept) > 1
}

// call runs f on the client in use and, on a signed replay or
// unavailable, once more (README 3: "retry with a fresh nonce"; each kit
// call signs afresh). A replay is net/http resending a GET on a reused
// connection that broke, with the same nonce; unavailable, the platform
// could not answer that once. Neither counts as an answer.
func (c *Client) call(f func(*kc.Client) error) error {
	k := c.kit.Load()
	if k == nil {
		return ErrNoSecret
	}
	err := f(k)
	switch RefusalCode(err) {
	case kc.CodeReplay, kc.CodeUnavailable:
		err = f(k)
	}
	return err
}

// Subscribe follows sub and returns its document, computed now
// (PUT /contract/v1/accounts/{sub}). The document comes only with a nil
// error, and only when it is valid and this app's document of sub.
func (c *Client) Subscribe(ctx context.Context, sub string) (kc.AccountDoc, error) {
	var d kc.AccountDoc
	err := c.call(func(k *kc.Client) (err error) {
		d, err = k.Subscribe(ctx, sub)
		return err
	})
	return d, err
}

// Account returns the document of a sub Wappie follows, computed now
// (GET /contract/v1/accounts/{sub}), on the same terms as Subscribe.
func (c *Client) Account(ctx context.Context, sub string) (kc.AccountDoc, error) {
	var d kc.AccountDoc
	err := c.call(func(k *kc.Client) (err error) {
		d, err = k.Account(ctx, sub)
		return err
	})
	return d, err
}

// Unsubscribe follows sub no more (DELETE /contract/v1/accounts/{sub}).
func (c *Client) Unsubscribe(ctx context.Context, sub string) error {
	return c.call(func(k *kc.Client) error { return k.Unsubscribe(ctx, sub) })
}

// Feed returns the documents after the cursor after, waiting up to wait
// seconds (GET /contract/v1/feed): a page the kit validated, every document
// in it this app's and of the page's generation.
func (c *Client) Feed(ctx context.Context, after int64, wait int) (kc.Feed, error) {
	var f kc.Feed
	err := c.call(func(k *kc.Client) (err error) {
		f, err = k.Feed(ctx, after, wait)
		return err
	})
	return f, err
}

// PutAccess sends a workspace's snapshot (PUT /contract/v1/workspaces/{id}/access).
func (c *Client) PutAccess(ctx context.Context, workspace string, snap kc.Snapshot) error {
	return c.call(func(k *kc.Client) error { return k.PutAccess(ctx, workspace, snap) })
}

// PostEvents sends a batch and returns one result per event, by position
// (POST /contract/v1/events).
func (c *Client) PostEvents(ctx context.Context, events []kc.Event) ([]kc.EventResult, error) {
	var r []kc.EventResult
	err := c.call(func(k *kc.Client) (err error) {
		r, err = k.PostEvents(ctx, events)
		return err
	})
	return r, err
}
