// Package access applies the same device authorization to HTTP and WebSocket.
//
// Three credentials come in: a person's session, an API key, and a platform
// token (thc_...; the plan's 3.1 to 3.3). Each has one way in, decided on
// the raw text before anything trims it (TokenText, TokenRequest): a token
// is never tried as a session or a key, and a session or a key never
// reaches the token path. Every check goes through a Checker, so no caller
// can skip the token branch.
package access

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
)

// Actor is who authenticated. For a token, User, Key, Scope and Role stay
// zero, so every path that asks for a person, a key's scope or an account
// refuses it as it refuses anyone else without one. Actor is comparable: a
// fresh Authenticate of an unchanged credential equals the first.
type Actor struct {
	Tenant uuid.UUID
	User   uuid.UUID
	Key    uuid.UUID
	Scope  store.KeyScope
	Role   string
	Token  store.TokenAuth
}

// IsToken reports whether a platform token authenticated.
func (a Actor) IsToken() bool { return a.Token.ID != uuid.Nil }

// hasThc reports whether s holds "thc_" in some ASCII case. Over bytes, so
// no Unicode folding can make one.
func hasThc(s string) bool {
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + ('a' - 'A')
		}
		return b
	}
	for i := 0; i+4 <= len(s); i++ {
		if lower(s[i]) == 't' && lower(s[i+1]) == 'h' && lower(s[i+2]) == 'c' && s[i+3] == '_' {
			return true
		}
	}
	return false
}

func base64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// sessionShaped is a well-formed session: 43 base64url characters.
func sessionShaped(s string) bool { return len(s) == 43 && base64URL(s) }

// keyShaped is a well-formed API key: 8 lowercase hex, a dot, and one or
// more base64url characters.
func keyShaped(s string) bool {
	if len(s) < 10 || s[8] != '.' || !base64URL(s[9:]) {
		return false
	}
	for i := range 8 {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// TokenText reports whether a credential's text is a platform token's: it
// holds "thc_" in some ASCII case, and, its surrounding spaces aside, it is
// neither a well-formed session (43 base64url characters) nor a
// well-formed key (8 lowercase hex, a dot, base64url). A session's or a
// key's random part can hold "thc_" (about one key in 50,000); a token is
// never shaped like either (t and h are not hex, and it has 64
// characters), so the exemptions never take one.
func TokenText(s string) bool {
	if !hasThc(s) {
		return false
	}
	t := strings.TrimSpace(s)
	return !sessionShaped(t) && !keyShaped(t)
}

// TokenRequest reports whether an HTTP request's Authorization values
// carry a token: some value holds "thc_" in some ASCII case, unless there
// is exactly one value, its strings.Fields are "Bearer" (any case) and one
// text, and TokenText rejects that text (a session or a key that holds
// "thc_"). Every other request keeps today's path, byte for byte.
func TokenRequest(values []string) bool {
	held := false
	for _, v := range values {
		held = held || hasThc(v)
	}
	if !held {
		return false
	}
	if len(values) == 1 {
		f := strings.Fields(values[0])
		if len(f) == 2 && strings.EqualFold(f[0], "Bearer") && !TokenText(f[1]) {
			return false
		}
	}
	return true
}

// FailureWait is the fixed wait before a refused credential's answer, so
// the time it takes says nothing of why it was refused.
const FailureWait = 250 * time.Millisecond

// Wait waits FailureWait, or until ctx ends.
func Wait(ctx context.Context) {
	t := time.NewTimer(FailureWait)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// Checker authenticates and authorizes every credential. Keys and Users
// serve sessions and keys, as before; Tokens, nil, refuses every token's
// text, never letting it fall through to a session or a key.
type Checker struct {
	Keys  *store.APIKeys
	Users *store.Users
	// Tokens serves platform tokens; nil refuses each.
	Tokens *store.Tokens
	// Switches are WS_MCP_WORKSPACE_DEFAULT and WS_MCP_DENY_TENANTS, which
	// token reads see beneath each workspace's own switches, in SQL.
	Switches store.TokenSwitches
	// Use counts tokens' uses and refusals for the usage report; nil counts
	// nothing.
	Use *TokenUse
	// Limits bounds token failures; nil limits nothing.
	Limits *TokenLimits
	// Watch wakes token sockets and streams on the token NOTIFY; nil wakes
	// nothing, and the one-second checks still bound every change.
	Watch *TokenWatch
	// Now is Wappie's clock; nil is time.Now.
	Now func() time.Time
	Log *slog.Logger
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Checker) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

// Peer is the address a request's token failures are limited on.
func (c *Checker) Peer(r *http.Request) string {
	var proxies []netip.Prefix
	if c.Limits != nil && c.Limits.Auth != nil {
		proxies = c.Limits.Auth.Proxies
	}
	return ratelimit.ClientIP(r, proxies)
}

// Authenticate resolves a credential's text. A token's (TokenText, tested
// before anything is trimmed) goes to AuthenticateToken with no address,
// and only there; every other text is tried as a session, then as a key, as
// it always was.
func (c *Checker) Authenticate(ctx context.Context, text string) (Actor, error) {
	if TokenText(text) {
		return c.AuthenticateToken(ctx, text, "")
	}
	return c.credential(ctx, text)
}

// Recheck is Authenticate for a request's second look at its credential,
// just before it answers (REST's finish): a token's is judged again at a
// fresh now, and nothing is counted or limited.
func (c *Checker) Recheck(ctx context.Context, text string) (Actor, error) {
	if TokenText(text) {
		if c.Tokens == nil {
			return Actor{}, store.ErrInvalidToken
		}
		auth, _, err := c.Tokens.ForAuth(ctx, text, c.now())
		if err != nil {
			return Actor{}, err
		}
		return Actor{Tenant: auth.Tenant, Token: auth}, nil
	}
	return c.credential(ctx, text)
}

// AuthenticateToken verifies a token's text, untrimmed, and judges it now
// (store.Tokens.ForAuth). With an address (peer), an address over its
// budget of token failures is refused before the token is looked at, and a
// failure spends that budget, and the selector's after a wrong secret. A
// refusal of a token whose secret matched counts its code (revoked,
// expired, suspended_here); a success counts the token used today. Every
// refusal is store.ErrInvalidToken; the caller answers its one token 401,
// after FailureWait.
func (c *Checker) AuthenticateToken(ctx context.Context, text, peer string) (Actor, error) {
	if c.Tokens == nil {
		return Actor{}, store.ErrInvalidToken
	}
	if !c.Limits.allow(peer) {
		return Actor{}, store.ErrInvalidToken
	}
	now := c.now()
	auth, fail, err := c.Tokens.ForAuth(ctx, text, now)
	if errors.Is(err, store.ErrInvalidToken) {
		c.Limits.failed(peer, fail)
		if fail.Token != uuid.Nil && fail.Code != "" {
			c.Use.Refused(fail.Token, now, uuid.Nil, "", fail.Code)
		}
		return Actor{}, store.ErrInvalidToken
	}
	if err != nil {
		// The database's: never the text, which a log must not hold.
		c.log().Error("could not check a platform token", "error", err)
		return Actor{}, store.ErrInvalidToken
	}
	c.Use.Used(auth.ID, now)
	return Actor{Tenant: auth.Tenant, Token: auth}, nil
}

// credential is a session's or a key's text, as it always was.
func (c *Checker) credential(ctx context.Context, token string) (Actor, error) {
	token = strings.TrimSpace(token)
	if c.Users != nil {
		if session, user, err := c.Users.ActiveSession(ctx, token); err == nil {
			return Actor{Tenant: session.TenantID, User: user.ID, Role: user.Role}, nil
		}
	}
	if c.Keys == nil {
		return Actor{}, store.ErrInvalidKey
	}
	key, err := c.Keys.VerifyScoped(ctx, token)
	if err != nil {
		return Actor{}, err
	}
	tenant, err := uuid.Parse(key.TenantID)
	if err != nil {
		return Actor{}, err
	}
	actor := Actor{Tenant: tenant, Key: key.ID, Scope: key.Scope}
	if key.ActsAs != nil {
		if c.Users == nil {
			return Actor{}, store.ErrInvalidKey
		}
		user, err := c.Users.Get(ctx, tenant, *key.ActsAs)
		if err != nil || user.Status != "active" || user.Role != store.RoleService {
			return Actor{}, store.ErrInvalidKey
		}
		actor.User = user.ID
		actor.Role = user.Role
	}
	return actor, nil
}

// Allows says whether actor may act on device, for an act the client
// named: a token's refusal is counted for its usage report. A key needs the
// action's scope and the number in its list; a key that acts as a service
// account also needs that account's permission, and a person needs their
// own.
//
// Pausing and resuming a number's capture (store.ActionPause) is a person's
// by role only: an owner or an admin, which in a personal workspace is its
// person, never a member with the Manage flag. A key keeps it under its
// scope, full, as for managing; one that acts as a service account adds the
// account's own Manage flag, as before: a service account acts as itself.
// A token pauses with its Manage perm (decision 0053).
func (c *Checker) Allows(ctx context.Context, actor Actor, device uuid.UUID, action store.DeviceAction) (bool, error) {
	if actor.IsToken() {
		v, err := c.TokenAllows(ctx, actor, device, store.TokenNeed{Action: action})
		return v.OK, err
	}
	return c.allows(ctx, actor, device, action)
}

// Probe is Allows, never counted: for the listings, the can_* flags, the
// push filters and REST's last check, which ask on every number whatever
// the client named (F4).
func (c *Checker) Probe(ctx context.Context, actor Actor, device uuid.UUID, action store.DeviceAction) (bool, error) {
	if actor.IsToken() {
		v, err := c.tokenVerdict(ctx, actor, device, store.TokenNeed{Action: action})
		return v.OK, err
	}
	return c.allows(ctx, actor, device, action)
}

// TokenAllows is a token's verdict on an act on device the client named,
// with what fetching an attachment adds (need.Media). A refusal with a code
// is counted, with the number and the perm.
func (c *Checker) TokenAllows(ctx context.Context, actor Actor, device uuid.UUID, need store.TokenNeed) (store.TokenVerdict, error) {
	v, err := c.tokenVerdict(ctx, actor, device, need)
	if err == nil && !v.OK && v.Code != "" {
		c.Use.Refused(actor.Token.ID, c.now(), device, v.Perm, v.Code)
	}
	return v, err
}

func (c *Checker) tokenVerdict(ctx context.Context, actor Actor, device uuid.UUID, need store.TokenNeed) (store.TokenVerdict, error) {
	if c.Tokens == nil || !actor.IsToken() {
		return store.TokenVerdict{}, nil
	}
	return c.Tokens.Allows(ctx, actor.Token, device, need, c.Switches, c.now())
}

// TokenSets is what a token reaches now, in one query: its listings, its
// flags, a socket's and a stream's checks. Never counted.
func (c *Checker) TokenSets(ctx context.Context, actor Actor) (store.TokenLive, error) {
	if c.Tokens == nil || !actor.IsToken() {
		return store.TokenLive{}, nil
	}
	return c.Tokens.ConnectionToken(ctx, actor.Token, c.Switches, c.now())
}

func (c *Checker) allows(ctx context.Context, actor Actor, device uuid.UUID, action store.DeviceAction) (bool, error) {
	if actor.Key != uuid.Nil {
		need := store.ScopeRead
		if action == store.ActionSend {
			need = store.ScopeSend
		}
		if action == store.ActionManage || action == store.ActionPause {
			need = store.ScopeFull
		}
		if !actor.Scope.Covers(need) {
			return false, nil
		}
		if c.Keys == nil {
			return false, errors.New("API key access is not configured")
		}
		allowed, err := c.Keys.AllowsDevice(ctx, actor.Key, actor.Tenant, device)
		if err != nil || !allowed {
			return false, err
		}
	}
	if actor.User == uuid.Nil {
		return actor.Key != uuid.Nil, nil
	}
	if c.Users == nil {
		return false, errors.New("account access is not configured")
	}
	p, err := c.Users.DevicePermission(ctx, actor.Tenant, actor.User, device)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return p.Allows(action), nil
}
