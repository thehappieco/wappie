package store

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/pg"
)

// Token auth (the plan's 3.1 and 3.3): a platform token (thc_...) is
// verified against its selector's row, then judged in one statement
// against the one predicate of a live token, and each act on a number in
// one more. Every time is Wappie's clock, passed in, never the database's
// now(): the database's clock drifts.

// ErrInvalidToken is every refusal of a token's text: one that does not
// parse, one Wappie holds no selector of, a secret that does not match, and
// a token that is not live. A caller answers each with its transport's one
// token 401, whatever the cause.
var ErrInvalidToken = errors.New("store: the token is expired, revoked or invalid")

// TokenAuth is a token that authenticated. It is comparable: a fresh
// ForAuth of an unchanged token equals the first, and one that narrowed
// since has a new Version. The zero value is no token.
type TokenAuth struct {
	ID       uuid.UUID
	Selector string
	Tenant   uuid.UUID
	// Version is the token row's access_version: every narrowing bumps it.
	Version int64
	// CreatedBy is the record's created_by, a platform sub.
	CreatedBy uuid.UUID
}

// IsZero reports whether a is no token.
func (a TokenAuth) IsZero() bool { return a.ID == uuid.Nil }

// The classes of a refused token text, for the failure limits only.
const (
	// TokenFailParse: the text is not a token (kc.ParseToken refused it).
	TokenFailParse = "parse"
	// TokenFailUnknown: Wappie holds no selector of it.
	TokenFailUnknown = "unknown"
	// TokenFailMismatch: the selector is known and the secret is wrong.
	TokenFailMismatch = "mismatch"
	// TokenFailState: the secret matched and the token is not live.
	TokenFailState = "state"
)

// TokenFailure says why ForAuth refused, for the failure limits and the
// usage counters only: never for an answer, which is the one token 401.
// Token is set once the secret matched, and Code then is the usage code
// (revoked, expired, suspended_here), or empty for a refusal that counts
// nothing.
type TokenFailure struct {
	Class    string
	Code     string
	Token    uuid.UUID
	Selector string
}

// TokenSwitches is the operator's configuration beneath each workspace's
// own text and attachments switches: WS_MCP_WORKSPACE_DEFAULT for a
// workspace that set none, and WS_MCP_DENY_TENANTS, refused whatever they
// set. The same in every process, so token auth reads the workspaces' own
// columns in SQL beside them and never loads anything at start.
type TokenSwitches struct {
	Default bool
	Deny    []uuid.UUID
}

// deny is the deny list as a parameter: never a nil slice, which pgx sends
// as NULL.
func (s TokenSwitches) deny() []uuid.UUID {
	if s.Deny == nil {
		return []uuid.UUID{}
	}
	return s.Deny
}

// TokenNeed is what a token asks of a number: an action, and for a read,
// whether it fetches an attachment (/v1/media, media.retry,
// media.expired), which the attachments switch also gates.
type TokenNeed struct {
	Action DeviceAction
	Media  bool
}

// TokenVerdict is Allows' answer for one act on one number. Code and Perm
// are set on a refusal that counts (the plan's 4.3 table); a refusal with
// no code counts nothing: the token is no longer live or narrowed (Live
// false), or the number is not one of its workspace's (Number false).
type TokenVerdict struct {
	OK      bool
	Live    bool
	Number  bool
	Code    string
	Perm    string
	MediaOn bool
}

// TokenLive is what a token reaches now: the numbers it reads, sends on and
// manages, for a socket's checks, the listings and a media stream's
// re-check. Live false closes a socket and ends a stream; a closed
// workspace or a switch empties the sets and closes nothing, so each act is
// then refused and counted with its code.
type TokenLive struct {
	Live    bool
	Closed  bool
	MediaOn bool
	// Reads: an applied read, a grant at the number's current epoch, the
	// text switch on, the workspace open.
	Reads map[uuid.UUID]struct{}
	// Sends and Manages: an applied send or manage, a fresh token feed,
	// the workspace open.
	Sends   map[uuid.UUID]struct{}
	Manages map[uuid.UUID]struct{}
}

// TokenFresh is how old the token feed's published_through may be for a
// token to send or manage (the plan's 3.3): older, those acts are refused
// as stale_feed. Reads are never gated by it.
const TokenFresh = time.Hour

// tokenLiveParts are the parts of the one predicate of a live token (the
// plan's 3.1), each a SQL text over contract_tokens t, with the token's id
// and workspace as expressions: tokenLiveSQL is their AND, and ForAuth
// selects each as a column, so neither can drift from the other. Each part
// is written so that a missing token row (a LEFT JOIN from its selector,
// once retention forgot it) still reads the sticky row by id.
type tokenLiveParts struct {
	// NotRevoked: no revocation on the row nor in the sticky set.
	NotRevoked string
	// NotExpired: before expires_at, and no sticky expiry at or before now.
	NotExpired string
	// Listed: the row exists and the platform still lists it.
	Listed string
	// Modes: tokens on and caught up, and the contract not off.
	Modes string
	// NotSuspended: none of Wappie's own stops (tokenSuspendedSQL).
	NotSuspended string
	// Belt: the creator's stored account document keeps the workspace, and
	// no disable or recovery came after the token.
	Belt string
	// TenantActive: the workspace is active.
	TenantActive string
}

func newTokenLiveParts(now, id, tenant string) tokenLiveParts {
	r := strings.NewReplacer("{now}", now, "{id}", id, "{tenant}", tenant)
	return tokenLiveParts{
		NotRevoked: r.Replace(`(t.revoked_at IS NULL
	AND NOT EXISTS (SELECT 1 FROM contract_token_sticky k WHERE k.token_id = {id} AND (k.revoked_at IS NOT NULL OR k.ended = 'revoked')))`),
		NotExpired: r.Replace(`(coalesce(t.expires_at > {now}::timestamptz, true)
	AND NOT EXISTS (SELECT 1 FROM contract_token_sticky k WHERE k.token_id = {id} AND (k.earliest_expires_at <= {now}::timestamptz OR k.ended = 'expired')))`),
		Listed: r.Replace(`(t.id IS NOT NULL AND t.unlisted_at IS NULL
	AND NOT EXISTS (SELECT 1 FROM contract_token_sticky k WHERE k.token_id = {id} AND k.ended = 'unlisted'))`),
		Modes: `EXISTS (SELECT 1 FROM contract_token_state ts0 CROSS JOIN contract_state cs0
	WHERE ts0.mode = 'on' AND ts0.caught_up_at IS NOT NULL AND cs0.mode <> 'off')`,
		NotSuspended: r.Replace(`NOT EXISTS (SELECT 1 FROM (` + tokenSuspendedSQL + `) x WHERE x.token_id = {id})`),
		Belt: `NOT EXISTS (SELECT 1 FROM contract_accounts a WHERE a.sub = t.created_by AND a.doc IS NOT NULL
	AND (a.disabled_at > t.created_at OR a.credentials_revoked_at > t.created_at
	     OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(a.doc->'workspaces') = 'array'
	                                                       THEN a.doc->'workspaces' ELSE '[]' END) aw
	                    WHERE aw->>'id' = t.tenant_id::text)))`,
		TenantActive: r.Replace(`EXISTS (SELECT 1 FROM tenants tw WHERE tw.id = {tenant} AND tw.status = 'active')`),
	}
}

func (p tokenLiveParts) all() []string {
	return []string{p.NotRevoked, p.NotExpired, p.Listed, p.Modes, p.NotSuspended, p.Belt, p.TenantActive}
}

// tokenLiveSQL is the one predicate of a live token (the plan's 3.1), over
// contract_tokens t in the statement's workspace (app.tenant_id), now being
// Wappie's clock as the parameter named: not revoked, unlisted or expired,
// and nothing sticky; tokens on, caught up, and the contract not off, read
// in the statement and never from a cache; no stop of Wappie's own
// (tokenSuspendedSQL: the operator's, apply_failed, creator_disabled_here,
// local_rule); the belt (the creator's stored account document drops the
// workspace, or a disable or a recovery came after the token); and an
// active workspace. Token auth, the socket's check, the grant write and
// the snapshot share it, part by part (tokenLiveParts).
func tokenLiveSQL(now string) string {
	return "(" + strings.Join(newTokenLiveParts(now, "t.id", "t.tenant_id").all(), "\n\tAND ") + ")"
}

// tokenSwitchSQL is a workspace's text or attachments switch for tokens:
// its own column, or the operator's default when it set none, and never on
// the deny list. w is the tenants row, t the token.
func tokenSwitchSQL(column, def, deny string) string {
	return `(coalesce(w.` + column + `, ` + def + `::boolean) AND NOT (t.tenant_id = ANY(` + deny + `::uuid[])))`
}

// tokenFreshSQL is the token feed's freshness, at now: published_through
// under an hour old by Wappie's clock.
func tokenFreshSQL(now string) string {
	return `coalesce(ts.published_through > ` + now + `::timestamptz - interval '1 hour', false)`
}

// tokenClosedSQL is a closed workspace: its stored workspace document says
// closed, at observe too (0040).
const tokenClosedSQL = `EXISTS (SELECT 1 FROM contract_workspaces cw WHERE cw.workspace_id = t.tenant_id AND cw.status = 'closed')`

// ForAuth verifies a token's text and judges it, at now (the plan's 3.1):
//  1. the text is parsed; one that does not parse is still compared with
//     the kit's dummy, so it costs what a wrong one costs;
//  2. one index probe of its selector, with no row-level security;
//  3. kc.VerifyToken compares the selector and the hash in constant time,
//     with the dummy when Wappie holds no selector;
//  4. only after a match, one statement in the token's workspace reads
//     each part of the one predicate (tokenLiveParts) from the selector's
//     row, with a LEFT JOIN to the token's, so a token whose row retention
//     forgot still reads its sticky revocation or expiry.
//
// Every refusal is ErrInvalidToken, with a TokenFailure for the limits and
// the counters only. Another error is the database's.
func (t *Tokens) ForAuth(ctx context.Context, text string, now time.Time) (TokenAuth, TokenFailure, error) {
	parsed, err := kc.ParseToken(text)
	if err != nil {
		//nolint:errcheck // the dummy compare: only its cost matters
		_ = kc.VerifyToken(nil, text)
		return TokenAuth{}, TokenFailure{Class: TokenFailParse}, ErrInvalidToken
	}
	fail := TokenFailure{Selector: parsed.Selector}
	var id, tenant uuid.UUID
	var hash []byte
	err = t.pool.QueryRow(ctx, `SELECT token_id, tenant_id, hash FROM contract_token_selectors WHERE selector = $1`,
		parsed.Selector).Scan(&id, &tenant, &hash)
	var rec *kc.TokenRecord
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return TokenAuth{}, fail, err
	default:
		rec = &kc.TokenRecord{Selector: parsed.Selector, Hash: hex.EncodeToString(hash)}
	}
	if err := kc.VerifyToken(rec, text); err != nil || rec == nil {
		fail.Class = TokenFailUnknown
		if rec != nil {
			fail.Class = TokenFailMismatch
		}
		return TokenAuth{}, fail, ErrInvalidToken
	}
	fail.Class, fail.Token = TokenFailState, id

	parts := newTokenLiveParts("$2", "s.token_id", "s.tenant_id")
	var present bool
	var version int64
	var createdBy *uuid.UUID
	var notRevoked, notExpired, listed, modes, notSuspended, belt, active bool
	err = pg.InTenantTx(ctx, t.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT t.id IS NOT NULL, coalesce(t.access_version, 0), t.created_by,
				coalesce(`+parts.NotRevoked+`, false), coalesce(`+parts.NotExpired+`, false), coalesce(`+parts.Listed+`, false),
				coalesce(`+parts.Modes+`, false), coalesce(`+parts.NotSuspended+`, false), coalesce(`+parts.Belt+`, false),
				coalesce(`+parts.TenantActive+`, false)
			FROM contract_token_selectors s LEFT JOIN contract_tokens t ON t.id = s.token_id
			WHERE s.selector = $1`, parsed.Selector, now).
			Scan(&present, &version, &createdBy, &notRevoked, &notExpired, &listed, &modes, &notSuspended, &belt, &active)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// Retention deleted the selector between the two reads.
		return TokenAuth{}, fail, ErrInvalidToken
	}
	if err != nil {
		return TokenAuth{}, fail, err
	}
	if present && notRevoked && notExpired && listed && modes && notSuspended && belt && active && createdBy != nil {
		return TokenAuth{ID: id, Selector: parsed.Selector, Tenant: tenant, Version: version, CreatedBy: *createdBy}, TokenFailure{}, nil
	}
	// The usage code (the plan's 3.6), in this order: revoked (the belt
	// counts as revoked), expired, suspended_here. An unlisted token counts
	// nothing; nor do tokens off, the contract off or an inactive workspace,
	// which are Wappie's state and not the token's. A row retention forgot
	// still counts its sticky revocation or expiry.
	switch {
	case present && !listed:
	case !notRevoked || (present && !belt):
		fail.Code = kc.UseRevoked
	case !notExpired:
		fail.Code = kc.UseExpired
	case present && !notSuspended:
		fail.Code = kc.UseSuspendedHere
	}
	return TokenAuth{}, fail, ErrInvalidToken
}

// usagePerm is the usage perm of an action: read for read and view, send,
// and manage for manage and pause (the kit's set).
func usagePerm(a DeviceAction) string {
	switch a {
	case ActionSend:
		return kc.CanSend
	case ActionManage, ActionPause:
		return kc.CanManage
	}
	return kc.CanRead
}

// Allows judges one act of a token on a number, at now, in one statement
// under its workspace (the plan's 4.3). The token must still be live with
// the version it authenticated with, and the number one of its workspace's,
// not deleted; then, the first test that fails gives the code:
// workspace_closed; for a read (view is read), no_permission without an
// applied read, switch_off with the text switch off (or, fetching an
// attachment, the attachments switch), no_grant without a grant to its
// identity at the number's current epoch; for send, manage and pause (pause
// is manage), no_permission without the applied perm and stale_feed when
// the token feed is over an hour old.
func (t *Tokens) Allows(ctx context.Context, tok TokenAuth, device uuid.UUID, need TokenNeed, sw TokenSwitches, now time.Time) (TokenVerdict, error) {
	var version int64
	var live, number, closed, textOn, mediaOn, fresh, canRead, canSend, canManage, hasGrant bool
	err := pg.InTenantTx(ctx, t.pool, tok.Tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT t.access_version, `+tokenLiveSQL("$3")+`,
				d.id IS NOT NULL, `+tokenClosedSQL+`,
				`+tokenSwitchSQL("mcp_text", "$4", "$5")+`, `+tokenSwitchSQL("mcp_media", "$4", "$5")+`,
				`+tokenFreshSQL("$3")+`,
				EXISTS (SELECT 1 FROM contract_token_perms p WHERE p.token_id = t.id AND p.device_id = d.id AND p.perm = 'read' AND p.state = 'applied'),
				EXISTS (SELECT 1 FROM contract_token_perms p WHERE p.token_id = t.id AND p.device_id = d.id AND p.perm = 'send' AND p.state = 'applied'),
				EXISTS (SELECT 1 FROM contract_token_perms p WHERE p.token_id = t.id AND p.device_id = d.id AND p.perm = 'manage' AND p.state = 'applied'),
				t.identity_dropped_at IS NULL AND EXISTS (SELECT 1 FROM device_key_grants g
					WHERE g.user_id = t.identity_user_id AND g.device_id = d.id AND g.epoch = d.current_epoch)
			FROM contract_tokens t
			JOIN tenants w ON w.id = t.tenant_id
			CROSS JOIN contract_token_state ts
			LEFT JOIN devices d ON d.id = $2
			WHERE t.id = $1`, tok.ID, device, now, sw.Default, sw.deny()).
			Scan(&version, &live, &number, &closed, &textOn, &mediaOn, &fresh, &canRead, &canSend, &canManage, &hasGrant)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return TokenVerdict{}, nil
	}
	if err != nil {
		return TokenVerdict{}, err
	}
	if !live || version != tok.Version {
		return TokenVerdict{}, nil
	}
	v := TokenVerdict{Live: true, Number: number, MediaOn: mediaOn, Perm: usagePerm(need.Action)}
	if !number {
		v.Perm = ""
		return v, nil
	}
	refuse := func(code string) (TokenVerdict, error) {
		v.Code = code
		return v, nil
	}
	if closed {
		return refuse(kc.UseWorkspaceClosed)
	}
	switch need.Action {
	case ActionRead, ActionView:
		switch {
		case !canRead:
			return refuse(kc.UseNoPermission)
		case !textOn || (need.Media && !mediaOn):
			return refuse(kc.UseSwitchOff)
		case !hasGrant:
			return refuse(kc.UseNoGrant)
		}
	case ActionSend:
		switch {
		case !canSend:
			return refuse(kc.UseNoPermission)
		case !fresh:
			return refuse(kc.UseStaleFeed)
		}
	case ActionManage, ActionPause:
		switch {
		case !canManage:
			return refuse(kc.UseNoPermission)
		case !fresh:
			return refuse(kc.UseStaleFeed)
		}
	default:
		return refuse(kc.UseNoPermission)
	}
	v.OK, v.Perm = true, ""
	return v, nil
}

// ConnectionToken is what a token reaches now (TokenLive), in one
// statement under its workspace (the plan's 4.4): the same parts as Allows,
// over every number its perms name that is still its workspace's.
func (t *Tokens) ConnectionToken(ctx context.Context, tok TokenAuth, sw TokenSwitches, now time.Time) (TokenLive, error) {
	var version int64
	var live, closed, textOn, mediaOn, fresh bool
	var reads, sends, manages []uuid.UUID
	err := pg.InTenantTx(ctx, t.pool, tok.Tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT t.access_version, `+tokenLiveSQL("$2")+`, `+tokenClosedSQL+`,
				`+tokenSwitchSQL("mcp_text", "$3", "$4")+`, `+tokenSwitchSQL("mcp_media", "$3", "$4")+`,
				`+tokenFreshSQL("$2")+`,
				coalesce((SELECT array_agg(p.device_id) FROM contract_token_perms p JOIN devices d ON d.id = p.device_id
					WHERE p.token_id = t.id AND p.perm = 'read' AND p.state = 'applied' AND t.identity_dropped_at IS NULL
					  AND EXISTS (SELECT 1 FROM device_key_grants g WHERE g.user_id = t.identity_user_id
					                 AND g.device_id = d.id AND g.epoch = d.current_epoch)), '{}'::uuid[]),
				coalesce((SELECT array_agg(p.device_id) FROM contract_token_perms p JOIN devices d ON d.id = p.device_id
					WHERE p.token_id = t.id AND p.perm = 'send' AND p.state = 'applied'), '{}'::uuid[]),
				coalesce((SELECT array_agg(p.device_id) FROM contract_token_perms p JOIN devices d ON d.id = p.device_id
					WHERE p.token_id = t.id AND p.perm = 'manage' AND p.state = 'applied'), '{}'::uuid[])
			FROM contract_tokens t
			JOIN tenants w ON w.id = t.tenant_id
			CROSS JOIN contract_token_state ts
			WHERE t.id = $1`, tok.ID, now, sw.Default, sw.deny()).
			Scan(&version, &live, &closed, &textOn, &mediaOn, &fresh, &reads, &sends, &manages)
	})
	out := TokenLive{Reads: map[uuid.UUID]struct{}{}, Sends: map[uuid.UUID]struct{}{}, Manages: map[uuid.UUID]struct{}{}}
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if !live || version != tok.Version {
		return out, nil
	}
	out.Live, out.Closed, out.MediaOn = true, closed, mediaOn
	if closed {
		return out, nil
	}
	if textOn {
		for _, d := range reads {
			out.Reads[d] = struct{}{}
		}
	}
	if fresh {
		for _, d := range sends {
			out.Sends[d] = struct{}{}
		}
		for _, d := range manages {
			out.Manages[d] = struct{}{}
		}
	}
	return out, nil
}
