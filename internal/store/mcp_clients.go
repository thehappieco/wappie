package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// Any MCP client (docs/mcp-enclave.md §19.20): who a connection is for, the
// new-assistant notice's bookkeeping, and the revoke-only link.

// Client kinds, as mcp_connections.client_kind stores them.
const (
	// ClientLegacy is a connection made under 0.5.0's two-host allowlist,
	// before descriptors said who the client is.
	ClientLegacy = "legacy"
	// ClientCIMD identifies itself by a client metadata document.
	ClientCIMD = "cimd"
	// ClientDCR registered dynamically, at a pinned redirect only.
	ClientDCR = "dcr"
	// ClientToken is a console connection token (§19.18).
	ClientToken = "token"
	// ClientAI is an AI authorization (§18), the console's own.
	ClientAI = "ai"
)

// Trust tiers (§19.6).
const (
	TrustTested  = "tested"
	TrustUnknown = "unknown"
)

// Limits tiers (§19.3, §19.19): a tested client on the web, a tested app on
// the person's computer, any client Wappie has not tested, and a console
// token.
const (
	TierWebTested   = "web_tested"
	TierLocalTested = "local_tested"
	TierUnknown     = "unknown"
	TierToken       = "token"
)

// TokenRedirectHost is a console token's redirect_host: it redirects
// nowhere.
const TokenRedirectHost = "token"

// HistoryDayChoices are the history windows an unknown client or a token
// may be given, the image's history_days.choices.
var HistoryDayChoices = []int{7, 30, 90}

// ErrMCPClient means a consent's client fields do not hold together; the
// handler checks them first, so this is the backstop.
var ErrMCPClient = errors.New("store: the connection's client fields do not hold together")

// clientHostPattern is the column's own CHECK.
var clientHostPattern = regexp.MustCompile(`^[a-z0-9.-]{4,253}$`)

// LimitsTier is the limits tier a connection's trust, locality and kind
// give (§19.6): a token's, an unknown client's, a tested app's on the
// person's computer, and otherwise a tested web client's, which a legacy
// row and an AI authorization keep.
func LimitsTier(trust string, local bool, clientKind string) string {
	switch {
	case clientKind == ClientToken:
		return TierToken
	case trust == TrustUnknown:
		return TierUnknown
	case local:
		return TierLocalTested
	}
	return TierWebTested
}

// Lifetime ceilings (§19.19), this server's copy: a tested web client's are
// the ones before 0.6.0, every other tier's are ninety days for metadata and
// thirty for text, each with an hour for the console's clock.
const (
	shortMetadataLifetime = 90*24*time.Hour + time.Hour
	shortContentLifetime  = 30*24*time.Hour + time.Hour
)

// MaxLifetime is the furthest a consent of this kind and limits tier may
// run.
func MaxLifetime(kind, tier string) time.Duration {
	content := kind == KindContent || kind == KindAI
	if tier == TierWebTested {
		if content {
			return maxContentLifetime
		}
		return maxKeyLifetime
	}
	if content {
		return shortContentLifetime
	}
	return shortMetadataLifetime
}

// checkClient holds a consent's client fields together and fills in the
// defaults: an AI authorization is ClientAI with no trust, and a consent
// with no kind is a legacy one of the allowlist, tested. What each kind
// carries:
//   - legacy: no client id, host, claimed name or history window, and a
//     content consent of version 1 to 3;
//   - cimd: an https client id and a host; dcr: a host and no client id;
//   - token: no client id, host or locality, unknown, and redirect_host
//     "token";
//   - cimd, dcr and token: a content consent of version 4;
//   - unknown: a history window from HistoryDayChoices; tested: none;
//   - unknown or local: no sending (I4).
func checkClient(in *CreateMCPConnection) error {
	bad := func(msg string) error { return fmt.Errorf("%w: %s", ErrMCPClient, msg) }
	if in.Kind == KindAI {
		if in.ClientKind == "" {
			in.ClientKind = ClientAI
		}
		if in.ClientKind != ClientAI || in.Trust != "" || in.ClientID != "" || in.ClientHost != "" || in.ClientLocal ||
			in.ClaimedName != "" || in.HistoryDays != 0 {
			return bad("an AI authorization carries no client fields")
		}
		return nil
	}
	if in.ClientKind == "" {
		in.ClientKind = ClientLegacy
	}
	if in.ClientKind == ClientLegacy && in.Trust == "" {
		in.Trust = TrustTested
	}
	content := in.Kind == KindContent
	switch in.ClientKind {
	case ClientLegacy:
		if in.Trust != TrustTested || in.ClientID != "" || in.ClientHost != "" || in.ClaimedName != "" {
			return bad("a legacy connection is tested and carries no client id, host or claimed name")
		}
		if content && in.ConsentVersion == ClientConsentVersion {
			return bad("consent version 4 is for a client a 0.6.0 reader described")
		}
	case ClientCIMD, ClientDCR, ClientToken:
		if content && in.ConsentVersion != ClientConsentVersion {
			return bad("a content consent to a 0.6.0 reader is version 4")
		}
	default:
		return bad("client_kind is not a kind")
	}
	switch in.ClientKind {
	case ClientCIMD:
		if !strings.HasPrefix(in.ClientID, "https://") || len(in.ClientID) > 512 || !clientHostPattern.MatchString(in.ClientHost) {
			return bad("a CIMD client has an https client id and a host")
		}
	case ClientDCR:
		if in.ClientID != "" || !clientHostPattern.MatchString(in.ClientHost) || in.ClientLocal {
			return bad("a DCR client has a host, no stored client id and no loopback redirect")
		}
	case ClientToken:
		if in.Trust != TrustUnknown || in.ClientID != "" || in.ClientHost != "" || in.ClientLocal || in.ClaimedName != "" ||
			in.RedirectHost != TokenRedirectHost {
			return bad("a token is unknown, local to nothing, and redirects nowhere")
		}
	}
	if in.ClientKind != ClientToken && in.RedirectHost == TokenRedirectHost {
		return bad("only a token redirects nowhere")
	}
	switch in.Trust {
	case TrustTested:
		if in.HistoryDays != 0 {
			return bad("a tested client reads the whole history")
		}
	case TrustUnknown:
		if !slices.Contains(HistoryDayChoices, in.HistoryDays) {
			return bad("an untested client or a token reads 7, 30 or 90 days")
		}
	default:
		return bad("trust is tested or unknown")
	}
	if utf8.RuneCountInString(in.ClaimedName) > 100 {
		return bad("claimed_name is 100 characters at most")
	}
	if (in.Trust == TrustUnknown || in.ClientLocal) && (in.SendMode != "" || in.SendSelf || in.SendGroups) {
		return bad("an untested client, a token or an app on the person's computer never sends")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Seen, and the notice
// ---------------------------------------------------------------------------

// MarkSeen records that viewer saw one of the workspace's connections, for
// the new-assistant banner. Idempotent. An id that is not one of the
// workspace's assistant connections is ErrMCPConnectionNotFound.
func (m *MCPConnections) MarkSeen(ctx context.Context, tenant, viewer uuid.UUID, id string) error {
	return pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO mcp_connection_seen (connection_id, tenant_id, user_id)
			SELECT c.id, c.tenant_id, $3 FROM mcp_connections c WHERE c.id = $1 AND c.tenant_id = $2 AND c.kind <> 'ai'
			ON CONFLICT (connection_id, user_id) DO NOTHING`, id, tenant, viewer)
		if err != nil {
			return fmt.Errorf("store: mark mcp connection seen: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mcp_connections WHERE id=$1 AND tenant_id=$2 AND kind <> 'ai')`,
			id, tenant).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrMCPConnectionNotFound
		}
		return nil
	})
}

// Notice events (mcp_connection_notices.event): a connection's activation,
// and each reading limit its reader says it reached (docs/mcp-enclave.md
// §19.19), by the budget_hit code.
const NoticeActivated = "activated"

// BudgetHitCodes are the budget_hit codes a reader reports: the daily and
// first-hour budgets of messages and attachments, and a token's call from
// outside its allowed networks.
var BudgetHitCodes = []string{"daily_messages", "daily_attachments", "first_hour_messages", "first_hour_attachments", "network"}

// maxNoticeMailsPerDay bounds the notice e-mails of one workspace in a
// rolling day, whatever raised them (§19.22).
const maxNoticeMailsPerDay = 20

// MCPNotice is what a new-assistant notice says about a connection
// (docs/mcp-enclave.md §19.22), and who it goes to. It never holds the
// client's claimed name.
type MCPNotice struct {
	ConnectionID string
	TenantID     uuid.UUID
	// Event is NoticeActivated or a budget_hit code; First says the
	// connection raised it for the first time, which is when an e-mail may
	// go.
	Event string
	First bool
	// Kind is KindMetadata or KindContent, Media whether attachments too.
	Kind  string
	Media bool
	// ClientKind and Trust are as listed; ClientHost the verified host, or
	// for a row without one the redirect host; ClientName the verified
	// display name (a token's label).
	ClientKind, Trust, ClientHost, ClientName string
	ClientLocal                               bool
	DeviceCount                               int
	ExpiresAt                                 time.Time
	HistoryDays                               int
	CreatedBy                                 uuid.UUID
	// Recipients are the person who consented and the workspace's owners,
	// active, whose address is verified, each once.
	Recipients []string
}

// RaiseNotice records that one of a reader's live connections raised a
// notice, and returns what the notice says and who it goes to. Every mark
// the workspace's managers left on the connection is forgotten, so the
// console's banner shows it again. Another reader's, an ended one and an AI
// authorization are ErrMCPConnectionNotFound.
func (m *MCPConnections) RaiseNotice(ctx context.Context, reader, id, event string) (MCPNotice, error) {
	if event != NoticeActivated && !slices.Contains(BudgetHitCodes, event) {
		return MCPNotice{}, fmt.Errorf("store: %q is not a notice event", event)
	}
	tenant, err := m.tenantOf(ctx, reader, id)
	if err != nil {
		return MCPNotice{}, err
	}
	n := MCPNotice{ConnectionID: id, TenantID: tenant, Event: event}
	err = pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT kind, media, client_kind, coalesce(trust, ''), coalesce(client_host, redirect_host),
			       client_name, client_local, device_count, expires_at, coalesce(history_days, 0), created_by
			  FROM mcp_connections
			 WHERE id=$1 AND tenant_id=$2 AND reader=$3 AND kind <> 'ai' AND status IN ('pending','active','reseal')
			   FOR UPDATE`, id, tenant, reader).
			Scan(&n.Kind, &n.Media, &n.ClientKind, &n.Trust, &n.ClientHost, &n.ClientName, &n.ClientLocal, &n.DeviceCount,
				&n.ExpiresAt, &n.HistoryDays, &n.CreatedBy)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMCPConnectionNotFound
		}
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO mcp_connection_notices (connection_id, tenant_id, event) VALUES ($1, $2, $3)
			ON CONFLICT (connection_id, event) DO UPDATE SET last_at = now(), count = mcp_connection_notices.count + 1
			RETURNING count = 1`, id, tenant, event).Scan(&n.First); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mcp_connection_seen WHERE connection_id=$1 AND tenant_id=$2`, id, tenant); err != nil {
			return err
		}
		n.Recipients, err = noticeRecipientsTx(ctx, tx, tenant, n.CreatedBy)
		return err
	})
	if err != nil {
		return MCPNotice{}, fmt.Errorf("store: raise mcp notice: %w", err)
	}
	return n, nil
}

// ClaimNoticeMail decides whether a notice's e-mail may go: its connection
// is still live, no e-mail went for this connection and event before, and
// the workspace sent fewer than twenty in the last day. A claim is recorded
// at once, with the hash of the revoke-only link the e-mail carries, which
// replaces the connection's previous one; the e-mail goes after, and one that
// fails is not sent again. False with no error is a refusal.
func (m *MCPConnections) ClaimNoticeMail(ctx context.Context, tenant uuid.UUID, id, event, revokeLinkSHA256 string) (bool, error) {
	if !revokeLinkPattern.MatchString(revokeLinkSHA256) {
		return false, errors.New("store: a revoke link is stored as its SHA-256 in lower-case hex")
	}
	claimed := false
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		// One workspace's claims run one after the other, so two notices at
		// once cannot both take the twentieth e-mail.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "mcp-notices/"+tenant.String()); err != nil {
			return err
		}
		var sent int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM mcp_connection_notices
			WHERE tenant_id=$1 AND mailed_at > now() - interval '1 day'`, tenant).Scan(&sent); err != nil {
			return err
		}
		if sent >= maxNoticeMailsPerDay {
			return nil
		}
		tag, err := tx.Exec(ctx, `UPDATE mcp_connection_notices SET mailed_at = now()
			WHERE connection_id=$1 AND tenant_id=$2 AND event=$3 AND mailed_at IS NULL`, id, tenant, event)
		if err != nil || tag.RowsAffected() != 1 {
			return err
		}
		tag, err = tx.Exec(ctx, `UPDATE mcp_connections SET revoke_link_sha256=$3
			WHERE id=$1 AND tenant_id=$2 AND kind <> 'ai' AND status IN ('pending','active','reseal')`, id, tenant, revokeLinkSHA256)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			// It ended meanwhile: no e-mail, and the claim goes with the
			// transaction.
			return errNoticeEnded
		}
		claimed = true
		return nil
	})
	if errors.Is(err, errNoticeEnded) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: claim mcp notice mail: %w", err)
	}
	return claimed, nil
}

// errNoticeEnded rolls a claim back for a connection that ended.
var errNoticeEnded = errors.New("store: the connection ended")

// noticeRecipientsTx are the person who consented and the workspace's
// owners, active members with a verified address, each address once, in
// order. The caller holds the tenant transaction.
func noticeRecipientsTx(ctx context.Context, tx pgx.Tx, tenant, consented uuid.UUID) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT u.email
		  FROM users u JOIN workspace_memberships m ON m.user_id = u.id AND m.tenant_id = $1
		 WHERE u.status = 'active' AND m.status = 'active' AND (m.expires_at IS NULL OR m.expires_at > now())
		   AND (u.id = $2 OR m.role = 'owner') AND m.role <> 'service'
		   AND `+verifiedEmail+`
		 ORDER BY u.email`, tenant, consented)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// verifiedEmail is the condition that an account's address was confirmed:
// public sign-up consumed a verification sent to it (signup.go), whose
// completed row housekeeping keeps while the address has a login. An
// account made by invitation has none until it confirms another way.
const verifiedEmail = `EXISTS(SELECT 1 FROM email_signup_verifications v WHERE v.email = lower(u.email) AND v.completed_at IS NOT NULL)`

// EmailVerified reports whether an account's address is verified, the
// precondition for letting an untested client or a token read text
// (docs/mcp-enclave.md §19.21).
func (u *Users) EmailVerified(ctx context.Context, tenant, user uuid.UUID) (bool, error) {
	var verified bool
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT `+verifiedEmail+` FROM users u WHERE u.id = $1`, user).Scan(&verified)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: email verified: %w", err)
	}
	return verified, nil
}

// ---------------------------------------------------------------------------
// The revoke-only link
// ---------------------------------------------------------------------------

// revokeLinkPattern is a link token's SHA-256 in lower-case hex.
var revokeLinkPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// RevokeLinkTarget is what a revoke-only link would revoke: the verified
// host of its connection (the redirect host for a row without one, "" for a
// token, which has none), while the link is the latest one minted for a
// connection that is still live. A replaced, spent or unknown link is
// ErrMCPConnectionNotFound.
func (m *MCPConnections) RevokeLinkTarget(ctx context.Context, sha256Hex string) (host string, err error) {
	if !revokeLinkPattern.MatchString(sha256Hex) {
		return "", ErrMCPConnectionNotFound
	}
	err = m.pool.QueryRow(ctx, `SELECT CASE WHEN client_kind = 'token' THEN '' ELSE coalesce(client_host, redirect_host) END
		FROM mcp_connections WHERE revoke_link_sha256=$1 AND kind <> 'ai' AND status IN ('pending','active','reseal')`, sha256Hex).Scan(&host)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrMCPConnectionNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: revoke link: %w", err)
	}
	return host, nil
}

// RevokeByLink ends the one connection a revoke-only link names, with its
// key and, for content, its service account, as a console revocation does,
// and spends the link. It returns the connection and its reader, which is
// the one to tell. A replaced, spent or unknown link, and one whose
// connection already ended, is ErrMCPConnectionNotFound.
func (m *MCPConnections) RevokeByLink(ctx context.Context, sha256Hex string) (id, reader string, err error) {
	if !revokeLinkPattern.MatchString(sha256Hex) {
		return "", "", ErrMCPConnectionNotFound
	}
	var tenant uuid.UUID
	err = m.pool.QueryRow(ctx, `SELECT id::text, tenant_id, reader FROM mcp_connections WHERE revoke_link_sha256=$1 AND kind <> 'ai'`,
		sha256Hex).Scan(&id, &tenant, &reader)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrMCPConnectionNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("store: revoke link: %w", err)
	}
	err = pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockWorkspaceAccess(ctx, tx, tenant); err != nil {
			return err
		}
		// The link is spent in the same transaction that ends the
		// connection, and only if it is still this connection's.
		tag, err := tx.Exec(ctx, `UPDATE mcp_connections SET revoke_link_sha256=NULL
			WHERE id=$1 AND tenant_id=$2 AND revoke_link_sha256=$3`, id, tenant, sha256Hex)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrMCPConnectionNotFound
		}
		ended, err := endMCPConnectionTx(ctx, tx, tenant, id, statusRevoked, ReasonConsole)
		if err != nil {
			return err
		}
		if !ended {
			return ErrMCPConnectionNotFound
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return id, reader, nil
}

// StatusOf is where one of a workspace's assistant connections stands, as
// the ledger has it. An AI authorization, or another workspace's connection,
// is ErrMCPConnectionNotFound.
func (m *MCPConnections) StatusOf(ctx context.Context, tenant uuid.UUID, id string) (string, error) {
	var status string
	err := m.pool.QueryRow(ctx, `SELECT status FROM mcp_connections WHERE id=$1 AND tenant_id=$2 AND kind <> 'ai'`, id, tenant).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrMCPConnectionNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: mcp connection status: %w", err)
	}
	return status, nil
}
