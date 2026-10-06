// Package mcpauth is the Go side of the hosted assistant connector.
//
// A remote assistant (claude.ai, ChatGPT) reaches an archive through a
// reader process on this host that speaks MCP over HTTP and issues its own
// OAuth tokens. This server holds no token and opens no bundle: what it does
// is the part that needs the ledger. It records the consent a workspace
// owner gives, on a read-only API key restricted to named numbers; relays
// the sealed bundle from the browser to the reader over loopback, because
// the browser's connect-src allows this origin only; answers the reader's
// questions about a connection's standing; and, for a reader before 0.6.0,
// fetches client metadata documents on its behalf, since that reader has no
// network of its own. A 0.6.0 reader fetches them itself, over TLS it
// verifies, through the parent's egress proxy (cmd/cimd-egress), so that
// this server can refuse or delay a document but never forge one
// (docs/mcp-enclave.md §19.9); it describes each client in a version-2
// descriptor, which this server holds to the host predicate and the
// operator's switches (clients.go) and never to the two-host allowlist.
//
// Two audiences, two guards. The console routes take a signed-in session and
// leave owner-or-admin to the store, like membership changes. The internal
// routes take the relay secret and a loopback peer, and answer 404 to
// anything that came through the proxy — nginx says the same before it gets
// here, so the check is belt and braces.
//
// An attested reader runs in a Nitro Enclave on another machine and reaches
// the same questions through /v1/mcp/enclave/*, with a signed request from a
// configured address instead of a loopback bearer (see enclave.go). Several
// readers may be configured; a pending request belongs to whichever reader
// answers for its id, and a connection to the reader recorded on its row.
package mcpauth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"whatserver2/internal/mailer"
	"whatserver2/internal/netguard"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/stepup"
	"whatserver2/internal/store"
)

// Handler serves /v1/mcp.
type Handler struct {
	Connections *store.MCPConnections
	APIKeys     *store.APIKeys
	Users       *store.Users
	// Limits bounds the consent itself, per account: the sign-in budget,
	// because a consent is a privileged act. Nil allows everything, for
	// tests.
	Limits *ratelimit.Auth
	// DescriptorLimits bounds the public descriptor fetch, per request id.
	// Its own budget, and a roomier one: the console reads the descriptor
	// on every render of the consent card — first load, after sign-in,
	// after a workspace switch, on reload — and none of that is a guess at
	// a password. Nil allows everything.
	DescriptorLimits *ratelimit.Auth
	// Reader is the loopback relay to the hosted reader process; nil when
	// the hosted reader is not configured.
	Reader *Relay
	// PublicOrigin is where the hosted reader is served from the internet;
	// the console posts its proof to PublicOrigin/mcp/authorize/complete.
	PublicOrigin string
	// RelaySecret is what the hosted reader presents on the internal routes.
	RelaySecret string
	// Attested are the readers off this host, each with its own relay,
	// secrets, peers and tenants.
	Attested []*AttestedReader
	// TrustedProxies are the proxies whose X-Forwarded-For names an
	// attested reader's address; the peer check reads through them.
	TrustedProxies []netip.Prefix
	// States keeps the attested readers' sealed state.
	States *store.MCPReaderStates
	// RedirectHosts are the hosts an assistant may redirect to and whose
	// metadata documents may be fetched, for a reader before 0.6.0: a
	// version-1 descriptor's consent is checked against them. Same list as
	// that reader's.
	RedirectHosts []string
	// CIMDTransport carries metadata fetches; nil is the default. Tests
	// hand in one that answers locally.
	CIMDTransport http.RoundTripper
	Log           *slog.Logger
	// OpenAIAppsChallenge is served at /.well-known/openai-apps-challenge for
	// OpenAI's plugin portal to verify the domain; empty means 404.
	OpenAIAppsChallenge string
	// ContentReader is the attested reader content connections may be held
	// by; empty allows content nowhere.
	ContentReader string
	// ContentAllowed reports whether a workspace may have content
	// connections right now: the kill switch and the workspace allowlist.
	// Nil allows none. It is asked on every consent, renewal and status
	// check, so turning the switch off reaches live connections too.
	ContentAllowed func(tenant uuid.UUID) bool
	// MediaAllowed reports whether a workspace's content connections that
	// consented to attachments may open them right now: the media switch
	// and its workspace list, on top of ContentAllowed. Nil allows none.
	// It is asked on every media consent and status check.
	MediaAllowed func(tenant uuid.UUID) bool
	// MediaOff are the attachment kinds switched off everywhere, sorted;
	// every attested status answer carries them.
	MediaOff []string
	// SendAllowed reports whether a workspace's content connections that
	// consented to sending may draft and send right now: the send switch
	// and its workspace list, on top of ContentAllowed. SendSelfAllowed and
	// SendDirectAllowed are the same with the own-chat and direct switches.
	// Nil allows none. They are asked on every consent, status check, draft,
	// send and confirmation, never cached.
	SendAllowed       func(tenant uuid.UUID) bool
	SendSelfAllowed   func(tenant uuid.UUID) bool
	SendDirectAllowed func(tenant uuid.UUID) bool
	// SendLimits bound drafts and sends; a zero field is the image's
	// ceiling (store's defaults in sendLimits).
	SendLimits store.SendLimits
	// SendText sends a text as a number and archives it: the WebSocket's
	// send core, handed in by main. Nil sends nothing, and the send route
	// refuses every send.
	SendText func(ctx context.Context, in OutboundText) (OutboundSent, error)
	// AIAllowed reports whether a workspace may have AI integrations right
	// now: the AI switch and its workspace list, on top of MediaAllowed.
	// Nil allows none. It is asked on every AI consent, renewal, status
	// check and AI route, never cached.
	AIAllowed func(tenant uuid.UUID) bool
	// AIOffProviders and AIOffFeatures are the providers and functions
	// switched off everywhere, sorted; every AI status answer carries them,
	// and no consent or renewal may use them.
	AIOffProviders []string
	AIOffFeatures  []string
	// AI keeps the AI integrations' results and usage. Nil refuses the
	// reader's AI routes.
	AI *store.AI
	// UnknownAllowed is WS_MCP_CIMD_MODE=any: a client Wappie has not
	// tested, or a console token, may connect. BlockedClients are the
	// tested clients refused whatever the mode (WS_MCP_BLOCKED_CLIENTS),
	// and DCRHosts the hosts a registered client may be identified by
	// (WS_MCP_DCR_HOSTS). They only refuse (docs/mcp-enclave.md §19.21).
	UnknownAllowed bool
	BlockedClients []string
	DCRHosts       []string
	// MailNotice sends a new-assistant e-mail to one address, and
	// NoticeOrigin is this server's public origin, where its revoke-only
	// link points. Without both no notice e-mail goes, and so no untested
	// client or token is given text (§19.21, §19.22).
	MailNotice   func(ctx context.Context, to string, n mailer.MCPNotice) error
	NoticeOrigin string
	// MailRenewal sends a renewal notice to one address (renewals.go); nil
	// sends none, and the console's banner alone says it.
	MailRenewal func(ctx context.Context, to string, n mailer.MCPRenewal) error
	// LiveListLimits bounds the attested live list per workspace, and
	// RevokeLinkLimits the revoke-only link per address. Nil allows
	// everything, for tests.
	LiveListLimits   *ratelimit.Limiter
	RevokeLinkLimits *ratelimit.Auth
	// Workspaces are each workspace's own assistant switches, which its
	// owner sets in the console (docs/mcp-enclave.md §19.35); the gates
	// above are composed from them and the operator's configuration. Nil
	// leaves the console's switches route answering 404.
	Workspaces *WorkspaceSwitches
	// StepUp is what every write that hands an archive to a reader asks of
	// the person's session: a content consent, a token with text, an AI
	// authorization and their renewals (internal/stepup). Nil is the session
	// store's own record, Users'.
	StepUp stepup.Checker

	// Set up by Mount.
	readers  []reader
	requests *requestCache
	replay   *replayCache
	dropped  *refusalDrops
	// notices are the notice e-mails on their way, for WaitNotices.
	notices sync.WaitGroup
	// renewalTimer is the pending send of a renewal round's notices, and
	// renewalAfter what replaces renewalDelay in a test; zero is renewalDelay.
	renewalMu    sync.Mutex
	renewalTimer *time.Timer
	renewalAfter time.Duration
}

// Mount registers the routes on a mux. Call it once, after the fields are
// set: it takes the list of readers from them.
func (h *Handler) Mount(mux *http.ServeMux) {
	h.readers = h.configuredReaders()
	h.requests = newRequestCache()
	h.replay = newReplayCache(replayCap)
	h.dropped = newRefusalDrops()
	mux.HandleFunc("GET /v1/mcp/requests/{id}", h.descriptor)
	mux.HandleFunc("POST /v1/mcp/requests/{id}/prepare", h.prepare)
	mux.HandleFunc("POST /v1/mcp/connections", h.create)
	mux.HandleFunc("GET /v1/mcp/connections", h.list)
	mux.HandleFunc("DELETE /v1/mcp/connections/{id}", h.remove)
	mux.HandleFunc("POST /v1/mcp/connections/{id}/seen", h.seen)
	mux.HandleFunc("POST /v1/mcp/token-requests", h.tokenRequest)
	mux.HandleFunc("POST /v1/mcp/token-requests/{id}/bundle", h.tokenBundle)
	mux.HandleFunc("POST /v1/mcp/workspaces/{id}/live-list", h.liveList)
	mux.HandleFunc("GET /v1/mcp/revoke-link/{token}", h.revokeLinkPage)
	mux.HandleFunc("POST /v1/mcp/revoke-link/{token}", h.revokeLinkPost)
	mux.HandleFunc("POST /v1/mcp/connections/{id}/renewal", h.renewal)
	mux.HandleFunc("POST /v1/mcp/connections/{id}/renew", h.renew)
	mux.HandleFunc("GET /v1/mcp/content", h.content)
	h.mountWorkspaceSwitches(mux)
	h.mountSendConsole(mux)
	mux.HandleFunc("GET /v1/mcp/internal/connections/{id}", h.internal(h.status))
	mux.HandleFunc("POST /v1/mcp/internal/connections/{id}/activate", h.internal(h.activate))
	mux.HandleFunc("POST /v1/mcp/internal/connections/{id}/revoke", h.internal(h.revoke))
	mux.HandleFunc("GET /v1/mcp/internal/cimd", h.internal(h.cimd))
	if len(h.Attested) > 0 {
		h.mountEnclave(mux)
	}
	mux.HandleFunc("GET /.well-known/openai-apps-challenge", h.openAIChallenge)
}

func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// completePath is where the console posts its proof once the bundle is with
// the reader. Fixed, so the console can refuse anything else.
const completePath = "/mcp/authorize/complete"

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

// createRequest is a consent. The sealed bundle is opaque here: it was
// sealed in the browser to the reader's key named by kid, and this server
// only carries it across.
type createRequest struct {
	RequestID  string `json:"request_id"`
	KeyPrefix  string `json:"key_prefix"`
	ClientName string `json:"client_name"`
	ExpiresAt  string `json:"expires_at"`
	KID        string `json:"kid"`
	Sealed     string `json:"sealed"`
	// Kind is "metadata" (the default when absent) or "content". The four
	// fields after it are for content only, and absent for metadata.
	Kind           string `json:"kind"`
	ServiceUserID  string `json:"service_user_id"`
	KeyMode        string `json:"key_mode"`
	ConsentVersion int    `json:"consent_version"`
	// Media asks for attachments as well as text: consent version 2 or 3,
	// and the same value the browser sealed in the bundle, which the reader
	// compares with this one. Absent is false.
	Media bool `json:"media"`
	// Send asks for sending ("draft"; "direct" from S3), only on consent
	// version 3, which always carries it. SendSelf adds the own chat and
	// SendGroups groups for drafts. SendChats is direct send's list (S3).
	// The same values the browser sealed, which the reader compares.
	Send       string          `json:"send"`
	SendSelf   bool            `json:"send_self"`
	SendGroups bool            `json:"send_groups"`
	SendChats  json.RawMessage `json:"send_chats"`
	// AIConfig is an AI authorization's configuration (kind "ai" only): the
	// mirror of what the browser sealed, which this server checks and keeps.
	AIConfig json.RawMessage `json:"ai_config"`
	// The client, for a consent to a version-2 descriptor only
	// (docs/mcp-enclave.md §19.21): Trust, ClientHost, ClientLocal and
	// ClaimedName must equal the descriptor's, null claimed_name for none;
	// HistoryDays is the window an untested client reads (7, 30 or 90),
	// null for a tested one. All absent or null for version 1.
	Trust       *string `json:"trust"`
	ClientHost  *string `json:"client_host"`
	ClientLocal *bool   `json:"client_local"`
	ClaimedName *string `json:"claimed_name"`
	HistoryDays *int    `json:"history_days"`
	// Replace asks that, once this connection activates, the person's
	// earlier live connections of the same client in this workspace end
	// (docs/mcp-enclave.md §19.35): the card's pre-ticked "Replace my
	// previous connection". A version-2 descriptor's consent only; absent is
	// false.
	Replace bool `json:"replace"`
}

// hasClient reports whether a consent carries any of the version-2 client
// fields.
func (r createRequest) hasClient() bool {
	return r.Trust != nil || r.ClientHost != nil || r.ClientLocal != nil || r.ClaimedName != nil || r.HistoryDays != nil || r.Replace
}

type createReply struct {
	ID          string    `json:"id"`
	Status      string    `json:"status"`
	ExpiresAt   time.Time `json:"expires_at"`
	CompleteURL string    `json:"complete_url"`
}

// connectionInfo is one connection as the console lists it. No secret and
// no request id: the latter is the handle a browser used once.
type connectionInfo struct {
	ID           string     `json:"id"`
	ClientName   string     `json:"client_name"`
	RedirectHost string     `json:"redirect_host"`
	Status       string     `json:"status"`
	DeviceCount  int        `json:"device_count"`
	KeyPrefix    string     `json:"key_prefix"`
	CreatedAt    time.Time  `json:"created_at"`
	ActivatedAt  *time.Time `json:"activated_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
	// Kind is "metadata" or "content"; KeyMode and ConsentVersion are null
	// for metadata. Media says the consent includes attachments, whether or
	// not the workspace may open them right now.
	Kind           string  `json:"kind"`
	KeyMode        *string `json:"key_mode"`
	ConsentVersion *int    `json:"consent_version"`
	Media          bool    `json:"media"`
	// SendMode is the consent's sending, "draft" or "direct", null for none;
	// SendSelf and SendGroups its own chat and groups, SendPaused whether
	// the pause is on, and SendChats how many chats direct send's list holds.
	// The consent's, whatever the switches say now.
	SendMode   *string `json:"send_mode"`
	SendSelf   bool    `json:"send_self"`
	SendGroups bool    `json:"send_groups"`
	SendPaused bool    `json:"send_paused"`
	SendChats  int     `json:"send_chats"`
	// RevokeReason says why an ended connection ended; null otherwise.
	// RevokedAt is when a revoked one was, so the console allows the
	// reader's minute of status cache before calling a revoked connection
	// the verified reader still holds a hidden one (§19.22).
	RevokeReason *string    `json:"revoke_reason"`
	RevokedAt    *time.Time `json:"revoked_at"`
	// Renewable is set on a live content connection the viewer consented
	// to, while content is allowed for the workspace.
	Renewable bool `json:"renewable"`
	// The client (docs/mcp-enclave.md §19.21): ClientKind is legacy, cimd,
	// dcr or token; ClientID a client id document's address, null for
	// every other kind; ClientHost the verified host, null for a legacy
	// row and a token; Trust tested or unknown, null for a row written
	// before migration 0046 (Legacy, never Tested); ClaimedName what the
	// client called itself, null for none; HistoryDays the window an
	// untested client or a token reads, null for the whole history.
	ClientKind string  `json:"client_kind"`
	ClientID   *string `json:"client_id"`
	ClientHost *string `json:"client_host"`
	// Registrable is ClientHost's registrable domain, from the same
	// snapshot as the reader's, so the list can show the main domain (§19.22);
	// null with ClientHost.
	Registrable *string `json:"registrable"`
	ClientLocal bool    `json:"client_local"`
	Trust       *string `json:"trust"`
	ClaimedName *string `json:"claimed_name"`
	HistoryDays *int    `json:"history_days"`
	// FirstUsedAt is the first status check that answered active.
	FirstUsedAt *time.Time `json:"first_used_at"`
	// CreatedByEmail is the address of the person who consented, null
	// when the account is gone; Seen says the viewer marked the row seen,
	// for the console's new-assistant banner.
	CreatedByEmail *string `json:"created_by_email"`
	Seen           bool    `json:"seen"`
	// Mine says the viewer consented to it: the connections a reconnect of
	// theirs may replace (§19.35).
	Mine bool `json:"mine"`
	// BudgetHits are the reading limits the reader said this connection
	// reached, each with when it last did (§19.19).
	BudgetHits []store.BudgetHit `json:"budget_hits"`
}

type connectionsReply struct {
	Connections []connectionInfo `json:"connections"`
}

// statusReply answers the hosted reader's standing check.
type statusReply struct {
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
}

// attestedStatusReply answers an attested reader's: the standing, and which
// kind of connection it is and, for content, which service account it reads
// as, so the reader can drop a key that belongs to another. Media says
// whether the connection may open attachments right now, and MediaOff which
// kinds are off everywhere; a reader without attachments reads neither.
// Send says how it may send right now ("draft" or "direct", null for not at
// all) and SendSelf whether to its own chat; a reader without sending reads
// neither.
type attestedStatusReply struct {
	Status        string    `json:"status"`
	ExpiresAt     time.Time `json:"expires_at"`
	Kind          string    `json:"kind"`
	ServiceUserID *string   `json:"service_user_id"`
	Media         bool      `json:"media"`
	MediaOff      []string  `json:"media_off"`
	Send          *string   `json:"send"`
	SendSelf      bool      `json:"send_self"`
}

// descriptor is the part of the reader's answer this server reads: enough to
// check that a consent is for the request the reader is holding, and that
// the reader is the one this server fronts.
type descriptor struct {
	RequestID    string `json:"request_id"`
	KID          string `json:"kid"`
	ClientName   string `json:"client_name"`
	RedirectHost string `json:"redirect_host"`
	Resource     string `json:"resource"`
}

// Shapes fixed by the contract with the reader and the console.
const (
	requestIDLen = 22 // base64url of 16 random bytes
	kidLen       = 16 // first 16 hex of sha256(reader public key)
	prefixLen    = 8  // hex prefix of an API key
	// minSealedLen is the KEM encapsulation plus an AEAD tag: the shortest
	// thing that could possibly open.
	minSealedLen = 32 + 16
	// maxClientName bounds what an assistant calls itself, in code points:
	// the reader counts the same way when it registers the client.
	maxClientName = 100
	// resourcePath is where the reader serves MCP under the public origin.
	resourcePath = "/mcp"
)

// ---------------------------------------------------------------------------
// Console routes
// ---------------------------------------------------------------------------

// descriptor relays what the reader knows about a pending request, so the
// consent page can show who is asking and seal to the right key. Public and
// unauthenticated: the console fetches it before the person has signed in,
// and the id is 128 bits of randomness that expires in twenty minutes.
func (h *Handler) descriptor(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !allow(w, r, h.DescriptorLimits, id) {
		return
	}
	if !validRequestID(id) {
		fail(w, http.StatusNotFound, "not_found", "no such request")
		return
	}
	_, raw, err := h.readDescriptor(r.Context(), id)
	if err != nil {
		h.readerError(w, err)
		return
	}
	sendRaw(w, raw)
}

// sendRaw answers with a reader's JSON as the reader sent it.
func sendRaw(w http.ResponseWriter, raw []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck // the client hung up; there is nothing left to say to it
	_, _ = w.Write(raw)
}

// prepareBody is the console's prepare: a nonce it generated for this page.
type prepareBody struct {
	Nonce string `json:"nonce"`
}

// prepare asks an attested reader for the request's descriptor with a fresh
// attestation over the browser's nonce, and relays it verbatim. Public and
// unauthenticated like the descriptor, and on the descriptor's budget: the
// console prepares on every render of an attested consent card.
//
// This server checks the answer's shape and remembers what the reader
// declared, for the ledger, and that this request was prepared with this
// kid: a consent for an attested reader is refused unless it was. It does
// not verify the document. The browser does, and a verifier here would run
// on the machine the attestation exists to not trust.
func (h *Handler) prepare(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !allow(w, r, h.DescriptorLimits, "prepare:"+id) {
		return
	}
	if !validRequestID(id) {
		fail(w, http.StatusNotFound, "not_found", "no such request")
		return
	}
	var req prepareBody
	if !decode(w, r, &req) {
		return
	}
	if !validPrepareNonce(req.Nonce) {
		fail(w, http.StatusBadRequest, "bad_request", "nonce must be 16 to 64 bytes in unpadded base64url")
		return
	}
	ctx := r.Context()
	rd, _, err := h.resolve(ctx, id)
	if err != nil {
		h.readerError(w, err)
		return
	}
	if rd.attested == nil {
		fail(w, http.StatusConflict, "attestation_unsupported", "this request's reader does not attest; use its descriptor")
		return
	}
	raw, err := rd.attested.Relay.Prepare(ctx, id, req.Nonce)
	if errors.Is(err, ErrTooManyPrepares) {
		fail(w, http.StatusTooManyRequests, "too_many_prepares", "this request has been prepared too many times; start again from the assistant")
		return
	}
	if err != nil {
		h.readerError(w, err)
		return
	}
	entry, err := checkPrepared(raw, id, rd)
	if err != nil {
		h.log().Warn("an attested reader answered a prepare with the wrong shape", "reader", rd.id, "error", err)
		fail(w, http.StatusBadGateway, "reader_unavailable", "the assistant connector answered with something unexpected; try again in a moment")
		return
	}
	h.requests.put(id, entry, time.Now())
	h.log().Info("mcp request prepared", "reader", rd.id, "pcr0", entry.pcr0[:12], "document", entry.documentSHA256[:12])
	sendRaw(w, raw)
}

// create records a consent and hands the reader the sealed bundle.
//
// The order matters. The key is looked up first, because a wrong key needs
// no reader. The reader is asked for the request next, because a consent
// for a request it no longer holds must not touch the ledger. The row is
// written and the key extended in one transaction, and only then is the
// bundle relayed; a relay that fails undoes both, so nothing consented
// survives a hand-off the reader never acknowledged.
func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !allow(w, r, h.Limits, user.ID.String()) {
		return
	}
	var req createRequest
	if !decode(w, r, &req) {
		return
	}
	// Text and AI hand the archive to the reader: they wait for the person's
	// fresh step-up, as the grants and the service invitation before them
	// did. A metadata consent opens nothing and asks for none.
	if (req.Kind == store.KindContent || req.Kind == store.KindAI) && !h.stepUpFresh(w, r, session) {
		return
	}
	if req.Kind == store.KindAI {
		h.createAI(w, r, user, req)
		return
	}
	in, ok := checkCreate(w, req)
	if !ok {
		return
	}
	ctx := r.Context()

	// The key the console minted for this consent: it must be here, and it
	// must name devices, because the count is what the list shows.
	keys, err := h.APIKeys.List(ctx, user.TenantID.String())
	if err != nil {
		h.log().Error("could not list api keys for a consent", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not record the consent")
		return
	}
	i := slices.IndexFunc(keys, func(k store.APIKeyInfo) bool { return k.Prefix == in.KeyPrefix })
	if i < 0 {
		fail(w, http.StatusNotFound, "not_found", "no such key in this workspace")
		return
	}
	if !keys[i].DevicesRestricted || len(keys[i].DeviceIDs) == 0 {
		fail(w, http.StatusUnprocessableEntity, "key_unsuitable", "the key must be restricted to named numbers")
		return
	}
	in.DeviceCount = len(keys[i].DeviceIDs)

	rd, raw, err := h.resolve(ctx, in.RequestID)
	if err != nil {
		h.readerError(w, err)
		return
	}
	content := in.Kind == store.KindContent
	if content && !h.contentAllowed(rd, user.TenantID) {
		// Text is opened only inside the attested reader, only while the
		// switch is on, and only for the workspaces listed.
		fail(w, http.StatusForbidden, "content_not_allowed", "this workspace may not let an assistant read message text yet")
		return
	}
	if in.Media && !h.mediaAllowed(rd, user.TenantID) {
		// Attachments likewise, behind their own switch and list.
		fail(w, http.StatusBadRequest, "media_not_allowed", "media is not enabled for this workspace")
		return
	}
	if in.SendMode != "" && !h.sendAllowed(rd, user.TenantID) || in.SendSelf && !h.sendSelfAllowed(rd, user.TenantID) ||
		in.SendMode == store.SendModeDirect && !h.sendDirectAllowed(rd, user.TenantID) {
		// Sending likewise, and the own chat and direct send each behind a
		// switch of their own.
		fail(w, http.StatusForbidden, "send_not_allowed", "sending is not enabled for this workspace")
		return
	}
	if rd.attested != nil {
		if !rd.attested.allows(user.TenantID) {
			fail(w, http.StatusForbidden, "tenant_not_allowed", "this workspace may not use this assistant connector yet")
			return
		}
		// The browser verified an attestation for this request and sealed
		// to the key it named; the kid it sends must be the one prepared
		// here, or the bundle is sealed to a key nothing attested.
		entry, ok := h.requests.get(in.RequestID, time.Now())
		if !ok || !entry.prepared || entry.reader != rd.id || entry.kid != req.KID || entry.connection != "" || entry.kind != "" ||
			content && len(entry.publicKey) != readerPublicKeyLen {
			fail(w, http.StatusConflict, "attestation_required", "this connector must be verified before a consent; reload the consent page")
			return
		}
		in.ReaderMeasurement = entry.measurement()
		if content {
			// The service account's public key must be the attested key.
			in.ReaderPublicKey = append([]byte(nil), entry.publicKey...)
		}
	}
	in.Reader = rd.id
	if raw == nil {
		if raw, err = rd.relay.Descriptor(ctx, in.RequestID); err != nil {
			h.readerError(w, err)
			return
		}
	}
	var d descriptor
	version, _, verr := descriptorVersion(raw)
	if verr != nil || json.Unmarshal(raw, &d) != nil || d.RequestID != in.RequestID || d.RedirectHost == "" {
		fail(w, http.StatusBadGateway, "reader_unavailable", "the reader answered with a descriptor for another request")
		return
	}
	if d.Resource != rd.resource() {
		// The reader and this server are configured with the public origin
		// separately, and the console refuses a completion address on any
		// other origin than the descriptor's. Caught here, before the
		// ledger, the drift costs the person one clear error instead of a
		// revoked row per attempt.
		fail(w, http.StatusBadGateway, "reader_unavailable", "the reader advertises another origin than this server; the deployment's origins have drifted apart")
		return
	}
	if d.KID != req.KID {
		fail(w, http.StatusBadRequest, "bad_request", "the bundle is sealed to a key the reader no longer holds; reload the consent page")
		return
	}
	if trimName(d.ClientName) != in.ClientName {
		fail(w, http.StatusBadRequest, "bad_request", "client_name does not match the request")
		return
	}
	in.RedirectHost = strings.ToLower(d.RedirectHost)
	switch version {
	case descriptorV1:
		// A reader before 0.6.0, with its two-host allowlist.
		if e, _ := h.requests.get(in.RequestID, time.Now()); rd.attested != nil && e.version == descriptorV2 {
			fail(w, http.StatusBadGateway, "reader_unavailable", "the reader described this request in two versions")
			return
		}
		if req.hasClient() || in.ConsentVersion == store.ClientConsentVersion {
			fail(w, http.StatusBadRequest, "bad_request", "the client fields and consent_version 4 are for a reader that describes its client")
			return
		}
		if !slices.Contains(h.RedirectHosts, in.RedirectHost) {
			// The reader and this server carry the same list; a request
			// for a host outside it means they have drifted apart.
			fail(w, http.StatusBadRequest, "bad_request", "the request's redirect host is not allowed here")
			return
		}
	case descriptorV2:
		var entry requestEntry
		if rd.attested != nil {
			entry, _ = h.requests.get(in.RequestID, time.Now())
		}
		if entry.version != descriptorV2 || entry.client == nil {
			// Only an attested reader describes its client, and only a
			// prepared request has its description in hand.
			fail(w, http.StatusConflict, "attestation_required", "this connector must be verified before a consent; reload the consent page")
			return
		}
		if !h.checkClientConsent(w, r, user, entry.client, req, &in) {
			return
		}
	}

	conn, err := h.Connections.Create(ctx, user.TenantID, user.ID, in)
	if err != nil {
		h.connectionError(w, err)
		return
	}
	relay := BundleRelay{ConnectionID: conn.ID, TenantID: conn.TenantID, KID: in.ReaderKID, Sealed: req.Sealed, ExpiresAt: conn.ExpiresAt}
	if content {
		relay.Kind, relay.Media = store.KindContent, in.Media
		relay.Send, relay.SendSelf, relay.SendGroups = in.SendMode, in.SendSelf, in.SendGroups
	}
	if version == descriptorV2 {
		// Never to an older reader, whose strict body would refuse them.
		relay.Client = &RelayClient{Trust: in.Trust, ClientLocal: in.ClientLocal}
		if in.HistoryDays != 0 {
			relay.Client.HistoryDays = &in.HistoryDays
		}
	}
	if err := rd.relay.Bundle(ctx, in.RequestID, relay); err != nil {
		if derr := h.Connections.DeleteFailed(ctx, conn.ID); derr != nil {
			// The row stays pending and the janitor revokes it with its
			// key once the reader's request lifetime has passed.
			h.log().Error("could not undo a consent the reader did not take", "connection", conn.ID, "error", derr)
		}
		h.log().Warn("the reader did not take a sealed bundle", "connection", conn.ID, "error", err)
		h.readerError(w, err)
		return
	}
	h.log().Info("mcp connection consented", "connection", conn.ID, "client", in.RedirectHost, "client_host", in.ClientHost,
		"trust", in.Trust, "devices", in.DeviceCount, "expires_at", conn.ExpiresAt, "reader", rd.id, "kind", in.Kind, "media", in.Media,
		"send", in.SendMode, "send_self", in.SendSelf, "send_groups", in.SendGroups)
	send(w, http.StatusCreated, createReply{
		ID: conn.ID, Status: conn.Status, ExpiresAt: conn.ExpiresAt,
		CompleteURL: rd.completeURL(),
	})
}

// checkCreate validates the shape of a consent. Everything here has one
// fixed form; the message names the field so the console can say so.
func checkCreate(w http.ResponseWriter, req createRequest) (store.CreateMCPConnection, bool) {
	var in store.CreateMCPConnection
	bad := func(msg string) (store.CreateMCPConnection, bool) {
		fail(w, http.StatusBadRequest, "bad_request", msg)
		return store.CreateMCPConnection{}, false
	}
	if !validRequestID(req.RequestID) {
		return bad("request_id must be 22 base64url characters")
	}
	if len(req.KeyPrefix) != prefixLen || !isHex(req.KeyPrefix) {
		return bad("key_prefix must be the 8 hex characters before the dot")
	}
	if len(req.KID) != kidLen || !isHex(req.KID) {
		return bad("kid must be 16 hex characters")
	}
	name := trimName(req.ClientName)
	if name == "" || utf8.RuneCountInString(name) > maxClientName || strings.ContainsFunc(name, func(r rune) bool { return !clientNameChar(r) }) {
		return bad("client_name must be 1 to 100 printable characters")
	}
	at, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		return bad("expires_at must be an RFC 3339 timestamp")
	}
	if now := time.Now(); !at.After(now) || at.After(now.Add(365*24*time.Hour)) {
		return bad("expires_at must be in the future and within a year")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(req.Sealed)
	if err != nil || len(sealed) < minSealedLen {
		return bad("sealed must be the unpadded base64url of the sealed bundle")
	}
	in = store.CreateMCPConnection{
		RequestID: req.RequestID, KeyPrefix: req.KeyPrefix, ClientName: name,
		ReaderKID: req.KID, ExpiresAt: at.UTC(), Kind: store.KindMetadata,
	}
	sending := req.Send != "" || req.SendSelf || req.SendGroups || len(req.SendChats) > 0
	if len(req.AIConfig) > 0 {
		return bad("ai_config is for an AI authorization only")
	}
	switch req.Kind {
	case "", store.KindMetadata:
		if req.ServiceUserID != "" || req.KeyMode != "" || req.ConsentVersion != 0 || req.Media || sending {
			return bad("service_user_id, key_mode, consent_version, media and the send fields are for a content connection only")
		}
	case store.KindContent:
		if sending && req.Send == "" {
			return bad("send_self, send_groups and send_chats need send")
		}
		service, err := uuid.Parse(req.ServiceUserID)
		if err != nil || len(req.ServiceUserID) != 36 || service == uuid.Nil {
			return bad("service_user_id must be the content connection's service account id")
		}
		if req.KeyMode != store.KeyModeEphemeral {
			return bad("key_mode must be ephemeral")
		}
		switch req.ConsentVersion {
		case store.ContentConsentVersion, store.MediaConsentVersion, store.SendConsentVersion, store.ClientConsentVersion:
		default:
			return bad("consent_version must be 1, 2, 3 or 4")
		}
		if req.ConsentVersion == store.SendConsentVersion && req.Send == "" || req.ConsentVersion < store.SendConsentVersion && req.Send != "" {
			return bad("consent version 3 carries sending, version 4 may, and versions 1 and 2 never do")
		}
		if req.Media && req.ConsentVersion < store.MediaConsentVersion {
			return bad("media requires consent_version 2 or later")
		}
		switch {
		case req.Send == store.SendModeDirect || len(req.SendChats) > 0:
			// Direct send's server is S3 (docs/mcp-enclave.md §17.15).
			return bad("direct send and send_chats are not available yet; send must be draft")
		case req.Send != "" && req.Send != store.SendModeDraft:
			return bad("send must be draft")
		}
		if at.After(time.Now().Add(maxContentLifetime)) {
			return bad("a content connection's expires_at must be within 90 days")
		}
		in.Kind, in.ServiceUserID, in.KeyMode, in.ConsentVersion = store.KindContent, service, req.KeyMode, req.ConsentVersion
		in.Media = req.Media
		in.SendMode, in.SendSelf, in.SendGroups = req.Send, req.SendSelf, req.SendGroups
	default:
		return bad("kind must be metadata or content")
	}
	return in, true
}

// maxContentLifetime bounds a content consent: ninety days, and an hour for
// the console's clock.
const maxContentLifetime = 90*24*time.Hour + time.Hour

// list shows every connection of the workspace, in every status. A member
// may look: knowing which assistants reach the archive is not a privilege.
func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	rows, err := h.Connections.ListFor(r.Context(), user.TenantID, user.ID)
	if err != nil {
		h.log().Error("could not list mcp connections", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not list the connections")
		return
	}
	out := connectionsReply{Connections: make([]connectionInfo, 0, len(rows))}
	now := time.Now()
	allowed := h.contentEnabledFor(user.TenantID)
	for _, c := range rows {
		out.Connections = append(out.Connections, listedConnection(c, user.ID, allowed, now))
	}
	send(w, http.StatusOK, out)
}

// listedConnection is one connection as the console lists it to viewer,
// with content allowed or not for the workspace right now.
func listedConnection(c store.MCPConnection, viewer uuid.UUID, allowed bool, now time.Time) connectionInfo {
	status := c.Status
	if (status == "active" || status == "reseal") && !c.ExpiresAt.After(now) {
		// What the reader is told, so the list never says an ended
		// connection is live while the janitor is between runs.
		status = "expired"
	}
	info := connectionInfo{
		ID: c.ID, ClientName: c.ClientName, RedirectHost: c.RedirectHost, Status: status,
		DeviceCount: c.DeviceCount, KeyPrefix: c.KeyPrefix, CreatedAt: c.CreatedAt,
		ActivatedAt: c.ActivatedAt, ExpiresAt: c.ExpiresAt, LastSeenAt: c.LastSeenAt, RevokedAt: c.RevokedAt,
		Kind:      c.Kind,
		Renewable: c.Kind == store.KindContent && (status == "active" || status == "reseal") && c.CreatedBy == viewer && allowed,
	}
	if c.KeyMode != "" {
		info.KeyMode = &c.KeyMode
	}
	if c.Kind == store.KindContent && c.ConsentVersion != 0 {
		info.ConsentVersion, info.Media = &c.ConsentVersion, c.Media
	}
	if c.SendMode != "" {
		mode := c.SendMode
		info.SendMode = &mode
	}
	info.SendSelf, info.SendGroups, info.SendPaused, info.SendChats = c.SendSelf, c.SendGroups, c.SendPausedAt != nil, c.SendChats
	if c.RevokeReason != "" {
		info.RevokeReason = &c.RevokeReason
	}
	info.ClientKind, info.ClientLocal, info.FirstUsedAt, info.Seen = c.ClientKind, c.ClientLocal, c.FirstUsedAt, c.Seen
	info.Mine = c.CreatedBy == viewer
	info.ClientID, info.ClientHost, info.Trust = optional(c.ClientID), optional(c.ClientHost), optional(c.Trust)
	if c.ClientHost != "" {
		if host, reason := netguard.CheckHost(c.ClientHost); reason == "" {
			info.Registrable = &host.Registrable
		}
	}
	info.ClaimedName, info.CreatedByEmail = optional(c.ClaimedName), optional(c.CreatedByEmail)
	if c.HistoryDays != 0 {
		days := c.HistoryDays
		info.HistoryDays = &days
	}
	info.BudgetHits = c.BudgetHits
	if info.BudgetHits == nil {
		info.BudgetHits = []store.BudgetHit{}
	}
	return info
}

// remove ends a connection: the row and its key in one transaction, then a
// word to the reader so it stops before its next check. The word is best
// effort; the ledger is the authority and the reader re-reads it.
func (h *Handler) remove(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id, ok := connectionID(w, r)
	if !ok {
		return
	}
	owner, err := h.Connections.Revoke(r.Context(), user.TenantID, user.ID, id)
	if err != nil {
		h.connectionError(w, err)
		return
	}
	h.tellRevoked(r.Context(), owner, id)
	h.log().Info("mcp connection revoked", "connection", id, "reason", store.ReasonConsole)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Internal routes, for the reader only
// ---------------------------------------------------------------------------

// internal guards a route the reader alone may call. The peer must be
// loopback and must not have come through a proxy — any X-Forwarded-For at
// all means it did, and the answer is the same 404 nginx gives — and it must
// present the relay secret. The secret check is constant time and comes
// after the address check, so a remote caller learns nothing about it.
func (h *Handler) internal(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.RelaySecret == "" || len(r.Header.Values("X-Forwarded-For")) > 0 || !loopback(r) {
			fail(w, http.StatusNotFound, "not_found", "no such route")
			return
		}
		token, ok := bearerToken(r)
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(h.RelaySecret)) != 1 {
			fail(w, http.StatusUnauthorized, "unauthorized", "relay secret required")
			return
		}
		next(w, r)
	}
}

// status answers where a connection stands and notes that the reader asked.
func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	h.connectionStatus(w, r, store.HostedReader)
}

// connectionStatus answers for one of this reader's connections; another
// reader's is not found.
func (h *Handler) connectionStatus(w http.ResponseWriter, r *http.Request, readerID string) {
	id, ok := connectionID(w, r)
	if !ok {
		return
	}
	var allowed store.StatusAllowed
	rd, known := h.readerByID(readerID)
	attested := known && rd.attested != nil
	if attested {
		allowed.Content = func(tenant uuid.UUID) bool { return h.contentAllowed(rd, tenant) }
		allowed.AI = func(tenant uuid.UUID) bool { return h.aiAllowed(rd, tenant) }
	}
	a, err := h.Connections.StatusFor(r.Context(), readerID, id, allowed)
	if err != nil {
		h.connectionError(w, err)
		return
	}
	if attested && a.Kind == store.KindAI {
		send(w, http.StatusOK, aiStanding(a, h.MediaOff, h.AIOffFeatures, h.AIOffProviders))
		return
	}
	var now standingNow
	if attested {
		now.media = a.Media && h.mediaAllowed(rd, a.TenantID)
		now.mediaOff = h.MediaOff
		// Sending needs an active answer: a connection waiting for its
		// handshake, or whose key the reader lost, sends nothing. Direct
		// send narrows to drafts while its switch is off, and a pause stops
		// both, never reading.
		if a.SendMode != "" && a.Status == "active" && !a.SendPaused && h.sendAllowed(rd, a.TenantID) {
			now.send = a.SendMode
			if now.send == store.SendModeDirect && !h.sendDirectAllowed(rd, a.TenantID) {
				now.send = store.SendModeDraft
			}
			now.sendSelf = a.SendSelf && h.sendSelfAllowed(rd, a.TenantID)
		}
	}
	send(w, http.StatusOK, standingReply(a, attested, now))
}

// standingNow is what an attested reader is told about a connection beyond
// its standing: what the switches let it do right now.
type standingNow struct {
	media    bool
	mediaOff []string
	// send is "draft", "direct" or "" for none.
	send     string
	sendSelf bool
}

// standingReply shapes a connection's standing for its reader. The expiry
// goes out in UTC whatever the host's zone, the form every other expiry on
// this interface takes: a reader holds it next to the consent's, and a
// renewal on a host with another zone would otherwise not match it. The
// hosted reader's reply never grows: its two fields are all it reads.
func standingReply(a store.StatusAnswer, attested bool, now standingNow) any {
	expires := a.ExpiresAt.UTC()
	if !attested {
		return statusReply{Status: a.Status, ExpiresAt: expires}
	}
	reply := attestedStatusReply{Status: a.Status, ExpiresAt: expires, Kind: a.Kind, Media: now.media, MediaOff: []string{}}
	if a.ServiceUserID != nil {
		service := a.ServiceUserID.String()
		reply.ServiceUserID = &service
	}
	if len(now.mediaOff) > 0 {
		reply.MediaOff = append(reply.MediaOff, now.mediaOff...)
	}
	if now.send != "" {
		mode := now.send
		reply.Send, reply.SendSelf = &mode, now.sendSelf
	}
	return reply
}

// activate records that the reader finished the handshake. Once: a second
// activation is a replay of something and is refused.
func (h *Handler) activate(w http.ResponseWriter, r *http.Request) {
	h.connectionActivate(w, r, store.HostedReader)
}

func (h *Handler) connectionActivate(w http.ResponseWriter, r *http.Request, readerID string) {
	id, ok := connectionID(w, r)
	if !ok {
		return
	}
	if err := h.Connections.Activate(r.Context(), readerID, id); err != nil {
		h.connectionError(w, err)
		return
	}
	h.log().Info("mcp connection activated", "connection", id, "reader", readerID)
	// A reconnect that asked to replace the person's earlier connections of
	// the same client ends them now, and tells their readers (§19.35). A
	// failure leaves them live: the idle sweep, or the person, ends them.
	replaced, err := h.Connections.ReplacePrevious(r.Context(), readerID, id)
	if err != nil {
		h.log().Warn("could not replace a reconnected assistant's earlier connections", "connection", id, "error", err)
	}
	for _, old := range replaced {
		h.log().Info("mcp connection revoked", "connection", old.ID, "reason", store.ReasonReplaced, "by", id)
		h.tellRevoked(context.WithoutCancel(r.Context()), old.Reader, old.ID)
	}
	// Every activation is announced (docs/mcp-enclave.md §19.22): an OAuth
	// connection's handshake and a console token's install alike.
	h.announce(r.Context(), readerID, id, store.NoticeActivated)
	w.WriteHeader(http.StatusNoContent)
}

// revoke ends a connection on the reader's word — a burnt request, a bundle
// that failed its checks. Idempotent, and an id the ledger never held is
// already as ended as it can be.
func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	h.connectionRevoke(w, r, store.HostedReader, store.ReasonReader)
}

// connectionRevoke ends one of this reader's connections. Another reader's
// is as unknown as an id the ledger never held, and gets the same 204.
func (h *Handler) connectionRevoke(w http.ResponseWriter, r *http.Request, readerID, reason string) {
	id, ok := connectionID(w, r)
	if !ok {
		return
	}
	err := h.Connections.RevokeByID(r.Context(), readerID, id, reason)
	if err != nil && !errors.Is(err, store.ErrMCPConnectionNotFound) {
		h.connectionError(w, err)
		return
	}
	if err == nil {
		h.log().Info("mcp connection revoked by the reader", "connection", id, "reader", readerID, "reason", reason)
	}
	w.WriteHeader(http.StatusNoContent)
}

// cimd fetches a client metadata document for the reader. The address is
// checked before anything is opened; see CIMD.
func (h *Handler) cimd(w http.ResponseWriter, r *http.Request) {
	urls := r.URL.Query()["url"]
	if len(urls) != 1 {
		fail(w, http.StatusBadRequest, "bad_request", "one url parameter is required")
		return
	}
	fetcher := &CIMD{Hosts: h.RedirectHosts, Transport: h.CIMDTransport}
	body, err := fetcher.Fetch(r.Context(), urls[0])
	switch {
	case errors.Is(err, ErrCIMDURL):
		fail(w, http.StatusBadRequest, "bad_request", "not a client metadata address this server will fetch")
		return
	case err != nil:
		h.log().Warn("client metadata document unavailable", "error", err)
		fail(w, http.StatusBadGateway, "cimd_unavailable", "the client metadata document could not be fetched")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	// Served as JSON to the reader over loopback; no browser ever reads it.
	//nolint:errcheck,gosec // the reader hung up; G705: JSON for a loopback client, not a page
	_, _ = w.Write(body)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// connectionError maps what the ledger says to a status and a code the
// console knows.
func (h *Handler) connectionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrMembershipForbidden):
		fail(w, http.StatusForbidden, "not_authorized", "this action requires a workspace owner or an authorized administrator")
	case errors.Is(err, store.ErrTooManyMCPConnections):
		fail(w, http.StatusConflict, "too_many_connections", "this workspace already has as many live assistant connections as it may; revoke one first")
	case errors.Is(err, store.ErrTooManyUnknownMCPConnections):
		fail(w, http.StatusConflict, "too_many_unknown", "this workspace already has as many untested assistants and tokens as it may; revoke one first")
	case errors.Is(err, store.ErrMCPClient):
		fail(w, http.StatusBadRequest, "bad_request", "the consent's client does not hold together")
	case errors.Is(err, store.ErrMCPKeyUnsuitable), errors.Is(err, store.ErrInvalidKey):
		fail(w, http.StatusUnprocessableEntity, "key_unsuitable",
			"the key must be read-only, restricted to named numbers, be live and carry a provisional deadline; for metadata it carries no service account, for content it acts as the connection's own")
	case errors.Is(err, store.ErrInvalidExpiry):
		fail(w, http.StatusBadRequest, "bad_request", "expires_at must be in the future and within a year")
	case errors.Is(err, store.ErrMCPConnectionState):
		fail(w, http.StatusConflict, "connection_state", "the connection is not waiting for that")
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrMCPConnectionNotFound):
		fail(w, http.StatusNotFound, "not_found", "no such key or connection in this workspace")
	default:
		h.log().Error("mcp connection operation failed", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not manage the connection")
	}
}

// readerError maps a relay failure. The reader not knowing a request is the
// person's problem to fix (the consent page has expired); anything else is
// this host's, and says so.
func (h *Handler) readerError(w http.ResponseWriter, err error) {
	var refusal *RefusalError
	switch {
	case errors.Is(err, ErrReaderNotFound):
		fail(w, http.StatusNotFound, "not_found", "that request is no longer waiting for a consent; start again from the assistant")
	case errors.As(err, &refusal) && refusal.Code == "too_many_unknown":
		// The reader counts its own records too (§19.10).
		fail(w, http.StatusConflict, "too_many_unknown", "this workspace already has as many untested assistants and tokens as it may; revoke one first")
	case errors.As(err, &refusal) && slices.Contains(aiRefusals, refusal.Code):
		// The reader opened the bundle and it was not what the consent
		// promised, or a grant in it did not open with the attested key,
		// or, for an AI authorization, a key or a model the provider did
		// not take.
		fail(w, http.StatusBadRequest, refusal.Code, "the reader refused the sealed bundle; start again from the assistant")
	case errors.Is(err, ErrReaderRefused):
		fail(w, http.StatusBadRequest, "bad_request", "the reader refused the sealed bundle; start again from the assistant")
	default:
		h.log().Warn("the reader is unavailable", "error", err)
		fail(w, http.StatusBadGateway, "reader_unavailable", "the assistant connector is not answering; try again in a moment")
	}
}

// ---------------------------------------------------------------------------
// Plumbing, as in authapi
// ---------------------------------------------------------------------------

// authenticate resolves a bearer token to a session and its account.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (store.Session, store.User, bool) {
	token, ok := bearerToken(r)
	if !ok {
		fail(w, http.StatusUnauthorized, "unauthorized", "sign in first")
		return store.Session{}, store.User{}, false
	}
	session, user, err := h.Users.ActiveSession(r.Context(), token)
	if err != nil {
		// Expired, revoked, or the account behind it was disabled: one
		// answer, because the fix is the same — sign in again, and find out
		// there if that is refused too.
		fail(w, http.StatusUnauthorized, "unauthorized", "that session has expired")
		return store.Session{}, store.User{}, false
	}
	return session, user, true
}

// stepUpFresh refuses a write that hands an archive to a reader when the
// session's person has not proved themselves within the step-up window
// (internal/stepup), with the code the console asks again on.
func (h *Handler) stepUpFresh(w http.ResponseWriter, r *http.Request, session store.Session) bool {
	checker := h.StepUp
	if checker == nil {
		checker = stepup.Recent(h.Users)
	}
	fresh, err := checker.Fresh(r.Context(), session.ID)
	if err != nil {
		h.log().Error("could not read a session's step-up", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not check your confirmation")
		return false
	}
	if !fresh {
		fail(w, http.StatusForbidden, stepup.Code, stepup.Message)
		return false
	}
	return true
}

// allow applies a rate limit, answering 429 with a Retry-After when it
// bites. The reply is the same whether the address or the subject ran out,
// because saying which would tell a caller whether the subject is worth
// spreading across more addresses.
func allow(w http.ResponseWriter, r *http.Request, limits *ratelimit.Auth, subject string) bool {
	ok, wait := limits.Allow(r, subject)
	if ok {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())))
	fail(w, http.StatusTooManyRequests, "rate_limited",
		"too many attempts; try again in "+wait.String())
	return false
}

// bearerToken pulls a token out of the Authorization header.
func bearerToken(r *http.Request) (string, bool) {
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	token = strings.TrimSpace(token)
	if !found || token == "" {
		return "", false
	}
	return token, true
}

// loopback reports whether the connection itself came from this host. The
// address is the socket's, never a header's.
func loopback(r *http.Request) bool {
	addr, err := netip.ParseAddr(ratelimit.ClientIP(r, nil))
	return err == nil && addr.IsLoopback()
}

// connectionID reads the path's connection id. Anything that is not a UUID
// is an id the ledger cannot hold.
func connectionID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || len(r.PathValue("id")) != 36 || id == uuid.Nil {
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return "", false
	}
	return id.String(), true
}

// trimName strips what the console's trim strips from a client name: Unicode
// white space plus the zero-width no-break space, which JavaScript counts as
// white space and Go does not. The descriptor's name and the body's must
// agree after the same trim, or a name with a stray U+FEFF at the edge would
// register with the reader and never pass a consent.
func trimName(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == '\uFEFF' })
}

// clientNameChar is the character class the reader accepts in a client name
// (`printable` in the reader's clients.mjs): printable ASCII and the Basic
// Multilingual Plane from U+00A0 up, controls and the astral planes out.
// The same class here, because the reader has already accepted the name by
// the time a consent for it arrives; anything stricter would let a client
// register and then refuse every consent for it.
func clientNameChar(r rune) bool {
	return r >= 0x20 && r <= 0x7E || r >= 0xA0 && r <= 0xFFFF
}

func validRequestID(id string) bool {
	return len(id) == requestIDLen && !strings.ContainsFunc(id, func(c rune) bool { return !base64urlChar(c) })
}

func base64urlChar(c rune) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

func isHex(s string) bool {
	return !strings.ContainsFunc(s, func(c rune) bool { return !hexChar(c) })
}

func hexChar(c rune) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }

// maxBody bounds a request. The sealed bundle is a few hundred bytes of
// base64; anything near the cap is a mistake or an attack.
const maxBody = 64 << 10

type wireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func decode(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "malformed request: "+err.Error())
		return false
	}
	return true
}

func send(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Consents and standing. Nothing here may be cached anywhere.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	//nolint:errcheck // the client hung up; there is nothing left to say to it
	_ = json.NewEncoder(w).Encode(body)
}

func fail(w http.ResponseWriter, status int, code, message string) {
	send(w, status, wireError{Code: code, Message: message})
}

// openAIChallenge answers OpenAI's domain verification with the token and
// nothing else, as the portal requires; until one is configured the path
// does not exist.
func (h *Handler) openAIChallenge(w http.ResponseWriter, _ *http.Request) {
	if h.OpenAIAppsChallenge == "" {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	//nolint:errcheck // the client hung up; there is nothing left to say to it
	_, _ = io.WriteString(w, h.OpenAIAppsChallenge)
}
