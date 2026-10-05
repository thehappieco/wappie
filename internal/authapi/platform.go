package authapi

// Sign-in through an external identity provider (docs/platform-sign-in.md):
// The Happie Co's id. for the hosted cloud, off everywhere else.
//
// The page completes the provider's sign-in itself (@thehappieco/kit's
// oidc-rp): it receives the product key sk_p sealed to it alone, and posts
// this server the single-use access token. This server takes the token to
// the provider's userinfo (kit oidcrp), pins the account's product key insert
// only, and answers with the pinned triple, which the page compares with the
// key it opened before it keeps anything. Then, by what the server knows of
// the sub:
//
//   - session: a linked account with a wrap for this epoch. A Wappie session
//     is issued, with the wrap, which the page opens with sk_p into the
//     account key.
//   - new: nobody here has this sub. The page generates an account key,
//     wraps it under sk_p, and creates the account (POST .../account), or
//     the person links an account they already have.
//   - link_required: a password account already has the provider's address.
//     Only a link is offered: the old password (or recovery code) proves
//     the account in the browser and to this server, and the account key
//     opened with it is wrapped under sk_p (POST .../link/prepare, .../link).
//   - rewrap_required: a linked account whose provider key moved to a new
//     epoch; a browser that still holds the account key stores its new wrap.
//
// The account key and sk_p never reach this server. An e-mail address never
// links anything: the link needs the legacy proof.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/thehappieco/kit/oidcrp"

	"whatserver2/internal/config"
	"whatserver2/internal/store"
)

// PlatformLogin is the configured identity provider. Nil on a Handler is
// off: every platform route answers platform_login_disabled.
type PlatformLogin struct {
	Client *oidcrp.Client
	Pins   oidcrp.PinStore
	// AppOrigin is the one page origin that may post here.
	AppOrigin string
	// Alert sends the "your account key changed" mail to one address, in
	// lang (the account's locale; "" is English); nil sends nothing.
	// AlertEmail is the operator's address, beside the account's own.
	Alert      func(ctx context.Context, to, lang string) error
	AlertEmail string
}

// NewPlatformLogin builds the provider's relying party from configuration;
// nil, nil when the provider is not configured. In development the userinfo
// request may dial a fixed address (WS_PLATFORM_ID_ADDR), because Go does
// not resolve *.localhost; its Host header still names the issuer.
func NewPlatformLogin(cfg config.Platform, pins oidcrp.PinStore) (*PlatformLogin, error) {
	if !cfg.Enabled() {
		return nil, nil
	}
	var dial func(ctx context.Context, network, addr string) (net.Conn, error)
	if cfg.IDAddr != "" {
		target := cfg.IDAddr
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, target)
		}
	}
	client := &oidcrp.Client{Issuer: cfg.Issuer, ClientID: cfg.ClientID, Product: config.PlatformProduct, HTTP: oidcrp.NewHTTPClient(dial)}
	if err := client.Check(); err != nil {
		return nil, err
	}
	return &PlatformLogin{Client: client, Pins: pins, AppOrigin: cfg.AppOrigin, AlertEmail: cfg.AlertEmail}, nil
}

func (h *Handler) mountPlatform(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/auth/platform/session", h.platformSession)
	mux.HandleFunc("POST /v1/auth/platform/account", h.platformAccount)
	mux.HandleFunc("POST /v1/auth/platform/link/prepare", h.platformLinkPrepare)
	mux.HandleFunc("POST /v1/auth/platform/link", h.platformLink)
	mux.HandleFunc("POST /v1/auth/platform/rewrap", h.platformRewrap)
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

// The kinds of answer to a sign-in (package comment).
const (
	platformKindSession        = "session"
	platformKindNew            = "new"
	platformKindLinkRequired   = "link_required"
	platformKindRewrapRequired = "rewrap_required"
)

// platformReply is the answer to every platform route that signs in or may.
// Binary fields are standard base64, as in every other auth reply, except
// pin, which is the kit's (base64url) so the page's keepProductKey reads it
// unchanged.
type platformReply struct {
	Kind string         `json:"kind"`
	Pin  *oidcrp.Answer `json:"pin,omitempty"`

	// session
	Token        string     `json:"token,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	User         *account   `json:"user,omitempty"`
	PlatformWrap string     `json:"platform_wrap,omitempty"`

	// new, link_required and rewrap_required
	Ticket          string     `json:"ticket,omitempty"`
	TicketExpiresAt *time.Time `json:"ticket_expires_at,omitempty"`
	// Email is the provider's verified address for this person: their own.
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
	// UserID and PublicKey name the linked account of a rewrap.
	UserID    string `json:"user_id,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}

type platformSessionRequest struct {
	AccessToken string `json:"access_token"`
}

type platformAccountRequest struct {
	Ticket       string `json:"ticket"`
	PublicKey    string `json:"public_key"`
	PlatformWrap string `json:"platform_wrap"`
	DisplayName  string `json:"display_name,omitempty"`
}

type platformLinkRequest struct {
	Ticket string `json:"ticket"`
	Email  string `json:"email"`
	// Exactly one of the two: the old password's auth key, or the recovery
	// code's proof.
	AuthKey       string `json:"auth_key,omitempty"`
	RecoveryProof string `json:"recovery_proof,omitempty"`
	// PlatformWrap is required by link and refused by link/prepare.
	PlatformWrap string `json:"platform_wrap,omitempty"`
}

// platformPrepareReply is what the browser needs to open the legacy account
// key and wrap it: handed back only against the proof, as a password
// sign-in hands back wrapped_usk.
type platformPrepareReply struct {
	UserID       string `json:"user_id"`
	PublicKey    string `json:"public_key"`
	WrappedUSK   string `json:"wrapped_usk,omitempty"`
	RecoveryWrap string `json:"recovery_wrap,omitempty"`
}

type platformRewrapRequest struct {
	Ticket       string `json:"ticket"`
	PlatformWrap string `json:"platform_wrap"`
}

// maxPlatformBody bounds a platform request: a token, a ticket, a key and a
// 61-byte wrap in base64.
const maxPlatformBody = 4 << 10

// ---------------------------------------------------------------------------
// The common rules
// ---------------------------------------------------------------------------

// platformRequest applies the session handler's rules of kit oidcrp, before
// the body is read: the provider is configured; the request comes from the
// console's page itself (exactly one Origin, the configured one, and
// Sec-Fetch-Site: same-origin); and its body is application/json. Without
// them another site could post an access token of its own account here from
// the person's browser (a no-cors text/plain POST needs no preflight) and
// sign that browser into the other site's account.
func (h *Handler) platformRequest(w http.ResponseWriter, r *http.Request) bool {
	if h.Platform == nil {
		fail(w, http.StatusForbidden, "platform_login_disabled", "this server does not sign in through an identity provider")
		return false
	}
	if o := r.Header.Values("Origin"); len(o) != 1 || o[0] != h.Platform.AppOrigin {
		fail(w, http.StatusForbidden, "forbidden", "this request must come from the console's own page")
		return false
	}
	if s := r.Header.Values("Sec-Fetch-Site"); len(s) != 1 || s[0] != "same-origin" {
		fail(w, http.StatusForbidden, "forbidden", "this request must come from the console's own page")
		return false
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		fail(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "send application/json")
		return false
	}
	return true
}

// decodePlatform reads one JSON object of at most maxPlatformBody bytes,
// with no unknown member and nothing after it.
func decodePlatform(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPlatformBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "malformed request")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		fail(w, http.StatusBadRequest, "bad_request", "malformed request")
		return false
	}
	return true
}

// localLoginRefused answers a route WS_LOCAL_LOGIN no longer allows.
func localLoginRefused(w http.ResponseWriter) {
	fail(w, http.StatusForbidden, "local_login_disabled", "this server signs in through its identity provider; password sign-in is closed")
}

// localAllowed reports whether a password route is open: every one with
// WS_LOCAL_LOGIN=on, the ones the link ceremony needs with link_only, none
// with off.
func (h *Handler) localAllowed(neededByLink bool) bool {
	switch h.LocalLogin {
	case "", config.LocalLoginOn:
		return true
	case config.LocalLoginLinkOnly:
		return neededByLink
	default:
		return false
	}
}

// local wraps a password route in its WS_LOCAL_LOGIN gate.
func (h *Handler) local(neededByLink bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.localAllowed(neededByLink) {
			localLoginRefused(w)
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// POST /v1/auth/platform/session
// ---------------------------------------------------------------------------

func (h *Handler) platformSession(w http.ResponseWriter, r *http.Request) {
	if !h.platformRequest(w, r) {
		return
	}
	if !h.allow(w, r, "") {
		return
	}
	var req platformSessionRequest
	if !decodePlatform(w, r, &req) {
		return
	}
	login, err := h.Platform.Client.Login(r.Context(), h.Platform.Pins, req.AccessToken)
	switch code := oidcrp.ErrorCode(err); {
	case err == nil:
	case code == "account_key_changed":
		h.accountKeyChanged(r.Context(), login.Userinfo)
		send(w, http.StatusConflict, struct {
			Code         string `json:"code"`
			Message      string `json:"message"`
			ProductKeyID string `json:"product_key_id"`
		}{"account_key_changed", "the account key presented differs from the one this account signed in with before; nothing was opened", login.Userinfo.ProductKeyID})
		return
	case code == "access_token":
		fail(w, http.StatusBadRequest, "bad_request", "not an access token")
		return
	case code == "token_refused":
		// The token works once: it is never retried, here or by the page.
		fail(w, http.StatusUnauthorized, "token_refused", "the identity provider refused the sign-in; sign in again")
		return
	case code == "wrong_client":
		fail(w, http.StatusForbidden, "wrong_client", "that sign-in was not made for this application")
		return
	case code == "userinfo" || code == "product_key":
		// No error of the kit names the token, the key or the account.
		h.log().Warn("the identity provider's userinfo was refused", "error", err)
		fail(w, http.StatusBadGateway, "userinfo", "the identity provider could not confirm the sign-in; try again")
		return
	default:
		h.log().Error("platform sign-in failed", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not sign in")
		return
	}
	ui := login.Userinfo
	if ui.Email == "" || !ui.EmailVerified {
		h.log().Warn("the identity provider's userinfo named no verified address")
		fail(w, http.StatusBadGateway, "userinfo", "the identity provider did not confirm an e-mail address")
		return
	}
	sub, err := uuid.Parse(ui.Sub)
	if err != nil {
		fail(w, http.StatusBadGateway, "userinfo", "the identity provider could not confirm the sign-in; try again")
		return
	}
	pin := login.Answer
	ident, err := h.Users.PlatformIdentity(r.Context(), sub)
	switch {
	case errors.Is(err, store.ErrNotFound):
		h.platformUnlinked(w, r, ui, sub, &pin)
		return
	case err != nil:
		h.log().Error("could not read a platform link", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not sign in")
		return
	}

	user, err := h.Users.PlatformAccount(r.Context(), ident.UserID)
	if err != nil || user.Status != "active" || user.Role == store.RoleService {
		fail(w, http.StatusForbidden, "account_disabled", "this account is disabled")
		return
	}
	if err := h.Users.SyncPlatformEmail(r.Context(), ident, ui.Email); errors.Is(err, store.ErrEmailTaken) {
		h.log().Warn("kept an account's address: the identity provider's new one belongs to another account")
	} else if err != nil {
		h.log().Warn("could not record the identity provider's address", "error", err)
	}
	wrap, err := h.Users.PlatformWrap(r.Context(), user.ID, ui.ProductKeyID)
	if errors.Is(err, store.ErrNotFound) {
		ticket, expires, err := h.platformTicket(r.Context(), store.PlatformTicket{Kind: store.TicketRewrap, Sub: sub,
			ProductKeyID: ui.ProductKeyID, ProductKey: ui.ProductKey, Email: ui.Email, UserID: user.ID})
		if err != nil {
			h.log().Error("could not issue a rewrap ticket", "error", err)
			fail(w, http.StatusInternalServerError, "internal", "could not sign in")
			return
		}
		send(w, http.StatusOK, platformReply{Kind: platformKindRewrapRequired, Pin: &pin, Ticket: ticket, TicketExpiresAt: &expires,
			UserID: user.ID.String(), PublicKey: b64(user.PublicKey)})
		return
	}
	if err != nil {
		h.log().Error("could not read a platform wrap", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not sign in")
		return
	}
	signed, err := h.Users.PlatformSignIn(r.Context(), user)
	if err != nil {
		h.log().Error("could not open a platform account", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not sign in")
		return
	}
	h.platformIssue(w, r, signed, platformReply{Pin: &pin, PlatformWrap: b64(wrap)})
}

// platformUnlinked answers a sub nobody here has: new, or link_required when
// an unlinked password account already has the provider's address. That is
// a hint shown to the verified owner of the address, never a link.
//
// With WS_LOCAL_LOGIN=off the link routes are closed, and a new account
// cannot take an address another account holds, so such a sign-in has no
// step left: it is answered legacy_account_unlinked, with no ticket, and the
// operator opens link_only while the person links (docs/platform-sign-in.md).
func (h *Handler) platformUnlinked(w http.ResponseWriter, r *http.Request, ui *oidcrp.Userinfo, sub uuid.UUID, pin *oidcrp.Answer) {
	legacy, err := h.Users.UnlinkedLegacyAccount(r.Context(), ui.Email)
	if err != nil {
		h.log().Error("could not look for a legacy account", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not sign in")
		return
	}
	if legacy && !h.localAllowed(true) {
		fail(w, http.StatusForbidden, "legacy_account_unlinked",
			"a Wappie account with this address still signs in with a password, which this server no longer accepts; ask its operator to let you link it")
		return
	}
	kind, answer := store.TicketNew, platformKindNew
	if legacy {
		kind, answer = store.TicketLink, platformKindLinkRequired
	}
	ticket, expires, err := h.platformTicket(r.Context(), store.PlatformTicket{Kind: kind, Sub: sub,
		ProductKeyID: ui.ProductKeyID, ProductKey: ui.ProductKey, Email: ui.Email, Name: ui.Name})
	if err != nil {
		h.log().Error("could not issue a sign-in ticket", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not sign in")
		return
	}
	send(w, http.StatusOK, platformReply{Kind: answer, Pin: pin, Ticket: ticket, TicketExpiresAt: &expires, Email: ui.Email, Name: ui.Name})
}

func (h *Handler) platformTicket(ctx context.Context, t store.PlatformTicket) (string, time.Time, error) {
	expires := time.Now().Add(store.PlatformTicketTTL).Truncate(time.Second)
	secret, err := h.Users.CreatePlatformTicket(ctx, t)
	return secret, expires, err
}

// accountKeyChanged is the alert (O1): the event row, an Error line with a
// stable event name for log-based alerting, and a mail to the operator and
// to the account. None of them names the key, the token or the address.
// The account's mail goes in its language (users.locale), English when it
// never said one; the operator's goes in English.
func (h *Handler) accountKeyChanged(ctx context.Context, ui *oidcrp.Userinfo) {
	h.log().Error("refused a sign-in whose account key differs from the pinned one",
		slog.String("event", "platform_account_key_changed"), slog.String("product_key_id", ui.ProductKeyID))
	sub, err := uuid.Parse(ui.Sub)
	if err != nil {
		return
	}
	var userID *uuid.UUID
	type recipient struct{ to, lang string }
	recipients := []recipient{}
	if h.Platform.AlertEmail != "" {
		recipients = append(recipients, recipient{to: h.Platform.AlertEmail})
	}
	if ident, err := h.Users.PlatformIdentity(ctx, sub); err == nil {
		userID = &ident.UserID
		if user, err := h.Users.PlatformAccount(ctx, ident.UserID); err == nil && user.Email != "" {
			lang := ""
			if profile, err := h.Users.Profile(ctx, ident.UserID); err == nil {
				lang = profile.Locale
			}
			recipients = append(recipients, recipient{to: user.Email, lang: lang})
		}
	}
	if err := h.Users.RecordSecurityEvent(ctx, "platform_account_key_changed", userID, sub, map[string]string{"product_key_id": ui.ProductKeyID}); err != nil {
		h.log().Error("could not record a security event", "event", "platform_account_key_changed", "error", err)
	}
	if h.Platform.Alert == nil || len(recipients) == 0 {
		return
	}
	alert := h.Platform.Alert
	go func() {
		mailCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		for _, to := range recipients {
			if err := alert(mailCtx, to.to, to.lang); err != nil {
				h.log().Warn("could not send the account key alert", "event", "platform_account_key_changed", "error", err)
			}
		}
	}()
}

// platformIssue starts a Wappie session for an account signed in through
// the provider and answers kind session with it.
//
// The answer never carries wrapped_usk. A linked account keeps its legacy
// password wrap through the rollback window, and this answer goes to whoever
// holds an access token for the sub, with no proof of the old password; the
// page opens the account key from platform_wrap and has no use for it.
// /v1/auth/me still returns it to the session (docs/platform-sign-in.md,
// "The rollback window").
//
// The session holds no step-up proof: a sign-in through the provider proves
// nothing to this server until step 4 takes the provider's re-authentication
// (internal/stepup), so every write that needs one is refused until then.
func (h *Handler) platformIssue(w http.ResponseWriter, r *http.Request, user store.User, reply platformReply) {
	token, session, err := h.Users.StartPlatformSession(r.Context(), user, r.UserAgent())
	if err != nil {
		h.log().Error("could not start a session", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not start a session")
		return
	}
	account := toAccount(user)
	account.WrappedUSK = ""
	reply.Kind, reply.Token, reply.ExpiresAt, reply.User = platformKindSession, token, &session.ExpiresAt, &account
	send(w, http.StatusOK, reply)
}

// ticketError answers the store's refusals of the steps after a sign-in.
func (h *Handler) ticketError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrTicketInvalid):
		fail(w, http.StatusUnauthorized, "ticket_invalid", "this sign-in has expired or was already used; sign in again")
	case errors.Is(err, store.ErrBadCredentials):
		fail(w, http.StatusUnauthorized, "bad_credentials", "email or password is wrong")
	case errors.Is(err, store.ErrAlreadyLinked):
		fail(w, http.StatusConflict, "already_linked", "that account or identity is already linked")
	case errors.Is(err, store.ErrEmailTaken):
		fail(w, http.StatusConflict, "email_taken", "another account already uses this address")
	case errors.Is(err, store.ErrPlatformWrap), errors.Is(err, store.ErrInvalidMembership):
		fail(w, http.StatusBadRequest, "bad_request", "could not use the supplied information")
	default:
		h.log().Error("platform account step failed", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not finish signing in")
	}
}

// ---------------------------------------------------------------------------
// POST /v1/auth/platform/account
// ---------------------------------------------------------------------------

// platformAccount creates the account of a "new" sign-in: the public half of
// the account key the page generated, and the key under sk_p.
func (h *Handler) platformAccount(w http.ResponseWriter, r *http.Request) {
	if !h.platformRequest(w, r) {
		return
	}
	if !h.allow(w, r, "") {
		return
	}
	var req platformAccountRequest
	if !decodePlatform(w, r, &req) {
		return
	}
	pub, ok1 := unb64(w, req.PublicKey, "public_key")
	if !ok1 {
		return
	}
	wrap, ok2 := unb64(w, req.PlatformWrap, "platform_wrap")
	if !ok2 {
		return
	}
	user, err := h.Users.SignupPlatform(r.Context(), store.NewPlatformUser{Ticket: req.Ticket, PublicKey: pub, Wrap: wrap, Name: req.DisplayName})
	if err != nil {
		h.ticketError(w, err)
		return
	}
	h.platformIssue(w, r, user, platformReply{})
}

// ---------------------------------------------------------------------------
// POST /v1/auth/platform/link/prepare and /link
// ---------------------------------------------------------------------------

func (r platformLinkRequest) proof(w http.ResponseWriter) (store.LegacyProof, bool) {
	if (r.AuthKey == "") == (r.RecoveryProof == "") {
		fail(w, http.StatusBadRequest, "bad_request", "send auth_key or recovery_proof, one of the two")
		return store.LegacyProof{}, false
	}
	if r.RecoveryProof != "" {
		return store.LegacyProof{Email: r.Email, Secret: r.RecoveryProof, Recovery: true}, true
	}
	return store.LegacyProof{Email: r.Email, Secret: r.AuthKey}, true
}

// platformLinkPrepare checks the ticket and the legacy proof, and hands back
// what the browser opens the account key with. Nothing is spent but, on a
// wrong proof, one of the ticket's attempts.
func (h *Handler) platformLinkPrepare(w http.ResponseWriter, r *http.Request) {
	if !h.platformRequest(w, r) {
		return
	}
	if !h.localAllowed(true) {
		localLoginRefused(w)
		return
	}
	var req platformLinkRequest
	if !decodePlatform(w, r, &req) {
		return
	}
	if !h.allow(w, r, strings.ToLower(strings.TrimSpace(req.Email))) {
		return
	}
	if req.PlatformWrap != "" {
		fail(w, http.StatusBadRequest, "bad_request", "the wrap goes with the link, not before it")
		return
	}
	proof, ok := req.proof(w)
	if !ok {
		return
	}
	user, err := h.Users.PrepareLegacyLink(r.Context(), req.Ticket, proof)
	if errors.Is(err, store.ErrBadCredentials) {
		h.failTicket(r.Context(), req.Ticket)
	}
	if err != nil {
		h.ticketError(w, err)
		return
	}
	out := platformPrepareReply{UserID: user.ID.String(), PublicKey: b64(user.PublicKey)}
	if proof.Recovery {
		out.RecoveryWrap = b64(user.RecoveryWrap)
	} else {
		out.WrappedUSK = b64(user.WrappedUSK)
	}
	send(w, http.StatusOK, out)
}

// platformLink links the legacy account (store.LinkLegacy) and signs the
// browser into it: every other session and Wappie passkey of the account
// has just been revoked.
func (h *Handler) platformLink(w http.ResponseWriter, r *http.Request) {
	if !h.platformRequest(w, r) {
		return
	}
	if !h.localAllowed(true) {
		localLoginRefused(w)
		return
	}
	var req platformLinkRequest
	if !decodePlatform(w, r, &req) {
		return
	}
	if !h.allow(w, r, strings.ToLower(strings.TrimSpace(req.Email))) {
		return
	}
	proof, ok := req.proof(w)
	if !ok {
		return
	}
	wrap, ok := unb64(w, req.PlatformWrap, "platform_wrap")
	if !ok {
		return
	}
	user, err := h.Users.LinkLegacy(r.Context(), store.LegacyLink{Ticket: req.Ticket, Proof: proof, Wrap: wrap})
	if errors.Is(err, store.ErrBadCredentials) {
		h.failTicket(r.Context(), req.Ticket)
	}
	if err != nil {
		h.ticketError(w, err)
		return
	}
	h.accessChanged()
	h.platformIssue(w, r, user, platformReply{})
}

func (h *Handler) failTicket(ctx context.Context, ticket string) {
	if err := h.Users.FailPlatformTicket(ctx, ticket); err != nil {
		h.log().Warn("could not count a failed link attempt", "error", err)
	}
}

// ---------------------------------------------------------------------------
// POST /v1/auth/platform/rewrap
// ---------------------------------------------------------------------------

// platformRewrap stores a linked account's wrap for a new provider epoch. It
// takes the rewrap ticket of a fresh sign-in and the session of the same
// account: only a browser that still holds the account key can make the
// wrap.
func (h *Handler) platformRewrap(w http.ResponseWriter, r *http.Request) {
	if !h.platformRequest(w, r) {
		return
	}
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req platformRewrapRequest
	if !decodePlatform(w, r, &req) {
		return
	}
	wrap, ok := unb64(w, req.PlatformWrap, "platform_wrap")
	if !ok {
		return
	}
	if err := h.Users.AddPlatformWrap(r.Context(), req.Ticket, user.ID, wrap); err != nil {
		h.ticketError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// PlatformDiscovery is what /.well-known/wappie says of the provider: enough
// for the console to begin a sign-in without hard-coding it.
type PlatformDiscovery struct {
	Issuer     string `json:"issuer"`
	ClientID   string `json:"client_id"`
	Product    string `json:"product"`
	LocalLogin string `json:"local_login"`
}

// Discovery describes the configured provider, nil when there is none.
func (p *PlatformLogin) Discovery(local config.LocalLogin) *PlatformDiscovery {
	if p == nil {
		return nil
	}
	if local == "" {
		local = config.LocalLoginOn
	}
	return &PlatformDiscovery{Issuer: p.Client.Issuer, ClientID: p.Client.ClientID, Product: p.Client.Product, LocalLogin: string(local)}
}
