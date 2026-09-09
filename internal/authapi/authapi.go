// Package authapi is signing up and signing in.
//
// Over HTTP rather than the websocket, because the websocket needs credentials
// before it will open and this is where credentials come from.
//
// The password never reaches this server in any form. The browser derives a
// master key from it with Argon2id and splits that in two: one branch is the
// auth key, which arrives here and is stored only as a slow hash; the other
// never leaves the browser and unwraps the account's private key. So a database
// dump yields a hash to attack and a wrapped key to attack, and no shortcut
// past either.
//
// What that private key is for: key grants. Each grant is one device's archive
// key sealed to one account, so signing in is what turns a sealed archive into
// a readable one — and nobody has to keep 32 bytes in a text file. The first
// archive this project stored was lost precisely because somebody did.
package authapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
)

// Handler serves the auth endpoints.
type Handler struct {
	// AccessChanged promptly wakes local WebSockets after committed revocations.
	AccessChanged func()
	Users         *store.Users
	Keys          *store.Keys
	Devices       *store.Devices
	// Limits bounds how often an address, and an address, may try. Every
	// sign-in attempt costs this server an Argon2id derivation, and every
	// wrong one is a guess; without a limit both are free to whoever asks.
	// Nil allows everything, for tests.
	Limits   *ratelimit.Auth
	Log      *slog.Logger
	Passkeys *PasskeyProvider
}

// Mount registers the routes on a mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	h.mountPasskeys(mux)
	mux.HandleFunc("POST /v1/auth/challenge", h.challenge)
	mux.HandleFunc("POST /v1/auth/signup", h.signup)
	mux.HandleFunc("POST /v1/auth/login", h.login)
	mux.HandleFunc("POST /v1/auth/logout", h.logout)
	mux.HandleFunc("GET /v1/auth/me", h.me)
	mux.HandleFunc("GET /v1/auth/workspaces", h.workspaces)
	mux.HandleFunc("PUT /v1/auth/workspaces/current", h.updateWorkspace)
	mux.HandleFunc("GET /v1/auth/workspaces/capacity", h.capacity)
	mux.HandleFunc("GET /v1/auth/workspaces/devices/{deviceID}/permissions", h.permissions)
	mux.HandleFunc("PUT /v1/auth/workspaces/devices/{deviceID}/permissions", h.permissions)
	mux.HandleFunc("GET /v1/auth/workspaces/members", h.members)
	mux.HandleFunc("PUT /v1/auth/workspaces/members/{userID}", h.updateMember)
	mux.HandleFunc("POST /v1/auth/workspaces/invites", h.inviteMember)
	mux.HandleFunc("POST /v1/auth/workspaces/accept-invite", h.acceptWorkspaceInvite)
	mux.HandleFunc("POST /v1/auth/workspaces/session", h.workspaceSession)
	// The way back from a forgotten password, in two steps that share one
	// proof: open returns the wrap, finish replaces everything.
	mux.HandleFunc("POST /v1/auth/recover/open", h.recoverOpen)
	mux.HandleFunc("POST /v1/auth/recover/finish", h.recoverFinish)
	// For somebody signed in: a new password, or a new recovery code.
	mux.HandleFunc("POST /v1/auth/password", h.password)
	mux.HandleFunc("POST /v1/auth/recovery", h.recovery)
	// The same key under the same password in a newer wrap format.
	mux.HandleFunc("POST /v1/auth/rewrap", h.rewrap)
}

func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

type challengeRequest struct {
	Email string `json:"email"`
}

// challengeReply carries what a browser needs to redo the derivation.
//
// The salt and the parameters are public by design: a salt is not a secret, and
// hiding the cost factors would mean a client could not reproduce them.
type challengeReply struct {
	Salt   string          `json:"salt"`
	Params store.KDFParams `json:"params"`
}

type signupRequest struct {
	Invite string `json:"invite"`
	Email  string `json:"email"`
	// Name is what a service account is registered as. An invite issued for
	// a service takes a name and a public key and nothing else: the system
	// keeps its private key and never has a password.
	Name string `json:"name,omitempty"`
	// AuthKey is one branch of the browser's derivation. The password itself
	// is not a field here and never will be.
	AuthKey   string          `json:"auth_key"`
	KDFSalt   string          `json:"kdf_salt"`
	KDFParams store.KDFParams `json:"kdf_params"`

	PublicKey    string `json:"public_key"`
	WrappedUSK   string `json:"wrapped_usk"`
	RecoveryWrap string `json:"recovery_wrap,omitempty"`
	// RecoveryProof is the other branch of the recovery code: sent, hashed,
	// and what the wrap is handed back against. It comes with the wrap or
	// not at all.
	RecoveryProof string `json:"recovery_proof,omitempty"`
}

// recoverOpenRequest asks for the recovery wrap, proving the code first.
type recoverOpenRequest struct {
	Email         string `json:"email"`
	RecoveryProof string `json:"recovery_proof"`
}

// recoverOpenReply is what the browser opens with the other branch of the
// code. Nothing in it is new to the server: the wrap was stored at signup.
type recoverOpenReply struct {
	RecoveryWrap string `json:"recovery_wrap"`
	PublicKey    string `json:"public_key"`
}

// rekeyRequest carries everything the password protected, re-derived.
//
// The public key is not among the fields, deliberately: the private key does
// not change, only what wraps it, so every grant sealed to this account keeps
// opening. A recovery that produced a new keypair would strand every device.
type rekeyRequest struct {
	AuthKey    string          `json:"auth_key"`
	KDFSalt    string          `json:"kdf_salt"`
	KDFParams  store.KDFParams `json:"kdf_params"`
	WrappedUSK string          `json:"wrapped_usk"`
	// The recovery pair is required on a recovery — the old code was just
	// typed into a browser, which spends it — and optional on a password
	// change, where the existing one stays valid.
	RecoveryWrap  string `json:"recovery_wrap,omitempty"`
	RecoveryProof string `json:"recovery_proof,omitempty"`
}

// recoverFinishRequest proves the code again and replaces the password.
type recoverFinishRequest struct {
	Email         string       `json:"email"`
	RecoveryProof string       `json:"recovery_proof"`
	New           rekeyRequest `json:"new"`
}

// passwordRequest proves the current password and replaces it.
type passwordRequest struct {
	// AuthKey is the branch derived from the current password. A session
	// token alone does not change a password: a tab left open is not the
	// same as knowing it.
	AuthKey string       `json:"auth_key"`
	New     rekeyRequest `json:"new"`
}

// rewrapRequest proves the current password and replaces only the wrap.
type rewrapRequest struct {
	AuthKey    string `json:"auth_key"`
	WrappedUSK string `json:"wrapped_usk"`
}

// recoveryRequest proves the current password and records a new code.
type recoveryRequest struct {
	AuthKey       string `json:"auth_key"`
	RecoveryWrap  string `json:"recovery_wrap"`
	RecoveryProof string `json:"recovery_proof"`
}

type loginRequest struct {
	Email   string `json:"email"`
	AuthKey string `json:"auth_key"`
}

// sessionReply is what a successful sign-in returns.
type sessionReply struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      account   `json:"user"`
}

type account struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	// WrappedUSK is opaque to this server: it is returned exactly as it was
	// stored, for the browser to open with the half of the derivation that
	// never left it.
	WrappedUSK  string `json:"wrapped_usk"`
	PublicKey   string `json:"public_key"`
	HasRecovery bool   `json:"has_recovery"`
}

// grant is one device this account may open.
type grant struct {
	DeviceID string `json:"device_id"`
	Label    string `json:"label"`
	Epoch    int    `json:"epoch"`
	// SealedDSK is the device's private archive key under this account's
	// public key. Ciphertext here, and nowhere else.
	SealedDSK string `json:"sealed_dsk"`
}

type meReply struct {
	User      account   `json:"user"`
	Grants    []grant   `json:"grants"`
	ExpiresAt time.Time `json:"expires_at"`
	SessionID string    `json:"session_id"`
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

func (h *Handler) challenge(w http.ResponseWriter, r *http.Request) {
	var req challengeRequest
	if !decode(w, r, &req) {
		return
	}
	// By address only: a challenge is cheap and reveals nothing, so the
	// point here is not to let one source flood it.
	if !h.allow(w, r, "") {
		return
	}
	salt, params, err := h.Users.Challenge(r.Context(), req.Email)
	if err != nil {
		h.log().Error("login challenge failed", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not start the sign-in")
		return
	}
	// Answers for addresses that have no account too, with a salt derived from
	// the address. Otherwise this endpoint would tell an unauthenticated caller
	// which addresses exist, one request at a time.
	send(w, http.StatusOK, challengeReply{Salt: b64(salt), Params: params})
}

func (h *Handler) signup(w http.ResponseWriter, r *http.Request) {
	var req signupRequest
	if !decode(w, r, &req) {
		return
	}
	if !h.allow(w, r, "") {
		return
	}

	// The body is checked before the invite is spent. An invite is one-time
	// and marked used in the same statement that reads it, so a request
	// refused after redeeming it would cost somebody their only way in over
	// a typo in a base64 field.
	pub, ok := unb64(w, req.PublicKey, "public_key")
	if !ok {
		return
	}
	if req.Name != "" {
		// A service: no password material at all. The invite's role is
		// checked after it is redeemed; a mismatch is refused there.
		h.signupService(w, r, req, pub)
		return
	}
	salt, ok1 := unb64(w, req.KDFSalt, "kdf_salt")
	wrapped, ok3 := unb64(w, req.WrappedUSK, "wrapped_usk")
	if !ok1 || !ok3 {
		return
	}
	var recovery []byte
	if req.RecoveryWrap != "" {
		var ok bool
		if recovery, ok = unb64(w, req.RecoveryWrap, "recovery_wrap"); !ok {
			return
		}
	}
	if (len(recovery) > 0) != (req.RecoveryProof != "") {
		fail(w, http.StatusBadRequest, "bad_request",
			"recovery_wrap and recovery_proof come together or not at all")
		return
	}

	invite, err := h.Users.RedeemInvite(r.Context(), req.Invite)
	if errors.Is(err, store.ErrInviteInvalid) {
		fail(w, http.StatusForbidden, "invite_invalid",
			"that invite code is not valid, has been used, or has expired")
		return
	}
	if err != nil {
		h.log().Error("redeeming an invite failed", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not check the invite")
		return
	}
	if invite.Email != "" && !strings.EqualFold(invite.Email, strings.TrimSpace(req.Email)) {
		fail(w, http.StatusForbidden, "invite_invalid", "that invite is for a different address")
		return
	}
	if invite.Role == store.RoleService {
		fail(w, http.StatusForbidden, "invite_invalid",
			"that invite is for a service account; register with a name and a public key")
		return
	}

	user, err := h.Users.Create(r.Context(), store.NewUser{
		TenantID: invite.TenantID, Email: req.Email, AuthKey: req.AuthKey,
		KDFSalt: salt, KDFParams: req.KDFParams,
		PublicKey: pub, WrappedUSK: wrapped,
		RecoveryWrap: recovery, RecoveryProof: req.RecoveryProof,
		Role: invite.Role,
	})
	if errors.Is(err, store.ErrEmailTaken) {
		fail(w, http.StatusConflict, "email_taken", "that address already has an account")
		return
	}
	if err != nil {
		h.log().Warn("could not create an account", "error", err)
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	h.issue(w, r, user)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decode(w, r, &req) {
		return
	}
	// Both limits: the address, and the account being guessed at.
	if !h.allow(w, r, req.Email) {
		return
	}
	user, err := h.Users.Authenticate(r.Context(), req.Email, req.AuthKey)
	if errors.Is(err, store.ErrBadCredentials) {
		// One message for a wrong password and for an address with no account.
		fail(w, http.StatusUnauthorized, "bad_credentials", "email or password is wrong")
		return
	}
	if err != nil {
		h.log().Error("sign-in failed", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not sign in")
		return
	}
	h.issue(w, r, user)
}

func (h *Handler) issue(w http.ResponseWriter, r *http.Request, user store.User) {
	token, session, err := h.Users.StartSession(r.Context(), user, r.UserAgent())
	if err != nil {
		h.log().Error("could not start a session", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not start a session")
		return
	}
	send(w, http.StatusOK, sessionReply{
		Token: token, ExpiresAt: session.ExpiresAt, User: toAccount(user),
	})
}

// signupService registers a system's public key against a service invite.
//
// The reply carries the account and no session: a service never signs in.
// What it gets instead is an API key acting as this account, minted by an
// operator in the console once the devices have been granted.
func (h *Handler) signupService(w http.ResponseWriter, r *http.Request, req signupRequest, pub []byte) {
	invite, err := h.Users.RedeemInvite(r.Context(), req.Invite)
	if errors.Is(err, store.ErrInviteInvalid) {
		fail(w, http.StatusForbidden, "invite_invalid",
			"that invite code is not valid, has been used, or has expired")
		return
	}
	if err != nil {
		h.log().Error("redeeming an invite failed", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not check the invite")
		return
	}
	if invite.Role != store.RoleService {
		fail(w, http.StatusForbidden, "invite_invalid",
			"that invite is for a person; a service needs an invite issued with -role service")
		return
	}
	user, err := h.Users.CreateService(r.Context(), invite.TenantID, req.Name, pub)
	if errors.Is(err, store.ErrEmailTaken) {
		fail(w, http.StatusConflict, "email_taken", "a service with that name already exists here")
		return
	}
	if err != nil {
		h.log().Warn("could not create a service account", "error", err)
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	send(w, http.StatusOK, sessionReply{User: toAccount(user)})
}

// recoverOpen hands back the recovery wrap to whoever proves the code.
//
// The wrap alone opens nothing: it needs the other branch of the same code,
// which never left the browser. The proof is asked for anyway, because a
// database that answers "give me the ciphertext" to anyone is a database
// whose leak is already complete.
func (h *Handler) recoverOpen(w http.ResponseWriter, r *http.Request) {
	var req recoverOpenRequest
	if !decode(w, r, &req) {
		return
	}
	if !h.allow(w, r, req.Email) {
		return
	}
	user, err := h.Users.OpenRecovery(r.Context(), req.Email, req.RecoveryProof)
	if errors.Is(err, store.ErrBadCredentials) {
		// One answer for a wrong code, an unknown address, and an account
		// that never set a code.
		fail(w, http.StatusUnauthorized, "bad_credentials", "email or recovery code is wrong")
		return
	}
	if err != nil {
		h.log().Error("recovery failed", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not start the recovery")
		return
	}
	send(w, http.StatusOK, recoverOpenReply{
		RecoveryWrap: b64(user.RecoveryWrap), PublicKey: b64(user.PublicKey),
	})
}

// recoverFinish replaces the password, proving the code a second time.
//
// Two proofs rather than a token between the steps: the code is in the
// browser's memory for the whole exchange anyway, and a token would be one
// more credential to store, expire and revoke.
func (h *Handler) recoverFinish(w http.ResponseWriter, r *http.Request) {
	var req recoverFinishRequest
	if !decode(w, r, &req) {
		return
	}
	if !h.allow(w, r, req.Email) {
		return
	}
	user, err := h.Users.OpenRecovery(r.Context(), req.Email, req.RecoveryProof)
	if errors.Is(err, store.ErrBadCredentials) {
		fail(w, http.StatusUnauthorized, "bad_credentials", "email or recovery code is wrong")
		return
	}
	if err != nil {
		h.log().Error("recovery failed", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not finish the recovery")
		return
	}
	if req.New.RecoveryWrap == "" || req.New.RecoveryProof == "" {
		fail(w, http.StatusBadRequest, "bad_request",
			"a recovery replaces the code that was just used; send a new recovery_wrap and recovery_proof")
		return
	}
	h.rekey(w, r, user, req.New, true)
}

// password replaces the password of somebody signed in who still knows it.
func (h *Handler) password(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req passwordRequest
	if !decode(w, r, &req) {
		return
	}
	if !h.allow(w, r, user.Email) {
		return
	}
	if _, err := h.Users.Authenticate(r.Context(), user.Email, req.AuthKey); err != nil {
		fail(w, http.StatusUnauthorized, "bad_credentials", "the current password is wrong")
		return
	}
	h.rekey(w, r, user, req.New, false)
}

// rekey applies a replacement and signs the account in again: every session
// was just revoked, including the one that asked.
func (h *Handler) rekey(w http.ResponseWriter, r *http.Request, user store.User, in rekeyRequest, revokePasskeys bool) {
	salt, ok1 := unb64(w, in.KDFSalt, "kdf_salt")
	wrapped, ok2 := unb64(w, in.WrappedUSK, "wrapped_usk")
	if !ok1 || !ok2 {
		return
	}
	var recovery []byte
	if in.RecoveryWrap != "" {
		var ok bool
		if recovery, ok = unb64(w, in.RecoveryWrap, "recovery_wrap"); !ok {
			return
		}
	}
	err := h.Users.Rekey(r.Context(), user.TenantID, user.ID, store.Rekey{
		RevokePasskeys: revokePasskeys,
		AuthKey:        in.AuthKey, KDFSalt: salt, KDFParams: in.KDFParams,
		WrappedUSK: wrapped, RecoveryWrap: recovery, RecoveryProof: in.RecoveryProof,
	})
	if err != nil {
		h.log().Warn("could not replace an account's keys", "error", err)
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	h.accessChanged()
	fresh, err := h.Users.Get(r.Context(), user.TenantID, user.ID)
	if err != nil {
		h.log().Error("account unreadable after rekey", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "the change was made but the account could not be read back")
		return
	}
	h.issue(w, r, fresh)
}

// recovery records a new recovery code for somebody signed in.
//
// The current password is proved again, for the same reason a password
// change asks for it: this replaces the one credential that survives a
// forgotten password, and a tab somebody walked away from should not be
// enough to swap it.
func (h *Handler) recovery(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req recoveryRequest
	if !decode(w, r, &req) {
		return
	}
	if !h.allow(w, r, user.Email) {
		return
	}
	if _, err := h.Users.Authenticate(r.Context(), user.Email, req.AuthKey); err != nil {
		fail(w, http.StatusUnauthorized, "bad_credentials", "the current password is wrong")
		return
	}
	wrap, ok := unb64(w, req.RecoveryWrap, "recovery_wrap")
	if !ok {
		return
	}
	if err := h.Users.SetRecovery(r.Context(), user.TenantID, user.ID, wrap, req.RecoveryProof); err != nil {
		h.log().Warn("could not record a recovery code", "error", err)
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rewrap stores the private key wrapped again, for a client upgrading the
// wrap format. The password is proved so a stolen session cannot swap the
// wrap for one it can open.
func (h *Handler) rewrap(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req rewrapRequest
	if !decode(w, r, &req) {
		return
	}
	if !h.allow(w, r, user.Email) {
		return
	}
	if _, err := h.Users.Authenticate(r.Context(), user.Email, req.AuthKey); err != nil {
		fail(w, http.StatusUnauthorized, "bad_credentials", "the current password is wrong")
		return
	}
	wrapped, ok := unb64(w, req.WrappedUSK, "wrapped_usk")
	if !ok {
		return
	}
	if err := h.Users.Rewrap(r.Context(), user.TenantID, user.ID, wrapped); err != nil {
		h.log().Warn("could not rewrap an account key", "error", err)
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	token, ok := BearerToken(r)
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var req struct {
		AllRelated bool `json:"all_related"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	decodeErr := dec.Decode(&req)
	if decodeErr == nil {
		var trailing any
		if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
			fail(w, http.StatusBadRequest, "bad_request", "malformed logout request")
			return
		}
	} else if !errors.Is(decodeErr, io.EOF) {
		fail(w, http.StatusBadRequest, "bad_request", "malformed logout request")
		return
	}
	var err error
	if req.AllRelated {
		err = h.Users.EndSessionFamily(r.Context(), token)
	} else {
		err = h.Users.EndSession(r.Context(), token)
	}
	if err != nil {
		h.log().Warn("could not end a session", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not end session")
		return
	}
	h.accessChanged()
	w.WriteHeader(http.StatusNoContent)
}

// me returns the account and every device it may open.
//
// The grants are the interesting part: each is a device's archive key as
// ciphertext under this account's public key. The server hands them over freely
// because it cannot open one, and an account with no grant for a device reads
// nothing of it however the server behaves.
func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	grants, err := h.Keys.GrantsFor(r.Context(), session.TenantID, session.UserID)
	if err != nil {
		h.log().Error("could not list grants", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not list the accounts you can read")
		return
	}
	labels := map[string]string{}
	if devices, err := h.Devices.List(r.Context(), session.TenantID.String()); err == nil {
		for _, d := range devices {
			labels[d.ID] = d.Label
		}
	}

	out := meReply{User: toAccount(user), Grants: make([]grant, 0, len(grants)), ExpiresAt: session.ExpiresAt, SessionID: session.ID.String()}
	for _, g := range grants {
		out.Grants = append(out.Grants, grant{
			DeviceID: g.DeviceID.String(), Label: labels[g.DeviceID.String()],
			Epoch: int(g.Epoch), SealedDSK: b64(g.SealedDSK),
		})
	}
	send(w, http.StatusOK, out)
}

// authenticate resolves a bearer token to a session and its account.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (store.Session, store.User, bool) {
	token, ok := BearerToken(r)
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

// allow applies the rate limit, answering 429 with a Retry-After when it
// bites. The reply is the same whether the address or the subject ran out,
// because saying which would tell a caller whether the subject is worth
// spreading across more addresses.
func (h *Handler) allow(w http.ResponseWriter, r *http.Request, subject string) bool {
	ok, wait := h.Limits.Allow(r, subject)
	if ok {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())))
	fail(w, http.StatusTooManyRequests, "rate_limited",
		"too many attempts; try again in "+wait.String())
	return false
}

// BearerToken pulls a token out of the Authorization header.
func BearerToken(r *http.Request) (string, bool) {
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	token = strings.TrimSpace(token)
	if !found || token == "" {
		return "", false
	}
	return token, true
}

func toAccount(u store.User) account {
	return account{
		ID: u.ID.String(), TenantID: u.TenantID.String(), Email: store.ServiceName(u), Role: u.Role,
		WrappedUSK: b64(u.WrappedUSK), PublicKey: b64(u.PublicKey),
		HasRecovery: len(u.RecoveryWrap) > 0 && u.RecoveryUsable,
	}
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

// maxBody bounds a request. Everything here is a handful of short base64
// strings; anything larger is a mistake or an attack.
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
	// Credentials and key material. Nothing here may be cached anywhere.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	//nolint:errcheck // the client hung up; there is nothing left to say to it
	_ = json.NewEncoder(w).Encode(body)
}

func fail(w http.ResponseWriter, status int, code, message string) {
	send(w, status, wireError{Code: code, Message: message})
}

func b64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func unb64(w http.ResponseWriter, s, field string) ([]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", field+" is not base64")
		return nil, false
	}
	return raw, true
}
