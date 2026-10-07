package authapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"whatserver2/internal/stepup"
	"whatserver2/internal/store"
)

// The step-up (internal/stepup): a signed-in person proves again that they are
// the one at the screen before a write that hands their archive on, to an
// assistant's reader or to anyone a number's key is granted to. Two proofs
// this server checks itself: a WebAuthn assertion with user verification
// from one of the account's passkeys, and the password's auth key, compared
// as at sign-in. A sign-in within the window counts as well, and asks for
// nothing. Each proof is recorded on the session, on the database's clock,
// and lasts stepup.Window.
//
// An account that signs in through the identity provider steps up there
// instead (decision D3, step 4 of the sign-in plan): while the provider is
// configured its passkey and password step-ups answer step_up_at_provider,
// the status says provider, and POST /v1/auth/platform/step-up/start and
// /finish take the provider's re-authentication (platform_stepup.go). Both
// proofs here are password routes, so they close with WS_LOCAL_LOGIN as the
// others do (stepUpHere); the provider's stays open.

func (h *Handler) mountStepUp(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/auth/step-up", h.stepUpStatus)
	mux.HandleFunc("POST /v1/auth/step-up/passkey/options", h.stepUpPasskeyOptions)
	mux.HandleFunc("POST /v1/auth/step-up/passkey", h.stepUpPasskey)
	mux.HandleFunc("POST /v1/auth/step-up/password", h.stepUpPassword)
	mux.HandleFunc("PUT /v1/auth/locale", h.locale)
}

// stepUpReply is where a session's proof stands: fresh or not, the whole
// seconds it still lasts, the window, whether the account can step up with a
// passkey on this server, and whether it steps up at the identity provider
// instead (then neither a passkey nor the password is taken here). The
// password can otherwise.
type stepUpReply struct {
	Fresh            bool `json:"fresh"`
	RemainingSeconds int  `json:"remaining_seconds"`
	WindowSeconds    int  `json:"window_seconds"`
	Passkey          bool `json:"passkey"`
	Provider         bool `json:"provider"`
}

// stepsUpAtProvider reports whether an account's step-up is the identity
// provider's re-authentication rather than a passkey or the password here:
// an account that signs in through the provider, while the provider is
// configured. With the provider unset (a rollback), a linked account signs
// in with its legacy password again and steps up with it; one created
// through the provider has no password and cannot sign in at all.
func (h *Handler) stepsUpAtProvider(user store.User) bool {
	return h.Platform != nil && authSource(user) == store.PlatformAuthSource
}

// stepUpHere reports whether this account may step up with a passkey or the
// password on this server, and answers why not otherwise: step_up_at_provider
// for an account that steps up at the identity provider (internal/stepup),
// local_login_disabled once WS_LOCAL_LOGIN closes the password routes.
func (h *Handler) stepUpHere(w http.ResponseWriter, user store.User) bool {
	if h.stepsUpAtProvider(user) {
		fail(w, http.StatusConflict, stepup.ProviderCode, stepup.ProviderMessage)
		return false
	}
	if !h.localAllowed(false) {
		localLoginRefused(w)
		return false
	}
	return true
}

func (h *Handler) stepUpReply(w http.ResponseWriter, r *http.Request, session store.Session, user store.User) {
	left, err := h.Users.StepUpRemaining(r.Context(), session.ID, stepup.Window)
	if errors.Is(err, store.ErrNoSession) {
		fail(w, http.StatusUnauthorized, "unauthorized", "that session has expired")
		return
	}
	if err != nil {
		h.log().Error("could not read a session's step-up", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not read your confirmation")
		return
	}
	provider, passkey := h.stepsUpAtProvider(user), false
	if h.Passkeys != nil && !provider && h.localAllowed(false) {
		u, err := h.passkeyUser(r.Context(), user)
		if err != nil {
			h.log().Warn("could not read passkeys for a step-up", "error", err)
		}
		passkey = len(u.credentials) > 0
	}
	send(w, http.StatusOK, stepUpReply{
		Fresh: left > 0, RemainingSeconds: int(left.Seconds()), WindowSeconds: int(stepup.Window.Seconds()), Passkey: passkey, Provider: provider,
	})
}

// stepUpStatus answers whether this session's proof is fresh, so the console
// asks for nothing when it is.
func (h *Handler) stepUpStatus(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	h.stepUpReply(w, r, session, user)
}

// stepUpPasskeyOptions starts an assertion over the account's own passkeys,
// with user verification required, bound to this session and origin. No PRF:
// the session already holds the account key, and the assertion only proves
// the person.
func (h *Handler) stepUpPasskeyOptions(w http.ResponseWriter, r *http.Request) {
	origin, ok := h.passkeyOrigin(w, r)
	if !ok {
		return
	}
	session, user, ok := h.authenticate(w, r)
	if !ok || !h.stepUpHere(w, user) || !h.allow(w, r, user.Email) {
		return
	}
	u, err := h.passkeyUser(r.Context(), user)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not read passkeys")
		return
	}
	if len(u.credentials) == 0 {
		fail(w, http.StatusConflict, "no_passkey", "this account has no passkey on this server; confirm with your password")
		return
	}
	options, data, err := h.Passkeys.web.BeginLogin(u, webauthn.WithLoginOrigin(origin), webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not start passkey verification")
		return
	}
	h.savePasskeyFlow(w, r, stepUpFlow, origin, "", session, data, options.Response)
}

// stepUpFlow is a step-up's passkey_challenges kind (0047). The provider's
// step-up of step 4 keeps no flow here: it records
// sessions.step_up_not_before (0048) instead.
const stepUpFlow = "step_up"

// stepUpPasskey finishes a passkey step-up: the flow must be this session's,
// from this origin, unexpired and unused; the assertion must verify against
// one of the account's live passkeys with user verification; then the
// session's proof is now.
func (h *Handler) stepUpPasskey(w http.ResponseWriter, r *http.Request) {
	origin, ok := h.passkeyOrigin(w, r)
	if !ok {
		return
	}
	session, user, ok := h.authenticate(w, r)
	if !ok || !h.stepUpHere(w, user) || !h.allow(w, r, user.Email) {
		return
	}
	var req passkeyFinishRequest
	if !decode(w, r, &req) {
		return
	}
	_, data, ok := h.consumePasskeyFlow(w, r, req, stepUpFlow, origin, session)
	if !ok {
		return
	}
	if req.WrappedUSK != "" || !safePasskeyExtensions(req.Credential) {
		fail(w, http.StatusBadRequest, "bad_request", "invalid passkey extension output")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.Credential)
	if err != nil || !parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		badPasskey(w)
		return
	}
	keys, err := h.Users.Passkeys(r.Context(), user.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not read passkeys")
		return
	}
	u, err := h.passkeyUser(r.Context(), user)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not read passkeys")
		return
	}
	credential, err := h.Passkeys.web.ValidateLogin(u, data, parsed)
	if err != nil || credential.Authenticator.CloneWarning {
		badPasskey(w)
		return
	}
	i := slices.IndexFunc(keys, func(k store.Passkey) bool {
		return k.RPID == h.Passkeys.rpID && bytes.Equal(k.CredentialID, credential.ID)
	})
	if i < 0 {
		badPasskey(w)
		return
	}
	raw, err := json.Marshal(credential)
	if err != nil || h.Users.UpdatePasskey(r.Context(), keys[i], raw) != nil {
		badPasskey(w)
		return
	}
	h.markStepUp(w, r, session, user, "passkey")
}

// stepUpPassword finishes a password step-up: the auth key the browser
// derived from the password, compared as sign-in compares it, on the sign-in
// budget. The password itself never arrives.
func (h *Handler) stepUpPassword(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.authenticate(w, r)
	if !ok || !h.stepUpHere(w, user) {
		return
	}
	var req struct {
		AuthKey string `json:"auth_key"`
	}
	if !decode(w, r, &req) || !h.passkeyPassword(w, r, user, req.AuthKey) {
		return
	}
	h.markStepUp(w, r, session, user, "password")
}

func (h *Handler) markStepUp(w http.ResponseWriter, r *http.Request, session store.Session, user store.User, method string) {
	if err := h.Users.MarkStepUp(r.Context(), session.ID); err != nil {
		if errors.Is(err, store.ErrNoSession) {
			fail(w, http.StatusUnauthorized, "unauthorized", "that session has expired")
			return
		}
		h.log().Error("could not record a step-up", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not record your confirmation")
		return
	}
	h.log().Info("step-up confirmed", "user", user.ID, "method", method)
	h.stepUpReply(w, r, session, user)
}

// stepUpFresh refuses a write that needs a fresh proof when this session has
// none (internal/stepup), with the code the console asks again on.
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

// locale records the language the person's console is set to, for the
// e-mails this server sends them (0047).
func (h *Handler) locale(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req struct {
		Locale string `json:"locale"`
	}
	if !decode(w, r, &req) {
		return
	}
	out, err := h.Users.SetLocale(r.Context(), user.ID, req.Locale)
	switch {
	case errors.Is(err, store.ErrInvalidLocale):
		fail(w, http.StatusBadRequest, "bad_request", "locale must be one of en, pt, es, fr or de")
		return
	case err != nil:
		fail(w, http.StatusInternalServerError, "internal", "could not save your language")
		return
	}
	send(w, http.StatusOK, out)
}
