package authapi

// The step-up of an account that signs in through the identity provider
// (owner decision D3, step 4 of the sign-in plan; docs/platform-sign-in.md,
// "Step-ups"). Nothing that asks for a proof changes (internal/stepup): only
// how such a session earns one.
//
//  1. POST /v1/auth/platform/step-up/start records, on the session, when it
//     asked (sessions.step_up_not_before), and answers the provider's
//     address of the linked account, which the console passes as login_hint.
//  2. The console sends the person to the provider with prompt=login and no
//     key delivery; the provider asks for the password or a passkey there.
//  3. POST /v1/auth/platform/step-up/finish {access_token} takes the token to
//     the provider's userinfo, once (never the ID token), and requires: this
//     client; the sub linked to the session's account; the account key the
//     sign-ins pinned for that epoch, compared and never pinned (Decision 4:
//     another key is refused and raises the alert); and an auth_time no more
//     than stepup.ProviderClockTolerance before the start (Decision 3). The
//     proof is then recorded as the passkey and the password record it,
//     authenticated_at = now() on the database's clock, and the start is
//     cleared in the same statement: one start, one proof.
//
// Both routes keep the rules of every /platform route (platformRequest,
// decodePlatform) and take the bearer session. No refusal clears a start; a
// new start replaces it.

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/thehappieco/kit/oidcrp"

	"whatserver2/internal/stepup"
	"whatserver2/internal/store"
)

// stepUpStartsPerWindow is how many step-ups at the provider one account may
// start within stepup.Window, across its sessions: a proof lasts that long,
// so a person needs one and retries a few.
const stepUpStartsPerWindow = 5

// The step-up's own codes beside the sign-in's, with their messages
// (E-STEP-16 to E-STEP-24, approved 2026-10-06; the console shows its own
// words by code).
const (
	stepUpHereCode            = "step_up_here"
	stepUpHereMessage         = "this account confirms it is you on this server, with its passkey or password, not at the identity provider"
	stepUpStartFailedMessage  = "could not start the confirmation"
	stepUpTokenRefusedMessage = "the identity provider refused this confirmation; confirm again"
	stepUpWrongClientMessage  = "that confirmation was not made for this application"
	stepUpUserinfoMessage     = "the identity provider could not check this confirmation; try again"
	stepUpNotStartedCode      = "step_up_not_started"
	stepUpNotStartedMessage   = "no confirmation was started for this session, or it was already used or is older than ten minutes; start it again"
	stepUpOtherAccountCode    = "step_up_other_account"
	stepUpOtherAccountMessage = "that confirmation was made with another account at the identity provider"
	stepUpStaleCode           = "step_up_stale"
	stepUpStaleMessage        = "the identity provider did not ask for the password or passkey again after this confirmation started; start it again"
	stepUpKeyChangedMessage   = "the account key presented differs from the one this account signed in with before; nothing was recorded"
	stepUpFailedMessage       = "could not record your confirmation"
)

// platformStepUpStartReply is the answer to a start: the provider's address
// of the linked account, for the console's login_hint and to name the
// account a refusal asks for, and how long the start waits for its finish.
type platformStepUpStartReply struct {
	LoginHint     string `json:"login_hint"`
	WindowSeconds int    `json:"window_seconds"`
}

type platformStepUpFinishRequest struct {
	AccessToken string `json:"access_token"`
}

// platformStepUpSession is what both routes ask before anything else: the
// page's own request, a live bearer session, and an account that steps up at
// the provider (step_up_here otherwise: a local account steps up here, with
// a passkey or the password).
func (h *Handler) platformStepUpSession(w http.ResponseWriter, r *http.Request) (store.Session, store.User, bool) {
	if !h.platformRequest(w, r) {
		return store.Session{}, store.User{}, false
	}
	session, user, ok := h.authenticate(w, r)
	if !ok {
		return store.Session{}, store.User{}, false
	}
	if !h.stepsUpAtProvider(user) {
		fail(w, http.StatusConflict, stepUpHereCode, stepUpHereMessage)
		return store.Session{}, store.User{}, false
	}
	return session, user, true
}

// stepUpSubject is an account's key in the rate limits of its step-ups.
func stepUpSubject(user store.User) string { return "platform-step-up/" + user.ID.String() }

// ---------------------------------------------------------------------------
// POST /v1/auth/platform/step-up/start
// ---------------------------------------------------------------------------

func (h *Handler) platformStepUpStart(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.platformStepUpSession(w, r)
	if !ok || !h.allow(w, r, "") {
		return
	}
	var req struct{}
	if !decodePlatform(w, r, &req) {
		return
	}
	if limit := h.Platform.StepUpStarts; limit != nil {
		if ok, wait := limit.Allow(stepUpSubject(user)); !ok {
			rateLimited(w, wait)
			return
		}
	}
	link, err := h.Users.PlatformLinkOf(r.Context(), user.ID)
	if err != nil {
		h.log().Error("could not read an account's platform link", "error", err)
		fail(w, http.StatusInternalServerError, "internal", stepUpStartFailedMessage)
		return
	}
	if _, err := h.Users.StartProviderStepUp(r.Context(), session.ID); err != nil {
		if errors.Is(err, store.ErrNoSession) {
			fail(w, http.StatusUnauthorized, "unauthorized", "that session has expired")
			return
		}
		h.log().Error("could not start a step-up", "error", err)
		fail(w, http.StatusInternalServerError, "internal", stepUpStartFailedMessage)
		return
	}
	send(w, http.StatusOK, platformStepUpStartReply{LoginHint: link.Email, WindowSeconds: int(stepup.Window.Seconds())})
}

// ---------------------------------------------------------------------------
// POST /v1/auth/platform/step-up/finish
// ---------------------------------------------------------------------------

func (h *Handler) platformStepUpFinish(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.platformStepUpSession(w, r)
	if !ok || !h.allow(w, r, stepUpSubject(user)) {
		return
	}
	var req platformStepUpFinishRequest
	if !decodePlatform(w, r, &req) {
		return
	}
	// A string that is not an access token never leaves this server.
	if !oidcrp.ValidAccessToken(req.AccessToken) {
		fail(w, http.StatusBadRequest, "bad_request", "not an access token")
		return
	}
	// Nothing goes to the provider for a session with no start to answer.
	// The start may be another session's of this one's family: the page that
	// started works in a workspace session derived from the browser's
	// sign-in, whose token the confirmation window finishes with.
	pending, err := h.Users.PendingProviderStepUp(r.Context(), session.ID, stepup.Window)
	if !h.stepUpFinishError(w, err) {
		return
	}
	link, err := h.Users.PlatformLinkOf(r.Context(), user.ID)
	if err != nil {
		h.log().Error("could not read an account's platform link", "error", err)
		fail(w, http.StatusInternalServerError, "internal", stepUpFailedMessage)
		return
	}

	ui, err := h.Platform.Client.FetchUserinfo(r.Context(), req.AccessToken)
	switch code := oidcrp.ErrorCode(err); {
	case err == nil:
	case code == "access_token":
		fail(w, http.StatusBadRequest, "bad_request", "not an access token")
		return
	case code == "token_refused":
		// The token works once: it is never retried, here or by the page.
		fail(w, http.StatusUnauthorized, "token_refused", stepUpTokenRefusedMessage)
		return
	case code == "wrong_client":
		fail(w, http.StatusForbidden, "wrong_client", stepUpWrongClientMessage)
		return
	case code == "userinfo" || code == "product_key":
		// No error of the kit names the token, the key or the account.
		h.log().Warn("the identity provider's userinfo was refused at a step-up", "error", err)
		fail(w, http.StatusBadGateway, "userinfo", stepUpUserinfoMessage)
		return
	default:
		h.log().Error("a step-up at the identity provider failed", "error", err)
		fail(w, http.StatusInternalServerError, "internal", stepUpFailedMessage)
		return
	}

	// The person who confirmed must be the one this account is linked to.
	if sub, err := uuid.Parse(ui.Sub); err != nil || sub != link.Sub {
		fail(w, http.StatusForbidden, stepUpOtherAccountCode, stepUpOtherAccountMessage)
		return
	}
	if account, err := h.Users.PlatformAccount(r.Context(), link.UserID); err != nil || account.Status != "active" || account.Role == store.RoleService {
		fail(w, http.StatusForbidden, "account_disabled", "this account is disabled")
		return
	}
	// The key the provider presents now must be the one the sign-ins pinned
	// for its epoch. This reads the pin and never makes one: an epoch no
	// sign-in here has seen is refused like another key.
	pinned, err := h.Platform.Pins.Pinned(r.Context(), link.Sub, ui.ProductKeyID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		h.stepUpKeyChanged(r, link, ui.ProductKeyID, false)
		h.keyChangedRefusal(w, ui.ProductKeyID)
		return
	case err != nil:
		h.log().Error("could not read a pin", "error", err)
		fail(w, http.StatusInternalServerError, "internal", stepUpFailedMessage)
		return
	case subtle.ConstantTimeCompare(pinned, ui.ProductKey) != 1:
		h.stepUpKeyChanged(r, link, ui.ProductKeyID, true)
		h.keyChangedRefusal(w, ui.ProductKeyID)
		return
	}

	err = h.Users.FinishProviderStepUp(r.Context(), session.ID, pending, authTimeOf(ui), stepup.Window, stepup.ProviderClockTolerance)
	if !h.stepUpFinishError(w, err) {
		return
	}
	h.log().Info("step-up confirmed", "user", user.ID, "method", "provider")
	h.stepUpReply(w, r, session, user)
}

// stepUpFinishError answers the store's refusals of a finish, and reports
// whether there was none.
func (h *Handler) stepUpFinishError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrNoSession):
		fail(w, http.StatusUnauthorized, "unauthorized", "that session has expired")
	case errors.Is(err, store.ErrStepUpNotStarted):
		fail(w, http.StatusConflict, stepUpNotStartedCode, stepUpNotStartedMessage)
	case errors.Is(err, store.ErrStepUpStale):
		fail(w, http.StatusForbidden, stepUpStaleCode, stepUpStaleMessage)
	default:
		h.log().Error("could not record a step-up", "error", err)
		fail(w, http.StatusInternalServerError, "internal", stepUpFailedMessage)
	}
	return false
}

// keyChangedRefusal answers a step-up refused for its account key, with the
// product key id as the sign-in's refusal names it.
func (h *Handler) keyChangedRefusal(w http.ResponseWriter, productKeyID string) {
	send(w, http.StatusConflict, struct {
		Code         string `json:"code"`
		Message      string `json:"message"`
		ProductKeyID string `json:"product_key_id"`
	}{"account_key_changed", stepUpKeyChangedMessage, productKeyID})
}

// stepUpKeyChanged is the alert (O1) of a step-up refused for its account
// key: the event row (with the step, and whether the epoch had a pin at
// all), the Error line with the sign-in's stable event name, and the
// step-up's mail (E-ALERT-10 to 14) to the operator and to the account. The
// pin is kept, no proof is recorded, and the session stays: it only reads.
func (h *Handler) stepUpKeyChanged(r *http.Request, link store.PlatformIdentity, productKeyID string, pinned bool) {
	detail := map[string]string{"product_key_id": productKeyID, "step": "step_up"}
	attrs := []any{slog.String("event", "platform_account_key_changed"), slog.String("product_key_id", productKeyID), slog.String("step", "step_up")}
	if !pinned {
		detail["pin"] = "missing"
		attrs = append(attrs, slog.String("pin", "missing"))
	}
	h.log().Error("refused a step-up whose account key differs from the pinned one", attrs...)
	h.raiseKeyChanged(r.Context(), link.Sub, &link.UserID, detail, h.Platform.StepUpAlert)
}
