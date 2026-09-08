package authapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"whatserver2/internal/config"
	"whatserver2/internal/store"
)

const passkeyLifetime = 5 * time.Minute

// PasskeyProvider holds only public relying-party configuration. A PRF result
// stays in the client: this server receives only an opaque encrypted key wrap.
type PasskeyProvider struct {
	web     *webauthn.WebAuthn
	rpID    string
	origins map[string]bool
	salt    []byte
}

func NewPasskeyProvider(cfg config.Passkeys) (*PasskeyProvider, error) {
	if err := cfg.Validate(false); err != nil {
		return nil, err
	}
	if cfg.RPID == "" {
		return nil, nil
	}
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyLifetime, TimeoutUVD: passkeyLifetime}
	web, err := webauthn.New(&webauthn.Config{
		RPID: cfg.RPID, RPDisplayName: "Wappie", RPOrigins: cfg.Origins,
		AttestationPreference:  protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired},
		Timeouts:               webauthn.TimeoutsConfig{Registration: timeout, Login: timeout},
	})
	if err != nil {
		return nil, err
	}
	// One public salt per RP permits discoverable login without enumerating
	// credentials. The PRF is still secret and unique to each credential.
	salt := sha256.Sum256([]byte("wappie/passkey-vault/v1/" + cfg.RPID))
	p := &PasskeyProvider{web: web, rpID: cfg.RPID, origins: map[string]bool{}, salt: salt[:]}
	for _, origin := range cfg.Origins {
		p.origins[origin] = true
	}
	return p, nil
}

func (h *Handler) mountPasskeys(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/auth/passkeys/config", func(w http.ResponseWriter, _ *http.Request) {
		out := struct {
			Enabled bool     `json:"enabled"`
			RPID    string   `json:"rp_id"`
			Origins []string `json:"origins"`
		}{Origins: []string{}}
		if h.Passkeys != nil {
			out.Enabled, out.RPID = true, h.Passkeys.rpID
			out.Origins = append(out.Origins, h.Passkeys.web.Config.RPOrigins...)
		}
		send(w, http.StatusOK, out)
	})
	mux.HandleFunc("GET /v1/auth/passkeys", h.listPasskeys)
	mux.HandleFunc("DELETE /v1/auth/passkeys/{id}", h.deletePasskey)
	mux.HandleFunc("POST /v1/auth/passkeys/register/options", h.registerPasskeyOptions)
	mux.HandleFunc("POST /v1/auth/passkeys/register/finish", h.registerPasskeyFinish)
	mux.HandleFunc("POST /v1/auth/passkeys/login/options", h.loginPasskeyOptions)
	mux.HandleFunc("POST /v1/auth/passkeys/login/finish", h.loginPasskeyFinish)
}

func (h *Handler) passkeyOrigin(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.Passkeys == nil {
		fail(w, http.StatusNotFound, "passkeys_disabled", "passkeys are not configured on this server")
		return "", false
	}
	origin := r.Header.Get("Origin")
	if !h.Passkeys.origins[origin] {
		fail(w, http.StatusForbidden, "origin_not_allowed", "this origin cannot use passkeys")
		return "", false
	}
	return origin, true
}

type passkeyUser struct {
	user        store.User
	credentials []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte                         { return u.user.ID[:] }
func (u passkeyUser) WebAuthnName() string                       { return u.user.Email }
func (u passkeyUser) WebAuthnDisplayName() string                { return u.user.Email }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (h *Handler) passkeyUser(ctx context.Context, user store.User) (passkeyUser, error) {
	u := passkeyUser{user: user}
	keys, err := h.Users.Passkeys(ctx, user.ID)
	if err != nil {
		return u, err
	}
	for _, key := range keys {
		if key.RPID != h.Passkeys.rpID {
			continue
		}
		var credential webauthn.Credential
		if err := json.Unmarshal(key.Credential, &credential); err != nil {
			return u, err
		}
		u.credentials = append(u.credentials, credential)
	}
	return u, nil
}

type passkeyOptionsReply struct {
	FlowID    uuid.UUID `json:"flow_id"`
	PublicKey any       `json:"publicKey"`
	PRFSalt   string    `json:"prf_salt"`
	RPID      string    `json:"rp_id"`
	UserID    string    `json:"user_id,omitempty"`
}

func (h *Handler) savePasskeyFlow(w http.ResponseWriter, r *http.Request, kind, origin, label string, session store.Session, data *webauthn.SessionData, publicKey any) {
	raw, err := json.Marshal(data)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not start passkey verification")
		return
	}
	flow := store.PasskeyChallenge{ID: uuid.New(), Kind: kind, UserID: session.UserID, SessionID: session.ID, Origin: origin, Data: raw, Label: label, ExpiresAt: time.Now().Add(passkeyLifetime)}
	if err := h.Users.CreatePasskeyChallenge(r.Context(), flow); err != nil {
		h.log().Error("could not save passkey challenge", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not start passkey verification")
		return
	}
	out := passkeyOptionsReply{FlowID: flow.ID, PublicKey: publicKey, PRFSalt: b64(h.Passkeys.salt), RPID: h.Passkeys.rpID}
	if session.UserID != uuid.Nil {
		out.UserID = session.UserID.String()
	}
	send(w, http.StatusOK, out)
}

func (h *Handler) passkeyPassword(w http.ResponseWriter, r *http.Request, user store.User, authKey string) bool {
	if !h.allow(w, r, user.Email) {
		return false
	}
	proved, err := h.Users.Authenticate(r.Context(), user.Email, authKey)
	if err != nil || proved.ID != user.ID {
		fail(w, http.StatusUnauthorized, "bad_credentials", "the current password is wrong")
		return false
	}
	return true
}

func (h *Handler) registerPasskeyOptions(w http.ResponseWriter, r *http.Request) {
	origin, ok := h.passkeyOrigin(w, r)
	if !ok {
		return
	}
	session, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req struct {
		AuthKey string `json:"auth_key"`
		Label   string `json:"label"`
	}
	if !decode(w, r, &req) || !h.passkeyPassword(w, r, user, req.AuthKey) {
		return
	}
	req.Label = strings.TrimSpace(req.Label)
	if req.Label == "" || utf8.RuneCountInString(req.Label) > 80 {
		fail(w, http.StatusBadRequest, "bad_request", "passkey label must have 1 to 80 characters")
		return
	}
	u, err := h.passkeyUser(r.Context(), user)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not read passkeys")
		return
	}
	if len(u.credentials) >= 12 {
		fail(w, http.StatusConflict, "passkey_limit", "remove a passkey before adding another")
		return
	}
	exclusions := make([]protocol.CredentialDescriptor, 0, len(u.credentials))
	for _, credential := range u.credentials {
		exclusions = append(exclusions, credential.Descriptor())
	}
	options, data, err := h.Passkeys.web.BeginRegistration(u,
		webauthn.WithRegistrationOrigin(origin), webauthn.WithExclusions(exclusions),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExtensions(webauthn.WithExtensionPRF(protocol.PRFValues{First: h.Passkeys.salt}), webauthn.WithExtensionCredProps()),
	)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not start passkey registration")
		return
	}
	h.savePasskeyFlow(w, r, "register", origin, req.Label, session, data, options.Response)
}

type passkeyFinishRequest struct {
	FlowID     uuid.UUID       `json:"flow_id"`
	Credential json.RawMessage `json:"credential"`
	WrappedUSK string          `json:"wrapped_usk,omitempty"`
}

func (h *Handler) consumePasskeyFlow(w http.ResponseWriter, r *http.Request, req passkeyFinishRequest, kind, origin string, session store.Session) (store.PasskeyChallenge, webauthn.SessionData, bool) {
	flow, err := h.Users.ConsumePasskeyChallenge(r.Context(), req.FlowID, kind, origin, session.UserID, session.ID)
	var data webauthn.SessionData
	if err != nil || json.Unmarshal(flow.Data, &data) != nil {
		fail(w, http.StatusUnauthorized, "bad_credentials", "passkey verification expired or was already used")
		return flow, data, false
	}
	return flow, data, true
}

// Only durable capability flags may cross this API. In particular PRF results
// are client secrets, and must never reach storage or structured logging.
func safePasskeyExtensions(raw json.RawMessage) bool {
	var credential map[string]json.RawMessage
	if json.Unmarshal(raw, &credential) != nil {
		return false
	}
	for key, value := range credential {
		if !strings.EqualFold(key, "clientExtensionResults") {
			continue
		}
		var extensions map[string]json.RawMessage
		if json.Unmarshal(value, &extensions) != nil {
			return false
		}
		for name, output := range extensions {
			var allowed string
			switch name {
			case "credProps":
				allowed = "rk"
			case "prf":
				allowed = "enabled"
			default:
				return false
			}
			var flags map[string]json.RawMessage
			if json.Unmarshal(output, &flags) != nil {
				return false
			}
			for flag, result := range flags {
				var b bool
				if flag != allowed || json.Unmarshal(result, &b) != nil {
					return false
				}
			}
		}
	}
	return true
}

func (h *Handler) registerPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	origin, ok := h.passkeyOrigin(w, r)
	if !ok {
		return
	}
	session, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !h.allow(w, r, user.Email) {
		return
	}
	var req passkeyFinishRequest
	if !decode(w, r, &req) {
		return
	}
	flow, data, ok := h.consumePasskeyFlow(w, r, req, "register", origin, session)
	if !ok {
		return
	}
	wrapped, err := base64.StdEncoding.Strict().DecodeString(req.WrappedUSK)
	if err != nil || len(wrapped) != 61 || wrapped[0] != 1 || !safePasskeyExtensions(req.Credential) {
		fail(w, http.StatusBadRequest, "bad_request", "invalid passkey envelope or extension output")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
	if err != nil {
		badPasskey(w)
		return
	}
	u, err := h.passkeyUser(r.Context(), user)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not read passkeys")
		return
	}
	credential, err := h.Passkeys.web.CreateCredential(u, data, parsed)
	if err != nil {
		badPasskey(w)
		return
	}
	if credential.Extensions.PRFEnabled == nil || !*credential.Extensions.PRFEnabled || (credential.Extensions.RK != nil && !*credential.Extensions.RK) {
		fail(w, http.StatusBadRequest, "prf_unsupported", "this passkey cannot unlock the encrypted account")
		return
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not save passkey")
		return
	}
	key := store.Passkey{UserID: user.ID, CredentialID: credential.ID, Credential: raw, Label: flow.Label, RPID: h.Passkeys.rpID, PRFSalt: h.Passkeys.salt, WrappedUSK: wrapped}
	if err := h.Users.AddPasskey(r.Context(), &key, session.ID); err != nil {
		if errors.Is(err, store.ErrNoSession) {
			badPasskey(w)
			return
		}
		fail(w, http.StatusConflict, "passkey_not_saved", "could not add this passkey; it may already be registered")
		return
	}
	send(w, http.StatusOK, map[string]any{"passkey": key})
}

func (h *Handler) loginPasskeyOptions(w http.ResponseWriter, r *http.Request) {
	origin, ok := h.passkeyOrigin(w, r)
	if !ok || !h.allow(w, r, "") {
		return
	}
	options, data, err := h.Passkeys.web.BeginDiscoverableLogin(webauthn.WithLoginOrigin(origin), webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithAssertionExtensions(webauthn.WithExtensionPRF(protocol.PRFValues{First: h.Passkeys.salt})))
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not start passkey login")
		return
	}
	h.savePasskeyFlow(w, r, "login", origin, "", store.Session{}, data, options.Response)
}

func badPasskey(w http.ResponseWriter) {
	fail(w, http.StatusUnauthorized, "bad_credentials", "could not verify this passkey")
}

func (h *Handler) loginPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	origin, ok := h.passkeyOrigin(w, r)
	if !ok || !h.allow(w, r, "") {
		return
	}
	var req passkeyFinishRequest
	if !decode(w, r, &req) {
		return
	}
	_, data, ok := h.consumePasskeyFlow(w, r, req, "login", origin, store.Session{})
	if !ok {
		return
	}
	if req.WrappedUSK != "" || !safePasskeyExtensions(req.Credential) {
		fail(w, http.StatusBadRequest, "bad_request", "invalid passkey extension output")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.Credential)
	if err != nil {
		badPasskey(w)
		return
	}
	var key store.Passkey
	var accountUser store.User
	ctx := r.Context()
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		id, err := uuid.FromBytes(userHandle)
		if err != nil {
			return nil, store.ErrBadCredentials
		}
		key, err = h.Users.Passkey(ctx, id, rawID)
		if err != nil || key.RPID != h.Passkeys.rpID {
			return nil, store.ErrBadCredentials
		}
		accountUser, err = h.Users.LoginIdentity(ctx, id)
		if err != nil {
			return nil, store.ErrBadCredentials
		}
		var credential webauthn.Credential
		if err := json.Unmarshal(key.Credential, &credential); err != nil {
			return nil, err
		}
		return passkeyUser{user: accountUser, credentials: []webauthn.Credential{credential}}, nil
	}
	_, credential, err := h.Passkeys.web.ValidatePasskeyLogin(handler, data, parsed)
	if err != nil || credential.Authenticator.CloneWarning {
		badPasskey(w)
		return
	}
	raw, err := json.Marshal(credential)
	if err != nil || h.Users.UpdatePasskey(r.Context(), key, raw) != nil {
		badPasskey(w)
		return
	}
	token, session, err := h.Users.StartPasskeySession(r.Context(), accountUser, r.UserAgent(), key.ID)
	if err != nil {
		badPasskey(w)
		return
	}
	send(w, http.StatusOK, struct {
		sessionReply
		Passkey map[string]string `json:"passkey"`
	}{sessionReply{Token: token, ExpiresAt: session.ExpiresAt, User: toAccount(accountUser)}, map[string]string{"id": key.ID.String(), "wrapped_usk": b64(key.WrappedUSK), "prf_salt": b64(key.PRFSalt)}})
}

func (h *Handler) listPasskeys(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	keys, err := h.Users.Passkeys(r.Context(), user.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not read passkeys")
		return
	}
	send(w, http.StatusOK, map[string]any{"passkeys": keys})
}

func (h *Handler) deletePasskey(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.passkeyOrigin(w, r); !ok {
		return
	}
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req struct {
		AuthKey string `json:"auth_key"`
	}
	if !decode(w, r, &req) || !h.passkeyPassword(w, r, user, req.AuthKey) {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "invalid passkey id")
		return
	}
	if err := h.Users.RevokePasskey(r.Context(), user.ID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, http.StatusNotFound, "not_found", "passkey not found")
			return
		}
		fail(w, http.StatusInternalServerError, "internal", "could not remove passkey")
		return
	}
	h.accessChanged()
	send(w, http.StatusOK, map[string]bool{"ok": true})
}
