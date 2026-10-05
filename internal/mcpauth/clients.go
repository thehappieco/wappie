package mcpauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"whatserver2/internal/netguard"
	"whatserver2/internal/store"
)

// Any MCP client (docs/mcp-enclave.md §19.12, §19.21): a 0.6.0 reader
// describes every request in a version-2 descriptor that names the client,
// its tier and its limits, and attests the whole of it. This server relays
// every descriptor verbatim and keys its checks on descriptor_version, never
// on a reader's capabilities: version 1 is a reader before 0.6.0, checked as
// before against WS_MCP_REDIRECT_HOSTS; version 2 is held to the host
// predicate, to what each kind of client must carry, and to the operator's
// switches. None of it verifies the attestation, which the console does: the
// checks catch drift, and the switches let this server refuse a tier or a
// client, never admit one.

// Descriptor versions and kinds.
const (
	descriptorV1 = 1
	descriptorV2 = 2
	// The kinds of a version-2 descriptor (§19.12).
	kindConnect     = "connect"
	kindRenewal     = "renewal"
	kindAIRenewal   = "ai_renewal"
	kindTokenReq    = "token"
	kindLiveList    = "live_list"
	maxRedirectURI  = 2048
	maxClientIDLen  = 512
	testedIDPattern = `^[a-z][a-z0-9_]{0,31}$`
)

var testedID = regexp.MustCompile(testedIDPattern)

// versioned is the part every descriptor shares: its version (absent before
// 0.6.0, which is version 1) and its kind.
type versioned struct {
	DescriptorVersion *int   `json:"descriptor_version"`
	Kind              string `json:"kind"`
}

// version reads a descriptor's version: 1 when the member is absent, 2 when
// it says 2, and an error for anything else.
func descriptorVersion(raw json.RawMessage) (int, string, error) {
	var v versioned
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, "", errors.New("the descriptor is not the expected object")
	}
	switch {
	case v.DescriptorVersion == nil:
		return descriptorV1, v.Kind, nil
	case *v.DescriptorVersion == descriptorV2:
		return descriptorV2, v.Kind, nil
	}
	return 0, "", fmt.Errorf("descriptor_version %d is not one this server reads", *v.DescriptorVersion)
}

// describedClient is a version-2 descriptor's client, as a connect or a
// renewal descriptor carries it (§19.12, §19.16).
type describedClient struct {
	ClientKind   string  `json:"client_kind"`
	ClientID     *string `json:"client_id"`
	TestedID     *string `json:"tested_id"`
	ClientHost   *string `json:"client_host"`
	Registrable  *string `json:"registrable"`
	SharedSuffix *string `json:"shared_suffix"`
	ClientLocal  bool    `json:"client_local"`
	ClientName   *string `json:"client_name"`
	ClaimedName  *string `json:"claimed_name"`
	Trust        string  `json:"trust"`
	LimitsTier   string  `json:"limits_tier"`
	// A connect descriptor's redirect.
	RedirectURI   string `json:"redirect_uri"`
	RedirectHost  string `json:"redirect_host"`
	RedirectLocal bool   `json:"redirect_local"`
}

// host is the client's host, "" for none.
func (c describedClient) host() string { return deref(c.ClientHost) }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// tier is the limits tier §19.6 gives the client's trust and locality.
func (c describedClient) tier() string {
	return store.LimitsTier(c.Trust, c.ClientLocal, c.ClientKind)
}

// parseClient reads a version-2 descriptor's client.
func parseClient(raw json.RawMessage) (*describedClient, error) {
	var c describedClient
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New("the descriptor's client is not the expected shape")
	}
	return &c, nil
}

// checkConnectClient holds a version-2 connect descriptor's client to what
// §19.12 and §19.13 say it carries. dcrHosts are WS_MCP_DCR_HOSTS.
func checkConnectClient(c *describedClient, dcrHosts []string) error {
	if c.Trust != store.TrustTested && c.Trust != store.TrustUnknown {
		return errors.New("trust is neither tested nor unknown")
	}
	h, reason := netguard.CheckHost(c.host())
	if reason != "" {
		return fmt.Errorf("client_host is refused (%s)", reason)
	}
	// The registrable domain and the shared suffix are the reader's, from
	// the same snapshot; another answer here is a snapshot that drifted.
	if deref(c.Registrable) != h.Registrable || deref(c.SharedSuffix) != h.SharedSuffix || (c.SharedSuffix == nil) != (h.SharedSuffix == "") {
		return errors.New("registrable and shared_suffix are not the host's")
	}
	if c.LimitsTier != c.tier() {
		return errors.New("limits_tier does not follow trust and client_local")
	}
	if c.RedirectLocal != c.ClientLocal {
		return errors.New("redirect_local and client_local disagree")
	}
	if _, reason := netguard.CheckHost(strings.ToLower(c.RedirectHost)); reason != "" {
		return errors.New("redirect_host is not a client's host")
	}
	redirect, err := redirectURI(c.RedirectURI, c.ClientLocal)
	if err != nil {
		return err
	}
	switch c.ClientKind {
	case store.ClientCIMD:
		id, reason := netguard.ParseCIMDID(deref(c.ClientID))
		if reason != "" {
			return fmt.Errorf("client_id is not a client id document's address (%s)", reason)
		}
		if id.Host.Host != c.host() {
			return errors.New("client_host is not the host of client_id")
		}
	case store.ClientDCR:
		if c.ClientID == nil || *c.ClientID == "" || len(*c.ClientID) > maxClientIDLen {
			return errors.New("a registered client has a client_id")
		}
		if c.Trust != store.TrustTested || c.ClientLocal {
			return errors.New("a registered client is tested and never loopback")
		}
		if !slices.Contains(dcrHosts, c.host()) {
			return errors.New("a registered client's host is not in WS_MCP_DCR_HOSTS")
		}
		if redirect != c.host() {
			return errors.New("a registered client's host is not its redirect's")
		}
	default:
		return errors.New("client_kind is neither cimd nor dcr")
	}
	if !c.ClientLocal && redirect != strings.ToLower(c.RedirectHost) {
		return errors.New("redirect_host is not the redirect's host")
	}
	if c.Trust == store.TrustUnknown && !c.ClientLocal && redirect != c.host() {
		// D8: an untested web client's redirect is on its document's host.
		return errors.New("an untested client's redirect is not on its host")
	}
	switch c.Trust {
	case store.TrustTested:
		if c.TestedID == nil || !testedID.MatchString(*c.TestedID) {
			return errors.New("a tested client has a tested_id")
		}
		if c.ClientName == nil || !validClientName(*c.ClientName) {
			return errors.New("a tested client's client_name is not a name")
		}
	case store.TrustUnknown:
		if c.TestedID != nil && !testedID.MatchString(*c.TestedID) {
			return errors.New("tested_id is malformed")
		}
		if deref(c.ClientName) != c.host() {
			return errors.New("an untested client's client_name is not its host")
		}
	}
	if c.ClaimedName != nil && !validClientName(*c.ClaimedName) {
		return errors.New("claimed_name is not a name")
	}
	return nil
}

// redirectURI checks a connect descriptor's full redirect and returns its
// host: https on the web, http to the loopback for an app on the person's
// computer.
func redirectURI(raw string, local bool) (string, error) {
	if raw == "" || len(raw) > maxRedirectURI || !utf8.ValidString(raw) {
		return "", errors.New("redirect_uri is missing or too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || u.Host == "" {
		return "", errors.New("redirect_uri is not an absolute address")
	}
	host := u.Hostname()
	if local {
		addr, perr := netip.ParseAddr(host)
		if u.Scheme != "http" || host != "localhost" && (perr != nil || !addr.IsLoopback() || addr.Zone() != "") {
			return "", errors.New("a loopback redirect_uri is not http to the loopback")
		}
		return host, nil
	}
	if u.Scheme != "https" || u.Port() != "" {
		return "", errors.New("a web redirect_uri is not https without a port")
	}
	return strings.ToLower(host), nil
}

// clientRefusal is what the operator's switches say of a client: "" when
// they let it through, else the code to refuse it with. A client Wappie has
// not tested, a console token included, is refused unless WS_MCP_CIMD_MODE
// is any; a tested client listed in WS_MCP_BLOCKED_CLIENTS always is.
func (h *Handler) clientRefusal(trust, tested string) string {
	if trust == store.TrustUnknown && !h.UnknownAllowed {
		return "client_not_allowed"
	}
	if tested != "" && slices.Contains(h.BlockedClients, tested) {
		return "client_not_allowed"
	}
	return ""
}

// checkClientConsent holds a consent to a version-2 descriptor to the client
// the reader attested (§19.21), and fills in the client fields the ledger
// keeps. It answers the refusal itself and returns false.
func (h *Handler) checkClientConsent(w http.ResponseWriter, r *http.Request, user store.User, c *describedClient, req createRequest,
	in *store.CreateMCPConnection) bool {
	if err := checkConnectClient(c, h.DCRHosts); err != nil {
		h.log().Warn("an attested reader described a client this server does not accept", "error", err)
		fail(w, http.StatusBadGateway, "reader_unavailable", "the assistant connector described its client in a way this server does not accept")
		return false
	}
	if code := h.clientRefusal(c.Trust, deref(c.TestedID)); code != "" {
		h.log().Info("a consent was refused by the client switches", "client_host", c.host(), "trust", c.Trust)
		fail(w, http.StatusForbidden, code, "this assistant may not connect to this workspace right now")
		return false
	}
	bad := func(msg string) bool {
		fail(w, http.StatusBadRequest, "bad_request", msg)
		return false
	}
	if req.Trust == nil || *req.Trust != c.Trust || req.ClientHost == nil || *req.ClientHost != c.host() ||
		req.ClientLocal == nil || *req.ClientLocal != c.ClientLocal ||
		(req.ClaimedName == nil) != (c.ClaimedName == nil) || deref(req.ClaimedName) != deref(c.ClaimedName) {
		return bad("trust, client_host, client_local and claimed_name must be the request's")
	}
	if in.ClientName != deref(c.ClientName) {
		return bad("client_name does not match the request")
	}
	switch c.Trust {
	case store.TrustTested:
		if req.HistoryDays != nil {
			return bad("a tested client reads the whole history: history_days must be null")
		}
	case store.TrustUnknown:
		if req.HistoryDays == nil || !slices.Contains(store.HistoryDayChoices, *req.HistoryDays) {
			return bad("history_days must be 7, 30 or 90 for a client Wappie has not tested")
		}
		in.HistoryDays = *req.HistoryDays
	}
	content := in.Kind == store.KindContent
	if content && in.ConsentVersion != store.ClientConsentVersion {
		return bad("a consent to this reader is consent_version 4")
	}
	if in.SendMode != "" && (c.Trust != store.TrustTested || c.ClientLocal) {
		return bad("only a tested client on the web may draft")
	}
	if in.ExpiresAt.After(time.Now().Add(store.MaxLifetime(in.Kind, c.tier()))) {
		return bad("expires_at is past what this client may be given")
	}
	if content && c.Trust == store.TrustUnknown && !h.mayGiveUntestedText(w, r, user) {
		return false
	}
	in.ClientKind, in.ClientHost, in.ClientLocal, in.Trust = c.ClientKind, c.host(), c.ClientLocal, c.Trust
	in.ClaimedName = deref(c.ClaimedName)
	in.Replaces = req.Replace
	if c.ClientKind == store.ClientCIMD {
		// A registered client's id is random and is not kept.
		in.ClientID = deref(c.ClientID)
	}
	return true
}

// noticesReady reports whether a notice e-mail can go at all.
func (h *Handler) noticesReady() bool { return h.MailNotice != nil && h.NoticeOrigin != "" }

// mayGiveUntestedText is the notice precondition (D7, §19.21): text for a
// client Wappie has not tested, or for a token, only while this server can
// send the new-assistant e-mail and the consenting person's address is
// verified. It answers the refusal itself.
func (h *Handler) mayGiveUntestedText(w http.ResponseWriter, r *http.Request, user store.User) bool {
	if !h.noticesReady() {
		fail(w, http.StatusForbidden, "email_unverified", "an untested assistant or a token reads text only while this server can send its notice e-mail")
		return false
	}
	verified, err := h.Users.EmailVerified(r.Context(), user.TenantID, user.ID)
	if err != nil {
		h.log().Error("could not read whether an address is verified", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not record the consent")
		return false
	}
	if !verified {
		fail(w, http.StatusForbidden, "email_unverified", "confirm your e-mail to let an untested assistant read text")
		return false
	}
	return true
}
