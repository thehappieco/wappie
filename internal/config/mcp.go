package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// MCP is the hosted assistant connector: the Go half of the remote MCP
// readers. The "hosted" reader runs as a separate process on this host and
// talks to this server over loopback only; an attested reader runs in a
// Nitro Enclave and talks to it over HMAC-signed HTTPS.
//
// Off by default. A deployment that does not run a reader gains nothing
// from the routes and should not carry them; when it is on, every value of
// every listed reader is required, because a half-configured relay is one
// that answers the console with a 502 at the moment somebody consents.
type MCP struct {
	Enabled bool
	// ReaderURL is where the reader listens. Loopback http only: the relay
	// carries a sealed bundle and a shared secret, and neither may leave the
	// host.
	ReaderURL string
	// RelaySecret authenticates the two processes to each other. Never
	// logged; String renders only whether it is set.
	RelaySecret string
	// PublicOrigin is where the reader is reachable from the internet. The
	// console derives the completion URL from it, so it must match what
	// nginx serves — https in prod, http localhost in development.
	PublicOrigin string
	// RedirectHosts are the exact hosts an OAuth client may redirect to and
	// whose client metadata documents this server will fetch on the reader's
	// behalf, for a reader before 0.6.0: a version-1 descriptor's consent is
	// checked against them, and the metadata relay fetches only from them.
	// The reader carries the same list under its own name; the runbook says
	// they must match. A 0.6.0 reader fetches documents itself and describes
	// its clients in a version-2 descriptor (docs/mcp-enclave.md §19.21), so
	// the list goes with the last reader before it.
	RedirectHosts []string
	// CIMDMode is WS_MCP_CIMD_MODE: CIMDModeAllowlist (the default) refuses
	// every consent for a client Wappie has not tested, console tokens
	// included; CIMDModeAny admits them. BlockedClients are tested clients'
	// ids (WS_MCP_BLOCKED_CLIENTS) refused whatever the mode. DCRHosts are
	// the hosts a dynamically registered client may be identified by
	// (WS_MCP_DCR_HOSTS). All three can only refuse what a reader admitted.
	CIMDMode       string
	BlockedClients []string
	DCRHosts       []string
	// NoticeOrigin is this server's public origin (WS_MCP_NOTICE_ORIGIN),
	// where a new-assistant e-mail's revoke-only link points. Unset, no
	// notice e-mail goes, and so no untested client or token is given text.
	NoticeOrigin string
	// OpenAIAppsChallenge is the domain-verification token OpenAI's plugin
	// portal issues for the MCP server's origin, served verbatim at
	// /.well-known/openai-apps-challenge. Empty until a submission asks for
	// one; the path answers 404 until then.
	OpenAIAppsChallenge string
	// Readers are the reader ids WS_MCP_READERS lists, in its order;
	// "hosted" alone by default. The four fields above are the hosted
	// reader's and are required only when it is listed.
	Readers []string
	// Attested are the listed readers other than "hosted": readers that run
	// off this host (a Nitro Enclave) and talk to this server over
	// HMAC-signed HTTPS, each with its own WS_MCP_READER_<ID>_* block.
	Attested []MCPReader
	// ContentEnabled is the kill switch for content connections: message
	// text read inside the enclave reader. Off by default; off, every
	// content connection's key is dropped within a minute and no new one
	// is consented, while the consents themselves survive.
	ContentEnabled bool
	// WorkspaceDefault is WS_MCP_WORKSPACE_DEFAULT, "on" or "off" (the
	// default): what each workspace's own assistant switches are until its
	// owner sets them in the console (docs/mcp-enclave.md §19.30). On for
	// Wappie Cloud, where every workspace may let assistants read text,
	// attachments, drafts and AI; off for a self-hosted server, which keeps
	// them off unless configured. Below the kill switches, the deny list and
	// the enclave reader's TENANTS, which still decide first.
	WorkspaceDefault bool
	// DenyTenants (WS_MCP_DENY_TENANTS) are the workspaces refused text,
	// attachments, drafts and AI whatever their own switches say: the
	// operator's word on one workspace, where the kill switches speak for
	// all. Empty by default.
	DenyTenants []uuid.UUID
	// MediaEnabled is the switch for attachments: a content connection
	// whose consent carries media may open attachment contents inside the
	// enclave reader. Off by default; off, the status of every media
	// connection says media is not allowed within a minute, while its text
	// keeps working and its consent survives. It rides on content: with
	// ContentEnabled off it is off too, and its kinds are not inspected.
	MediaEnabled bool
	// MediaOffKinds are the attachment kinds switched off at the reader, a
	// sorted subset of MediaKinds: the reader refuses them while text and
	// the other kinds keep working. /v1/media does not look at kinds, so
	// only the reader enforces them. Empty by default.
	MediaOffKinds []string
	// SendEnabled is the switch for sending (docs/mcp-enclave.md §17): a
	// content connection whose consent carries sending may draft messages
	// for the person who consented to confirm in the console. Off by
	// default; off, every draft, send and confirmation is refused at once
	// and the status of every such connection says sending is off within a
	// minute, while reading keeps working and the consent survives. It rides
	// on content, and on is a configuration error while content is off.
	SendEnabled bool
	// SendSelfEnabled lets those connections send notes to the number's own
	// chat as well, if their consent says so. Read only while SendEnabled.
	SendSelfEnabled bool
	// SendDirectEnabled is direct send's switch (S3). Until its server
	// ships, true is a configuration error while SendEnabled is on.
	SendDirectEnabled bool
	// SendLimits are the sending limits, each at most the image's ceiling
	// (SendCeilings): an operator may lower a limit, never raise one.
	SendLimits MCPSendLimits
	// AIEnabled is the switch for AI integrations (docs/mcp-enclave.md §18):
	// the attested reader sends attachments to the AI providers a person
	// chose, with their own keys, and stores what comes back. Off by default;
	// off, every AI authorization's status reads reseal and the reader wipes
	// its keys within a minute, while the authorizations, the keychain and
	// the stored results survive. It rides on attachments (see ai.go).
	AIEnabled bool
	// AIOffProviders and AIOffFeatures are the providers and functions
	// switched off everywhere, sorted subsets of AIProviders and AIFeatures:
	// every AI status answer carries them, and no new authorization may use
	// them. Empty by default.
	AIOffProviders []string
	AIOffFeatures  []string

	// readersErr is what was wrong with WS_MCP_READERS itself, and
	// strayHosted the WS_MCP_READER_HOSTED_* names that were set. Both are
	// reported by Validate, because a disabled connector is not inspected.
	readersErr  error
	strayHosted []string
	// workspaceDefaultErr is a WS_MCP_WORKSPACE_DEFAULT that is neither on
	// nor off, denyErr a WS_MCP_DENY_TENANTS value that did not parse,
	// mediaOffErr a word of WS_MCP_MEDIA_OFF_KINDS that is not a kind and
	// sendLimitErrs the sending limits that did not.
	workspaceDefaultErr error
	denyErr             error
	mediaOffErr         error
	sendLimitErrs       []error
	// retiredLists are the operator's former workspace lists that are still
	// set (WS_MCP_CONTENT_TENANTS and its kin): Validate refuses them while
	// their switch is on, so nobody believes they still restrict anything.
	retiredLists map[string]bool
	// blockedErr and dcrHostErr are what was wrong with
	// WS_MCP_BLOCKED_CLIENTS and WS_MCP_DCR_HOSTS.
	blockedErr error
	dcrHostErr error
	// aiOffProvidersErr and aiOffFeaturesErr are the same for the AI block.
	aiOffProvidersErr error
	aiOffFeaturesErr  error
}

// MCPSendLimits bound what a connection that may send does, per connection
// unless named otherwise (docs/mcp-enclave.md §17.3, §17.10).
type MCPSendLimits struct {
	// DraftsPerHour are the drafts a connection may create in a rolling hour.
	DraftsPerHour int
	// DraftsPending are the drafts a connection may have waiting at once.
	DraftsPending int
	// PerDay are the own-chat and direct sends in a rolling 24 hours.
	PerDay int
	// PerChatPerDay are the direct sends to one chat in a rolling 24 hours
	// (S3).
	PerChatPerDay int
	// MinInterval is the least time between two sends of a connection.
	MinInterval time.Duration
	// TenantPerDay are the own-chat and direct sends of a whole workspace
	// in a rolling 24 hours: this server's own bound, which the image does
	// not know.
	TenantPerDay int
}

// SendCeilings are the image's limits (packages/mcp-http/enclave/send/
// policy.mjs, measured in PCR0), and the defaults. The effective limit is the
// lower of this server's and the image's, so a value above its ceiling is a
// configuration error rather than a promise the reader would not keep. The
// interval is the other way round: the image's is the shortest, and a longer
// one here is allowed. TenantPerDay is this server's only.
var SendCeilings = MCPSendLimits{
	DraftsPerHour: 30, DraftsPending: 20, PerDay: 20, PerChatPerDay: 5,
	MinInterval: 30 * time.Second, TenantPerDay: 1000,
}

// defaultTenantSendsPerDay is WS_MCP_SEND_TENANT_PER_DAY's default, below
// its ceiling.
const defaultTenantSendsPerDay = 100

// maxSendInterval bounds WS_MCP_SEND_MIN_INTERVAL: an hour between two sends
// is already a switch that is nearly off.
const maxSendInterval = time.Hour

// ContentReader is the reader content connections are held by: the
// production enclave. No other reader, attested or not, is given text.
const ContentReader = "enclave"

// MediaKinds are the kinds of attachment WS_MCP_MEDIA_OFF_KINDS may switch
// off, each a family the reader opens with its own parser: images (with
// stickers and video thumbnails), PDF, office documents, plain text, zip
// archives, audio and video.
var MediaKinds = []string{"image", "pdf", "office", "text", "zip", "audio", "video"}

// MCPReader is one attested reader's block, WS_MCP_READER_<ID>_*.
type MCPReader struct {
	// ID matches ^[a-z][a-z0-9]{0,15}$; its upper case is the environment
	// suffix.
	ID string
	// URL is where this server reaches the reader's internal listener:
	// https://<host>:<port>, on the public origin's host.
	URL string
	// PublicOrigin is where assistants reach the reader.
	PublicOrigin string
	// Secret signs every request in both directions. 43 base64url
	// characters; the HMAC key is the string's bytes as written.
	Secret string
	// SecretNext is accepted alongside Secret during a rotation. Optional.
	SecretNext string
	// Peers are the addresses the reader's calls may come from: the
	// parent instance's Elastic IP.
	Peers []netip.Prefix
	// Tenants are the workspaces that may consent to this reader;
	// AllTenants is the single value "*".
	Tenants    []uuid.UUID
	AllTenants bool

	// tenantErr is a TENANTS value that did not parse, kept for Validate.
	tenantErr error
	// peerErrs are PEER entries that did not parse.
	peerErrs []error
}

// defaultRedirectHosts are the assistants the pilot serves.
const defaultRedirectHosts = "claude.ai,chatgpt.com"

func loadMCP(errs *[]error) MCP {
	m := MCP{
		Enabled:             boolean("WS_MCP_ENABLED", false, errs),
		ReaderURL:           strings.TrimSpace(os.Getenv("WS_MCP_READER_URL")),
		RelaySecret:         os.Getenv("WS_MCP_RELAY_SECRET"),
		PublicOrigin:        strings.TrimSpace(os.Getenv("WS_MCP_PUBLIC_ORIGIN")),
		OpenAIAppsChallenge: strings.TrimSpace(os.Getenv("WS_MCP_OPENAI_APPS_CHALLENGE")),
	}
	for _, host := range strings.Split(str("WS_MCP_REDIRECT_HOSTS", defaultRedirectHosts), ",") {
		if host = strings.ToLower(strings.TrimSpace(host)); host != "" {
			m.RedirectHosts = append(m.RedirectHosts, host)
		}
	}
	m.Readers, m.readersErr = readerIDs(str("WS_MCP_READERS", hostedReader))
	for _, id := range m.Readers {
		if id != hostedReader {
			m.Attested = append(m.Attested, loadReader(id))
		}
	}
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "WS_MCP_READER_HOSTED_") {
			m.strayHosted = append(m.strayHosted, name)
		}
	}
	m.ContentEnabled = boolean("WS_MCP_CONTENT_ENABLED", false, errs)
	m.WorkspaceDefault, m.workspaceDefaultErr = onOrOff("WS_MCP_WORKSPACE_DEFAULT")
	m.DenyTenants, m.denyErr = workspaceList("WS_MCP_DENY_TENANTS", os.Getenv("WS_MCP_DENY_TENANTS"))
	m.retiredLists = map[string]bool{}
	for _, name := range retiredLists {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			m.retiredLists[name] = true
		}
	}
	m.MediaEnabled = boolean("WS_MCP_MEDIA_ENABLED", false, errs)
	m.MediaOffKinds, m.mediaOffErr = mediaKinds(os.Getenv("WS_MCP_MEDIA_OFF_KINDS"))
	m.SendEnabled = boolean("WS_MCP_SEND_ENABLED", false, errs)
	m.SendSelfEnabled = boolean("WS_MCP_SEND_SELF_ENABLED", false, errs)
	m.SendDirectEnabled = boolean("WS_MCP_SEND_DIRECT_ENABLED", false, errs)
	m.SendLimits, m.sendLimitErrs = sendLimits()
	loadAI(&m, errs)
	loadClients(&m)
	return m
}

// sendLimits reads the six WS_MCP_SEND_* limits. A value that does not parse
// or is out of range comes back as its default, with an error that Validate
// reports only while sending is on: a limit nobody uses must not stop a
// server.
func sendLimits() (MCPSendLimits, []error) {
	var errs []error
	count := func(name string, def, ceiling int) int {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			return def
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > ceiling {
			errs = append(errs, fmt.Errorf("%s: %q is not a whole number from 1 to %d, the reader's own limit", name, raw, ceiling))
			return def
		}
		return n
	}
	c := SendCeilings
	out := MCPSendLimits{
		DraftsPerHour: count("WS_MCP_SEND_DRAFTS_PER_HOUR", c.DraftsPerHour, c.DraftsPerHour),
		DraftsPending: count("WS_MCP_SEND_DRAFTS_PENDING", c.DraftsPending, c.DraftsPending),
		PerDay:        count("WS_MCP_SEND_PER_DAY", c.PerDay, c.PerDay),
		PerChatPerDay: count("WS_MCP_SEND_PER_CHAT_PER_DAY", c.PerChatPerDay, c.PerChatPerDay),
		MinInterval:   c.MinInterval,
		TenantPerDay:  count("WS_MCP_SEND_TENANT_PER_DAY", defaultTenantSendsPerDay, c.TenantPerDay),
	}
	if raw := strings.TrimSpace(os.Getenv("WS_MCP_SEND_MIN_INTERVAL")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < c.MinInterval || d > maxSendInterval {
			errs = append(errs, fmt.Errorf("WS_MCP_SEND_MIN_INTERVAL: %q is not a duration from %s to %s (the reader's own interval is %s)",
				raw, c.MinInterval, maxSendInterval, c.MinInterval))
		} else {
			out.MinInterval = d
		}
	}
	return out, errs
}

// retiredLists are the operator's workspace lists that each workspace's own
// switches replaced (docs/mcp-enclave.md §19.30).
var retiredLists = []string{"WS_MCP_CONTENT_TENANTS", "WS_MCP_MEDIA_TENANTS", "WS_MCP_SEND_TENANTS", "WS_AI_TENANTS"}

// retiredList is the refusal of a retired list that is still set.
func retiredList(name string) error {
	return fmt.Errorf("%s is no longer read: each workspace's owner now turns assistants' text, attachments, drafts and AI "+
		"on or off in the console, starting from WS_MCP_WORKSPACE_DEFAULT (on for Wappie Cloud); refuse a workspace with "+
		"WS_MCP_DENY_TENANTS (docs/mcp.md), and remove %s", name, name)
}

// onOrOff parses a setting that reads "on" or "off", in any case; empty is
// off.
func onOrOff(name string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "", "off":
		return false, nil
	case "on":
		return true, nil
	}
	return false, fmt.Errorf("%s: %q is neither on nor off", name, os.Getenv(name))
}

// workspaceList parses a list of workspaces named by name
// (WS_MCP_DENY_TENANTS): workspace UUIDs, comma separated. Every workspace is
// named; "*" is refused, since every workspace at once is what the kill
// switches are for.
func workspaceList(name, raw string) ([]uuid.UUID, error) {
	var out []uuid.UUID
	var errs []error
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		tenant, err := uuid.Parse(part)
		if err != nil || len(part) != 36 || tenant == uuid.Nil {
			errs = append(errs, fmt.Errorf("%s: %q is not a workspace id (a UUID; * is not accepted)", name, part))
			continue
		}
		if !slices.Contains(out, tenant) {
			out = append(out, tenant)
		}
	}
	return out, errors.Join(errs...)
}

// mediaKinds parses WS_MCP_MEDIA_OFF_KINDS: kinds from MediaKinds, comma
// separated, in any case and order. They come back lower-cased, once each
// and sorted, which is the order the reader is told them in. A word that is
// not a kind is an error rather than ignored: a mistyped kind would leave on
// the parser it was meant to switch off.
func mediaKinds(raw string) ([]string, error) {
	var out []string
	var errs []error
	for _, part := range strings.Split(raw, ",") {
		if part = strings.ToLower(strings.TrimSpace(part)); part == "" {
			continue
		}
		if !slices.Contains(MediaKinds, part) {
			errs = append(errs, fmt.Errorf("WS_MCP_MEDIA_OFF_KINDS: %q is not an attachment kind (%s)", part, strings.Join(MediaKinds, ", ")))
			continue
		}
		if !slices.Contains(out, part) {
			out = append(out, part)
		}
	}
	slices.Sort(out)
	return out, errors.Join(errs...)
}

// hostedReader is the reader on this host, configured by the original
// variables. Every other id is an attested reader.
const hostedReader = "hosted"

// readerIDPattern is the shape of a reader id: short, lower case, and safe
// to upper-case into an environment variable name.
var readerIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)

// readerIDs parses WS_MCP_READERS. The ids come back trimmed, in order; an
// id of the wrong shape or a duplicate is an error, and so is an empty list.
func readerIDs(raw string) ([]string, error) {
	var ids []string
	var errs []error
	for _, id := range strings.Split(raw, ",") {
		id = strings.TrimSpace(id)
		switch {
		case id == "":
			continue
		case !readerIDPattern.MatchString(id):
			errs = append(errs, fmt.Errorf("WS_MCP_READERS: %q is not a reader id (^[a-z][a-z0-9]{0,15}$)", id))
			continue
		case slices.Contains(ids, id):
			errs = append(errs, fmt.Errorf("WS_MCP_READERS: %q is listed twice", id))
			continue
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 && len(errs) == 0 {
		errs = append(errs, errors.New("WS_MCP_READERS must name at least one reader"))
	}
	return ids, errors.Join(errs...)
}

// loadReader reads one attested reader's block. Nothing is judged here
// beyond parsing; Validate says what is wrong, once, with the variable's name.
func loadReader(id string) MCPReader {
	prefix := "WS_MCP_READER_" + strings.ToUpper(id) + "_"
	r := MCPReader{
		ID:           id,
		URL:          strings.TrimSpace(os.Getenv(prefix + "URL")),
		PublicOrigin: strings.TrimSpace(os.Getenv(prefix + "PUBLIC_ORIGIN")),
		Secret:       strings.TrimSpace(os.Getenv(prefix + "SECRET")),
		SecretNext:   strings.TrimSpace(os.Getenv(prefix + "SECRET_NEXT")),
	}
	var peerErrs []error
	r.Peers = prefixes(prefix+"PEER", &peerErrs)
	r.peerErrs = peerErrs
	tenants := strings.TrimSpace(os.Getenv(prefix + "TENANTS"))
	if tenants == "*" {
		r.AllTenants = true
		return r
	}
	for _, part := range strings.Split(tenants, ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		tenant, err := uuid.Parse(part)
		if err != nil || len(part) != 36 || tenant == uuid.Nil {
			r.tenantErr = fmt.Errorf("%sTENANTS: %q is not a workspace id (a UUID, or the single value *)", prefix, part)
			continue
		}
		r.Tenants = append(r.Tenants, tenant)
	}
	return r
}

// Hosted reports whether the reader on this host is listed. An empty list
// is the default, which is the hosted reader alone.
func (m MCP) Hosted() bool {
	return len(m.Readers) == 0 || slices.Contains(m.Readers, hostedReader)
}

// Reader returns the attested reader with this id.
func (m MCP) Reader(id string) (MCPReader, bool) {
	i := slices.IndexFunc(m.Attested, func(r MCPReader) bool { return r.ID == id })
	if i < 0 {
		return MCPReader{}, false
	}
	return m.Attested[i], true
}

// Validate checks the block when it is enabled. A disabled connector is not
// inspected: a leftover value must not stop a server that does not use it.
func (m MCP) Validate(prod bool) error {
	if !m.Enabled {
		return nil
	}
	var errs []error
	if m.readersErr != nil {
		errs = append(errs, m.readersErr)
	}
	for _, name := range m.strayHosted {
		errs = append(errs, fmt.Errorf("%s: the hosted reader is configured by WS_MCP_READER_URL, WS_MCP_RELAY_SECRET and WS_MCP_PUBLIC_ORIGIN, not by WS_MCP_READER_HOSTED_*", name))
	}
	if m.Hosted() {
		errs = append(errs, m.validateHosted(prod)...)
	}
	for _, r := range m.Attested {
		errs = append(errs, r.validate()...)
	}
	if len(m.RedirectHosts) == 0 {
		errs = append(errs, errors.New("WS_MCP_REDIRECT_HOSTS must name at least one host when WS_MCP_ENABLED is set"))
	}
	for _, host := range m.RedirectHosts {
		if !validHostname(host) {
			errs = append(errs, fmt.Errorf("WS_MCP_REDIRECT_HOSTS: %q is not a bare host name", host))
		}
	}
	if !validChallenge(m.OpenAIAppsChallenge) {
		errs = append(errs, errors.New("WS_MCP_OPENAI_APPS_CHALLENGE must be up to 256 printable characters without spaces"))
	}
	if m.workspaceDefaultErr != nil {
		errs = append(errs, m.workspaceDefaultErr)
	}
	if m.denyErr != nil {
		errs = append(errs, m.denyErr)
	}
	errs = append(errs, m.validateContent()...)
	errs = append(errs, m.validateMedia()...)
	errs = append(errs, m.validateSend()...)
	errs = append(errs, m.validateAI()...)
	errs = append(errs, m.validateClients(prod)...)
	return errors.Join(errs...)
}

// validateContent checks the content switch. Off, nothing of it is
// inspected. On, it needs the enclave reader, and WS_MCP_CONTENT_TENANTS,
// which the workspaces' own switches replaced, must be gone.
func (m MCP) validateContent() []error {
	if !m.ContentEnabled {
		return nil
	}
	var errs []error
	if m.retiredLists["WS_MCP_CONTENT_TENANTS"] {
		errs = append(errs, retiredList("WS_MCP_CONTENT_TENANTS"))
	}
	if _, ok := m.Reader(ContentReader); !ok {
		errs = append(errs, fmt.Errorf("WS_MCP_CONTENT_ENABLED needs the %q reader in WS_MCP_READERS: content is opened only inside it", ContentReader))
	}
	return errs
}

// ContentAllowed reports whether the operator lets a workspace have content
// connections right now: the connector and the switch are on, the enclave
// reader is configured and admits the workspace, and the workspace is not on
// the deny list. The workspace's own switch, which its owner sets, comes on
// top (mcpauth.WorkspaceSwitches); this is the operator's half alone.
func (m MCP) ContentAllowed(tenant uuid.UUID) bool {
	if !m.Enabled || !m.ContentEnabled || slices.Contains(m.DenyTenants, tenant) {
		return false
	}
	enclave, ok := m.Reader(ContentReader)
	return ok && (enclave.AllTenants || slices.Contains(enclave.Tenants, tenant))
}

// validateMedia checks the attachments switch. It rides on content: while
// either switch is off its kinds are not inspected, so turning content off in
// a hurry never needs them tidied first. On, it needs kinds that exist, and
// WS_MCP_MEDIA_TENANTS gone.
func (m MCP) validateMedia() []error {
	if !m.ContentEnabled || !m.MediaEnabled {
		return nil
	}
	var errs []error
	if m.retiredLists["WS_MCP_MEDIA_TENANTS"] {
		errs = append(errs, retiredList("WS_MCP_MEDIA_TENANTS"))
	}
	if m.mediaOffErr != nil {
		errs = append(errs, m.mediaOffErr)
	}
	return errs
}

// MediaAllowed reports whether the operator lets a workspace's content
// connections that consented to attachments open them right now: content is
// allowed for the workspace and the media switch is on. Which kinds are off
// is MediaOffKinds, and applies to every workspace.
func (m MCP) MediaAllowed(tenant uuid.UUID) bool {
	return m.ContentAllowed(tenant) && m.MediaEnabled
}

// validateSend checks the sending switch. Off, its limits and the own-chat
// and direct switches are not inspected, so turning sending off in a hurry
// never needs them tidied first. On, it needs content on, limits within the
// reader's and WS_MCP_SEND_TENANTS gone; direct send cannot be switched on
// before its server exists.
func (m MCP) validateSend() []error {
	if !m.SendEnabled {
		return nil
	}
	if !m.ContentEnabled {
		return []error{errors.New("WS_MCP_SEND_ENABLED needs WS_MCP_CONTENT_ENABLED: a connection sends only what it may read")}
	}
	var errs []error
	if m.retiredLists["WS_MCP_SEND_TENANTS"] {
		errs = append(errs, retiredList("WS_MCP_SEND_TENANTS"))
	}
	if m.SendDirectEnabled {
		errs = append(errs, errors.New("WS_MCP_SEND_DIRECT_ENABLED: direct send (docs/mcp-enclave.md §17.15) is not in this server yet; leave it false"))
	}
	return append(errs, m.sendLimitErrs...)
}

// SendAllowed reports whether the operator lets a workspace's content
// connections that consented to sending draft and send right now: content is
// allowed for the workspace and the send switch is on.
func (m MCP) SendAllowed(tenant uuid.UUID) bool {
	return m.ContentAllowed(tenant) && m.SendEnabled
}

// SendSelfAllowed is SendAllowed with the own-chat switch on as well.
func (m MCP) SendSelfAllowed(tenant uuid.UUID) bool {
	return m.SendAllowed(tenant) && m.SendSelfEnabled
}

// SendDirectAllowed is SendAllowed with the direct send switch on as well.
func (m MCP) SendDirectAllowed(tenant uuid.UUID) bool {
	return m.SendAllowed(tenant) && m.SendDirectEnabled
}

// validateHosted is today's check of the hosted reader, unchanged: a
// loopback http reader, a bearer secret of at least 32 bytes, and a public
// origin.
func (m MCP) validateHosted(prod bool) []error {
	var errs []error
	if err := validReaderURL(m.ReaderURL); err != nil {
		errs = append(errs, err)
	}
	if len(m.RelaySecret) < 32 {
		errs = append(errs, errors.New("WS_MCP_RELAY_SECRET must be at least 32 bytes when WS_MCP_ENABLED is set"))
	}
	if err := validPublicOrigin(m.PublicOrigin, prod); err != nil {
		errs = append(errs, err)
	}
	return errs
}

// validate checks an attested reader's block. Everything is required but
// SECRET_NEXT, and nothing is relaxed outside prod: the reader is an enclave
// with its own certificate, and a laptop has no business pretending to be one.
func (r MCPReader) validate() []error {
	prefix := "WS_MCP_READER_" + strings.ToUpper(r.ID) + "_"
	var errs []error
	origin, err := attestedOrigin(r.PublicOrigin)
	if err != nil {
		errs = append(errs, fmt.Errorf("%sPUBLIC_ORIGIN %w", prefix, err))
	}
	if err := attestedReaderURL(r.URL, origin); err != nil {
		errs = append(errs, fmt.Errorf("%sURL %w", prefix, err))
	}
	if !validReaderSecret(r.Secret) {
		errs = append(errs, fmt.Errorf("%sSECRET must be exactly 43 base64url characters (32 random bytes)", prefix))
	}
	if r.SecretNext != "" && !validReaderSecret(r.SecretNext) {
		errs = append(errs, fmt.Errorf("%sSECRET_NEXT must be exactly 43 base64url characters (32 random bytes)", prefix))
	}
	if r.SecretNext != "" && r.SecretNext == r.Secret {
		errs = append(errs, fmt.Errorf("%sSECRET_NEXT must differ from %sSECRET", prefix, prefix))
	}
	errs = append(errs, r.peerErrs...)
	if len(r.Peers) == 0 && len(r.peerErrs) == 0 {
		errs = append(errs, fmt.Errorf("%sPEER must list the addresses the reader calls from", prefix))
	}
	switch {
	case r.tenantErr != nil:
		errs = append(errs, r.tenantErr)
	case !r.AllTenants && len(r.Tenants) == 0:
		errs = append(errs, fmt.Errorf("%sTENANTS must list the workspaces that may use this reader, or be *", prefix))
	}
	return errs
}

// attestedOrigin wants an https origin with no path, and returns its host.
func attestedOrigin(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("is required for an attested reader")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || (u.Path != "" && u.Path != "/") || !validHostname(u.Hostname()) {
		return "", errors.New("must be an https origin with no path, such as https://mcp.wappie.thehappie.co")
	}
	return u.Hostname(), nil
}

// attestedReaderURL wants https://<host>:<port> with nothing else, on the
// public origin's host: the certificate the reader serves on its internal
// listener is the one it serves the public, and it names that host only.
func attestedReaderURL(raw, originHost string) error {
	if raw == "" {
		return errors.New("is required for an attested reader")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Port() == "" || u.User != nil || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.Path != "" || !validHostname(u.Hostname()) {
		return errors.New("must be https://<host>:<port> with no path, such as https://mcp.wappie.thehappie.co:8443")
	}
	if port, err := strconv.Atoi(u.Port()); err != nil || port < 1 || port > 65535 {
		return errors.New("must carry a port between 1 and 65535")
	}
	if originHost != "" && u.Hostname() != originHost {
		return fmt.Errorf("must be on the public origin's host, %s", originHost)
	}
	return nil
}

// validReaderSecret is 43 base64url characters that decode to 32 bytes. The
// HMAC key is the string itself; the shape only makes sure it was generated
// rather than typed.
func validReaderSecret(secret string) bool {
	if len(secret) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	return err == nil && len(raw) == 32
}

// validChallenge keeps the token to something a response body can carry
// verbatim: printable ASCII, no whitespace, bounded. Empty is allowed.
func validChallenge(token string) bool {
	if len(token) > 256 {
		return false
	}
	for _, r := range token {
		if r <= ' ' || r > '~' {
			return false
		}
	}
	return true
}

// validReaderURL accepts http://127.0.0.1:18093 and its kin, nothing else.
func validReaderURL(raw string) error {
	invalid := errors.New("WS_MCP_READER_URL must be an http loopback origin such as http://127.0.0.1:18093")
	if raw == "" {
		return errors.New("WS_MCP_READER_URL is required when WS_MCP_ENABLED is set")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return invalid
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Unmap().IsLoopback() {
		return invalid
	}
	return nil
}

// validPublicOrigin wants an https origin; a local http one passes outside
// prod so the whole flow can be exercised on a laptop.
func validPublicOrigin(raw string, prod bool) error {
	if raw == "" {
		return errors.New("WS_MCP_PUBLIC_ORIGIN is required when WS_MCP_ENABLED is set")
	}
	invalid := errors.New("WS_MCP_PUBLIC_ORIGIN must be an https origin with no path (http localhost is allowed outside prod)")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return invalid
	}
	host := strings.ToLower(u.Hostname())
	local := host == "localhost"
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		local = ip.Unmap().IsLoopback()
	}
	secure := u.Scheme == "https" || !prod && local && u.Scheme == "http"
	if !secure {
		return invalid
	}
	return nil
}

// validHostname is a lower-case DNS name: labels of letters, digits and
// hyphens, no scheme, port, path or wildcard. The list is compared byte for
// byte against what a client presents, so anything looser would be a hole.
func validHostname(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/:*@ \t\n") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		if strings.ContainsFunc(label, func(char rune) bool { return !hostChar(char) }) {
			return false
		}
	}
	return true
}

func hostChar(char rune) bool {
	return char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-'
}

// String renders the block for startup logs without the relay secret.
func (m MCP) String() string {
	if !m.Enabled {
		return "mcp=disabled"
	}
	var b strings.Builder
	b.WriteString("mcp=enabled")
	if m.Hosted() {
		fmt.Fprintf(&b, " reader=%s origin=%s relay_secret=%s", m.ReaderURL, m.PublicOrigin, setOrUnset(m.RelaySecret))
	}
	fmt.Fprintf(&b, " redirect_hosts=%s readers=%s", strings.Join(m.RedirectHosts, ","), strings.Join(m.Readers, ","))
	b.WriteString(m.clientsString())
	for _, r := range m.Attested {
		b.WriteString(" ")
		b.WriteString(r.String())
	}
	fmt.Fprintf(&b, " content=%s workspace_default=%s deny_tenants=%d", onOff(m.ContentEnabled), onOff(m.WorkspaceDefault), len(m.DenyTenants))
	fmt.Fprintf(&b, " media=%s", onOff(m.MediaEnabled))
	if len(m.MediaOffKinds) > 0 {
		fmt.Fprintf(&b, " media_off=%s", strings.Join(m.MediaOffKinds, ","))
	}
	fmt.Fprintf(&b, " send=%s send_self=%s send_direct=%s", onOff(m.SendEnabled), onOff(m.SendSelfEnabled), onOff(m.SendDirectEnabled))
	l := m.SendLimits
	fmt.Fprintf(&b, " send_limits=drafts_per_hour:%d,drafts_pending:%d,per_day:%d,per_chat_per_day:%d,min_interval:%s,tenant_per_day:%d",
		l.DraftsPerHour, l.DraftsPending, l.PerDay, l.PerChatPerDay, l.MinInterval, l.TenantPerDay)
	b.WriteString(m.aiString())
	return b.String()
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// String renders an attested reader without either secret.
func (r MCPReader) String() string {
	tenants := strconv.Itoa(len(r.Tenants))
	if r.AllTenants {
		tenants = "*"
	}
	return fmt.Sprintf("reader[%s]=url:%s,origin:%s,secret:%s,secret_next:%s,peers:%d,tenants:%s",
		r.ID, r.URL, r.PublicOrigin, setOrUnset(r.Secret), setOrUnset(r.SecretNext), len(r.Peers), tenants)
}

// GoString keeps %#v from printing the secrets field by field.
func (r MCPReader) GoString() string { return r.String() }

func setOrUnset(secret string) string {
	if secret == "" {
		return "unset"
	}
	return "set"
}
