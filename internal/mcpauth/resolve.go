package mcpauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// AttestedReader is one reader that runs off this host, in a Nitro Enclave,
// as the handler serves it: where to reach it, what it signs with, where its
// calls come from and which workspaces may use it.
type AttestedReader struct {
	// ID is the reader's id, as configured and as it signs.
	ID string
	// PublicOrigin is where assistants reach it; its MCP resource is
	// PublicOrigin/mcp and the console completes consents there.
	PublicOrigin string
	// Relay carries this server's requests to the reader.
	Relay *SignedRelay
	// Secrets are what the reader's requests may be signed with: the
	// current secret, and the next one during a rotation.
	Secrets []string
	// Peers are the addresses its calls may come from.
	Peers []netip.Prefix
	// Tenants may consent to this reader; AllTenants lets every workspace.
	Tenants    []uuid.UUID
	AllTenants bool
}

// allows reports whether a workspace may consent to this reader.
func (a *AttestedReader) allows(tenant uuid.UUID) bool {
	return a.AllTenants || slices.Contains(a.Tenants, tenant)
}

// peer reports whether a caller's address is one of the reader's.
func (a *AttestedReader) peer(addr string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return slices.ContainsFunc(a.Peers, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// readerRelay is what every reader answers, hosted or attested.
type readerRelay interface {
	Descriptor(ctx context.Context, requestID string) (json.RawMessage, error)
	Bundle(ctx context.Context, requestID string, in BundleRelay) error
	Revoke(ctx context.Context, connectionID string) error
}

// reader is one configured reader as the handler routes to it.
type reader struct {
	id     string
	origin string
	relay  readerRelay
	// attested is nil for the hosted reader.
	attested *AttestedReader
}

// resource is the canonical MCP resource the reader must advertise: its
// public origin plus the MCP path, byte for byte.
func (rd reader) resource() string {
	return strings.TrimRight(rd.origin, "/") + resourcePath
}

// completeURL is where the console posts its proof for this reader.
func (rd reader) completeURL() string {
	return strings.TrimRight(rd.origin, "/") + completePath
}

// configuredReaders lists the hosted reader, when there is one, and then the
// attested readers in their configured order.
func (h *Handler) configuredReaders() []reader {
	var out []reader
	if h.Reader != nil {
		out = append(out, reader{id: store.HostedReader, origin: h.PublicOrigin, relay: h.Reader})
	}
	for _, a := range h.Attested {
		out = append(out, reader{id: a.ID, origin: a.PublicOrigin, relay: a.Relay, attested: a})
	}
	return out
}

func (h *Handler) readerByID(id string) (reader, bool) {
	i := slices.IndexFunc(h.readers, func(rd reader) bool { return rd.id == id })
	if i < 0 {
		return reader{}, false
	}
	return h.readers[i], true
}

func (h *Handler) attestedByID(id string) *AttestedReader {
	i := slices.IndexFunc(h.Attested, func(a *AttestedReader) bool { return a.ID == id })
	if i < 0 {
		return nil
	}
	return h.Attested[i]
}

// ---------------------------------------------------------------------------
// Which reader holds a request
// ---------------------------------------------------------------------------

const (
	// requestTTL outlives the readers' twenty-minute pending lifetime, so an
	// entry never forgets a request its reader still holds.
	requestTTL = 30 * time.Minute
	// requestCap bounds the map. Only ids a reader answered 200 for are
	// entered, so filling it takes that many real pending requests.
	requestCap = 10_000
)

// requestEntry is what this server knows about a pending request: whose it
// is and, once the console prepared it, what the reader attested.
type requestEntry struct {
	reader         string
	kid            string
	pcr0           string
	documentSHA256 string
	prepared       bool
	expires        time.Time
	// publicKey is the full per-request key the reader attested (32
	// bytes), which a content consent's service account must carry.
	publicKey []byte
	// connection is set for a renewal: the connection the renewal id was
	// issued for. A consent's entry has none, and neither kind of entry
	// answers for the other.
	connection string
}

// measurement is the ledger's record of what the reader declared, for
// operations; the browser is what verified it.
func (e requestEntry) measurement() string {
	return "nitro:pcr0=" + e.pcr0 + ";doc=" + e.documentSHA256
}

type requestCache struct {
	mu      sync.Mutex
	entries map[string]requestEntry
}

func newRequestCache() *requestCache { return &requestCache{entries: map[string]requestEntry{}} }

func (c *requestCache) get(id string, now time.Time) (requestEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok || !e.expires.After(now) {
		return requestEntry{}, false
	}
	return e, true
}

// put records an entry. When the map is full the expired entries go first
// and then the one closest to expiry: forgetting an entry costs a lookup, or
// at worst a second prepare, never a wrong answer.
func (c *requestCache) put(id string, e requestEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.expires = now.Add(requestTTL)
	if _, ok := c.entries[id]; !ok && len(c.entries) >= requestCap {
		oldest, first := "", time.Time{}
		for k, v := range c.entries {
			if !v.expires.After(now) {
				delete(c.entries, k)
				continue
			}
			if oldest == "" || v.expires.Before(first) {
				oldest, first = k, v.expires
			}
		}
		if len(c.entries) >= requestCap {
			delete(c.entries, oldest)
		}
	}
	c.entries[id] = e
}

// resolve finds the reader that holds a request. A remembered answer is used
// as it is and no reader is called; the descriptor comes back nil. Otherwise
// every reader is asked at once, the first to know the request wins and is
// remembered, and its descriptor comes back.
func (h *Handler) resolve(ctx context.Context, id string) (reader, json.RawMessage, error) {
	if e, ok := h.requests.get(id, time.Now()); ok {
		if rd, known := h.readerByID(e.reader); known {
			return rd, nil, nil
		}
	}
	return h.askReaders(ctx, id)
}

// readDescriptor resolves a request and returns its reader's current
// descriptor, fetching it when resolve did not.
func (h *Handler) readDescriptor(ctx context.Context, id string) (reader, json.RawMessage, error) {
	rd, raw, err := h.resolve(ctx, id)
	if err != nil || raw != nil {
		return rd, raw, err
	}
	raw, err = rd.relay.Descriptor(ctx, id)
	return rd, raw, err
}

// askReaders sends the descriptor request to every reader concurrently. The
// first 200 wins and the others are cancelled. Every reader not knowing the
// request is ErrReaderNotFound; no 200 and any other failure is
// unavailable, because the request may be with the reader that failed.
func (h *Handler) askReaders(ctx context.Context, id string) (reader, json.RawMessage, error) {
	if len(h.readers) == 0 {
		return reader{}, nil, fmt.Errorf("%w: no reader is configured", ErrReaderUnavailable)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type answer struct {
		rd  reader
		raw json.RawMessage
		err error
	}
	// Buffered, so the losers can answer after the winner has returned.
	answers := make(chan answer, len(h.readers))
	for _, rd := range h.readers {
		go func() {
			raw, err := rd.relay.Descriptor(ctx, id)
			answers <- answer{rd: rd, raw: raw, err: err}
		}()
	}
	var failure error
	for range h.readers {
		a := <-answers
		switch {
		case a.err == nil:
			var d descriptor
			//nolint:errcheck // a descriptor without a kid is remembered without one; create checks it anyway
			_ = json.Unmarshal(a.raw, &d)
			h.requests.put(id, requestEntry{reader: a.rd.id, kid: d.KID}, time.Now())
			return a.rd, a.raw, nil
		case errors.Is(a.err, ErrReaderNotFound):
		default:
			failure = a.err
		}
	}
	if failure != nil {
		return reader{}, nil, failure
	}
	return reader{}, nil, ErrReaderNotFound
}

// ---------------------------------------------------------------------------
// Prepare
// ---------------------------------------------------------------------------

const (
	minPrepareNonce = 16
	maxPrepareNonce = 64
	// maxAttestationDocument bounds the COSE_Sign1 document, decoded. A
	// Nitro document with its certificate chain is about five kilobytes.
	maxAttestationDocument = 16 << 10
	pcr0Len                = 96
)

// preparedDescriptor is the part of a prepared descriptor this server reads.
type preparedDescriptor struct {
	RequestID       string `json:"request_id"`
	KID             string `json:"kid"`
	ReaderPublicKey string `json:"reader_public_key"`
	Resource        string `json:"resource"`
	Attestation     *struct {
		Document  string `json:"document"`
		PCR0      string `json:"pcr0"`
		RequestID string `json:"request_id"`
	} `json:"attestation"`
}

// readerPublicKeyLen is an X25519 public key.
const readerPublicKeyLen = 32

// validPrepareNonce is 16 to 64 bytes in unpadded base64url.
func validPrepareNonce(nonce string) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	return err == nil && len(raw) >= minPrepareNonce && len(raw) <= maxPrepareNonce
}

// checkPrepared reads what the reader attested and checks its shape: this
// request, this reader's resource, a document of bounded size and a PCR0 of
// the right length. It does not verify the document; the browser does.
func checkPrepared(raw json.RawMessage, id string, rd reader) (requestEntry, error) {
	var p preparedDescriptor
	if err := json.Unmarshal(raw, &p); err != nil {
		return requestEntry{}, errors.New("the prepared descriptor is not the expected object")
	}
	if p.RequestID != id || p.Resource != rd.resource() {
		return requestEntry{}, errors.New("the prepared descriptor is for another request or resource")
	}
	return p.entry(rd, false)
}

// entry checks the fields a prepared descriptor and a renewal share and
// turns them into what this server remembers. The public key is kept when
// present and must then be well formed; needKey makes it required, as it is
// for a renewal. A consent's entry without one cannot bind a content
// connection (create refuses it).
func (p preparedDescriptor) entry(rd reader, needKey bool) (requestEntry, error) {
	if len(p.KID) != kidLen || !isHex(p.KID) {
		return requestEntry{}, errors.New("the prepared descriptor's kid is malformed")
	}
	var publicKey []byte
	if p.ReaderPublicKey != "" || needKey {
		var err error
		publicKey, err = base64.RawURLEncoding.Strict().DecodeString(p.ReaderPublicKey)
		if err != nil || len(publicKey) != readerPublicKeyLen {
			return requestEntry{}, errors.New("the prepared descriptor's reader_public_key is malformed")
		}
	}
	if p.Attestation == nil {
		return requestEntry{}, errors.New("the prepared descriptor carries no attestation")
	}
	document, err := base64.RawURLEncoding.Strict().DecodeString(p.Attestation.Document)
	if err != nil || len(document) == 0 || len(document) > maxAttestationDocument {
		return requestEntry{}, errors.New("the attestation document is missing, malformed or too large")
	}
	if len(p.Attestation.PCR0) != pcr0Len || !isHex(p.Attestation.PCR0) {
		return requestEntry{}, errors.New("the declared pcr0 is malformed")
	}
	sum := sha256.Sum256(document)
	return requestEntry{
		reader: rd.id, kid: p.KID, pcr0: p.Attestation.PCR0,
		documentSHA256: hex.EncodeToString(sum[:]), prepared: true, publicKey: publicKey,
	}, nil
}

// renewalDescriptor is the part of a renewal answer this server reads.
type renewalDescriptor struct {
	preparedDescriptor
	RenewalID    string `json:"renewal_id"`
	ConnectionID string `json:"connection_id"`
}

// checkRenewal reads what the reader attested for a renewal and checks its
// shape as checkPrepared does: a renewal id of a request id's shape, this
// connection, this reader's resource, and an attestation over the renewal
// id. The renewal id comes back with the entry to remember under it.
func checkRenewal(raw json.RawMessage, connectionID string, rd reader) (string, requestEntry, error) {
	var p renewalDescriptor
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", requestEntry{}, errors.New("the renewal is not the expected object")
	}
	if !validRequestID(p.RenewalID) || p.ConnectionID != connectionID || p.Resource != rd.resource() {
		return "", requestEntry{}, errors.New("the renewal is for another connection or resource, or its id is malformed")
	}
	if p.Attestation != nil && p.Attestation.RequestID != p.RenewalID {
		return "", requestEntry{}, errors.New("the renewal's attestation is for another request")
	}
	e, err := p.entry(rd, true)
	if err != nil {
		return "", requestEntry{}, err
	}
	e.connection = connectionID
	return p.RenewalID, e, nil
}
