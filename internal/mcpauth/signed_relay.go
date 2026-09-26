package mcpauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SignedRelay is the client side of the link to an attested reader: the same
// calls as Relay, plus prepare, health and the relay-secret rotation, over
// HTTPS to the reader's internal listener with every request signed.
//
// The reader terminates TLS inside the enclave with a certificate for its
// public host, so the connection is checked against the system roots with
// that name, as any browser would. No proxy, no redirects: the address is
// configuration, and anything else answering is not the reader.
type SignedRelay struct {
	// ReaderID is the reader's id, signed into every request.
	ReaderID string
	// BaseURL is the reader's internal origin, https://<host>:8443.
	BaseURL string
	// Secret signs every request. Never logged.
	Secret string
	// Client carries the requests; NewSignedRelay builds the right one.
	Client *http.Client
	// Now is the clock the timestamps are taken from; nil is time.Now.
	Now func() time.Time
}

// signedRelayTimeout covers a whole exchange with the reader, TLS included.
// It is on another machine, and a prepare asks the NSM for a document.
const signedRelayTimeout = 10 * time.Second

// ErrTooManyPrepares is the reader refusing another attestation for a request
// that has had its share.
var ErrTooManyPrepares = errors.New("mcpauth: too many prepares for that request")

// NewSignedRelay builds the client for one attested reader. Roots nil means
// the system roots; tests hand in their own.
func NewSignedRelay(readerID, baseURL, secret string, roots *x509.CertPool) *SignedRelay {
	serverName := ""
	if u, err := url.Parse(baseURL); err == nil {
		serverName = u.Hostname()
	}
	return &SignedRelay{
		ReaderID: readerID, BaseURL: strings.TrimRight(baseURL, "/"), Secret: secret,
		Client: signedClient(serverName, roots),
	}
}

// signedClient is an HTTPS client that trusts WebPKI for serverName and
// nothing else about the path there.
func signedClient(serverName string, roots *x509.CertPool) *http.Client {
	dialer := &net.Dialer{Timeout: signedRelayTimeout, KeepAlive: 30 * time.Second}
	return &http.Client{
		Timeout: signedRelayTimeout,
		Transport: &http.Transport{
			// No proxy from the environment: HTTPS_PROXY on this host must
			// not become a hop between this server and the enclave.
			Proxy:       nil,
			DialContext: dialer.DialContext,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: serverName,
				RootCAs:    roots,
			},
			TLSHandshakeTimeout: signedRelayTimeout,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
		// A redirect would be a request to an address nobody configured.
		// The 3xx comes back as the answer and counts as unavailable.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Descriptor fetches what the reader knows about a pending request.
func (c *SignedRelay) Descriptor(ctx context.Context, requestID string) (json.RawMessage, error) {
	status, body, err := c.do(ctx, http.MethodGet, "/internal/requests/"+url.PathEscape(requestID), nil)
	if err != nil {
		return nil, err
	}
	return descriptorAnswer(status, body)
}

// prepareRequest is the body of a prepare: the browser's nonce, as it sent it.
type prepareRequest struct {
	Nonce string `json:"nonce"`
}

// Prepare asks the reader for the request's descriptor with a fresh
// attestation document over the browser's nonce. The bytes come back as the
// reader sent them; the browser verifies them, this server only checks
// their shape.
func (c *SignedRelay) Prepare(ctx context.Context, requestID, nonce string) (json.RawMessage, error) {
	status, body, err := c.do(ctx, http.MethodPost, "/internal/requests/"+url.PathEscape(requestID)+"/prepare", prepareRequest{Nonce: nonce})
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusTooManyRequests:
		return nil, ErrTooManyPrepares
	case http.StatusBadRequest:
		return nil, fmt.Errorf("%w: %s", ErrReaderRefused, readerCode(body))
	case http.StatusServiceUnavailable:
		// policy_unknown, tls_not_ready, attest_failed or starting: the
		// reader cannot attest right now, and says which.
		return nil, fmt.Errorf("%w: prepare answered 503 %s", ErrReaderUnavailable, readerCode(body))
	}
	return descriptorAnswer(status, body)
}

// Bundle hands the reader a sealed bundle for a pending request.
func (c *SignedRelay) Bundle(ctx context.Context, requestID string, in BundleRelay) error {
	status, body, err := c.do(ctx, http.MethodPost, "/internal/requests/"+url.PathEscape(requestID)+"/bundle", in)
	if err != nil {
		return err
	}
	return bundleAnswer(status, body)
}

// Revoke tells the reader a connection is over. Best effort, as for Relay.
func (c *SignedRelay) Revoke(ctx context.Context, connectionID string) error {
	status, _, err := c.do(ctx, http.MethodPost, "/internal/connections/"+url.PathEscape(connectionID)+"/revoke", nil)
	if err != nil {
		return err
	}
	return revokeAnswer(status)
}

// Renewal asks the reader for a new per-connection key for a content
// connection, attested over the browser's nonce like a prepare. The bytes
// come back as the reader sent them.
func (c *SignedRelay) Renewal(ctx context.Context, connectionID, nonce string) (json.RawMessage, error) {
	status, body, err := c.do(ctx, http.MethodPost, "/internal/connections/"+url.PathEscape(connectionID)+"/renewal", prepareRequest{Nonce: nonce})
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusTooManyRequests:
		return nil, ErrTooManyPrepares
	case http.StatusBadRequest:
		return nil, &RefusalError{Code: readerCode(body)}
	case http.StatusServiceUnavailable:
		return nil, fmt.Errorf("%w: renewal answered 503 %s", ErrReaderUnavailable, readerCode(body))
	}
	return descriptorAnswer(status, body)
}

// RenewalBundle hands the reader the sealed bundle of a renewal. The reader
// checks it and stages the new key; it commits it when it next hears the
// connection names the new service account.
func (c *SignedRelay) RenewalBundle(ctx context.Context, connectionID, renewalID string, in BundleRelay) error {
	status, body, err := c.do(ctx, http.MethodPost,
		"/internal/connections/"+url.PathEscape(connectionID)+"/renewal/"+url.PathEscape(renewalID)+"/bundle", in)
	if err != nil {
		return err
	}
	return bundleAnswer(status, body)
}

// ReaderHealth is the reader's own account of itself. Every fingerprint in
// it is public: the PCR0 is in the release, the SPKI is in the certificate
// transparency logs, and the policy hash is published with the release.
type ReaderHealth struct {
	OK             bool       `json:"ok"`
	ReaderID       string     `json:"reader_id"`
	ReaderVersion  string     `json:"reader_version"`
	BootID         string     `json:"boot_id"`
	State          string     `json:"state"`
	PCR0           string     `json:"pcr0"`
	TLSSPKISHA256  *string    `json:"tls_spki_sha256"`
	CertNotAfter   *time.Time `json:"cert_not_after"`
	PolicySHA256   *string    `json:"policy_sha256"`
	ACMEAccountURI *string    `json:"acme_account_uri"`
	RelaySecrets   int        `json:"relay_secrets"`
}

// Health asks the reader how it is.
func (c *SignedRelay) Health(ctx context.Context) (ReaderHealth, error) {
	status, body, err := c.do(ctx, http.MethodGet, "/internal/healthz", nil)
	if err != nil {
		return ReaderHealth{}, err
	}
	if status != http.StatusOK {
		return ReaderHealth{}, fmt.Errorf("%w: healthz answered %d", ErrReaderUnavailable, status)
	}
	var health ReaderHealth
	if err := json.Unmarshal(body, &health); err != nil {
		return ReaderHealth{}, fmt.Errorf("%w: healthz is not the health object", ErrReaderUnavailable)
	}
	if !health.OK || health.ReaderID != c.ReaderID {
		// A reader answering under another id is a routing mistake, and
		// the one thing worse than no answer is the wrong reader's.
		return ReaderHealth{}, fmt.Errorf("%w: healthz is not ok for reader %s", ErrReaderUnavailable, c.ReaderID)
	}
	return health, nil
}

// relaySecretRequest carries a new relay secret, encrypted to the reader's
// boot key; only the attested image can open it.
type relaySecretRequest struct {
	Ciphertext string `json:"ciphertext"`
}

// RelaySecret hands the reader the next relay secret, as KMS ciphertext in
// standard base64. The request is signed with the current secret.
func (c *SignedRelay) RelaySecret(ctx context.Context, ciphertext string) error {
	status, body, err := c.do(ctx, http.MethodPost, "/internal/relay-secret", relaySecretRequest{Ciphertext: ciphertext})
	if err != nil {
		return err
	}
	switch status {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusBadRequest:
		return fmt.Errorf("%w: %s", ErrReaderRefused, readerCode(body))
	default:
		return fmt.Errorf("%w: relay-secret answered %d %s", ErrReaderUnavailable, status, readerCode(body))
	}
}

// do signs and sends one request and returns the status and the bounded
// body. Nothing here logs; the signature and the body never leave it.
func (c *SignedRelay) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return 0, nil, fmt.Errorf("%w: %w", ErrReaderUnavailable, err)
		}
	}
	var payload io.Reader
	if raw != nil {
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, payload)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", ErrReaderUnavailable, err)
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	if err := sign(req, c.Secret, c.ReaderID, raw, now()); err != nil {
		return 0, nil, fmt.Errorf("%w: %w", ErrReaderUnavailable, err)
	}
	req.Header.Set("Accept", "application/json")
	if raw != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := c.Client
	if client == nil {
		client = signedClient("", nil)
	}
	resp, err := client.Do(req)
	if err != nil {
		// The error carries the URL, which is the reader's public host;
		// the signature is a header and is not part of it.
		return 0, nil, fmt.Errorf("%w: %w", ErrReaderUnavailable, err)
	}
	defer func() {
		//nolint:errcheck // the body is drained; a close error changes nothing
		_ = resp.Body.Close()
	}()
	return readAnswer(resp)
}
