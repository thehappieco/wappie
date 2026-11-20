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
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
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
	// The reader's clock, from reader 0.6.1 (docs/mcp-enclave.md §5.1).
	// Each is nil from an older reader, when the reader sends null (it does
	// not know), and when the value is not one Go reads: a field here never
	// costs the health line, which carries the fingerprints the release
	// gate reads.
	//
	// ClockOK is whether the reader vouches for its clock; when it does
	// not, its state is "clock_unknown". ClockUncMS is its uncertainty,
	// NSMSkewMS its clock minus the NSM's, and GoSkewMS its clock minus the
	// timestamps on Go's verified requests, the median over a window, with
	// the timestamps' 1 s resolution.
	ClockOK    *bool  `json:"clock_ok"`
	ClockUncMS *int64 `json:"clock_unc_ms"`
	NSMSkewMS  *int64 `json:"nsm_skew_ms"`
	GoSkewMS   *int64 `json:"go_skew_ms"`
	// What the clock alerts read (clock_alerts.go), from a 0.6.1 reader
	// that sends them; nil the same way as the four above.
	//
	// ClockCode is the reason the reader gives for its clock, one of
	// ReaderClockCodes and nil for any other word: a word Go does not know
	// is never kept. ClockDisagreeKMS is how many times since its Node
	// process started the reader found KMS's Date range contradicting its
	// clock helper. KMSSkewLoMS and KMSSkewHiMS are the range KMS allows
	// for the reader's clock minus true time, and ClockCorrHourMS and
	// ClockCorrDayMS how far the helper corrected the clock in the last hour
	// and day.
	ClockCode        *string `json:"clock_code"`
	ClockDisagreeKMS *int64  `json:"clock_disagree_kms"`
	KMSSkewLoMS      *int64  `json:"kms_skew_lo_ms"`
	KMSSkewHiMS      *int64  `json:"kms_skew_hi_ms"`
	ClockCorrHourMS  *int64  `json:"clock_corr_hour_ms"`
	ClockCorrDayMS   *int64  `json:"clock_corr_day_ms"`
}

// ReaderClockCodes are the reasons a 0.6.1 reader gives for its clock
// (enclave/clock.mjs), "ok" when it vouches for it.
var ReaderClockCodes = []string{
	"ok", "helper_stale", "nsm_stale", "boot_refused", "cap_exceeded",
	"chronyd_gone", "nsm_error", "unc_high", "kms_proof", "nsm_node_proof",
	"starting",
}

// readerHealthWire is the health object as it arrives: the clock fields are
// read apart, so a shape Go does not expect leaves the field out instead of
// failing the whole answer. The outer fields shadow the embedded ones.
type readerHealthWire struct {
	ReaderHealth
	ClockOK          json.RawMessage `json:"clock_ok"`
	ClockUncMS       json.RawMessage `json:"clock_unc_ms"`
	NSMSkewMS        json.RawMessage `json:"nsm_skew_ms"`
	GoSkewMS         json.RawMessage `json:"go_skew_ms"`
	ClockCode        json.RawMessage `json:"clock_code"`
	ClockDisagreeKMS json.RawMessage `json:"clock_disagree_kms"`
	KMSSkewLoMS      json.RawMessage `json:"kms_skew_lo_ms"`
	KMSSkewHiMS      json.RawMessage `json:"kms_skew_hi_ms"`
	ClockCorrHourMS  json.RawMessage `json:"clock_corr_hour_ms"`
	ClockCorrDayMS   json.RawMessage `json:"clock_corr_day_ms"`
}

// maxClockMS bounds a clock field: a day either way is past anything a
// reader can mean, and keeps the conversion to int64 exact.
const maxClockMS = 24 * 60 * 60 * 1000

// absent is a field left out or sent as null. Unmarshal reads a null into
// a bool or a number as nothing at all, so it is told apart first.
func absent(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null"
}

// healthBool is a JSON boolean, or nil for anything else.
func healthBool(raw json.RawMessage) *bool {
	var v bool
	if absent(raw) || json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return &v
}

// healthMS is a JSON number of milliseconds within maxClockMS, rounded to
// the nearest whole one, or nil for anything else.
func healthMS(raw json.RawMessage) *int64 {
	var v float64
	if absent(raw) || json.Unmarshal(raw, &v) != nil || math.Abs(v) > maxClockMS {
		return nil
	}
	ms := int64(math.Round(v))
	return &ms
}

// healthClockCode is a JSON string that is one of ReaderClockCodes, or nil
// for anything else.
func healthClockCode(raw json.RawMessage) *string {
	var v string
	if absent(raw) || json.Unmarshal(raw, &v) != nil || !codePattern.MatchString(v) || !slices.Contains(ReaderClockCodes, v) {
		return nil
	}
	return &v
}

// healthCount is a JSON whole number from 0 to maxClockMS, or nil for
// anything else.
func healthCount(raw json.RawMessage) *int64 {
	var v float64
	if absent(raw) || json.Unmarshal(raw, &v) != nil || v < 0 || v > maxClockMS || v != math.Trunc(v) {
		return nil
	}
	n := int64(v)
	return &n
}

// ReaderCodeClockUnknown is a 0.6.1 reader that cannot vouch for its clock
// and, by that clock, found Go's signature outside its window: it answers
// 503 with this code instead of a 401. A reader that cannot vouch for its
// clock but accepts the signature answers 200 with state "clock_unknown".
const ReaderCodeClockUnknown = "clock_unknown"

// HealthStatusError is the reader answering its health check with a status
// other than 200 or 401. It is ErrReaderUnavailable.
type HealthStatusError struct {
	// Status is the reader's answer.
	Status int
	// Code is the {"code":...} of the body when it has the shape of one
	// (ReaderCodeClockUnknown, say), else empty.
	Code string
	// Health is the health object a reader sends with its 503
	// clock_unknown, from 0.6.1 with its clock in it; nil with any other
	// answer, with a bare code, and with a body that is not this reader's
	// health object.
	Health *ReaderHealth
}

func (e *HealthStatusError) Error() string {
	msg := ErrReaderUnavailable.Error() + ": healthz answered " + strconv.Itoa(e.Status)
	if e.Code != "" {
		msg += " " + e.Code
	}
	return msg
}

// Unwrap makes the answer ErrReaderUnavailable.
func (e *HealthStatusError) Unwrap() error { return ErrReaderUnavailable }

// healthCode is the body's code when it has the shape of one, else empty:
// the body is the reader's, and only a code goes into the log.
func healthCode(body []byte) string {
	var e struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &e) != nil || !codePattern.MatchString(e.Code) {
		return ""
	}
	return e.Code
}

// errHealthzUnauthorized is the reader refusing this server's signature on
// its health check. Its 401 says nothing about why; the monitor names the
// likely cause (skew.go).
var errHealthzUnauthorized = errors.New("healthz answered 401")

// Health asks the reader how it is.
func (c *SignedRelay) Health(ctx context.Context) (ReaderHealth, error) {
	status, body, err := c.do(ctx, http.MethodGet, "/internal/healthz", nil)
	if err != nil {
		return ReaderHealth{}, err
	}
	if status == http.StatusUnauthorized {
		return ReaderHealth{}, fmt.Errorf("%w: %w", ErrReaderUnavailable, errHealthzUnauthorized)
	}
	if status != http.StatusOK {
		e := &HealthStatusError{Status: status, Code: healthCode(body)}
		if status == http.StatusServiceUnavailable && e.Code == ReaderCodeClockUnknown {
			// From 0.6.1 the stale 503 carries the health object, so the
			// clock's reason survives a clock too far from Go's.
			if health, err := parseHealth(body, c.ReaderID); err == nil {
				e.Health = &health
			}
		}
		return ReaderHealth{}, e
	}
	return parseHealth(body, c.ReaderID)
}

// parseHealth reads a health object, which must be ok and readerID's.
func parseHealth(body []byte, readerID string) (ReaderHealth, error) {
	var wire readerHealthWire
	if err := json.Unmarshal(body, &wire); err != nil {
		return ReaderHealth{}, fmt.Errorf("%w: healthz is not the health object", ErrReaderUnavailable)
	}
	health := wire.ReaderHealth
	health.ClockOK = healthBool(wire.ClockOK)
	health.ClockUncMS = healthMS(wire.ClockUncMS)
	health.NSMSkewMS = healthMS(wire.NSMSkewMS)
	health.GoSkewMS = healthMS(wire.GoSkewMS)
	health.ClockCode = healthClockCode(wire.ClockCode)
	health.ClockDisagreeKMS = healthCount(wire.ClockDisagreeKMS)
	health.KMSSkewLoMS = healthMS(wire.KMSSkewLoMS)
	health.KMSSkewHiMS = healthMS(wire.KMSSkewHiMS)
	health.ClockCorrHourMS = healthMS(wire.ClockCorrHourMS)
	health.ClockCorrDayMS = healthMS(wire.ClockCorrDayMS)
	if !health.OK || health.ReaderID != readerID {
		// A reader answering under another id is a routing mistake, and
		// the one thing worse than no answer is the wrong reader's.
		return ReaderHealth{}, fmt.Errorf("%w: healthz is not ok for reader %s", ErrReaderUnavailable, readerID)
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
	return c.doWith(ctx, c.Client, method, path, body)
}

// doWith is do with another client, for the calls that wait longer.
func (c *SignedRelay) doWith(ctx context.Context, client *http.Client, method, path string, body any) (int, []byte, error) {
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
