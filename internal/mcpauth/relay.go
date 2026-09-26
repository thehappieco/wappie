package mcpauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Relay is the client side of the loopback link to the reader process.
//
// Three calls, all small: fetch a pending request's descriptor, hand it the
// sealed bundle a person consented to, and tell it a connection is over. The
// bundle is opaque here — sealed to the reader's key in the browser — and the
// relay never logs a body in either direction.
type Relay struct {
	// BaseURL is the reader's loopback origin, http://127.0.0.1:18093.
	BaseURL string
	// Secret is the shared relay secret, sent as a bearer token.
	Secret string
	// Client is the HTTP client; nil uses one with a five second timeout.
	// The reader is on the same host, so anything slower is a reader that
	// is not going to answer.
	Client *http.Client
}

// NewRelay builds a relay client with the default timeout.
func NewRelay(baseURL, secret string) *Relay {
	return &Relay{BaseURL: strings.TrimRight(baseURL, "/"), Secret: secret, Client: &http.Client{Timeout: relayTimeout}}
}

const relayTimeout = 5 * time.Second

// maxRelayBody bounds what is read back from the reader. A descriptor is a
// few hundred bytes; the cap is generous so a future field fits and small
// enough that a misbehaving reader cannot make this server buffer much.
const maxRelayBody = 64 << 10

var (
	// ErrReaderNotFound is the reader saying the request or connection is
	// unknown, expired or already consumed.
	ErrReaderNotFound = errors.New("mcpauth: the reader does not know that request")
	// ErrReaderRefused is the reader rejecting what it was handed: a bundle
	// sealed to the wrong key, a malformed one, or a request already
	// answered. The reader's own code is carried alongside.
	ErrReaderRefused = errors.New("mcpauth: the reader refused the relay")
	// ErrReaderUnavailable covers everything else: connection refused, a
	// timeout, a body that is not what was expected. The console tells the
	// person to try again; nothing consented survives it.
	ErrReaderUnavailable = errors.New("mcpauth: the reader is unavailable")
)

// BundleRelay is what the reader receives after a consent: the connection it
// belongs to, the workspace it is for, the key the bundle was sealed to, the
// bundle itself and the lifetime the person chose. The reader checks that the
// workspace inside the bundle is the one named here.
type BundleRelay struct {
	ConnectionID string    `json:"connection_id"`
	TenantID     string    `json:"tenant_id"`
	KID          string    `json:"kid"`
	Sealed       string    `json:"sealed"`
	ExpiresAt    time.Time `json:"expires_at"`
	// Kind is "content" for a content consent or renewal, sent to attested
	// readers only; empty (and absent on the wire) for metadata, so the
	// hosted reader's strict body never sees it.
	Kind string `json:"kind,omitempty"`
}

// RefusalError is a reader refusing what it was handed, with its code. It
// is ErrReaderRefused to errors.Is.
type RefusalError struct {
	// Code is the reader's error code, "unspecified" when it gave none.
	Code string
}

func (e *RefusalError) Error() string { return ErrReaderRefused.Error() + ": " + e.Code }

// Unwrap makes a refusal ErrReaderRefused.
func (e *RefusalError) Unwrap() error { return ErrReaderRefused }

// Descriptor fetches what the reader knows about a pending request. The
// bytes come back as the reader sent them, so the console reads the reader's
// answer rather than this server's summary of it.
func (c *Relay) Descriptor(ctx context.Context, requestID string) (json.RawMessage, error) {
	status, body, err := c.do(ctx, http.MethodGet, "/internal/requests/"+url.PathEscape(requestID), nil)
	if err != nil {
		return nil, err
	}
	return descriptorAnswer(status, body)
}

// descriptorAnswer maps a reader's answer to a descriptor fetch, the same
// for every reader.
func descriptorAnswer(status int, body []byte) (json.RawMessage, error) {
	switch status {
	case http.StatusOK:
		if !json.Valid(body) || len(body) == 0 || body[0] != '{' {
			return nil, fmt.Errorf("%w: the descriptor is not a JSON object", ErrReaderUnavailable)
		}
		return body, nil
	case http.StatusNotFound:
		return nil, ErrReaderNotFound
	default:
		return nil, fmt.Errorf("%w: descriptor answered %d", ErrReaderUnavailable, status)
	}
}

// Bundle hands the reader a sealed bundle for a pending request.
func (c *Relay) Bundle(ctx context.Context, requestID string, in BundleRelay) error {
	status, body, err := c.do(ctx, http.MethodPost, "/internal/requests/"+url.PathEscape(requestID)+"/bundle", in)
	if err != nil {
		return err
	}
	return bundleAnswer(status, body)
}

// bundleAnswer maps a reader's answer to a bundle hand-off.
func bundleAnswer(status int, body []byte) error {
	switch status {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrReaderNotFound
	case http.StatusBadRequest, http.StatusConflict:
		return &RefusalError{Code: readerCode(body)}
	default:
		return fmt.Errorf("%w: bundle answered %d", ErrReaderUnavailable, status)
	}
}

// Revoke tells the reader a connection is over so it stops serving tokens
// for it before its next status check. Best effort: the ledger already says
// so, and the reader re-checks it.
func (c *Relay) Revoke(ctx context.Context, connectionID string) error {
	status, _, err := c.do(ctx, http.MethodPost, "/internal/connections/"+url.PathEscape(connectionID)+"/revoke", nil)
	if err != nil {
		return err
	}
	return revokeAnswer(status)
}

// revokeAnswer maps a reader's answer to a revocation notice.
func revokeAnswer(status int) error {
	if status != http.StatusNoContent && status != http.StatusOK && status != http.StatusNotFound {
		return fmt.Errorf("%w: revoke answered %d", ErrReaderUnavailable, status)
	}
	return nil
}

// do performs one request and returns the status and the body, bounded. Any
// transport failure is ErrReaderUnavailable; the caller decides what a status
// means. Nothing here logs.
func (c *Relay) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("%w: %w", ErrReaderUnavailable, err)
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, payload)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", ErrReaderUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Secret)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: relayTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		// The error carries the URL, which is loopback and secret-free;
		// the bearer header is not part of it.
		return 0, nil, fmt.Errorf("%w: %w", ErrReaderUnavailable, err)
	}
	defer func() {
		//nolint:errcheck // the body is drained; a close error changes nothing
		_ = resp.Body.Close()
	}()
	return readAnswer(resp)
}

// readAnswer returns a reader's status and body, bounded. The caller closes
// the body.
func readAnswer(resp *http.Response) (int, []byte, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRelayBody+1))
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", ErrReaderUnavailable, err)
	}
	if len(raw) > maxRelayBody {
		return 0, nil, fmt.Errorf("%w: the answer is larger than %d bytes", ErrReaderUnavailable, maxRelayBody)
	}
	return resp.StatusCode, raw, nil
}

// readerCode pulls the reader's error code out of a refusal, for the log.
// Only the code: the message is the reader's business.
func readerCode(body []byte) string {
	var e struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &e) != nil || e.Code == "" {
		return "unspecified"
	}
	return e.Code
}
