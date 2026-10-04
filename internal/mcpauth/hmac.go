package mcpauth

import (
	"net/http"
	"time"

	"github.com/thehappieco/kit/profiles/wappie"
	"github.com/thehappieco/kit/reqhmac"
)

// Request authentication between this server and an attested reader.
//
// The hosted reader shares this host and a bearer secret; an attested reader
// is on another machine, behind a parent instance that sees every byte of the
// traffic TLS does not hide and every header nginx logs. So every request in
// either direction is signed over its method, target, body and a fresh nonce,
// with a direction so that a request signed for one side cannot be replayed
// to the other, and a receiver refuses anything stale or already seen. A
// bearer secret would be replayable by anyone who ever saw one request.
//
// The scheme is the shared kit's request signature
// (github.com/thehappieco/kit/reqhmac), which started as this file, under
// Wappie's label wappie-mcp-hmac/v1 and headers. The refusal codes are the
// ones this server has always logged.

// Directions, as they appear in the canonical string.
const (
	DirectionToReader = wappie.DirectionToReader
	DirectionToGo     = wappie.DirectionToGo
)

// The headers every signed request carries: the scheme's own, named here as
// constants for the routes and tests that set them.
const (
	HeaderReader    = "X-Wappie-Reader"
	HeaderTimestamp = "X-Wappie-Timestamp"
	HeaderNonce     = "X-Wappie-Nonce"
	HeaderSignature = "X-Wappie-Signature"
)

// mcpHMAC is the wappie-mcp-hmac/v1 scheme: its label, the four headers above
// and a skew of sixty seconds either way of this server's clock.
var mcpHMAC = wappie.MCPHMAC()

// replayCap bounds the nonces held at once, after expired ones are swept. A
// reader at its rate limits sends a few per second; a hundred thousand live
// nonces is a flood, and the answer to a flood is 503.
const replayCap = wappie.ReplayCapacity

// Signature computes the v1 signature of one request: HMAC-SHA256, keyed with
// the secret's bytes as written, over the canonical string. The target is
// the raw path and query exactly as on the request line.
func Signature(secret, direction, readerID, method, target, timestamp, nonce string, body []byte) string {
	return mcpHMAC.Signature(secret, direction, readerID, method, target, timestamp, nonce, body)
}

// sign adds the four headers to an outgoing request. The target signed is
// the one Go writes on the request line, so the receiver sees the same bytes.
func sign(req *http.Request, secret, readerID string, body []byte, now time.Time) error {
	return mcpHMAC.Sign(req.Header, secret, DirectionToReader, readerID, req.Method, req.URL.RequestURI(), body, now)
}

// signedHeaders is what a received request claims about itself.
type signedHeaders struct {
	timestamp string
	unix      int64
	nonce     string
	signature string
}

// readSignedHeaders checks that the timestamp, nonce and signature are each
// present once and well formed, and that the timestamp is within the skew.
// The reader header is the caller's to check, before this. The two ways the
// headers alone fail are reqhmac.ErrMissing and reqhmac.ErrStale, whose texts
// (hmac_missing, hmac_stale) are the codes refuse logs.
func readSignedHeaders(h http.Header, now time.Time) (signedHeaders, error) {
	got, err := mcpHMAC.Read(h, now)
	if err != nil {
		return signedHeaders{}, err
	}
	return signedHeaders{timestamp: got.Timestamp, unix: got.Unix, nonce: got.Nonce, signature: got.Signature}, nil
}

// signedBy reports whether any of the secrets produced the signature. Every
// secret is tried, with no early exit, so the time taken does not say which
// one matched or how close a guess came.
func signedBy(secrets []string, got signedHeaders, direction, readerID, method, target string, body []byte) bool {
	signed := reqhmac.Signed{Timestamp: got.timestamp, Unix: got.unix, Nonce: got.nonce, Signature: got.signature}
	return mcpHMAC.SignedBy(secrets, signed, direction, readerID, method, target, body)
}

// replayCache remembers the nonces of accepted requests until they could no
// longer be accepted anyway. It is filled only after a signature checks, so
// nobody without a secret can put anything in it.
type replayCache struct {
	*reqhmac.ReplayCache
}

// errReplay and errReplayFull are the two refusals.
var (
	errReplay     = reqhmac.ErrReplay
	errReplayFull = reqhmac.ErrReplayFull
)

// newReplayCache remembers each nonce one second longer than its timestamp
// stays acceptable.
func newReplayCache(capacity int) *replayCache {
	return &replayCache{reqhmac.NewReplayCache(capacity, wappie.ReplayLifetime)}
}

// admit records a nonce, or says it was seen or that there is no room. A
// full cache fails closed: refusing a genuine request is a retry, and
// accepting one unremembered would be a replay window.
func (c *replayCache) admit(direction, readerID, nonce string, timestamp int64, now time.Time) error {
	return c.Admit(direction, readerID, nonce, timestamp, now)
}
