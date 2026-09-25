package mcpauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
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

// Directions, as they appear in the canonical string.
const (
	DirectionToReader = "to-reader"
	DirectionToGo     = "to-go"
)

// The headers every signed request carries.
const (
	HeaderReader    = "X-Wappie-Reader"
	HeaderTimestamp = "X-Wappie-Timestamp"
	HeaderNonce     = "X-Wappie-Nonce"
	HeaderSignature = "X-Wappie-Signature"
)

const (
	hmacScheme = "wappie-mcp-hmac/v1"
	// hmacSkew is how far a timestamp may be from this server's clock.
	hmacSkew = 60 * time.Second
	// replayLifetime is how long a nonce is remembered past its timestamp:
	// one second longer than any timestamp stays acceptable.
	replayLifetime = hmacSkew + time.Second
	// replayCap bounds the nonces held at once, after expired ones are
	// swept. A reader at its rate limits sends a few per second; a hundred
	// thousand live nonces is a flood, and the answer to a flood is 503.
	replayCap = 100_000
	// nonceLen is 16 random bytes in unpadded base64url.
	nonceLen = 22
)

// Signature computes the v1 signature of one request: HMAC-SHA256, keyed with
// the secret's bytes as written, over the canonical string. The target is
// the raw path and query exactly as on the request line.
func Signature(secret, direction, readerID, method, target, timestamp, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	canonical := strings.Join([]string{
		hmacScheme, direction, readerID, strings.ToUpper(method), target, timestamp, nonce, hex.EncodeToString(sum[:]),
	}, "\n")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

// sign adds the four headers to an outgoing request. The target signed is
// the one Go writes on the request line, so the receiver sees the same bytes.
func sign(req *http.Request, secret, readerID string, body []byte, now time.Time) error {
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	req.Header.Set(HeaderReader, readerID)
	req.Header.Set(HeaderTimestamp, timestamp)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, Signature(secret, DirectionToReader, readerID, req.Method, req.URL.RequestURI(), timestamp, nonce, body))
	return nil
}

func newNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// signedHeaders is what a received request claims about itself.
type signedHeaders struct {
	timestamp string
	unix      int64
	nonce     string
	signature string
}

// errHMACMissing and errHMACStale are the two ways the headers alone fail.
var (
	errHMACMissing = errors.New("hmac_missing")
	errHMACStale   = errors.New("hmac_stale")
)

// readSignedHeaders checks that the timestamp, nonce and signature are each
// present once and well formed, and that the timestamp is within the skew.
// The reader header is the caller's to check, before this.
func readSignedHeaders(h http.Header, now time.Time) (signedHeaders, error) {
	one := func(name string) (string, bool) {
		values := h.Values(name)
		return strings.Join(values, ""), len(values) == 1
	}
	timestamp, okT := one(HeaderTimestamp)
	nonce, okN := one(HeaderNonce)
	signature, okS := one(HeaderSignature)
	if !okT || !okN || !okS || !validTimestamp(timestamp) || !validNonce(nonce) || !validSignature(signature) {
		return signedHeaders{}, errHMACMissing
	}
	unix, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return signedHeaders{}, errHMACMissing
	}
	if skew := now.Unix() - unix; skew > int64(hmacSkew/time.Second) || skew < -int64(hmacSkew/time.Second) {
		return signedHeaders{}, errHMACStale
	}
	return signedHeaders{timestamp: timestamp, unix: unix, nonce: nonce, signature: signature}, nil
}

// validTimestamp is decimal Unix seconds with no sign and no leading zero.
func validTimestamp(s string) bool {
	if s == "" || len(s) > 18 || s[0] == '0' {
		return false
	}
	return !strings.ContainsFunc(s, func(c rune) bool { return c < '0' || c > '9' })
}

func validNonce(s string) bool {
	return len(s) == nonceLen && !strings.ContainsFunc(s, func(c rune) bool { return !base64urlChar(c) })
}

func validSignature(s string) bool {
	digest, ok := strings.CutPrefix(s, "v1=")
	return ok && len(digest) == 64 && isHex(digest)
}

// signedBy reports whether any of the secrets produced the signature. Every
// secret is tried, with no early exit, so the time taken does not say which
// one matched or how close a guess came.
func signedBy(secrets []string, got signedHeaders, direction, readerID, method, target string, body []byte) bool {
	matched := 0
	for _, secret := range secrets {
		want := Signature(secret, direction, readerID, method, target, got.timestamp, got.nonce, body)
		matched |= subtle.ConstantTimeCompare([]byte(want), []byte(got.signature))
	}
	return matched == 1
}

// replayCache remembers the nonces of accepted requests until they could no
// longer be accepted anyway. It is filled only after a signature checks, so
// nobody without a secret can put anything in it.
type replayCache struct {
	mu       sync.Mutex
	seen     map[string]time.Time
	capacity int
}

// errReplay and errReplayFull are the two refusals.
var (
	errReplay     = errors.New("hmac_replay")
	errReplayFull = errors.New("replay_cache_full")
)

func newReplayCache(capacity int) *replayCache {
	return &replayCache{seen: map[string]time.Time{}, capacity: capacity}
}

// admit records a nonce, or says it was seen or that there is no room. A
// full cache fails closed: refusing a genuine request is a retry, and
// accepting one unremembered would be a replay window.
func (c *replayCache) admit(direction, readerID, nonce string, timestamp int64, now time.Time) error {
	key := direction + "\x00" + readerID + "\x00" + nonce
	c.mu.Lock()
	defer c.mu.Unlock()
	if until, ok := c.seen[key]; ok && until.After(now) {
		return errReplay
	}
	if len(c.seen) >= c.capacity {
		for k, until := range c.seen {
			if !until.After(now) {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= c.capacity {
			return errReplayFull
		}
	}
	c.seen[key] = time.Unix(timestamp, 0).Add(replayLifetime)
	return nil
}
