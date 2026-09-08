// Package media fetches attachments and stores them without opening them.
//
// The design decision that shapes everything here: this server downloads
// WhatsApp's ciphertext and never decrypts it. whatsmeow's own download
// helpers decrypt on the way past, which would mean every photograph and voice
// note in the archive passing through this process in the clear — and would
// make "the server cannot read your media" false in exactly the moment it
// matters.
//
// It is possible to avoid because the CDN serves the encrypted bytes to a plain
// HTTP client: the URL carried in the message is a capability, and what comes
// back is AES-256-CBC ciphertext with a trailing HMAC. Verified here against
// the fileEncSHA256 the sender published, which is a hash of the *ciphertext* —
// so a download can be proven correct without a key.
//
// The media key is sealed into the message row and never reaches this package.
package media

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"whatserver2/internal/store"
)

// ErrGone reports an attachment WhatsApp will not serve again.
//
// Separate from an ordinary failure because the remedy is different: there is
// none. Retrying a 404 produces a 404, and a row that retries forever crowds
// out the ones that would succeed.
var ErrGone = errors.New("media: the CDN will not serve this attachment")

// ErrTooLarge reports an attachment past the configured ceiling.
var ErrTooLarge = errors.New("media: attachment is larger than the limit")

// ErrCorrupt reports bytes that do not hash to what the sender published.
var ErrCorrupt = errors.New("media: downloaded bytes do not match the published hash")

// defaultHost is where WhatsApp serves media.
//
// Used only to rebuild a URL from a direct path. whatsmeow asks the server for
// a host list on every download; that call is unexported, and the path carries
// its own authorisation, so the well-known host is enough for the fallback.
const defaultHost = "https://mmg.whatsapp.net"

// Fetcher downloads ciphertext.
type Fetcher struct {
	client *http.Client
	// Origins is where the fetcher will go. The URL comes from the message,
	// which is to say from whoever sent it; see Origins for why that matters.
	Origins Origins
	// MaxBytes bounds one attachment. A ceiling is not optional: the length in
	// the message is the sender's claim, and a hostile one saying "8 KB" while
	// serving gigabytes would otherwise fill the disk.
	MaxBytes int64
	// TempDir is where ciphertext lands while it is being verified. Ciphertext
	// only — there is no point in this package where plaintext exists, so this
	// directory never holds anything readable.
	TempDir string
}

// NewFetcher builds a fetcher.
func NewFetcher(maxBytes int64, tempDir string) *Fetcher {
	return NewFetcherFrom(WhatsAppOrigins(), maxBytes, tempDir)
}

// NewFetcherFrom builds a fetcher that will only go where origins allow.
func NewFetcherFrom(origins Origins, maxBytes int64, tempDir string) *Fetcher {
	return &Fetcher{
		// Redirects are followed, but only a few: a capability URL that
		// bounces indefinitely is a way to hold a worker open. Each hop is
		// checked against the origins like the first request was.
		client:   origins.Client(10*time.Minute, 5),
		Origins:  origins,
		MaxBytes: maxBytes,
		TempDir:  tempDir,
	}
}

// Fetch downloads one attachment's ciphertext into a temporary file.
//
// The returned file is positioned at the start and is the caller's to close and
// remove. Its contents have already been verified against the published hash,
// so an upload of it cannot store the wrong bytes.
func (f *Fetcher) Fetch(ctx context.Context, p store.Pending) (*os.File, int64, error) {
	urls := candidateURLs(p)
	if len(urls) == 0 {
		return nil, 0, fmt.Errorf("%w: no url and no direct path", ErrGone)
	}

	var lastErr error
	for _, u := range urls {
		file, n, err := f.fetchOne(ctx, u, p)
		if err == nil {
			return file, n, nil
		}
		if errors.Is(err, ErrTooLarge) || errors.Is(err, context.Canceled) {
			return nil, 0, err
		}
		if errors.Is(err, ErrOrigin) {
			// A refused origin is final for this URL and worth saying so in
			// the log; the direct-path fallback is still worth a try.
			lastErr = err
			continue
		}
		lastErr = err
	}
	return nil, 0, lastErr
}

func (f *Fetcher) fetchOne(ctx context.Context, url string, p store.Pending) (*os.File, int64, error) {
	// Checked before a request exists. The URL is the sender's, and a sender
	// who can point this server at an address of their choosing has a request
	// forgery, hash check or not.
	if err := f.Origins.Check(url); err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("media: build request: %w", err)
	}
	// The CDN answers a bare request with a 403. These two headers are what
	// WhatsApp Web sends and what makes it serve the bytes.
	req.Header.Set("Origin", "https://web.whatsapp.com")
	req.Header.Set("Referer", "https://web.whatsapp.com/")
	req.Header.Set("User-Agent", "WhatsApp/2.2413.51 Mozilla/5.0")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("media: fetch: %w", err)
	}
	//nolint:errcheck // a failed close on a response we are done reading tells us nothing
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusPartialContent:
	case http.StatusForbidden, http.StatusNotFound, http.StatusGone:
		// The capability in the URL has expired, or the attachment was
		// removed. Both are final for these bytes.
		return nil, 0, fmt.Errorf("%w: http %d", ErrGone, resp.StatusCode)
	default:
		return nil, 0, fmt.Errorf("media: fetch: http %d", resp.StatusCode)
	}
	if resp.ContentLength > 0 && resp.ContentLength > f.MaxBytes {
		return nil, 0, fmt.Errorf("%w: %d bytes announced", ErrTooLarge, resp.ContentLength)
	}

	file, err := os.CreateTemp(f.TempDir, "wa-media-*.enc")
	if err != nil {
		return nil, 0, fmt.Errorf("media: temp file: %w", err)
	}
	cleanup := func() {
		name := file.Name()
		//nolint:errcheck // discarding a temp file we have already decided not to use
		_ = file.Close()
		//nolint:errcheck // the file is temporary; a stale one is swept by the OS
		_ = os.Remove(name)
	}

	// Hash while writing rather than reading the file back afterwards: the
	// bytes are already going past, and a second pass over a large attachment
	// is pure cost.
	sum := sha256.New()
	// MaxBytes+1 so an attachment exactly at the limit is allowed and one byte
	// over is caught, rather than being silently truncated to the limit.
	n, err := io.Copy(io.MultiWriter(file, sum), io.LimitReader(resp.Body, f.MaxBytes+1))
	if err != nil {
		cleanup()
		return nil, 0, fmt.Errorf("media: read body: %w", err)
	}
	if n > f.MaxBytes {
		cleanup()
		return nil, 0, fmt.Errorf("%w: over %d bytes", ErrTooLarge, f.MaxBytes)
	}

	// The published hash is of the ciphertext, which is why a download can be
	// checked without a key. Constant time is habit rather than necessity
	// here; the comparison is cheap and the habit is worth keeping.
	if len(p.FileEncSHA256) > 0 {
		if subtle.ConstantTimeCompare(sum.Sum(nil), p.FileEncSHA256) != 1 {
			cleanup()
			return nil, 0, fmt.Errorf("%w: got %d bytes", ErrCorrupt, n)
		}
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, 0, fmt.Errorf("media: rewind: %w", err)
	}
	return file, n, nil
}

// candidateURLs lists where an attachment might be, best first.
//
// The URL carried in the message is tried first because it is what the sender's
// client was given and it works verbatim. The direct path is the fallback: it
// carries its own authorisation in its query string, so pointing it at the
// well-known host reconstructs a working request without needing the host list
// whatsmeow keeps to itself.
func candidateURLs(p store.Pending) []string {
	var out []string
	if p.URL != "" {
		out = append(out, p.URL)
	}
	if p.DirectPath != "" && strings.HasPrefix(p.DirectPath, "/") {
		out = append(out, fmt.Sprintf("%s%s&hash=%s&mms-type=%s&__wa-mms=",
			defaultHost, p.DirectPath,
			base64.URLEncoding.EncodeToString(p.FileEncSHA256), mmsType(p.MediaType)))
	}
	return out
}

// mmsType maps our media type onto the name the CDN expects.
//
// Stickers travel as images: WhatsApp has no sticker mms type on the download
// path, and asking for one gets a 404 rather than a sticker.
func mmsType(t string) string {
	switch t {
	case "image", "sticker":
		return "image"
	case "video", "ptv":
		return "video"
	case "audio", "ptt":
		return "audio"
	case "document":
		return "document"
	default:
		return "image"
	}
}
