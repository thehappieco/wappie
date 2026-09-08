package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/crypto/wamedia"
	"whatserver2/internal/wsapi"
)

// cmdMedia downloads an attachment and opens it locally.
//
// This is the end-to-end statement of the media design, the same way "watch"
// is for message bodies. The server streams ciphertext it cannot read, over an
// endpoint that sets no content type because it has no idea what the bytes are.
// The 32-byte key that makes them a photograph is sealed in the message row,
// and is unwrapped here, on this machine, by a private key the server has never
// held.
//
// Run it without -key and you get the ciphertext, which is what an attacker
// with the bucket gets.
func cmdMedia(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("media", flag.ContinueOnError)
	keyArg := fs.String("key", "", "archive private key, as printed by `whatserverd archive-key`")
	uid := fs.String("uid", "", "message uid (required)")
	out := fs.String("o", "", "where to write; defaults to a name derived from the message")
	raw := fs.Bool("raw", false, "write the ciphertext as served, without decrypting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *uid == "" {
		return errors.New("-uid is required; wsctl watch prints one per message")
	}
	if !*raw && *keyArg == "" {
		return errors.New("-key is required to decrypt; pass -raw to write the " +
			"ciphertext instead, which is what the server itself holds")
	}

	var priv seal.PrivateKey
	if *keyArg != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(*keyArg))
		if err != nil {
			return fmt.Errorf("-key is not a valid archive key: %w", err)
		}
		if priv, err = seal.ParsePrivateKey(decoded); err != nil {
			return err
		}
	}

	c, err := dial(ctx)
	if err != nil {
		return err
	}
	defer c.close()

	tenant, err := uuid.Parse(c.tenant)
	if err != nil {
		return fmt.Errorf("server reported an unusable tenant: %w", err)
	}

	frame, err := c.request(ctx, "get-1", wsapi.TypeMessageGet,
		wsapi.MessageGetRequest{UID: *uid}, wsapi.TypeMessageFrame)
	if err != nil {
		return err
	}
	var msg wsapi.SealedMessage
	if err := json.Unmarshal(frame.Payload, &msg); err != nil {
		return err
	}
	if msg.Media == nil {
		return fmt.Errorf("message %s has no attachment", *uid)
	}
	if msg.Media.DownloadStatus != "done" {
		return fmt.Errorf("the attachment is %s, not stored yet. The worker fetches "+
			"it in the background; try again shortly", msg.Media.DownloadStatus)
	}

	dest := *out
	if dest == "" {
		dest = defaultName(ctx, msg, newOpener(c, tenant, priv), *raw)
	}

	body, cipherLen, err := fetchCiphertext(ctx, *uid)
	if err != nil {
		return err
	}
	//nolint:errcheck // the download is finished; a close error changes nothing
	defer func() { _ = body.Close() }()

	// Written aside and renamed only on success. DecryptTo says so in capitals
	// and it is not a formality: the MAC covers the whole ciphertext, so it
	// cannot be checked until the last block has already been written. A file
	// left behind after a failure would hold unauthenticated bytes that look
	// exactly like a good download.
	partial := dest + ".part"
	file, err := os.Create(partial) //nolint:gosec // the path is the operator's own -o
	if err != nil {
		return err
	}
	discard := func() {
		//nolint:errcheck // already failing; a close error would replace a better one
		_ = file.Close()
		//nolint:errcheck // best effort cleanup of a file being abandoned
		_ = os.Remove(partial)
	}

	var n int64
	if *raw {
		n, err = io.Copy(file, body)
	} else {
		var mediaKey []byte
		if mediaKey, err = newOpener(c, tenant, priv).mediaKey(ctx, msg); err == nil {
			// Streamed rather than buffered: an attachment can be hundreds of
			// megabytes, and holding one in memory twice to decrypt it is how
			// a client falls over on a video.
			//
			// The length passed is the *ciphertext* length — the plaintext
			// padded to a block boundary plus the ten byte MAC. Passing the
			// file_length the sender declared instead makes the block-size
			// check reject a perfectly good download.
			n, err = wamedia.DecryptTo(file, body, cipherLen,
				mediaKey, wamedia.Type(msg.Media.MediaType))
		}
	}
	if err != nil {
		discard()
		// A MAC failure here is meaningful rather than generic: the stored
		// bytes were altered, or this is the wrong key.
		return fmt.Errorf("could not open the attachment: %w", err)
	}
	if err := file.Close(); err != nil {
		//nolint:errcheck // best effort cleanup of a file being abandoned
		_ = os.Remove(partial)
		return err
	}
	if err := os.Rename(partial, dest); err != nil {
		return err
	}

	if *raw {
		fmt.Printf("wrote %s: %d bytes of ciphertext, undecrypted\n", dest, n)
		fmt.Println("That is exactly what the object store holds.")
		return nil
	}
	fmt.Printf("wrote %s: %d bytes\n", dest, n)
	fmt.Println("The server streamed ciphertext; the key came from the sealed row and " +
		"was unwrapped here.")
	return nil
}

// mediaKey unwraps the 32 bytes that make an attachment readable.
func (o *opener) mediaKey(ctx context.Context, msg wsapi.SealedMessage) ([]byte, error) {
	if !o.priv.Valid() {
		return nil, errors.New("no archive key, so the attachment cannot be opened")
	}
	if len(msg.Media.MediaKeySealed) == 0 {
		return nil, errors.New("the message carries no media key; the attachment " +
			"cannot be opened by anyone, including the sender's other devices")
	}
	uid, err := uuid.Parse(msg.UID)
	if err != nil {
		return nil, err
	}
	device, err := uuid.Parse(msg.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("the message names a device this client cannot parse: %w", err)
	}
	ck, err := o.key(ctx, device, msg.ContentKeyID)
	if err != nil {
		return nil, err
	}
	return ck.Open(seal.KindMediaKey, o.tenant, uid, msg.Media.MediaKeySealed)
}

// fetchCiphertext streams an attachment from the media endpoint, with its
// length.
//
// The length is the size of the ciphertext, which is what the streaming
// decryptor needs in order to find the trailing MAC. It is a different number
// from the plaintext length the sender declared.
func fetchCiphertext(ctx context.Context, uid string) (io.ReadCloser, int64, error) {
	apiKey := os.Getenv("WS_API_KEY")
	if apiKey == "" {
		return nil, 0, errors.New("WS_API_KEY is not set")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mediaURL(uid), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := (&http.Client{Timeout: 30 * time.Minute}).Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch attachment: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		//nolint:errcheck // failing anyway; the close error would replace a better one
		defer func() { _ = resp.Body.Close() }()
		// Best effort: the body is a diagnostic, and failing to read it must
		// not replace the status code with a less useful error.
		//nolint:errcheck // see above
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return nil, 0, fmt.Errorf("fetch attachment: http %d: %s",
			resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	if resp.ContentLength < 0 {
		//nolint:errcheck // failing anyway
		defer func() { _ = resp.Body.Close() }()
		return nil, 0, errors.New("the media endpoint reported no length, so the " +
			"boundary between ciphertext and its trailing MAC is unknown")
	}
	return resp.Body, resp.ContentLength, nil
}

// mediaURL turns the websocket address into the media one, so a non-default
// port set in .env moves both without being repeated.
func mediaURL(uid string) string {
	base := serverURL()
	base = strings.TrimSuffix(base, "/v1/ws")
	base = strings.Replace(base, "ws://", "http://", 1)
	base = strings.Replace(base, "wss://", "https://", 1)
	return base + "/v1/media/" + uid
}

// defaultName picks a file name when the operator did not.
//
// The stored file name is sealed, so this can only use it when a key was given.
// Without one the name falls back to the uid, which is honest: the server does
// not know what the file was called either.
func defaultName(ctx context.Context, msg wsapi.SealedMessage, o *opener, raw bool) string {
	ext := ".bin"
	if raw {
		ext = ".enc"
	}
	name := short(msg.UID)
	if !raw {
		if sealedName := msg.Media.FileNameSealed; len(sealedName) > 0 {
			if opened := o.open(ctx, msg.DeviceID, msg.ContentKeyID, msg.UID, seal.KindContactName, sealedName); opened != "" &&
				!strings.HasPrefix(opened, "<") {
				return filepath.Base(opened)
			}
		}
		if guessed := extensionFor(msg.Media.MimeType, msg.Media.MediaType); guessed != "" {
			ext = guessed
		}
	}
	return name + ext
}

// extensionFor guesses a file extension from what the message declared.
func extensionFor(mime, mediaType string) string {
	if i := strings.IndexByte(mime, ';'); i >= 0 {
		mime = mime[:i]
	}
	switch strings.TrimSpace(mime) {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/webp":
		return ".webp"
	case "video/mp4":
		return ".mp4"
	case "audio/ogg", "audio/ogg; codecs=opus":
		return ".ogg"
	case "audio/mpeg":
		return ".mp3"
	case "application/pdf":
		return ".pdf"
	}
	switch mediaType {
	case "image":
		return ".jpg"
	case "video", "ptv":
		return ".mp4"
	case "audio", "ptt":
		return ".ogg"
	}
	return ".bin"
}

// cmdMediaRetry asks senders to upload attachments again.
//
// WhatsApp signs media URLs with an expiry and puts the same signature on the
// direct path, so once it passes there is no address left to try — no header
// helps and no library can do better. A history sync replays months-old
// messages carrying the URL minted back then, which is why a bootstrap can land
// with most of its attachments already unreachable.
//
// The media key travels to the server for the exchange, because the request has
// to be authenticated with it and the answer is encrypted under it, and the
// server cannot open the sealed copy it holds. It is kept in memory for
// minutes and never written down.
//
// Expect a modest success rate. The sender's device has to be reachable and to
// still hold the file; for anything old, the usual answer is that it does not.
func cmdMediaRetry(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("media-retry", flag.ContinueOnError)
	keyArg := fs.String("key", "", "archive private key (required)")
	device := fs.String("device", "", "device id (required)")
	uid := fs.String("uid", "", "one message to recover")
	sweep := fs.Int("n", 0, "instead of -uid, ask for this many expired attachments, newest first")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *keyArg == "":
		return errors.New("-key is required: the media key has to be opened here, " +
			"because the server cannot open its own sealed copy")
	case *device == "":
		return errors.New("-device is required")
	case *uid == "" && *sweep <= 0:
		return errors.New("give -uid for one attachment, or -n COUNT to sweep the expired ones")
	}

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(*keyArg))
	if err != nil {
		return fmt.Errorf("-key is not a valid archive key: %w", err)
	}
	priv, err := seal.ParsePrivateKey(raw)
	if err != nil {
		return err
	}

	c, err := dial(ctx)
	if err != nil {
		return err
	}
	defer c.close()
	tenant, err := uuid.Parse(c.tenant)
	if err != nil {
		return fmt.Errorf("server reported an unusable tenant: %w", err)
	}
	opener := newOpener(c, tenant, priv)

	targets := []string{*uid}
	if *uid == "" {
		if targets, err = expiredUIDs(ctx, c, *device, *sweep); err != nil {
			return err
		}
		fmt.Printf("%d attachment(s) with an expired url\n\n", len(targets))
	}

	var asked, skipped int
	for i, target := range targets {
		msg, err := fetchMessage(ctx, c, target, i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", short(target), err)
			skipped++
			continue
		}
		if msg.Media == nil {
			skipped++
			continue
		}
		mediaKey, err := opener.mediaKey(ctx, msg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", short(target), err)
			skipped++
			continue
		}
		if _, err := c.request(ctx, fmt.Sprintf("retry-%d", i), wsapi.TypeMediaRetry,
			wsapi.MediaRetryRequest{DeviceID: *device, UID: target, MediaKey: mediaKey},
			wsapi.TypeRetryQueued); err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", short(target), err)
			skipped++
			continue
		}
		asked++
	}

	fmt.Printf("asked for %d, skipped %d\n", asked, skipped)
	fmt.Println("Answers arrive over the next minutes and the attachments download " +
		"themselves. Watch with: tail -f the server log, or re-run wsctl media later.")
	fmt.Println("A sender who is offline, or who no longer has the file, simply never " +
		"answers. That is the common case for anything old.")
	return nil
}

// fetchMessage loads one message by uid.
func fetchMessage(ctx context.Context, c *client, uid string, seq int) (wsapi.SealedMessage, error) {
	f, err := c.request(ctx, fmt.Sprintf("get-%d", seq), wsapi.TypeMessageGet,
		wsapi.MessageGetRequest{UID: uid}, wsapi.TypeMessageFrame)
	if err != nil {
		return wsapi.SealedMessage{}, err
	}
	var msg wsapi.SealedMessage
	err = json.Unmarshal(f.Payload, &msg)
	return msg, err
}

// expiredUIDs asks the server which attachments are unreachable.
func expiredUIDs(ctx context.Context, c *client, device string, limit int) ([]string, error) {
	f, err := c.request(ctx, "expired-1", wsapi.TypeMediaExpired,
		wsapi.ExpiredMediaRequest{DeviceID: device, Limit: limit}, wsapi.TypeExpiredList)
	if err != nil {
		return nil, err
	}
	var out wsapi.ExpiredMedia
	if err := json.Unmarshal(f.Payload, &out); err != nil {
		return nil, err
	}
	return out.UIDs, nil
}
