package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"whatserver2/internal/wsapi"
)

// cmdSendMedia uploads a file and sends it.
//
// Two steps, and the split is deliberate: the bytes go over HTTP and the
// message that references them over the websocket. Framing a video through the
// same connection that carries live messages would stall every other frame
// behind it.
//
// This is also the one place attachment plaintext passes through the server.
// WhatsApp's upload takes cleartext and encrypts on the way out, and offers no
// way to hand it ciphertext somebody else produced — so an attachment being
// *sent* is exposed exactly as outbound text already is. Receiving has no such
// compromise.
func cmdSendMedia(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("send-media", flag.ContinueOnError)
	device := fs.String("device", "", "device id (required)")
	to := fs.String("to", "", "recipient JID or phone number (required)")
	path := fs.String("file", "", "file to send (required)")
	kind := fs.String("type", "", "image, video, ptv, audio, ptt, document or sticker; guessed from the file when omitted")
	caption := fs.String("caption", "", "text under the attachment; not allowed on audio")
	mimeType := fs.String("mime", "", "override the mime type guessed from the extension")
	seconds := fs.Uint("seconds", 0, "duration of audio or video, for the recipient's player")
	width := fs.Uint("width", 0, "pixel width, for the placeholder before it loads")
	height := fs.Uint("height", 0, "pixel height")
	gif := fs.Bool("gif", false, "send a video as a looping GIF")
	viewOnce := fs.Bool("view-once", false, "the recipient may open it once")
	replyTo := fs.String("reply-to", "", "message id being replied to")
	replyBody := fs.String("reply-body", "", "preview text for the quote; optional")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireAll(map[string]string{
		"-device": *device, "-to": *to, "-file": *path,
	}); err != nil {
		return err
	}

	info, err := os.Stat(*path)
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		return fmt.Errorf("%s is empty", *path)
	}

	if *kind == "" {
		*kind = guessType(*path)
		if *kind == "" {
			return fmt.Errorf("cannot tell what %s is; pass -type", filepath.Base(*path))
		}
	}
	if *mimeType == "" {
		*mimeType = guessMime(*path, *kind)
	}
	if *caption != "" && (*kind == "audio" || *kind == "ptt") {
		return errors.New("audio and voice notes carry no caption: WhatsApp has no " +
			"field for it, so it would vanish without a trace")
	}
	if *kind == "document" && *caption == "" {
		// Not an error, just worth knowing: the bubble shows the file name.
		fmt.Fprintf(os.Stderr, "note: sending %s as a document\n", filepath.Base(*path))
	}

	upload, err := uploadFile(ctx, *path, *device, *kind)
	if err != nil {
		return err
	}

	c, err := dial(ctx)
	if err != nil {
		return err
	}
	defer c.close()

	req := wsapi.SendMediaRequest{
		DeviceID: *device,
		Chat:     normaliseJID(*to),
		Type:     *kind,
		Upload:   *upload,
		MimeType: *mimeType,
		Caption:  *caption,
		//nolint:gosec // G115: dimensions and durations are small user-supplied counts
		Width: uint32(*width),
		//nolint:gosec // G115: see above
		Height: uint32(*height),
		//nolint:gosec // G115: see above
		Seconds:   uint32(*seconds),
		IsGIF:     *gif,
		ViewOnce:  *viewOnce,
		ReplyTo:   *replyTo,
		ReplyBody: *replyBody,
	}
	if *kind == "document" {
		req.FileName = filepath.Base(*path)
	}

	f, err := c.request(ctx, "sendmedia-1", wsapi.TypeSendMedia, req, wsapi.TypeSendResult)
	if err != nil {
		return err
	}
	var res wsapi.SendResult
	if err := json.Unmarshal(f.Payload, &res); err != nil {
		return err
	}

	fmt.Printf("sent   %s (%s, %d bytes)\n", res.ID, *kind, upload.FileLength)
	reportArchive(res)
	fmt.Println("The archive fetches it back from the CDN as ciphertext, like any " +
		"attachment that arrives. Open it with: wsctl media -uid <uid> -key ...")
	return nil
}

// uploadFile streams a file to the upload endpoint and returns where it landed.
func uploadFile(ctx context.Context, path, device, kind string) (*wsapi.UploadRef, error) {
	apiKey := os.Getenv("WS_API_KEY")
	if apiKey == "" {
		return nil, errors.New("WS_API_KEY is not set")
	}
	file, err := os.Open(path) //nolint:gosec // the path is the operator's own -file
	if err != nil {
		return nil, err
	}
	//nolint:errcheck // read-only; a close error after a successful upload is noise
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s?device=%s&type=%s", uploadURL(), device, kind)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, file)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/octet-stream")
	// Set explicitly so the server does not have to buffer to find the length.
	req.ContentLength = info.Size()

	resp, err := (&http.Client{Timeout: 30 * time.Minute}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("upload: %w", err)
	}
	//nolint:errcheck // the response is fully read below or being discarded
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		//nolint:errcheck // best effort diagnostic; the status is the real error
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return nil, fmt.Errorf("upload: http %d: %s",
			resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	var out wsapi.UploadRef
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("upload: unreadable response: %w", err)
	}
	return &out, nil
}

func uploadURL() string {
	base := strings.TrimSuffix(serverURL(), "/v1/ws")
	base = strings.Replace(base, "ws://", "http://", 1)
	base = strings.Replace(base, "wss://", "https://", 1)
	return base + "/v1/upload"
}

// guessType picks an attachment type from the file extension.
//
// A guess, and a conservative one: anything unrecognised comes back empty so
// the caller is asked rather than having a spreadsheet sent as a video.
func guessType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jpg", ".jpeg", ".png", ".gif", ".heic":
		return "image"
	case ".mp4", ".mov", ".m4v", ".3gp":
		return "video"
	case ".ogg", ".opus", ".m4a", ".mp3", ".aac", ".wav":
		return "audio"
	case ".webp":
		return "sticker"
	case ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".txt", ".csv", ".zip", ".json":
		return "document"
	default:
		return ""
	}
}

// guessMime picks a mime type, since the recipient renders from that alone.
func guessMime(path, kind string) string {
	if t := mime.TypeByExtension(strings.ToLower(filepath.Ext(path))); t != "" {
		return t
	}
	switch kind {
	case "image":
		return "image/jpeg"
	case "video", "ptv":
		return "video/mp4"
	case "audio", "ptt":
		// Opus in an Ogg container is what WhatsApp records voice notes as,
		// and what its clients render with a waveform.
		return "audio/ogg; codecs=opus"
	case "sticker":
		return "image/webp"
	default:
		return "application/octet-stream"
	}
}
