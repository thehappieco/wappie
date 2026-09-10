package wsapi_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/coder/websocket"

	"whatserver2/internal/wsapi"
)

// An attachment is described twice: once to the upload endpoint, which picks
// the HKDF label its bytes are encrypted under, and again on the frame that
// sends it, which picks the protobuf field. Nothing links the two calls.
//
// Getting them to disagree is not exotic — "enviar a foto como arquivo" is a
// photograph uploaded as an image and sent as a document if a client is not
// careful. Every step then answers success, the archive stores the row, and the
// attachment opens for nobody afterwards: not the recipient, and not us either,
// because we derive our own decryption keys from the type we stored.
//
// So the frame is checked against itself, before any device is looked up.

func handshake(t *testing.T) (*websocket.Conn, string) {
	t.Helper()
	srv, key := newServer(t)
	conn := dial(t, srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: key, Version: wsapi.Version, ClientID: "test"})
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("handshake: %q %s", f.Type, f.Payload)
	}
	return conn, key
}

func mediaFrame(kind, uploadedAs string) wsapi.SendMediaRequest {
	return wsapi.SendMediaRequest{
		// Deliberately a device that does not exist. The point of the test is
		// that the frame is refused before anything is looked up: a caller
		// whose request could never have worked should not be sent looking at
		// their phone's connection.
		DeviceID: "018f3a2b-9999-7000-8000-00000000dead",
		Chat:     "5511999999999@s.whatsapp.net",
		Type:     kind,
		MimeType: "image/jpeg",
		Upload: wsapi.UploadRef{
			Type:       uploadedAs,
			URL:        "https://mmg.whatsapp.net/d/f/AbC.enc",
			DirectPath: "/v/t62.7118-24/1_2_3.enc",
			MediaKey:   []byte("0123456789abcdef0123456789abcdef"),
		},
	}
}

func errorOf(t *testing.T, f wsapi.Frame) wsapi.Error {
	t.Helper()
	if f.Type != wsapi.TypeError {
		t.Fatalf("frame = %q, want an error: %s", f.Type, f.Payload)
	}
	var e wsapi.Error
	if err := json.Unmarshal(f.Payload, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSendingAPhotographAsAFileIsRefused(t *testing.T) {
	conn, _ := handshake(t)
	send(t, conn, wsapi.TypeSendMedia, mediaFrame("document", "image"))

	e := errorOf(t, read(t, conn))
	if e.Code != wsapi.ErrCodeBadRequest {
		t.Errorf("code = %q, want %q — a caller cannot fix this by retrying",
			e.Code, wsapi.ErrCodeBadRequest)
	}
	// The message has to name both halves. "Bad request" alone leaves somebody
	// looking at a frame that appears entirely reasonable.
	for _, want := range []string{"image", "document"} {
		if !strings.Contains(e.Message, want) {
			t.Errorf("the refusal does not mention %q: %s", want, e.Message)
		}
	}
}

func TestTypesThatShareTheirKeysAreAccepted(t *testing.T) {
	// A sticker rides on the image keys, so uploading as one and sending as the
	// other is fine — and refusing it would break sending a sticker at all.
	// Getting past this check means failing later on the device, which is the
	// answer that proves the frame itself was allowed through.
	for _, pair := range [][2]string{
		{"sticker", "image"},
		{"ptv", "video"},
		{"ptt", "audio"},
	} {
		conn, _ := handshake(t)
		send(t, conn, wsapi.TypeSendMedia, mediaFrame(pair[0], pair[1]))

		e := errorOf(t, read(t, conn))
		if e.Code == wsapi.ErrCodeBadRequest && strings.Contains(e.Message, "encryption keys") {
			t.Errorf("%s uploaded as %s was refused as a key mismatch: %s", pair[0], pair[1], e.Message)
		}
	}
}

func TestAnOlderClientThatSaysNothingIsNotRefused(t *testing.T) {
	// The upload only began reporting its type recently. A client built before
	// that sends an empty one, and refusing those would break every existing
	// caller to guard against a mistake they may not be making.
	conn, _ := handshake(t)
	send(t, conn, wsapi.TypeSendMedia, mediaFrame("document", ""))

	e := errorOf(t, read(t, conn))
	if strings.Contains(e.Message, "encryption keys") {
		t.Errorf("an upload with no declared type was refused: %s", e.Message)
	}
}

func TestAnIncompleteUploadIsRefusedBeforeTheDevice(t *testing.T) {
	conn, _ := handshake(t)
	req := mediaFrame("image", "image")
	req.Upload.MediaKey = nil
	send(t, conn, wsapi.TypeSendMedia, req)

	e := errorOf(t, read(t, conn))
	if e.Code != wsapi.ErrCodeBadRequest || !strings.Contains(e.Message, "upload") {
		t.Errorf("error = %q %q, want a bad request naming the upload", e.Code, e.Message)
	}
}

func TestInvalidRoundVideoIsRefusedBeforeDeviceLookup(t *testing.T) {
	conn, _ := handshake(t)
	for _, scenario := range []string{"long", "caption", "gif", "mimetype"} {
		req := mediaFrame("ptv", "video")
		req.MimeType = "video/mp4"
		switch scenario {
		case "long":
			req.Seconds = 61
		case "caption":
			req.Caption = "unsupported"
		case "gif":
			req.IsGIF = true
		case "mimetype":
			req.MimeType = "audio/ogg"
		}
		send(t, conn, wsapi.TypeSendMedia, req)
		e := errorOf(t, read(t, conn))
		if e.Code != wsapi.ErrCodeBadRequest || !strings.Contains(e.Message, "video") {
			t.Fatalf("%s was not a video request error: %+v", scenario, e)
		}
	}
}
