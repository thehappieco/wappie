package send

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/domain"
)

// Attachment is an uploaded file, ready to be referenced by a message.
//
// Everything here comes back from the upload: WhatsApp's servers hold the
// ciphertext and hand back where it is and what it hashes to. A message is
// then a small protobuf pointing at it — which is why the same upload can be
// sent to several chats without transferring the bytes again.
type Attachment struct {
	Type     domain.Type
	MimeType string

	URL           string
	DirectPath    string
	MediaKey      []byte
	FileSHA256    []byte
	FileEncSHA256 []byte
	FileLength    uint64

	// Caption is the text under an image, video or document. Audio has none:
	// WhatsApp has no field for it and a caption passed here would vanish.
	Caption string

	// FileName is shown for a document and is what the recipient's download
	// is called.
	FileName string

	Width  uint32
	Height uint32
	// Seconds is the duration of audio and video. Zero leaves the recipient's
	// player showing nothing until it has buffered the whole file.
	Seconds uint32

	// Waveform is the 64-byte amplitude sketch behind a voice note.
	//
	// Supplied by the caller. Computing it means decoding the audio, and the
	// only thing that has already decoded it is whatever recorded it.
	Waveform []byte

	// Thumbnail is a small JPEG preview, likewise from the caller. Generating
	// one server-side would mean decoding images and video frames here, for a
	// picture the sending client has already rendered.
	Thumbnail []byte

	// Sidecar carries per-chunk MACs so a recipient can play a video before it
	// has finished downloading.
	Sidecar []byte

	// IsGIF makes a video loop silently, which is how WhatsApp does GIFs: it
	// has no GIF type, only a video flagged this way.
	IsGIF bool
	// IsAnimated marks an animated sticker.
	IsAnimated bool
}

// ErrNoAttachment reports a media send with nothing uploaded.
var ErrNoAttachment = errors.New("send: no attachment: url, direct path and media key are all required")

// ErrCaptionOnAudio reports a caption where WhatsApp has no field for one.
//
// Refused rather than dropped. A caption that silently disappears looks like a
// delivery failure to whoever wrote it.
var ErrCaptionOnAudio = errors.New("send: audio and voice notes carry no caption; " +
	"WhatsApp has no field for it and it would be dropped without a trace")

// Media builds an outbound message for an uploaded attachment.
func Media(chat types.JID, a Attachment, opts Options) (*waE2E.Message, error) {
	if a.URL == "" || a.DirectPath == "" || len(a.MediaKey) == 0 {
		return nil, ErrNoAttachment
	}
	if a.MimeType == "" {
		return nil, errors.New("send: an attachment needs a mime type; the recipient " +
			"decides how to render it from that alone")
	}

	ctx := buildContext(chat, opts)
	// WhatsApp stamps when the key was minted. Clients use it to decide
	// whether a re-download is worth attempting.
	stamp := time.Now().Unix()

	var msg *waE2E.Message
	switch a.Type {
	case domain.TypeImage:
		msg = &waE2E.Message{ImageMessage: &waE2E.ImageMessage{
			ViewOnce: optionalBool(opts.ViewOnce),
			URL:      &a.URL, DirectPath: &a.DirectPath, Mimetype: &a.MimeType,
			MediaKey: a.MediaKey, FileSHA256: a.FileSHA256, FileEncSHA256: a.FileEncSHA256,
			FileLength: &a.FileLength, MediaKeyTimestamp: &stamp,
			Caption: optional(a.Caption), JPEGThumbnail: a.Thumbnail,
			Width: optionalU32(a.Width), Height: optionalU32(a.Height),
			ContextInfo: ctx,
		}}

	case domain.TypeVideo, domain.TypePTV:
		video := &waE2E.VideoMessage{
			ViewOnce: optionalBool(opts.ViewOnce),
			URL:      &a.URL, DirectPath: &a.DirectPath, Mimetype: &a.MimeType,
			MediaKey: a.MediaKey, FileSHA256: a.FileSHA256, FileEncSHA256: a.FileEncSHA256,
			FileLength: &a.FileLength, MediaKeyTimestamp: &stamp,
			Seconds: optionalU32(a.Seconds), JPEGThumbnail: a.Thumbnail,
			Width: optionalU32(a.Width), Height: optionalU32(a.Height),
			StreamingSidecar: a.Sidecar,
			ContextInfo:      ctx,
		}
		if a.Type == domain.TypePTV {
			// A round video note travels in its own field. It has no caption
			// and clients render it as a circle, so putting one in the video
			// field instead would change how it looks on the recipient's
			// screen.
			if a.Caption != "" {
				return nil, errors.New("send: a round video note carries no caption")
			}
			msg = &waE2E.Message{PtvMessage: video}
			break
		}
		video.Caption = optional(a.Caption)
		video.GifPlayback = optionalBool(a.IsGIF)
		msg = &waE2E.Message{VideoMessage: video}

	case domain.TypeAudio, domain.TypePTT:
		if a.Caption != "" {
			return nil, ErrCaptionOnAudio
		}
		msg = &waE2E.Message{AudioMessage: &waE2E.AudioMessage{
			ViewOnce: optionalBool(opts.ViewOnce),
			URL:      &a.URL, DirectPath: &a.DirectPath, Mimetype: &a.MimeType,
			MediaKey: a.MediaKey, FileSHA256: a.FileSHA256, FileEncSHA256: a.FileEncSHA256,
			FileLength: &a.FileLength, MediaKeyTimestamp: &stamp,
			Seconds: optionalU32(a.Seconds),
			// PTT is what makes it a voice note rather than an audio file:
			// same bytes, but the recipient sees a waveform and a play button
			// instead of a file row, and it counts as "played" rather than
			// "read".
			PTT:              optionalBool(a.Type == domain.TypePTT),
			Waveform:         a.Waveform,
			StreamingSidecar: a.Sidecar,
			ContextInfo:      ctx,
		}}

	case domain.TypeDocument:
		name := a.FileName
		if name == "" {
			return nil, errors.New("send: a document needs a file name; without one " +
				"the recipient sees an unnamed download")
		}
		msg = &waE2E.Message{DocumentMessage: &waE2E.DocumentMessage{
			URL: &a.URL, DirectPath: &a.DirectPath, Mimetype: &a.MimeType,
			MediaKey: a.MediaKey, FileSHA256: a.FileSHA256, FileEncSHA256: a.FileEncSHA256,
			FileLength: &a.FileLength, MediaKeyTimestamp: &stamp,
			FileName: &name,
			// Title is what WhatsApp shows in the bubble; without it the
			// bubble is blank above the file name.
			Title:         &name,
			Caption:       optional(a.Caption),
			JPEGThumbnail: a.Thumbnail,
			ContextInfo:   ctx,
		}}

	case domain.TypeSticker:
		msg = &waE2E.Message{StickerMessage: &waE2E.StickerMessage{
			URL: &a.URL, DirectPath: &a.DirectPath, Mimetype: &a.MimeType,
			MediaKey: a.MediaKey, FileSHA256: a.FileSHA256, FileEncSHA256: a.FileEncSHA256,
			FileLength: &a.FileLength, MediaKeyTimestamp: &stamp,
			Width: optionalU32(a.Width), Height: optionalU32(a.Height),
			IsAnimated:  optionalBool(a.IsAnimated),
			ContextInfo: ctx,
		}}

	default:
		return nil, fmt.Errorf("send: %q is not an attachment type", a.Type)
	}

	// View once is marked twice: on the media message itself, above, and by the
	// wrapper below.
	//
	// Both are needed and the reason is not obvious. The wrapper is what
	// whatsmeow and other libraries unwrap to decide IsViewOnce; the field on
	// the media message is what several official clients actually read when
	// deciding whether to render a one-time bubble. Sending only the wrapper
	// produces a message that some clients treat as view-once and others show
	// as an ordinary photograph -- which is exactly the split reported against
	// the first version of this.
	return wrap(msg, opts), nil
}

// MediaRequest is one outbound attachment.
type MediaRequest struct {
	Chat       types.JID
	Attachment Attachment
	Opts       Options
	ID         string
}

// SendMedia sends an attachment and returns what to archive.
//
// The archived envelope carries the same URL, direct path and media key the
// recipient got, so the attachment is fetched back from the CDN by the ordinary
// download worker and stored exactly like an inbound one. Uploading the bytes
// to object storage directly from here would store something assembled by a
// different path, and the two would drift.
func SendMedia(ctx context.Context, c Client, req MediaRequest) (Sent, error) {
	msg, err := Media(req.Chat, req.Attachment, req.Opts)
	if err != nil {
		return Sent{}, err
	}

	var extra []whatsmeow.SendRequestExtra
	if req.ID != "" {
		extra = append(extra, whatsmeow.SendRequestExtra{ID: req.ID})
	}
	resp, err := c.SendMessage(ctx, req.Chat, msg, extra...)
	if err != nil {
		return Sent{}, fmt.Errorf("send: %w", err)
	}

	env := outboundEnvelope(req.Chat, resp, domain.KindMessage,
		req.Attachment.Type, req.Attachment.Caption, req.Opts)
	a := req.Attachment
	env.Content.Media = &domain.Media{
		MimeType: a.MimeType, FileLength: a.FileLength,
		FileSHA256: a.FileSHA256, FileEncSHA256: a.FileEncSHA256,
		DirectPath: a.DirectPath, URL: a.URL,
		MediaKey: a.MediaKey, Sidecar: a.Sidecar,
		Width: a.Width, Height: a.Height, Seconds: a.Seconds,
		Waveform: a.Waveform, Thumbnail: a.Thumbnail,
		FileName: a.FileName, IsGIF: a.IsGIF,
	}
	return Sent{ID: resp.ID, Timestamp: resp.Timestamp, Envelope: env}, nil
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func optionalU32(v uint32) *uint32 {
	if v == 0 {
		return nil
	}
	return &v
}

func optionalBool(v bool) *bool {
	if !v {
		return nil
	}
	return proto.Bool(true)
}
