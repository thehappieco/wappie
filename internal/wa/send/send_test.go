package send_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/domain"
	"whatserver2/internal/wa/fakewa"
	"whatserver2/internal/wa/send"
)

var (
	dmChat = types.JID{User: "5511999999999", Server: types.DefaultUserServer}
	group  = types.JID{User: "120363000000000000", Server: types.GroupServer}
	other  = types.JID{User: "5511888888888", Server: types.DefaultUserServer}
)

func sendText(t *testing.T, chat types.JID, body string, opts send.Options) *waE2E.Message {
	t.Helper()
	fake := fakewa.New()
	if _, err := send.SendText(context.Background(), fake,
		send.Request{Chat: chat, Body: body, Opts: opts}); err != nil {
		t.Fatalf("SendText: %v", err)
	}
	last := fake.LastSent()
	if last == nil {
		t.Fatal("nothing was sent")
	}
	return last.Message
}

// Outbound text always goes as ExtendedTextMessage, never Conversation.
//
// Conversation is a bare string with nowhere to attach ContextInfo, so a
// message sent that way cannot express a reply, a mention, an expiry or the
// forwarded flag. Using the richer form unconditionally means there is no case
// where a feature silently does nothing.
func TestTextIsAlwaysExtended(t *testing.T) {
	msg := sendText(t, dmChat, "olá", send.Options{})
	if msg.GetConversation() != "" {
		t.Fatal("sent as Conversation, which cannot carry ContextInfo")
	}
	if msg.GetExtendedTextMessage().GetText() != "olá" {
		t.Fatalf("text = %q", msg.GetExtendedTextMessage().GetText())
	}
}

// A plain message gets no ContextInfo at all, rather than an empty struct.
func TestPlainMessageHasNoContext(t *testing.T) {
	msg := sendText(t, dmChat, "oi", send.Options{})
	if msg.GetExtendedTextMessage().GetContextInfo() != nil {
		t.Error("a plain message was padded with an empty ContextInfo")
	}
}

// A forwarded message with a score of zero shows no badge on the recipient's
// phone, which makes the flag pointless. One is the minimum that renders.
func TestForwardedScoreIsNeverZero(t *testing.T) {
	msg := sendText(t, dmChat, "encaminhada", send.Options{Forwarded: true})
	ci := msg.GetExtendedTextMessage().GetContextInfo()
	if !ci.GetIsForwarded() {
		t.Fatal("the forwarded flag was not set")
	}
	if ci.GetForwardingScore() < 1 {
		t.Fatalf("forwarding score = %d; zero renders no badge at all", ci.GetForwardingScore())
	}
}

// Five or more is what WhatsApp renders as "forwarded many times", so an
// explicit score must survive untouched.
func TestExplicitForwardingScoreIsKept(t *testing.T) {
	msg := sendText(t, dmChat, "viral", send.Options{Forwarded: true, ForwardingScore: 7})
	if got := msg.GetExtendedTextMessage().GetContextInfo().GetForwardingScore(); got != 7 {
		t.Fatalf("forwarding score = %d, want 7", got)
	}
}

// Participant identifies the author of a quoted message. In a group it is
// required: without it the recipient renders the quote stripped of its author,
// which is a visible defect. In a direct chat the remote JID already says who
// the other party is, and sending it is wrong.
func TestReplyParticipantOnlyInGroups(t *testing.T) {
	quoted := &waE2E.Message{Conversation: proto.String("original")}

	inGroup := sendText(t, group, "respondendo", send.Options{
		ReplyTo: "TARGET1", ReplySender: other, ReplyContent: quoted,
	})
	gi := inGroup.GetExtendedTextMessage().GetContextInfo()
	if gi.GetStanzaID() != "TARGET1" {
		t.Errorf("stanza id = %q", gi.GetStanzaID())
	}
	if gi.GetParticipant() == "" {
		t.Error("a group reply must name the author of the quoted message")
	}
	if gi.GetQuotedMessage() == nil {
		t.Error("the quoted message was dropped")
	}

	inDM := sendText(t, dmChat, "respondendo", send.Options{
		ReplyTo: "TARGET1", ReplyContent: quoted,
	})
	if p := inDM.GetExtendedTextMessage().GetContextInfo().GetParticipant(); p != "" {
		t.Errorf("a direct-message reply set Participant to %q", p)
	}
}

func TestExpirationAndMentions(t *testing.T) {
	msg := sendText(t, group, "@fulano some em 24h", send.Options{
		Expiration: 86400,
		Mentions:   []types.JID{other},
	})
	// An expiration brings the disappearing envelope with it, so the text is
	// one level in. See TestAnExpirationAlwaysBringsTheEnvelope for why the
	// two are not separable.
	ci := msg.GetEphemeralMessage().GetMessage().GetExtendedTextMessage().GetContextInfo()
	if ci.GetExpiration() != 86400 {
		t.Errorf("expiration = %d", ci.GetExpiration())
	}
	if len(ci.GetMentionedJID()) != 1 {
		t.Fatalf("mentions = %v", ci.GetMentionedJID())
	}
}

// The ephemeral wrapper is the one that works on text, and it must be the
// outermost envelope so the recipient's client peels it in the order whatsmeow
// peels an incoming one.
func TestEphemeralWrapping(t *testing.T) {
	msg := sendText(t, dmChat, "sumir", send.Options{Ephemeral: true, Expiration: 86400})

	inner := msg.GetEphemeralMessage().GetMessage()
	if inner == nil {
		t.Fatal("the ephemeral wrapper is missing")
	}
	if inner.GetExtendedTextMessage() == nil {
		t.Fatal("the text did not survive the wrapping")
	}
	if inner.GetExtendedTextMessage().GetContextInfo().GetExpiration() != 86400 {
		t.Error("the timer was lost inside the wrapper")
	}
}

// View-once is a media feature. WhatsApp renders it for images, videos and
// voice notes; for anything else it shows "this message will not disappear,
// sent from an older version of WhatsApp", which is the fallback for an
// envelope the client cannot interpret.
//
// The protobuf does carry a ViewOnce field on ExtendedTextMessage, but the
// generated types come from Meta's own definitions and contain plenty no client
// acts on. Sending something that renders as a version warning is worse than
// refusing, so this refuses — and this test is what stops the flag quietly
// coming back for text.
func TestViewOnceIsRefusedOnText(t *testing.T) {
	fake := fakewa.New()
	_, err := send.SendText(context.Background(), fake, send.Request{
		Chat: dmChat, Body: "uma vez só", Opts: send.Options{ViewOnce: true},
	})
	if !errors.Is(err, send.ErrViewOnceText) {
		t.Fatalf("err = %v, want ErrViewOnceText", err)
	}
	if len(fake.Sent()) != 0 {
		t.Fatal("an invalid message was sent anyway")
	}
}

// StanzaID and QuotedMessage do different jobs and are not alternatives.
// StanzaID is the link that lets the recipient tap through to the original;
// QuotedMessage is the preview shown when their own copy is gone. A recipient
// who still has the message renders from their copy and ignores the preview,
// which makes it look redundant — it is not, and dropping it would leave
// anyone without the original looking at an empty quote.
func TestReplyWithoutPreviewStillLinks(t *testing.T) {
	msg := sendText(t, dmChat, "respondendo", send.Options{ReplyTo: "TARGET1"})
	ci := msg.GetExtendedTextMessage().GetContextInfo()
	if ci.GetStanzaID() != "TARGET1" {
		t.Fatalf("stanza id = %q; the link is what makes a reply a reply", ci.GetStanzaID())
	}
	if ci.GetQuotedMessage() != nil {
		t.Error("a preview appeared without being supplied")
	}
}

func TestEmptyBodyIsRefused(t *testing.T) {
	fake := fakewa.New()
	if _, err := send.SendText(context.Background(), fake,
		send.Request{Chat: dmChat, Body: ""}); err == nil {
		t.Fatal("an empty message was accepted")
	}
}

// WhatsApp allows twenty minutes. Checking locally turns a stanza the server
// would reject into an error the caller can show, without burning a round trip.
func TestEditWindow(t *testing.T) {
	fake := fakewa.New()
	ctx := context.Background()

	_, err := send.SendEdit(ctx, fake, send.EditRequest{
		Chat: dmChat, TargetID: "MSG1", Body: "corrigido",
		SentAt: time.Now().Add(-25 * time.Minute),
	})
	if !errors.Is(err, send.ErrEditWindowExpired) {
		t.Fatalf("err = %v, want ErrEditWindowExpired", err)
	}
	if err != nil && !strings.Contains(err.Error(), "ago") {
		t.Errorf("the error should say how old the message is: %v", err)
	}

	// Inside the window it goes out.
	sent, err := send.SendEdit(ctx, fake, send.EditRequest{
		Chat: dmChat, TargetID: "MSG1", Body: "corrigido",
		SentAt: time.Now().Add(-2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("an edit inside the window failed: %v", err)
	}
	if sent.Envelope.Kind != domain.KindEdit {
		t.Errorf("kind = %q, want edit", sent.Envelope.Kind)
	}
	if sent.Envelope.TargetID != "MSG1" {
		t.Errorf("target = %q", sent.Envelope.TargetID)
	}
	// An edit always targets a real message; WhatsApp has no notion of
	// editing a reaction.
	if sent.Envelope.TargetRel != domain.TargetMessage {
		t.Errorf("target rel = %q, want message", sent.Envelope.TargetRel)
	}
}

// A revoke leaves the relation unresolved: whether it deletes a message or
// withdraws a reaction depends on what the target is, and ingest answers that
// by looking rather than guessing.
func TestRevokeLeavesTargetRelationOpen(t *testing.T) {
	fake := fakewa.New()
	sent, err := send.SendRevoke(context.Background(), fake, send.RevokeRequest{
		Chat: dmChat, TargetID: "MSG1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sent.Envelope.Kind != domain.KindDelete {
		t.Errorf("kind = %q, want delete", sent.Envelope.Kind)
	}
	if sent.Envelope.TargetRel != domain.TargetNone {
		t.Errorf("target rel = %q; a revoke's target is resolved during ingest",
			sent.Envelope.TargetRel)
	}
}

// An empty emoji removes a reaction. It is a withdrawal, not an empty
// reaction, and it must still be sent.
func TestReactionRemoval(t *testing.T) {
	fake := fakewa.New()
	ctx := context.Background()

	for name, emoji := range map[string]string{"add": "\U0001F44D", "remove": ""} {
		t.Run(name, func(t *testing.T) {
			sent, err := send.SendReaction(ctx, fake, send.ReactRequest{
				Chat: dmChat, TargetID: "MSG1", Sender: other, Emoji: emoji,
			})
			if err != nil {
				t.Fatal(err)
			}
			if sent.Envelope.Kind != domain.KindReaction {
				t.Errorf("kind = %q", sent.Envelope.Kind)
			}
			if sent.Envelope.Content.Body != emoji {
				t.Errorf("body = %q, want %q", sent.Envelope.Content.Body, emoji)
			}
		})
	}
}

// A caller-supplied id makes a retry idempotent: the same id sent twice is the
// same message, not two.
func TestCallerSuppliedIDIsUsed(t *testing.T) {
	fake := fakewa.New()
	sent, err := send.SendText(context.Background(), fake, send.Request{
		Chat: dmChat, Body: "oi", ID: "MYID123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sent.ID != "MYID123" {
		t.Errorf("id = %q, want the one supplied", sent.ID)
	}
	last := fake.LastSent()
	if len(last.Extra) == 0 || last.Extra[0].ID != "MYID123" {
		t.Error("the id was not passed to whatsmeow")
	}
}

// The archive records what the recipient actually saw, not what was asked for.
func TestOutboundEnvelopeRecordsWhatWentOut(t *testing.T) {
	fake := fakewa.New()
	sent, err := send.SendText(context.Background(), fake, send.Request{
		Chat: dmChat, Body: "encaminhada",
		Opts: send.Options{Forwarded: true, Expiration: 3600},
	})
	if err != nil {
		t.Fatal(err)
	}
	env := sent.Envelope
	if env.Source != domain.SourceOutbox {
		t.Errorf("source = %q, want outbox", env.Source)
	}
	if !env.IsFromMe {
		t.Error("an outbound message must be marked as ours")
	}
	if !env.IsForwarded || env.ForwardingScore != 1 {
		t.Errorf("forwarded = %v score = %d; the archive should record the score that "+
			"was actually sent", env.IsForwarded, env.ForwardingScore)
	}
	if env.Expiration != 3600 {
		t.Errorf("expiration = %d", env.Expiration)
	}
	if env.Content.Body != "encaminhada" {
		t.Errorf("body = %q", env.Content.Body)
	}
}

// TestLinkPreviewMustMatchTheBody.
//
// WhatsApp attaches the card by finding MatchedText inside the message text. A
// card describing a link that is not there does not render and produces no
// error, so the mismatch is refused here rather than becoming a silent nothing
// on the recipient's screen.
func TestLinkPreviewMustMatchTheBody(t *testing.T) {
	_, err := send.Text(dmChat, "olha isso", send.Options{
		Preview: &send.Preview{URL: "https://example.invalid/a"},
	})
	if err == nil {
		t.Fatal("a preview for a url absent from the body was accepted")
	}

	msg, err := send.Text(dmChat, "olha isso https://example.invalid/a", send.Options{
		Preview: &send.Preview{
			URL: "https://example.invalid/a", Title: "Um título",
			Thumbnail: []byte{0xFF, 0xD8, 0xFF},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ext := msg.GetExtendedTextMessage()
	if ext.GetMatchedText() != "https://example.invalid/a" {
		t.Fatalf("matched text = %q", ext.GetMatchedText())
	}
	if ext.GetTitle() != "Um título" || len(ext.GetJPEGThumbnail()) != 3 {
		t.Fatalf("card came back as title=%q thumb=%d bytes",
			ext.GetTitle(), len(ext.GetJPEGThumbnail()))
	}
}

// Attachment builders. The interesting cases are the ones where WhatsApp has
// no field for what was asked, because the failure mode is silence: the
// message arrives with the thing simply missing.

func upload() send.Attachment {
	return send.Attachment{
		Type: domain.TypeImage, MimeType: "image/jpeg",
		URL: "https://mmg.whatsapp.net/x", DirectPath: "/x",
		MediaKey: make([]byte, 32), FileLength: 1234,
	}
}

// TestViewOnceWorksOnMedia is the other half of TestViewOnceIsRefusedOnText.
//
// View once is a media feature. The same wrapper on text renders as "sent from
// an older version of WhatsApp", which is why Text refuses it — and why it has
// to work here, or the refusal would be the whole story.
func TestViewOnceWorksOnMedia(t *testing.T) {
	msg, err := send.Media(dmChat, upload(), send.Options{ViewOnce: true})
	if err != nil {
		t.Fatal(err)
	}
	inner := msg.GetViewOnceMessageV2().GetMessage()
	if inner == nil {
		t.Fatal("the message was not wrapped for view once")
	}
	if inner.GetImageMessage() == nil {
		t.Fatal("the wrapper does not contain the image")
	}
}

// TestACaptionOnAudioIsRefused. WhatsApp has no caption field on audio, so one
// passed here would be dropped in silence — which looks like a delivery
// failure to whoever wrote it.
func TestACaptionOnAudioIsRefused(t *testing.T) {
	a := upload()
	a.Type, a.MimeType, a.Caption = domain.TypePTT, "audio/ogg", "escuta isso"
	if _, err := send.Media(dmChat, a, send.Options{}); !errors.Is(err, send.ErrCaptionOnAudio) {
		t.Fatalf("got %v, want ErrCaptionOnAudio", err)
	}
}

// TestAVoiceNoteIsMarkedAsOne. Same bytes as an audio file; the PTT flag is
// what makes the recipient see a waveform and a play button rather than a file
// row, and what makes it "played" rather than "read".
func TestAVoiceNoteIsMarkedAsOne(t *testing.T) {
	a := upload()
	a.Type, a.MimeType, a.Seconds = domain.TypePTT, "audio/ogg; codecs=opus", 7
	a.Waveform = make([]byte, 64)

	msg, err := send.Media(dmChat, a, send.Options{})
	if err != nil {
		t.Fatal(err)
	}
	audio := msg.GetAudioMessage()
	if !audio.GetPTT() {
		t.Fatal("sent as an audio file rather than a voice note")
	}
	if audio.GetSeconds() != 7 || len(audio.GetWaveform()) != 64 {
		t.Fatalf("seconds=%d waveform=%d", audio.GetSeconds(), len(audio.GetWaveform()))
	}

	a.Type = domain.TypeAudio
	msg, err = send.Media(dmChat, a, send.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if msg.GetAudioMessage().GetPTT() {
		t.Fatal("a plain audio file was marked as a voice note")
	}
}

// TestARoundVideoNoteTravelsInItsOwnField. Shaped exactly like a video, but
// clients render it as a circle and it has no caption; putting it in the video
// field would change how it looks on the recipient's screen.
func TestARoundVideoNoteTravelsInItsOwnField(t *testing.T) {
	a := upload()
	a.Type, a.MimeType = domain.TypePTV, "video/mp4"

	msg, err := send.Media(dmChat, a, send.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if msg.GetPtvMessage() == nil {
		t.Fatal("a round video note was not sent as one")
	}
	if msg.GetVideoMessage() != nil {
		t.Fatal("it went out as an ordinary video too")
	}

	a.Caption = "oi"
	if _, err := send.Media(dmChat, a, send.Options{}); err == nil {
		t.Fatal("a caption on a round video note was accepted")
	}
}

// TestADocumentNeedsAName. Without one the recipient sees an unnamed download.
func TestADocumentNeedsAName(t *testing.T) {
	a := upload()
	a.Type, a.MimeType = domain.TypeDocument, "application/pdf"
	if _, err := send.Media(dmChat, a, send.Options{}); err == nil {
		t.Fatal("a document with no file name was accepted")
	}

	a.FileName = "contrato.pdf"
	msg, err := send.Media(dmChat, a, send.Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc := msg.GetDocumentMessage()
	if doc.GetFileName() != "contrato.pdf" {
		t.Fatalf("file name = %q", doc.GetFileName())
	}
	// Title is what fills the bubble; without it the bubble is blank above the
	// file name.
	if doc.GetTitle() == "" {
		t.Fatal("no title, so the bubble renders empty")
	}
}

// TestAnAttachmentWithNoUploadIsRefused. Building a message that points at
// nothing produces a bubble the recipient can never open.
func TestAnAttachmentWithNoUploadIsRefused(t *testing.T) {
	for _, broken := range []func(*send.Attachment){
		func(a *send.Attachment) { a.URL = "" },
		func(a *send.Attachment) { a.DirectPath = "" },
		func(a *send.Attachment) { a.MediaKey = nil },
	} {
		a := upload()
		broken(&a)
		if _, err := send.Media(dmChat, a, send.Options{}); !errors.Is(err, send.ErrNoAttachment) {
			t.Fatalf("got %v, want ErrNoAttachment", err)
		}
	}
	a := upload()
	a.MimeType = ""
	if _, err := send.Media(dmChat, a, send.Options{}); err == nil {
		t.Fatal("an attachment with no mime type was accepted; the recipient " +
			"decides how to render it from that alone")
	}
}

// TestAttachmentsCarryContextTheSameWayTextDoes. A reply, a mention or the
// forwarded badge working on a text message and not on a photograph is exactly
// the kind of quiet divergence this codebase exists to avoid.
func TestAttachmentsCarryContextTheSameWayTextDoes(t *testing.T) {
	msg, err := send.Media(group, upload(), send.Options{
		ReplyTo: "3EB0ABC", ReplySender: other,
		Forwarded: true, Mentions: []types.JID{other},
		Expiration: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	ci := msg.GetEphemeralMessage().GetMessage().GetImageMessage().GetContextInfo()
	if ci.GetStanzaID() != "3EB0ABC" {
		t.Fatalf("stanza id = %q", ci.GetStanzaID())
	}
	if ci.GetParticipant() == "" {
		t.Fatal("no participant on a group reply, so the quote renders with no author")
	}
	if ci.GetForwardingScore() != 1 {
		t.Fatalf("forwarding score = %d, want 1: zero shows no badge", ci.GetForwardingScore())
	}
	if len(ci.GetMentionedJID()) != 1 || ci.GetExpiration() != 86400 {
		t.Fatalf("mentions=%v expiration=%d", ci.GetMentionedJID(), ci.GetExpiration())
	}
}

// TestAnExpirationAlwaysBringsTheEnvelope is the bug from the field, pinned.
//
// "-expires 3600 and it was still there an hour later": the timer was written
// into the context and the message was not wrapped in the disappearing
// envelope, so every client read the number and kept the message. The two are
// not independent settings, and no caller should have to know that.
func TestAnExpirationAlwaysBringsTheEnvelope(t *testing.T) {
	msg, err := send.Text(dmChat, "some ate as 19h", send.Options{Expiration: 3600})
	if err != nil {
		t.Fatal(err)
	}
	inner := msg.GetEphemeralMessage().GetMessage()
	if inner == nil {
		t.Fatal("a message with an expiration was not wrapped in the disappearing envelope")
	}
	if got := inner.GetExtendedTextMessage().GetContextInfo().GetExpiration(); got != 3600 {
		t.Fatalf("expiration = %d, want 3600", got)
	}

	// And the same for an attachment, or the two paths disagree.
	a := upload()
	media, err := send.Media(dmChat, a, send.Options{Expiration: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if media.GetEphemeralMessage().GetMessage().GetImageMessage() == nil {
		t.Fatal("an attachment with an expiration was not wrapped")
	}
}

// TestNoExpirationMeansNoEnvelope. Wrapping an ordinary message would tell
// every client it belongs to a disappearing chat.
func TestNoExpirationMeansNoEnvelope(t *testing.T) {
	msg, err := send.Text(dmChat, "oi", send.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if msg.GetEphemeralMessage() != nil {
		t.Fatal("an ordinary message was wrapped as disappearing")
	}
}

// TestViewOnceIsMarkedOnTheMediaAndTheWrapper.
//
// Reported from the field: WhatsApp Web recognised the message as view-once
// and an iPhone rendered it as an ordinary photograph. The wrapper is what
// libraries unwrap; the field on the media message is what several official
// clients read. Sending one without the other is how clients end up
// disagreeing.
func TestViewOnceIsMarkedOnTheMediaAndTheWrapper(t *testing.T) {
	msg, err := send.Media(dmChat, upload(), send.Options{ViewOnce: true})
	if err != nil {
		t.Fatal(err)
	}
	inner := msg.GetViewOnceMessageV2().GetMessage()
	if inner == nil {
		t.Fatal("no view-once wrapper")
	}
	if !inner.GetImageMessage().GetViewOnce() {
		t.Fatal("the image itself is not marked view once, so clients that read " +
			"the field rather than the wrapper render an ordinary photograph")
	}

	// And an ordinary attachment must not carry the flag.
	plain, err := send.Media(dmChat, upload(), send.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if plain.GetImageMessage().GetViewOnce() {
		t.Fatal("an ordinary image was marked view once")
	}
}

// TestTheArchiveRecordsTheEnvelopeThatWentOut.
//
// The row has to say what the recipient's client will do. A message wrapped in
// the disappearing envelope but archived as ordinary is an archive that
// disagrees with the conversation it is recording — and the disagreement only
// shows up later, when someone asks why a message nobody can find was never
// marked as ephemeral.
func TestTheArchiveRecordsTheEnvelopeThatWentOut(t *testing.T) {
	sent, err := send.SendText(context.Background(), fakewa.New(),
		send.Request{Chat: dmChat, Body: "some em 1h", Opts: send.Options{Expiration: 3600}})
	if err != nil {
		t.Fatal(err)
	}
	if !sent.Envelope.Ephemeral {
		t.Fatal("archived as an ordinary message, but it went out in the " +
			"disappearing envelope")
	}
	if sent.Envelope.Expiration != 3600 {
		t.Fatalf("archived expiration = %d, want 3600", sent.Envelope.Expiration)
	}

	plain, err := send.SendText(context.Background(), fakewa.New(),
		send.Request{Chat: dmChat, Body: "oi"})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Envelope.Ephemeral {
		t.Fatal("an ordinary message was archived as disappearing")
	}
}

// TestOutboundEnvelopeCarriesMentionsAndPreview closes a gap where our own copy
// of a message was poorer than everybody else's.
//
// buildContext puts the mention list and the link card on the wire, so the
// recipient gets both. The archive row was built from the body alone, so a
// message we sent arrived in our own archive with payload_sealed empty — no
// mentions to highlight, no card to draw — while the identical message in the
// recipient's hands had both. Nothing failed and nothing was logged; the
// message simply looked different depending on which side of it you were.
func TestOutboundEnvelopeCarriesMentionsAndPreview(t *testing.T) {
	fake := fakewa.New()
	sent, err := send.SendText(context.Background(), fake, send.Request{
		Chat: group,
		Body: "olha isso https://example.invalid/a",
		Opts: send.Options{
			// With a device suffix, as a client that took the JID off a
			// message would have it. The archive keys people, not phones.
			Mentions: []types.JID{other, {User: "5511777777777", Server: types.HiddenUserServer, Device: 4}},
			Preview: &send.Preview{
				URL: "https://example.invalid/a", Title: "Um título",
				Description: "uma descrição", Thumbnail: []byte{0xff, 0xd8},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := sent.Envelope.Content

	want := []string{other.String(), "5511777777777@lid"}
	if len(got.Mentions) != len(want) {
		t.Fatalf("mentions = %v, want %v", got.Mentions, want)
	}
	for i := range want {
		if got.Mentions[i] != want[i] {
			t.Errorf("mention %d = %q, want %q", i, got.Mentions[i], want[i])
		}
	}

	if got.LinkPreview == nil {
		t.Fatal("the link card reached the recipient and not the archive")
	}
	if got.LinkPreview.URL != "https://example.invalid/a" ||
		got.LinkPreview.Title != "Um título" ||
		got.LinkPreview.Description != "uma descrição" ||
		len(got.LinkPreview.Thumbnail) != 2 {
		t.Errorf("link card = %+v, want the one that was sent", got.LinkPreview)
	}
}

// Our own vote has to be stored the way everybody else's is: as hashes.
//
// The tally happens in the client, which opens the poll, hashes each option and
// matches. If this row carried the option text instead, it would be the one row
// of the poll whose content was not sealed — and it would still not be counted,
// because nothing looking for a hash would find a word.
func TestOurOwnVoteIsStoredHashedLikeEverybodyElses(t *testing.T) {
	fake := fakewa.New()

	sent, err := send.SendPollVote(context.Background(), fake, send.PollVoteRequest{
		Chat: dmChat, PollID: "POLL1", PollSender: other, Options: []string{"Sexta"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sent.Envelope.Type != domain.TypePollVote {
		t.Errorf("type = %q, want poll_vote", sent.Envelope.Type)
	}
	if sent.Envelope.TargetID != "POLL1" {
		t.Errorf("target = %q, want the poll answered", sent.Envelope.TargetID)
	}
	vote := sent.Envelope.Content.PollVote
	if vote == nil || len(vote.Selected) != 1 {
		t.Fatalf("selection = %+v, want one hash", vote)
	}
	want := sha256.Sum256([]byte("Sexta"))
	if !bytes.Equal(vote.Selected[0], want[:]) {
		t.Errorf("selection = %x, want SHA-256 of the option text", vote.Selected[0])
	}
	if bytes.Contains(vote.Selected[0], []byte("Sexta")) {
		t.Error("the option text went into the row in the clear")
	}
}

// Withdrawing is a vote with nothing chosen, and it has to leave.
//
// WhatsApp replaces a voter's previous answer rather than adding to it, so an
// empty selection is the only way to take a vote back. Refusing it here as
// "nothing to send" would leave somebody's answer standing forever.
func TestWithdrawingAVoteIsSentRatherThanRefused(t *testing.T) {
	fake := fakewa.New()

	sent, err := send.SendPollVote(context.Background(), fake, send.PollVoteRequest{
		Chat: dmChat, PollID: "POLL1", PollSender: other, Options: nil,
	})
	if err != nil {
		t.Fatalf("a withdrawal was refused: %v", err)
	}
	if sent.Envelope.Content.PollVote == nil {
		t.Fatal("the row does not say the vote was opened; it reads as unreadable")
	}
	if len(sent.Envelope.Content.PollVote.Selected) != 0 {
		t.Error("a withdrawal arrived carrying a selection")
	}
	if len(fake.PollVotesMade()) != 1 {
		t.Error("nothing was sent; the previous answer stands forever")
	}
}

// A vote with no poll is not a vote. Refused here rather than after a round
// trip: WhatsApp rejects it, and the error names the wrong thing.
func TestAVoteWithoutAPollIsRefused(t *testing.T) {
	if _, err := send.SendPollVote(context.Background(), fakewa.New(),
		send.PollVoteRequest{Chat: dmChat, Options: []string{"Sexta"}}); err == nil {
		t.Fatal("a vote with no poll was accepted")
	}
}
