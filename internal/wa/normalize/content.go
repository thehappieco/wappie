package normalize

import (
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"go.mau.fi/whatsmeow/proto/waE2E"

	"whatserver2/internal/domain"
)

// housekeeping is the set of fields that are protocol machinery rather than
// anything a person sent.
//
// senderKeyDistributionMessage is the one that matters, and the damage it did
// is worth recording. WhatsApp delivers a group message as ONE node with two
// encrypted children: the first carries only the sender key, the second carries
// the message. whatsmeow dispatches an event for each, both with the same
// message id. The first was landing here, falling through to "unsupported", and
// being INSERTED -- so when the real message arrived a moment later it was
// rejected by ON CONFLICT (device_id, chat_key, wa_id) as a duplicate of a stub
// that had already taken its place.
//
// Every group message on this installation was being replaced by an empty row:
// 40 of 152, and zero in one-to-one chats, because sender keys only exist in
// groups. The archive looked like it was working.
var housekeeping = map[protoreflect.Name]bool{
	"senderKeyDistributionMessage":               true,
	"fastRatchetKeySenderKeyDistributionMessage": true,
	"stickerSyncRmrMessage":                      true,
	"groupRootKeyShare":                          true,
	"rootSecretDistributeMessage":                true,
	// Not housekeeping in itself, but never content either: it rides along on
	// nearly every message, because UnwrapRaw copies it down from the wrapper.
	// Left in this set so it can never be mistaken for the answer.
	"messageContextInfo": true,
}

// unclassified names the field a message carries, and says whether that field
// is content at all.
//
// The name is what makes "unsupported" actionable: the payload is sealed, so
// without it nobody can discover which waE2E branch to implement next. It comes
// from the compiled descriptor rather than from the sender, so the value is one
// of about a hundred fixed strings.
//
// Iterated over the descriptor rather than through ProtoReflect.Range, whose
// order is explicitly undefined -- two identical messages must not produce two
// different answers.
func unclassified(m *waE2E.Message) (string, bool) {
	if m == nil {
		return "", false
	}
	r := m.ProtoReflect()
	fields := r.Descriptor().Fields()

	var named []string
	content := false
	for i := range fields.Len() {
		fd := fields.Get(i)
		if !r.Has(fd) {
			continue
		}
		if housekeeping[fd.Name()] {
			continue
		}
		named = append(named, string(fd.Name()))
		content = true
	}

	// A field number this build has never heard of survives as unknown bytes.
	// Reporting it is better than reporting nothing: it says a newer protocol
	// revision is in use and gives the number to look up.
	if !content {
		if tag, ok := firstUnknownTag(r.GetUnknown()); ok {
			return fmt.Sprintf("unknown:%d", tag), true
		}
		return "", false
	}
	return strings.Join(named, "+"), true
}

// firstUnknownTag reads the field number of the first unknown field.
func firstUnknownTag(raw protoreflect.RawFields) (protowire.Number, bool) {
	if len(raw) > 0 {
		number, _, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return 0, false
		}
		return number, true
	}
	return 0, false
}

// content dispatches a plain message onto its type.
//
// The switch is ordered by how common each type is, and every branch fills in
// both the type and whatever content that type carries. An unrecognised message
// falls through to TypeUnsupported rather than being dropped: WhatsApp adds
// message types continuously, and the v1 server silently discarded anything it
// did not know, leaving holes in conversations that could never be explained or
// recovered. An unsupported row keeps the routing metadata and the raw
// protobuf, so the same message becomes readable after an upgrade.
func content(env domain.Envelope, in input) (domain.Envelope, error) {
	m := in.Message

	switch {
	case m.GetConversation() != "":
		env.Type = domain.TypeText
		env.Content.Body = m.GetConversation()

	case m.GetExtendedTextMessage() != nil:
		ext := m.GetExtendedTextMessage()
		env.Type = domain.TypeText
		env.Content.Body = ext.GetText()
		env.Content.LinkPreview = previewOf(ext)

	case m.GetImageMessage() != nil:
		img := m.GetImageMessage()
		env.Type = domain.TypeImage
		env.Content.Body = img.GetCaption()
		env.Content.Media = &domain.Media{
			MimeType:      img.GetMimetype(),
			FileLength:    img.GetFileLength(),
			FileSHA256:    img.GetFileSHA256(),
			FileEncSHA256: img.GetFileEncSHA256(),
			DirectPath:    img.GetDirectPath(),
			URL:           img.GetURL(),
			MediaKey:      img.GetMediaKey(),
			Width:         img.GetWidth(),
			Height:        img.GetHeight(),
			Thumbnail:     img.GetJPEGThumbnail(),
		}
		env.ViewOnce = env.ViewOnce || img.GetViewOnce()

	case m.GetVideoMessage() != nil:
		env = videoInto(env, m.GetVideoMessage(), domain.TypeVideo)

	case m.GetPtvMessage() != nil:
		// A round video note. Carried in its own field but shaped exactly like
		// a video, and it must not be conflated with one: clients render it
		// as a circle and it has no caption.
		env = videoInto(env, m.GetPtvMessage(), domain.TypePTV)

	case m.GetAudioMessage() != nil:
		audio := m.GetAudioMessage()
		// PTT is what separates a voice note from an attached audio file. The
		// difference is visible: a voice note draws a waveform and reports
		// "played" separately from "read".
		typ := domain.TypeAudio
		if audio.GetPTT() {
			typ = domain.TypePTT
		}
		env.Type = typ
		env.Content.Media = &domain.Media{
			MimeType:      audio.GetMimetype(),
			FileLength:    audio.GetFileLength(),
			FileSHA256:    audio.GetFileSHA256(),
			FileEncSHA256: audio.GetFileEncSHA256(),
			DirectPath:    audio.GetDirectPath(),
			URL:           audio.GetURL(),
			MediaKey:      audio.GetMediaKey(),
			Seconds:       audio.GetSeconds(),
			Waveform:      audio.GetWaveform(),
			Sidecar:       audio.GetStreamingSidecar(),
		}
		env.ViewOnce = env.ViewOnce || audio.GetViewOnce()

	case m.GetDocumentMessage() != nil:
		doc := m.GetDocumentMessage()
		env.Type = domain.TypeDocument
		env.Content.Body = doc.GetCaption()
		env.Content.Media = &domain.Media{
			MimeType:      doc.GetMimetype(),
			FileLength:    doc.GetFileLength(),
			FileSHA256:    doc.GetFileSHA256(),
			FileEncSHA256: doc.GetFileEncSHA256(),
			DirectPath:    doc.GetDirectPath(),
			URL:           doc.GetURL(),
			MediaKey:      doc.GetMediaKey(),
			FileName:      doc.GetFileName(),
			Thumbnail:     doc.GetJPEGThumbnail(),
		}

	case m.GetStickerMessage() != nil:
		st := m.GetStickerMessage()
		env.Type = domain.TypeSticker
		env.Content.Media = &domain.Media{
			MimeType:      st.GetMimetype(),
			FileLength:    st.GetFileLength(),
			FileSHA256:    st.GetFileSHA256(),
			FileEncSHA256: st.GetFileEncSHA256(),
			DirectPath:    st.GetDirectPath(),
			URL:           st.GetURL(),
			MediaKey:      st.GetMediaKey(),
			Width:         st.GetWidth(),
			Height:        st.GetHeight(),
		}

	case m.GetLocationMessage() != nil:
		loc := m.GetLocationMessage()
		env.Type = domain.TypeLocation
		env.Content.Body = loc.GetComment()
		env.Content.Location = &domain.Location{
			Latitude:       loc.GetDegreesLatitude(),
			Longitude:      loc.GetDegreesLongitude(),
			Name:           loc.GetName(),
			Address:        loc.GetAddress(),
			AccuracyMeters: loc.GetAccuracyInMeters(),
			Speed:          loc.GetSpeedInMps(),
		}

	case m.GetLiveLocationMessage() != nil:
		loc := m.GetLiveLocationMessage()
		env.Type = domain.TypeLiveLocation
		env.Content.Body = loc.GetCaption()
		env.Content.Location = &domain.Location{
			Latitude:       loc.GetDegreesLatitude(),
			Longitude:      loc.GetDegreesLongitude(),
			AccuracyMeters: loc.GetAccuracyInMeters(),
			Speed:          loc.GetSpeedInMps(),
			SequenceNumber: loc.GetSequenceNumber(),
		}

	case m.GetContactMessage() != nil:
		c := m.GetContactMessage()
		env.Type = domain.TypeContact
		env.Content.Contacts = []domain.Contact{{
			DisplayName: c.GetDisplayName(),
			VCard:       c.GetVcard(),
		}}

	case m.GetContactsArrayMessage() != nil:
		arr := m.GetContactsArrayMessage()
		env.Type = domain.TypeContactArray
		env.Content.Body = arr.GetDisplayName()
		for _, c := range arr.GetContacts() {
			env.Content.Contacts = append(env.Content.Contacts, domain.Contact{
				DisplayName: c.GetDisplayName(),
				VCard:       c.GetVcard(),
			})
		}

	// Every revision, not just the first. The field was versioned rather than
	// extended, so a poll from a current phone arrives as V3 and was landing in
	// "unsupported" while the code read only V1. V4 is a FutureProofMessage and
	// is reached by the wrapper descent instead.
	case m.GetPollCreationMessage() != nil:
		env = pollInto(env, m.GetPollCreationMessage())

	case m.GetPollCreationMessageV2() != nil:
		env = pollInto(env, m.GetPollCreationMessageV2())

	case m.GetPollCreationMessageV3() != nil:
		env = pollInto(env, m.GetPollCreationMessageV3())

	case m.GetPollCreationMessageV5() != nil:
		env = pollInto(env, m.GetPollCreationMessageV5())

	case m.GetPollCreationMessageV6() != nil:
		env = pollInto(env, m.GetPollCreationMessageV6())

	case m.GetPollUpdateMessage() != nil:
		// A vote. The selection itself is encrypted with a per-poll secret and
		// is not readable here; the row records that a vote happened and
		// against which poll.
		env.Type = domain.TypePollVote
		env.TargetID = m.GetPollUpdateMessage().GetPollCreationMessageKey().GetID()
		env.TargetRel = domain.TargetMessage
		// The selection, when the device managed to open it. Hashes of the
		// option text, which is what WhatsApp sends — this server cannot
		// resolve them, because the options are sealed content it has never
		// been able to read. The client does, by hashing what it opens.
		//
		// Recorded even when empty. An empty selection is a withdrawal, and a
		// reader has to be able to tell it from a vote nobody could open: the
		// first says somebody changed their mind, the second says this archive
		// missed an answer.
		if in.PollVote != nil {
			env.Content.PollVote = &domain.PollVote{Selected: in.PollVote.Selected}
		}

	case m.GetEventMessage() != nil:
		env = eventInto(env, m.GetEventMessage())

	case m.GetGroupInviteMessage() != nil:
		env = inviteInto(env, m.GetGroupInviteMessage())

	case m.GetInteractiveMessage() != nil:
		env = interactiveInto(env, m.GetInteractiveMessage())

	case m.GetButtonsMessage() != nil:
		env = buttonsInto(env, m.GetButtonsMessage())

	case m.GetListMessage() != nil:
		env = listInto(env, m.GetListMessage())

	case m.GetTemplateButtonReplyMessage() != nil:
		// Somebody pressed a button. The reply quotes the message it answers
		// through ContextInfo, which applyContext has already picked up.
		env.Type = domain.TypeButtonReply
		env.Content.Body = m.GetTemplateButtonReplyMessage().GetSelectedDisplayText()

	case m.GetPlaceholderMessage() != nil:
		// The phone masked this one from linked devices. There is no content
		// and there never will be; the type is the whole message.
		env.Type = domain.TypePlaceholder

	case m.GetMessageHistoryNotice() != nil, m.GetKeepInChatMessage() != nil:
		// Protocol, not a message: a notice that history exists, or a flag on
		// somebody else's message. Skipped on the way in like key
		// distribution is, so it never becomes a row nobody can render.
		return domain.Envelope{}, ErrSkip

	case m.GetAlbumMessage() != nil:
		env = albumInto(env, m.GetAlbumMessage())

	case m.GetTemplateMessage() != nil:
		env = templateInto(env, m.GetTemplateMessage())

	default:
		// Nothing matched. Two very different reasons, and telling them apart
		// is the difference between an archive with holes and one without.
		field, isContent := unclassified(m)
		if !isContent {
			// Protocol machinery, not a message. Skipping it is what
			// ingest/router.go has always claimed happens to key distribution.
			return domain.Envelope{}, ErrSkip
		}
		env.Type = domain.TypeUnsupported
		env.Content.Unsupported = field
	}

	// A caption on media is the message text. Applying the context afterwards
	// keeps reply, forwarding and expiry working uniformly across every type,
	// rather than being repeated in each branch and forgotten in one.
	return env, nil
}

// inviteInto records an invitation to join a group.
//
// Everything lands in Content, which is sealed, and the invite code is the
// reason to be careful about that rather than merely consistent. The code is a
// capability — whoever holds it can join the group without the sender being
// consulted again — so a readable column would hand a database dump the ability
// to walk into every group this account was ever invited to.
//
// The caption becomes the body, like a media caption does, so a conversation
// preview says whatever the sender wrote rather than naming a message type.
func inviteInto(env domain.Envelope, in *waE2E.GroupInviteMessage) domain.Envelope {
	env.Type = domain.TypeGroupInvite
	env.Content.Body = in.GetCaption()
	env.Content.GroupInvite = &domain.GroupInvite{
		GroupJID:   in.GetGroupJID(),
		Code:       in.GetInviteCode(),
		Expiration: in.GetInviteExpiration(),
		Name:       in.GetGroupName(),
		Caption:    in.GetCaption(),
		Thumbnail:  in.GetJPEGThumbnail(),
	}
	return env
}

// albumInto records the header WhatsApp sends before a run of photographs.
//
// A header and nothing else: it declares how many pictures and videos follow
// and carries none of them. The images arrive as ordinary messages of their
// own, and nothing in the protobuf links a child back to this one — so what is
// recorded is what the message says, and the client draws "álbum com N fotos"
// rather than a grid it would have had to guess the contents of.
func albumInto(env domain.Envelope, a *waE2E.AlbumMessage) domain.Envelope {
	env.Type = domain.TypeAlbum
	env.Content.Album = &domain.Album{
		Images: int(a.GetExpectedImageCount()),
		Videos: int(a.GetExpectedVideoCount()),
	}
	return env
}

// templateInto keeps what a business template actually said.
//
// It was the largest remaining kind filed as unsupported. Only the hydrated
// form carries text a person wrote — the unhydrated one is a template id and
// parameters, which say nothing without the template — so an unhydrated
// message keeps the type and has no body, which is the honest rendering of a
// message whose content is somewhere this archive cannot reach.
//
// The buttons are content: they are labels somebody wrote, and a message
// offering "Confirmar" and "Cancelar" reads very differently without them.
func templateInto(env domain.Envelope, t *waE2E.TemplateMessage) domain.Envelope {
	env.Type = domain.TypeTemplate
	h := t.GetHydratedTemplate()
	if h == nil {
		return env
	}
	env.Content.Body = h.GetHydratedContentText()
	if title := h.GetHydratedTitleText(); title != "" {
		if env.Content.Body == "" {
			env.Content.Body = title
		} else {
			env.Content.Body = title + "\n\n" + env.Content.Body
		}
	}
	if footer := h.GetHydratedFooterText(); footer != "" {
		env.Content.Body += "\n\n" + footer
	}
	for _, b := range h.GetHydratedButtons() {
		switch {
		case b.GetQuickReplyButton() != nil:
			env.Content.Buttons = append(env.Content.Buttons, b.GetQuickReplyButton().GetDisplayText())
		case b.GetUrlButton() != nil:
			env.Content.Buttons = append(env.Content.Buttons, b.GetUrlButton().GetDisplayText())
		case b.GetCallButton() != nil:
			env.Content.Buttons = append(env.Content.Buttons, b.GetCallButton().GetDisplayText())
		}
	}
	return env
}

func videoInto(env domain.Envelope, v *waE2E.VideoMessage, typ domain.Type) domain.Envelope {
	env.Type = typ
	if typ == domain.TypeVideo {
		env.Content.Body = v.GetCaption()
	}
	env.Content.Media = &domain.Media{
		MimeType:      v.GetMimetype(),
		FileLength:    v.GetFileLength(),
		FileSHA256:    v.GetFileSHA256(),
		FileEncSHA256: v.GetFileEncSHA256(),
		DirectPath:    v.GetDirectPath(),
		URL:           v.GetURL(),
		MediaKey:      v.GetMediaKey(),
		Width:         v.GetWidth(),
		Height:        v.GetHeight(),
		Seconds:       v.GetSeconds(),
		Sidecar:       v.GetStreamingSidecar(),
		Thumbnail:     v.GetJPEGThumbnail(),
		IsGIF:         v.GetGifPlayback(),
	}
	env.ViewOnce = env.ViewOnce || v.GetViewOnce()
	return env
}

// previewOf extracts the link card a sender's client built.
//
// Nothing here fetches anything. Every field was produced by the sender and
// arrived inside the message; this server resolving a URL to build its own
// preview would mean it knows which links pass through it, and would let a
// stranger's message steer it into issuing requests to addresses of their
// choosing.
func previewOf(ext *waE2E.ExtendedTextMessage) *domain.LinkPreview {
	if ext.GetMatchedText() == "" {
		return nil
	}
	return &domain.LinkPreview{
		URL:         ext.GetMatchedText(),
		Title:       ext.GetTitle(),
		Description: ext.GetDescription(),
		Thumbnail:   ext.GetJPEGThumbnail(),
	}
}

// eventInto captures a scheduled event.
//
// The whole thing, not just the name. Keeping only the title was enough to
// classify the message and useless to anybody reading it later: an event
// without its date, place or join link is a row that says something happened
// and refuses to say what.
func eventInto(env domain.Envelope, ev *waE2E.EventMessage) domain.Envelope {
	env.Type = domain.TypeEvent
	env.Content.Body = ev.GetName()

	out := &domain.Event{
		Name:               ev.GetName(),
		Description:        ev.GetDescription(),
		JoinLink:           ev.GetJoinLink(),
		IsCanceled:         ev.GetIsCanceled(),
		ExtraGuestsAllowed: ev.GetExtraGuestsAllowed(),
	}
	// Event times are signed seconds off the wire, and go through the same
	// plausibility bound as every other timestamp: a value that wraps when
	// narrowed would sort an event to the beginning of recorded time.
	if t := ev.GetStartTime(); t > 0 {
		out.StartTime = unixSeconds(uint64(t))
	}
	if t := ev.GetEndTime(); t > 0 {
		out.EndTime = unixSeconds(uint64(t))
	}
	if loc := ev.GetLocation(); loc != nil {
		out.Location = &domain.Location{
			Latitude:  loc.GetDegreesLatitude(),
			Longitude: loc.GetDegreesLongitude(),
			Name:      loc.GetName(),
			Address:   loc.GetAddress(),
		}
	}
	env.Content.Event = out
	return env
}

func pollInto(env domain.Envelope, p *waE2E.PollCreationMessage) domain.Envelope {
	env.Type = domain.TypePoll
	poll := &domain.Poll{
		Question:        p.GetName(),
		SelectableCount: p.GetSelectableOptionsCount(),
	}
	for _, opt := range p.GetOptions() {
		poll.Options = append(poll.Options, opt.GetOptionName())
	}
	env.Content.Poll = poll
	env.Content.Body = poll.Question
	return env
}

// contextInfoOf finds the ContextInfo wherever this message type keeps it.
//
// There is no common accessor: every content type declares its own field. This
// is the single place that knows the list, so reply, forwarding and expiry work
// uniformly instead of being wired up per type and missed on one.
func contextInfoOf(m *waE2E.Message) *waE2E.ContextInfo {
	switch {
	case m == nil:
		return nil
	case m.GetExtendedTextMessage() != nil:
		return m.GetExtendedTextMessage().GetContextInfo()
	case m.GetImageMessage() != nil:
		return m.GetImageMessage().GetContextInfo()
	case m.GetVideoMessage() != nil:
		return m.GetVideoMessage().GetContextInfo()
	case m.GetPtvMessage() != nil:
		return m.GetPtvMessage().GetContextInfo()
	case m.GetAudioMessage() != nil:
		return m.GetAudioMessage().GetContextInfo()
	case m.GetDocumentMessage() != nil:
		return m.GetDocumentMessage().GetContextInfo()
	case m.GetStickerMessage() != nil:
		return m.GetStickerMessage().GetContextInfo()
	case m.GetLocationMessage() != nil:
		return m.GetLocationMessage().GetContextInfo()
	case m.GetLiveLocationMessage() != nil:
		return m.GetLiveLocationMessage().GetContextInfo()
	case m.GetContactMessage() != nil:
		return m.GetContactMessage().GetContextInfo()
	case m.GetContactsArrayMessage() != nil:
		return m.GetContactsArrayMessage().GetContextInfo()
	case m.GetPollCreationMessage() != nil:
		return m.GetPollCreationMessage().GetContextInfo()
	case m.GetEventMessage() != nil:
		return m.GetEventMessage().GetContextInfo()
	case m.GetGroupInviteMessage() != nil:
		return m.GetGroupInviteMessage().GetContextInfo()
	case m.GetInteractiveMessage() != nil:
		return m.GetInteractiveMessage().GetContextInfo()
	case m.GetButtonsMessage() != nil:
		return m.GetButtonsMessage().GetContextInfo()
	case m.GetListMessage() != nil:
		return m.GetListMessage().GetContextInfo()
	case m.GetTemplateButtonReplyMessage() != nil:
		return m.GetTemplateButtonReplyMessage().GetContextInfo()
	case m.GetAlbumMessage() != nil:
		return m.GetAlbumMessage().GetContextInfo()
	case m.GetTemplateMessage() != nil:
		return m.GetTemplateMessage().GetContextInfo()
	default:
		// Conversation is a bare string with nowhere to put context, which is
		// exactly why outbound text always goes as ExtendedTextMessage: a
		// forwarded or quoted plain string is not expressible.
		return nil
	}
}

// textOf extracts the text from a message, for edits.
func textOf(m *waE2E.Message) string {
	if m == nil {
		return ""
	}
	if s := m.GetConversation(); s != "" {
		return s
	}
	if ext := m.GetExtendedTextMessage(); ext != nil {
		return ext.GetText()
	}
	// Editing a caption is possible, so fall back to the media caption.
	if img := m.GetImageMessage(); img != nil {
		return img.GetCaption()
	}
	if vid := m.GetVideoMessage(); vid != nil {
		return vid.GetCaption()
	}
	if doc := m.GetDocumentMessage(); doc != nil {
		return doc.GetCaption()
	}
	return ""
}

// marshalRaw serialises the original protobuf for the archive.
//
// Sealed like everything else in Content. It is the only way to recover a
// message whose type this build did not understand, which makes it worth the
// storage; it is also the most sensitive single field, since it contains the
// whole message including parts the code never surfaces.
func marshalRaw(m *waE2E.Message) []byte {
	if m == nil {
		return nil
	}
	b, err := proto.Marshal(m)
	if err != nil {
		// Nothing actionable: the message is still stored, just without the
		// raw copy. Losing the fallback is better than losing the row.
		return nil
	}
	return b
}

// stack joins the pieces of a business message into one body, in order,
// dropping the ones that are empty. Title, content and footer are three
// fields and one message; a classifier that kept only the content would
// archive the offer without the price.
func stack(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "\n\n")
}

// interactiveInto reads the current business format: a native flow with
// buttons, or a carousel of cards that are each an interactive message of
// their own.
//
// The header may carry an attachment. It is not extracted here — the same
// limit templateInto has — and is named so the omission is a known one rather
// than a surprise: a reader sees the text and the labels, and a picture in the
// header is not yet in the archive.
func interactiveInto(env domain.Envelope, im *waE2E.InteractiveMessage) domain.Envelope {
	env.Type = domain.TypeInteractive
	body, buttons := interactiveText(im)
	env.Content.Body = body
	env.Content.Buttons = buttons
	return env
}

func interactiveText(im *waE2E.InteractiveMessage) (string, []string) {
	h := im.GetHeader()
	body := stack(h.GetTitle(), h.GetSubtitle(), im.GetBody().GetText(), im.GetFooter().GetText())
	var buttons []string
	for _, b := range im.GetNativeFlowMessage().GetButtons() {
		buttons = append(buttons, nativeFlowLabel(b))
	}
	if cards := im.GetCarouselMessage().GetCards(); len(cards) > 0 {
		lines := []string{fmt.Sprintf("Carrossel com %d cartões", len(cards))}
		for i, card := range cards {
			text, more := interactiveText(card)
			lines = append(lines, fmt.Sprintf("%d. %s", i+1, strings.ReplaceAll(text, "\n\n", " — ")))
			buttons = append(buttons, more...)
		}
		body = stack(body, strings.Join(lines, "\n"))
	}
	return body, buttons
}

// nativeFlowLabel is what a native-flow button says. The label lives inside a
// JSON blob as display_text; the button's name is a kind ("quick_reply",
// "cta_url") and is the fallback when the blob does not say.
func nativeFlowLabel(b *waE2E.InteractiveMessage_NativeFlowMessage_NativeFlowButton) string {
	var params struct {
		DisplayText string `json:"display_text"`
	}
	if err := json.Unmarshal([]byte(b.GetButtonParamsJSON()), &params); err == nil && params.DisplayText != "" {
		return params.DisplayText
	}
	return b.GetName()
}

// buttonsInto reads the older buttons format.
func buttonsInto(env domain.Envelope, bm *waE2E.ButtonsMessage) domain.Envelope {
	env.Type = domain.TypeButtons
	env.Content.Body = stack(bm.GetText(), bm.GetContentText(), bm.GetFooterText())
	for _, b := range bm.GetButtons() {
		if label := b.GetButtonText().GetDisplayText(); label != "" {
			env.Content.Buttons = append(env.Content.Buttons, label)
		}
	}
	return env
}

// listInto reads a list of options. The rows are what was offered, so they go
// where button labels go, with their section in front when the list has
// sections — "Horários › Manhã" reads, "Manhã" alone does not.
func listInto(env domain.Envelope, lm *waE2E.ListMessage) domain.Envelope {
	env.Type = domain.TypeList
	env.Content.Body = stack(lm.GetTitle(), lm.GetDescription(), lm.GetFooterText())
	if open := lm.GetButtonText(); open != "" {
		env.Content.Buttons = append(env.Content.Buttons, open)
	}
	for _, sec := range lm.GetSections() {
		for _, row := range sec.GetRows() {
			label := row.GetTitle()
			if d := row.GetDescription(); d != "" {
				label += " — " + d
			}
			if t := sec.GetTitle(); t != "" {
				label = t + " › " + label
			}
			env.Content.Buttons = append(env.Content.Buttons, label)
		}
	}
	return env
}
