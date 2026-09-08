package normalize_test

import (
	"errors"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"testing"

	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/domain"
	"whatserver2/internal/wa/normalize"
)

// Three types that used to reach the archive as "tipo não suportado" — 34
// templates and 13 albums in one real archive, plus every poll answer ever
// cast. Each one is a message somebody sent and a reader could not read.
//
// The tests below are about what each type is allowed to claim. The failure
// they guard against is not a crash: it is an album inventing pictures it does
// not carry, or a template arriving with an empty body because nobody composed
// its three text fields into one.

func TestAnAlbumSaysWhatItDeclaresAndNothingMore(t *testing.T) {
	env := live(t, &waE2E.Message{AlbumMessage: &waE2E.AlbumMessage{
		ExpectedImageCount: proto.Uint32(3),
		ExpectedVideoCount: proto.Uint32(1),
	}})

	if env.Type != domain.TypeAlbum {
		t.Fatalf("type = %q, want album", env.Type)
	}
	if env.Content.Album == nil {
		t.Fatal("the counts were dropped, leaving an album that declares nothing")
	}
	if env.Content.Album.Images != 3 || env.Content.Album.Videos != 1 {
		t.Errorf("declared %d images and %d videos, want 3 and 1",
			env.Content.Album.Images, env.Content.Album.Videos)
	}
	// A header carries no attachment. Inventing one would send the media
	// fetcher after a file that does not exist, on every album ever archived.
	if env.Content.Media != nil {
		t.Error("the album claims to carry an attachment; it is a header and carries none")
	}
}

func TestATemplateComposesItsThreeTextsIntoOneBody(t *testing.T) {
	// Title, content and footer are three fields and one message. A classifier
	// that took only the content would archive the offer without the price, or
	// the price without the offer, depending on where the sender put it.
	env := live(t, &waE2E.Message{TemplateMessage: &waE2E.TemplateMessage{
		HydratedTemplate: &waE2E.TemplateMessage_HydratedFourRowTemplate{
			Title: &waE2E.TemplateMessage_HydratedFourRowTemplate_HydratedTitleText{
				HydratedTitleText: "Sua fatura",
			},
			HydratedContentText: proto.String("Vence sexta."),
			HydratedFooterText:  proto.String("Banco Exemplo"),
			HydratedButtons: []*waE2E.HydratedTemplateButton{
				{HydratedButton: &waE2E.HydratedTemplateButton_QuickReplyButton{
					QuickReplyButton: &waE2E.HydratedTemplateButton_HydratedQuickReplyButton{
						DisplayText: proto.String("Pagar agora"),
					},
				}},
				{HydratedButton: &waE2E.HydratedTemplateButton_UrlButton{
					UrlButton: &waE2E.HydratedTemplateButton_HydratedURLButton{
						DisplayText: proto.String("Ver fatura"),
						URL:         proto.String("https://exemplo.invalid/f/1"),
					},
				}},
			},
		},
	}})

	if env.Type != domain.TypeTemplate {
		t.Fatalf("type = %q, want template", env.Type)
	}
	for _, want := range []string{"Sua fatura", "Vence sexta.", "Banco Exemplo"} {
		if !contains(env.Content.Body, want) {
			t.Errorf("body = %q, missing %q", env.Content.Body, want)
		}
	}
	if len(env.Content.Buttons) != 2 {
		t.Fatalf("kept %d button labels, want 2: %q", len(env.Content.Buttons), env.Content.Buttons)
	}
}

func TestAnUnhydratedTemplateKeepsItsTypeAndSaysNothing(t *testing.T) {
	// The text lives somewhere this archive cannot reach. Filing it as
	// unsupported would send somebody looking for a classifier to write; it is
	// a template, and its content is simply not here.
	env := live(t, &waE2E.Message{TemplateMessage: &waE2E.TemplateMessage{}})

	if env.Type != domain.TypeTemplate {
		t.Fatalf("type = %q, want template", env.Type)
	}
	if env.Content.Body != "" {
		t.Errorf("body = %q, want nothing — there was nothing to compose", env.Content.Body)
	}
}

func TestAPollVoteNamesThePollEvenWhenNobodyCouldOpenIt(t *testing.T) {
	env := live(t, &waE2E.Message{PollUpdateMessage: &waE2E.PollUpdateMessage{
		PollCreationMessageKey: &waCommon.MessageKey{ID: proto.String("POLL-1")},
		Vote:                   &waE2E.PollEncValue{EncPayload: []byte{1}},
	}})

	if env.Type != domain.TypePollVote {
		t.Fatalf("type = %q, want poll_vote", env.Type)
	}
	if env.TargetID != "POLL-1" {
		t.Errorf("target = %q, want the poll being answered", env.TargetID)
	}
	// No selection: nothing opened it. The absence is the record, and a client
	// has to be able to tell it from a withdrawal.
	if env.Content.PollVote != nil {
		t.Error("a vote nobody opened arrived claiming to know what was chosen")
	}
}

func TestAnOpenedVoteCarriesWhatWasChosen(t *testing.T) {
	env := liveWith(t, &waE2E.Message{PollUpdateMessage: &waE2E.PollUpdateMessage{
		PollCreationMessageKey: &waCommon.MessageKey{ID: proto.String("POLL-2")},
		Vote:                   &waE2E.PollEncValue{EncPayload: []byte{1}},
	}}, &normalize.OpenedVote{Selected: [][]byte{[]byte("hash-of-sexta")}})

	if env.Content.PollVote == nil {
		t.Fatal("the selection was dropped between the device and the archive")
	}
	if len(env.Content.PollVote.Selected) != 1 {
		t.Fatalf("selected %d options, want 1", len(env.Content.PollVote.Selected))
	}
}

func TestAWithdrawnVoteIsRecordedAsOpenedAndEmpty(t *testing.T) {
	// Empty, but present. A reader has to tell "changed their mind" from "this
	// archive could not read it": the first is an answer taken back, the
	// second is an answer missed.
	env := liveWith(t, &waE2E.Message{PollUpdateMessage: &waE2E.PollUpdateMessage{
		PollCreationMessageKey: &waCommon.MessageKey{ID: proto.String("POLL-3")},
		Vote:                   &waE2E.PollEncValue{EncPayload: []byte{1}},
	}}, &normalize.OpenedVote{})

	if env.Content.PollVote == nil {
		t.Fatal("a withdrawal was recorded as a vote nobody could open")
	}
	if len(env.Content.PollVote.Selected) != 0 {
		t.Errorf("selected %v, want nothing", env.Content.PollVote.Selected)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// The business formats, and the two that are not messages at all.
//
// Every one of these used to land as unsupported, a few every day, for as long
// as the account talked to any business — the ongoing trickle behind a
// reprojection list that never emptied. They all open to the same shape: some
// text, and the labels of what was offered.

func TestAnInteractiveMessageKeepsItsTextAndItsButtonLabels(t *testing.T) {
	env := live(t, &waE2E.Message{InteractiveMessage: &waE2E.InteractiveMessage{
		Header: &waE2E.InteractiveMessage_Header{Title: proto.String("Sua fatura")},
		Body:   &waE2E.InteractiveMessage_Body{Text: proto.String("Vence sexta.")},
		Footer: &waE2E.InteractiveMessage_Footer{Text: proto.String("Banco Exemplo")},
		InteractiveMessage: &waE2E.InteractiveMessage_NativeFlowMessage_{
			NativeFlowMessage: &waE2E.InteractiveMessage_NativeFlowMessage{
				Buttons: []*waE2E.InteractiveMessage_NativeFlowMessage_NativeFlowButton{
					// The label lives inside a JSON blob; the name is a kind.
					{Name: proto.String("cta_url"),
						ButtonParamsJSON: proto.String(`{"display_text":"Ver fatura","url":"https://x.invalid"}`)},
					{Name: proto.String("quick_reply"), ButtonParamsJSON: proto.String(`not json`)},
				},
			},
		},
	}})
	if env.Type != domain.TypeInteractive {
		t.Fatalf("type = %q, want interactive", env.Type)
	}
	for _, want := range []string{"Sua fatura", "Vence sexta.", "Banco Exemplo"} {
		if !contains(env.Content.Body, want) {
			t.Errorf("body = %q, missing %q", env.Content.Body, want)
		}
	}
	if len(env.Content.Buttons) != 2 || env.Content.Buttons[0] != "Ver fatura" || env.Content.Buttons[1] != "quick_reply" {
		t.Errorf("buttons = %q; want the JSON label, then the kind as fallback", env.Content.Buttons)
	}
}

func TestAButtonsMessageKeepsItsLabels(t *testing.T) {
	env := live(t, &waE2E.Message{ButtonsMessage: &waE2E.ButtonsMessage{
		ContentText: proto.String("Confirma o horário?"),
		FooterText:  proto.String("Clínica"),
		Buttons: []*waE2E.ButtonsMessage_Button{
			{ButtonText: &waE2E.ButtonsMessage_Button_ButtonText{DisplayText: proto.String("Sim")}},
			{ButtonText: &waE2E.ButtonsMessage_Button_ButtonText{DisplayText: proto.String("Remarcar")}},
		},
	}})
	if env.Type != domain.TypeButtons {
		t.Fatalf("type = %q, want buttons", env.Type)
	}
	if !contains(env.Content.Body, "Confirma o horário?") || !contains(env.Content.Body, "Clínica") {
		t.Errorf("body = %q", env.Content.Body)
	}
	if len(env.Content.Buttons) != 2 {
		t.Fatalf("buttons = %q, want 2", env.Content.Buttons)
	}
}

func TestAListMessagePutsItsRowsWhereLabelsGo(t *testing.T) {
	// The rows are what was offered. "Manhã" alone does not read; "Horários ›
	// Manhã" does.
	env := live(t, &waE2E.Message{ListMessage: &waE2E.ListMessage{
		Title:      proto.String("Escolha um horário"),
		ButtonText: proto.String("Ver opções"),
		Sections: []*waE2E.ListMessage_Section{{
			Title: proto.String("Horários"),
			Rows: []*waE2E.ListMessage_Row{
				{Title: proto.String("Manhã"), Description: proto.String("9h às 12h")},
				{Title: proto.String("Tarde")},
			},
		}},
	}})
	if env.Type != domain.TypeList {
		t.Fatalf("type = %q, want list", env.Type)
	}
	want := []string{"Ver opções", "Horários › Manhã — 9h às 12h", "Horários › Tarde"}
	if len(env.Content.Buttons) != len(want) {
		t.Fatalf("buttons = %q, want %q", env.Content.Buttons, want)
	}
	for i := range want {
		if env.Content.Buttons[i] != want[i] {
			t.Errorf("button %d = %q, want %q", i, env.Content.Buttons[i], want[i])
		}
	}
}

func TestPressingAButtonIsARepliedLabel(t *testing.T) {
	env := live(t, &waE2E.Message{TemplateButtonReplyMessage: &waE2E.TemplateButtonReplyMessage{
		SelectedDisplayText: proto.String("Pagar agora"),
	}})
	if env.Type != domain.TypeButtonReply || env.Content.Body != "Pagar agora" {
		t.Fatalf("type = %q body = %q, want button_reply / the label", env.Type, env.Content.Body)
	}
}

func TestAMaskedMessageIsAPlaceholderNotUnsupported(t *testing.T) {
	// The phone kept this one from linked devices. There is nothing a later
	// build could do about it, so filing it as unsupported would put it in a
	// list of work forever.
	env := live(t, &waE2E.Message{PlaceholderMessage: &waE2E.PlaceholderMessage{
		Type: waE2E.PlaceholderMessage_MASK_LINKED_DEVICES.Enum(),
	}})
	if env.Type != domain.TypePlaceholder {
		t.Fatalf("type = %q, want placeholder", env.Type)
	}
	if env.Content.Unsupported != "" {
		t.Errorf("unsupported field = %q, want none — this is a known thing", env.Content.Unsupported)
	}
}

func TestAHistoryNoticeIsNotARow(t *testing.T) {
	// Protocol. Stored by an older build as unsupported; skipped now, like
	// key distribution is, so it never becomes a row nobody can render.
	for name, msg := range map[string]*waE2E.Message{
		"historyNotice": {MessageHistoryNotice: &waE2E.MessageHistoryNotice{}},
		"keepInChat":    {KeepInChatMessage: &waE2E.KeepInChatMessage{}},
	} {
		evt := &events.Message{RawMessage: msg, Info: types.MessageInfo{
			MessageSource: types.MessageSource{Chat: chatJID, Sender: chatJID}, ID: msgID, Timestamp: sentAt,
		}}
		evt.UnwrapRaw()
		if _, err := normalize.FromLive(evt, opts); !errors.Is(err, normalize.ErrSkip) {
			t.Errorf("%s: err = %v, want ErrSkip", name, err)
		}
	}
}
