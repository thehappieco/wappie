package normalize_test

import (
	"bytes"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/domain"
	"whatserver2/internal/wa/normalize"
)

// An invitation to a group is content, and the code inside it is a capability.
//
// It arrived as type='unsupported' with the field name groupInviteMessage,
// which is the archive saying honestly that it did not know what it had. What
// makes this one worth more than a label is the code: whoever holds it can walk
// into the group without the sender being consulted again. Storing it in a
// readable column would put "join every group these users were invited to" in a
// database dump, next to the group's name and the face of whoever runs it.
//
// So the whole thing lands in Content, which is sealed — and that decides where
// accepting can happen. This server cannot read the code it stored, so it
// cannot act on an invitation by itself.

func TestAGroupInvitationIsRecognisedAndSealed(t *testing.T) {
	expires := time.Now().Add(72 * time.Hour).Unix()
	env := live(t, &waE2E.Message{
		GroupInviteMessage: &waE2E.GroupInviteMessage{
			GroupJID:         proto.String("120363429965256963@g.us"),
			InviteCode:       proto.String("SEGREDO123"),
			InviteExpiration: proto.Int64(expires),
			GroupName:        proto.String("Churrasco de sábado"),
			Caption:          proto.String("bora?"),
			JPEGThumbnail:    []byte{0xff, 0xd8, 0xff},
		},
	})

	if env.Type != domain.TypeGroupInvite {
		t.Fatalf("type = %q, want %q — it was landing in 'unsupported'",
			env.Type, domain.TypeGroupInvite)
	}
	inv := env.Content.GroupInvite
	if inv == nil {
		t.Fatal("the invitation was classified and then not kept")
	}
	if inv.Code != "SEGREDO123" {
		t.Errorf("code = %q", inv.Code)
	}
	if inv.GroupJID != "120363429965256963@g.us" || inv.Name != "Churrasco de sábado" {
		t.Errorf("group = %q %q", inv.GroupJID, inv.Name)
	}
	if inv.Expiration != expires {
		t.Errorf("expiration = %d, want %d", inv.Expiration, expires)
	}
	if len(inv.Thumbnail) != 3 {
		t.Errorf("thumbnail lost: %d bytes", len(inv.Thumbnail))
	}

	// The caption is the body, so a chat-list preview shows what the sender
	// wrote rather than the name of a message type.
	if env.Content.Body != "bora?" {
		t.Errorf("body = %q, want the caption", env.Content.Body)
	}

	// Everything above rides in Content, which is what gets sealed. A field
	// added to the readable half of the envelope would not fail any of the
	// assertions above and would leak the capability.
	if env.Content.GroupInvite.Code == "" {
		t.Error("the code is not in the sealed half")
	}
}

// A reply or an expiry on an invitation must survive, like on any other type.
//
// contextInfoOf is a switch with one case per message type, and a type missing
// from it silently loses its reply link, its forwarding flag and its
// disappearing timer — the message renders, just stripped.
func TestAnInvitationKeepsItsContext(t *testing.T) {
	env := live(t, &waE2E.Message{
		GroupInviteMessage: &waE2E.GroupInviteMessage{
			GroupJID:   proto.String("120363429965256963@g.us"),
			InviteCode: proto.String("X"),
			ContextInfo: &waE2E.ContextInfo{
				StanzaID:    proto.String("PAI1"),
				IsForwarded: proto.Bool(true),
				Expiration:  proto.Uint32(86400),
			},
		},
	})
	if env.ReplyTo != "PAI1" {
		t.Errorf("reply_to = %q, want PAI1", env.ReplyTo)
	}
	if !env.IsForwarded {
		t.Error("the forwarded flag was dropped")
	}
	if env.Expiration != 86400 {
		t.Errorf("expiration = %d, want 86400", env.Expiration)
	}
}

// TestReprojectionAgreesWithIngest.
//
// A message filed as unsupported keeps the protobuf that produced it, so a
// later build can look again. What makes that trustworthy is that it looks with
// the SAME classifier: FromRaw and FromLive are two doors into one
// implementation. If they could disagree, a reprojection would leave the archive
// holding two kinds of row for one kind of message, with only the date to say
// which door produced which — and no way to tell, later, which was right.
//
// Checked on a type that WAS unsupported until this build, because that is
// exactly the population a reprojection walks.
func TestReprojectionAgreesWithIngest(t *testing.T) {
	msg := &waE2E.Message{
		GroupInviteMessage: &waE2E.GroupInviteMessage{
			GroupJID:         proto.String("120363429965256963@g.us"),
			InviteCode:       proto.String("SEGREDO123"),
			InviteExpiration: proto.Int64(1_800_000_000),
			GroupName:        proto.String("Churrasco de sábado"),
			Caption:          proto.String("bora?"),
		},
	}

	// Through the live door, as it would arrive.
	fresh := live(t, msg)

	// And through the reprojection door, from the stored protobuf. The routing
	// columns are readable precisely so this info can be rebuilt.
	stored, err := normalize.FromRaw(types.MessageInfo{
		ID: "ID1",
		MessageSource: types.MessageSource{
			Chat:   types.JID{User: "5511999999999", Server: types.DefaultUserServer},
			Sender: types.JID{User: "5511999999999", Server: types.DefaultUserServer},
		},
	}, msg, normalize.Options{TenantID: "t"})
	if err != nil {
		t.Fatalf("FromRaw: %v", err)
	}

	if stored.Type != fresh.Type {
		t.Errorf("type: reprojected %q, ingested %q", stored.Type, fresh.Type)
	}
	if stored.Content.Body != fresh.Content.Body {
		t.Errorf("body: reprojected %q, ingested %q", stored.Content.Body, fresh.Content.Body)
	}
	a, b := stored.Content.GroupInvite, fresh.Content.GroupInvite
	if a == nil || b == nil {
		t.Fatalf("invite: reprojected %v, ingested %v", a, b)
	}
	if a.GroupJID != b.GroupJID || a.Code != b.Code || a.Expiration != b.Expiration ||
		a.Name != b.Name || a.Caption != b.Caption || !bytes.Equal(a.Thumbnail, b.Thumbnail) {
		t.Errorf("invite differs:\n  reprojected %+v\n  ingested    %+v", *a, *b)
	}
}

// A protobuf that still means nothing must come back as unsupported, not as an
// error and not as something else.
//
// It is the common case: a run walks a thousand rows and most of them are types
// this build still does not know. Reporting them as failures would bury the
// handful that did convert, and rewriting them as anything would lose the field
// name that says what to implement next.
func TestSomethingStillUnknownStaysUnsupported(t *testing.T) {
	// A payment invitation: real, and nothing here reads it. Templates and
	// albums used to stand in for "unknown" and now classify, which is the
	// point of reprojection — so this test has to keep moving to a type that
	// genuinely is not implemented, or it stops testing anything.
	env, err := normalize.FromRaw(types.MessageInfo{ID: "ID2"},
		&waE2E.Message{PaymentInviteMessage: &waE2E.PaymentInviteMessage{}},
		normalize.Options{TenantID: "t"})
	if err != nil {
		t.Fatalf("FromRaw: %v", err)
	}
	if env.Type != domain.TypeUnsupported {
		t.Errorf("type = %q, want unsupported", env.Type)
	}
	if env.Content.Unsupported != "paymentInviteMessage" {
		t.Errorf("unsupported field = %q, want it named so somebody can decide "+
			"what to implement next", env.Content.Unsupported)
	}
}
