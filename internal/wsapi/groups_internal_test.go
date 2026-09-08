package wsapi

import (
	"testing"
	"time"

	"go.mau.fi/whatsmeow/types"
)

// Every gate on accepting a group invitation, because every one of them stands
// between a frame and an outward-facing act.
//
// What is on the other side is JoinGroupWithInvite: this account becomes a
// member, everyone already in the group sees it happen, and nothing on this
// side undoes it. A gate that silently stopped working would not fail a build
// or a request — it would join a group.
func TestAcceptingAnInvitationIsGated(t *testing.T) {
	group := types.JID{User: "120363429965256963", Server: types.GroupServer}
	person := types.JID{User: "5511999999999", Server: types.DefaultUserServer}
	now := time.Unix(1_800_000_000, 0)

	ok := GroupJoinRequest{
		GroupJID: group.String(), Inviter: person.String(),
		Code: "SEGREDO", Expiration: now.Add(time.Hour).Unix(),
	}

	if _, _, reason := checkJoin(ok, group, now); reason != "" {
		t.Fatalf("a good invitation was refused: %s", reason)
	}

	for _, c := range []struct {
		name string
		req  GroupJoinRequest
		chat types.JID
		want string
	}{
		{
			// Without it there is nothing to join with, and the request would
			// reach WhatsApp as a malformed stanza rather than a refusal.
			name: "sem código",
			req:  GroupJoinRequest{GroupJID: group.String(), Inviter: person.String()},
			chat: group,
			want: ErrCodeBadRequest,
		},
		{
			// The sharp one. Nothing else checks that the target is a group,
			// so a caller naming a person here would have this server issue a
			// group-join stanza against a direct chat.
			name: "alvo não é grupo",
			req:  GroupJoinRequest{GroupJID: person.String(), Inviter: person.String(), Code: "X"},
			chat: person,
			want: ErrCodeBadRequest,
		},
		{
			// WhatsApp validates the code against the pair, so a missing
			// inviter is a refusal rather than something to guess at.
			name: "sem quem convidou",
			req:  GroupJoinRequest{GroupJID: group.String(), Code: "X"},
			chat: group,
			want: ErrCodeBadRequest,
		},
		{
			name: "quem convidou não é JID",
			req:  GroupJoinRequest{GroupJID: group.String(), Inviter: "fulano", Code: "X"},
			chat: group,
			want: ErrCodeBadRequest,
		},
		{
			// A stale code is refused here so the answer names something the
			// person can act on. WhatsApp would reject it too, a round trip
			// later, with nothing useful to show.
			name: "convite expirado",
			req: GroupJoinRequest{
				GroupJID: group.String(), Inviter: person.String(), Code: "X",
				Expiration: now.Add(-time.Second).Unix(),
			},
			chat: group,
			want: ErrCodeConflict,
		},
	} {
		_, code, reason := checkJoin(c.req, c.chat, now)
		if reason == "" {
			t.Errorf("%s: aceito, deveria recusar", c.name)
			continue
		}
		if code != c.want {
			t.Errorf("%s: código %q, queria %q", c.name, code, c.want)
		}
	}
}

// The inviter is keyed like a person, not like one of their phones.
//
// A sender key taken off a message can carry a device suffix, and WhatsApp
// validates the invitation against the person who sent it. The same missing
// ToNonAD produced a lookup matching no contact and no chat once already.
func TestTheInviterIsAPersonNotADevice(t *testing.T) {
	group := types.JID{User: "120363429965256963", Server: types.GroupServer}
	inviter, _, reason := checkJoin(GroupJoinRequest{
		GroupJID: group.String(),
		Inviter:  "5511999999999:12@s.whatsapp.net",
		Code:     "X",
	}, group, time.Unix(1_800_000_000, 0))
	if reason != "" {
		t.Fatalf("refused: %s", reason)
	}
	if inviter.String() != "5511999999999@s.whatsapp.net" {
		t.Errorf("inviter = %q, want the device suffix dropped", inviter)
	}
}

// An invitation with no expiry is allowed through.
//
// The field is optional in the protobuf, and treating absent as "expired at the
// epoch" would refuse every invitation that omits it — a refusal produced by a
// zero value, which is the kind of bug that reads as WhatsApp being broken.
func TestAnInvitationWithNoExpiryIsNotTreatedAsExpired(t *testing.T) {
	group := types.JID{User: "120363429965256963", Server: types.GroupServer}
	if _, _, reason := checkJoin(GroupJoinRequest{
		GroupJID: group.String(),
		Inviter:  "5511999999999@s.whatsapp.net",
		Code:     "X",
	}, group, time.Now()); reason != "" {
		t.Errorf("an invitation with no stated expiry was refused: %s", reason)
	}
}
