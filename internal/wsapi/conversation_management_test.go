package wsapi

import (
	"context"
	"errors"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/types"
	"strings"
	"testing"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
)

func TestNewConversationNumbersAreUnambiguous(t *testing.T) {
	for _, input := range []string{"+55 (11) 99999-9999", "5511999999999"} {
		actual, err := phoneNumber(input)
		if err != nil || actual != "5511999999999" {
			t.Fatalf("%q: %q %v", input, actual, err)
		}
	}
	for _, input := range []string{"", "+123", "005511999999999", "1234567890123456", "call +5511999999999", "5511999999999@g.us", "55+11999999999"} {
		if _, err := phoneNumber(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}
func TestGroupParticipantsRejectNonPeopleAndBoundOperations(t *testing.T) {
	got, err := participantJIDs([]string{"+55 (11) 99999-9999", "5511999999999:2@s.whatsapp.net", "123456@lid"})
	if err != nil || len(got) != 2 || got[1].Server != types.HiddenUserServer {
		t.Fatalf("participants %v %v", got, err)
	}
	for _, values := range [][]string{nil, {"120363123@g.us"}, {"status@broadcast"}, {"@lid"}, {"someone@lid"}, {"123456789012345678901@lid"}, {""}, strings.Fields(strings.Repeat("5511999999999 ", 33))} {
		if _, err := participantJIDs(values); err == nil {
			t.Errorf("accepted invalid participants: %v", values)
		}
	}
}
func TestGroupAuthorityRequiresCurrentOwnIdentity(t *testing.T) {
	pn := types.NewJID("5511999999999", types.DefaultUserServer)
	lid := types.NewJID("12345", types.HiddenUserServer)
	info := &types.GroupInfo{Participants: []types.GroupParticipant{{JID: lid, PhoneNumber: pn, IsAdmin: true}}}
	for _, self := range []wa.Identity{{PN: pn}, {LID: lid}, {LID: lid, PN: pn}} {
		member, admin := groupMembership(info, self)
		if !member || !admin {
			t.Fatal("current administrator not matched across identities")
		}
	}
	member, admin := groupMembership(info, wa.Identity{})
	if member || admin {
		t.Fatal("unknown identity became administrator")
	}
	info.Participants[0].IsAdmin = false
	member, admin = groupMembership(info, wa.Identity{PN: pn})
	if !member || admin {
		t.Fatal("ordinary member became administrator")
	}
}
func TestNewCommandsUseRequiredDevicePermissions(t *testing.T) {
	for _, frame := range []string{TypeChatStart, TypePollCreate, TypeLocationSend} {
		if frameAction(frame) != store.ActionSend {
			t.Errorf("%s must require send", frame)
		}
	}
	for _, frame := range []string{TypeGroupCreate, TypeGroupParticipants, TypeGroupLeave} {
		if frameAction(frame) != store.ActionManage {
			t.Errorf("%s must require manage", frame)
		}
	}
}
func TestParticipantFailuresAreNotHidden(t *testing.T) {
	out := participantResults([]types.GroupParticipant{{JID: types.NewJID("1234567", types.DefaultUserServer), Error: 403}})
	if len(out) != 1 || out[0].Error != 403 {
		t.Fatalf("lost refusal: %+v", out)
	}
}

func TestCreatedGroupReportsPartialAdditionsWithoutInventingMembers(t *testing.T) {
	fake := fakewa.New()
	calls := 0
	joined := types.NewJID("5511999999999", types.DefaultUserServer)
	refused := types.NewJID("5511888888888", types.DefaultUserServer)
	group := types.NewJID("120363123", types.GroupServer)
	fake.CreateGroupFunc = func(req whatsmeow.ReqCreateGroup) (*types.GroupInfo, error) {
		calls++
		if req.Name != "Support" || len(req.Participants) != 2 {
			t.Fatal("wrong group request")
		}
		return &types.GroupInfo{JID: group, Participants: []types.GroupParticipant{{JID: joined}, {JID: refused, Error: 403}}}, nil
	}
	result, snapshot, err := createGroupOnWhatsApp(context.Background(), fake, "Support", []types.JID{joined, refused})
	if err != nil || calls != 1 || result.Chat != group.String() || result.Refreshed || len(result.Participants) != 2 || result.Participants[1].Error != 403 {
		t.Fatalf("result: %+v %v", result, err)
	}
	if len(snapshot.Participants) != 1 || snapshot.Participants[0].JID != joined {
		t.Fatalf("invented membership: %+v", snapshot)
	}
	fake.CreateGroupFunc = func(whatsmeow.ReqCreateGroup) (*types.GroupInfo, error) {
		calls++
		return nil, errors.New("connection lost")
	}
	_, _, err = createGroupOnWhatsApp(context.Background(), fake, "Support", []types.JID{joined, refused})
	if err == nil || calls != 2 {
		t.Fatal("ambiguous creation retried or hidden")
	}
}
