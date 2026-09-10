package wsapi_test

import (
	"context"
	"testing"
	"time"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

func TestConversationManagementRejectsInsufficientScopes(t *testing.T) {
	c := newConsole(t)
	device := c.deviceWithKey(t, "conversation-permissions")
	readKey, err := c.keys.IssueScoped(context.Background(), c.tenant.String(), "read-only", store.ScopeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	sendKey, err := c.keys.IssueScoped(context.Background(), c.tenant.String(), "send-only", store.ScopeSend, nil)
	if err != nil {
		t.Fatal(err)
	}
	lat, lon := 0.0, 0.0
	cases := []struct {
		frame   string
		payload any
		key     string
	}{
		{wsapi.TypeChatStart, wsapi.ChatStartRequest{DeviceID: device, Phone: "5511999999999"}, readKey},
		{wsapi.TypeLocationSend, wsapi.LocationSendRequest{DeviceID: device, Chat: "5511999999999@s.whatsapp.net", Latitude: &lat, Longitude: &lon}, readKey},
		{wsapi.TypePollCreate, wsapi.PollCreateRequest{DeviceID: device, Chat: "5511999999999@s.whatsapp.net", Question: "Lunch?", Options: []string{"Pizza", "Salad"}}, readKey},
		{wsapi.TypeEventCreate, wsapi.EventCreateRequest{DeviceID: device, Chat: "5511999999999@s.whatsapp.net", Name: "Planning", StartTime: time.Now().Add(time.Hour)}, readKey},
		{wsapi.TypeGroupCreate, wsapi.GroupCreateRequest{DeviceID: device, Name: "QA", Participants: []string{"5511999999999"}}, sendKey},
		{wsapi.TypeGroupParticipants, wsapi.GroupParticipantsRequest{DeviceID: device, Chat: "120363123@g.us", Action: "remove", Participants: []string{"5511999999999"}}, sendKey},
		{wsapi.TypeGroupLeave, wsapi.GroupLeaveRequest{DeviceID: device, Chat: "120363123@g.us"}, sendKey},
	}
	for _, tc := range cases {
		t.Run(tc.frame, func(t *testing.T) {
			wantError(t, ask(t, c, wsapi.Hello{APIKey: tc.key}, tc.frame, tc.payload), wsapi.ErrCodeNotAuthorized)
		})
	}
}
func TestConversationManagementRequiresDeviceAccessEvenForMembers(t *testing.T) {
	c := newConsole(t)
	device := c.deviceWithKey(t, "private-device")
	member := c.account(t, "member@qa.example", "member")
	wantError(t, ask(t, c, wsapi.Hello{Session: member}, wsapi.TypeEventCreate, wsapi.EventCreateRequest{DeviceID: device, Chat: "5511999999999@s.whatsapp.net", Name: "Planning", StartTime: time.Now().Add(time.Hour)}), wsapi.ErrCodeNotAuthorized)
	lat, lon := 0.0, 0.0
	wantError(t, ask(t, c, wsapi.Hello{Session: member}, wsapi.TypeLocationSend, wsapi.LocationSendRequest{DeviceID: device, Chat: "5511999999999@s.whatsapp.net", Latitude: &lat, Longitude: &lon}), wsapi.ErrCodeNotAuthorized)
	wantError(t, ask(t, c, wsapi.Hello{Session: member}, wsapi.TypeChatStart, wsapi.ChatStartRequest{DeviceID: device, Phone: "5511999999999"}), wsapi.ErrCodeNotAuthorized)
	wantError(t, ask(t, c, wsapi.Hello{Session: member}, wsapi.TypeGroupCreate, wsapi.GroupCreateRequest{DeviceID: device, Name: "QA", Participants: []string{"5511999999999"}}), wsapi.ErrCodeNotAuthorized)
}
