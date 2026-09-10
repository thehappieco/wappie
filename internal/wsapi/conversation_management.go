package wsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/types"
	"whatserver2/internal/domain"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wa/send"
)

// phoneNumber accepts explicit international numbers; no country is guessed.
func phoneNumber(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	var b strings.Builder
	for i, c := range raw {
		switch {
		case c >= '0' && c <= '9':
			b.WriteRune(c)
		case c == '+' && i == 0, c == ' ', c == '-', c == '(', c == ')', c == '.':
		default:
			return "", fmt.Errorf("phone must be an international number including country code")
		}
	}
	value := b.String()
	if len(value) < 7 || len(value) > 15 || value[0] == '0' {
		return "", fmt.Errorf("phone must contain 7 to 15 digits including country code")
	}
	return value, nil
}

func participantJIDs(values []string) ([]types.JID, error) {
	if len(values) == 0 || len(values) > 32 {
		return nil, fmt.Errorf("provide 1 to 32 participants per operation")
	}
	out := make([]types.JID, 0, len(values))
	seen := map[string]bool{}
	for _, raw := range values {
		var jid types.JID
		if strings.Contains(raw, "@") {
			parsed, err := types.ParseJID(strings.TrimSpace(raw))
			if err != nil || parsed.User == "" || (parsed.Server != types.DefaultUserServer && parsed.Server != types.HiddenUserServer) {
				return nil, fmt.Errorf("participants must be individual WhatsApp accounts")
			}
			jid = parsed.ToNonAD()
			if len(jid.User) > 20 {
				return nil, fmt.Errorf("participants must be individual WhatsApp accounts")
			}
			for _, digit := range jid.User {
				if digit < '0' || digit > '9' {
					return nil, fmt.Errorf("participants must be individual WhatsApp accounts")
				}
			}
		} else {
			phone, err := phoneNumber(raw)
			if err != nil {
				return nil, err
			}
			jid = types.NewJID(phone, types.DefaultUserServer)
		}
		if seen[jid.String()] {
			continue
		}
		seen[jid.String()] = true
		out = append(out, jid)
	}
	return out, nil
}

func groupMembership(info *types.GroupInfo, identity wa.Identity) (member, admin bool) {
	if info == nil {
		return
	}
	for _, p := range info.Participants {
		for _, jid := range []types.JID{p.JID, p.LID, p.PhoneNumber} {
			if jid.IsEmpty() {
				continue
			}
			if (!identity.LID.IsEmpty() && jid.ToNonAD() == identity.LID.ToNonAD()) || (!identity.PN.IsEmpty() && jid.ToNonAD() == identity.PN.ToNonAD()) {
				return true, p.IsAdmin || p.IsSuperAdmin
			}
		}
	}
	return
}

func participantResults(members []types.GroupParticipant) []ParticipantResult {
	out := make([]ParticipantResult, 0, len(members))
	for _, p := range members {
		jid := p.JID
		if jid.IsEmpty() {
			jid = p.PhoneNumber
		}
		if jid.IsEmpty() {
			jid = p.LID
		}
		if jid.IsEmpty() {
			continue
		}
		out = append(out, ParticipantResult{JID: jid.ToNonAD().String(), Error: p.Error})
	}
	return out
}

func (s *session) handleChatStart(ctx context.Context, f Frame) {
	var req ChatStartRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "invalid chat request")
		return
	}
	phone, err := phoneNumber(req.Phone)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	t, ok := s.resolveSend(ctx, f, req.DeviceID, types.NewJID(phone, types.DefaultUserServer).String())
	if !ok {
		return
	}
	found, err := t.device.Client().IsOnWhatsApp(ctx, []string{"+" + phone})
	if err != nil {
		s.replyError(f.ReqID, ErrCodeConflict, "could not verify this number on WhatsApp")
		return
	}
	if len(found) != 1 || !found[0].IsIn || found[0].JID.IsEmpty() {
		s.replyError(f.ReqID, ErrCodeNotFound, "this number is not registered on WhatsApp")
		return
	}
	jid := found[0].JID.ToNonAD()
	if jid.Server != types.DefaultUserServer && jid.Server != types.HiddenUserServer {
		s.replyError(f.ReqID, ErrCodeConflict, "WhatsApp returned an unsupported account")
		return
	}
	addr := domain.AddressOf(jid).Merge(domain.AddressOf(found[0].PhoneNumber))
	if s.srv.cfg.Messages == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "conversations are unavailable")
		return
	}
	err = s.srv.cfg.Messages.UpsertChatMeta(ctx, store.ChatMeta{TenantID: t.tenant, DeviceID: t.deviceID, ChatKey: jid.String(), ChatLID: jidStringOrEmpty(addr.LID), ChatPN: jidStringOrEmpty(addr.PN)})
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not open this conversation")
		return
	}
	if s.srv.cfg.Router != nil {
		s.srv.cfg.Router.EnsureIdentity(ctx, t.tenant, t.deviceID, jid)
	}
	s.reply(TypeChatStarted, f.ReqID, ChatStarted{Chat: jid.String()})
}

func jidStringOrEmpty(jid types.JID) string {
	if jid.IsEmpty() {
		return ""
	}
	return jid.ToNonAD().String()
}

func (s *session) groupTarget(ctx context.Context, f Frame, device, chat string) (sendTarget, *types.GroupInfo, bool) {
	if !s.requireScope(f.ReqID, store.ScopeFull) {
		return sendTarget{}, nil, false
	}
	t, ok := s.resolveSend(ctx, f, device, chat)
	if !ok {
		return t, nil, false
	}
	if t.chat.Server != types.GroupServer || t.chat.User == "" {
		s.replyError(f.ReqID, ErrCodeBadRequest, "chat must be a group JID")
		return t, nil, false
	}
	info, err := t.device.Client().GetGroupInfo(ctx, t.chat)
	if err != nil || info == nil {
		s.replyError(f.ReqID, ErrCodeConflict, "could not check current group permissions on WhatsApp")
		return t, nil, false
	}
	member, _ := groupMembership(info, t.device.Identity())
	if !member {
		s.replyError(f.ReqID, ErrCodeNotAuthorized, "this WhatsApp account is not a current group member")
		return t, nil, false
	}
	return t, info, true
}

func (s *session) handleGroupCreate(ctx context.Context, f Frame) {
	var req GroupCreateRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "invalid group request")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || utf8.RuneCountInString(req.Name) > 100 {
		s.replyError(f.ReqID, ErrCodeBadRequest, "group name must contain 1 to 100 characters")
		return
	}
	participants, err := participantJIDs(req.Participants)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if !s.requireScope(f.ReqID, store.ScopeFull) {
		return
	}
	tenant, deviceID, ok := s.resolveDevice(ctx, f, req.DeviceID)
	if !ok {
		return
	}
	dev, running := s.srv.cfg.Registry.Get(deviceID.String())
	if !running || !dev.Client().IsConnected() {
		s.replyError(f.ReqID, ErrCodeConflict, "this device is not connected to WhatsApp")
		return
	}
	result, snapshot, err := createGroupOnWhatsApp(ctx, dev.Client(), req.Name, participants)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeConflict, err.Error())
		return
	}
	if s.srv.cfg.Router != nil {
		result.Refreshed = s.srv.cfg.Router.SyncGroups(ctx, tenant, deviceID, []*types.GroupInfo{snapshot}) == 1
	}
	s.reply(TypeGroupChanged, f.ReqID, result)
}

func (s *session) handleGroupParticipants(ctx context.Context, f Frame) {
	var req GroupParticipantsRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "invalid participant request")
		return
	}
	if req.Action != "add" && req.Action != "remove" {
		s.replyError(f.ReqID, ErrCodeBadRequest, "action must be add or remove")
		return
	}
	participants, err := participantJIDs(req.Participants)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	t, info, ok := s.groupTarget(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}
	_, admin := groupMembership(info, t.device.Identity())
	if !admin {
		s.replyError(f.ReqID, ErrCodeNotAuthorized, "this WhatsApp account must be a group administrator")
		return
	}
	identity := t.device.Identity()
	for _, p := range participants {
		if p == identity.LID.ToNonAD() || p == identity.PN.ToNonAD() {
			s.replyError(f.ReqID, ErrCodeBadRequest, "use group.leave to leave the group yourself")
			return
		}
	}
	changed, err := t.device.Client().UpdateGroupParticipants(ctx, t.chat, participants, whatsmeow.ParticipantChange(req.Action))
	if err != nil {
		s.replyError(f.ReqID, ErrCodeConflict, err.Error())
		return
	}
	result := GroupChanged{Chat: t.chat.String(), Action: req.Action, Participants: participantResults(changed)}
	// WhatsApp may refuse individual members because of their privacy settings.
	// Only a fresh snapshot is allowed to change the recorded membership.
	if latest, err := t.device.Client().GetGroupInfo(ctx, t.chat); err == nil && latest != nil && s.srv.cfg.Router != nil {
		result.Refreshed = s.srv.cfg.Router.SyncGroups(ctx, t.tenant, t.deviceID, []*types.GroupInfo{latest}) == 1
	}
	s.reply(TypeGroupChanged, f.ReqID, result)
}

func (s *session) handleGroupLeave(ctx context.Context, f Frame) {
	var req GroupLeaveRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "invalid group request")
		return
	}
	t, info, ok := s.groupTarget(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}
	if err := t.device.Client().LeaveGroup(ctx, t.chat); err != nil {
		s.replyError(f.ReqID, ErrCodeConflict, err.Error())
		return
	}
	if s.srv.cfg.Groups != nil {
		identity := t.device.Identity()
		for _, participant := range info.Participants {
			member, _ := groupMembership(&types.GroupInfo{Participants: []types.GroupParticipant{participant}}, identity)
			if !member {
				continue
			}
			addr := domain.AddressOf(participant.JID).Merge(domain.AddressOf(participant.LID)).Merge(domain.AddressOf(participant.PhoneNumber))
			key := addr.Primary().ToNonAD().String()
			err := s.srv.cfg.Groups.Record(ctx, t.tenant, t.deviceID, t.chat.String(), store.GroupChange{
				TS: time.Now(), Action: store.ChangeRemove, ActorKey: key, ActorLID: jidStringOrEmpty(addr.LID), ActorPN: jidStringOrEmpty(addr.PN),
				SubjectKey: key, SubjectLID: jidStringOrEmpty(addr.LID), SubjectPN: jidStringOrEmpty(addr.PN),
			})
			if err != nil {
				s.log.Warn("left group but could not record membership change", "error", err)
			}
			break
		}
	}
	s.reply(TypeGroupChanged, f.ReqID, GroupChanged{Chat: t.chat.String(), Action: "leave"})
}

func (s *session) handlePollCreate(ctx context.Context, f Frame) {
	var req PollCreateRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "invalid poll request")
		return
	}
	poll, err := send.ValidatePoll(req.Question, req.Options, req.SelectableCount)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	t, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}
	if t.chat.Server != types.GroupServer && t.chat.Server != types.DefaultUserServer && t.chat.Server != types.HiddenUserServer {
		s.replyError(f.ReqID, ErrCodeBadRequest, "polls need an individual chat or a group")
		return
	}
	opts := send.Options{}
	s.applyChatTimer(ctx, t, &opts)
	sent, err := send.SendPoll(ctx, t.device.Client(), t.chat, req.ID, poll, opts)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeConflict, err.Error())
		return
	}
	s.archive(ctx, t, sent, f)
}

// Keep the remote result separate from the snapshot: a group can exist even
// when WhatsApp declined individual additions or the local store is offline.
func createGroupOnWhatsApp(ctx context.Context, client wa.Client, name string, participants []types.JID) (GroupChanged, *types.GroupInfo, error) {
	info, err := client.CreateGroup(ctx, whatsmeow.ReqCreateGroup{Name: name, Participants: participants})
	if err != nil {
		return GroupChanged{}, nil, err
	}
	if info == nil || info.JID.User == "" || info.JID.Server != types.GroupServer {
		return GroupChanged{}, nil, fmt.Errorf("WhatsApp did not return the created group; check your phone before trying again")
	}
	result := GroupChanged{Chat: info.JID.ToNonAD().String(), Action: "create", Participants: participantResults(info.Participants)}
	snapshot := *info
	snapshot.Participants = nil
	for _, p := range info.Participants {
		if p.Error == 0 {
			snapshot.Participants = append(snapshot.Participants, p)
		}
	}
	if snapshot.ParticipantCount == 0 {
		snapshot.ParticipantCount = len(snapshot.Participants)
	}
	return result, &snapshot, nil
}
