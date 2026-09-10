package wsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"whatserver2/internal/store"

	"go.mau.fi/whatsmeow/types"
)

// handleGroupJoin accepts an invitation that arrived as a message.
//
// Outward facing, explicit, and with no undo on this side: the account becomes
// a member and everyone already in the group can see it. So this is reachable
// only from a frame a person's client sent, never from the ingest path, and it
// refuses rather than guesses whenever something is missing.
//
// The invite code arrives in the request rather than being read from the
// archive, and that is not a shortcut. The code is a capability — it is what
// lets somebody into the group — so it is sealed with the rest of the message
// payload and this server cannot open it. The client can, and passes it in for
// this one exchange.
func (s *session) handleGroupJoin(ctx context.Context, f Frame) {
	var req GroupJoinRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	// Joining is visible to everyone in the group and cannot be taken back
	// quietly; a key issued to send messages does not get to do it.
	if !s.requireScope(f.ReqID, store.ScopeFull) {
		return
	}
	// The group is validated by resolveSend, which parses it as the chat.
	t, ok := s.resolveSend(ctx, f, req.DeviceID, req.GroupJID)
	if !ok {
		return
	}
	inviter, code, reason := checkJoin(req, t.chat, time.Now())
	if reason != "" {
		s.replyError(f.ReqID, code, reason)
		return
	}

	if err := t.device.Client().JoinGroupWithInvite(
		ctx, t.chat, inviter, req.Code, req.Expiration); err != nil {
		s.log.Warn("could not accept a group invitation",
			"group", t.chat, "error", err)
		s.replyError(f.ReqID, ErrCodeConflict, err.Error())
		return
	}
	s.reply(TypeGroupJoined, f.ReqID, GroupJoined{GroupJID: t.chat.String()})
}

// checkJoin decides whether an invitation may be acted on, and says why not.
//
// Pulled out of the handler and given a clock, because every branch here is a
// refusal and refusals are the part worth testing. What is on the other side is
// a call that makes this account a member of a group, visible to everyone
// already in it, with no undo on this side — so "compiles and returns nil" is
// not evidence that any of these gates works.
//
// Returns the parsed inviter, the error code to answer with, and a reason.
// An empty reason means go ahead.
func checkJoin(req GroupJoinRequest, chat types.JID, now time.Time) (types.JID, string, string) {
	if req.Code == "" {
		return types.EmptyJID, ErrCodeBadRequest, "an invitation needs its code"
	}
	if chat.Server != types.GroupServer {
		return types.EmptyJID, ErrCodeBadRequest,
			fmt.Sprintf("%q is not a group", req.GroupJID)
	}
	inviter, err := types.ParseJID(req.Inviter)
	if err != nil || inviter.IsEmpty() || inviter.User == "" {
		return types.EmptyJID, ErrCodeBadRequest, "inviter is required and must be a JID"
	}
	// Refused here rather than spending a round trip on a stanza WhatsApp will
	// reject, and refused with something a person can act on: an expired
	// invitation needs a new one, not another press. Same shape as the edit
	// window, which is checked locally for the same reason.
	if req.Expiration > 0 && now.After(time.Unix(req.Expiration, 0)) {
		return types.EmptyJID, ErrCodeConflict, "that invitation has expired; ask for a new one"
	}
	return inviter.ToNonAD(), "", ""
}

// groupChangeLimit bounds one history. A group with years of churn is not
// something a panel can render, and the newest is what a reader is looking for.
const groupChangeLimit = 200

// handleGroupInfo answers who is in a group and what has happened to it.
//
// Refreshes from WhatsApp when asked and when the device is connected. A
// membership list a week old presented as current is a worse answer than a
// round trip, and the reply says which of the two it is rather than leaving a
// reader to assume.
func (s *session) handleGroupInfo(ctx context.Context, f Frame) {
	var req GroupRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if s.srv.cfg.Groups == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "groups are not configured on this server")
		return
	}
	tenant, device, ok := s.resolveDevice(ctx, f, req.DeviceID)
	if !ok {
		return
	}
	chat, err := types.ParseJID(req.Chat)
	if err != nil || chat.Server != types.GroupServer {
		s.replyError(f.ReqID, ErrCodeBadRequest, "chat must be a group JID")
		return
	}
	key := chat.ToNonAD().String()

	out := Group{ChatKey: key, Members: []GroupMember{}}
	if req.Refresh {
		// Best effort. A device that is not connected, or a group WhatsApp
		// declines to describe, still gets whatever the archive holds — which
		// is the whole point of holding it.
		if dev, running := s.srv.cfg.Registry.Get(device.String()); running {
			if info, err := dev.Client().GetGroupInfo(ctx, chat); err == nil && info != nil {
				out.PermissionsKnown = dev.Identity().Known()
				out.IsMember, out.CanManage = groupMembership(info, dev.Identity())
				if s.srv.cfg.Router == nil {
					out.Refreshed = false
				} else if err := s.srv.cfg.Router.SnapshotGroup(ctx, tenant, device, info); err != nil {
					s.log.Debug("could not snapshot a group", "chat", key, "error", err)
				} else {
					out.Refreshed = true
				}
			}
		}
	}

	members, err := s.srv.cfg.Groups.Participants(ctx, tenant, device, key)
	if err != nil {
		s.log.Error("could not list participants", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not read the group")
		return
	}
	for _, m := range members {
		out.Members = append(out.Members, GroupMember{
			Key: m.Key, LID: m.LID, PN: m.PN,
			IsAdmin: m.IsAdmin, IsSuperAdmin: m.IsSuperAdmin,
		})
	}

	changes, err := s.srv.cfg.Groups.Changes(ctx, tenant, device, key, groupChangeLimit)
	if err == nil {
		for _, c := range changes {
			out.Changes = append(out.Changes, GroupChange{
				TS: c.TS, Action: c.Action,
				ActorKey: c.ActorKey, ActorLID: c.ActorLID, ActorPN: c.ActorPN,
				SubjectKey: c.SubjectKey, SubjectLID: c.SubjectLID, SubjectPN: c.SubjectPN,
				Detail: c.Detail,
			})
		}
	}
	if since, err := s.srv.cfg.Groups.Since(ctx, tenant, device, key); err == nil {
		out.Since = since
	}

	s.reply(TypeGroupFrame, f.ReqID, out)
}
