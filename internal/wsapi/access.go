package wsapi

import (
	"context"
	"errors"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"whatserver2/internal/access"
	"whatserver2/internal/store"
)

// RevalidateAccess wakes all local connections after an HTTP mutation commits.
// The database remains authoritative; other processes and direct DB changes
// are covered by the periodic check and checks before commands/delivery.
func (s *Server) RevalidateAccess() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for sess := range s.sessions {
		select {
		case sess.accessWake <- struct{}{}:
		default:
		}
	}
}

func (s *session) validAccess(ctx context.Context) bool {
	who := s.actor()
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	valid := true
	if !who.person {
		valid = s.srv.cfg.Keys != nil && s.srv.cfg.Keys.ConnectionKey(checkCtx, who.keyID, who.tenant, who.scope, who.userID) == nil
	}
	if valid && (who.person || who.service) {
		accounts := s.srv.cfg.Accounts
		if who.person {
			accounts = s.srv.cfg.Sessions
		}
		if accounts == nil {
			valid = false
		} else {
			tenant, err := uuid.Parse(who.tenant)
			if err != nil {
				valid = false
			} else {
				role, version, err := accounts.ConnectionAccess(checkCtx, tenant, who.userID, who.sessionID)
				valid = err == nil && role == who.role && version == who.accessVersion
			}
		}
	}
	if !valid {
		s.closeWith(websocket.StatusPolicyViolation, "access changed or expired; reconnect")
	}
	return valid
}

func (s *session) accessLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.accessWake:
		}
		if !s.validAccess(ctx) {
			return
		}
	}
}

// grantDevices snapshots the readable device set for a subscription/directory.
// A removed grant changes access_version and closes the connection, including
// frames already queued under this snapshot.
func (s *session) grantDevices(ctx context.Context) (map[uuid.UUID]struct{}, error) {
	return s.actionDevices(ctx, store.ActionRead)
}

func (s *session) actionDevices(ctx context.Context, action store.DeviceAction) (map[uuid.UUID]struct{}, error) {
	who := s.actor()
	if s.srv.cfg.Devices == nil {
		return nil, errors.New("device access is not configured")
	}
	tenant, err := uuid.Parse(who.tenant)
	if err != nil {
		return nil, err
	}
	devices, err := s.srv.cfg.Devices.List(ctx, who.tenant)
	if err != nil {
		return nil, err
	}
	allowed := map[uuid.UUID]struct{}{}
	for _, d := range devices {
		id, err := uuid.Parse(d.ID)
		if err != nil {
			return nil, err
		}
		has, err := access.Allows(ctx, access.Actor{Tenant: tenant, User: who.userID, Key: who.keyID, Scope: who.scope, Role: who.role}, id, action, s.srv.cfg.Keys, s.accountStore())
		if err != nil {
			return nil, err
		}
		if has {
			allowed[id] = struct{}{}
		}
	}
	return allowed, nil
}

func (s *session) accountStore() *store.Users {
	if s.actor().person {
		return s.srv.cfg.Sessions
	}
	return s.srv.cfg.Accounts
}

func frameAction(kind string) store.DeviceAction {
	switch kind {
	case TypeSend, TypeSendMedia, TypeEdit, TypeRevoke, TypeReact, TypePollVote, TypeMarkRead, TypeChatTyping, TypeChatTimer:
		return store.ActionSend
	case TypeDeviceStop, TypeDeviceMode, TypeDeviceDelete, TypeBackfill, TypeGroupJoin, TypeReprojectPut, TypeGrantAdd, TypeGrantRevoke:
		return store.ActionManage
	case TypeDeviceInfo:
		return store.ActionView
	default:
		return store.ActionRead
	}
}

func (s *session) authorizeDevice(ctx context.Context, f Frame, device uuid.UUID, action store.DeviceAction) bool {
	who := s.actor()
	tenant, err := uuid.Parse(who.tenant)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "invalid workspace")
		return false
	}
	allowed, err := access.Allows(ctx, access.Actor{Tenant: tenant, User: who.userID, Key: who.keyID, Scope: who.scope, Role: who.role}, device, action, s.srv.cfg.Keys, s.accountStore())
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not check device permissions")
		return false
	}
	if !allowed {
		s.replyError(f.ReqID, ErrCodeNotAuthorized, "this account or token lacks the required "+string(action)+" permission or API key scope; reading also requires a key grant")
		return false
	}
	return true
}
