// Package access applies the same device authorization to HTTP and WebSocket.
package access

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"strings"
	"whatserver2/internal/store"
)

type Actor struct {
	Tenant uuid.UUID
	User   uuid.UUID
	Key    uuid.UUID
	Scope  store.KeyScope
	Role   string
}

func Authenticate(ctx context.Context, token string, keys *store.APIKeys, users *store.Users) (Actor, error) {
	token = strings.TrimSpace(token)
	if users != nil {
		if session, user, err := users.ActiveSession(ctx, token); err == nil {
			return Actor{Tenant: session.TenantID, User: user.ID, Role: user.Role}, nil
		}
	}
	if keys == nil {
		return Actor{}, store.ErrInvalidKey
	}
	key, err := keys.VerifyScoped(ctx, token)
	if err != nil {
		return Actor{}, err
	}
	tenant, err := uuid.Parse(key.TenantID)
	if err != nil {
		return Actor{}, err
	}
	actor := Actor{Tenant: tenant, Key: key.ID, Scope: key.Scope}
	if key.ActsAs != nil {
		if users == nil {
			return Actor{}, store.ErrInvalidKey
		}
		user, err := users.Get(ctx, tenant, *key.ActsAs)
		if err != nil || user.Status != "active" || user.Role != store.RoleService {
			return Actor{}, store.ErrInvalidKey
		}
		actor.User = user.ID
		actor.Role = user.Role
	}
	return actor, nil
}

// Allows says whether actor may act on device. A key needs the action's
// scope and the number in its list; a key that acts as a service account
// also needs that account's permission, and a person needs their own.
//
// Pausing and resuming a number's capture (store.ActionPause) is a person's
// by role only: an owner or an admin, which in a personal workspace is its
// person, never a member with the Manage flag. A key keeps it under its
// scope, full, as for managing; one that acts as a service account adds the
// account's own Manage flag, as before: a service account acts as itself.
func Allows(ctx context.Context, actor Actor, device uuid.UUID, action store.DeviceAction, keys *store.APIKeys, users *store.Users) (bool, error) {
	if actor.Key != uuid.Nil {
		need := store.ScopeRead
		if action == store.ActionSend {
			need = store.ScopeSend
		}
		if action == store.ActionManage || action == store.ActionPause {
			need = store.ScopeFull
		}
		if !actor.Scope.Covers(need) {
			return false, nil
		}
		if keys == nil {
			return false, errors.New("API key access is not configured")
		}
		allowed, err := keys.AllowsDevice(ctx, actor.Key, actor.Tenant, device)
		if err != nil || !allowed {
			return false, err
		}
	}
	if actor.User == uuid.Nil {
		return actor.Key != uuid.Nil, nil
	}
	if users == nil {
		return false, errors.New("account access is not configured")
	}
	p, err := users.DevicePermission(ctx, actor.Tenant, actor.User, device)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return p.Allows(action), nil
}
