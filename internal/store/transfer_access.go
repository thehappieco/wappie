package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A Team's number moves to its owner's Personal only when nobody else has
// access to it (decision 0040; the plan's D16), so a move never ends anyone's
// reading, sending or integration. otherAccessTx is that rule, read from
// Wappie's own rows; the preview and the transfer's own re-check, under the
// locks it holds to its commit, both ask it.

// ReasonOthersHaveAccess is a transfer refused while someone else has access
// to the number.
const ReasonOthersHaveAccess = "others_have_access"

// othersHaveAccess is the refusal's reason, for consoles that show only it.
const othersHaveAccess = "Só é possível mover este número quando ninguém mais tem acesso a ele."

// Why someone has access to a number, as a transfer's refusal says it.
const (
	whyRead   = "read"
	whySend   = "send"
	whyManage = "manage"
	// whyKey is a grant at the number's current epoch; whyOldKey a grant only
	// at an older one that is not retired, which still opens older history
	// and which the permissions screen shows as no key.
	whyKey    = "key"
	whyOldKey = "old_key"
)

// TransferAccess is someone, or something, that still has access to a
// number a transfer to Personal would take from them. Kind is person,
// service (a standing service account, and every key acting as it),
// assistant or ai (another person's assistant connection or AI
// authorization, whose access is its creator's), or key (another person's
// Integrations key restricted to the number, whose act is its creator's).
// Why says what it holds; Status, for people and service accounts, whether
// their membership is active, since a disabled one can only be removed.
// UserID is the person, the service account, or the creator; it is empty for
// a key or connection whose creator is gone, which still counts.
type TransferAccess struct {
	Kind          string     `json:"kind"`
	Why           []string   `json:"why"`
	Status        string     `json:"status,omitempty"`
	UserID        *uuid.UUID `json:"user_id,omitempty"`
	Name          string     `json:"name"`
	Email         string     `json:"email,omitempty"`
	ConnectionID  string     `json:"connection_id,omitempty"`
	ClientName    string     `json:"client_name,omitempty"`
	KeyID         string     `json:"key_id,omitempty"`
	KeyName       string     `json:"key_name,omitempty"`
	CreatedByName string     `json:"created_by_name,omitempty"`
}

// whyOf lists the flags that hold, in a fixed order.
func whyOf(read, send, manage, key, oldKey bool) []string {
	out := []string{}
	for _, w := range []struct {
		on   bool
		name string
	}{{read, whyRead}, {send, whySend}, {manage, whyManage}, {key, whyKey}, {oldKey && !key, whyOldKey}} {
		if w.on {
			out = append(out, w.name)
		}
	}
	return out
}

// accessRowsQuery is, for each account other than $3, what it holds on
// number $2 of workspace $1: a permission with Read or Send, or with Manage
// when the account's role is neither owner nor admin (theirs adds nothing to
// the role, and the console stores it on every save), and grants at an
// epoch that is not retired. Rows only: membership status, a connection's
// service account and the rest are the callers'.
const accessRowsQuery = `
	WITH held AS (
	  SELECT p.user_id, p.can_read AS r, p.can_send AS s,
	         p.can_manage AND coalesce(m.role, 'member') NOT IN ('owner', 'admin') AS mg, false AS k, false AS ok
	  FROM device_permissions p
	  LEFT JOIN workspace_memberships m ON m.tenant_id = p.tenant_id AND m.user_id = p.user_id
	  WHERE p.tenant_id = $1 AND p.device_id = $2
	  UNION ALL
	  SELECT g.user_id, false, false, false, g.epoch = d.current_epoch, g.epoch <> d.current_epoch
	  FROM device_key_grants g
	  JOIN device_archive_keys a ON a.device_id = g.device_id AND a.epoch = g.epoch AND a.retired_at IS NULL
	  JOIN devices d ON d.id = g.device_id
	  WHERE g.tenant_id = $1 AND g.device_id = $2
	)
	SELECT user_id, bool_or(r) AS r, bool_or(s) AS s, bool_or(mg) AS mg, bool_or(k) AS k, bool_or(ok) AS ok
	FROM held WHERE user_id <> $3 GROUP BY user_id`

// otherAccessTx is everyone but the actor who has access to the number, by
// 0040's rule as Wappie reads it from its rows (D16):
//   - a person, or a standing service account, with a permission or a
//     grant, as accessRowsQuery counts them, whatever their membership's
//     status (fail closed: a disabled one keeps rows a move would delete);
//   - another person's connection of any kind (an assistant, or an AI
//     authorization), live, whose key names the number or whose service
//     account holds a grant or a permission for it: a connection's service
//     account never counts by itself, its grants being copies of its
//     creator's, and the access is the creator's;
//   - another person's Integrations key restricted to the number, with no
//     acts_as and no connection behind it, which fetches its ciphertext and
//     metadata, and sends with a send scope. A key or a connection whose
//     creator is gone counts.
//
// Never counted: the actor's own keys and connections (the move narrows the
// keys and ends the connections), keys for every number (not bound to this
// one), keys acting as a service account (they reach only its rows), and an
// owner's or an admin's role, which manages every number without a row.
func otherAccessTx(ctx context.Context, tx pgx.Tx, source, device, actor uuid.UUID) ([]TransferAccess, error) {
	out := []TransferAccess{}
	rows, err := tx.Query(ctx, `WITH a AS (`+accessRowsQuery+`)
		SELECT u.id, u.role = 'service' OR coalesce(m.role, '') = 'service', u.name, u.email,
		       coalesce(m.status = 'active', false), a.r, a.s, a.mg, a.k, a.ok
		FROM a JOIN users u ON u.id = a.user_id
		LEFT JOIN workspace_memberships m ON m.tenant_id = $1 AND m.user_id = a.user_id
		WHERE (a.r OR a.s OR a.mg OR a.k OR a.ok)
		  AND NOT ((u.role = 'service' OR coalesce(m.role, '') = 'service')
		           AND (m.expires_at IS NOT NULL OR EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = u.id)))
		ORDER BY u.role = 'service' OR coalesce(m.role, '') = 'service', lower(u.email), u.id`, source, device, actor)
	if err != nil {
		return nil, err
	}
	people, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (TransferAccess, error) {
		var o TransferAccess
		var id uuid.UUID
		var service, active, r, s, mg, k, ok bool
		var email string
		err := row.Scan(&id, &service, &o.Name, &email, &active, &r, &s, &mg, &k, &ok)
		o.UserID, o.Why, o.Kind, o.Email, o.Status = &id, whyOf(r, s, mg, k, ok), "person", email, "active"
		if service {
			o.Kind, o.Name, o.Email = "service", ServiceName(User{Email: email, Role: RoleService}), ""
		}
		if !active {
			o.Status = "disabled"
		}
		return o, err
	})
	if err != nil {
		return nil, err
	}
	out = append(out, people...)

	rows, err = tx.Query(ctx, `WITH a AS (`+accessRowsQuery+`)
		SELECT c.id, c.kind, c.client_name, c.created_by, coalesce(nullif(u.name, ''), u.email, h.email, ''),
		       coalesce(a.r, false), coalesce(a.s, false), coalesce(a.mg, false), coalesce(a.k, false), coalesce(a.ok, false)
		FROM mcp_connections c
		LEFT JOIN a ON a.user_id = c.service_user_id
		LEFT JOIN users u ON u.id = c.created_by
		LEFT JOIN workspace_member_history h ON h.tenant_id = c.tenant_id AND h.user_id = c.created_by
		WHERE c.tenant_id = $1 AND c.status IN ('pending', 'active', 'reseal') AND c.created_by IS DISTINCT FROM $3
		  AND ((a.r OR a.s OR a.mg OR a.k OR a.ok) OR EXISTS (SELECT 1 FROM api_key_devices x WHERE x.api_key_id = c.api_key_id AND x.device_id = $2))
		ORDER BY c.created_at, c.id`, source, device, actor)
	if err != nil {
		return nil, err
	}
	connections, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (TransferAccess, error) {
		var o TransferAccess
		var kind string
		var r, s, mg, k, ok bool
		err := row.Scan(&o.ConnectionID, &kind, &o.ClientName, &o.UserID, &o.Name, &r, &s, &mg, &k, &ok)
		o.Kind, o.CreatedByName, o.Why = assistantKind(kind), o.Name, whyOf(r, s, mg, k, ok)
		if len(o.Why) == 0 {
			// Its key names the number: it reads it through that key.
			o.Why = []string{whyRead}
		}
		return o, err
	})
	if err != nil {
		return nil, err
	}
	out = append(out, connections...)

	rows, err = tx.Query(ctx, `SELECT k.prefix, k.name, k.created_by, coalesce(nullif(u.name, ''), u.email, h.email, ''), k.scope
		FROM api_keys k
		JOIN api_key_devices x ON x.api_key_id = k.id AND x.device_id = $2
		LEFT JOIN users u ON u.id = k.created_by
		LEFT JOIN workspace_member_history h ON h.tenant_id = k.tenant_id AND h.user_id = k.created_by
		WHERE k.tenant_id = $1 AND k.devices_restricted AND k.acts_as IS NULL AND k.revoked_at IS NULL
		  AND (k.expires_at IS NULL OR k.expires_at > now())
		  AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.api_key_id = k.id)
		  AND k.created_by IS DISTINCT FROM $3
		ORDER BY k.created_at, k.id`, source, device, actor)
	if err != nil {
		return nil, err
	}
	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (TransferAccess, error) {
		var o TransferAccess
		var scope KeyScope
		err := row.Scan(&o.KeyID, &o.KeyName, &o.UserID, &o.Name, &scope)
		o.Kind, o.CreatedByName = "key", o.Name
		o.Why = whyOf(true, scope.Covers(ScopeSend), scope.Covers(ScopeFull), false, false)
		return o, err
	})
	if err != nil {
		return nil, err
	}
	return append(out, keys...), nil
}

// ownConnectionsTx is the actor's own live connections, of every kind,
// whose key names the number or whose service account holds a grant or a
// permission for it: a move ends them (access_lost), since a renewal must
// name exactly the old key's numbers.
func ownConnectionsTx(ctx context.Context, tx pgx.Tx, source, device, actor uuid.UUID) ([]EndedAssistant, error) {
	rows, err := tx.Query(ctx, `SELECT c.id, c.client_name, c.kind FROM mcp_connections c
		WHERE c.tenant_id = $1 AND c.status IN ('pending', 'active', 'reseal') AND c.created_by = $3
		  AND (EXISTS (SELECT 1 FROM api_key_devices x WHERE x.api_key_id = c.api_key_id AND x.device_id = $2)
		       OR EXISTS (SELECT 1 FROM device_key_grants g WHERE g.tenant_id = $1 AND g.device_id = $2 AND g.user_id = c.service_user_id)
		       OR EXISTS (SELECT 1 FROM device_permissions p WHERE p.tenant_id = $1 AND p.device_id = $2 AND p.user_id = c.service_user_id))
		ORDER BY c.created_at, c.id`, source, device, actor)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (EndedAssistant, error) {
		var a EndedAssistant
		err := row.Scan(&a.ID, &a.ClientName, &a.Kind)
		a.Kind = assistantKind(a.Kind)
		return a, err
	})
}

// ownRestrictedKeysTx is the actor's own Integrations keys restricted to
// chosen numbers, this one among them, that act as nobody and are no
// connection's: a move takes the number off them, revoking none. A key
// acting as a service account reaches only that account's rows, which the
// move removes anyway.
func ownRestrictedKeysTx(ctx context.Context, tx pgx.Tx, source, device, actor uuid.UUID) ([]NarrowedKey, error) {
	rows, err := tx.Query(ctx, `SELECT k.prefix, k.name FROM api_keys k
		JOIN api_key_devices x ON x.api_key_id = k.id AND x.device_id = $2
		WHERE k.tenant_id = $1 AND k.created_by = $3 AND k.acts_as IS NULL AND k.revoked_at IS NULL
		  AND (k.expires_at IS NULL OR k.expires_at > now())
		  AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.api_key_id = k.id)
		ORDER BY k.created_at, k.id`, source, device, actor)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (NarrowedKey, error) {
		var k NarrowedKey
		err := row.Scan(&k.ID, &k.Name)
		return k, err
	})
}
