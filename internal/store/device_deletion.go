package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"whatserver2/internal/pg"
	"whatserver2/internal/wa"
)

// Deleting a number (decision 0038, as amended by 0039 and 0040) excludes it:
// the row stays, marked deleted_at, hidden by 0050's policy, for 30 days in
// which an owner can recover it; then it is purged. Only owners delete and
// recover, in every workspace, a personal one included, and the store checks
// the live role inside its own transaction.
//
// A deletion revokes no API key. A key restricted to chosen numbers loses
// this one and stays restricted, so a key left with none reaches nothing; a
// key for every number stops reaching it while it is excluded and reaches it
// again after a recovery. Assistant connections whose key names the number
// end with access_lost. The WhatsApp logout runs after the commit, outside
// these transactions, and RecordUnlink writes what it achieved.

var (
	// ErrOwnerOnly refuses anyone but an active owner of an active
	// workspace.
	ErrOwnerOnly = errors.New("store: only an owner of this workspace may do this")
	// ErrPendingDevice is a registration that never linked: it has no
	// identity and holds nothing, so it is removed, never excluded.
	ErrPendingDevice = errors.New("store: this number never linked")
	// ErrRecoveryClosed is a deleted number past its 30 days, or one whose
	// purge has started.
	ErrRecoveryClosed = errors.New("store: this number can no longer be recovered")
	// ErrDeviceBusy is a number whose device lock is held: a client is
	// still running, or a deletion's logout is in flight.
	ErrDeviceBusy = errors.New("store: this number is busy; try again in a few seconds")
	// ErrCapacity is a workspace with no free slot for a recovered number.
	ErrCapacity = errors.New("store: workspace device capacity reached")
	// ErrIdentityInUse is a recovery of a number whose phone was linked
	// again, as another number, while it was excluded.
	ErrIdentityInUse = errors.New("store: this phone is linked again as another number")
)

// ErrDeviceHasReaders refuses a deletion whose readers the owner did not
// acknowledge, naming them as they are now.
type ErrDeviceHasReaders struct{ Readers []Person }

func (e *ErrDeviceHasReaders) Error() string {
	return fmt.Sprintf("store: %d people still read this number", len(e.Readers))
}

// Person is someone an owner is shown in a deletion's or a recovery's
// preflight.
type Person struct {
	UserID uuid.UUID `json:"user_id"`
	Name   string    `json:"name"`
	Email  string    `json:"email"`
}

// ServiceAccountRef is a standing service account, by its service name.
type ServiceAccountRef struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// AssistantRef is a live assistant connection or AI authorization whose key
// names the number. Kind is "assistant" or "ai".
type AssistantRef struct {
	ID            uuid.UUID `json:"id"`
	ClientName    string    `json:"client_name"`
	CreatedByName string    `json:"created_by_name"`
	Kind          string    `json:"kind"`
}

// RestrictedKeyRef is an Integrations key restricted to chosen numbers, this
// one among them, by its prefix. OnlyNumber means it reaches nothing once
// the number is taken off it.
type RestrictedKeyRef struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	OnlyNumber bool   `json:"only_number"`
}

// AllNumberKey is a working key for every number of the workspace, by its
// prefix.
type AllNumberKey struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	CreatedByName string `json:"created_by_name"`
}

// DeletionCheck is a deletion's preflight: who and what loses the number.
type DeletionCheck struct {
	Readers         []Person
	ServiceAccounts []ServiceAccountRef
	Assistants      []AssistantRef
	Keys            []RestrictedKeyRef
	AllNumberKeys   []AllNumberKey
	Bytes           int64
	// Session is a WhatsApp session for the number in the session store,
	// so the deletion has something to log out.
	Session bool
	// CheckedAt is the database's clock, and RecoverableUntilPreview that
	// clock plus 30 days: the deletion's own clock is a little later.
	CheckedAt, RecoverableUntilPreview time.Time
}

// WASession is the fingerprint of a WhatsApp session that may have survived a
// deletion: its JID and registration id, as whatsmeow_device holds them.
type WASession struct {
	JID            string
	RegistrationID int64
}

// EndedAssistant is a connection a deletion ended.
type EndedAssistant struct {
	ID         uuid.UUID `json:"id"`
	ClientName string    `json:"client_name"`
	Kind       string    `json:"kind"`
}

// NarrowedKey is an Integrations key that lost the number, by its prefix.
type NarrowedKey struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Quarantined is what a deletion did, or, with Already, the state of a
// number that was already excluded.
type Quarantined struct {
	DeviceID              uuid.UUID
	Already               bool
	DeletedAt, PurgeAfter time.Time
	// Session is the session the logout is for, nil when there is none.
	Session *WASession
	// Unlinked and NoteCode describe an already excluded number: no
	// session is left, and what the reply should say about WhatsApp.
	Unlinked        bool
	NoteCode        string
	AssistantsEnded []EndedAssistant
	KeysNarrowed    []NarrowedKey
}

// Note codes a deletion's reply carries about the WhatsApp session.
const (
	NoteUnlinkUnconfirmed   = "unlink_unconfirmed"
	NoteAlreadyDisconnected = "already_disconnected"
)

// status_reason values a deletion writes.
const (
	reasonDeleted          = "deleted"
	reasonNoSession        = "no session at deletion"
	reasonUnlinkedWhenGone = "unlinked when deleted"
)

// noteCode is what a reply says about WhatsApp, from the stored state.
func noteCode(leftover bool, statusReason string) string {
	switch {
	case leftover:
		return NoteUnlinkUnconfirmed
	case statusReason == reasonNoSession:
		return NoteAlreadyDisconnected
	}
	return ""
}

// requireOwnerTx locks the workspace and checks that actor is one of its
// active owners now.
func requireOwnerTx(ctx context.Context, tx pgx.Tx, tenant, actor uuid.UUID) error {
	role, err := lockWorkspaceManager(ctx, tx, tenant, actor)
	if errors.Is(err, ErrMembershipForbidden) || err == nil && role != "owner" {
		return ErrOwnerOnly
	}
	return err
}

// ownerNowTx checks that actor is an active owner of the active workspace now,
// as requireOwnerTx does, but locks nothing: the read-only owner frames
// (DeleteCheck, ListDeleted, RecoverCheck, GetExcluded) scan the
// workspace's storage, and every archive write of the workspace waits on its
// row, so holding it would stall live ingest for every number meanwhile.
func ownerNowTx(ctx context.Context, tx pgx.Tx, tenant, actor uuid.UUID) error {
	var owner bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants t
		JOIN workspace_memberships m ON m.tenant_id = t.id JOIN users u ON u.id = m.user_id
		WHERE t.id = $1 AND t.status = 'active' AND m.user_id = $2 AND m.role = 'owner' AND m.status = 'active' AND u.status = 'active')`,
		tenant, actor).Scan(&owner); err != nil {
		return err
	}
	if !owner {
		return ErrOwnerOnly
	}
	return nil
}

// reader is a person who reads a number (D10): with their platform sub, for
// the event row.
type reader struct {
	Person
	sub *uuid.UUID
}

// readersTx is everyone who reads the number now: a person (never a service
// account) with an active membership and user in an active workspace, an
// unexpired membership, Read, and a grant at the number's current epoch.
// The caller has the number visible: a live one, or the quarantine scope.
func readersTx(ctx context.Context, tx pgx.Tx, tenant, device uuid.UUID) ([]reader, error) {
	rows, err := tx.Query(ctx, `SELECT u.id, u.name, u.email, pi.sub
		FROM workspace_memberships m
		JOIN users u ON u.id = m.user_id
		JOIN tenants t ON t.id = m.tenant_id
		JOIN devices d ON d.tenant_id = m.tenant_id AND d.id = $2
		JOIN device_permissions p ON p.tenant_id = m.tenant_id AND p.device_id = d.id AND p.user_id = m.user_id AND p.can_read
		LEFT JOIN platform_identities pi ON pi.user_id = u.id
		WHERE m.tenant_id = $1 AND m.role <> 'service' AND u.role <> 'service'
		  AND m.status = 'active' AND u.status = 'active' AND t.status = 'active'
		  AND (m.expires_at IS NULL OR m.expires_at > now())
		  AND EXISTS (SELECT 1 FROM device_key_grants g WHERE g.device_id = d.id AND g.user_id = m.user_id AND g.epoch = d.current_epoch)
		ORDER BY lower(u.email), u.id`, tenant, device)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (reader, error) {
		var r reader
		err := row.Scan(&r.UserID, &r.Name, &r.Email, &r.sub)
		return r, err
	})
}

// serviceReadersTx is every standing service account that reads the number:
// no deadline, named by no connection, with Read and a grant at the current
// epoch. A connection's service account holds copies of a person's access
// and is never listed.
func serviceReadersTx(ctx context.Context, tx pgx.Tx, tenant, device uuid.UUID) ([]ServiceAccountRef, error) {
	rows, err := tx.Query(ctx, `SELECT u.id, u.email
		FROM workspace_memberships m
		JOIN users u ON u.id = m.user_id
		JOIN devices d ON d.tenant_id = m.tenant_id AND d.id = $2
		JOIN device_permissions p ON p.tenant_id = m.tenant_id AND p.device_id = d.id AND p.user_id = m.user_id AND p.can_read
		WHERE m.tenant_id = $1 AND m.role = 'service' AND m.status = 'active' AND u.status = 'active' AND m.expires_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = m.user_id)
		  AND EXISTS (SELECT 1 FROM device_key_grants g WHERE g.device_id = d.id AND g.user_id = m.user_id AND g.epoch = d.current_epoch)
		ORDER BY u.email, u.id`, tenant, device)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ServiceAccountRef, error) {
		var s ServiceAccountRef
		var email string
		err := row.Scan(&s.ID, &email)
		s.Name = ServiceName(User{Email: email, Role: RoleService})
		return s, err
	})
}

// allNumberKeysTx is every working Integrations key for all of the
// workspace's numbers. A key that acts as a service account reaches only
// what that account reads, and a connection's key is an assistant's.
func allNumberKeysTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID) ([]AllNumberKey, error) {
	rows, err := tx.Query(ctx, `SELECT k.prefix, k.name, coalesce(nullif(u.name, ''), u.email, h.email, '')
		FROM api_keys k
		LEFT JOIN users u ON u.id = k.created_by
		LEFT JOIN workspace_member_history h ON h.tenant_id = k.tenant_id AND h.user_id = k.created_by
		WHERE k.tenant_id = $1 AND NOT k.devices_restricted AND k.acts_as IS NULL AND k.revoked_at IS NULL
		  AND (k.expires_at IS NULL OR k.expires_at > now())
		  AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.api_key_id = k.id)
		ORDER BY k.created_at, k.id`, tenant)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (AllNumberKey, error) {
		var k AllNumberKey
		err := row.Scan(&k.ID, &k.Name, &k.CreatedByName)
		return k, err
	})
}

// sessionTableTx reports whether whatsmeow's session store shares this
// database. It always does in a deployment (the container opens the same
// DSN); a database without it has no session to log out or to remove.
func sessionTableTx(ctx context.Context, tx pgx.Tx) (bool, error) {
	var present bool
	err := tx.QueryRow(ctx, `SELECT to_regclass('whatsmeow_device') IS NOT NULL`).Scan(&present)
	return present, err
}

// sessionExistsTx reports whether the session store holds a session under
// jid, with that registration id when reg is set.
func sessionExistsTx(ctx context.Context, tx pgx.Tx, jid string, reg *int64) (bool, error) {
	if jid == "" {
		return false, nil
	}
	present, err := sessionTableTx(ctx, tx)
	if err != nil || !present {
		return false, err
	}
	var exists bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM whatsmeow_device WHERE jid = $1 AND ($2::bigint IS NULL OR registration_id = $2))`,
		jid, reg).Scan(&exists)
	return exists, err
}

// keyHoldersTx counts the accounts that can still open the number's current
// archive: reader_safety's backup predicate, at the current epoch.
func keyHoldersTx(ctx context.Context, tx pgx.Tx, device uuid.UUID) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(DISTINCT g.user_id)
		FROM device_key_grants g
		JOIN devices d ON d.id = g.device_id AND d.current_epoch = g.epoch
		JOIN device_archive_keys k ON k.device_id = g.device_id AND k.epoch = g.epoch AND k.retired_at IS NULL
		JOIN workspace_memberships m ON m.tenant_id = g.tenant_id AND m.user_id = g.user_id AND m.status = 'active' AND m.expires_at IS NULL
		JOIN users u ON u.id = m.user_id AND u.status = 'active'
		JOIN device_permissions p ON p.tenant_id = g.tenant_id AND p.device_id = g.device_id AND p.user_id = g.user_id AND p.can_read
		WHERE g.device_id = $1 AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = g.user_id)`, device).Scan(&n)
	return n, err
}

// deviceBytesQuery is how many bytes each number holds: its archive rows and
// the objects only it references. The visible numbers only; inside the
// quarantine scope, excluded ones too. One statement, so one snapshot: the
// caller need not hold the workspace row, and the read-only frames do not.
const deviceBytesQuery = `
 WITH records AS (
  SELECT CASE
   WHEN i.source IN ('messages','media') THEN m.device_id
   WHEN i.source='group_changes' THEN g.device_id
   WHEN i.source IN ('chats','receipts','contacts','group_participants') THEN (i.identity::jsonb->>0)::uuid
   WHEN i.source='ai_derived' THEN a.device_id
  END device_id,i.bytes
  FROM storage_inventory i
  LEFT JOIN messages m ON m.uid=(CASE WHEN i.source IN ('messages','media') THEN i.identity::jsonb->>0 END)::uuid
  LEFT JOIN group_changes g ON g.id=(CASE WHEN i.source='group_changes' THEN i.identity::jsonb->>0 END)::bigint
  LEFT JOIN ai_derived a ON a.message_uid=(CASE WHEN i.source='ai_derived' THEN i.identity::jsonb->>0 END)::uuid
   AND a.feature=(CASE WHEN i.source='ai_derived' THEN i.identity::jsonb->>1 END)
 ), object_references AS (
  SELECT d.object_key,m.device_id FROM media d JOIN messages m ON m.uid=d.message_uid WHERE d.object_key IS NOT NULL
  UNION
  SELECT d.content_key,m.device_id FROM media d JOIN messages m ON m.uid=d.message_uid WHERE d.content_key IS NOT NULL
 ), objects AS (
  SELECT o.bytes,count(r.device_id) device_count,min(r.device_id::text) device_id
  FROM storage_objects o LEFT JOIN object_references r ON r.object_key=o.object_key
  GROUP BY o.object_key,o.bytes
 ), used AS (
  SELECT device_id::text device_id,sum(bytes) bytes FROM records WHERE device_id IS NOT NULL GROUP BY device_id
  UNION ALL
  SELECT device_id,sum(bytes) FROM objects WHERE device_count=1 GROUP BY device_id
 )
 SELECT u.device_id,sum(u.bytes)::bigint FROM used u JOIN devices d ON d.id::text=u.device_id GROUP BY u.device_id`

func deviceBytesTx(ctx context.Context, tx pgx.Tx) (map[string]int64, error) {
	rows, err := tx.Query(ctx, deviceBytesQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id string
		var n int64
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// DeleteCheck is a deletion's preflight, for an owner, on a live number:
// who reads it, which standing service accounts, assistants and keys lose
// it, and which keys for every number stop reaching it. It changes nothing.
func (d *Devices) DeleteCheck(ctx context.Context, tenant, actor, device uuid.UUID) (DeletionCheck, error) {
	var out DeletionCheck
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := ownerNowTx(ctx, tx, tenant, actor); err != nil {
			return err
		}
		var pn string
		err := tx.QueryRow(ctx, `SELECT coalesce(pn, '') FROM devices WHERE id = $1 AND deleted_at IS NULL`, device).Scan(&pn)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT t, t + interval '30 days' FROM (SELECT clock_timestamp() AS t) now`).
			Scan(&out.CheckedAt, &out.RecoverableUntilPreview); err != nil {
			return err
		}
		readers, err := readersTx(ctx, tx, tenant, device)
		if err != nil {
			return err
		}
		out.Readers = []Person{}
		for _, r := range readers {
			if r.UserID != actor {
				out.Readers = append(out.Readers, r.Person)
			}
		}
		if out.ServiceAccounts, err = serviceReadersTx(ctx, tx, tenant, device); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT c.id, c.client_name, coalesce(nullif(u.name, ''), u.email, h.email, ''), c.kind
			FROM mcp_connections c
			JOIN api_key_devices x ON x.api_key_id = c.api_key_id AND x.device_id = $2
			LEFT JOIN users u ON u.id = c.created_by
			LEFT JOIN workspace_member_history h ON h.tenant_id = c.tenant_id AND h.user_id = c.created_by
			WHERE c.tenant_id = $1 AND c.status IN ('pending', 'active', 'reseal')
			ORDER BY c.created_at, c.id`, tenant, device)
		if err != nil {
			return err
		}
		if out.Assistants, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (AssistantRef, error) {
			var a AssistantRef
			err := row.Scan(&a.ID, &a.ClientName, &a.CreatedByName, &a.Kind)
			a.Kind = assistantKind(a.Kind)
			return a, err
		}); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT k.prefix, k.name,
			NOT EXISTS (SELECT 1 FROM api_key_devices o WHERE o.api_key_id = k.id AND o.device_id <> $2)
			FROM api_keys k JOIN api_key_devices x ON x.api_key_id = k.id AND x.device_id = $2
			WHERE k.tenant_id = $1 AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now())
			  AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.api_key_id = k.id)
			ORDER BY k.created_at, k.id`, tenant, device)
		if err != nil {
			return err
		}
		if out.Keys, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (RestrictedKeyRef, error) {
			var k RestrictedKeyRef
			err := row.Scan(&k.ID, &k.Name, &k.OnlyNumber)
			return k, err
		}); err != nil {
			return err
		}
		if out.AllNumberKeys, err = allNumberKeysTx(ctx, tx, tenant); err != nil {
			return err
		}
		bytes, err := deviceBytesTx(ctx, tx)
		if err != nil {
			return err
		}
		out.Bytes = bytes[device.String()]
		out.Session, err = sessionExistsTx(ctx, tx, pn, nil)
		return err
	})
	return out, err
}

// assistantKind names a connection's kind the way an owner reads it: an AI
// authorization, or an assistant.
func assistantKind(kind string) string {
	if kind == KindAI {
		return "ai"
	}
	return "assistant"
}

// Quarantine deletes a linked number, in one transaction: the live owner
// check; the readers the owner acknowledged, which must cover everyone who
// reads it now; the assistant connections whose key names it, ended with
// access_lost; the number taken off every key restricted to it, revoking
// none; its downloads in flight returned to the queue; the row excluded, with
// purge_after 30 days on, paused, its status kept when it was already logged
// out or banned, and the fingerprint of any WhatsApp session it still has
// (with none, logged out at once: there is nothing to log out);
// the readers' and the other owners' notices; everyone else's access bumped,
// so their consoles let go of it, but not the owner's, whose socket carries
// the reply; the deleted event; and a notification every process hears at
// the commit. An already excluded number answers Already, with what it holds.
func (d *Devices) Quarantine(ctx context.Context, tenant, actor, device uuid.UUID, acknowledged []uuid.UUID) (Quarantined, error) {
	out := Quarantined{DeviceID: device}
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := requireOwnerTx(ctx, tx, tenant, actor); err != nil {
			return err
		}
		return withQuarantine(ctx, tx, func() error {
			var deletedAt, purgeAfter *time.Time
			var noLeftover, pending bool
			var statusReason string
			err := tx.QueryRow(ctx, `SELECT deleted_at, purge_after, wa_leftover IS NULL, status_reason,
				lid IS NULL AND pn IS NULL AND last_connected_at IS NULL
				FROM devices WHERE id = $1 FOR UPDATE`, device).Scan(&deletedAt, &purgeAfter, &noLeftover, &statusReason, &pending)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
			if deletedAt != nil {
				out.Already, out.DeletedAt, out.PurgeAfter = true, *deletedAt, *purgeAfter
				out.Unlinked, out.NoteCode = noLeftover, noteCode(!noLeftover, statusReason)
				return nil
			}
			if pending {
				return ErrPendingDevice
			}

			// (c) Everyone who reads it now, the owner included for the
			// event; the others must all have been acknowledged.
			readers, err := readersTx(ctx, tx, tenant, device)
			if err != nil {
				return err
			}
			var others []Person
			var told []uuid.UUID
			readerSubs, readerUsers := readerIDs(readers)
			for _, r := range readers {
				if r.UserID == actor {
					continue
				}
				others = append(others, r.Person)
				told = append(told, r.UserID)
			}
			for _, r := range others {
				if !slices.Contains(acknowledged, r.UserID) {
					return &ErrDeviceHasReaders{Readers: others}
				}
			}

			// (d) Assistant connections whose key names the number end: a
			// renewal must name exactly the old key's numbers, so a
			// narrowed one could never renew again.
			rows, err := tx.Query(ctx, `SELECT c.id, c.client_name, c.kind, c.api_key_id FROM mcp_connections c
				JOIN api_key_devices x ON x.api_key_id = c.api_key_id AND x.device_id = $2
				WHERE c.tenant_id = $1 AND c.status IN ('pending', 'active', 'reseal') ORDER BY c.id`, tenant, device)
			if err != nil {
				return err
			}
			var endedKeys []uuid.UUID
			ended, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (EndedAssistant, error) {
				var a EndedAssistant
				var key uuid.UUID
				err := row.Scan(&a.ID, &a.ClientName, &a.Kind, &key)
				a.Kind = assistantKind(a.Kind)
				endedKeys = append(endedKeys, key)
				return a, err
			})
			if err != nil {
				return err
			}
			for _, a := range ended {
				if _, err := endMCPConnectionTx(ctx, tx, tenant, a.ID.String(), statusRevoked, ReasonAccessLost); err != nil {
					return err
				}
			}
			out.AssistantsEnded = append([]EndedAssistant{}, ended...)

			// (e) Off every key restricted to it. 0026's trigger keeps them
			// restricted and bumps each one's access_version; none is
			// revoked.
			rows, err = tx.Query(ctx, `WITH gone AS (DELETE FROM api_key_devices WHERE device_id = $1 RETURNING api_key_id)
				SELECT k.id, k.prefix, k.name FROM gone JOIN api_keys k ON k.id = gone.api_key_id
				WHERE k.revoked_at IS NULL ORDER BY k.created_at, k.id`, device)
			if err != nil {
				return err
			}
			type narrowedRow struct {
				id  uuid.UUID
				key NarrowedKey
			}
			narrowed, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (narrowedRow, error) {
				var k narrowedRow
				err := row.Scan(&k.id, &k.key.ID, &k.key.Name)
				return k, err
			})
			if err != nil {
				return err
			}
			// A connection's own key is the connection's, reported as ended.
			out.KeysNarrowed = []NarrowedKey{}
			for _, k := range narrowed {
				if !slices.Contains(endedKeys, k.id) {
					out.KeysNarrowed = append(out.KeysNarrowed, k.key)
				}
			}

			// (f) Its downloads in flight go back to the queue, while the
			// number can still be written to.
			if _, err := tx.Exec(ctx, `UPDATE media SET download_status = 'pending', claimed_at = NULL
				WHERE download_status = 'downloading' AND message_uid IN (SELECT uid FROM messages WHERE device_id = $1)`, device); err != nil {
				return err
			}

			// (g) Excluded. One clock for both dates, so the window is
			// exactly 30 days; a dead status is kept, so a recovered number
			// is never offered a resume it cannot do; and the session's
			// fingerprint is in the commit, so it is known even if this
			// process dies before the logout. With no session there is
			// nothing to log out, and that outcome is written here, once:
			// RecordUnlink only reads it back, so a second record of the
			// same deletion (the janitor's, racing the handler's) cannot
			// rewrite a confirmed logout as "already disconnected".
			sessions, err := sessionTableTx(ctx, tx)
			if err != nil {
				return err
			}
			var jid *string
			var reg *int64
			if sessions {
				err := tx.QueryRow(ctx, `SELECT w.jid, w.registration_id FROM whatsmeow_device w
					JOIN devices d ON d.pn = w.jid WHERE d.id = $1`, device).Scan(&jid, &reg)
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
			}
			var lbl, pushName, pn string
			if err := tx.QueryRow(ctx, `WITH now AS (SELECT clock_timestamp() AS t)
				UPDATE devices SET deleted_at = now.t, deleted_by = $2, purge_after = now.t + interval '30 days', paused = true,
				  pause_cause = 'deletion',
				  status = CASE WHEN $3::text IS NULL AND status <> 'banned' THEN 'logged_out'
				                WHEN status IN ('logged_out', 'banned') THEN status ELSE 'offline' END,
				  status_reason = CASE WHEN $3::text IS NULL THEN '`+reasonNoSession+`'
				                       WHEN status IN ('logged_out', 'banned') THEN status_reason ELSE '`+reasonDeleted+`' END,
				  wa_leftover = CASE WHEN $3::text IS NULL THEN NULL
				                     ELSE jsonb_build_object('jid', $3::text, 'registration_id', $4::bigint) END
				FROM now WHERE devices.id = $1
				RETURNING deleted_at, purge_after, label, push_name, coalesce(pn, '')`, device, actor, jid, reg).
				Scan(&out.DeletedAt, &out.PurgeAfter, &lbl, &pushName, &pn); err != nil {
				return err
			}
			if jid != nil && reg != nil {
				out.Session = &WASession{JID: *jid, RegistrationID: *reg}
			}
			itemName, hint := itemLabel(device, lbl, pushName, pn)

			// (h) Its readers, and the workspace's other owners, are told in
			// Wappie's own pages. A pause notice gives way to the deletion's.
			if _, err := tx.Exec(ctx, `DELETE FROM device_notices WHERE device_id = $1 AND kind = 'sync_paused'`, device); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO device_notices (tenant_id, device_id, user_id, kind, label, hint, raised_by, raised_by_kind, until)
				SELECT $1, $2, u, 'number_deleted', $3, $4, $5, 'person', $6
				FROM (SELECT unnest($7::uuid[]) AS u
				      UNION SELECT m.user_id FROM workspace_memberships m JOIN users o ON o.id = m.user_id
				       WHERE m.tenant_id = $1 AND m.role = 'owner' AND m.status = 'active' AND o.status = 'active' AND m.user_id <> $5) people
				ON CONFLICT (tenant_id, device_id, user_id, kind) WHERE seen_at IS NULL DO UPDATE
				SET label = excluded.label, hint = excluded.hint, raised_at = excluded.raised_at, raised_by = excluded.raised_by,
				    raised_by_kind = excluded.raised_by_kind, until = excluded.until, purged_at = NULL`,
				tenant, device, itemName, hint, actor, out.PurgeAfter, told); err != nil {
				return err
			}

			// (i) Everyone else who held a grant or a permission on it
			// reconnects without it; the owner's socket stays, so the reply
			// arrives.
			if _, err := tx.Exec(ctx, `UPDATE workspace_memberships SET access_version = access_version
				WHERE tenant_id = $1 AND user_id <> $2 AND user_id IN (
				  SELECT user_id FROM device_key_grants WHERE device_id = $3
				  UNION SELECT user_id FROM device_permissions WHERE device_id = $3)`, tenant, actor, device); err != nil {
				return err
			}

			// (j) The event, with the readers the number had, the owner
			// among them when they read it.
			sub, err := actorSubTx(ctx, tx, actor)
			if err != nil {
				return err
			}
			if err := recordEvent(ctx, tx, tenant, itemEvent{
				Type: eventDeleted, ItemID: device, DedupeKey: dedupeKey(eventDeleted, device, out.DeletedAt),
				OccurredAt: out.DeletedAt, ActorKind: "person", ActorSub: sub, ActorUserID: &actor,
				ReaderSubs: readerSubs, ReaderUserIDs: readerUsers, Label: itemName, Hint: hint,
				DeletedAt: &out.DeletedAt, PurgeAfter: &out.PurgeAfter,
			}); err != nil {
				return err
			}

			// (k) Every process hears it at the commit, and lets go of the
			// number before its supervisor's next tick.
			_, err = tx.Exec(ctx, `SELECT pg_notify($1, $2)`, DeviceExcludedChannel, tenant.String()+":"+device.String())
			return err
		})
	})
	return out, err
}

// DeviceExcludedChannel is the notification a deletion sends at its commit,
// with "tenant:device" as its payload.
const DeviceExcludedChannel = "wappie_device_excluded"

// ParseDeviceExcluded reads a DeviceExcludedChannel payload.
func ParseDeviceExcluded(payload string) (tenant, device uuid.UUID, err error) {
	t, dev, ok := strings.Cut(payload, ":")
	if !ok {
		return uuid.Nil, uuid.Nil, fmt.Errorf("store: malformed exclusion notice %q", payload)
	}
	if tenant, err = uuid.Parse(t); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	device, err = uuid.Parse(dev)
	return tenant, device, err
}

// Excluded is the state of an excluded number an owner may be told.
type Excluded struct {
	DeletedAt, PurgeAfter time.Time
	Unlinked              bool
	NoteCode              string
}

// GetExcluded is an excluded number, for an owner only: anyone else, and a
// number that is not excluded, gets ErrNotFound.
func (d *Devices) GetExcluded(ctx context.Context, tenant, actor, device uuid.UUID) (Excluded, error) {
	var out Excluded
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := ownerNowTx(ctx, tx, tenant, actor); err != nil {
			if errors.Is(err, ErrOwnerOnly) {
				return ErrNotFound
			}
			return err
		}
		return withQuarantine(ctx, tx, func() error {
			var leftover bool
			var reason string
			err := tx.QueryRow(ctx, `SELECT deleted_at, purge_after, wa_leftover IS NOT NULL, status_reason
				FROM devices WHERE id = $1 AND deleted_at IS NOT NULL`, device).Scan(&out.DeletedAt, &out.PurgeAfter, &leftover, &reason)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			out.Unlinked, out.NoteCode = !leftover, noteCode(leftover, reason)
			return err
		})
	})
	return out, err
}

// UnlinkRecord is what RecordUnlink wrote: whether a WhatsApp session is
// left, and what to say about it.
type UnlinkRecord struct {
	Unlinked bool
	NoteCode string
}

// RecordUnlink records what the logout after a deletion achieved, on the
// excluded row with that deletedAt only, so it never touches a number an
// owner has recovered (ErrNotFound then). A banned number stays banned on
// every branch.
//
//   - No fingerprint left: Quarantine found no session ("no session at
//     deletion", written in its commit), or an earlier record confirmed the
//     logout. Nothing is written; the reply is the stored outcome, so a
//     second record of one deletion never rewrites the first.
//   - The logout acknowledged and the fingerprinted session gone: logged
//     out, the fingerprint cleared, and the session's privacy tokens, which
//     whatsmeow keeps with no foreign key, deleted.
//   - Otherwise the fingerprint stays, with one more attempt, for the
//     janitor's retry and, at the end, the purge.
//
// An acknowledged logout is recorded while the device lock is still held
// (wa.Registry.Unlink's record), so a recovery cannot land between the
// logout and its record.
func (d *Devices) RecordUnlink(ctx context.Context, tenant, device uuid.UUID, deletedAt time.Time, acknowledged bool) (UnlinkRecord, error) {
	var out UnlinkRecord
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		return withQuarantine(ctx, tx, func() error {
			var jid *string
			var reg *int64
			var reason string
			err := tx.QueryRow(ctx, `SELECT wa_leftover->>'jid', (wa_leftover->>'registration_id')::bigint, status_reason
				FROM devices WHERE id = $1 AND deleted_at = $2 FOR UPDATE`, device, deletedAt).Scan(&jid, &reg, &reason)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
			if jid == nil {
				// Nothing left to log out: Quarantine found no session, or a
				// record of this deletion already confirmed the logout. The
				// outcome is the stored one, and it is never written twice.
				out = UnlinkRecord{Unlinked: true, NoteCode: noteCode(false, reason)}
				return nil
			}
			if acknowledged {
				left, err := sessionExistsTx(ctx, tx, *jid, reg)
				if err != nil {
					return err
				}
				if !left {
					out = UnlinkRecord{Unlinked: true}
					if _, err := tx.Exec(ctx, `UPDATE devices SET `+loggedOutStatus+`, status_reason = $3, wa_leftover = NULL
						WHERE id = $1 AND deleted_at = $2`, device, deletedAt, reasonUnlinkedWhenGone); err != nil {
						return err
					}
					return deletePrivacyTokensTx(ctx, tx, *jid)
				}
			}
			out = UnlinkRecord{NoteCode: NoteUnlinkUnconfirmed}
			_, err = tx.Exec(ctx, `UPDATE devices SET wa_leftover = wa_leftover ||
				jsonb_build_object('attempts', coalesce((wa_leftover->>'attempts')::int, 0) + 1)
				WHERE id = $1 AND deleted_at = $2`, device, deletedAt)
			return err
		})
	})
	return out, err
}

// loggedOutStatus is the status a confirmed logout leaves: logged out, unless
// WhatsApp banned the number, which every branch keeps.
const loggedOutStatus = `status = CASE WHEN status = 'banned' THEN status ELSE 'logged_out' END`

// deletePrivacyTokensTx deletes the privacy tokens of a session that has just
// gone, which whatsmeow keeps with no foreign key, so they are nobody's:
// unless a phone linked again under the same JID holds a session now.
func deletePrivacyTokensTx(ctx context.Context, tx pgx.Tx, jid string) error {
	var tokens bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('whatsmeow_privacy_tokens') IS NOT NULL`).Scan(&tokens); err != nil || !tokens {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM whatsmeow_privacy_tokens WHERE our_jid = $1
		AND NOT EXISTS (SELECT 1 FROM whatsmeow_device WHERE jid = $1)`, jid)
	return err
}

// StillExcluded reports whether the number is still excluded by the deletion
// at deletedAt. Every logout asks it right before it calls WhatsApp, under
// the device lock, so none runs on a number an owner has recovered, or
// deleted again since. With reg set (the janitor's retry), the fingerprint
// must also still be that registration, and the session store must still
// hold exactly that session: a phone linked again under the same JID has
// another registration id and is never logged out.
func (d *Devices) StillExcluded(ctx context.Context, tenant, device uuid.UUID, deletedAt time.Time, reg *int64) (bool, error) {
	var still bool
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		return withQuarantine(ctx, tx, func() error {
			var jid *string
			err := tx.QueryRow(ctx, `SELECT wa_leftover->>'jid' FROM devices WHERE id = $1 AND deleted_at = $2
				AND ($3::bigint IS NULL OR (wa_leftover->>'registration_id')::bigint = $3)`, device, deletedAt, reg).Scan(&jid)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil || reg == nil {
				still = err == nil
				return err
			}
			if jid == nil {
				return nil
			}
			still, err = sessionExistsTx(ctx, tx, *jid, reg)
			return err
		})
	})
	return still, err
}

// Leftover is a session a deletion's logout did not confirm.
type Leftover struct {
	DeviceID  uuid.UUID
	DeletedAt time.Time
	WASession
	Attempts int
	// Present is the fingerprinted session still in the session store.
	// Gone, the logout went through and only its record was lost.
	Present bool
}

// MaxUnlinkAttempts is how many logouts one session gets, the deletion's
// own included, so the janitor tries at most MaxUnlinkAttempts-1 more; after
// them the purge removes it by its fingerprint.
const MaxUnlinkAttempts = 3

// LeftoverSessions is the excluded numbers of a workspace whose session may
// have survived the deletion, for the janitor's retry: not logged out, fewer
// than MaxUnlinkAttempts attempts, and no purge started.
func (d *Devices) LeftoverSessions(ctx context.Context, tenant uuid.UUID) ([]Leftover, error) {
	var out []Leftover
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		return withQuarantine(ctx, tx, func() error {
			rows, err := tx.Query(ctx, `SELECT id, deleted_at, wa_leftover->>'jid', (wa_leftover->>'registration_id')::bigint,
				coalesce((wa_leftover->>'attempts')::int, 0)
				FROM devices WHERE deleted_at IS NOT NULL AND wa_leftover IS NOT NULL AND purge_started_at IS NULL
				  AND status <> 'logged_out' AND coalesce((wa_leftover->>'attempts')::int, 0) < $1
				ORDER BY deleted_at, id`, MaxUnlinkAttempts)
			if err != nil {
				return err
			}
			if out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Leftover, error) {
				var l Leftover
				err := row.Scan(&l.DeviceID, &l.DeletedAt, &l.JID, &l.RegistrationID, &l.Attempts)
				return l, err
			}); err != nil {
				return err
			}
			for i := range out {
				reg := out[i].RegistrationID
				if out[i].Present, err = sessionExistsTx(ctx, tx, out[i].JID, &reg); err != nil {
					return err
				}
			}
			return nil
		})
	})
	return out, err
}

// DeletedNumber is one excluded number, as an owner sees it in the list of
// deleted numbers. The label inputs are raw: only owners see them.
type DeletedNumber struct {
	DeviceID         uuid.UUID
	Label, PushName  string
	PN               string
	DeletedAt        time.Time
	DeletedByName    string
	RecoverableUntil time.Time
	// Recoverable is inside the 30 days with no purge started, on the
	// database's clock; Purging is a purge under way.
	Recoverable, Purging bool
	Bytes                int64
	// Unlinked and NoteCode are what the deletion's reply said about
	// WhatsApp, from the stored state, as GetExcluded has them: a console
	// whose reply was lost words its banner from the list.
	Unlinked bool
	NoteCode string
	RecoveryState
}

// RecoveryState is what a recovery gives back, and how.
type RecoveryState struct {
	Status       wa.Status
	StatusReason string
	// LoggedOut is a number WhatsApp logged out: read-only once recovered.
	LoggedOut bool
	// CanResume is a status that can sync again with a session to do it.
	CanResume bool
	// KeyHolders counts who can still open its current archive.
	KeyHolders int
}

// recoveryStateTx fills a number's recovery state. sessionPresent is whether
// a session it could sync with is left.
func recoveryStateTx(ctx context.Context, tx pgx.Tx, device uuid.UUID, status wa.Status, reason string, sessionPresent bool) (RecoveryState, error) {
	out := RecoveryState{Status: status, StatusReason: reason, LoggedOut: status == wa.StatusLoggedOut}
	out.CanResume = !status.Terminal() && sessionPresent
	var err error
	out.KeyHolders, err = keyHoldersTx(ctx, tx, device)
	return out, err
}

// ListDeleted is the workspace's excluded numbers, for an owner, newest
// deletion first.
func (d *Devices) ListDeleted(ctx context.Context, tenant, actor uuid.UUID) ([]DeletedNumber, error) {
	out := []DeletedNumber{}
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := ownerNowTx(ctx, tx, tenant, actor); err != nil {
			return err
		}
		return withQuarantine(ctx, tx, func() error {
			rows, err := tx.Query(ctx, `SELECT d.id, d.label, d.push_name, coalesce(d.pn, ''), d.deleted_at,
				coalesce(nullif(u.name, ''), u.email, h.email, ''), d.purge_after,
				d.purge_started_at IS NULL AND d.purge_after > clock_timestamp(), d.purge_started_at IS NOT NULL,
				d.status, d.status_reason, d.wa_leftover IS NOT NULL, d.wa_leftover->>'jid', (d.wa_leftover->>'registration_id')::bigint
				FROM devices d
				LEFT JOIN users u ON u.id = d.deleted_by
				LEFT JOIN workspace_member_history h ON h.tenant_id = d.tenant_id AND h.user_id = d.deleted_by
				WHERE d.deleted_at IS NOT NULL ORDER BY d.deleted_at DESC, d.id`)
			if err != nil {
				return err
			}
			type row struct {
				DeletedNumber
				leftover bool
				jid      *string
				reg      *int64
			}
			listed, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
				var n row
				err := r.Scan(&n.DeviceID, &n.Label, &n.PushName, &n.PN, &n.DeletedAt, &n.DeletedByName, &n.RecoverableUntil,
					&n.Recoverable, &n.Purging, &n.Status, &n.StatusReason, &n.leftover, &n.jid, &n.reg)
				n.Unlinked, n.NoteCode = !n.leftover, noteCode(n.leftover, n.StatusReason)
				return n, err
			})
			if err != nil || len(listed) == 0 {
				// The console asks on every owner's devices view, and the
				// list is usually empty: no storage scan then.
				return err
			}
			bytes, err := deviceBytesTx(ctx, tx)
			if err != nil {
				return err
			}
			for _, n := range listed {
				present := false
				if n.jid != nil {
					if present, err = sessionExistsTx(ctx, tx, *n.jid, n.reg); err != nil {
						return err
					}
				}
				if n.RecoveryState, err = recoveryStateTx(ctx, tx, n.DeviceID, n.Status, n.StatusReason, present); err != nil {
					return err
				}
				n.Bytes = bytes[n.DeviceID.String()]
				out = append(out, n.DeletedNumber)
			}
			return nil
		})
	})
	return out, err
}

// RecoveryCheck is a recovery's preflight: who regains the number.
type RecoveryCheck struct {
	Readers         []Person
	ServiceAccounts []ServiceAccountRef
	// Others regain the number without reading it: Send, or a member's
	// Manage.
	Others        []OtherAccess
	AllNumberKeys []AllNumberKey
	Recoverable   bool
	RecoveryState
}

// OtherAccess is someone a recovery gives the number back to who does not
// read it: a person, or a standing service account (and with it every key
// acting as it), whose permission sends through it, or a member's that
// manages it. Why holds "send", "manage" or both. An owner's or an admin's
// stored Manage adds nothing to their role and is not listed, as for a
// transfer (the plan's D16).
type OtherAccess struct {
	ID    uuid.UUID `json:"id"`
	Kind  string    `json:"kind"`
	Name  string    `json:"name"`
	Email string    `json:"email,omitempty"`
	Why   []string  `json:"why"`
}

// recoveryOthersTx is everyone, the actor left out, who holds Send or a
// member's Manage on the number and is in neither list given: the readers
// and the standing service accounts that read it. A connection's service
// account holds copies of a person's access and is never listed.
func recoveryOthersTx(ctx context.Context, tx pgx.Tx, tenant, device, actor uuid.UUID, readers []Person, services []ServiceAccountRef) ([]OtherAccess, error) {
	rows, err := tx.Query(ctx, `SELECT u.id, m.role = 'service', u.name, u.email, p.can_send, p.can_manage AND m.role NOT IN ('owner', 'admin')
		FROM device_permissions p
		JOIN devices d ON d.id = p.device_id AND d.tenant_id = p.tenant_id
		JOIN workspace_memberships m ON m.tenant_id = p.tenant_id AND m.user_id = p.user_id
		JOIN users u ON u.id = m.user_id
		WHERE p.tenant_id = $1 AND p.device_id = $2 AND p.user_id <> $3 AND m.status = 'active' AND u.status = 'active'
		  AND (p.can_send OR (p.can_manage AND m.role NOT IN ('owner', 'admin')))
		  AND (m.role <> 'service' AND u.role <> 'service' AND (m.expires_at IS NULL OR m.expires_at > now())
		       OR m.role = 'service' AND m.expires_at IS NULL
		          AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = m.user_id))
		ORDER BY m.role = 'service', lower(u.email), u.id`, tenant, device, actor)
	if err != nil {
		return nil, err
	}
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (OtherAccess, error) {
		var o OtherAccess
		var service, send, manage bool
		var email string
		err := row.Scan(&o.ID, &service, &o.Name, &email, &send, &manage)
		o.Kind, o.Email = "person", email
		if service {
			o.Kind, o.Name, o.Email = "service", ServiceName(User{Email: email, Role: RoleService}), ""
		}
		if send {
			o.Why = append(o.Why, "send")
		}
		if manage {
			o.Why = append(o.Why, "manage")
		}
		return o, err
	})
	if err != nil {
		return nil, err
	}
	out := []OtherAccess{}
	for _, o := range all {
		if slices.ContainsFunc(readers, func(p Person) bool { return p.UserID == o.ID }) ||
			slices.ContainsFunc(services, func(s ServiceAccountRef) bool { return s.ID == o.ID }) {
			continue
		}
		out = append(out, o)
	}
	return out, nil
}

// RecoverCheck is a recovery's preflight, for an owner, on an excluded
// number: the people whose grants and permissions come back (D10, the owner
// left out), the standing service accounts that read it again, everyone
// else who sends through it or manages it again, and the keys for every
// number that reach it again. It changes nothing.
func (d *Devices) RecoverCheck(ctx context.Context, tenant, actor, device uuid.UUID) (RecoveryCheck, error) {
	var out RecoveryCheck
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := ownerNowTx(ctx, tx, tenant, actor); err != nil {
			return err
		}
		return withQuarantine(ctx, tx, func() error {
			var status wa.Status
			var reason string
			var jid *string
			var reg *int64
			err := tx.QueryRow(ctx, `SELECT purge_started_at IS NULL AND purge_after > clock_timestamp(), status, status_reason,
				wa_leftover->>'jid', (wa_leftover->>'registration_id')::bigint
				FROM devices WHERE id = $1 AND deleted_at IS NOT NULL`, device).Scan(&out.Recoverable, &status, &reason, &jid, &reg)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
			readers, err := readersTx(ctx, tx, tenant, device)
			if err != nil {
				return err
			}
			out.Readers = []Person{}
			for _, r := range readers {
				if r.UserID != actor {
					out.Readers = append(out.Readers, r.Person)
				}
			}
			if out.ServiceAccounts, err = serviceReadersTx(ctx, tx, tenant, device); err != nil {
				return err
			}
			if out.Others, err = recoveryOthersTx(ctx, tx, tenant, device, actor, out.Readers, out.ServiceAccounts); err != nil {
				return err
			}
			if out.AllNumberKeys, err = allNumberKeysTx(ctx, tx, tenant); err != nil {
				return err
			}
			present := false
			if jid != nil {
				if present, err = sessionExistsTx(ctx, tx, *jid, reg); err != nil {
					return err
				}
			}
			out.RecoveryState, err = recoveryStateTx(ctx, tx, device, status, reason, present)
			return err
		})
	})
	return out, err
}

// Recovered is what a recovery left, or with Already, a number that was
// already live.
type Recovered struct {
	Already bool
	RecoveryState
}

// Recover brings an excluded number back, paused, for an owner, in one
// transaction: the live owner check, which locks the workspace; a live row
// with that id answers Already, so a retry whose reply was lost is never
// refused; the window, closed past purge_after or once a purge started; the
// device lock, held by a running client or a deletion's logout; the plan's
// capacity, counted with the number still hidden, as check_device_capacity
// counts it; the row un-deleted, with the status RecordUnlink left and its
// pause now the owner's (pause_cause person), which only an explicit resume
// ends; its deletion notices gone; everyone else's access bumped, so their
// consoles list it again; and the recovered event. What does not come back: the
// assistant connections, the number's place in restricted keys, and anything
// of a person who left or was disabled meanwhile.
func (d *Devices) Recover(ctx context.Context, tenant, actor, device uuid.UUID) (Recovered, error) {
	var out Recovered
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := requireOwnerTx(ctx, tx, tenant, actor); err != nil {
			return err
		}
		var deletedAt time.Time
		var leftJID *string
		var leftReg *int64
		if err := withQuarantine(ctx, tx, func() error {
			var live bool
			var status wa.Status
			var reason, pn string
			var stamp *time.Time
			var closed bool
			err := tx.QueryRow(ctx, `SELECT deleted_at IS NULL, deleted_at, status, status_reason, coalesce(pn, ''),
				coalesce(purge_started_at IS NOT NULL OR purge_after <= clock_timestamp(), false),
				wa_leftover->>'jid', (wa_leftover->>'registration_id')::bigint
				FROM devices WHERE id = $1 FOR UPDATE`, device).Scan(&live, &stamp, &status, &reason, &pn, &closed, &leftJID, &leftReg)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
			if live {
				present, err := sessionExistsTx(ctx, tx, pn, nil)
				if err != nil {
					return err
				}
				out.Already = true
				out.RecoveryState, err = recoveryStateTx(ctx, tx, device, status, reason, present)
				return err
			}
			if closed {
				return ErrRecoveryClosed
			}
			acquired, err := pg.TryLockTx(ctx, tx, "device:"+device.String())
			if err != nil {
				return err
			}
			if !acquired {
				return ErrDeviceBusy
			}
			deletedAt = *stamp
			return nil
		}); err != nil || out.Already {
			return err
		}

		// Capacity with the number still hidden, so it counts as the slot it
		// would take back. A workspace with no capacity row has no limit.
		var capacity *int64
		var used int64
		if err := tx.QueryRow(ctx, `SELECT (SELECT max_devices FROM workspace_capacity WHERE tenant_id = $1), workspace_device_usage($1)`,
			tenant).Scan(&capacity, &used); err != nil {
			return err
		}
		if capacity != nil && used >= *capacity {
			return ErrCapacity
		}

		return withQuarantine(ctx, tx, func() error {
			// A fingerprinted session that is gone was logged out, and only
			// its record is missing (a logout that ended between its answer
			// and RecordUnlink): the device lock is ours, so no logout is
			// still running, and the number comes back as RecordUnlink's
			// acknowledged branch leaves it, never offered a resume.
			gone := false
			if leftJID != nil {
				present, err := sessionExistsTx(ctx, tx, *leftJID, leftReg)
				if err != nil {
					return err
				}
				gone = !present
			}
			var status wa.Status
			var reason, pn, name, pushName string
			err := tx.QueryRow(ctx, `UPDATE devices SET deleted_at = NULL, deleted_by = NULL, purge_after = NULL, wa_leftover = NULL,
				pause_cause = 'person',
				status = CASE WHEN $3 AND status <> 'banned' THEN 'logged_out' ELSE status END,
				status_reason = CASE WHEN $3 THEN '`+reasonUnlinkedWhenGone+`' ELSE status_reason END
				WHERE id = $1 AND deleted_at = $2 RETURNING status, status_reason, coalesce(pn, ''), label, push_name`,
				device, deletedAt, gone).Scan(&status, &reason, &pn, &name, &pushName)
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrIdentityInUse
			}
			if err != nil {
				return err
			}
			if gone {
				if err := deletePrivacyTokensTx(ctx, tx, *leftJID); err != nil {
					return err
				}
			}
			present, err := sessionExistsTx(ctx, tx, pn, nil)
			if err != nil {
				return err
			}
			if out.RecoveryState, err = recoveryStateTx(ctx, tx, device, status, reason, present); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM device_notices WHERE device_id = $1 AND kind = 'number_deleted'`, device); err != nil {
				return err
			}
			if err := recoveredStrandedTx(ctx, tx, device); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE workspace_memberships SET access_version = access_version
				WHERE tenant_id = $1 AND user_id <> $2 AND user_id IN (
				  SELECT user_id FROM device_key_grants WHERE device_id = $3
				  UNION SELECT user_id FROM device_permissions WHERE device_id = $3)`, tenant, actor, device); err != nil {
				return err
			}
			readers, err := readersTx(ctx, tx, tenant, device)
			if err != nil {
				return err
			}
			subs, users := readerIDs(readers)
			sub, err := actorSubTx(ctx, tx, actor)
			if err != nil {
				return err
			}
			var at time.Time
			if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
				return err
			}
			itemName, hint := itemLabel(device, name, pushName, pn)
			return recordEvent(ctx, tx, tenant, itemEvent{
				Type: eventRecovered, ItemID: device, DedupeKey: dedupeKey(eventRecovered, device, deletedAt),
				OccurredAt: at, ActorKind: "person", ActorSub: sub, ActorUserID: &actor, ReaderSubs: subs, ReaderUserIDs: users,
				Label: itemName, Hint: hint, DeletedAt: &deletedAt,
			})
		})
	})
	return out, err
}
