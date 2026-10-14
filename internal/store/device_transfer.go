package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

type PersonalTransferPreview struct {
	DeviceID            string `json:"device_id"`
	TargetWorkspaceID   string `json:"target_workspace_id"`
	TargetWorkspaceName string `json:"target_workspace_name"`
	Eligible            bool   `json:"eligible"`
	Reason              string `json:"reason"`
	// ReasonCode is others_have_access when someone else still has access
	// to the number (decision 0040), with Others saying who and why.
	ReasonCode   string           `json:"reason_code,omitempty"`
	Others       []TransferAccess `json:"others,omitempty"`
	ArchiveBytes int64            `json:"archive_bytes"`
	ObjectBytes  int64            `json:"object_bytes"`
	// For an owner: the actor's own keys restricted to the number, which
	// stop reaching it; the keys for every number, which do too; and the
	// actor's own assistants and AI authorizations connected to it, which
	// the move ends. A transfer's reply says which it ended and narrowed.
	Keys            []NarrowedKey    `json:"keys,omitempty"`
	AllNumberKeys   []AllNumberKey   `json:"all_number_keys,omitempty"`
	AssistantsEnded []EndedAssistant `json:"assistants_ended,omitempty"`
	KeysNarrowed    []NarrowedKey    `json:"keys_narrowed,omitempty"`
}

// TransferDenied contains a user-readable explanation, never database details.
// Code is set for a refusal a console words itself (others_have_access, with
// Others).
type TransferDenied struct {
	Reason string
	Code   string
	Others []TransferAccess
}

func (e *TransferDenied) Error() string { return e.Reason }

const movingInventory = `tenant_id=$1 AND (
 (source IN ('chats','receipts','contacts','group_participants') AND identity::jsonb->>0=($2::uuid)::text)
 OR (source IN ('messages','media','ai_derived') AND (CASE WHEN source IN ('messages','media','ai_derived') THEN identity::jsonb->>0 END)::uuid IN (SELECT uid FROM messages WHERE device_id=$2))
 OR (source='group_changes' AND (CASE WHEN source='group_changes' THEN identity::jsonb->>0 END)::bigint IN (SELECT id FROM group_changes WHERE device_id=$2)))`

func transferPreviewTx(ctx context.Context, tx pgx.Tx, source, actor, device uuid.UUID) (out PersonalTransferPreview, resultErr error) {
	out = PersonalTransferPreview{DeviceID: device.String()}
	var kind, status string
	if err := tx.QueryRow(ctx, `SELECT kind,status FROM tenants WHERE id=$1 FOR UPDATE`, source).Scan(&kind, &status); err != nil {
		return out, err
	}
	role, err := lockWorkspaceManager(ctx, tx, source, actor)
	if errors.Is(err, ErrMembershipForbidden) || role != "owner" || kind != "team" || status != "active" {
		out.Reason = "Somente o proprietário de um Team ativo pode mover este número."
		return out, nil
	}
	if err != nil {
		return out, err
	}
	var owners int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM workspace_memberships WHERE tenant_id=$1 AND role='owner'`, source).Scan(&owners); err != nil {
		return out, err
	}
	if owners != 1 {
		out.Reason = "O Team precisa ter você como único proprietário."
		return out, nil
	}
	var exists, missingKeys bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1),EXISTS(SELECT 1 FROM device_archive_keys k WHERE device_id=$1 AND NOT EXISTS(SELECT 1 FROM device_key_grants g WHERE g.device_id=k.device_id AND g.epoch=k.epoch AND g.user_id=$2))`, device, actor).Scan(&exists, &missingKeys); err != nil {
		return out, err
	}
	if !exists {
		return out, ErrNotFound
	}
	if missingKeys {
		out.Reason = "Você precisa ter acesso às chaves de todo o histórico deste número."
		return out, nil
	}
	// Nobody else may have access to it (decision 0040), checked here, under
	// the source's row lock, and again by the transfer under the locks it
	// holds to its commit: every write that gives access takes that lock
	// first, and one that waits for it finds the number gone.
	if out.Others, err = otherAccessTx(ctx, tx, source, device, actor); err != nil {
		return out, err
	}
	if out.Keys, err = ownRestrictedKeysTx(ctx, tx, source, device, actor); err != nil {
		return out, err
	}
	if out.AllNumberKeys, err = allNumberKeysTx(ctx, tx, source); err != nil {
		return out, err
	}
	if out.AssistantsEnded, err = ownConnectionsTx(ctx, tx, source, device, actor); err != nil {
		return out, err
	}
	if len(out.Others) > 0 {
		out.Reason, out.ReasonCode = othersHaveAccess, ReasonOthersHaveAccess
		return out, nil
	}
	out.Others = nil
	var target uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id,name,status FROM tenants WHERE kind='personal' AND personal_owner_id=$1`, actor).Scan(&target, &out.TargetWorkspaceName, &status); err != nil {
		return out, err
	}
	out.TargetWorkspaceID = target.String()
	if status != "active" {
		out.Reason = "Seu Personal precisa estar ativo."
		return out, nil
	}
	if err = tx.QueryRow(ctx, `SELECT coalesce(sum(bytes),0) FROM storage_inventory WHERE `+movingInventory, source, device).Scan(&out.ArchiveBytes); err != nil {
		return out, err
	}
	// Include all confirmed objects for this number, including objects shared
	// with other Team numbers. Personal charges each key once in its own scope.
	if err = tx.QueryRow(ctx, `SELECT coalesce(sum(bytes),0) FROM storage_objects WHERE tenant_id=$1 AND object_key IN (
 SELECT d.object_key FROM media d JOIN messages m ON m.uid=d.message_uid WHERE m.device_id=$2 AND d.object_key IS NOT NULL)`, source, device).Scan(&out.ObjectBytes); err != nil {
		return out, err
	}
	var objectKeys []string
	var objectSizes []int64
	rows, e := tx.Query(ctx, `SELECT object_key,bytes FROM storage_objects WHERE tenant_id=$1 AND object_key IN (SELECT d.object_key FROM media d JOIN messages m ON m.uid=d.message_uid WHERE m.device_id=$2 AND d.object_key IS NOT NULL) ORDER BY object_key`, source, device)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var key string
		var size int64
		if e = rows.Scan(&key, &size); e != nil {
			rows.Close()
			return out, e
		}
		objectKeys = append(objectKeys, key)
		objectSizes = append(objectSizes, size)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return out, e
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, target.String()); err != nil {
		return out, err
	}
	defer func() {
		_, restoreErr := tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, source.String())
		if resultErr == nil {
			resultErr = restoreErr
		}
	}()
	if len(objectKeys) > 0 {
		if err = tx.QueryRow(ctx, `SELECT coalesce(sum(greatest(i.bytes-coalesce(o.bytes,0),0)),0) FROM unnest($1::text[],$2::bigint[]) AS i(key,bytes) LEFT JOIN storage_objects o ON o.object_key=i.key AND o.tenant_id=$3`, objectKeys, objectSizes, target).Scan(&out.ObjectBytes); err != nil {
			return out, err
		}
	}
	var capacity *int
	var used int64
	var bytes int64
	var limit *int64
	var paused bool
	if err = tx.QueryRow(ctx, `SELECT (SELECT max_devices FROM workspace_capacity WHERE tenant_id=$1),workspace_device_usage($1),storage_archive_bytes+storage_object_bytes,storage_limit_bytes,storage_paused_at IS NOT NULL FROM tenants WHERE id=$1`, target).Scan(&capacity, &used, &bytes, &limit, &paused); err != nil {
		return out, err
	}
	if capacity != nil && used >= int64(*capacity) {
		out.Reason = "Seu Personal precisa de um vínculo disponível para receber este número."
		return out, nil
	}
	if paused || limit != nil && bytes+out.ArchiveBytes+out.ObjectBytes > *limit {
		out.Reason = "Seu Personal precisa de espaço de armazenamento disponível para receber todo o histórico."
		return out, nil
	}
	out.Eligible = true
	return out, nil
}

// MovePause is the pause a transfer's handler makes before the move. Seq
// is the pause count it left; Changed is false when the number was paused
// already, and the handler then has nothing to undo.
type MovePause struct {
	Changed bool
	Seq     int64
}

// PauseForMove pauses a live number before its move, in one statement, and
// says whether this call paused it. It is Wappie's own pause: it tells
// nobody and records nothing (the plan's section 5).
func (d *Devices) PauseForMove(ctx context.Context, tenant, device uuid.UUID) (MovePause, error) {
	var out MovePause
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `UPDATE devices SET paused = true, pause_seq = pause_seq + 1 WHERE id = $1 AND NOT paused
			RETURNING pause_seq`, device).Scan(&out.Seq)
		if err == nil {
			out.Changed = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT pause_seq FROM devices WHERE id = $1`, device).Scan(&out.Seq)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	return out, err
}

// UndoMovePause takes back a transfer's own pause after a move that did not
// happen, unless the number was paused again since: a person's or a key's
// stop (which finds it paused and changes nothing else) or another of
// Wappie's own pauses then stands, and so does a resume. It reports whether
// it unpaused the number, and ErrNotFound when the number is no longer in
// the workspace (the move committed and only its answer was lost, or it was
// deleted).
func (d *Devices) UndoMovePause(ctx context.Context, tenant, device uuid.UUID, p MovePause) (bool, error) {
	if !p.Changed {
		return false, nil
	}
	var undone bool
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE devices SET paused = false WHERE id = $1 AND paused AND pause_seq = $2`, device, p.Seq)
		if err != nil {
			return err
		}
		if undone = tag.RowsAffected() == 1; undone {
			return nil
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1)`, device).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		return nil
	})
	return undone, err
}

func (d *Devices) PreviewPersonalTransfer(ctx context.Context, source, actor, device uuid.UUID) (PersonalTransferPreview, error) {
	var out PersonalTransferPreview
	err := pg.InTenantTx(ctx, d.pool, source.String(), func(tx pgx.Tx) error {
		var err error
		out, err = transferPreviewTx(ctx, tx, source, actor, device)
		return err
	})
	return out, err
}

// TransferPersonal changes ownership in a single transaction. Both workspaces
// are locked in UUID order; the supervisor lock excludes running WhatsApp
// clients. Original envelopes and object keys remain untouched. Objects acquire
// a destination ownership claim before the source claim may be removed.
// The device stays paused so resuming capture is an explicit destination action.
//
// It moves only a number nobody else has access to (decision 0040): the
// preview's refusal is decided again here, under the locks held to the
// commit, and returns a TransferDenied with others_have_access and the list.
// The actor's own assistants and AI authorizations connected to the number
// end (access_lost), the actor's own keys restricted to it lose it, and the
// Team records moved_out, with the readers it had: at most the actor.
func (d *Devices) TransferPersonal(ctx context.Context, source, actor, device, target uuid.UUID) (PersonalTransferPreview, error) {
	var out PersonalTransferPreview
	err := pg.InTenantTx(ctx, d.pool, source.String(), func(tx pgx.Tx) error {
		// Do not use a caller-supplied target to choose authority or a workspace lock.
		var own uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, actor).Scan(&own); err != nil {
			return err
		}
		if own != target {
			return &TransferDenied{Reason: "O destino precisa ser o seu Personal."}
		}
		if _, err := tx.Exec(ctx, `SELECT id FROM tenants WHERE id IN ($1,$2) ORDER BY id FOR UPDATE`, source, target); err != nil {
			return err
		}
		var err error
		out, err = transferPreviewTx(ctx, tx, source, actor, device)
		if err != nil {
			return err
		}
		if !out.Eligible {
			return &TransferDenied{Reason: out.Reason, Code: out.ReasonCode, Others: out.Others}
		}
		var paused bool
		if err = tx.QueryRow(ctx, `SELECT paused FROM devices WHERE id=$1 FOR UPDATE`, device).Scan(&paused); err != nil {
			return err
		}
		if !paused {
			return &TransferDenied{Reason: "Pause o número antes de movê-lo."}
		}
		acquired, err := pg.TryLockTx(ctx, tx, "device:"+device.String())
		if err != nil {
			return err
		}
		if !acquired {
			return &TransferDenied{Reason: "A conexão ainda está encerrando. Aguarde e tente novamente."}
		}
		// What the moved_out event keeps, read while the number is still the
		// Team's: its readers (after the refusal, at most the actor) and its
		// label. Once the row moves, the Team's readers find nobody.
		readers, err := readersTx(ctx, tx, source, device)
		if err != nil {
			return err
		}
		var readerSubs []uuid.UUID
		for _, r := range readers {
			if r.sub != nil {
				readerSubs = append(readerSubs, *r.sub)
			}
		}
		var name, pushName, pn string
		if err = tx.QueryRow(ctx, `SELECT label, push_name, coalesce(pn, '') FROM devices WHERE id=$1`, device).Scan(&name, &pushName, &pn); err != nil {
			return err
		}
		// The actor's own assistants and AI authorizations connected to the
		// number end, as a deletion ends them: a renewal must name exactly
		// the old key's numbers, so a narrowed one could never renew.
		ended, err := ownConnectionsTx(ctx, tx, source, device, actor)
		if err != nil {
			return err
		}
		for _, a := range ended {
			if _, err := endMCPConnectionTx(ctx, tx, source, a.ID.String(), statusRevoked, ReasonAccessLost); err != nil {
				return err
			}
		}
		out.AssistantsEnded = ended
		// All database work is atomic; a closed browser or failed check rolls it back.
		if _, err = tx.Exec(ctx, `SELECT set_config('app.device_move_id',$1,true),set_config('app.device_move_source',$2,true),set_config('app.device_move_target',$3,true),set_config('app.storage_reconcile','true',true),set_config('statement_timeout','120s',true)`, device.String(), source.String(), target.String()); err != nil {
			return err
		}
		// Acquire physical object claims in a stable order before row triggers run.
		if _, err = tx.Exec(ctx, `INSERT INTO storage_objects(tenant_id,object_key,bytes)
   SELECT $3,object_key,bytes FROM storage_objects WHERE tenant_id=$1 AND object_key IN (
    SELECT d.object_key FROM media d JOIN messages m ON m.uid=d.message_uid WHERE m.device_id=$2 AND d.object_key IS NOT NULL)
   ORDER BY object_key ON CONFLICT(tenant_id,object_key) DO UPDATE SET bytes=greatest(storage_objects.bytes,excluded.bytes)`, source, device, target); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM storage_inventory WHERE `+movingInventory, source, device); err != nil {
			return err
		}
		var offset, sourceLast int64
		if err = tx.QueryRow(ctx, `SELECT (SELECT last_seq FROM tenants WHERE id=$1),(SELECT last_seq FROM tenants WHERE id=$2)`, target, source).Scan(&offset, &sourceLast); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, target.String()); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE devices SET tenant_id=$2,status='offline',status_reason='moved to Personal',paused=true WHERE id=$1`, device, target); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, source.String()); err != nil {
			return err
		}
		// Remove Team member and machine permissions. No grants are manufactured.
		// The actor's own keys restricted to the number lose it, revoking none.
		if out.KeysNarrowed, err = ownRestrictedKeysTx(ctx, tx, source, device, actor); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM api_key_devices WHERE device_id=$1`, device); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM device_permissions WHERE device_id=$1 AND user_id<>$2`, device, actor); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM reader_preferences WHERE device_id=$1 AND user_id<>$2`, device, actor); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM device_key_grants WHERE device_id=$1 AND user_id<>$2`, device, actor); err != nil {
			return err
		}
		// The Team's notices about the number would stay behind with nothing
		// to point at: device_notices has no foreign key (0050). Nobody else
		// reads it, so only the actor's own can be there.
		if _, err = tx.Exec(ctx, `DELETE FROM device_notices WHERE device_id=$1`, device); err != nil {
			return err
		}
		// Move media before messages: message accounting updates its media rows too.
		if _, err = tx.Exec(ctx, `UPDATE media SET tenant_id=$2,download_status=CASE WHEN download_status='downloading' THEN 'pending' ELSE download_status END,claimed_at=NULL WHERE message_uid IN (SELECT uid FROM messages WHERE device_id=$1)`, device, target); err != nil {
			return err
		}
		// AI results go with their number, before its messages. The
		// authorization that made one belongs to the old workspace, so the
		// new workspace's owners and admins decide about it from now on.
		if _, err = tx.Exec(ctx, `UPDATE ai_derived SET tenant_id=$2,authorization_id=NULL WHERE device_id=$1`, device, target); err != nil {
			return err
		}
		for _, table := range []string{"device_archive_keys", "device_key_grants", "content_keys", "contacts", "group_participants", "group_changes", "reader_preferences", "device_permissions"} {
			if _, err = tx.Exec(ctx, `UPDATE `+table+` SET tenant_id=$2 WHERE device_id=$1`, device, target); err != nil {
				return fmt.Errorf("move %s: %w", table, err)
			}
		}
		// Receipt batches share the event journal's sequence. Remap them together
		// so replay cannot combine acknowledgements from different numbers.
		if _, err = tx.Exec(ctx, `UPDATE receipts SET tenant_id=$2,seq=seq+$3 WHERE device_id=$1`, device, target, offset); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE messages SET tenant_id=$2,seq=seq+$3 WHERE device_id=$1`, device, target, offset); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE events SET tenant_id=$2,seq=seq+$3 WHERE device_id=$1`, device, target, offset); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE chats SET tenant_id=$2,last_seq=CASE WHEN last_seq>0 THEN last_seq+$3 ELSE 0 END,read_through_seq=CASE WHEN read_through_seq>0 THEN read_through_seq+$3 ELSE 0 END WHERE device_id=$1`, device, target, offset); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE tenants SET last_seq=$2::bigint+$3::bigint WHERE id=$1`, target, offset, sourceLast); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO device_permissions(tenant_id,device_id,user_id,can_read,can_send,can_manage) VALUES($1,$2,$3,true,true,true) ON CONFLICT(tenant_id,device_id,user_id) DO NOTHING`, target, device, actor); err != nil {
			return err
		}
		// Destination ownership now keeps the physical objects alive. Release only
		// confirmed source objects no remaining Team archive or pending hash names.
		if _, err = tx.Exec(ctx, `DELETE FROM storage_objects o WHERE o.tenant_id=$1 AND o.object_key IN (
   SELECT d.object_key FROM media d JOIN messages m ON m.uid=d.message_uid WHERE m.device_id=$2)
   AND NOT EXISTS(SELECT 1 FROM media d WHERE d.tenant_id=$1 AND (d.object_key=o.object_key OR d.tenant_id::text||'/'||left(encode(d.file_enc_sha256,'hex'),2)||'/'||encode(d.file_enc_sha256,'hex')=o.object_key))`, source, device); err != nil {
			return err
		}
		for _, tenant := range []uuid.UUID{source, target} {
			if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant.String()); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE tenants SET storage_archive_bytes=(SELECT coalesce(sum(bytes),0) FROM storage_inventory WHERE tenant_id=$1),storage_object_bytes=(SELECT coalesce(sum(bytes),0) FROM storage_objects WHERE tenant_id=$1),storage_reconciled_at=clock_timestamp(),storage_over_since=CASE WHEN storage_limit_bytes IS NULL OR (SELECT coalesce(sum(bytes),0) FROM storage_inventory WHERE tenant_id=$1)+(SELECT coalesce(sum(bytes),0) FROM storage_objects WHERE tenant_id=$1)<storage_limit_bytes THEN NULL ELSE coalesce(storage_over_since,clock_timestamp()) END WHERE id=$1`, tenant); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `DELETE FROM storage_samples WHERE tenant_id=$1`, tenant); err != nil {
				return err
			}
		}
		// Recheck actual persisted bytes (preview could conservatively overcount an
		// existing destination object). Never spend grace storage on a migration.
		var fits bool
		if err = tx.QueryRow(ctx, `SELECT storage_paused_at IS NULL AND (storage_limit_bytes IS NULL OR storage_archive_bytes+storage_object_bytes<=storage_limit_bytes) FROM tenants WHERE id=$1`, target).Scan(&fits); err != nil {
			return err
		}
		if !fits {
			return &TransferDenied{Reason: "Seu Personal não tem espaço suficiente para este histórico."}
		}
		if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, source.String()); err != nil {
			return err
		}
		var completed time.Time
		if err = tx.QueryRow(ctx, `INSERT INTO device_transfers(device_id,source_workspace_id,target_workspace_id,actor_id) VALUES($1,$2,$3,$4)
   RETURNING completed_at`, device, source, target, actor).Scan(&completed); err != nil {
			return err
		}
		// moved_out, in the Team: the team's other owners are told of it
		// (contract 4.2), and the ledger keeps it, so a restore never puts the
		// number back in the Team.
		sub, err := actorSubTx(ctx, tx, actor)
		if err != nil {
			return err
		}
		itemName, hint := itemLabel(device, name, pushName, pn)
		return recordEvent(ctx, tx, source, itemEvent{
			Type: eventMovedOut, ItemID: device, DedupeKey: dedupeKey(eventMovedOut, device, completed), OccurredAt: completed,
			ActorKind: actorPerson, ActorSub: sub, ActorUserID: &actor, ReaderSubs: readerSubs, Label: itemName, Hint: hint,
			ToTenantID: &target,
		})
	})
	return out, err
}
