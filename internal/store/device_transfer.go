package store

import (
	"context"
	"errors"
	"fmt"
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
	ArchiveBytes        int64  `json:"archive_bytes"`
	ObjectBytes         int64  `json:"object_bytes"`
}

// TransferDenied contains a user-readable explanation, never database details.
type TransferDenied struct{ Reason string }

func (e *TransferDenied) Error() string { return e.Reason }

const movingInventory = `tenant_id=$1 AND (
 (source IN ('chats','receipts','contacts','group_participants') AND identity::jsonb->>0=($2::uuid)::text)
 OR (source IN ('messages','media') AND (CASE WHEN source IN ('messages','media') THEN identity::jsonb->>0 END)::uuid IN (SELECT uid FROM messages WHERE device_id=$2))
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
func (d *Devices) TransferPersonal(ctx context.Context, source, actor, device, target uuid.UUID) (PersonalTransferPreview, error) {
	var out PersonalTransferPreview
	err := pg.InTenantTx(ctx, d.pool, source.String(), func(tx pgx.Tx) error {
		// Do not use a caller-supplied target to choose authority or a workspace lock.
		var own uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, actor).Scan(&own); err != nil {
			return err
		}
		if own != target {
			return &TransferDenied{"O destino precisa ser o seu Personal."}
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
			return &TransferDenied{out.Reason}
		}
		var paused bool
		if err = tx.QueryRow(ctx, `SELECT paused FROM devices WHERE id=$1 FOR UPDATE`, device).Scan(&paused); err != nil {
			return err
		}
		if !paused {
			return &TransferDenied{"Pause o número antes de movê-lo."}
		}
		acquired, err := pg.TryLockTx(ctx, tx, "device:"+device.String())
		if err != nil {
			return err
		}
		if !acquired {
			return &TransferDenied{"A conexão ainda está encerrando. Aguarde e tente novamente."}
		}
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
		// Move media before messages: message accounting updates its media rows too.
		if _, err = tx.Exec(ctx, `UPDATE media SET tenant_id=$2,download_status=CASE WHEN download_status='downloading' THEN 'pending' ELSE download_status END,claimed_at=NULL WHERE message_uid IN (SELECT uid FROM messages WHERE device_id=$1)`, device, target); err != nil {
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
			return &TransferDenied{"Seu Personal não tem espaço suficiente para este histórico."}
		}
		if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, source.String()); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO device_transfers(device_id,source_workspace_id,target_workspace_id,actor_id) VALUES($1,$2,$3,$4)`, device, source, target, actor)
		return err
	})
	return out, err
}
