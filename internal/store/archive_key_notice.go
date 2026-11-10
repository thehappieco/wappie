package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ArchiveKeyChannel is the notification a number's archive key sends at
// the commit that changes it: CreateArchiveKey, for that number, and
// ResetArchive, which deletes every key of the workspace. Ingest builds
// each number's pipeline once, with the number's key, and keeps it. On
// the notice every process drops the pipelines it built from the old key,
// and the next message builds them again (DS49). The payload is
// "tenant:device" for one number and "tenant" for every number of a
// workspace.
//
// These are the only paths that make or delete the key of a number that
// may be ingesting. Pairing makes a number's first key through
// CreateArchiveKey. A deletion's notice (DeviceExcludedChannel) already
// lets go of the number, and its purge deletes the key 30 days later. A
// number that never linked has nothing to drop. A move to Personal keeps
// the key and its epoch, and pauses the number first.
const ArchiveKeyChannel = "wappie_archive_key"

// notifyArchiveKeyTx sends ArchiveKeyChannel at tx's commit, for device,
// or for every number of tenant when device is nil.
func notifyArchiveKeyTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, device *uuid.UUID) error {
	payload := tenant.String()
	if device != nil {
		payload += ":" + device.String()
	}
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, ArchiveKeyChannel, payload); err != nil {
		return fmt.Errorf("store: tell the processes of the archive key: %w", err)
	}
	return nil
}

// ParseArchiveKeyNotice reads an ArchiveKeyChannel payload. device is
// uuid.Nil for every number of the workspace.
func ParseArchiveKeyNotice(payload string) (tenant, device uuid.UUID, err error) {
	t, d, one := strings.Cut(payload, ":")
	if tenant, err = uuid.Parse(t); err != nil || tenant == uuid.Nil || len(t) != 36 {
		return uuid.Nil, uuid.Nil, fmt.Errorf("store: malformed archive key notice %q", payload)
	}
	if !one {
		return tenant, uuid.Nil, nil
	}
	if device, err = uuid.Parse(d); err != nil || device == uuid.Nil || len(d) != 36 {
		return uuid.Nil, uuid.Nil, errors.Join(fmt.Errorf("store: malformed archive key notice %q", payload), err)
	}
	return tenant, device, nil
}
