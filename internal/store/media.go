package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// Media tracks attachments and where their bytes ended up.
type Media struct{ pool *pgxpool.Pool }

// NewMedia returns a media store.
func NewMedia(pool *pgxpool.Pool) *Media { return &Media{pool: pool} }

// ErrNoMedia reports a message with no attachment.
var ErrNoMedia = errors.New("store: message has no attachment")

// Pending is one attachment waiting to be fetched.
//
// Everything here is readable metadata. There is no media key: the download
// path never needs one, because it stores WhatsApp's ciphertext exactly as
// served and never looks inside it.
type Pending struct {
	MessageUID uuid.UUID
	TenantID   uuid.UUID
	MediaType  string
	// FileLength is what the sender claimed the plaintext measures. Not a
	// checked fact, and not what gets stored.
	FileLength int64
	// FileEncSHA256 is the hash of the ciphertext. It is what makes a download
	// verifiable without decrypting anything, and it is the object key.
	FileEncSHA256 []byte
	DirectPath    string
	URL           string
	Attempts      int
}

// ObjectRef locates the stored bytes of one attachment.
type ObjectRef struct {
	DeviceID  uuid.UUID
	ObjectKey string
	Size      int64
	MediaType string
	Status    string
}

// Claim marks up to limit due attachments as being downloaded and returns them.
//
// FOR UPDATE SKIP LOCKED so several workers can run without handing the same
// attachment to two of them, and without one long transaction blocking the
// rest. The claim is the state change: a row in 'downloading' is not offered
// again until it finishes or the sweeper decides its worker died.
func (m *Media) Claim(ctx context.Context, tenant uuid.UUID, limit int) ([]Pending, error) {
	var out []Pending
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			UPDATE media SET download_status = 'downloading', claimed_at = now()
			 WHERE message_uid IN (
			     SELECT message_uid FROM media
			      WHERE tenant_id = $1
			        AND download_status IN ('pending', 'failed')
			        AND (next_attempt_at IS NULL OR next_attempt_at <= now())
			      ORDER BY next_attempt_at NULLS FIRST, created_at
			      LIMIT $2
			      FOR UPDATE SKIP LOCKED)
			RETURNING message_uid, tenant_id, media_type, file_length,
			          file_enc_sha256, coalesce(direct_path,''), coalesce(url,''), attempts`,
			tenant, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p Pending
			if err := rows.Scan(&p.MessageUID, &p.TenantID, &p.MediaType, &p.FileLength,
				&p.FileEncSHA256, &p.DirectPath, &p.URL, &p.Attempts); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: claim media: %w", err)
	}
	return out, nil
}

// MarkDone records where the ciphertext was stored.
func (m *Media) MarkDone(ctx context.Context, tenant, messageUID uuid.UUID,
	objectKey string, size int64) error {
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE media SET download_status = 'done', object_key = $2, object_size = $3,
			                 download_error = '', downloaded_at = now(),
			                 next_attempt_at = NULL, claimed_at = NULL
			 WHERE message_uid = $1`, messageUID, objectKey, size)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: mark media done: %w", err)
	}
	return nil
}

// MarkFailed records why a download did not work and when to try again.
//
// permanent moves the row to 'gone' instead of scheduling a retry. A 404 from
// the CDN does not become a 200 by waiting, and a row that will never succeed
// must stop being offered or it crowds out the ones that would.
func (m *Media) MarkFailed(ctx context.Context, tenant, messageUID uuid.UUID,
	reason string, permanent bool, retryAfter time.Duration) error {
	status := "failed"
	var next *time.Time
	if permanent {
		status = "gone"
	} else {
		t := time.Now().Add(retryAfter)
		next = &t
	}
	// Error text goes in a column a human reads, so it is bounded here rather
	// than letting an upstream body of any length into the row.
	if len(reason) > 500 {
		reason = reason[:500] + "…"
	}
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE media SET download_status = $2, download_error = $3,
			                 attempts = attempts + 1, next_attempt_at = $4
			 WHERE message_uid = $1`, messageUID, status, reason, next)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: mark media failed: %w", err)
	}
	return nil
}

// Object returns where one attachment's bytes are, for serving.
func (m *Media) Object(ctx context.Context, tenant, messageUID uuid.UUID) (ObjectRef, error) {
	var ref ObjectRef
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT messages.device_id, coalesce(media.object_key,''), coalesce(media.object_size,0), media.media_type, media.download_status
			  FROM media JOIN messages ON messages.uid = media.message_uid
			 WHERE media.message_uid = $1`, messageUID).
			Scan(&ref.DeviceID, &ref.ObjectKey, &ref.Size, &ref.MediaType, &ref.Status)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ObjectRef{}, ErrNoMedia
	}
	if err != nil {
		return ObjectRef{}, fmt.Errorf("store: locate media: %w", err)
	}
	return ref, nil
}

// AdoptExisting points a row at an object that is already stored.
//
// Attachments are content-addressed by the hash of their ciphertext, so the
// same image forwarded into twenty chats is twenty rows and one object. Without
// this the twentieth still costs a download.
func (m *Media) AdoptExisting(ctx context.Context, tenant uuid.UUID, encSHA []byte) (string, int64, bool, error) {
	var key string
	var size int64
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT object_key, coalesce(object_size,0) FROM media
			 WHERE file_enc_sha256 = $1 AND download_status = 'done' AND object_key IS NOT NULL
			 LIMIT 1`, encSHA).Scan(&key, &size)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, fmt.Errorf("store: look for an existing object: %w", err)
	}
	return key, size, true, nil
}

// Sweep returns attachments stuck mid-download to the queue.
//
// A worker that dies holding a claim leaves the row in 'downloading' forever,
// and nothing else will ever pick it up. The age of the claim is the only
// signal available: there is no lock to expire, because holding a transaction
// open for the length of a download would pin a connection per attachment.
//
// It measures from claimed_at, not created_at. A backfilled attachment can be
// weeks old and claimed a second ago, and sweeping on arrival time would hand
// every in-flight download straight back to the queue.
func (m *Media) Sweep(ctx context.Context, tenant uuid.UUID, olderThan time.Duration) (int, error) {
	var n int
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE media SET download_status = 'pending'
			 WHERE tenant_id = $1 AND download_status = 'downloading'
			   AND claimed_at < now() - $2::interval`,
			tenant, olderThan.String())
		if err != nil {
			return err
		}
		n = int(tag.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: sweep stuck downloads: %w", err)
	}
	return n, nil
}

// Refresh points an attachment at a fresh direct path and queues it again.
//
// Used after a media retry: WhatsApp's URLs are signed with an expiry, and once
// that passes the bytes are unreachable by any download — the signature is on
// the direct path too, so there is no second address to try. Asking the sender
// to re-upload is the only recovery, and this is where the answer lands.
//
// The old url is cleared rather than kept. It is dead, and leaving it would
// have the fetcher spend its first attempt on an address that cannot work.
func (m *Media) Refresh(ctx context.Context, tenant, messageUID uuid.UUID, directPath string) error {
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE media SET direct_path = $2, url = NULL,
			                 download_status = 'pending', download_error = '',
			                 attempts = 0, next_attempt_at = NULL, claimed_at = NULL
			 WHERE message_uid = $1`, messageUID, directPath)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: refresh media path: %w", err)
	}
	return nil
}

// Expired lists attachments whose URL signature ran out, oldest first.
//
// A separate query from the download queue because these are not retryable by
// downloading: nothing about them changes until the sender re-uploads.
func (m *Media) Expired(ctx context.Context, tenant, device uuid.UUID, limit int) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT md.message_uid
			  FROM media md JOIN messages m ON m.uid = md.message_uid
			 WHERE md.tenant_id = $1 AND m.device_id = $2
			   AND md.download_status = 'gone'
			   AND md.download_error LIKE '%403%'
			 ORDER BY md.created_at DESC
			 LIMIT $3`, tenant, device, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list expired media: %w", err)
	}
	return out, nil
}
