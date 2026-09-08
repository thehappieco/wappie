package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/domain"
	"whatserver2/internal/pg"
)

// Reprojection is one stored message a later build might understand.
//
// A row filed as unsupported is not a loss: the protobuf that produced it was
// sealed and kept, precisely so that adding a classifier later can go back and
// look. What it is, is frozen — classification happens once, on the way in, so
// a message that arrived before its type was supported stays unsupported for
// good unless something goes back for it.
type Reprojection struct {
	UID uuid.UUID
	// Seq is the cursor. A pass walks newest first and asks for what comes
	// before the oldest it has seen, so rows this build still cannot classify
	// do not block the ones after them.
	Seq          int64
	WAID         string
	ChatKey      string
	SenderKey    string
	SenderLID    string
	SenderPN     string
	IsFromMe     bool
	IsGroup      bool
	ContentKeyID uint32
	RawSealed    []byte
	Unsupported  string
}

// Unsupported lists messages this build might now classify.
//
// Newest first, and pageable, and both were learned the hard way. Oldest first
// put a message from last night at position 748 of 750 — so the row somebody
// had actually noticed and asked about was the last one a run would reach, four
// passes away. Recent messages are the ones a person is looking at.
//
// beforeSeq is a cursor rather than an offset because most rows stay
// unsupported: they are types this build still does not understand, and they
// come back on every pass. Without a cursor a second pass returns the same
// unconvertible page for ever and nothing past it is ever seen.
func (m *Messages) Unsupported(ctx context.Context, tenant, device uuid.UUID,
	beforeSeq int64, limit int) ([]Reprojection, error) {
	var out []Reprojection
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT uid, seq, wa_id, chat_key,
			       coalesce(sender_key,''), coalesce(sender_lid,''), coalesce(sender_pn,''),
			       is_from_me, is_group, coalesce(content_key_id,0),
			       raw_sealed, coalesce(unsupported_field,'')
			  FROM messages
			 WHERE device_id = $1 AND type = $2 AND raw_sealed IS NOT NULL
			   AND ($4 = 0 OR seq < $4)
			 ORDER BY seq DESC
			 LIMIT $3`, device, string(domain.TypeUnsupported), limit, beforeSeq)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r Reprojection
			var keyID int32
			if err := rows.Scan(&r.UID, &r.Seq, &r.WAID, &r.ChatKey,
				&r.SenderKey, &r.SenderLID, &r.SenderPN,
				&r.IsFromMe, &r.IsGroup, &keyID, &r.RawSealed, &r.Unsupported); err != nil {
				return err
			}
			if keyID > 0 {
				r.ContentKeyID = uint32(keyID)
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list unsupported messages: %w", err)
	}
	return out, nil
}

// Reproject rewrites one row with what a later classifier made of it.
//
// Every sealed value on the row moves to the new content key together, and that
// is not tidiness: content_key_id names the key ALL of a row's sealed values
// share, so rewriting the body under a fresh key and leaving the raw protobuf
// under the old one produces a row where one of the two opens and the other
// reports tampering — with the correct key in hand, which reads as an attack
// rather than a bug.
//
// The type is narrowed, never widened: a row is only rewritten when it stops
// being unsupported. Guarded in the WHERE so a concurrent ingest that had
// already reclassified it wins, and so a second run is a no-op.
func (m *Messages) Reproject(ctx context.Context, tenant, device uuid.UUID, uid uuid.UUID,
	typ domain.Type, keyID uint32, body, payload, raw []byte, media *InsertMedia) error {
	if typ == domain.TypeUnsupported {
		return fmt.Errorf("store: refusing to reproject %s back to unsupported", uid)
	}
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE messages SET
				type = $3,
				unsupported_field = NULL,
				content_key_id = $4,
				body_sealed = $5,
				payload_sealed = $6,
				raw_sealed = $7
			 WHERE uid = $1 AND device_id = $2 AND type = 'unsupported'`,
			uid, device, string(typ), nullableKeyID(keyID),
			nullableBytes(body), nullableBytes(payload), nullableBytes(raw))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}

		// The chat list carries a projection of its newest message, and the
		// type in it was written when the row was stored. Reclassifying the
		// message without it leaves the sidebar saying "tipo não suportado"
		// about a photograph — the row is right and the summary of it is not,
		// which is the failure mode a projection always has.
		//
		// Only when this message IS the newest: the projection is about the
		// last row, and a reclassified message from last year must not
		// overwrite what a conversation says today.
		if _, err := tx.Exec(ctx, `
			UPDATE chats SET last_type = $3
			 WHERE device_id = $1 AND chat_key = $2
			   AND last_seq = (SELECT seq FROM messages WHERE uid = $4)`,
			device, chatKeyOf(ctx, tx, uid), string(typ), uid); err != nil {
			return err
		}

		if media == nil {
			return nil
		}

		// The attachment row, in the same transaction as the message.
		//
		// Its sealed values share the message's content key — the id on the
		// message names the key ALL of its sealed values use — so writing it
		// outside this transaction would leave a window where the message
		// points at a key the attachment was not sealed under.
		//
		// download_status defaults to 'pending', which IS the queue: the media
		// table is the work list, not a channel, so a row appearing here is
		// the whole of enqueueing it. A URL minted months ago has very likely
		// expired, and the worker records that as 'gone' rather than retrying
		// forever — which is the honest outcome and is what the media-retry
		// path exists to recover from.
		return insertMediaFor(ctx, tx, tenant, uid, keyID, media)
	})
	if err != nil {
		return fmt.Errorf("store: reproject %s: %w", uid, err)
	}
	return nil
}

// insertMediaFor attaches an attachment row to a message that already exists.
//
// Idempotent: message_uid is the primary key, so a second reprojection of the
// same row changes nothing rather than failing.
func insertMediaFor(ctx context.Context, tx pgx.Tx, tenant, uid uuid.UUID,
	keyID uint32, m *InsertMedia) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO media (
			message_uid, tenant_id, media_type, mimetype, file_length,
			file_sha256, file_enc_sha256, direct_path, url,
			width, height, seconds, waveform, sidecar, is_gif,
			content_key_id, media_key_sealed, thumb_sealed, filename_sealed)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		ON CONFLICT (message_uid) DO NOTHING`,
		uid, tenant, m.MediaType, nullable(m.MimeType), m.FileLength,
		m.FileSHA256, m.FileEncSHA256, nullable(m.DirectPath), nullable(m.URL),
		m.Width, m.Height, m.Seconds, m.Waveform, m.Sidecar, m.IsGIF,
		nullableKeyID(keyID), nullableBytes(m.MediaKeySealed),
		nullableBytes(m.ThumbSealed), nullableBytes(m.FileNameSealed))
	return err
}

// UnsupportedByUID reads one row that is still filed as unsupported.
//
// The type is part of the lookup, not checked afterwards: a row already
// reclassified must not be reopened, so a stale client replaying an old listing
// finds nothing rather than rewriting something.
func (m *Messages) UnsupportedByUID(ctx context.Context, tenant, device, uid uuid.UUID) (Reprojection, error) {
	var r Reprojection
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		var keyID int32
		err := tx.QueryRow(ctx, `
			SELECT uid, wa_id, chat_key,
			       coalesce(sender_key,''), coalesce(sender_lid,''), coalesce(sender_pn,''),
			       is_from_me, is_group, coalesce(content_key_id,0),
			       raw_sealed, coalesce(unsupported_field,'')
			  FROM messages
			 WHERE uid = $1 AND device_id = $2 AND type = $3`,
			uid, device, string(domain.TypeUnsupported)).Scan(
			&r.UID, &r.WAID, &r.ChatKey,
			&r.SenderKey, &r.SenderLID, &r.SenderPN,
			&r.IsFromMe, &r.IsGroup, &keyID, &r.RawSealed, &r.Unsupported)
		if err != nil {
			return err
		}
		if keyID > 0 {
			r.ContentKeyID = uint32(keyID)
		}
		return nil
	})
	if err != nil {
		return Reprojection{}, fmt.Errorf("store: read unsupported message %s: %w", uid, err)
	}
	return r, nil
}

// chatKeyOf reads the conversation a message was filed under.
//
// Read rather than passed in: the caller has a uid, and the chat key is a
// property of the row. Threading it through would be a second source for
// something the row already states.
func chatKeyOf(ctx context.Context, tx pgx.Tx, uid uuid.UUID) string {
	var key string
	if err := tx.QueryRow(ctx, `SELECT chat_key FROM messages WHERE uid = $1`, uid).Scan(&key); err != nil {
		return ""
	}
	return key
}

// MarkProtocol retypes an unsupported row as protocol traffic.
//
// For the rows the classifier now skips on the way in — key distribution,
// history notices, and the rest of what an older build stored because it did
// not yet know to drop them. They are not messages and nothing will ever
// render them, and leaving them typed unsupported had a cost that grew with
// every press: the reprojection panel offered them again each time, so an
// archive whose real backlog was long since done went on reporting a hundred
// and thirty rows of work. The raw protobuf stays sealed on the row, because
// nothing here is certain enough to throw bytes away.
func (m *Messages) MarkProtocol(ctx context.Context, tenant, device, uid uuid.UUID) error {
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE messages SET type = $3, unsupported_field = NULL
			 WHERE uid = $1 AND device_id = $2 AND type = 'unsupported'`,
			uid, device, string(domain.TypeProtocol))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("store: %s is not an unsupported row", uid)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: mark protocol: %w", err)
	}
	return nil
}
