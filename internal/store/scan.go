package store

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/domain"
	"whatserver2/internal/pg"
)

// ScanFilter describes routing metadata only. Encrypted content is never
// searched by the server. Empty optional filters accept every archived event.
type ScanFilter struct {
	From, Until time.Time
	SenderKeys  []string
	ChatKeys    []string
	FromMe      *bool
	Type        domain.Type
	Kind        domain.Kind
}

// timestampCeiling preserves half-open bounds when an HTTP client supplies
// nanoseconds but PostgreSQL stores microseconds. Truncating a lower bound
// would include a stored timestamp that precedes the requested interval.
func timestampCeiling(at time.Time) time.Time {
	floor := at.Truncate(time.Microsecond)
	if floor.Before(at) {
		return floor.Add(time.Microsecond)
	}
	return at
}

// Scan returns immutable archive events across a device, oldest first within
// each newest-first page. This is live pagination, not a database snapshot:
// concurrent historical backfills can require a new scan.
func (m *Messages) Scan(ctx context.Context, tenant, device uuid.UUID, filter ScanFilter, before Cursor, limit int) ([]Row, error) {
	var out []Row
	cursor := before
	if rounded := timestampCeiling(cursor.TS); !rounded.Equal(cursor.TS) {
		// Every row at the preceding microsecond is before this cursor,
		// regardless of its sequence.
		cursor.TS, cursor.Seq = rounded, 0
	}
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+rowColumns+`
			  FROM messages m LEFT JOIN media md ON md.message_uid = m.uid
			 WHERE m.device_id = $1
			   AND coalesce(m.ts,m.created_at) >= $2
			   AND coalesce(m.ts,m.created_at) < $3
			   AND ($4::boolean OR m.sender_key = ANY($5::text[])
			        OR m.sender_lid = ANY($5::text[]) OR m.sender_pn = ANY($5::text[]))
			   AND ($6::boolean OR m.chat_key = ANY($7::text[]))
			   AND ($8::boolean IS NULL OR m.is_from_me = $8)
			   AND ($9::text = '' OR m.type = $9)
			   AND ($10::text = '' OR m.kind = $10)
			   AND ($11::boolean OR (coalesce(m.ts,m.created_at),m.seq) < ($12::timestamptz,$13::bigint))
			 ORDER BY coalesce(m.ts,m.created_at) DESC,m.seq DESC
			 LIMIT $14`, device, timestampCeiling(filter.From), timestampCeiling(filter.Until),
			len(filter.SenderKeys) == 0, filter.SenderKeys, len(filter.ChatKeys) == 0, filter.ChatKeys,
			filter.FromMe, string(filter.Type), string(filter.Kind), before.TS.IsZero(), cursor.TS, cursor.Seq, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			row, err := scanRow(rows)
			if err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: scan device archive: %w", err)
	}
	slices.Reverse(out)
	return out, nil
}

// Page returns stored contact metadata after an exclusive key cursor. It does
// not contact WhatsApp or create missing entries. Both the comparison and the
// ordering use the database's collation and the existing primary key.
func (c *Contacts) Page(ctx context.Context, tenant, device uuid.UUID, afterKey string, limit int) ([]ContactRow, error) {
	var out []ContactRow
	err := pg.InTenantTx(ctx, c.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+contactColumns+` FROM contacts
			WHERE device_id=$1 AND ($2::text='' OR contact_key>$2)
			ORDER BY contact_key LIMIT $3`, device, afterKey, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			row, err := scanContact(rows)
			if err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: page contacts: %w", err)
	}
	return out, nil
}
