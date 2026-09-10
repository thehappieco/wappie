package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/domain"
	"whatserver2/internal/pg"
)

// Receipts persists acknowledgements.
type Receipts struct{ pool *pgxpool.Pool }

// NewReceipts returns a receipt store.
func NewReceipts(pool *pgxpool.Pool) *Receipts { return &Receipts{pool: pool} }

// InsertReceipt is one acknowledgement event to record.
type InsertReceipt struct {
	TenantID uuid.UUID
	DeviceID uuid.UUID

	ChatKey string

	ReaderKey string
	ReaderLID string
	ReaderPN  string
	IsFromMe  bool

	// WAIDs are every message id acknowledged at this moment. They share one
	// sequence number because they arrived as one stanza.
	WAIDs []string

	Kind domain.ReceiptKind
	TS   time.Time
}

// ReceiptResult reports what was recorded.
type ReceiptResult struct {
	Seq int64
	// Stored is how many ids were new. Zero means the whole batch was already
	// known, which is the common case on a resync.
	Stored int
	// Duplicate is true when nothing was new, and therefore no sequence number
	// was allocated and nothing should be published.
	Duplicate bool
}

// ReceiptRow is one stored acknowledgement.
type ReceiptRow struct {
	Seq       int64
	DeviceID  uuid.UUID
	ChatKey   string
	WAID      string
	ReaderKey string
	ReaderLID string
	ReaderPN  string
	IsFromMe  bool
	Kind      domain.ReceiptKind
	TS        time.Time
}

// ReceiptBatch is one acknowledgement event as it left WhatsApp: one reader,
// one kind, one moment, several message ids.
//
// Reassembled from the rows by sequence number, which is exact because a
// sequence is allocated per event rather than per id.
type ReceiptBatch struct {
	Seq       int64
	DeviceID  uuid.UUID
	ChatKey   string
	WAIDs     []string
	ReaderKey string
	ReaderLID string
	ReaderPN  string
	IsFromMe  bool
	Kind      domain.ReceiptKind
	TS        time.Time
}

// Insert records one acknowledgement event.
//
// Already-known ids are filtered before a sequence number is allocated, not
// after. WhatsApp resends receipts on every resync, and letting a redelivered
// batch bump the tenant cursor would tear every connected client's position
// forward for no new information — the same reason the message path checks for
// a duplicate before allocating.
func (r *Receipts) Insert(ctx context.Context, in InsertReceipt) (ReceiptResult, error) {
	var res ReceiptResult
	if len(in.WAIDs) == 0 {
		res.Duplicate = true
		return res, nil
	}

	err := pg.InTenantTx(ctx, r.pool, in.TenantID.String(), func(tx pgx.Tx) error {
		fresh, err := unknownIDs(ctx, tx, in)
		if err != nil {
			return err
		}
		if len(fresh) == 0 {
			res.Duplicate = true
			return nil
		}

		seq, err := nextSeq(ctx, tx, in.TenantID)
		if err != nil {
			return err
		}

		// One statement for the batch. ON CONFLICT DO NOTHING rather than an
		// update: the row already there records when this acknowledgement was
		// first learned, and a resend does not make it happen again.
		tag, err := tx.Exec(ctx, `
			INSERT INTO receipts (
				tenant_id, device_id, seq, chat_key, wa_id,
				reader_key, reader_lid, reader_pn, is_from_me, kind, ts)
			SELECT $1, $2, $3, $4, id, $5, $6, $7, $8, $9, $10
			  FROM unnest($11::text[]) AS id
			ON CONFLICT DO NOTHING`,
			in.TenantID, in.DeviceID, seq, in.ChatKey,
			in.ReaderKey, nullable(in.ReaderLID), nullable(in.ReaderPN),
			in.IsFromMe, string(in.Kind), in.TS, fresh)
		if err != nil {
			return fmt.Errorf("store: insert receipts: %w", err)
		}
		res.Stored = int(tag.RowsAffected())
		if res.Stored == 0 {
			// Lost a race with a concurrent identical batch. The sequence is
			// spent, but nothing new exists to publish.
			res.Duplicate = true
			return nil
		}
		res.Seq = seq

		// The journal stays complete. message_uid is null because a batch
		// spans several messages, which is exactly why the replay read goes to
		// the receipts table rather than through here.
		if _, err := tx.Exec(ctx, `
			INSERT INTO events (seq, tenant_id, device_id, kind, chat_key)
			VALUES ($1,$2,$3,'receipt',$4)`,
			seq, in.TenantID, in.DeviceID, in.ChatKey); err != nil {
			return fmt.Errorf("store: journal receipt: %w", err)
		}
		return nil
	})
	if err != nil {
		return ReceiptResult{}, err
	}
	return res, nil
}

// unknownIDs returns the subset of the batch not already stored.
func unknownIDs(ctx context.Context, tx pgx.Tx, in InsertReceipt) ([]string, error) {
	// Keyed without chat_key on purpose. The same acknowledgement can arrive
	// addressed by LID once and by phone number another time; including the
	// chat here would store it twice and burn a second sequence number on a
	// fact already known. See migration 0004.
	rows, err := tx.Query(ctx, `
		SELECT wa_id FROM receipts
		 WHERE device_id = $1 AND reader_key = $2 AND kind = $3
		   AND wa_id = ANY($4::text[])`,
		in.DeviceID, in.ReaderKey, string(in.Kind), in.WAIDs)
	if err != nil {
		return nil, fmt.Errorf("store: check known receipts: %w", err)
	}
	defer rows.Close()

	known := make(map[string]struct{}, len(in.WAIDs))
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		known[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	fresh := make([]string, 0, len(in.WAIDs))
	seen := make(map[string]struct{}, len(in.WAIDs))
	for _, id := range in.WAIDs {
		if _, dup := known[id]; dup {
			continue
		}
		// The same id twice within one stanza would make the insert conflict
		// with itself, which Postgres reports as a cardinality violation
		// rather than skipping quietly.
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		fresh = append(fresh, id)
	}
	return fresh, nil
}

const receiptColumns = `seq, device_id, chat_key, wa_id, reader_key,
	coalesce(reader_lid,''), coalesce(reader_pn,''), is_from_me, kind, ts`

func scanReceipt(rows pgx.Rows) (ReceiptRow, error) {
	var r ReceiptRow
	var kind string
	if err := rows.Scan(&r.Seq, &r.DeviceID, &r.ChatKey, &r.WAID, &r.ReaderKey,
		&r.ReaderLID, &r.ReaderPN, &r.IsFromMe, &kind, &r.TS); err != nil {
		return ReceiptRow{}, err
	}
	r.Kind = domain.ReceiptKind(kind)
	return r, nil
}

// Since returns acknowledgement batches after a cursor, in sequence order.
//
// The limit counts rows, not batches. A batch cut in half by it is dropped
// rather than returned short, because a client cannot tell a two-id
// acknowledgement from the first half of a three-id one. truncated reports
// that this happened, so a caller merging this stream with another knows the
// highest sequence it may trust is the last one returned rather than whatever
// ceiling it had in mind.
func (r *Receipts) Since(ctx context.Context, tenant uuid.UUID, sinceSeq int64, limit int) (
	batches []ReceiptBatch, truncated bool, err error) {
	var out []ReceiptBatch
	rowCount := 0
	err = pg.InTenantTx(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+receiptColumns+`
			  FROM receipts
			 WHERE tenant_id = $1 AND seq > $2
			 ORDER BY seq, wa_id
			 LIMIT $3`, tenant, sinceSeq, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			row, err := scanReceipt(rows)
			if err != nil {
				return err
			}
			rowCount++
			if n := len(out); n > 0 && out[n-1].Seq == row.Seq {
				out[n-1].WAIDs = append(out[n-1].WAIDs, row.WAID)
				continue
			}
			out = append(out, ReceiptBatch{
				Seq: row.Seq, DeviceID: row.DeviceID, ChatKey: row.ChatKey,
				WAIDs:     []string{row.WAID},
				ReaderKey: row.ReaderKey, ReaderLID: row.ReaderLID, ReaderPN: row.ReaderPN,
				IsFromMe: row.IsFromMe, Kind: row.Kind, TS: row.TS,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, fmt.Errorf("store: read receipts since %d: %w", sinceSeq, err)
	}
	if rowCount == limit && len(out) > 1 {
		// The last batch may have been cut off mid-way. It comes back whole on
		// the next page, which starts from the sequence before it.
		out = out[:len(out)-1]
		truncated = true
	}
	return out, truncated, nil
}

// Batch returns one acknowledgement event by sequence number, for live
// delivery.
//
// Read back from storage rather than rendered from the publishing event, for
// the same reason messages are: a live receipt and a replayed one then come
// from one query and cannot drift apart.
func (r *Receipts) Batch(ctx context.Context, tenant uuid.UUID, seq int64) (ReceiptBatch, error) {
	batches, _, err := r.Since(ctx, tenant, seq-1, maxBatchIDs)
	if err != nil {
		return ReceiptBatch{}, err
	}
	for _, b := range batches {
		if b.Seq == seq {
			return b, nil
		}
	}
	return ReceiptBatch{}, pgx.ErrNoRows
}

// ForMessages returns every acknowledgement of the given message ids.
//
// This is the projection's input. Ordered by time so the attribution can walk
// it once.
//
// The chat is deliberately not part of the lookup. WhatsApp addresses a message
// by phone number and its receipt by LID for the same peer, so the two rows
// disagree about which conversation they belong to while agreeing perfectly
// about which message — and the message id is what WhatsApp itself resolves a
// receipt by. Requiring the chat keys to match made every acknowledgement
// invisible here, which is how this was found.
func (r *Receipts) ForMessages(ctx context.Context, tenant, device uuid.UUID,
	waIDs []string) ([]ReceiptRow, error) {
	if len(waIDs) == 0 {
		return nil, nil
	}
	var out []ReceiptRow
	err := pg.InTenantTx(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+receiptColumns+`
			  FROM receipts
			 WHERE device_id = $1 AND wa_id = ANY($2::text[])
			 ORDER BY ts, wa_id`, device, waIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			row, err := scanReceipt(rows)
			if err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: read receipts for messages: %w", err)
	}
	return out, nil
}

// maxBatchIDs bounds how many ids one acknowledgement may carry.
//
// A read receipt in a busy group can name a great many messages at once, and
// the single-batch read below has to fetch the whole thing or return something
// misleadingly short. Well above anything observed; it exists so a malformed
// stanza cannot ask for an unbounded read.
const maxBatchIDs = 2000

// PageAcks is what a conversation page says about one message's ticks.
//
// Counts of PEOPLE, not of rows and not of devices: one reader with a phone and
// a laptop is one person who received it, and a tick that waits for everyone
// must not be waiting for a device count nobody can name.
//
// Our own acknowledgements are excluded from every count and reported apart.
// types.ReceiptTypeSender is our own phone confirming it received something WE
// sent, and it is stored as a delivery with is_from_me — so counting it puts
// two grey ticks on a message the moment our own handset acknowledges, with the
// recipient having received nothing. In a direct chat, where the denominator is
// one, that is every message.
//
// Retrying and Failed are their own fields and no tick rule reads them. A
// message stuck in retry looks delivered and is not.
type PageAcks struct {
	Delivered int
	Read      int
	Played    int

	DeliveredAt *time.Time
	ReadAt      *time.Time
	PlayedAt    *time.Time

	// ReadByUs is one of our own devices reporting a read — the message was
	// read, just not here.
	ReadByUs bool
	Retrying bool
	Failed   bool
}

// AcksForPage folds every acknowledgement for a page of messages into per
// message counts.
//
// Folded during the scan rather than returned as rows, and the difference is
// not stylistic: fifty messages in a group of two hundred is ten thousand
// acknowledgements before a single tick is drawn, and every one of them would
// otherwise be allocated, carried across the wire and folded again in a
// browser. What comes back is the size of the answer.
//
// The lookup is by message id alone. Adding chat_key would look tidier and is
// the exact regression migration 0004 exists to document: a message stored
// under a phone number gets its receipt addressed by LID, and a join including
// the chat finds nothing.
func (r *Receipts) AcksForPage(ctx context.Context, tenant, device uuid.UUID,
	waIDs []string) (map[string]PageAcks, error) {
	if len(waIDs) == 0 {
		return nil, nil
	}
	// Per message, per kind, the set of people who acknowledged.
	type bucket struct {
		people map[string]struct{}
		at     *time.Time
	}
	seen := map[string]map[domain.ReceiptKind]*bucket{}
	out := map[string]PageAcks{}
	// One alias table per message: two rows addressed differently are one
	// person only within the conversation that produced them.
	links := map[string]*aliases{}

	err := pg.InTenantTx(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+receiptColumns+`
			  FROM receipts
			 WHERE device_id = $1 AND wa_id = ANY($2::text[])`, device, waIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			row, err := scanReceipt(rows)
			if err != nil {
				return err
			}
			acks := out[row.WAID]

			switch row.Kind {
			case domain.ReceiptRetry:
				acks.Retrying = true
				out[row.WAID] = acks
				continue
			case domain.ReceiptError:
				acks.Failed = true
				out[row.WAID] = acks
				continue
			}

			if row.IsFromMe {
				// Ours. Never a count — but a read from another of our own
				// devices is worth saying, because the message really was read.
				if row.Kind == domain.ReceiptRead || row.Kind == domain.ReceiptPlayed {
					acks.ReadByUs = true
					out[row.WAID] = acks
				}
				continue
			}
			jid, err := types.ParseJID(row.ReaderKey)
			if err != nil || jid.User == "" || (jid.Server != types.DefaultUserServer && jid.Server != types.HiddenUserServer) {
				continue
			}

			link, ok := links[row.WAID]
			if !ok {
				link = newAliases()
				links[row.WAID] = link
			}
			person := link.link(row)

			byKind, ok := seen[row.WAID]
			if !ok {
				byKind = map[domain.ReceiptKind]*bucket{}
				seen[row.WAID] = byKind
			}
			b, ok := byKind[row.Kind]
			if !ok {
				b = &bucket{people: map[string]struct{}{}}
				byKind[row.Kind] = b
			}
			b.people[person] = struct{}{}
			// The first moment, not the last: with several devices the
			// earliest is when the person actually got it.
			if b.at == nil || row.TS.Before(*b.at) {
				ts := row.TS
				b.at = &ts
			}
			out[row.WAID] = acks
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: fold receipts for a page: %w", err)
	}

	// The union runs as rows arrive, so a person can be counted under two
	// names until a later row links them. Resolve once, at the end.
	for waID, byKind := range seen {
		acks := out[waID]
		link := links[waID]
		for kind, b := range byKind {
			people := map[string]struct{}{}
			for p := range b.people {
				people[link.find(p)] = struct{}{}
			}
			switch kind {
			case domain.ReceiptDelivered:
				acks.Delivered, acks.DeliveredAt = len(people), b.at
			case domain.ReceiptRead:
				acks.Read, acks.ReadAt = len(people), b.at
			case domain.ReceiptPlayed:
				acks.Played, acks.PlayedAt = len(people), b.at
			}
		}
		out[waID] = acks
	}
	return out, nil
}
