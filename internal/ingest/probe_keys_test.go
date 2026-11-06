package ingest_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// lidPhones is whatsmeow's map of LIDs and phone numbers, both ways.
type lidPhones struct{ lid, pn types.JID }

func (b lidPhones) PhoneFor(_ context.Context, lid types.JID) (types.JID, bool) {
	return b.pn, lid.User == b.lid.User
}

func (b lidPhones) LIDFor(_ context.Context, pn types.JID) (types.JID, bool) {
	return b.lid, pn.User == b.pn.User
}

// After a relink, history comes again under the conversation's LID or its
// phone number, whichever WhatsApp uses now. A direct message already
// stored under the other key is a duplicate: no second row, no event. The
// chat key itself never changes. Fictional numbers.
func TestHistoryResendDropsOtherKeyDuplicates(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	pn := types.NewJID("155501000401", types.DefaultUserServer)
	lid := types.NewJID("100000000000401", types.HiddenUserServer)
	pub, epoch, err := f.keys.ArchiveKey(ctx, f.tenant, f.device)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.NewSealer(f.tenant, f.device, pub, epoch, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := ingest.New(ingest.Config{
		Tenant: f.tenant, Sealer: sealer, Messages: store.NewMessages(f.pool), Bus: f.bus,
		Phones: lidPhones{lid: lid, pn: pn}, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Truncate(time.Second)
	env := func(id string, chat types.JID) domain.Envelope {
		return domain.Envelope{
			TenantID: f.tenant.String(), DeviceID: f.device.String(), MessageID: id,
			Chat: domain.AddressOf(chat), Sender: domain.AddressOf(chat), Timestamp: at,
			Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceHistory,
			Content: domain.Content{Body: "x"},
		}
	}
	// Stored under the phone number before the logout, sent again under the
	// LID; and the reverse.
	for _, step := range []struct {
		id    string
		chat  types.JID
		dupe  bool
		chats string
	}{
		{"H1", pn, false, pn.String()},
		{"H1", lid, true, ""},
		{"H2", lid, false, lid.String()},
		{"H2", pn, true, ""},
	} {
		res, err := pipe.Ingest(ctx, env(step.id, step.chat))
		if err != nil {
			t.Fatal(err)
		}
		if res.Duplicate != step.dupe {
			t.Fatalf("%s under %s: duplicate %v, want %v", step.id, step.chat.Server, res.Duplicate, step.dupe)
		}
		if step.chats == "" {
			continue
		}
		var key string
		if err := pg.InTenantTx(ctx, f.pool, f.tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT chat_key FROM messages WHERE wa_id = $1`, step.id).Scan(&key)
		}); err != nil {
			t.Fatal(err)
		}
		if key != step.chats {
			t.Fatalf("%s stored under %q, want %q", step.id, key, step.chats)
		}
	}
	var rows int
	if err := pg.InTenantTx(ctx, f.pool, f.tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM messages WHERE device_id = $1`, f.device).Scan(&rows)
	}); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("%d rows, want 2", rows)
	}
}
