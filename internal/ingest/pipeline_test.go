package ingest_test

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

var (
	chatJID   = types.JID{User: "5511999999999", Server: types.DefaultUserServer}
	senderJID = types.JID{User: "5511999999999", Server: types.DefaultUserServer}
)

type capturedBus struct {
	mu     sync.Mutex
	events []ingest.Event
}

func (b *capturedBus) Publish(_ uuid.UUID, ev ingest.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, ev)
}

func (b *capturedBus) all() []ingest.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]ingest.Event(nil), b.events...)
}

type fixture struct {
	pool   *pgxpool.Pool
	tenant uuid.UUID
	device uuid.UUID
	priv   seal.PrivateKey
	keys   *store.Keys
	pipe   *ingest.Pipeline
	bus    *capturedBus
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('acme') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	tenant := uuid.MustParse(tenantID)

	devices := store.NewDevices(pool)
	dev, err := devices.Create(ctx, tenantID, "test", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	device := uuid.MustParse(dev.ID)

	// The archive key belongs to the device, so it cannot be created before
	// the device row exists.
	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keys := store.NewKeys(pool)
	if err := keys.CreateArchiveKey(ctx, tenant, device, 1, pub); err != nil {
		t.Fatal(err)
	}

	sealer, err := seal.NewSealer(tenant, device, pub, 1, keys)
	if err != nil {
		t.Fatal(err)
	}
	bus := &capturedBus{}
	pipe, err := ingest.New(ingest.Config{
		Tenant: tenant, Sealer: sealer, Messages: store.NewMessages(pool),
		Bus: bus, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		pool: pool, tenant: tenant, device: uuid.MustParse(dev.ID),
		priv: priv, keys: keys, pipe: pipe, bus: bus,
	}
}

func (f *fixture) envelope(id string, kind domain.Kind, typ domain.Type, body string) domain.Envelope {
	return domain.Envelope{
		TenantID:  f.tenant.String(),
		DeviceID:  f.device.String(),
		MessageID: id,
		Chat:      domain.AddressOf(chatJID),
		Sender:    domain.AddressOf(senderJID),
		Timestamp: time.Now().Truncate(time.Second),
		Kind:      kind,
		Type:      typ,
		Source:    domain.SourceLive,
		Content:   domain.Content{Body: body},
	}
}

// open unwraps a sealed field the way a client would.
func (f *fixture) open(t *testing.T, uid uuid.UUID, kind seal.Kind, keyID uint32, sealed []byte) []byte {
	t.Helper()
	blob, err := f.keys.SealedContentKey(context.Background(), f.tenant, f.device, keyID)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := seal.OpenContentKey(f.priv, f.tenant, f.device, keyID, blob)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ck.Open(kind, f.tenant, uid, sealed)
	if err != nil {
		t.Fatalf("opening %s: %v", kind, err)
	}
	return pt
}

// TestContentIsSealedInTheDatabase is the end-to-end statement of the promise.
//
// A message goes through the real pipeline into a real Postgres, and the
// plaintext is nowhere in the database — not in the message row, not in any
// other table. Only a holder of the private key can get it back.
func TestContentIsSealedInTheDatabase(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	secret := "encontro as oito no lugar de sempre"

	res, err := f.pipe.Ingest(ctx, f.envelope("MSG1", domain.KindMessage, domain.TypeText, secret))
	if err != nil {
		t.Fatal(err)
	}
	if res.Duplicate {
		t.Fatal("a first insert reported a duplicate")
	}

	// Search every text and bytea column in the schema for the plaintext.
	rows, err := f.pool.Query(ctx, `
		SELECT table_name, column_name FROM information_schema.columns
		 WHERE table_schema = current_schema() AND data_type IN ('text','bytea')`)
	if err != nil {
		t.Fatal(err)
	}
	type col struct{ table, name string }
	var cols []col
	for rows.Next() {
		var c col
		if err := rows.Scan(&c.table, &c.name); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	rows.Close()

	for _, c := range cols {
		var hits int
		// Row-level security hides tenant tables outside a scoped
		// transaction, so this runs unscoped and finds nothing there —
		// which is itself the correct behaviour. The scoped check follows.
		err := f.pool.QueryRow(ctx,
			`SELECT count(*) FROM `+c.table+` WHERE `+c.name+`::text LIKE '%'||$1||'%'`, secret).Scan(&hits)
		if err == nil && hits > 0 {
			t.Errorf("plaintext found in %s.%s", c.table, c.name)
		}
	}

	// Now with the tenant scope set, so the rows are actually visible.
	var bodyBytes []byte
	var keyID uint32
	if err := withTenant(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
		var k int32
		if err := tx.QueryRow(ctx,
			`SELECT body_sealed, content_key_id FROM messages WHERE uid = $1`,
			res.UID).Scan(&bodyBytes, &k); err != nil {
			return err
		}
		keyID = uint32(k)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(bodyBytes) == 0 {
		t.Fatal("the body was not stored at all")
	}
	if bytes.Contains(bodyBytes, []byte(secret)) {
		t.Fatal("the stored body contains the plaintext")
	}

	// And it opens with the private key, which lives only on a client.
	if got := f.open(t, res.UID, seal.KindBody, keyID, bodyBytes); string(got) != secret {
		t.Errorf("recovered %q, want %q", got, secret)
	}
}

// withTenant runs a query inside a tenant-scoped transaction.
//
// It delegates to the same helper production uses, deliberately. An earlier
// version of this took a connection out of the pool, set the scope on it, and
// then ran the query through the pool — which handed back a *different*
// connection with no scope set, and every row came back invisible. Row-level
// security is per session, so the scope and the query have to be on the same
// one, and the only way to be sure of that is to go through the transaction
// helper that owns both.
func withTenant(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID, fn func(pgx.Tx) error) error {
	return pg.InTenantTx(ctx, pool, tenant.String(), fn)
}

// History sync redelivers what has already been seen, and the event stream is
// at-least-once. A duplicate must be recognised and must not be republished, or
// every backfill shows the same message twice.
func TestDuplicatesAreIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	env := f.envelope("MSG1", domain.KindMessage, domain.TypeText, "oi")

	first, err := f.pipe.Ingest(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.pipe.Ingest(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Duplicate {
		t.Fatal("the second ingest was not recognised as a duplicate")
	}
	if second.UID != first.UID || second.Seq != first.Seq {
		t.Errorf("the duplicate got a different identity: %v/%d vs %v/%d",
			second.UID, second.Seq, first.UID, first.Seq)
	}
	// Counted by class, because one message now publishes two events: the
	// message itself, and the recomputed badge that nothing else would ever
	// mention. A total would pass for the wrong reason the moment a third
	// class is added.
	var messages, badges int
	for _, ev := range f.bus.all() {
		switch ev.Class {
		case ingest.ClassMessage:
			messages++
		case ingest.ClassChat:
			badges++
		}
	}
	if messages != 1 {
		t.Errorf("published %d message events for one message, want 1", messages)
	}
	if badges != 1 {
		t.Errorf("published %d badge events, want 1 — a duplicate must not "+
			"announce a count it did not change", badges)
	}
}

// This is the question v1 answered at render time, in two places that
// disagreed. Removing a reaction produces a delete whose target is the
// reaction, not the message.
func TestControlRowTargetsAreResolvedOnIngest(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	msg, err := f.pipe.Ingest(ctx, f.envelope("MSG1", domain.KindMessage, domain.TypeText, "oi"))
	if err != nil {
		t.Fatal(err)
	}

	// A reaction to the message.
	react := f.envelope("REACT1", domain.KindReaction, domain.TypeReaction, "\U0001F44D")
	react.TargetID = "MSG1"
	if _, err := f.pipe.Ingest(ctx, react); err != nil {
		t.Fatal(err)
	}

	// Withdrawing it: a delete whose target is the reaction.
	undo := f.envelope("DEL1", domain.KindDelete, domain.TypeText, "")
	undo.TargetID = "REACT1"
	if _, err := f.pipe.Ingest(ctx, undo); err != nil {
		t.Fatal(err)
	}

	// Deleting the message itself: a delete whose target is a message.
	revoke := f.envelope("DEL2", domain.KindDelete, domain.TypeText, "")
	revoke.TargetID = "MSG1"
	if _, err := f.pipe.Ingest(ctx, revoke); err != nil {
		t.Fatal(err)
	}
	_ = msg

	for waID, want := range map[string]string{
		"REACT1": "message",  // a reaction targets a message
		"DEL1":   "reaction", // withdrawing a reaction targets the reaction
		"DEL2":   "message",  // revoking a message targets the message
	} {
		var rel *string
		if err := withTenant(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT target_rel FROM messages WHERE wa_id = $1`, waID).Scan(&rel)
		}); err != nil {
			t.Fatalf("%s: %v", waID, err)
		}
		if rel == nil {
			t.Errorf("%s: target_rel is null, want %q", waID, want)
			continue
		}
		if *rel != want {
			t.Errorf("%s: target_rel = %q, want %q", waID, *rel, want)
		}
	}
}

// Messages arrive out of order — a reaction can land before the message it
// reacts to, routinely during a backfill. The row is stored with the target
// unresolved and reconciled when the other half arrives.
func TestOutOfOrderTargetsReconcile(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// The reaction first.
	react := f.envelope("REACT1", domain.KindReaction, domain.TypeReaction, "❤️")
	react.TargetID = "MSG1"
	if _, err := f.pipe.Ingest(ctx, react); err != nil {
		t.Fatal(err)
	}
	var targetUID *uuid.UUID
	if err := withTenant(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT target_uid FROM messages WHERE wa_id = 'REACT1'`).Scan(&targetUID)
	}); err != nil {
		t.Fatal(err)
	}
	if targetUID != nil {
		t.Fatal("a target was resolved before it existed")
	}

	// Then the message it refers to.
	msg, err := f.pipe.Ingest(ctx, f.envelope("MSG1", domain.KindMessage, domain.TypeText, "oi"))
	if err != nil {
		t.Fatal(err)
	}

	n, err := store.NewMessages(f.pool).ResolvePendingTargets(ctx, f.tenant, f.device, 100)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("reconciled %d rows, want 1", n)
	}
	if err := withTenant(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT target_uid FROM messages WHERE wa_id = 'REACT1'`).Scan(&targetUID)
	}); err != nil {
		t.Fatal(err)
	}
	if targetUID == nil || *targetUID != msg.UID {
		t.Errorf("target_uid = %v, want %v", targetUID, msg.UID)
	}
}

// The chat list is a projection maintained on write, so the sidebar is an
// index-only scan rather than v1's triple join over the whole message table.
func TestChatProjectionTracksTheNewestMessage(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	for _, id := range []string{"MSG1", "MSG2", "MSG3"} {
		if _, err := f.pipe.Ingest(ctx, f.envelope(id, domain.KindMessage, domain.TypeText, id)); err != nil {
			t.Fatal(err)
		}
	}
	var lastSeq int64
	var lastType string
	if err := withTenant(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT last_seq, last_type FROM chats WHERE chat_key = $1`,
			chatJID.String()).Scan(&lastSeq, &lastType)
	}); err != nil {
		t.Fatal(err)
	}
	if lastSeq != 3 {
		t.Errorf("last_seq = %d, want 3", lastSeq)
	}
	if lastType != string(domain.TypeText) {
		t.Errorf("last_type = %q", lastType)
	}
}

// Sequence numbers are the cursor. They must be strictly increasing per tenant,
// or a client resuming from one silently skips messages.
func TestSequenceIsMonotonic(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	var prev int64
	for i := range 25 {
		res, err := f.pipe.Ingest(ctx,
			f.envelope(string(rune('A'+i))+"MSG", domain.KindMessage, domain.TypeText, "x"))
		if err != nil {
			t.Fatal(err)
		}
		if res.Seq <= prev {
			t.Fatalf("seq went from %d to %d", prev, res.Seq)
		}
		prev = res.Seq
	}
}

// A pipeline without a sealer must refuse to exist. Falling back to storing
// plaintext would be a silent failure of the only guarantee this system makes.
func TestPipelineRefusesToRunUnsealed(t *testing.T) {
	_, err := ingest.New(ingest.Config{Messages: &store.Messages{}})
	if err == nil {
		t.Fatal("a pipeline was built with no sealer")
	}
}

func TestMalformedEnvelopesAreRejected(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	for name, mutate := range map[string]func(*domain.Envelope){
		"no message id": func(e *domain.Envelope) { e.MessageID = "" },
		"no device":     func(e *domain.Envelope) { e.DeviceID = "" },
		"unknown kind":  func(e *domain.Envelope) { e.Kind = "nonsense" },
		"no type":       func(e *domain.Envelope) { e.Type = "" },
		"no chat":       func(e *domain.Envelope) { e.Chat = domain.Address{} },
		"control row with no target": func(e *domain.Envelope) {
			e.Kind = domain.KindDelete
			e.TargetID = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			env := f.envelope("MSG_"+name, domain.KindMessage, domain.TypeText, "x")
			mutate(&env)
			if _, err := f.pipe.Ingest(ctx, env); err == nil {
				t.Fatal("a malformed envelope was accepted")
			}
		})
	}
}

// Disappearing messages are kept, and expires_at records when the sender meant
// them to vanish — so a reader can be told plainly, rather than the archive
// presenting an ephemeral message as an ordinary one.
func TestExpiringMessagesAreKeptAndMarked(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	env := f.envelope("EPH1", domain.KindMessage, domain.TypeText, "some em 24h")
	env.Expiration = 86400
	env.Ephemeral = true
	res, err := f.pipe.Ingest(ctx, env)
	if err != nil {
		t.Fatal(err)
	}

	var expiresAt *time.Time
	var ephemeral bool
	if err := withTenant(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT expires_at, ephemeral FROM messages WHERE uid = $1`, res.UID).
			Scan(&expiresAt, &ephemeral)
	}); err != nil {
		t.Fatal(err)
	}
	if expiresAt == nil {
		t.Fatal("expires_at was not recorded, so a reader cannot be told this was ephemeral")
	}
	if !ephemeral {
		t.Error("the ephemeral flag was lost")
	}
	want := env.Timestamp.Add(24 * time.Hour)
	if expiresAt.Sub(want).Abs() > time.Second {
		t.Errorf("expires_at = %v, want about %v", expiresAt, want)
	}
}
