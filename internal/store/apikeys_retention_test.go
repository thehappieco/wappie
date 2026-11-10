package store_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/domain"
	"whatserver2/internal/migrate"
	"whatserver2/internal/obs"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// Ended API keys go 13 months after their end (step 7's plan, 7.6).

// TestAnEndedKeyGoesThirteenMonthsAfterItsEnd: a key revoked, or expired,
// 13 months less a minute ago stays, and one 13 months and a minute ago
// goes, by both clocks: with Wappie's an hour behind the database's
// nothing goes, and with the database's behind Wappie's only what the
// database says is due goes. A key revoked after it expired goes by its
// expiry; one expired that no pass revoked yet goes too. A live key and
// one with no end stay. Rows are inserted in bulk, ended by the
// database's own clock.
func TestAnEndedKeyGoesThirteenMonthsAfterItsEnd(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")
	const due = `clock_timestamp() - interval '13 months' - interval '1 minute'`
	const notDue = `clock_timestamp() - interval '13 months' + interval '1 minute'`
	keys := []struct {
		name, revoked, expires string
		goes                   bool
	}{
		{"revoked, due", due, "NULL", true},
		{"revoked, not due", notDue, "NULL", false},
		{"expired, due", due, due, true},
		{"expired, not due", notDue, notDue, false},
		{"expired, then revoked", "clock_timestamp() - interval '1 day'", due, true},
		{"expired, not revoked yet", "NULL", due, true},
		{"revoked before its expiry", due, "clock_timestamp() + interval '1 day'", true},
		{"live", "NULL", "NULL", false},
		{"live, with a deadline", "NULL", "clock_timestamp() + interval '1 day'", false},
	}
	for i, k := range keys {
		if _, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO api_keys (tenant_id, prefix, key_hash, name, revoked_at, expires_at, origin)
			VALUES ($1, $2, 'x', $3, %s, %s, 'rest')`, k.revoked, k.expires), tenant, fmt.Sprintf("%08x", i), k.name); err != nil {
			t.Fatalf("%s: %v", k.name, err)
		}
	}
	left := func() []string {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT name FROM api_keys ORDER BY prefix`)
		if err != nil {
			t.Fatal(err)
		}
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return names
	}
	all := left()
	if got, err := store.RetainAPIKeys(ctx, pool, time.Now().Add(-time.Hour)); err != nil || len(got.Deleted) != 0 {
		t.Fatalf("Wappie's clock behind: %+v %v", got, err)
	}
	if got := left(); !slices.Equal(got, all) {
		t.Fatalf("Wappie's clock behind deleted: %v", got)
	}
	got, err := store.RetainAPIKeys(ctx, pool, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, k := range keys {
		if !k.goes {
			want = append(want, k.name)
		}
	}
	if left := left(); !slices.Equal(left, want) {
		t.Fatalf("the database's clock behind left %v, want %v", left, want)
	}
	if got.Deleted[store.OriginREST] != int64(len(keys)-len(want)) || got.Held != 0 {
		t.Fatalf("the counts: %+v", got)
	}
	if got, err := store.RetainAPIKeys(ctx, pool, time.Now()); err != nil || len(got.Deleted) != 0 {
		t.Fatalf("a second pass: %+v %v", got, err)
	}
}

// quarantineAll deletes device, acknowledging whoever reads it.
func quarantineAll(ctx context.Context, t *testing.T, f *aiFixture, device uuid.UUID) {
	t.Helper()
	devices := store.NewDevices(f.pool)
	var ack []uuid.UUID
	for range 2 {
		_, err := devices.Quarantine(ctx, f.tenant, f.owner, device, ack)
		var readers *store.ErrDeviceHasReaders
		if !errors.As(err, &readers) {
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		ack = nil
		for _, p := range readers.Readers {
			ack = append(ack, p.UserID)
		}
	}
	t.Fatal("the deletion never took its readers")
}

// TestAKeysConnectionGoesWithIt: an AI integration's key, on a live, a
// deleted and a moved-out number, and a metadata connection's key with
// its numbers, each with a row in every table hanging off a connection,
// go whole once their end is 13 months past. The integration's derived
// rows stay on all three numbers, authorization_id NULL. A key past its
// 13 months whose connection is still active stays, and is counted.
func TestAKeysConnectionGoesWithIt(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	devices := store.NewDevices(f.pool)
	number := func(label, pn, lid string) uuid.UUID {
		t.Helper()
		id := linkedNumber(t, f.pool, f.tenant, label, pn, lid)
		f.archiveKey(ctx, t, id, 1)
		f.ownerReads(ctx, t, f.owner, id)
		return id
	}
	live, deleted, moved := f.device, number("deleted", "5511900001111", "100000000001111"), number("moved", "5511900002222", "100000000002222")
	ai, _ := f.consentAI(ctx, t, f.owner, f.aiKeys(ctx, t, f.owner), nil, withDevices(live, deleted, moved))
	var messages []uuid.UUID
	for _, d := range []uuid.UUID{live, deleted, moved} {
		uid := f.message(ctx, t, d, domain.TypePTT, false)
		if err := f.ai.PutAIDerived(ctx, f.tenant, ai.ID, f.derived(t, uid, d, "audio"), false); err != nil {
			t.Fatal(err)
		}
		messages = append(messages, uid)
	}
	if err := f.ai.RecordAIUsage(ctx, f.tenant, ai.ID, store.AIUsage{DeviceID: live, Feature: "audio", Provider: "google", Model: geminiModel,
		Origin: "console", RequesterID: f.owner, Items: 1}); err != nil {
		t.Fatal(err)
	}
	_, prefix := f.provisionalKey(ctx, t, "MCP · Claude")
	in := consent(prefix)
	meta, err := f.conns.Create(ctx, f.tenant, f.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Activate(ctx, store.HostedReader, meta.ID); err != nil {
		t.Fatal(err)
	}
	_, keepPrefix := f.provisionalKey(ctx, t, "MCP · Desktop")
	held, err := f.conns.Create(ctx, f.tenant, f.owner, consent(keepPrefix))
	if err != nil {
		t.Fatal(err)
	}
	// The moved number takes its derived rows, the deleted one keeps
	// them; the integration ends (access_lost), then the rest.
	personal := uuid.Nil
	if err := f.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id = $1`, f.owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	if err := devices.SetPaused(ctx, f.tenant.String(), moved.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.TransferPersonal(ctx, f.tenant, f.owner, moved, personal); err != nil {
		t.Fatal(err)
	}
	quarantineAll(ctx, t, f, deleted)
	for _, id := range []string{ai.ID, meta.ID} {
		var status string
		if err := f.pool.QueryRow(ctx, `SELECT status FROM mcp_connections WHERE id = $1`, id).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status == "active" || status == "pending" {
			if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A row in each table that hangs off a connection, as an ended
	// connection keeps them.
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		for _, conn := range []string{ai.ID, meta.ID} {
			for _, q := range []struct {
				sql  string
				args []any
			}{
				{`INSERT INTO mcp_send_chats (tenant_id, connection_id, device_id, chat_key) VALUES ($1, $2, $3, '5511911111111@s.whatsapp.net')`,
					[]any{f.tenant, conn, live}},
				{`INSERT INTO mcp_outbound (id, tenant_id, connection_id, device_id, chat_key, kind, status)
					VALUES (uuidv7(), $1, $2, $3, '5511911111111@s.whatsapp.net', 'send', 'sent')`, []any{f.tenant, conn, live}},
				{`INSERT INTO mcp_connection_seen (connection_id, tenant_id, user_id) VALUES ($1, $2, $3)`, []any{conn, f.tenant, f.owner}},
				{`INSERT INTO mcp_connection_notices (connection_id, tenant_id, event) VALUES ($1, $2, 'network')`, []any{conn, f.tenant}},
				{`INSERT INTO mcp_revoke_links (sha256, connection_id, tenant_id, event) VALUES (encode(sha256(convert_to($1, 'UTF8')), 'hex'), $1::uuid, $2, 'network')`,
					[]any{conn, f.tenant}},
			} {
				if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
					return fmt.Errorf("%s: %w", q.sql, err)
				}
			}
		}
		return nil
	})

	keyIDs := make([]uuid.UUID, 3)
	for i, id := range []string{ai.ID, meta.ID, held.ID} {
		if err := f.pool.QueryRow(ctx, `SELECT api_key_id FROM mcp_connections WHERE id = $1`, id).Scan(&keyIDs[i]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.pool.Exec(ctx, `UPDATE api_keys SET revoked_at = clock_timestamp() - interval '14 months' WHERE id = ANY ($1)`, keyIDs); err != nil {
		t.Fatal(err)
	}
	restricted := 0
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM api_key_devices WHERE api_key_id = ANY ($1)`, keyIDs[:2]).Scan(&restricted); err != nil || restricted == 0 {
		t.Fatalf("no numbers on the keys: %d %v", restricted, err)
	}

	count := func(tenant uuid.UUID, q string, args ...any) int {
		t.Helper()
		var n int
		if err := pg.InTenantTx(ctx, f.pool, tenant.String(), func(tx pgx.Tx) error {
			return store.WithQuarantineForTest(ctx, tx, func() error { return tx.QueryRow(ctx, q, args...).Scan(&n) })
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	gone := []string{ai.ID, meta.ID}
	tables := map[string]struct {
		sql string
		arg any
	}{
		"api_keys":               {`SELECT count(*) FROM api_keys WHERE id = ANY ($1)`, keyIDs[:2]},
		"api_key_devices":        {`SELECT count(*) FROM api_key_devices WHERE api_key_id = ANY ($1)`, keyIDs[:2]},
		"mcp_connections":        {`SELECT count(*) FROM mcp_connections WHERE id::text = ANY ($1)`, gone},
		"mcp_send_chats":         {`SELECT count(*) FROM mcp_send_chats WHERE connection_id::text = ANY ($1)`, gone},
		"mcp_outbound":           {`SELECT count(*) FROM mcp_outbound WHERE connection_id::text = ANY ($1)`, gone},
		"ai_usage_daily":         {`SELECT count(*) FROM ai_usage_daily WHERE authorization_id::text = ANY ($1)`, gone},
		"mcp_connection_seen":    {`SELECT count(*) FROM mcp_connection_seen WHERE connection_id::text = ANY ($1)`, gone},
		"mcp_connection_notices": {`SELECT count(*) FROM mcp_connection_notices WHERE connection_id::text = ANY ($1)`, gone},
		"mcp_revoke_links":       {`SELECT count(*) FROM mcp_revoke_links WHERE connection_id::text = ANY ($1)`, gone},
	}
	for table, q := range tables {
		if n := count(f.tenant, q.sql, q.arg); n == 0 {
			t.Fatalf("%s: no rows before the pass", table)
		}
	}
	got, err := store.RetainAPIKeys(ctx, f.pool, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// The fixture's AI key is not named as a setup's, so its origin is
	// rest; the metadata one's is mcp_setup.
	if got.Deleted[store.OriginMCPSetup] != 1 || got.Deleted[store.OriginREST] != 1 || got.Held != 1 {
		t.Fatalf("the pass: %+v", got)
	}
	for table, q := range tables {
		if n := count(f.tenant, q.sql, q.arg); n != 0 {
			t.Errorf("%s: %d rows left", table, n)
		}
	}
	for _, c := range []struct {
		tenant uuid.UUID
		uid    uuid.UUID
	}{{f.tenant, messages[0]}, {f.tenant, messages[1]}, {personal, messages[2]}} {
		if n := count(c.tenant, `SELECT count(*) FROM ai_derived WHERE message_uid = $1 AND authorization_id IS NULL`, c.uid); n != 1 {
			t.Errorf("the derived row of %s: %d", c.uid, n)
		}
	}
	if n := count(f.tenant, `SELECT count(*) FROM api_keys k JOIN mcp_connections c ON c.api_key_id = k.id WHERE c.id = $1`, held.ID); n != 1 {
		t.Fatal("the key of a connection still active went")
	}
}

// TestTheRetirementReportLosesItsKeysAtThirteenMonths: 13 months after an
// apply, its revoked keys go and its report's per-key entries with them;
// the row and its counts stay, so keys stay narrowed (apikeys.create, the
// setup's gate, discovery); and a later retire-keys still removes a
// service the earlier run kept, now that no key of the earlier run is left
// to say a retired key acted as it.
func TestTheRetirementReportLosesItsKeysAtThirteenMonths(t *testing.T) {
	w := newRetireWorld(t)
	ctx := context.Background()
	c := w.retiring(t, "kept")
	w.tokensOn(t)
	first := w.apply(t)
	if s := service(t, first, c.service); s.Remove || s.Reason != store.KeptSoleReader {
		t.Fatalf("the first run: %+v", s)
	}
	// Thirteen months on, by both clocks.
	w.exec(t, `UPDATE key_retirements SET applied_at = applied_at - interval '13 months 1 day'`)
	w.exec(t, `UPDATE api_keys SET revoked_at = revoked_at - interval '13 months 1 day' WHERE revoke_reason = 'platform_tokens'`)
	got, err := store.RetainAPIKeys(ctx, w.pool, time.Now())
	if err != nil || got.Deleted[store.OriginREST] != 1 || got.Reports != 1 {
		t.Fatalf("the pass: %+v %v", got, err)
	}
	var revoked, kept, keys int
	var hasKeys bool
	if err := w.pool.QueryRow(ctx, `SELECT revoked, services_kept, report ? 'keys', jsonb_array_length(report->'kept')
		FROM key_retirements`).Scan(&revoked, &kept, &hasKeys, &keys); err != nil {
		t.Fatal(err)
	}
	if revoked != 1 || kept != 1 || hasKeys || keys != 1 {
		t.Fatalf("the record: revoked %d, kept %d, keys listed %t, kept listed %d", revoked, kept, hasKeys, keys)
	}
	w.exec(t, `UPDATE contract_token_state SET mode = 'off'`)
	if narrowed, err := w.apiKeys.KeysNarrowed(ctx); err != nil || !narrowed {
		t.Fatalf("keys no longer narrowed: %v %v", narrowed, err)
	}
	if _, err := w.apiKeys.IssueAsked(ctx, w.tenant.String(), "deploy bot", store.ScopeFull, &w.owner, nil, nil, nil); !errors.Is(err, store.ErrTokensAreThePlatforms) {
		t.Fatalf("a panel's key: %v", err)
	}
	w.reads(t, w.owner, c.number)
	w.tokensOn(t)
	if s := service(t, w.apply(t), c.service); !s.Remove || w.member(t, c.service) {
		t.Fatalf("the later run: %+v", s)
	}
}

// TestTheKeySweepBesideItsWriters (the plan's 7.6, DB25): the sweep takes
// its workspace's row first, as a connection's end and a number's
// deletion do, and apikeys.revoke takes no row the sweep holds before a
// key's; released together from behind a held workspace row, each round's
// sweep, revoke, end and deletion all finish, with no 40P01 and no retry.
func TestTheKeySweepBesideItsWriters(t *testing.T) {
	w := newRetireWorld(t)
	var logs strings.Builder
	var mu sync.Mutex
	ctx := obs.WithLogger(context.Background(), slog.New(slog.NewTextHandler(lockedWriter{&mu, &logs}, nil)))
	devices := store.NewDevices(w.pool)
	for round := range 4 {
		number := w.number(t, fmt.Sprintf("round %d", round))
		w.reads(t, w.owner, number)
		// A key whose end is past, restricted to the number, with its
		// ended connection.
		due, _ := w.connect(t, w.owner, store.KindMetadata, number)
		if _, err := w.conns.Revoke(ctx, w.tenant, w.owner, due); err != nil {
			t.Fatal(err)
		}
		w.exec(t, `UPDATE api_keys SET revoked_at = clock_timestamp() - interval '14 months'
			WHERE id = (SELECT api_key_id FROM mcp_connections WHERE id = $1)`, due)
		live, _ := w.connect(t, w.owner, store.KindMetadata, w.shared)
		key := w.key(t, "deploy", store.ScopeFull, &w.owner, nil, nil, nil)
		prefix, _, _ := strings.Cut(key, ".")
		var ack []uuid.UUID
		var readers *store.ErrDeviceHasReaders
		if _, err := devices.Quarantine(ctx, w.tenant, w.owner, number, nil); errors.As(err, &readers) {
			for _, p := range readers.Readers {
				ack = append(ack, p.UserID)
			}
		} else if err != nil {
			t.Fatal(err)
		}

		holder, err := w.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := holder.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, w.tenant); err != nil {
			t.Fatal(err)
		}
		errs := make(chan error, 4)
		var wg sync.WaitGroup
		for name, run := range map[string]func() error{
			"the sweep": func() error {
				got, err := store.RetainAPIKeys(ctx, w.pool, time.Now())
				if err == nil && got.Deleted[store.OriginREST]+got.Deleted[store.OriginMCPSetup] != 1 {
					err = fmt.Errorf("deleted %+v", got.Deleted)
				}
				return err
			},
			"apikeys.revoke":     func() error { return w.apiKeys.Revoke(ctx, w.tenant.String(), prefix) },
			"a connection's end": func() error { _, err := w.conns.Revoke(ctx, w.tenant, w.owner, live); return err },
			"a number's deletion": func() error {
				_, err := devices.Quarantine(ctx, w.tenant, w.owner, number, ack)
				return err
			},
		} {
			wg.Go(func() {
				if err := run(); err != nil {
					errs <- fmt.Errorf("round %d, %s: %w", round, name, err)
				}
			})
		}
		// Every writer that takes the workspace's row waits on it.
		deadline := time.Now().Add(10 * time.Second)
		for w.count(t, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`) < 3 {
			if time.Now().After(deadline) {
				t.Fatal("the writers never waited on the workspace")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err := holder.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	}
	if strings.Contains(logs.String(), "deadlock") {
		t.Fatalf("a deadlock was retried:\n%s", logs.String())
	}
}

// lockedWriter is a writer shared by goroutines.
type lockedWriter struct {
	mu *sync.Mutex
	b  *strings.Builder
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
