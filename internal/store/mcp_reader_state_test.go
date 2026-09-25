package store_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"whatserver2/internal/migrate"
	"whatserver2/internal/store"
)

// Every write names the generation it replaces; zero creates. A write
// against anything else changes nothing and reports where the row is.
func TestReaderStateCompareAndSwap(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()
	states := store.NewMCPReaderStates(f.pool)

	if _, _, err := states.Get(ctx, "enclave", "as-tokens"); !errors.Is(err, store.ErrReaderStateNotFound) {
		t.Fatalf("never written: %v", err)
	}
	if got, err := states.Put(ctx, "enclave", "as-tokens", 1, []byte("x")); !errors.Is(err, store.ErrReaderStateConflict) || got != 0 {
		t.Fatalf("update of a missing row = %d %v", got, err)
	}
	if got, err := states.Put(ctx, "enclave", "as-tokens", 0, []byte("one")); err != nil || got != 1 {
		t.Fatalf("create = %d %v", got, err)
	}
	if got, err := states.Put(ctx, "enclave", "as-tokens", 0, []byte("again")); !errors.Is(err, store.ErrReaderStateConflict) || got != 1 {
		t.Fatalf("second create = %d %v", got, err)
	}
	if got, err := states.Put(ctx, "enclave", "as-tokens", 1, []byte("two")); err != nil || got != 2 {
		t.Fatalf("update = %d %v", got, err)
	}
	if got, err := states.Put(ctx, "enclave", "as-tokens", 1, []byte("stale")); !errors.Is(err, store.ErrReaderStateConflict) || got != 2 {
		t.Fatalf("stale update = %d %v", got, err)
	}
	gen, blob, err := states.Get(ctx, "enclave", "as-tokens")
	if err != nil || gen != 2 || string(blob) != "two" {
		t.Fatalf("get = %d %q %v", gen, blob, err)
	}
	// Readers and collections are separate rows.
	if _, _, err := states.Get(ctx, "staging", "as-tokens"); !errors.Is(err, store.ErrReaderStateNotFound) {
		t.Fatalf("another reader's state: %v", err)
	}
	if got, err := states.Put(ctx, "staging", "as-tokens", 0, []byte("theirs")); err != nil || got != 1 {
		t.Fatalf("another reader's create = %d %v", got, err)
	}
	if _, _, err := states.Get(ctx, "enclave", "infra"); !errors.Is(err, store.ErrReaderStateNotFound) {
		t.Fatalf("another collection: %v", err)
	}
	for _, name := range []string{"keys", "", "AS-TOKENS"} {
		if _, err := states.Put(ctx, "enclave", name, 0, []byte("x")); !errors.Is(err, store.ErrReaderStateName) {
			t.Fatalf("name %q: %v", name, err)
		}
	}
	if _, err := states.Put(ctx, "enclave", "infra", -1, []byte("x")); err == nil {
		t.Fatal("a negative generation was accepted")
	}
}

// Two writers on the same generation: exactly one wins, whoever is first.
func TestReaderStateConcurrentWriters(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()
	states := store.NewMCPReaderStates(f.pool)
	if _, err := states.Put(ctx, "enclave", "as-clients", 0, []byte("base")); err != nil {
		t.Fatal(err)
	}
	const writers = 8
	var wg sync.WaitGroup
	wins := make(chan int, writers)
	for i := range writers {
		wg.Go(func() {
			if _, err := states.Put(ctx, "enclave", "as-clients", 1, bytes.Repeat([]byte{byte(i)}, 10)); err == nil {
				wins <- i
			} else if !errors.Is(err, store.ErrReaderStateConflict) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	close(wins)
	if len(wins) != 1 {
		t.Fatalf("%d writers won the same generation", len(wins))
	}
	winner := <-wins
	gen, blob, err := states.Get(ctx, "enclave", "as-clients")
	if err != nil || gen != 2 || !bytes.Equal(blob, bytes.Repeat([]byte{byte(winner)}, 10)) {
		t.Fatalf("after the race: %d %v %v", gen, blob, err)
	}
}

// A connection records its reader and what the reader declared; each
// reader's calls reach only its own rows.
func TestConnectionsAreScopedToTheirReader(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()
	const measurement = "nitro:pcr0=abc;doc=def"

	_, hostedPrefix := f.provisionalKey(ctx, t, "hosted")
	hosted, err := f.conns.Create(ctx, f.tenant, f.owner, consent(hostedPrefix))
	if err != nil {
		t.Fatal(err)
	}
	enclaveKey, enclavePrefix := f.provisionalKey(ctx, t, "enclave")
	in := consent(enclavePrefix)
	in.Reader, in.ReaderMeasurement = "enclave", measurement
	enclave, err := f.conns.Create(ctx, f.tenant, f.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	if hosted.Reader != store.HostedReader || enclave.Reader != "enclave" || enclave.ReaderMeasurement != measurement {
		t.Fatalf("created = %+v / %+v", hosted, enclave)
	}
	listed, err := f.conns.List(ctx, f.tenant)
	if err != nil || len(listed) != 2 {
		t.Fatalf("list = %+v %v", listed, err)
	}
	for _, c := range listed {
		switch c.ID {
		case hosted.ID:
			if c.Reader != "hosted" || c.ReaderMeasurement != "" {
				t.Fatalf("hosted row = %+v", c)
			}
		case enclave.ID:
			if c.Reader != "enclave" || c.ReaderMeasurement != measurement {
				t.Fatalf("enclave row = %+v", c)
			}
		}
	}
	var null bool
	if err := f.pool.QueryRow(ctx, `SELECT reader_measurement IS NULL FROM mcp_connections WHERE id=$1`, hosted.ID).Scan(&null); err != nil || !null {
		t.Fatalf("the hosted row's measurement is not NULL: %v %v", null, err)
	}

	// Another reader asks about the row: not found, and nothing changes.
	if _, _, err := f.conns.Status(ctx, store.HostedReader, enclave.ID); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("hosted status of an enclave row: %v", err)
	}
	if err := f.conns.Activate(ctx, store.HostedReader, enclave.ID); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("hosted activation of an enclave row: %v", err)
	}
	if err := f.conns.RevokeByID(ctx, store.HostedReader, enclave.ID); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("hosted revoke of an enclave row: %v", err)
	}
	if err := f.conns.RevokeByID(ctx, "enclave", hosted.ID); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("enclave revoke of a hosted row: %v", err)
	}
	if _, err := f.keys.Verify(ctx, enclaveKey); err != nil {
		t.Fatalf("another reader's revoke reached the key: %v", err)
	}
	// Its own reader gets through.
	if err := f.conns.Activate(ctx, "enclave", enclave.ID); err != nil {
		t.Fatal(err)
	}
	if status, _, err := f.conns.Status(ctx, "enclave", enclave.ID); err != nil || status != "active" {
		t.Fatalf("status = %q %v", status, err)
	}
	// The console's revoke says whose it was, so the right reader is told.
	if reader, err := f.conns.Revoke(ctx, f.tenant, f.owner, enclave.ID); err != nil || reader != "enclave" {
		t.Fatalf("revoke = %q %v", reader, err)
	}
	if reader, err := f.conns.Revoke(ctx, f.tenant, f.owner, hosted.ID); err != nil || reader != store.HostedReader {
		t.Fatalf("revoke = %q %v", reader, err)
	}

	// The column refuses a reader id of the wrong shape.
	_, prefix := f.provisionalKey(ctx, t, "bad")
	in = consent(prefix)
	in.Reader = "Enclave-1"
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, in); err == nil {
		t.Fatal("a malformed reader id was stored")
	}
}

// 0041's down-step, exactly as the migration's header documents it: the
// attested readers' connections and keys are revoked, the state table and
// the columns go, the ledger forgets version 41, and the hosted reader's
// connection is untouched. Running the migrations again brings 0041 back.
func TestMigration0041DownStep(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()

	hostedKey, hostedPrefix := f.provisionalKey(ctx, t, "hosted")
	hosted, err := f.conns.Create(ctx, f.tenant, f.owner, consent(hostedPrefix))
	if err != nil {
		t.Fatal(err)
	}
	enclaveKey, enclavePrefix := f.provisionalKey(ctx, t, "enclave")
	in := consent(enclavePrefix)
	in.Reader = "enclave"
	enclave, err := f.conns.Create(ctx, f.tenant, f.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Activate(ctx, "enclave", enclave.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewMCPReaderStates(f.pool).Put(ctx, "enclave", "infra", 0, []byte("acme")); err != nil {
		t.Fatal(err)
	}

	if _, err := f.pool.Exec(ctx, downStep0041(t)); err != nil {
		t.Fatalf("down-step: %v", err)
	}
	var version int
	if err := f.pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 40 {
		t.Fatalf("ledger at %d %v", version, err)
	}
	var tables, columns int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='mcp_reader_state'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("state table left: %d %v", tables, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema()
		AND table_name='mcp_connections' AND column_name IN ('reader','reader_measurement')`).Scan(&columns); err != nil || columns != 0 {
		t.Fatalf("columns left: %d %v", columns, err)
	}
	if _, err := f.keys.Verify(ctx, enclaveKey); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("the enclave connection's key survived the down-step: %v", err)
	}
	if _, err := f.keys.Verify(ctx, hostedKey); err != nil {
		t.Fatalf("the hosted connection's key was revoked: %v", err)
	}
	statuses := map[string]string{}
	rows, err := f.pool.Query(ctx, `SELECT id::text, status FROM mcp_connections`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			t.Fatal(err)
		}
		statuses[id] = status
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if statuses[enclave.ID] != "revoked" || statuses[hosted.ID] != "pending" {
		t.Fatalf("statuses after the down-step = %v", statuses)
	}

	// And up again.
	if err := migrate.Run(ctx, f.pool, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("re-applying 0041: %v", err)
	}
	listed, err := f.conns.List(ctx, f.tenant)
	if err != nil || len(listed) != 2 {
		t.Fatalf("list after re-applying = %+v %v", listed, err)
	}
	for _, c := range listed {
		if c.Reader != store.HostedReader {
			t.Fatalf("row %s came back with reader %q", c.ID, c.Reader)
		}
	}
}

// downStep0041 reads the transaction out of 0041's header comment, so the
// statements tested are the ones an operator copies.
func downStep0041(t *testing.T) string {
	t.Helper()
	migrations, err := migrate.Load()
	if err != nil {
		t.Fatal(err)
	}
	var body string
	for _, m := range migrations {
		if m.Version == 41 {
			body = m.SQL
		}
	}
	var out []string
	in := false
	for _, line := range strings.Split(body, "\n") {
		text, ok := strings.CutPrefix(line, "--      ")
		if !ok {
			continue
		}
		if strings.TrimSpace(text) == "BEGIN;" {
			in = true
		}
		if in {
			out = append(out, text)
		}
		if strings.TrimSpace(text) == "COMMIT;" {
			break
		}
	}
	if len(out) < 3 || out[len(out)-1] != "COMMIT;" {
		t.Fatalf("no down-step transaction in 0041's header: %q", out)
	}
	return strings.Join(out, "\n")
}
