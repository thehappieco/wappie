package store_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"whatserver2/internal/migrate"
	"whatserver2/internal/store"
)

// Attachments (docs/mcp-enclave.md §16.3, §16.4): a content connection
// given under consent version 2 may carry media. The ledger records it,
// keeps it through a renewal, reports it only while the connection is live,
// and finds a key's connection for /v1/media's gate. Same ordinary role as
// the rest of the content tests.

// withMedia makes a prepared consent a version-2 one, with attachments or
// without.
func withMedia(c contentConsent, media bool) contentConsent {
	c.in.ConsentVersion, c.in.Media = store.MediaConsentVersion, media
	return c
}

// consentMedia records and activates a version-2 content connection.
func (f *contentFixture) consentMedia(ctx context.Context, t *testing.T, media bool) (store.MCPConnection, contentConsent) {
	t.Helper()
	c := withMedia(f.prepareContent(ctx, t, f.owner), media)
	conn, err := f.conns.Create(ctx, f.tenant, f.owner, c.in)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Activate(ctx, "enclave", conn.ID); err != nil {
		t.Fatal(err)
	}
	return conn, c
}

func TestCreateMediaConnection(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()

	for name, tc := range map[string]struct {
		version int
		media   bool
	}{"version 1": {1, false}, "version 2": {2, false}, "version 2 with media": {2, true}} {
		t.Run(name, func(t *testing.T) {
			c := f.prepareContent(ctx, t, f.owner)
			c.in.ConsentVersion, c.in.Media = tc.version, tc.media
			conn, err := f.conns.Create(ctx, f.tenant, f.owner, c.in)
			if err != nil {
				t.Fatal(err)
			}
			if conn.ConsentVersion != tc.version || conn.Media != tc.media {
				t.Fatalf("created = version %d media %v", conn.ConsentVersion, conn.Media)
			}
			if got := f.row(ctx, t, conn.ID); got.ConsentVersion != tc.version || got.Media != tc.media {
				t.Fatalf("listed = version %d media %v", got.ConsentVersion, got.Media)
			}
			if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, conn.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
	// The backstop behind the handler: media only on version 2, and only
	// the versions there are.
	for name, mutate := range map[string]func(*store.CreateMCPConnection){
		"media on version 1": func(in *store.CreateMCPConnection) { in.Media = true },
		"version 3":          func(in *store.CreateMCPConnection) { in.ConsentVersion = 3 },
		"version 3 media":    func(in *store.CreateMCPConnection) { in.ConsentVersion, in.Media = 3, true },
	} {
		t.Run(name, func(t *testing.T) {
			c := f.prepareContent(ctx, t, f.owner)
			mutate(&c.in)
			if _, err := f.conns.Create(ctx, f.tenant, f.owner, c.in); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	_, prefix := f.provisionalKey(ctx, t, "meta")
	meta := consent(prefix)
	meta.Media = true
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, meta); err == nil {
		t.Fatal("a metadata connection took media")
	}
	meta.Media = false
	metaConn, err := f.conns.Create(ctx, f.tenant, f.owner, meta)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.row(ctx, t, metaConn.ID); got.ConsentVersion != 0 || got.Media {
		t.Fatalf("metadata listed = version %d media %v", got.ConsentVersion, got.Media)
	}

	// The migration's CHECK behind both: media only on content of version
	// 2 or later, whoever writes the row.
	v1, _ := f.consentContent(ctx, t, f.owner)
	for name, id := range map[string]string{"version 1": v1.ID, "metadata": metaConn.ID} {
		_, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET media=true WHERE id=$1`, id)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "mcp_connections_media_content" {
			t.Fatalf("%s took media: %v", name, err)
		}
	}
}

// The status carries the row's media only while the connection is live; the
// switch is the caller's.
func TestStatusCarriesMedia(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	media, _ := f.consentMedia(ctx, t, true)
	text, _ := f.consentMedia(ctx, t, false)

	for id, want := range map[string]bool{media.ID: true, text.ID: false} {
		answer, err := f.conns.Status(ctx, "enclave", id, allowAll)
		if err != nil || answer.Status != "active" || answer.Media != want || answer.TenantID != f.tenant {
			t.Fatalf("status = %+v %v", answer, err)
		}
	}
	// Content off: a computed reseal, still the row's media for the caller
	// to narrow; the caller's media switch includes content.
	if answer, _ := f.conns.Status(ctx, "enclave", media.ID, nil); answer.Status != "reseal" || !answer.Media {
		t.Fatalf("switched off = %+v", answer)
	}
	if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, media.ID); err != nil {
		t.Fatal(err)
	}
	if answer, _ := f.conns.Status(ctx, "enclave", media.ID, allowAll); answer.Status != "revoked" || answer.Media {
		t.Fatalf("revoked = %+v", answer)
	}
}

// A renewal renews the key, never the consent.
func TestRenewKeepsMedia(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	conn, _ := f.consentMedia(ctx, t, true)
	next := f.prepareContent(ctx, t, f.owner)
	renewed, err := f.conns.Renew(ctx, f.tenant, f.owner, conn.ID, store.RenewMCPConnection{
		KeyPrefix: next.prefix, ServiceUserID: next.service, ReaderKID: "abcdefabcdefabcd", ReaderPublicKey: next.publicKey,
	})
	if err != nil || renewed.Status != "active" {
		t.Fatalf("renew = %+v %v", renewed, err)
	}
	if got := f.row(ctx, t, conn.ID); got.ConsentVersion != store.MediaConsentVersion || !got.Media || got.KeyPrefix != next.prefix {
		t.Fatalf("after renewal = version %d media %v key %s", got.ConsentVersion, got.Media, got.KeyPrefix)
	}
}

// /v1/media's gate asks the ledger about every key: the content connection
// it belongs to, whether that is live, and whether it carries media; and,
// for a key no connection holds, whether it acts as a connection service
// account all the same.
func TestContentConnectionByAPIKey(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	media, mc := f.consentMedia(ctx, t, true)
	_, tc := f.consentMedia(ctx, t, false)
	metaKey, metaPrefix := f.provisionalKey(ctx, t, "meta")
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(metaPrefix)); err != nil {
		t.Fatal(err)
	}
	keyID := func(key string) uuid.UUID {
		t.Helper()
		k, err := f.keys.VerifyScoped(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		return k.ID
	}

	got, err := f.conns.ContentConnectionByAPIKey(ctx, f.tenant, keyID(mc.key))
	if err != nil || got.ConnectionID != media.ID || got.TenantID != f.tenant || !got.Live || !got.Media {
		t.Fatalf("media key = %+v %v", got, err)
	}
	if got, err := f.conns.ContentConnectionByAPIKey(ctx, f.tenant, keyID(tc.key)); err != nil || !got.Live || got.Media {
		t.Fatalf("text key = %+v %v", got, err)
	}
	for name, id := range map[string]uuid.UUID{"metadata key": keyID(metaKey), "unknown key": uuid.New()} {
		if _, err := f.conns.ContentConnectionByAPIKey(ctx, f.tenant, id); !errors.Is(err, store.ErrMCPConnectionNotFound) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// Keys acting as a connection service account that no connection
	// holds: a prepared consent's or renewal's, before the ledger points at
	// it, and a second key acting as a live media connection's account.
	staged := f.prepareContent(ctx, t, f.owner)
	in := time.Now().Add(20 * time.Minute)
	second, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "second", store.ScopeRead, &f.owner, &mc.service, []uuid.UUID{f.device}, &in)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]string{"staged key": staged.key, "second key": second} {
		got, err := f.conns.ContentConnectionByAPIKey(ctx, f.tenant, keyID(key))
		if err != nil || got.ConnectionID != "" || got.TenantID != f.tenant || got.Live || got.Media {
			t.Fatalf("%s = %+v %v", name, got, err)
		}
	}

	id := keyID(mc.key)
	if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, media.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := f.conns.ContentConnectionByAPIKey(ctx, f.tenant, id); err != nil || got.Live || !got.Media {
		t.Fatalf("revoked = %+v %v", got, err)
	}
}

// 0043's down-step, exactly as its header documents it, run as the table
// owner under FORCE RLS: every media connection revoked with its key and its
// service account stripped, 0042's cascade; version-2 text connections, the
// others and every person's access untouched; the column and its CHECK gone
// and version 43 forgotten; and up again. 0045 and 0044 come down first, as
// the plan orders it.
func TestMigration0043DownStep(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	media, mc := f.consentMedia(ctx, t, true)
	pendingMedia := withMedia(f.prepareContent(ctx, t, f.owner), true)
	pending, err := f.conns.Create(ctx, f.tenant, f.owner, pendingMedia.in)
	if err != nil {
		t.Fatal(err)
	}
	text, tc := f.consentMedia(ctx, t, false)
	v1, c1 := f.consentContent(ctx, t, f.owner)
	metaKey, metaPrefix := f.provisionalKey(ctx, t, "meta")
	meta, err := f.conns.Create(ctx, f.tenant, f.owner, consent(metaPrefix))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.pool.Exec(ctx, downStep(t, 45)); err != nil {
		t.Fatalf("0045 down-step: %v", err)
	}
	if _, err := f.pool.Exec(ctx, downStep(t, 44)); err != nil {
		t.Fatalf("0044 down-step: %v", err)
	}
	if _, err := f.pool.Exec(ctx, downStep(t, 43)); err != nil {
		t.Fatalf("down-step: %v", err)
	}
	var version int
	if err := f.pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 42 {
		t.Fatalf("ledger at %d %v", version, err)
	}
	var columns, constraints int
	if err := f.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='mcp_connections' AND column_name='media'),
		(SELECT count(*) FROM pg_constraint WHERE conname='mcp_connections_media_content' AND connamespace=current_schema()::regnamespace)`).
		Scan(&columns, &constraints); err != nil || columns != 0 || constraints != 0 {
		t.Fatalf("left: %d columns, %d constraints %v", columns, constraints, err)
	}
	for name, c := range map[string]contentConsent{"media": mc, "pending media": pendingMedia} {
		if _, err := f.keys.Verify(ctx, c.key); !errors.Is(err, store.ErrInvalidKey) {
			t.Fatalf("the %s key survived: %v", name, err)
		}
		if tr := f.trace(ctx, t, c.service); tr != (serviceTrace{}) {
			t.Fatalf("the %s service account kept %+v", name, tr)
		}
	}
	for name, key := range map[string]string{"version-2 text": tc.key, "version-1": c1.key, "metadata": metaKey} {
		if _, err := f.keys.Verify(ctx, key); err != nil {
			t.Fatalf("the %s key was revoked: %v", name, err)
		}
	}
	for name, c := range map[string]contentConsent{"version-2 text": tc, "version-1": c1} {
		if tr := f.trace(ctx, t, c.service); tr.grants != 1 || tr.permissions != 1 || tr.memberships != 1 || tr.liveKeys != 1 {
			t.Fatalf("the %s service account changed: %+v", name, tr)
		}
	}
	if tr := f.trace(ctx, t, f.owner); tr.grants != 1 || tr.memberships != 1 {
		t.Fatalf("the owner's access changed: %+v", tr)
	}
	want := map[string]string{media.ID: "revoked", pending.ID: "revoked", text.ID: "active", v1.ID: "active", meta.ID: "pending"}
	rows, err := f.pool.Query(ctx, `SELECT id::text, status, coalesce(consent_version, 0) FROM mcp_connections`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, status string
		var consent int
		if err := rows.Scan(&id, &status, &consent); err != nil {
			t.Fatal(err)
		}
		if status != want[id] || id == text.ID && consent != 2 {
			t.Fatalf("%s: %s version %d, want %s", id, status, consent, want[id])
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// The enclave hears of both, like any other end.
	ids, err := f.conns.Unnotified(ctx, "enclave", 100)
	if err != nil || len(ids) != 2 {
		t.Fatalf("unnotified = %v %v", ids, err)
	}

	if err := migrate.Run(ctx, f.pool, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("re-applying 0043: %v", err)
	}
	listed, err := f.conns.List(ctx, f.tenant)
	if err != nil || len(listed) != 5 {
		t.Fatalf("list after re-applying = %+v %v", listed, err)
	}
	for _, l := range listed {
		if l.Media {
			t.Fatalf("row %s came back with media", l.ID)
		}
		if l.ID == text.ID && l.ConsentVersion != store.MediaConsentVersion {
			t.Fatalf("the version-2 text row came back as version %d", l.ConsentVersion)
		}
	}
}
