package store_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"whatserver2/internal/domain"
	"whatserver2/internal/migrate"
	"whatserver2/internal/store"
)

// 0045's down-step, exactly as its header documents it, run as the table
// owner under FORCE RLS: every AI authorization ends with 0043's cascade
// (its key revoked, its service account stripped) and is deleted; the
// results are deleted row by row first, so the quota gets their bytes back
// and the inventory forgets them; the tables, the columns and the
// constraints go, the kind and reason CHECKs are as 0044 left them, and
// version 45 is forgotten; every other connection and every person's access
// untouched; and up again.
func TestMigration0045DownStep(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	storage := store.NewStorage(f.pool)
	if _, err := storage.Reconcile(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	keys := f.aiKeys(ctx, t, f.owner)
	active, ac := f.consentAI(ctx, t, f.owner, keys, nil)
	pending := f.prepareAI(ctx, t, f.owner, keys, nil)
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, pending.in); err != nil {
		t.Fatal(err)
	}
	ended, _ := f.consentAI(ctx, t, f.owner, keys, nil)
	if _, _, err := f.conns.RevokeAI(ctx, f.tenant, f.owner, ended.ID, false); err != nil {
		t.Fatal(err)
	}
	media, mc := f.consentMedia(ctx, t, true)
	text, tc := f.consentContent(ctx, t, f.owner)
	metaKey, metaPrefix := f.provisionalKey(ctx, t, "meta")
	meta, err := f.conns.Create(ctx, f.tenant, f.owner, consent(metaPrefix))
	if err != nil {
		t.Fatal(err)
	}
	voice := f.message(ctx, t, f.device, domain.TypePTT, false)
	before, err := storage.Usage(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.ai.PutAIDerived(ctx, f.tenant, active.ID, f.derived(t, voice, f.device, "audio"), false); err != nil {
		t.Fatal(err)
	}
	if err := f.ai.RecordAIUsage(ctx, f.tenant, active.ID, store.AIUsage{DeviceID: f.device, Feature: "audio", Provider: "google", Model: geminiModel,
		Origin: "console", RequesterID: f.owner, Items: 1, InputTokens: 424, OutputTokens: 741, ChargedTokens: 1165}); err != nil {
		t.Fatal(err)
	}
	// A lower cap in tokens, so the down-step drops a column in use.
	capTokens := int64(2_500_000)
	if _, err := f.conns.SetAIControls(ctx, f.tenant, f.owner, active.ID, store.AIControls{CapSet: true, Cap: &capTokens}); err != nil {
		t.Fatal(err)
	}
	if with, err := storage.Usage(ctx, f.tenant); err != nil || with.ArchiveBytes <= before.ArchiveBytes {
		t.Fatalf("the result was not counted: %d, before %d %v", with.ArchiveBytes, before.ArchiveBytes, err)
	}

	if _, err := f.pool.Exec(ctx, downStep(t, 46)); err != nil {
		t.Fatalf("0046 down-step: %v", err)
	}
	if _, err := f.pool.Exec(ctx, downStep(t, 45)); err != nil {
		t.Fatalf("down-step: %v", err)
	}
	var version int
	if err := f.pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 44 {
		t.Fatalf("ledger at %d %v", version, err)
	}
	var tables, columns, constraints int
	if err := f.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema()
		   AND table_name IN ('ai_keychain','ai_derived','ai_usage_daily')),
		(SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='mcp_connections'
		   AND column_name IN ('ai_config','ai_paused_at','ai_off','ai_cap_tokens','ai_alerts')),
		(SELECT count(*) FROM pg_constraint WHERE conname='mcp_connections_ai_coherent' AND connamespace=current_schema()::regnamespace)`).
		Scan(&tables, &columns, &constraints); err != nil || tables+columns+constraints != 0 {
		t.Fatalf("left: %d tables, %d columns, %d constraints %v", tables, columns, constraints, err)
	}
	for name, want := range map[string]string{
		"mcp_connections_kind_check":          "'metadata'::text, 'content'::text])",
		"mcp_connections_revoke_reason_check": "'access_lost'::text])",
		"mcp_connections_kind_coherent":       "kind = 'content'::text",
	} {
		var def string
		if err := f.pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname=$1 AND connamespace=current_schema()::regnamespace`, name).
			Scan(&def); err != nil || !strings.Contains(def, want) || strings.Contains(def, "'ai'") || strings.Contains(def, "ai_key_deleted") {
			t.Fatalf("%s = %s %v", name, def, err)
		}
	}
	// Every AI row is gone, its key revoked and its account stripped.
	var ai int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM mcp_connections WHERE kind NOT IN ('metadata','content')`).Scan(&ai); err != nil || ai != 0 {
		t.Fatalf("%d AI rows left %v", ai, err)
	}
	for name, c := range map[string]contentConsent{"active": ac, "pending": pending} {
		if _, err := f.keys.Verify(ctx, c.key); !errors.Is(err, store.ErrInvalidKey) {
			t.Fatalf("the %s authorization's key survived: %v", name, err)
		}
		if tr := f.trace(ctx, t, c.service); tr != (serviceTrace{}) {
			t.Fatalf("the %s authorization's service account kept %+v", name, tr)
		}
	}
	// The quota has the result's bytes back, and the inventory forgot it.
	after, err := storage.Usage(ctx, f.tenant)
	if err != nil || after.ArchiveBytes != before.ArchiveBytes {
		t.Fatalf("archive bytes %d, %d before the result %v", after.ArchiveBytes, before.ArchiveBytes, err)
	}
	var inventory int
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM storage_inventory WHERE source='ai_derived'`).Scan(&inventory)
	})
	if inventory != 0 {
		t.Fatalf("%d inventory rows of results left", inventory)
	}
	// Everything else is as it was.
	for name, key := range map[string]string{"media": mc.key, "text": tc.key, "metadata": metaKey} {
		if _, err := f.keys.Verify(ctx, key); err != nil {
			t.Fatalf("the %s key was revoked: %v", name, err)
		}
	}
	if tr := f.trace(ctx, t, f.owner); tr.grants != 1 || tr.memberships != 1 {
		t.Fatalf("the owner's access changed: %+v", tr)
	}
	want := map[string]string{media.ID: "active", text.ID: "active", meta.ID: "pending"}
	rows, err := f.pool.Query(ctx, `SELECT id::text, status FROM mcp_connections`)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			t.Fatal(err)
		}
		if status != want[id] {
			t.Fatalf("%s: %s, want %s", id, status, want[id])
		}
		n++
	}
	if err := rows.Err(); err != nil || n != 3 {
		t.Fatalf("%d rows %v", n, err)
	}

	if err := migrate.Run(ctx, f.pool, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("re-applying 0045: %v", err)
	}
	// The counters were the tables' own all along.
	if reconciled, err := storage.Reconcile(ctx, f.tenant); err != nil || reconciled.ArchiveBytes != before.ArchiveBytes {
		t.Fatalf("reconciled %d, before %d %v", reconciled.ArchiveBytes, before.ArchiveBytes, err)
	}
	if listed, err := f.conns.List(ctx, f.tenant); err != nil || len(listed) != 3 {
		t.Fatalf("list after re-applying = %+v %v", listed, err)
	}
	if all, err := f.conns.AIAuthorizations(ctx, f.tenant, f.owner, true); err != nil || len(all) != 0 {
		t.Fatalf("authorizations after re-applying = %+v %v", all, err)
	}
	if items, err := f.ai.Keychain(ctx, f.tenant, f.owner); err != nil || len(items) != 0 {
		t.Fatalf("keychain after re-applying = %+v %v", items, err)
	}
	// And it works again.
	f.consentAI(ctx, t, f.owner, f.aiKeys(ctx, t, f.owner), nil)
}
