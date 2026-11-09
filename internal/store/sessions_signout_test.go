package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// TestSignOutEverywhereScope (a gate; the spec's 14.7, DS11): a
// person.sign_out_everywhere ends the session families begun before its
// issued_at, a workspace session of such a family included whatever its
// own age, and counts their live rows only (a row that expired unrevoked
// is revoked with its family, uncounted); a family begun after stays; a
// rerun ends nothing new and counts 0; API keys the person created stay;
// and signed_out_everywhere_at keeps the latest issued_at that ran.
func TestSignOutEverywhereScope(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	user, sub := w.actor(t, "admin", "admin")
	u, err := w.users.Get(ctx, w.tenant, user)
	if err != nil {
		t.Fatal(err)
	}
	old, oldSession, err := w.users.StartSession(ctx, u, "old")
	if err != nil {
		t.Fatal(err)
	}
	// The same family: a workspace session, started now, and one that
	// expired unrevoked.
	ws, _, err := w.users.StartWorkspaceSession(ctx, u, "workspace", oldSession)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("expired"))
	if _, err := w.pool.Exec(ctx, `INSERT INTO sessions (user_id, tenant_id, token_hash, expires_at, family_id, created_at)
		VALUES ($1, $2, $3, clock_timestamp() - interval '1 minute', $4, clock_timestamp() - interval '1 day')`,
		user, w.tenant, hash[:], oldSession.FamilyID); err != nil {
		t.Fatal(err)
	}
	key, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "theirs", store.ScopeRead, &user, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var issued time.Time
	if err := w.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&issued); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	newer, _, err := w.users.StartSession(ctx, u, "newer")
	if err != nil {
		t.Fatal(err)
	}
	sessionsEnded := func(act store.ContractAct) int64 {
		t.Helper()
		var d kc.ResultDetail
		if err := json.Unmarshal(act.Result.Detail, &d); err != nil || d.SessionsEnded == nil {
			t.Fatalf("the detail %s: %v", act.Result.Detail, err)
		}
		return *d.SessionsEnded
	}
	live := func(token string) bool {
		_, _, err := w.users.ActiveSession(ctx, token)
		if err != nil && !errors.Is(err, store.ErrNoSession) {
			t.Fatal(err)
		}
		return err == nil
	}

	act, err := w.c.RunSignOutEverywhere(ctx, w.command(t, kc.OpPersonSignOutEverywhere, user, sub), issued)
	ranAct(t, "the sign-out", act, err)
	if n := sessionsEnded(act); n != 2 {
		t.Fatalf("%d sessions ended, want the two live ones of the old family", n)
	}
	if live(old) || live(ws) || !live(newer) {
		t.Fatalf("live after: old %v, workspace %v, newer %v", live(old), live(ws), live(newer))
	}
	var unrevoked int
	if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE family_id = $1 AND revoked_at IS NULL`, oldSession.FamilyID).
		Scan(&unrevoked); err != nil || unrevoked != 0 {
		t.Fatalf("%d rows of the old family left unrevoked: %v", unrevoked, err)
	}
	if _, err := w.apiKeys.VerifyScoped(ctx, key); err != nil {
		t.Fatalf("the person's API key: %v", err)
	}

	// Delivered again (after Wappie's own restore): nothing new ends, and
	// what ended is not counted again; an older issued_at keeps the later.
	act, err = w.c.RunSignOutEverywhere(ctx, w.command(t, kc.OpPersonSignOutEverywhere, user, sub), issued.Add(-time.Hour))
	ranAct(t, "the rerun", act, err)
	if n := sessionsEnded(act); n != 0 || !live(newer) {
		t.Fatalf("the rerun ended %d, newer live %v", n, live(newer))
	}
	var at *time.Time
	if err := w.pool.QueryRow(ctx, `SELECT signed_out_everywhere_at FROM contract_persons WHERE sub = $1`, sub).Scan(&at); err != nil ||
		at == nil || !at.Equal(issued) {
		t.Fatalf("signed_out_everywhere_at %v, want %v (%v)", at, issued, err)
	}
	// A person not linked has no sessions here: the executor answers
	// not_held before (R1). Another person's sessions are never touched.
	stranger := uuid.New()
	act, err = w.c.RunSignOutEverywhere(ctx, w.command(t, kc.OpPersonSignOutEverywhere, stranger, uuid.New()), time.Now().Add(time.Hour))
	ranAct(t, "a sign-out of nobody's account", act, err)
	if sessionsEnded(act) != 0 || !live(newer) {
		t.Fatal("a sign-out of another account ended this one's session")
	}
}
