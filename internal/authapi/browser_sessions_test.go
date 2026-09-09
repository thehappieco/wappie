package authapi_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"whatserver2/internal/store"
)

func browserAccount(t *testing.T, h *harness) (signupBody, sessionReply) {
	t.Helper()
	body, _ := newAccount(t, h.invite(t, "owner"), "browser@example.com", "browser-proof")
	var signed sessionReply
	if code := h.post(t, "/v1/auth/signup", body, &signed, ""); code != http.StatusOK {
		t.Fatalf("signup: %d", code)
	}
	return body, signed
}

func browserSecondWorkspace(t *testing.T, h *harness, token string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var target uuid.UUID
	if err := h.pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('browser second workspace') RETURNING id`).Scan(&target); err != nil {
		t.Fatal(err)
	}
	invite, err := h.users.CreateInvite(ctx, target, "member", "", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": invite}, nil, token); code != http.StatusOK {
		t.Fatalf("join: %d", code)
	}
	return target
}

func browserSwitch(t *testing.T, h *harness, token string, target uuid.UUID) sessionReply {
	t.Helper()
	var out sessionReply
	if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": target.String()}, &out, token); code != http.StatusOK {
		t.Fatalf("switch: %d", code)
	}
	return out
}

func TestBrowserLogoutRevokesItsWorkspacesAndPreservesAnotherBrowser(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	body, original := browserAccount(t, h)
	target := browserSecondWorkspace(t, h, original.Token)
	first := browserSwitch(t, h, original.Token, target)
	second := browserSwitch(t, h, first.Token, h.tenant)
	var independent sessionReply
	if code := h.post(t, "/v1/auth/login", map[string]string{"email": body.Email, "auth_key": body.AuthKey}, &independent, ""); code != http.StatusOK {
		t.Fatalf("second browser login: %d", code)
	}
	independentWorkspace := browserSwitch(t, h, independent.Token, target)
	root, err := h.users.Session(ctx, original.Token)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{first.Token, second.Token} {
		s, err := h.users.Session(ctx, token)
		if err != nil || s.FamilyID == uuid.Nil || s.FamilyID != root.FamilyID || !s.ExpiresAt.Equal(root.ExpiresAt) {
			t.Fatalf("workspace did not inherit login family and expiry: %+v %v", s, err)
		}
	}
	other, err := h.users.Session(ctx, independent.Token)
	if err != nil || other.FamilyID == root.FamilyID {
		t.Fatalf("independent login reused browser family: %+v %v", other, err)
	}
	var me struct {
		ExpiresAt time.Time `json:"expires_at"`
		SessionID string    `json:"session_id"`
	}
	if code := h.get(t, "/v1/auth/me", &me, original.Token); code != http.StatusOK || me.SessionID != root.ID.String() || !me.ExpiresAt.Equal(root.ExpiresAt) {
		t.Fatalf("session resume metadata: %d %+v", code, me)
	}
	// Clients replace one immutable workspace token without ending the browser login.
	if code := h.post(t, "/v1/auth/logout", struct{}{}, nil, original.Token); code != http.StatusNoContent {
		t.Fatalf("token-only logout: %d", code)
	}
	for _, token := range []string{first.Token, second.Token, independent.Token, independentWorkspace.Token} {
		if _, err := h.users.Session(ctx, token); err != nil {
			t.Fatalf("token-only logout revoked another session: %v", err)
		}
	}
	// A retained original login may already be revoked after switching spaces.
	// It must still be able to revoke its own derived tokens, without choosing a family.
	if code := h.post(t, "/v1/auth/logout", map[string]any{"all_related": true, "family_id": other.FamilyID.String()}, nil, original.Token); code != http.StatusBadRequest {
		t.Fatalf("caller-selected family was accepted: %d", code)
	}
	if code := h.post(t, "/v1/auth/logout", map[string]bool{"all_related": true}, nil, original.Token); code != http.StatusNoContent {
		t.Fatalf("browser logout: %d", code)
	}
	for _, token := range []string{original.Token, first.Token, second.Token} {
		if _, err := h.users.Session(ctx, token); !errors.Is(err, store.ErrNoSession) {
			t.Fatalf("a browser token survived logout: %v", err)
		}
	}
	for _, token := range []string{independent.Token, independentWorkspace.Token} {
		if _, err := h.users.Session(ctx, token); err != nil {
			t.Fatalf("logout reached another browser: %v", err)
		}
	}
	if code := h.post(t, "/v1/auth/logout", map[string]bool{"all_related": true}, nil, original.Token); code != http.StatusNoContent {
		t.Fatalf("repeated browser logout: %d", code)
	}
}

func TestWorkspaceSessionRevalidatesSourceAndUsesItsStoredLifetime(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, signed := browserAccount(t, h)
	source, user, err := h.users.ActiveSession(ctx, signed.Token)
	if err != nil {
		t.Fatal(err)
	}
	tampered := source
	tampered.FamilyID = uuid.New()
	tampered.PasskeyID = uuid.New()
	tampered.ExpiresAt = time.Now().AddDate(10, 0, 0)
	_, derived, err := h.users.StartWorkspaceSession(ctx, user, "test browser", tampered)
	if err != nil || derived.FamilyID != source.FamilyID || derived.PasskeyID != source.PasskeyID || !derived.ExpiresAt.Equal(source.ExpiresAt) {
		t.Fatalf("source metadata was trusted instead of database state: %+v %v", derived, err)
	}
	tampered.UserID = uuid.New()
	if _, _, err := h.users.StartWorkspaceSession(ctx, user, "test browser", tampered); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("another identity source accepted: %v", err)
	}
	if err := h.users.EndSession(ctx, signed.Token); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.users.StartWorkspaceSession(ctx, user, "test browser", source); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("revoked source issued a token: %v", err)
	}
}

func TestBrowserPasskeyLoginsHaveIndependentFamilies(t *testing.T) {
	h := newPasskeyHarness(t)
	_, key := h.register(t)
	ctx := context.Background()
	password, user, err := h.users.ActiveSession(ctx, h.signed.Token)
	if err != nil {
		t.Fatal(err)
	}
	token, login, err := h.users.StartPasskeySession(ctx, user, "first browser", key.ID)
	if err != nil {
		t.Fatal(err)
	}
	otherToken, other, err := h.users.StartPasskeySession(ctx, user, "second browser", key.ID)
	if err != nil {
		t.Fatal(err)
	}
	derivedToken, derived, err := h.users.StartWorkspaceSession(ctx, user, "first browser workspace", login)
	if err != nil || derived.PasskeyID != key.ID || derived.FamilyID != login.FamilyID || !derived.ExpiresAt.Equal(login.ExpiresAt) {
		t.Fatalf("passkey source metadata lost: %+v %v", derived, err)
	}
	if login.FamilyID == password.FamilyID || login.FamilyID == other.FamilyID || other.FamilyID == uuid.Nil {
		t.Fatal("separately proven logins were merged into one family")
	}
	if err := h.users.EndSessionFamily(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := h.users.Session(ctx, derivedToken); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("passkey-derived token survived browser logout: %v", err)
	}
	for _, surviving := range []string{h.signed.Token, otherToken} {
		if _, err := h.users.Session(ctx, surviving); err != nil {
			t.Fatalf("logout affected an independent password/passkey login: %v", err)
		}
	}
}

func TestBrowserLogoutUnknownAndExpiredTokensCannotSelectAFamily(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, signed := browserAccount(t, h)
	source, user, err := h.users.ActiveSession(ctx, signed.Token)
	if err != nil {
		t.Fatal(err)
	}
	derived, _, err := h.users.StartWorkspaceSession(ctx, user, "test browser", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE sessions SET expires_at=now()-interval '1 second' WHERE id=$1`, source.ID); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "malformed", base64.RawURLEncoding.EncodeToString(make([]byte, 32)), signed.Token} {
		if code := h.post(t, "/v1/auth/logout", map[string]bool{"all_related": true}, nil, token); code != http.StatusNoContent {
			t.Fatalf("invalid-token logout differs: %d", code)
		}
	}
	if _, err := h.users.Session(ctx, derived); err != nil {
		t.Fatalf("an expired source was allowed to revoke a family: %v", err)
	}
	if _, _, err := h.users.StartWorkspaceSession(ctx, user, "test browser", source); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("expired source issued a token: %v", err)
	}
}

func TestBrowserLogoutAndWorkspaceIssuanceSerialize(t *testing.T) {
	for _, first := range []string{"issue", "logout"} {
		t.Run(first+" first", func(t *testing.T) {
			h := newHarness(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_, signed := browserAccount(t, h)
			source, user, err := h.users.ActiveSession(ctx, signed.Token)
			if err != nil {
				t.Fatal(err)
			}
			independent, _, err := h.users.StartSession(ctx, user, "other browser")
			if err != nil {
				t.Fatal(err)
			}
			blocker, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = blocker.Rollback(context.Background()) }()
			var blockerPID int
			if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
				t.Fatal(err)
			}
			if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "session-family/"+source.FamilyID.String()); err != nil {
				t.Fatal(err)
			}
			type issueResult struct {
				token string
				err   error
			}
			issued := make(chan issueResult, 1)
			ended := make(chan error, 1)
			issue := func() {
				token, _, err := h.users.StartWorkspaceSession(ctx, user, "racing tab", source)
				issued <- issueResult{token, err}
			}
			logout := func() { ended <- h.users.EndSessionFamily(ctx, signed.Token) }
			if first == "issue" {
				go issue()
			} else {
				go logout()
			}
			waitBrowserBlocked(t, ctx, h.pool, blockerPID, 1)
			if first == "issue" {
				go logout()
			} else {
				go issue()
			}
			waitBrowserBlocked(t, ctx, h.pool, blockerPID, 2)
			if err := blocker.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			result := <-issued
			if err := <-ended; err != nil {
				t.Fatal(err)
			}
			if first == "logout" && !errors.Is(result.err, store.ErrNoSession) {
				t.Fatalf("issuance succeeded after logout: %v", result.err)
			}
			if first == "issue" && result.err != nil {
				t.Fatalf("earlier issuance failed: %v", result.err)
			}
			for _, token := range []string{signed.Token, result.token} {
				if token != "" {
					if _, err := h.users.Session(ctx, token); !errors.Is(err, store.ErrNoSession) {
						t.Fatalf("a token escaped concurrent logout: %v", err)
					}
				}
			}
			if _, err := h.users.Session(ctx, independent); err != nil {
				t.Fatalf("concurrent logout affected another browser: %v", err)
			}
		})
	}
}

func TestBrowserSessionExpiryIsRecheckedAfterWaitingForItsFamily(t *testing.T) {
	for _, operation := range []string{"issue", "logout"} {
		t.Run(operation, func(t *testing.T) {
			h := newHarness(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_, signed := browserAccount(t, h)
			source, user, err := h.users.ActiveSession(ctx, signed.Token)
			if err != nil {
				t.Fatal(err)
			}
			derived, _, err := h.users.StartWorkspaceSession(ctx, user, "existing tab", source)
			if err != nil {
				t.Fatal(err)
			}
			blocker, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = blocker.Rollback(context.Background()) }()
			var blockerPID int
			if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
				t.Fatal(err)
			}
			if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "session-family/"+source.FamilyID.String()); err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() {
				if operation == "issue" {
					_, _, err := h.users.StartWorkspaceSession(ctx, user, "waiting tab", source)
					finished <- err
				} else {
					finished <- h.users.EndSessionFamily(ctx, signed.Token)
				}
			}()
			waitBrowserBlocked(t, ctx, h.pool, blockerPID, 1)
			// Expiration occurs after the operation's transaction began. Using
			// transaction-stable now() after the wait would still authorize it.
			if _, err := h.pool.Exec(ctx, `UPDATE sessions SET expires_at=clock_timestamp() WHERE id=$1`, source.ID); err != nil {
				t.Fatal(err)
			}
			if err := blocker.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = <-finished
			if operation == "issue" && !errors.Is(err, store.ErrNoSession) {
				t.Fatalf("expired source issued a session after waiting: %v", err)
			}
			if operation == "logout" && err != nil {
				t.Fatalf("expired source logout was not idempotent: %v", err)
			}
			if _, err := h.users.Session(ctx, derived); err != nil {
				t.Fatalf("expired source revoked a different active token: %v", err)
			}
		})
	}
}

func waitBrowserBlocked(t *testing.T, ctx context.Context, pool *pgxpool.Pool, blockerPID, count int) {
	t.Helper()
	for {
		var waiting int
		if err := pool.QueryRow(ctx, `WITH RECURSIVE waiting(pid) AS (
			SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))
			UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid=ANY(pg_blocking_pids(a.pid))
		) SELECT count(*) FROM waiting`, blockerPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= count {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("operations did not reach controlled browser-session race")
		case <-time.After(5 * time.Millisecond):
		}
	}
}
