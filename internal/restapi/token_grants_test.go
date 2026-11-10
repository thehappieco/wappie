package restapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/restapi"
	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
)

// grantsOf is GET /v1/grants for text, which must answer 200.
func (r *tokenREST) grantsOf(t *testing.T, text string) restapi.Grants {
	t.Helper()
	code, body := r.do(t, "/v1/grants", bearer(text)...)
	var out restapi.Grants
	if code != http.StatusOK || json.Unmarshal([]byte(body), &out) != nil {
		t.Fatalf("GET /v1/grants: %d %s", code, body)
	}
	return out
}

// TestTokenGrantsOnREST (the plan's 5.4): GET /v1/grants for a token is its
// identity's grants at each number's current epoch, on the numbers it
// reads now, with user_id its identity; a rotated number and the text
// switch off leave its grants out; a token with no reading key holds none.
func TestTokenGrantsOnREST(t *testing.T) {
	r := newTokenREST(t)
	w := r.w
	a, b := w.Number("Vendas"), w.Number("Suporte")
	tok := w.Token(tokentest.Read(a), tokentest.Read(b))
	identity, err := w.Tokens.Identity(context.Background(), store.TokenAuth{ID: tok.ID, Tenant: w.Tenant})
	if err != nil {
		t.Fatal(err)
	}
	got := r.grantsOf(t, tok.Text)
	if got.TenantID != w.Tenant.String() || got.UserID != identity.String() || len(got.Grants.Grants) != 2 {
		t.Fatalf("the grants: %+v", got)
	}
	for _, g := range got.Grants.Grants {
		if g.Epoch != 1 || string(g.SealedDSK) != "sealed to the token" || g.ArchiveTenantID == "" || g.Label == "" {
			t.Fatalf("a grant: %+v", g)
		}
	}
	w.Rotate(b, 2)
	if got := r.grantsOf(t, tok.Text); len(got.Grants.Grants) != 1 || got.Grants.Grants[0].DeviceID != a.String() {
		t.Fatalf("after b's rotation: %+v", got)
	}
	off := false
	w.Switches(&off, nil)
	if got := r.grantsOf(t, tok.Text); len(got.Grants.Grants) != 0 || got.UserID != identity.String() {
		t.Fatalf("with text off: %+v", got)
	}
	w.Switches(nil, nil)
	text, selector, hash := tokentest.Mint()
	keyless := &tokentest.Token{ID: uuid.New(), Text: text, Selector: selector, Hash: hash, Perms: []tokentest.Perm{tokentest.Read(a)}}
	w.Commit(keyless)
	if got := r.grantsOf(t, keyless.Text); got.UserID != "" || len(got.Grants.Grants) != 0 {
		t.Fatalf("a token with no reading key: %+v", got)
	}
	if err := r.use.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := w.Refusals(tok); len(got) != 0 {
		t.Fatalf("listing grants counted: %v", got)
	}
}

// TestAResetNumbersOldKeyGetsNoGrantOnREST (the platform's answer of
// 2026-11-10, W46 7929b4a): after reset-archive -keep-devices and a new key
// at epoch 1, a grant sealed for the old key is refused, so the token's
// reads are no_grant and it lists no grant; the grant for the new key lets
// it read again.
func TestAResetNumbersOldKeyGetsNoGrantOnREST(t *testing.T) {
	r := newTokenREST(t)
	w := r.w
	a := w.Number("Vendas")
	tok := w.Token(tokentest.Read(a))
	old := w.ArchiveKey(a, 1)
	if code, body := r.do(t, "/v1/devices/"+a.String()+"/chats", bearer(tok.Text)...); code != http.StatusOK {
		t.Fatalf("before the reset: %d %s", code, body)
	}
	w.ResetArchive()
	w.Rotate(a, 1)
	if err := w.TrySealFor(tok, a, 1, old); !errors.Is(err, store.ErrArchiveKeyChanged) {
		t.Fatalf("a grant sealed for the old key: %v", err)
	}
	if code, body := r.do(t, "/v1/devices/"+a.String()+"/chats", bearer(tok.Text)...); code != http.StatusForbidden {
		t.Fatalf("a read after the old key's grant was refused: %d %s", code, body)
	}
	if got := r.grantsOf(t, tok.Text); len(got.Grants.Grants) != 0 {
		t.Fatalf("the grants: %+v", got)
	}
	if err := r.use.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := w.Refusals(tok); len(got) != 1 || got[a.String()+"/read=no_grant"] != 1 {
		t.Fatalf("the refusals: %v", got)
	}
	w.Seal(tok, a, 1)
	if code, body := r.do(t, "/v1/devices/"+a.String()+"/chats", bearer(tok.Text)...); code != http.StatusOK {
		t.Fatalf("after the new key's grant: %d %s", code, body)
	}
}
