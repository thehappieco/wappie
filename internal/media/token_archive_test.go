package media_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
)

// TestAResetNumbersOldKeyGetsNoGrantOnMedia (the platform's answer of
// 2026-11-10, W46 7929b4a): after reset-archive -keep-devices and a new key
// at epoch 1, a grant sealed for the old key is refused, so the token's
// download of an attachment stored since is the one 404, counted no_grant;
// the grant for the new key lets it download.
func TestAResetNumbersOldKeyGetsNoGrantOnMedia(t *testing.T) {
	m := newTokenMedia(t)
	w := m.w
	a := w.Number("Vendas")
	tok := w.Token(tokentest.Read(a))
	old := w.ArchiveKey(a, 1)
	w.ResetArchive()
	w.Rotate(a, 1)
	uid := m.attachment(t, a, 100)
	if err := w.TrySealFor(tok, a, 1, old); !errors.Is(err, store.ErrArchiveKeyChanged) {
		t.Fatalf("a grant sealed for the old key: %v", err)
	}
	if code, body := m.do(t, http.MethodGet, "/v1/media/"+uid.String(), nil, "Bearer "+tok.Text); code != http.StatusNotFound {
		t.Fatalf("a download after the old key's grant was refused: %d %q", code, body)
	}
	if err := m.checker.Use.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := w.Refusals(tok); len(got) != 1 || got[a.String()+"/read=no_grant"] != 1 {
		t.Fatalf("the refusals: %v", got)
	}
	w.Seal(tok, a, 1)
	if code, body := m.do(t, http.MethodGet, "/v1/media/"+uid.String(), nil, "Bearer "+tok.Text); code != http.StatusOK || len(body) != 100 {
		t.Fatalf("after the new key's grant: %d %d bytes", code, len(body))
	}
}
