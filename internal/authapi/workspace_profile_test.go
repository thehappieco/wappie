package authapi_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"whatserver2/internal/store"
)

func profileAvatar(t *testing.T, width, height int) string {
	t.Helper()
	pixels := image.NewRGBA(image.Rect(0, 0, width, height))
	pixels.Set(0, 0, color.RGBA{R: 120, G: 180, B: 60, A: 255})
	var body bytes.Buffer
	if err := png.Encode(&body, pixels); err != nil {
		t.Fatal(err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(body.Bytes())
}

func putProfile(t *testing.T, h *harness, token string, body any, result any) int {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, h.srv.URL+"/v1/auth/workspaces/current", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return h.do(t, req, result)
}

func TestWorkspaceProfileAuthorizationAndIsolation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, ownerToken := memberAccount(t, h, "owner@example.com", "owner")
	admin, adminToken := memberAccount(t, h, "admin@example.com", "admin")
	_, memberToken := memberAccount(t, h, "member@example.com", "member")
	var other uuid.UUID
	if err := h.pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('other') RETURNING id`).Scan(&other); err != nil {
		t.Fatal(err)
	}
	avatar := profileAvatar(t, 32, 32)
	profile := map[string]string{"name": "  São Paulo · Equipe  ", "avatar": avatar}
	for _, tc := range []struct {
		token string
		want  int
	}{{"", 401}, {memberToken, 403}, {adminToken, 200}, {ownerToken, 200}} {
		if code := putProfile(t, h, tc.token, profile, nil); code != tc.want {
			t.Fatalf("profile status = %d, want %d", code, tc.want)
		}
	}
	spaces, err := h.users.Workspaces(ctx, owner.ID)
	if err != nil || len(spaces) != 1 || spaces[0].Name != "São Paulo · Equipe" || spaces[0].Avatar != avatar {
		t.Fatalf("saved metadata not available to members: %+v %v", spaces, err)
	}
	// A client cannot supply another tenant, even while acting as a manager.
	if code := putProfile(t, h, ownerToken, map[string]string{"name": "stolen", "avatar": "", "tenant_id": other.String()}, nil); code != 400 {
		t.Fatalf("accepted target injection: %d", code)
	}
	var otherName, otherAvatar string
	if err := h.pool.QueryRow(ctx, `SELECT name,avatar FROM tenants WHERE id=$1`, other).Scan(&otherName, &otherAvatar); err != nil || otherName != "other" || otherAvatar != "" {
		t.Fatalf("other workspace changed: %q %q %v", otherName, otherAvatar, err)
	}
	// A demoted manager's previous authority cannot change profile metadata.
	if err := h.users.UpdateMember(ctx, h.tenant, owner.ID, admin.ID, "member", "active"); err != nil {
		t.Fatal(err)
	}
	if code := putProfile(t, h, adminToken, profile, nil); code != 401 {
		t.Fatalf("demoted session retained authority: %d", code)
	}
	if _, err := h.users.UpdateWorkspaceProfile(ctx, h.tenant, admin.ID, "stolen", ""); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("store trusted stale manager: %v", err)
	}
	var saved store.Workspace
	if code := putProfile(t, h, ownerToken, map[string]string{"name": "Fresh name", "avatar": ""}, &saved); code != 200 || saved.Avatar != "" || saved.Name != "Fresh name" {
		t.Fatalf("avatar removal: %d %+v", code, saved)
	}
}

func TestWorkspaceProfileRejectsUnsafeAndOversizedAvatars(t *testing.T) {
	h := newHarness(t)
	_, token := memberAccount(t, h, "owner@example.com", "owner")
	valid := profileAvatar(t, 32, 32)
	for name, avatar := range map[string]string{
		"external":        "https://example.com/picture.png",
		"svg":             "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)),
		"wrong MIME":      strings.Replace(valid, "image/png", "image/jpeg", 1),
		"corrupted":       "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("not an image")),
		"huge dimensions": profileAvatar(t, 513, 1),
		"huge request":    "data:image/png;base64," + strings.Repeat("A", 70<<10),
	} {
		t.Run(name, func(t *testing.T) {
			if code := putProfile(t, h, token, map[string]string{"name": "New", "avatar": avatar}, nil); code != 400 {
				t.Fatalf("accepted invalid avatar: %d", code)
			}
		})
	}
	for _, name := range []string{"", "   ", "line\nbreak", strings.Repeat("é", 81)} {
		if code := putProfile(t, h, token, map[string]string{"name": name, "avatar": valid}, nil); code != 400 {
			t.Fatalf("accepted invalid name %q: %d", name, code)
		}
	}
	// The decoder also accepts image formats with arbitrary trailing bytes. The
	// server must persist only the decoded/re-encoded pixels, never that payload.
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(valid, "data:image/png;base64,"))
	if err != nil {
		t.Fatal(err)
	}
	withPayload := "data:image/png;base64," + base64.StdEncoding.EncodeToString(append(raw, []byte("<script>untrusted metadata</script>")...))
	var saved store.Workspace
	if code := putProfile(t, h, token, map[string]string{"name": "Clean", "avatar": withPayload}, &saved); code != 200 || saved.Avatar != valid {
		t.Fatalf("avatar did not strip trailing data: %d", code)
	}
}
