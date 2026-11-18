package authapi_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/config"
	"whatserver2/internal/store"
)

// id. alone owns a platform account's display name (DS52): each sign-in
// copies userinfo's name, an empty or invalid one keeps the stored name, a
// linked legacy account takes it at the link and follows it afterwards, and
// a local password account is never touched.
func TestPlatformNameFollowsTheProvider(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	ctx := context.Background()
	p := newPerson(t, "hana@example.com")
	_, first := h.signIn(t, p, 1)
	code, created, _, _ := h.createAccount(t, first.Ticket)
	if code != http.StatusOK || created.User.Name != "Ana" {
		t.Fatalf("account: %d %+v", code, created.User)
	}

	p.name = "  Ana Souza "
	code, s := h.signIn(t, p, 1)
	if code != http.StatusOK || s.Kind != "session" || s.User.Name != "Ana Souza" {
		t.Fatalf("after id.'s name changed: %d %+v", code, s.User)
	}
	var profile store.Profile
	if code := h.get(t, "/v1/auth/profile", &profile, s.Token); code != http.StatusOK || profile.Name != "Ana Souza" {
		t.Fatalf("profile: %d %+v", code, profile)
	}
	var me struct {
		User struct {
			Name string `json:"name"`
		} `json:"user"`
	}
	if code := h.get(t, "/v1/auth/me", &me, s.Token); code != http.StatusOK || me.User.Name != "Ana Souza" {
		t.Fatalf("me: %d %+v", code, me)
	}

	// A missing or unusable name never blanks or garbles the account's.
	for label, name := range map[string]string{
		"empty":             "",
		"blank":             "   ",
		"control character": "Ana\u0007Souza",
		"over 80 runes":     strings.Repeat("é", 81),
	} {
		p.name = name
		code, s := h.signIn(t, p, 1)
		if code != http.StatusOK || s.Kind != "session" || s.User.Name != "Ana Souza" {
			t.Fatalf("%s: %d %+v", label, code, s.User)
		}
	}
	p.name = strings.Repeat("é", 80)
	if code, s := h.signIn(t, p, 1); code != http.StatusOK || s.User.Name != p.name {
		t.Fatalf("80 runes: %d %q", code, s.User.Name)
	}

	// A local password account is never the provider's: its name stays,
	// whatever a caller asks.
	legacyID := uuid.MustParse(h.signed.User.ID)
	if took, err := h.users.SyncPlatformName(ctx, legacyID, "Intruder"); err != nil || took != "" {
		t.Fatalf("a local account took a name: %q %v", took, err)
	}
	if code := h.get(t, "/v1/auth/profile", &profile, h.signed.Token); code != http.StatusOK || profile.Name != "" {
		t.Fatalf("a local account's name: %d %+v", code, profile)
	}

	// A linked legacy account adopts id.'s name at the link, and follows it.
	q := newPerson(t, "passkey@example.com")
	q.name = "Bruno"
	_, b := h.signIn(t, q, 1)
	if b.Kind != "link_required" {
		t.Fatalf("link sign-in: %+v", b)
	}
	var linked platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link", map[string]string{"ticket": b.Ticket, "email": "passkey@example.com", "auth_key": h.account.AuthKey, "platform_wrap": randomWrap(t)}, &linked, "", nil); code != http.StatusOK || linked.User.Name != "Bruno" {
		t.Fatalf("link: %d %+v", code, linked.User)
	}
	q.name = "Bruno Lima"
	if code, s := h.signIn(t, q, 1); code != http.StatusOK || s.User.ID != h.signed.User.ID || s.User.Name != "Bruno Lima" {
		t.Fatalf("a linked account after id.'s name changed: %d %+v", code, s.User)
	}
}

// A link whose ticket carries no name keeps the legacy account's own.
func TestPlatformLinkWithNoNameKeepsTheAccounts(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	var profile store.Profile
	if code := methodRequest(t, h.harness, http.MethodPut, "/v1/auth/profile", map[string]string{"name": "Carla", "avatar": ""}, h.signed.Token, &profile); code != http.StatusOK || profile.Name != "Carla" {
		t.Fatalf("a local account names itself: %d %+v", code, profile)
	}
	q := newPerson(t, "passkey@example.com")
	q.name = ""
	_, b := h.signIn(t, q, 1)
	var linked platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link", map[string]string{"ticket": b.Ticket, "email": "passkey@example.com", "auth_key": h.account.AuthKey, "platform_wrap": randomWrap(t)}, &linked, "", nil); code != http.StatusOK || linked.User.Name != "Carla" {
		t.Fatalf("link: %d %+v", code, linked.User)
	}
}

// A new account takes id.'s name; the page's display_name is only the
// fallback when id. gave none (old pages still send it).
func TestPlatformNewAccountNameIsTheProviders(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	create := func(p person) platformAnswer {
		t.Helper()
		_, first := h.signIn(t, p, 1)
		if first.Kind != "new" || first.Name != strings.TrimSpace(p.name) {
			t.Fatalf("sign-in: %+v", first)
		}
		var out platformAnswer
		if code := h.pagePost(t, "/v1/auth/platform/account", map[string]string{"ticket": first.Ticket, "public_key": randomKey(t),
			"platform_wrap": randomWrap(t), "display_name": "Other"}, &out, "", nil); code != http.StatusOK {
			t.Fatalf("account: %d %+v", code, out)
		}
		return out
	}
	if out := create(newPerson(t, "dora@example.com")); out.User.Name != "Ana" {
		t.Fatalf("display_name won over id.'s name: %+v", out.User)
	}
	nameless := newPerson(t, "edu@example.com")
	nameless.name = ""
	if out := create(nameless); out.User.Name != "Other" {
		t.Fatalf("display_name is not the fallback: %+v", out.User)
	}
}

// PUT /v1/auth/profile ignores the name of a platform account and saves its
// photo: the answer carries the stored (id.'s) name. A local account's name
// is still its own, and still checked.
func TestPlatformProfileNameIsTheProviders(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p := newPerson(t, "ines@example.com")
	_, first := h.signIn(t, p, 1)
	code, created, _, _ := h.createAccount(t, first.Ticket)
	if code != http.StatusOK {
		t.Fatalf("account: %d %+v", code, created)
	}
	avatar := profileAvatar(t, 8, 8)
	var profile store.Profile
	if code := methodRequest(t, h.harness, http.MethodPut, "/v1/auth/profile", map[string]string{"name": "X", "avatar": avatar}, created.Token, &profile); code != http.StatusOK ||
		profile.Name != "Ana" || profile.Avatar == "" {
		t.Fatalf("a platform account's PUT: %d %+v", code, profile)
	}
	// A photo-only save, as the hosted console sends with no name field.
	if code := methodRequest(t, h.harness, http.MethodPut, "/v1/auth/profile", map[string]string{"name": "", "avatar": ""}, created.Token, &profile); code != http.StatusOK ||
		profile.Name != "Ana" || profile.Avatar != "" {
		t.Fatalf("an empty name of a platform account: %d %+v", code, profile)
	}
	// A bad photo is still refused.
	if code := methodRequest(t, h.harness, http.MethodPut, "/v1/auth/profile", map[string]string{"name": "Ana", "avatar": "data:image/png;base64,AAAA"}, created.Token, nil); code != http.StatusBadRequest {
		t.Fatalf("a bad photo: %d", code)
	}
	if code := h.get(t, "/v1/auth/profile", &profile, created.Token); code != http.StatusOK || profile.Name != "Ana" {
		t.Fatalf("profile: %d %+v", code, profile)
	}

	// The local password account's PUT is as before.
	if code := methodRequest(t, h.harness, http.MethodPut, "/v1/auth/profile", map[string]string{"name": "", "avatar": ""}, h.signed.Token, nil); code != http.StatusBadRequest {
		t.Fatalf("a local account's empty name: %d", code)
	}
	if code := methodRequest(t, h.harness, http.MethodPut, "/v1/auth/profile", map[string]string{"name": "Local Name", "avatar": avatar}, h.signed.Token, &profile); code != http.StatusOK ||
		profile.Name != "Local Name" || profile.Avatar == "" {
		t.Fatalf("a local account's PUT: %d %+v", code, profile)
	}
}
