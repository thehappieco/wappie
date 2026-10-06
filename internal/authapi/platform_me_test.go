package authapi_test

import (
	"net/http"
	"testing"

	"whatserver2/internal/config"
)

// /v1/auth/me never hands the legacy password wrap to a session that came
// through the provider, nor does a workspace switch made from one, before or
// after a step-up; a session of the same linked account that signed in with
// the old password still gets it, as its switches do.
func TestPlatformSessionsAreNotHandedTheLegacyWrap(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p := newPerson(t, "passkey@example.com")
	_, answer := h.signIn(t, p, 1)
	var linked platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link", map[string]string{"ticket": answer.Ticket, "email": "passkey@example.com",
		"auth_key": h.account.AuthKey, "platform_wrap": randomWrap(t)}, &linked, "", nil); code != http.StatusOK {
		t.Fatalf("link: %d %+v", code, linked)
	}
	_, through := h.signIn(t, p, 1)
	var password sessionReply
	if code := h.post(t, "/v1/auth/login", map[string]string{"email": "passkey@example.com", "auth_key": h.account.AuthKey}, &password, ""); code != http.StatusOK ||
		password.User.WrappedUSK != h.account.WrappedUSK {
		t.Fatalf("legacy sign-in: %d", code)
	}
	wrapOf := func(name, token string) string {
		t.Helper()
		var me struct {
			User struct {
				ID         string `json:"id"`
				WrappedUSK string `json:"wrapped_usk"`
				PublicKey  string `json:"public_key"`
			} `json:"user"`
		}
		if code := h.get(t, "/v1/auth/me", &me, token); code != http.StatusOK || me.User.ID != h.signed.User.ID || me.User.PublicKey != h.account.PublicKey {
			t.Fatalf("%s: me %d %+v", name, code, me)
		}
		return me.User.WrappedUSK
	}
	switchFrom := func(name, token string) sessionReply {
		t.Helper()
		var switched sessionReply
		if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": linked.User.TenantID}, &switched, token); code != http.StatusOK {
			t.Fatalf("%s: switch %d", name, code)
		}
		return switched
	}
	for name, token := range map[string]string{"the link's session": linked.Token, "a sign-in through the provider": through.Token} {
		if wrap := wrapOf(name, token); wrap != "" {
			t.Fatalf("%s was handed the legacy wrap", name)
		}
		switched := switchFrom(name, token)
		if switched.User.WrappedUSK != "" || wrapOf(name+", switched", switched.Token) != "" {
			t.Fatalf("a switch from %s was handed the legacy wrap", name)
		}
	}
	// After a step-up at the provider, still none.
	h.age(t, through.Token)
	if code, _ := h.start(t, through.Token); code != http.StatusOK {
		t.Fatal(code)
	}
	if code, out := h.finish(t, through.Token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusOK || !out.Fresh {
		t.Fatalf("finish: %d %+v", code, out)
	}
	if wrapOf("after a step-up", through.Token) != "" {
		t.Fatal("a step-up at the provider handed the legacy wrap")
	}
	// The old password proved the password: its session keeps the wrap.
	if wrapOf("the password session", password.Token) != h.account.WrappedUSK {
		t.Fatal("the password session lost the legacy wrap")
	}
	if switched := switchFrom("the password session", password.Token); switched.User.WrappedUSK != h.account.WrappedUSK ||
		wrapOf("the password session, switched", switched.Token) != h.account.WrappedUSK {
		t.Fatal("a switch from the password session lost the legacy wrap")
	}
}
