package mailer

import (
	"bytes"
	"net/mail"
	"strings"
	"testing"
)

// The account key alert names the recipient and nothing else of the
// account, links only to the public console, and is refused for a local
// origin like every other template.
func TestAccountKeyChangedEmail(t *testing.T) {
	const origin = "https://app.wappie.thehappie.co"
	const recipient = "person.tag@example.com"
	model, err := accountKeyChangedEmail(origin, recipient, "")
	if err != nil {
		t.Fatal(err)
	}
	if model.Link != origin || model.HomeURL != origin || model.Code != "" || model.Workspace != "" {
		t.Fatalf("unexpected model: %+v", model)
	}
	text, page, err := model.render()
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{text, page} {
		if !strings.Contains(body, recipient) || !strings.Contains(body, "account key") || strings.Contains(body, "localhost") {
			t.Fatalf("alert body: %s", body)
		}
	}
	data, _, _, err := message("Wappie <accounts@example.com>", recipient, model)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil || msg.Header.Get("Subject") == "" || msg.Header.Get("Auto-Submitted") != "auto-generated" {
		t.Fatalf("alert message: %v %v", err, msg)
	}
	for _, local := range []string{"http://localhost:5173", "https://dev.localhost", "https://127.0.0.1"} {
		if _, err := accountKeyChangedEmail(local, recipient, "pt"); err == nil {
			t.Fatalf("an alert linked to %s", local)
		}
	}
}

// The alert goes in the account's language, English when it has none or the
// language has no words here; its advice is the callback page's, word for
// word (C-AUTHERR-04 and E-ALERT-07, approved 2026-10-05), and the
// template's own words follow the language.
func TestAccountKeyChangedEmailLanguages(t *testing.T) {
	const origin = "https://app.wappie.thehappie.co"
	advice := map[string]string{
		"en": "If you did not reset your The Happie Co account, change its password now and contact Wappie support before signing in again.",
		"pt": "Se você não redefiniu sua conta The Happie Co, troque a senha dela agora e fale com o suporte da Wappie antes de entrar de novo.",
		"es": "Si no restableciste tu cuenta de The Happie Co, cambia su contraseña ahora y contacta con el soporte de Wappie antes de volver a iniciar sesión.",
		"fr": "Si vous n’avez pas réinitialisé votre compte The Happie Co, changez son mot de passe maintenant et contactez le support de Wappie avant de vous reconnecter.",
		"de": "Wenn Sie Ihr The-Happie-Co-Konto nicht zurückgesetzt haben, ändern Sie jetzt sein Passwort und wenden Sie sich an den Wappie-Support, bevor Sie sich erneut anmelden.",
	}
	for lang, want := range map[string]string{"": "en", "en": "en", "pt": "pt", "pt-BR": "pt", "es": "es", "fr": "fr", "de": "de", "it": "en"} {
		model, err := accountKeyChangedEmail(origin, "ana@example.com", lang)
		if err != nil {
			t.Fatal(err)
		}
		if model.Lang != want || model.Expiry != advice[want] {
			t.Errorf("%q: lang %q, advice %q", lang, model.Lang, model.Expiry)
		}
		text, page, err := model.render()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(page, `<html lang="`+want+`">`) || !strings.Contains(page, model.LinkHelp) || !strings.Contains(text, model.HomeLabel+": "+origin) {
			t.Errorf("%q: the template's own words are not in its language:\n%s", lang, text)
		}
		if want != "en" && (strings.Contains(page, "If the button does not work") || strings.Contains(page, ">Open Wappie<")) {
			t.Errorf("%q: English template words in the alert", lang)
		}
		if strings.Contains(model.Intro+model.Expiry+model.Footer+model.Subject, "'") {
			t.Errorf("%q: a straight apostrophe in the alert", lang)
		}
	}
	// The other account e-mails keep the template's English words.
	signup, err := signupEmail(origin, "ana@example.com", "token")
	if err != nil {
		t.Fatal(err)
	}
	_, page, err := signup.render()
	if err != nil || !strings.Contains(page, `<html lang="en">`) || !strings.Contains(page, "If the button does not work") || !strings.Contains(page, ">Open Wappie<") {
		t.Fatalf("the sign-up e-mail: %v", err)
	}
}
