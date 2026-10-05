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
	model, err := accountKeyChangedEmail(origin, recipient)
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
		if _, err := accountKeyChangedEmail(local, recipient); err == nil {
			t.Fatalf("an alert linked to %s", local)
		}
	}
}
