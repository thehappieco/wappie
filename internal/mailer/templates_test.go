package mailer

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestAllEmailTemplatesHaveSafePublicActionsAndMIMEAlternatives(t *testing.T) {
	const origin = "https://app.wappie.thehappie.co"
	const recipient = "person+tag@example.com"
	const code = "a+b/c=some-long-secret"
	const workspace = `Acme & <img src="https://bad.example" onerror="alert(1)">`
	verification, err := signupEmail(origin, recipient, code)
	if err != nil {
		t.Fatal(err)
	}
	invite, err := invitationEmail(origin, recipient, code, workspace)
	if err != nil {
		t.Fatal(err)
	}
	for name, model := range map[string]accountEmail{"verification": verification, "invitation": invite} {
		t.Run(name, func(t *testing.T) {
			data, _, _, err := message("Wappie <accounts@example.com>", recipient, model)
			if err != nil {
				t.Fatal(err)
			}
			message, err := mail.ReadMessage(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if message.Header.Get("Date") == "" || message.Header.Get("Message-ID") == "" {
				t.Fatal("missing delivery headers")
			}
			if message.Header.Get("Auto-Submitted") != "auto-generated" {
				t.Fatal("transactional mail must identify itself to auto-responders")
			}
			kind, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
			if err != nil || kind != "multipart/related" {
				t.Fatal("missing related image container")
			}
			parts := multipart.NewReader(message.Body, params["boundary"])
			alternative, err := parts.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			kind, params, err = mime.ParseMediaType(alternative.Header.Get("Content-Type"))
			if err != nil || kind != "multipart/alternative" {
				t.Fatal("missing text/HTML alternatives")
			}
			alternatives := multipart.NewReader(alternative, params["boundary"])
			var htmlBody string
			for _, expected := range []string{"text/plain", "text/html"} {
				part, err := alternatives.NextPart()
				if err != nil {
					t.Fatal(err)
				}
				kind, _, err = mime.ParseMediaType(part.Header.Get("Content-Type"))
				if err != nil || kind != expected {
					t.Fatalf("expected %s, got %s", expected, kind)
				}
				body, err := io.ReadAll(part)
				if err != nil {
					t.Fatal(err)
				}
				if expected == "text/plain" && (!bytes.Contains(body, []byte(model.Action)) || !bytes.Contains(body, []byte(recipient)) || !bytes.Contains(body, []byte(code))) {
					t.Fatal("action, recipient or fallback code missing")
				}
				if expected == "text/plain" && !bytes.Contains(body, []byte(model.Link)) {
					t.Fatal("plain fallback lost action URL")
				}
				if expected == "text/html" {
					htmlBody = string(body)
				}
			}
			doc, err := html.Parse(strings.NewReader(htmlBody))
			if err != nil {
				t.Fatal(err)
			}
			images, actions := 0, 0
			var visible strings.Builder
			var visit func(*html.Node)
			visit = func(node *html.Node) {
				if node.Type == html.TextNode {
					visible.WriteString(node.Data)
				}
				if node.Type == html.ElementNode {
					if node.Data == "script" || node.Data == "form" {
						t.Error("active content in email")
					}
					for _, attr := range node.Attr {
						if strings.HasPrefix(attr.Key, "on") {
							t.Error("event handler in email")
						}
						if node.Data == "img" && attr.Key == "src" {
							images++
							if attr.Val != "cid:wappie-brand" {
								t.Error("external or injected image")
							}
						}
						if node.Data == "a" && attr.Key == "href" {
							u, err := url.Parse(attr.Val)
							if err != nil || u.Scheme != "https" || u.Host != "app.wappie.thehappie.co" {
								t.Error("non-public or foreign email link")
								continue
							}
							if u.Fragment != "" {
								actions++
								fragment, _ := url.ParseQuery(u.Fragment)
								field := "invite"
								if name == "verification" {
									field = "verification"
								}
								if fragment.Get(field) != code || fragment.Get("email") != recipient || u.Path != "/console" || u.RawQuery != "signup=1" {
									t.Error("action did not preserve invitation/verification")
								}
							}
						}
					}
				}
				for child := node.FirstChild; child != nil; child = child.NextSibling {
					visit(child)
				}
			}
			visit(doc)
			for _, want := range []string{model.Action, recipient, code, model.Workspace} {
				if !strings.Contains(visible.String(), want) {
					t.Error("HTML display lost action, recipient, code or workspace")
				}
			}
			if images != 1 || actions != 2 {
				t.Fatalf("expected one logo and button/fallback actions, got %d/%d", images, actions)
			}
			logo, err := parts.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			if logo.Header.Get("Content-ID") != "<wappie-brand>" {
				t.Fatal("logo CID mismatch")
			}
			img, err := png.DecodeConfig(base64.NewDecoder(base64.StdEncoding, logo))
			if err != nil || img.Width < 88 || img.Height < 88 {
				t.Fatal("missing high resolution embedded logo")
			}
		})
	}
}

func TestTemplatesRefuseLocalhostEvenWhenSenderBypassesConfigLoad(t *testing.T) {
	for _, origin := range []string{"http://localhost:5173", "https://localhost", "https://dev.localhost", "https://localhost.", "https://127.0.0.1", "https://[::1]", "https://0.0.0.0", "https://[::]", "https://127.1", "https://2130706433", "https://0x7f000001", "https://app.example.com/path", "https://app.example.com/?redirect=wrong", "https://app.example.com/#fragment"} {
		if _, err := signupEmail(origin, "a@example.com", "token"); err == nil {
			t.Errorf("signup accepted %s", origin)
		}
		if _, err := invitationEmail(origin, "a@example.com", "code", "Team"); err == nil {
			t.Errorf("invitation accepted %s", origin)
		}
	}
}
