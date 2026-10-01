package mailer

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
)

// mcpBodies renders a notice into a message and returns its plain-text and
// HTML bodies.
func mcpBodies(t *testing.T, n MCPNotice) (mcpEmail, string, string) {
	t.Helper()
	model, err := mcpNoticeEmail("https://app.wappie.thehappie.co", n)
	if err != nil {
		t.Fatal(err)
	}
	data, _, _, err := message("Wappie <accounts@example.com>", "owner@example.com", model)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject")); err != nil || subject != model.Subject {
		t.Fatalf("subject = %q %v", subject, err)
	}
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	related := multipart.NewReader(msg.Body, params["boundary"])
	alternative, err := related.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	_, params, err = mime.ParseMediaType(alternative.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	parts := multipart.NewReader(alternative, params["boundary"])
	var bodies [2]string
	for i := range bodies {
		part, err := parts.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}
		bodies[i] = string(body)
	}
	return model, bodies[0], bodies[1]
}

// Every notice: the domain, the tier, the numbers, what it reads and until
// when; exactly one link, the revoke-only one, and nothing that leads to a
// page where a password is typed; the console's address as plain text in the
// footer; and no field that could carry the client's claimed name.
func TestMCPNoticeEmail(t *testing.T) {
	const revoke = "https://api.wappie.thehappie.co/v1/mcp/revoke-link/" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	at := time.Date(2026, 10, 1, 13, 4, 0, 0, time.UTC)
	for name, n := range map[string]MCPNotice{
		"unknown text": {Event: "activated", ClientHost: "agent.example.com", Tier: "unknown", Numbers: 2, Text: true, Attachments: true,
			HistoryDays: 30, ExpiresAt: at.Add(7 * 24 * time.Hour), At: at, RevokeLink: revoke},
		"tested metadata":   {Event: "activated", ClientHost: "claude.ai", Tier: "tested", Numbers: 1, ExpiresAt: at.AddDate(0, 3, 0), At: at, RevokeLink: revoke},
		"a limit":           {Event: "daily_messages", ClientHost: "agent.example.com", Tier: "unknown", Numbers: 3, Text: true, HistoryDays: 7, ExpiresAt: at, At: at, RevokeLink: revoke},
		"a token's network": {Event: "network", Tier: "token", Numbers: 1, HistoryDays: 30, ExpiresAt: at, At: at, RevokeLink: revoke},
	} {
		t.Run(name, func(t *testing.T) {
			model, plain, body := mcpBodies(t, n)
			for _, want := range []string{model.Intro, "Numbers: ", "Valid until: ", "Don't recognise it?", "Revoke only this connection",
				"Wappie never asks for your password from an e-mail. To see your assistants, open the console yourself at app.wappie.thehappie.co.",
				revoke} {
				if !strings.Contains(plain, want) {
					t.Errorf("plain text lacks %q:\n%s", want, plain)
				}
			}
			if strings.Contains(plain, "https://app.wappie.thehappie.co") || strings.Contains(plain, "Open Wappie") {
				t.Errorf("the plain text links to the console:\n%s", plain)
			}
			if n.ClientHost != "" && !strings.Contains(plain, n.ClientHost) {
				t.Errorf("the domain is missing:\n%s", plain)
			}
			if n.HistoryDays > 0 && !strings.Contains(plain, "the last") {
				t.Errorf("the history window is missing:\n%s", plain)
			}
			doc, err := html.Parse(strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			var hrefs []string
			var visible strings.Builder
			var visit func(*html.Node)
			visit = func(node *html.Node) {
				if node.Type == html.TextNode {
					visible.WriteString(node.Data)
				}
				if node.Type == html.ElementNode {
					if node.Data == "script" || node.Data == "form" {
						t.Error("active content in the e-mail")
					}
					for _, attr := range node.Attr {
						if node.Data == "a" && attr.Key == "href" {
							hrefs = append(hrefs, attr.Val)
						}
						if node.Data == "img" && attr.Key == "src" && attr.Val != "cid:wappie-brand" {
							t.Error("an external image")
						}
					}
				}
				for child := node.FirstChild; child != nil; child = child.NextSibling {
					visit(child)
				}
			}
			visit(doc)
			if len(hrefs) != 2 || hrefs[0] != revoke || hrefs[1] != revoke {
				t.Fatalf("links = %v, want only the revoke-only link", hrefs)
			}
			if !strings.Contains(visible.String(), "app.wappie.thehappie.co") || !strings.Contains(visible.String(), model.Intro) {
				t.Error("the HTML lost the footer or the intro")
			}
		})
	}
	// The wording for a token never names a host, and a limit says which.
	if model, _, _ := mcpBodies(t, MCPNotice{Event: "network", Tier: "token", Numbers: 1, ExpiresAt: at, At: at, RevokeLink: revoke}); !strings.Contains(model.Intro, "console connection token") {
		t.Errorf("token intro = %q", model.Intro)
	}
	if model, _, _ := mcpBodies(t, MCPNotice{Event: "first_hour_attachments", ClientHost: "a.example.com", Tier: "unknown", Numbers: 1, ExpiresAt: at, At: at, RevokeLink: revoke}); !strings.Contains(model.Intro, "attachments for its first hour") {
		t.Errorf("limit intro = %q", model.Intro)
	}
	for name, n := range map[string]MCPNotice{
		"not an event":   {Event: "spam", Tier: "unknown", RevokeLink: revoke},
		"not a tier":     {Event: "activated", Tier: "legacy", RevokeLink: revoke},
		"no link":        {Event: "activated", Tier: "tested"},
		"a relative one": {Event: "activated", Tier: "tested", RevokeLink: "/v1/mcp/revoke-link/x"},
	} {
		if _, err := mcpNoticeEmail("https://app.wappie.thehappie.co", n); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}
