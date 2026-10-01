package mailer

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
)

// mcpBodies renders a notice into a message and returns its plain-text and
// HTML bodies.
func mcpBodies(t *testing.T, n MCPNotice) (mcpEmail, string, string) {
	t.Helper()
	model, err := mcpNoticeEmail(n)
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

// Every notice, in one language (English unless the recipient's locale has
// words): the domain or the token's label, the tier, the workspace, the
// numbers, what it reads and until when; exactly one link, the revoke-only
// one, behind one button, and nothing that leads to a page where a password
// is typed; no console address at all, and no domain a mail client could
// make a link of in the HTML; no field that could carry the client's claimed
// name.
func TestMCPNoticeEmail(t *testing.T) {
	const revoke = "https://api.wappie.thehappie.co/v1/mcp/revoke-link/" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	at := time.Date(2026, 10, 1, 13, 4, 0, 0, time.UTC)
	const enFooter = "Wappie's e-mails about assistants never ask for your password. Their only button revokes one connection. To see your assistants, open the Wappie console yourself."
	const ptFooter = "Os e-mails da Wappie sobre assistentes nunca pedem sua senha. O único botão deles revoga uma conexão. Para ver seus assistentes, abra você mesmo o console da Wappie."
	for name, n := range map[string]MCPNotice{
		"unknown text": {Event: "activated", ClientHost: "agent.example.com", Tier: "unknown", Workspace: "Acme", Numbers: 2, Text: true, Attachments: true,
			HistoryDays: 30, ExpiresAt: at.Add(7 * 24 * time.Hour), At: at, RevokeLink: revoke},
		"tested metadata": {Event: "activated", ClientHost: "claude.ai", Tier: "tested", Workspace: "Acme", Numbers: 1, ExpiresAt: at.AddDate(0, 3, 0), At: at, RevokeLink: revoke},
		"a limit": {Event: "daily_messages", ClientHost: "agent.example.com", Tier: "unknown", Workspace: "acme.com", Numbers: 3, Text: true, HistoryDays: 7,
			ExpiresAt: at, At: at, RevokeLink: revoke},
		"a token's network": {Event: "network", Tier: "token", Label: "Cursor on the laptop", Workspace: "Acme", Numbers: 1, HistoryDays: 30, ExpiresAt: at, At: at, RevokeLink: revoke},
		"a token":           {Event: "activated", Tier: "token", Label: "n8n server", Workspace: "Acme", Numbers: 1, HistoryDays: 30, ExpiresAt: at, At: at, RevokeLink: revoke},
		"Portuguese":        {Event: "activated", ClientHost: "agent.example.com", Tier: "unknown", Workspace: "Acme", Numbers: 2, Text: true, HistoryDays: 30, ExpiresAt: at, At: at, RevokeLink: revoke, Lang: "pt-BR"},
	} {
		t.Run(name, func(t *testing.T) {
			model, plain, body := mcpBodies(t, n)
			pt := n.Lang == "pt-BR"
			wants := []string{model.Intro, "Numbers: ", "Valid until: ", "Don't recognize it? Revoke only this connection", enFooter, "Workspace: " + n.Workspace}
			if pt {
				wants = []string{model.Intro, "Números: ", "Válido até: ", "Não reconhece? Revogar só esta conexão", ptFooter, "Espaço de trabalho: " + n.Workspace}
			}
			if model.Lang != map[bool]string{true: "pt", false: "en"}[pt] || !strings.Contains(body, `<html lang="`+model.Lang+`">`) {
				t.Fatalf("language = %q", model.Lang)
			}
			for _, want := range append(wants, "“"+n.Workspace+"”", revoke) {
				if !strings.Contains(plain, want) {
					t.Errorf("plain text lacks %q:\n%s", want, plain)
				}
			}
			// One language per message: none of the other's words.
			for _, other := range []string{"Números: ", "Numbers: ", enFooter, ptFooter} {
				if !strings.Contains(strings.Join(wants, "\n"), other) && strings.Contains(plain, other) {
					t.Errorf("plain text carries the other language's %q:\n%s", other, plain)
				}
			}
			if strings.Contains(plain, "app.wappie.thehappie.co") || strings.Contains(plain, "Open Wappie") || strings.Contains(plain, "recognise") ||
				strings.Contains(plain, "never asks for your password from an e-mail") {
				t.Errorf("the plain text names the console's address, a spelling the console does not use, or the old footer:\n%s", plain)
			}
			if n.ClientHost != "" && !strings.Contains(plain, n.ClientHost) {
				t.Errorf("the domain is missing:\n%s", plain)
			}
			if n.Tier == "token" && (!strings.Contains(plain, "“"+n.Label+"”") || strings.Contains(plain, "(a console connection token)")) {
				t.Errorf("the token is not named by its label alone:\n%s", plain)
			}
			if n.HistoryDays > 0 && !strings.Contains(plain, map[bool]string{true: "últimos", false: "the last"}[pt]) {
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
					visible.WriteString(node.Data + "\n")
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
			text := strings.ReplaceAll(visible.String(), revoke, "")
			// A name in the text keeps an invisible break after each dot, so no mail client links it.
			if names := regexp.MustCompile(`[A-Za-z0-9-]\.[A-Za-z0-9]`).FindAllString(text, -1); len(names) != 0 {
				t.Errorf("a name a mail client could link: %v", names)
			}
			if n.ClientHost != "" && !strings.Contains(text, noAutolink(n.ClientHost)) {
				t.Error("the HTML lost the domain")
			}
			if !strings.Contains(strings.ReplaceAll(text, "\u200c", ""), model.Intro) {
				t.Error("the HTML lost the intro")
			}
		})
	}
	// A limit says which; the event's time is there, in UTC.
	model, plain, _ := mcpBodies(t, MCPNotice{Event: "first_hour_attachments", ClientHost: "a.example.com", Tier: "unknown", Workspace: "Acme", Numbers: 1, ExpiresAt: at, At: at, RevokeLink: revoke})
	if !strings.Contains(model.Intro, "attachments for its first hour") || !strings.Contains(plain, "When: 1 October 2026, 13:04 UTC") {
		t.Errorf("limit = %+v\n%s", model, plain)
	}
	model, plain, _ = mcpBodies(t, MCPNotice{Event: "first_hour_attachments", ClientHost: "a.example.com", Tier: "unknown", Workspace: "Acme", Numbers: 1, ExpiresAt: at, At: at, RevokeLink: revoke, Lang: "pt"})
	if !strings.Contains(model.Intro, "anexos da primeira hora") || !strings.Contains(plain, "Quando: 1 de outubro de 2026, 13:04 UTC") {
		t.Errorf("Portuguese limit = %+v\n%s", model, plain)
	}
	// Metadata says so, and does not claim the archive.
	model, _, _ = mcpBodies(t, MCPNotice{Event: "activated", ClientHost: "claude.ai", Tier: "tested", Workspace: "Acme", Numbers: 2, ExpiresAt: at, At: at, RevokeLink: revoke})
	if model.Intro != "claude.ai (tested by Wappie) can now see who wrote to whom and when, but not the text, on 2 numbers in the workspace “Acme”." {
		t.Errorf("metadata intro = %q", model.Intro)
	}
	// A locale without words, or none, is English.
	for _, lang := range []string{"", "de", "fr-CA", "xx", "pt_PT"} {
		if got := wordsFor(lang).lang; got != map[bool]string{true: "pt", false: "en"}[lang == "pt_PT"] {
			t.Errorf("%q speaks %q", lang, got)
		}
	}
	for name, n := range map[string]MCPNotice{
		"not an event":       {Event: "spam", ClientHost: "a.example.com", Tier: "unknown", Workspace: "Acme", RevokeLink: revoke},
		"not a tier":         {Event: "activated", ClientHost: "a.example.com", Tier: "legacy", Workspace: "Acme", RevokeLink: revoke},
		"no link":            {Event: "activated", ClientHost: "a.example.com", Tier: "tested", Workspace: "Acme"},
		"a relative one":     {Event: "activated", ClientHost: "a.example.com", Tier: "tested", Workspace: "Acme", RevokeLink: "/v1/mcp/revoke-link/x"},
		"a token's host":     {Event: "activated", ClientHost: "a.example.com", Tier: "token", Label: "x", Workspace: "Acme", RevokeLink: revoke},
		"a token, no label":  {Event: "activated", Tier: "token", Workspace: "Acme", RevokeLink: revoke},
		"a client's label":   {Event: "activated", ClientHost: "a.example.com", Label: "x", Tier: "unknown", Workspace: "Acme", RevokeLink: revoke},
		"no workspace named": {Event: "activated", ClientHost: "a.example.com", Tier: "unknown", RevokeLink: revoke},
	} {
		if _, err := mcpNoticeEmail(n); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}
