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
	const enFooter = "Wappie’s e-mails about assistants never ask for your password. Their only button revokes one connection. To see your assistants, open the Wappie console yourself."
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
			wants := []string{model.Intro, "Numbers: ", "Valid until: ", "Don’t recognize it? Revoke only this connection", enFooter, "Workspace: " + n.Workspace}
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
	// The console's five languages have words, a region or a case aside; a
	// locale without words, or none, is English.
	for lang, want := range map[string]string{"": "en", "xx": "en", "it": "en", "pt_PT": "pt", "pt-BR": "pt", "es-MX": "es", "fr-CA": "fr", "DE": "de", "en-GB": "en"} {
		if got := wordsFor(lang).lang; got != want {
			t.Errorf("%q speaks %q, want %q", lang, got, want)
		}
	}
	// Every language says every event, tier and fact, with no word left from
	// another and no placeholder left unfilled.
	for _, words := range mcpLanguages {
		for name, n := range map[string]MCPNotice{
			"text":    {Event: "activated", ClientHost: "agent.example.com", Tier: "unknown", Workspace: "Acme", Numbers: 2, Text: true, HistoryDays: 30, ExpiresAt: at, At: at, RevokeLink: revoke},
			"media":   {Event: "activated", ClientHost: "claude.ai", Tier: "tested", Workspace: "Acme", Numbers: 1, Text: true, Attachments: true, ExpiresAt: at, At: at, RevokeLink: revoke},
			"meta":    {Event: "activated", ClientHost: "chatgpt.com", Tier: "local", Workspace: "Acme", Numbers: 3, ExpiresAt: at, At: at, RevokeLink: revoke},
			"limit":   {Event: "daily_attachments", ClientHost: "agent.example.com", Tier: "unknown", Workspace: "Acme", Numbers: 1, Text: true, ExpiresAt: at, At: at, RevokeLink: revoke},
			"token":   {Event: "activated", Tier: "token", Label: "n8n", Workspace: "Acme", Numbers: 1, HistoryDays: 7, ExpiresAt: at, At: at, RevokeLink: revoke},
			"network": {Event: "network", Tier: "token", Label: "n8n", Workspace: "Acme", Numbers: 1, ExpiresAt: at, At: at, RevokeLink: revoke},
			"client":  {Event: "network", ClientHost: "agent.example.com", Tier: "unknown", Workspace: "Acme", Numbers: 1, ExpiresAt: at, At: at, RevokeLink: revoke},
		} {
			n.Lang = words.lang
			model, plain, _ := mcpBodies(t, n)
			if model.Lang != words.lang || model.Title == "" || model.Intro == "" || len(model.Facts) != 6 {
				t.Errorf("%s %s = %+v", words.lang, name, model)
			}
			if strings.ContainsAny(plain, "{}") || strings.Contains(plain, "%!") || strings.Contains(plain, "%s") || strings.Contains(plain, "%d") {
				t.Errorf("%s %s left a placeholder:\n%s", words.lang, name, plain)
			}
			if !strings.Contains(plain, words.footer) || !strings.Contains(plain, words.action) {
				t.Errorf("%s %s lacks its own words:\n%s", words.lang, name, plain)
			}
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

// The renewal notice: in the recipient's language, how many connections wait
// and which, and where to go, with no link at all, since renewing asks for a
// passkey or the password.
func TestMCPRenewalEmail(t *testing.T) {
	since := time.Date(2026, 10, 5, 9, 30, 0, 0, time.UTC)
	for lang, want := range map[string][2]string{
		"":   {"Your assistants need renewing", "2 assistant connections in the workspace “acme.com”"},
		"pt": {"Seus assistentes precisam ser renovados", "2 conexões de assistentes do espaço de trabalho “acme.com”"},
		"es": {"Tus asistentes necesitan renovarse", "2 conexiones de asistentes del espacio de trabajo “acme.com”"},
		"fr": {"Vos assistants doivent être renouvelés", "2 connexions d’assistants de l’espace de travail « acme.com »"},
		"de": {"Ihre Assistenten müssen erneuert werden", "2 Assistentenverbindungen im Arbeitsbereich „acme.com“"},
	} {
		model, err := mcpRenewalEmail(MCPRenewal{Workspace: "acme.com", Assistants: []string{"Claude", "agent.example.com"}, Since: since, Lang: lang})
		if err != nil {
			t.Fatal(err)
		}
		if model.Subject != want[0] || !strings.HasPrefix(model.Intro, want[1]) || model.Link != "" || model.Steps == "" {
			t.Errorf("%q = %+v", lang, model)
		}
		data, _, _, err := message("Wappie <accounts@example.com>", "owner@example.com", model)
		if err != nil {
			t.Fatal(err)
		}
		body := string(data)
		if strings.Contains(body, "href=") || strings.Contains(body, "http://") || strings.Contains(body, "https://") {
			t.Errorf("%q carries a link", lang)
		}
		plain, _, err := model.render()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(plain, "Claude, agent.example.com") || !strings.Contains(plain, model.Steps) || strings.ContainsAny(plain, "{}") {
			t.Errorf("%q plain =\n%s", lang, plain)
		}
	}
	one, err := mcpRenewalEmail(MCPRenewal{Workspace: "Acme", Assistants: []string{"Claude"}, Since: since, Lang: "pt-BR"})
	if err != nil || one.Subject != "Seu assistente precisa ser renovado" || !strings.HasPrefix(one.Intro, "Uma conexão") {
		t.Fatalf("one = %+v %v", one, err)
	}
	for name, n := range map[string]MCPRenewal{
		"no workspace":        {Assistants: []string{"Claude"}},
		"no connection":       {Workspace: "Acme"},
		"more one by one":     {Workspace: "Acme", Assistants: []string{"Claude"}, OneByOne: 2},
		"fewer than none one": {Workspace: "Acme", Assistants: []string{"Claude"}, OneByOne: -1},
	} {
		if _, err := mcpRenewalEmail(n); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}

// The renewal notice's words: the footer is every notice's own, word for
// word (D10, 5); no text names a restart as the cause, since a workspace
// that turned text off and on again waits the same way (D10, 7); English
// uses the typographic apostrophe (D10, 9); and the steps name the console's
// buttons for what waits. Renew all renews tested connections only, so an
// untested client's or a token's is sent to its own Renew.
func TestMCPRenewalWords(t *testing.T) {
	since := time.Date(2026, 10, 5, 9, 30, 0, 0, time.UTC)
	buttons := map[string][2]string{
		"en": {"Renew all", "Renew beside"}, "pt": {"Renovar todas", "Renovar ao lado"}, "es": {"Renovar todas", "Renovar junto a"},
		"fr": {"Tout renouveler", "Renouveler à côté"}, "de": {"Alle erneuern", "Erneuern"},
	}
	restart := []string{"restart", "reinici", "redémarr", "neu gestartet", "reinicia"}
	for _, words := range mcpLanguages {
		r, ok := renewalLanguages[words.lang]
		if !ok {
			t.Fatalf("%s has no renewal words", words.lang)
		}
		all := []string{r.titleOne, r.titleMany, r.introOne, r.introMany, r.question, r.allOne, r.allMany, r.eachOne, r.eachMany, r.mixed}
		all = append(all, r.facts[:]...)
		for _, text := range all {
			for _, word := range restart {
				if strings.Contains(strings.ToLower(text), word) {
					t.Errorf("%s names a restart: %q", words.lang, text)
				}
			}
			if words.lang == "en" && strings.Contains(text, "'") {
				t.Errorf("an English text without the typographic apostrophe: %q", text)
			}
		}
		for name, tc := range map[string]struct {
			assistants []string
			oneByOne   int
			want       string
			all, each  bool
		}{
			"one tested":     {[]string{"Claude"}, 0, r.allOne, true, false},
			"tested":         {[]string{"Claude", "ChatGPT"}, 0, r.allMany, true, false},
			"one untested":   {[]string{"agent.example.com"}, 1, r.eachOne, false, true},
			"untested":       {[]string{"agent.example.com", "n8n"}, 2, r.eachMany, false, true},
			"some of either": {[]string{"Claude", "n8n", "agent.example.com"}, 2, r.mixed, true, true},
		} {
			model, err := mcpRenewalEmail(MCPRenewal{Workspace: "Acme", Assistants: tc.assistants, OneByOne: tc.oneByOne, Since: since, Lang: words.lang})
			if err != nil {
				t.Fatal(err)
			}
			if model.Steps != tc.want || model.Footer != words.footer {
				t.Errorf("%s %s = steps %q, footer %q", words.lang, name, model.Steps, model.Footer)
			}
			if strings.Contains(model.Steps, buttons[words.lang][0]) != tc.all {
				t.Errorf("%s %s: Renew all said %v: %q", words.lang, name, !tc.all, model.Steps)
			}
			if tc.each && !strings.Contains(model.Steps, buttons[words.lang][1]) {
				t.Errorf("%s %s: no Renew of its own: %q", words.lang, name, model.Steps)
			}
		}
	}
}
