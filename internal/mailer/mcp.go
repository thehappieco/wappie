package mailer

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// The new-assistant notice (docs/mcp-enclave.md §19.22): an assistant
// connected to a workspace, or one reached a reading limit. It goes to the
// person who consented and to the workspace's owners.
//
// What it must not carry decides its shape. Never the name the client gave
// itself: an attacker's text, sent from Wappie's domain. Never a link that
// leads to a page where a password is typed: a spoofed copy that taught
// people to click and then sign in would be worse than any leak it warns of,
// because the Wappie password opens the number keys. So the account
// template, whose logo and footer link to the console, is not used; the one
// link is the revoke-only link, which needs no session and can do nothing but
// revoke this one connection, and the console is named without an address.
// The HTML part also keeps mail clients from turning a domain in the text
// (the client's, or a workspace named like one) into a link of their own: a
// zero-width non-joiner follows each dot inside a name.
//
// One message, in one language: the recipient's preferred locale when the
// account has one this server knows, English otherwise. Accounts carry no
// locale on this server today (the console keeps its language in the
// browser), so every notice goes in English until one does; the Portuguese
// words wait for that. A console token is named by its label, the words a
// workspace admin chose for it, never by anything a client said. The texts
// are drafts for the owner (docs/mcp-enclave.md §19.22).

//go:embed templates/mcp.html
var mcpTemplate string

var mcpHTML = template.Must(template.New("mcp").Parse(mcpTemplate))

// MCPNotice is what a notice e-mail says.
type MCPNotice struct {
	// Event is "activated", or the budget_hit code of the reading limit
	// reached: daily_messages, daily_attachments, first_hour_messages,
	// first_hour_attachments, or network for a token's call from a network
	// it does not allow.
	Event string
	// ClientHost is the client's verified host in ASCII; empty for a
	// console token, which has none.
	ClientHost string
	// Label is a console token's label; empty for an assistant.
	Label string
	// Workspace is the workspace's name.
	Workspace string
	// Tier is "tested", "local" (a tested app on the person's computer),
	// "unknown" or "token".
	Tier string
	// Numbers is how many numbers the connection reads.
	Numbers int
	// Text and Attachments are what it may read beyond metadata.
	Text, Attachments bool
	// HistoryDays is the window an untested client or a token reads, 0 for
	// the whole history.
	HistoryDays int
	// ExpiresAt is when the connection ends; At when the event happened.
	ExpiresAt, At time.Time
	// RevokeLink is the revoke-only link, on this server's public origin.
	RevokeLink string
	// Lang is the recipient's preferred locale ("pt", "en", "pt-BR"...), ""
	// when the account has none; a language without words here is English.
	Lang string
}

// MCPConnected sends a notice to one address.
func (s Sender) MCPConnected(ctx context.Context, email string, n MCPNotice) error {
	model, err := mcpNoticeEmail(n)
	if err != nil {
		return err
	}
	return s.send(ctx, email, model)
}

// mcpEmail is a notice as the template shows it: its title, intro and facts,
// the one question, the one button and the footer, in one language.
type mcpEmail struct {
	Lang, Kicker, Subject, Preheader, Title, Intro string
	Facts                                          []string
	Question, Action, Link, LinkHelp, Footer       string
}

func (m mcpEmail) subject() string { return m.Subject }

// mcpWords are a notice's words in one language.
type mcpWords struct {
	lang, kicker                string
	tiers, limits, titles       map[string]string
	token, assistant, tokenFact string
	numbers                     func(int) string
	reads                       func(text, attachments bool, days int) string
	activated                   map[string]string
	history                     string
	limit, network              string
	networkClient               string
	date                        func(time.Time) string
	facts                       [6]string
	question, action, linkHelp  string
	footer                      string
}

var ptMonths = [...]string{"janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"}

// The words of each language, English first: the fallback. {who} is the
// client's host and its tier, or the token; {limit} a reading limit;
// {workspace} the workspace's name, quoted by the words; {history} the window
// an untested client or a token reads, empty for the whole history. The
// activation says what the connection may read by its kind: metadata, text,
// or text and attachments.
//
//nolint:gosec // G101: words for a reader, not a credential
var mcpLanguages = []mcpWords{
	{
		lang: "en", kicker: "WAPPIE · ASSISTANTS",
		tiers:  map[string]string{"tested": "tested by Wappie", "local": "an app on a computer, tested by Wappie", "unknown": "not tested by Wappie"},
		limits: map[string]string{"daily_messages": "its daily limit of messages", "daily_attachments": "its daily limit of attachments", "first_hour_messages": "its limit of messages for its first hour", "first_hour_attachments": "its limit of attachments for its first hour"},
		titles: map[string]string{"activated": "A new assistant connected", "token": "A new connection token", "limit": "An assistant reached its reading limit", "token_limit": "A token reached its reading limit", "network": "A token was used from another network"},
		token:  "The console connection token “%s”", assistant: "%s (%s)", tokenFact: "Token: “%s”",
		numbers: func(n int) string {
			if n == 1 {
				return "1 number"
			}
			return fmt.Sprintf("%d numbers", n)
		},
		reads: func(text, attachments bool, days int) string {
			out := "metadata only (who, when and how much), without the text"
			switch {
			case text && attachments:
				out = "message text and attachments"
			case text:
				out = "message text"
			}
			if days > 0 {
				out += fmt.Sprintf(", from the last %d days", days)
			}
			return out
		},
		activated: map[string]string{
			"metadata": "{who} can now see who wrote to whom and when, but not the text, on {numbers} in the workspace “{workspace}”{history}.",
			"text":     "{who} can now read message text on {numbers} in the workspace “{workspace}”{history}.",
			"media":    "{who} can now read message text and attachments on {numbers} in the workspace “{workspace}”{history}.",
		},
		history:       ", from the last {days} days",
		limit:         "{who} reached {limit} in the workspace “{workspace}”. It reads nothing more until the limit resets.",
		network:       "Someone used {who} from a network it does not allow, in the workspace “{workspace}”. Wappie refused the call.",
		networkClient: "Someone used the connection of {who} from a network it does not allow, in the workspace “{workspace}”. Wappie refused the call.",
		date:          func(t time.Time) string { return t.UTC().Format("2 January 2006, 15:04 UTC") },
		facts:         [6]string{"Assistant: ", "Workspace: ", "Numbers: ", "What it can read: ", "Valid until: ", "When: "},
		question:      "Don't recognize it?", action: "Revoke only this connection",
		linkHelp: "The button revokes this one connection and nothing else. It needs no password. If it does not work, copy this address into your browser:",
		footer:   "Wappie's e-mails about assistants never ask for your password. Their only button revokes one connection. To see your assistants, open the Wappie console yourself.",
	},
	{
		lang: "pt", kicker: "WAPPIE · ASSISTENTES",
		tiers:  map[string]string{"tested": "testado pela Wappie", "local": "um app num computador, testado pela Wappie", "unknown": "não testado pela Wappie"},
		limits: map[string]string{"daily_messages": "o limite diário de mensagens", "daily_attachments": "o limite diário de anexos", "first_hour_messages": "o limite de mensagens da primeira hora", "first_hour_attachments": "o limite de anexos da primeira hora"},
		titles: map[string]string{"activated": "Um novo assistente se conectou", "token": "Um novo token de conexão", "limit": "Um assistente atingiu o limite de leitura", "token_limit": "Um token atingiu o limite de leitura", "network": "Um token foi usado de outra rede"},
		token:  "O token de conexão do console “%s”", assistant: "%s (%s)", tokenFact: "Token: “%s”",
		numbers: func(n int) string {
			if n == 1 {
				return "1 número"
			}
			return fmt.Sprintf("%d números", n)
		},
		reads: func(text, attachments bool, days int) string {
			out := "só metadados (quem, quando e quanto), sem o texto"
			switch {
			case text && attachments:
				out = "o texto das mensagens e os anexos"
			case text:
				out = "o texto das mensagens"
			}
			if days > 0 {
				out += fmt.Sprintf(", dos últimos %d dias", days)
			}
			return out
		},
		activated: map[string]string{
			"metadata": "{who} agora pode ver quem escreveu para quem e quando, mas não o texto, em {numbers} do espaço de trabalho “{workspace}”{history}.",
			"text":     "{who} agora pode ler o texto das mensagens de {numbers} do espaço de trabalho “{workspace}”{history}.",
			"media":    "{who} agora pode ler o texto das mensagens e os anexos de {numbers} do espaço de trabalho “{workspace}”{history}.",
		},
		history:       ", dos últimos {days} dias",
		limit:         "{who} atingiu {limit} no espaço de trabalho “{workspace}”. Não lê mais nada até o limite reiniciar.",
		network:       "Alguém usou {who} de uma rede que ele não permite, no espaço de trabalho “{workspace}”. A Wappie recusou a chamada.",
		networkClient: "Alguém usou a conexão de {who} de uma rede que ela não permite, no espaço de trabalho “{workspace}”. A Wappie recusou a chamada.",
		date: func(t time.Time) string {
			t = t.UTC()
			return fmt.Sprintf("%d de %s de %d, %s UTC", t.Day(), ptMonths[t.Month()-1], t.Year(), t.Format("15:04"))
		},
		facts:    [6]string{"Assistente: ", "Espaço de trabalho: ", "Números: ", "O que pode ler: ", "Válido até: ", "Quando: "},
		question: "Não reconhece?", action: "Revogar só esta conexão",
		linkHelp: "O botão revoga só esta conexão e nada mais, sem pedir senha. Se não funcionar, copie este endereço no navegador:",
		footer:   "Os e-mails da Wappie sobre assistentes nunca pedem sua senha. O único botão deles revoga uma conexão. Para ver seus assistentes, abra você mesmo o console da Wappie.",
	},
}

// mcpTiers are the tiers a notice may name.
var mcpTiers = map[string]bool{"tested": true, "local": true, "unknown": true, "token": true}

// wordsFor is the language a notice goes in: the locale's when there are
// words for it, English otherwise.
func wordsFor(locale string) mcpWords {
	tag := strings.ToLower(strings.TrimSpace(locale))
	if i := strings.IndexAny(tag, "-_"); i >= 0 {
		tag = tag[:i]
	}
	for _, w := range mcpLanguages {
		if w.lang == tag {
			return w
		}
	}
	return mcpLanguages[0]
}

// mcpSection is a notice's title, intro and facts in one language.
type mcpSection struct {
	Title, Intro string
	Facts        []string
}

// section is a notice in one language.
func (w mcpWords) section(n MCPNotice) (mcpSection, error) {
	token := n.Tier == "token"
	who := fmt.Sprintf(w.assistant, n.ClientHost, w.tiers[n.Tier])
	first := w.facts[0] + who
	if token {
		who, first = fmt.Sprintf(w.token, n.Label), fmt.Sprintf(w.tokenFact, n.Label)
	}
	s := mcpSection{Facts: []string{
		first,
		w.facts[1] + n.Workspace,
		w.facts[2] + fmt.Sprint(n.Numbers),
		w.facts[3] + w.reads(n.Text, n.Attachments, n.HistoryDays),
		w.facts[4] + w.date(n.ExpiresAt),
		w.facts[5] + w.date(n.At),
	}}
	var intro string
	switch {
	case n.Event == "activated":
		kind := "metadata"
		switch {
		case n.Text && n.Attachments:
			kind = "media"
		case n.Text:
			kind = "text"
		}
		s.Title, intro = w.titles["activated"], w.activated[kind]
		if token {
			s.Title = w.titles["token"]
		}
	case n.Event == "network":
		s.Title, intro = w.titles["network"], w.network
		if !token {
			intro, who = w.networkClient, n.ClientHost
		}
	case w.limits[n.Event] != "":
		s.Title, intro = w.titles["limit"], strings.ReplaceAll(w.limit, "{limit}", w.limits[n.Event])
		if token {
			s.Title = w.titles["token_limit"]
		}
	default:
		return mcpSection{}, errors.New("mailer: not a notice event")
	}
	history := ""
	if n.HistoryDays > 0 {
		history = strings.ReplaceAll(w.history, "{days}", fmt.Sprint(n.HistoryDays))
	}
	s.Intro = strings.NewReplacer("{who}", who, "{numbers}", w.numbers(n.Numbers), "{workspace}", n.Workspace, "{history}", history).Replace(intro)
	return s, nil
}

func mcpNoticeEmail(n MCPNotice) (mcpEmail, error) {
	if !mcpTiers[n.Tier] {
		return mcpEmail{}, errors.New("mailer: not a tier")
	}
	if (n.Tier == "token") != (n.Label != "") || (n.Tier == "token") == (n.ClientHost != "") {
		return mcpEmail{}, errors.New("mailer: a token has a label and an assistant a host")
	}
	if n.Workspace == "" {
		return mcpEmail{}, errors.New("mailer: the workspace is unnamed")
	}
	link, err := url.Parse(n.RevokeLink)
	if err != nil || link.Scheme != "https" && link.Scheme != "http" || link.Host == "" || link.User != nil || link.RawQuery != "" {
		return mcpEmail{}, errors.New("mailer: the revoke link must be an absolute address")
	}
	w := wordsFor(n.Lang)
	s, err := w.section(n)
	if err != nil {
		return mcpEmail{}, err
	}
	return mcpEmail{
		Lang: w.lang, Kicker: w.kicker, Subject: s.Title, Preheader: s.Intro, Title: s.Title, Intro: s.Intro, Facts: s.Facts,
		Question: w.question, Action: w.action, Link: link.String(), LinkHelp: w.linkHelp, Footer: w.footer,
	}, nil
}

// nameDot is a dot between two characters of a name.
var nameDot = regexp.MustCompile(`([A-Za-z0-9-])\.([A-Za-z0-9])`)

// noAutolink keeps a mail client from making a link of a name in the text:
// a zero-width non-joiner after each dot inside it, which nobody sees.
func noAutolink(s string) string { return nameDot.ReplaceAllString(s, "$1.\u200c$2") }

func (m mcpEmail) render() (string, string, error) {
	view := m
	view.Preheader, view.Intro = noAutolink(m.Preheader), noAutolink(m.Intro)
	view.Facts = make([]string, len(m.Facts))
	for i, fact := range m.Facts {
		view.Facts[i] = noAutolink(fact)
	}
	var html bytes.Buffer
	if err := mcpHTML.Execute(&html, view); err != nil {
		return "", "", err
	}
	plain := strings.Join([]string{"Wappie · The Happie", m.Title, m.Intro, strings.Join(m.Facts, "\n"),
		m.Question + " " + m.Action + ":\n" + m.Link, m.Footer}, "\n\n") + "\n"
	return plain, html.String(), nil
}
