package mailer

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	"time"

	"whatserver2/internal/config"
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
// revoke this one connection, and the console's address is plain text.
//
// The texts are drafts for the owner, in English only, as the account
// e-mails are; the other languages are the console's to decide with the owner
// (docs/mcp-enclave.md §19.28, point 4).

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
}

// MCPConnected sends a notice to one address.
func (s Sender) MCPConnected(ctx context.Context, email string, n MCPNotice) error {
	model, err := mcpNoticeEmail(s.AppURL, n)
	if err != nil {
		return err
	}
	return s.send(ctx, email, model)
}

// mcpEmail is a notice as the template shows it.
type mcpEmail struct {
	Subject, Preheader, Title, Intro string
	Facts                            []string
	Question, Link, Action           string
	Footer, LinkHelp                 string
}

func (m mcpEmail) subject() string { return m.Subject }

// limitWords say which reading limit a budget_hit code is.
var limitWords = map[string]string{
	"daily_messages":         "its daily limit of messages",
	"daily_attachments":      "its daily limit of attachments",
	"first_hour_messages":    "its limit of messages for its first hour",
	"first_hour_attachments": "its limit of attachments for its first hour",
}

// tierWords describe a tier, never with anything the client said of itself.
var tierWords = map[string]string{
	"tested":  "tested by Wappie",
	"local":   "an app on a computer, tested by Wappie",
	"unknown": "not tested by Wappie",
	"token":   "a console connection token",
}

func mcpNoticeEmail(appURL string, n MCPNotice) (mcpEmail, error) {
	tier, ok := tierWords[n.Tier]
	if !ok {
		return mcpEmail{}, errors.New("mailer: not a tier")
	}
	link, err := url.Parse(n.RevokeLink)
	if err != nil || link.Scheme != "https" && link.Scheme != "http" || link.Host == "" || link.User != nil || link.RawQuery != "" {
		return mcpEmail{}, errors.New("mailer: the revoke link must be an absolute address")
	}
	console, err := config.AccountBrowserOrigin(appURL, false)
	if err != nil {
		return mcpEmail{}, errors.New("mailer: invalid browser origin")
	}
	who := n.ClientHost
	if n.Tier == "token" || who == "" {
		who = "A console connection token"
	}
	reads := "who wrote to whom and when, without the text"
	switch {
	case n.Text && n.Attachments:
		reads = "message text and attachments"
	case n.Text:
		reads = "message text"
	}
	if n.HistoryDays > 0 {
		reads += fmt.Sprintf(", from the last %d days", n.HistoryDays)
	}
	numbers := fmt.Sprintf("%d numbers", n.Numbers)
	if n.Numbers == 1 {
		numbers = "1 number"
	}
	m := mcpEmail{
		Facts: []string{
			"Assistant: " + who + " (" + tier + ")",
			"Numbers: " + numbers,
			"What it can read: " + reads,
			"Valid until: " + n.ExpiresAt.UTC().Format("2 January 2006, 15:04 UTC"),
			"When: " + n.At.UTC().Format("2 January 2006, 15:04 UTC"),
		},
		Question: "Don't recognise it?", Link: link.String(), Action: "Revoke only this connection",
		Footer: "Wappie never asks for your password from an e-mail. To see your assistants, open the console yourself at " +
			console.Host + ".",
		LinkHelp: "The button revokes this one connection and nothing else. It needs no password. If it does not work, copy this address into your browser:",
	}
	switch {
	case n.Event == "activated":
		m.Subject, m.Title = "A new assistant connected to your Wappie", "A new assistant connected"
		m.Intro = who + " (" + tier + ") can now read your Wappie archive."
	case n.Event == "network":
		m.Subject, m.Title = "A connection token was used from another network", "A token was used from another network"
		m.Intro = "Someone used " + strings.ToLower(who[:1]) + who[1:] + " from a network it does not allow. The call was refused."
		if n.Tier != "token" {
			m.Intro = "Someone used the connection of " + who + " from a network it does not allow. The call was refused."
		}
	case limitWords[n.Event] != "":
		m.Subject, m.Title = "An assistant reached its reading limit in Wappie", "An assistant reached its reading limit"
		m.Intro = who + " (" + tier + ") reached " + limitWords[n.Event] + ". It reads nothing more until the limit resets."
	default:
		return mcpEmail{}, errors.New("mailer: not a notice event")
	}
	m.Preheader = m.Intro
	return m, nil
}

func (m mcpEmail) render() (string, string, error) {
	var html bytes.Buffer
	if err := mcpHTML.Execute(&html, m); err != nil {
		return "", "", err
	}
	sections := []string{"Wappie · The Happie", m.Title, m.Intro, strings.Join(m.Facts, "\n"),
		m.Question + " " + m.Action + ":\n" + m.Link, m.Footer}
	return strings.Join(sections, "\n\n") + "\n", html.String(), nil
}
