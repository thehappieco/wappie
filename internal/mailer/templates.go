package mailer

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/url"
	"strings"
)

//go:embed templates/account.html
var accountTemplate string

//go:embed assets/wappie.png
var brandPNG []byte

var accountHTML = template.Must(template.New("account").Parse(accountTemplate))

// Untrusted workspace names, recipient addresses and codes are always escaped
// by html/template. All links originate from the configured browser origin.
type accountEmail struct {
	Subject, Preheader, Eyebrow, Title, Intro        string
	Workspace, Link, HomeURL, Action, Expiry         string
	Instructions, Recipient, Code, CodeLabel, Footer string
}

func signupEmail(origin, email, token string) (accountEmail, error) {
	link, err := accountLink(origin, url.Values{"email": {email}, "verification": {token}})
	if err != nil {
		return accountEmail{}, err
	}
	return accountEmail{
		Subject: "Confirm your Wappie account", Preheader: "One step to your Wappie account and personal workspace.",
		Eyebrow: "WELCOME TO WAPPIE", Title: "Your workspace starts here.",
		Intro: "Verify your email to create your Wappie account. Your personal workspace will be ready for you, and you can join a team whenever you need.",
		Link:  link, HomeURL: origin, Action: "Verify email", Expiry: "This verification link expires in 30 minutes.",
		Instructions: "This confirmation is for:", Recipient: email, Code: token,
		CodeLabel: "Prefer to use a code? Paste this into Wappie's email verification field:",
		Footer:    "If you did not request this account, you can safely ignore this email. Do not share your verification code.",
	}, nil
}

func invitationEmail(origin, email, code, workspace string) (accountEmail, error) {
	link, err := accountLink(origin, url.Values{"invite": {code}, "email": {email}})
	if err != nil {
		return accountEmail{}, err
	}
	return accountEmail{
		Subject: "Wappie workspace invitation", Preheader: "You have been invited to join a workspace on Wappie.",
		Eyebrow: "YOU'RE INVITED", Title: "A place for you on the team.", Intro: "You have been invited to collaborate in the workspace below. Accept the invitation to join your team on Wappie.",
		Workspace: workspace, Link: link, HomeURL: origin, Action: "Join workspace", Expiry: "This invitation expires in 7 days.",
		Instructions: "Sign in or create an account using this email address. A new account includes your own personal workspace:",
		Recipient:    email, Code: code, CodeLabel: "Already in Wappie? Open the workspace menu, choose to join a workspace and paste this invitation code:",
		Footer: "Only the email address above can accept this invitation. If you were not expecting it, you can ignore this message.",
	}, nil
}

func (m accountEmail) render() (string, string, error) {
	var html bytes.Buffer
	if err := accountHTML.Execute(&html, m); err != nil {
		return "", "", err
	}
	sections := []string{"Wappie · The Happie", m.Title, m.Intro}
	if m.Workspace != "" {
		sections = append(sections, "Workspace: "+m.Workspace)
	}
	sections = append(sections, m.Action+":\n"+m.Link, m.Expiry, m.Instructions+"\n"+m.Recipient)
	if m.Code != "" {
		sections = append(sections, m.CodeLabel+"\n"+m.Code)
	}
	sections = append(sections, m.Footer, "Open Wappie: "+m.HomeURL)
	return strings.Join(sections, "\n\n") + "\n", html.String(), nil
}
