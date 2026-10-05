package mailer

import (
	"bytes"
	_ "embed"
	"errors"
	"html/template"
	"net/url"
	"strings"

	"whatserver2/internal/config"
)

//go:embed templates/account.html
var accountTemplate string

//go:embed assets/wappie.png
var brandPNG []byte

var accountHTML = template.Must(template.New("account").Parse(accountTemplate))

// Untrusted workspace names, recipient addresses and codes are always escaped
// by html/template. All links originate from the configured browser origin.
// Lang, LinkHelp and HomeLabel are the language and the template's own words
// of a message in another language than English; empty, the template says
// them in English.
type accountEmail struct {
	Subject, Preheader, Eyebrow, Title, Intro        string
	Workspace, Link, HomeURL, Action, Expiry         string
	Instructions, Recipient, Code, CodeLabel, Footer string
	Lang, LinkHelp, HomeLabel                        string
}

func signupEmail(origin, email, token string) (accountEmail, error) {
	link, err := accountLink(origin, url.Values{"email": {email}, "verification": {token}})
	if err != nil {
		return accountEmail{}, err
	}
	return accountEmail{
		Subject: "Confirm your Wappie account", Preheader: "Confirm the email address used to register your Wappie account.",
		Eyebrow: "Wappie account", Title: "Confirm your email address",
		Intro: "We received a request to create a Wappie account using the email address below. Confirm your email address to complete registration.",
		Link:  link, HomeURL: origin, Action: "Verify email", Expiry: "This verification link expires in 30 minutes.",
		Instructions: "This confirmation is for:", Recipient: email, Code: token,
		CodeLabel: "Prefer to use a code? Paste this into Wappie’s email verification field:",
		Footer:    "If you did not request this account, you can safely ignore this email. Do not share your verification code.",
	}, nil
}

func invitationEmail(origin, email, code, workspace string) (accountEmail, error) {
	link, err := accountLink(origin, url.Values{"invite": {code}, "email": {email}})
	if err != nil {
		return accountEmail{}, err
	}
	return accountEmail{
		Subject: "Wappie workspace invitation", Preheader: "A workspace administrator has invited you to join their workspace on Wappie.",
		Eyebrow: "Wappie workspace", Title: "Workspace invitation", Intro: "A workspace administrator invited this email address to join the workspace below. Use the button to review and accept the invitation in Wappie.",
		Workspace: workspace, Link: link, HomeURL: origin, Action: "View invitation", Expiry: "This invitation expires in 7 days.",
		Instructions: "To accept, sign in or create an account with this email address:",
		Recipient:    email, Code: code, CodeLabel: "Already in Wappie? Open the workspace menu, choose to join a workspace and paste this invitation code:",
		Footer: "Only the email address above can accept this invitation. If you were not expecting it, you can ignore this message.",
	}, nil
}

// alertWords are the account-key alert's words in one language (E-ALERT,
// approved 2026-10-05): the advice is the callback page's, word for word
// (C-AUTHERR-04), and the template's own words come with them.
type alertWords struct {
	subject, preheader, eyebrow, title, intro string
	action, advice, instructions, footer      string
	linkHelp, homeLabel                       string
}

//nolint:misspell // the Spanish and French words are not English misspellings
var alertLanguages = map[string]alertWords{
	"en": {
		subject: "A sign-in to Wappie was refused", preheader: "A sign-in to Wappie was refused because your account key changed.",
		eyebrow: "Wappie security", title: "A sign-in was refused",
		intro:        "A sign-in to Wappie through The Happie Co was refused because it presented a different account key from the one your account has always used. Nothing was opened and no session was started.",
		action:       "Open Wappie",
		advice:       "If you did not reset your The Happie Co account, change its password now and contact Wappie support before signing in again.",
		instructions: "This alert is for:", footer: "Wappie never asks for your password or recovery code by e-mail.",
		linkHelp: "If the button does not work, copy and paste this link into your browser:", homeLabel: "Open Wappie",
	},
	"pt": {
		subject: "Uma entrada na Wappie foi recusada", preheader: "Uma entrada na Wappie foi recusada porque a chave da sua conta mudou.",
		eyebrow: "Segurança da Wappie", title: "Uma entrada foi recusada",
		intro:        "Uma entrada na Wappie pela The Happie Co foi recusada porque apresentou uma chave de conta diferente da que a sua conta sempre usou. Nada foi aberto e nenhuma sessão foi iniciada.",
		action:       "Abrir o Wappie",
		advice:       "Se você não redefiniu sua conta The Happie Co, troque a senha dela agora e fale com o suporte da Wappie antes de entrar de novo.",
		instructions: "Este alerta é para:", footer: "A Wappie nunca pede sua senha nem seu código de recuperação por e-mail.",
		linkHelp: "Se o botão não funcionar, copie este endereço no navegador:", homeLabel: "Abrir o Wappie",
	},
	"es": {
		subject: "Se rechazó un inicio de sesión en Wappie", preheader: "Se rechazó un inicio de sesión en Wappie porque la clave de tu cuenta cambió.",
		eyebrow: "Seguridad de Wappie", title: "Se rechazó un inicio de sesión",
		intro:        "Se rechazó un inicio de sesión en Wappie con The Happie Co porque presentó una clave de cuenta distinta de la que tu cuenta ha usado siempre. No se abrió nada y no se inició ninguna sesión.",
		action:       "Abrir Wappie",
		advice:       "Si no restableciste tu cuenta de The Happie Co, cambia su contraseña ahora y contacta con el soporte de Wappie antes de volver a iniciar sesión.",
		instructions: "Esta alerta es para:", footer: "Wappie nunca pide tu contraseña ni tu código de recuperación por correo.",
		linkHelp: "Si el botón no funciona, copia esta dirección en el navegador:", homeLabel: "Abrir Wappie",
	},
	"fr": {
		subject: "Une connexion à Wappie a été refusée", preheader: "Une connexion à Wappie a été refusée parce que la clé de votre compte a changé.",
		eyebrow: "Sécurité Wappie", title: "Une connexion a été refusée",
		intro:        "Une connexion à Wappie avec The Happie Co a été refusée parce qu’elle présentait une clé de compte différente de celle que votre compte a toujours utilisée. Rien n’a été ouvert et aucune session n’a été démarrée.",
		action:       "Ouvrir Wappie",
		advice:       "Si vous n’avez pas réinitialisé votre compte The Happie Co, changez son mot de passe maintenant et contactez le support de Wappie avant de vous reconnecter.",
		instructions: "Cette alerte concerne :", footer: "Wappie ne demande jamais votre mot de passe ni votre code de récupération par e-mail.",
		linkHelp: "Si le bouton ne fonctionne pas, copiez cette adresse dans votre navigateur :", homeLabel: "Ouvrir Wappie",
	},
	"de": {
		subject: "Eine Anmeldung bei Wappie wurde abgelehnt", preheader: "Eine Anmeldung bei Wappie wurde abgelehnt, weil sich der Schlüssel Ihres Kontos geändert hat.",
		eyebrow: "Wappie-Sicherheit", title: "Eine Anmeldung wurde abgelehnt",
		intro:        "Eine Anmeldung bei Wappie mit The Happie Co wurde abgelehnt, weil sie einen anderen Kontoschlüssel vorgelegt hat als den, den Ihr Konto immer verwendet hat. Es wurde nichts geöffnet und keine Sitzung gestartet.",
		action:       "Wappie öffnen",
		advice:       "Wenn Sie Ihr The-Happie-Co-Konto nicht zurückgesetzt haben, ändern Sie jetzt sein Passwort und wenden Sie sich an den Wappie-Support, bevor Sie sich erneut anmelden.",
		instructions: "Diese Warnung ist für:", footer: "Wappie fragt nie per E-Mail nach Ihrem Passwort oder Wiederherstellungscode.",
		linkHelp: "Wenn der Button nicht funktioniert, kopieren Sie diese Adresse in Ihren Browser:", homeLabel: "Wappie öffnen",
	},
}

// accountKeyChangedEmail is the alert of a sign-in refused because the
// identity provider presented another account key than the one this
// account signs in with (docs/platform-sign-in.md), in the recipient's
// language: the account's own (users.locale), English when it never said
// one or for the operator's copy. It names no key, no account id and no
// other address than the recipient's.
func accountKeyChangedEmail(origin, email, lang string) (accountEmail, error) {
	u, err := config.AccountBrowserOrigin(origin, false)
	if err != nil {
		return accountEmail{}, errors.New("mailer: invalid browser origin")
	}
	home := u.String()
	tag := wordsFor(lang).lang
	w, ok := alertLanguages[tag]
	if !ok {
		tag, w = "en", alertLanguages["en"]
	}
	return accountEmail{
		Lang: tag, Subject: w.subject, Preheader: w.preheader, Eyebrow: w.eyebrow, Title: w.title, Intro: w.intro,
		Link: home, HomeURL: home, Action: w.action, Expiry: w.advice,
		Instructions: w.instructions, Recipient: email, Footer: w.footer,
		LinkHelp: w.linkHelp, HomeLabel: w.homeLabel,
	}, nil
}

func (m accountEmail) subject() string { return m.Subject }

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
	home := m.HomeLabel
	if home == "" {
		home = "Open Wappie"
	}
	sections = append(sections, m.Footer, home+": "+m.HomeURL)
	return strings.Join(sections, "\n\n") + "\n", html.String(), nil
}
