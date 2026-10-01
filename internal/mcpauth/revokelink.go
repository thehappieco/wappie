package mcpauth

import (
	"bytes"
	"errors"
	"html/template"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"whatserver2/internal/store"
)

// The revoke-only link of a new-assistant e-mail (docs/mcp-enclave.md
// §19.21): GET shows a page with one button and no other link; POST revokes
// the one connection the link names, with its key, as the console's Revoke
// does. No session and no password: the link is 32 random bytes, stored only
// as its SHA-256, minted for a notice and replaced by the next one, spent by
// its first POST, and dead with its connection. A replaced, spent or unknown
// link answers the same page. A mail scanner's GET changes nothing. The
// token is never logged; the path is rate-limited per address.

// revokeLinkPath is the link's path before its token.
const revokeLinkPath = "/v1/mcp/revoke-link/"

// revokeLinkTokenLen is 32 bytes in unpadded base64url.
const revokeLinkTokenLen = 43

// revokePage is the page in all its states. Its texts are drafts for the
// owner, in the console's five languages, pt and en first.
var revokePage = template.Must(template.New("revoke").Parse(`<!doctype html>
<html lang="{{.Lang}}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>Wappie</title>
<style>body{margin:0;background:#f1f5f4;color:#173d34;font:16px/1.5 Arial,Helvetica,sans-serif}main{max-width:520px;margin:48px auto;padding:32px 28px;background:#fff;border:1px solid #dce7e3;border-top:4px solid #087f67;border-radius:16px}h1{font-size:24px;line-height:1.3;margin:0 0 16px}p{margin:0 0 20px;color:#50675f;overflow-wrap:anywhere}button{font:bold 15px Arial,Helvetica,sans-serif;color:#fff;background:#087f67;border:0;border-radius:9px;padding:14px 22px;cursor:pointer}small{display:block;margin-top:28px;color:#71857e}</style></head>
<body><main><h1>{{.Title}}</h1>{{if .Body}}<p>{{.Body}}</p>{{end}}{{if .Button}}<form method="post"><button type="submit">{{.Button}}</button></form>{{end}}<small>{{.Footer}}</small></main></body>
</html>
`))

// revokeTexts are the page's texts by language: the question, its body for a
// client and for a token, the button, the answer and its bodies, the dead
// link, and the footer. {host} is the client's verified host.
//
//nolint:gosec // G101: words for a reader, not a credential
var revokeTexts = map[string]map[string]string{
	"en": {
		"ask": "Revoke this assistant connection?", "ask_body": "This revokes only the connection of {host} to your Wappie. Nothing else changes.",
		"ask_token": "This revokes only this console connection token. Nothing else changes.", "button": "Revoke only this connection",
		"done": "Connection revoked", "done_body": "{host} can no longer read your Wappie.", "done_token": "This token no longer works.",
		"dead": "This link is no longer valid.", "footer": "Wappie never asks for your password from an e-mail.",
	},
	"pt": {
		"ask": "Revogar esta conexão de assistente?", "ask_body": "Isto revoga só a conexão de {host} ao seu Wappie. Nada mais muda.",
		"ask_token": "Isto revoga só este token de conexão do console. Nada mais muda.", "button": "Revogar só esta conexão",
		"done": "Conexão revogada", "done_body": "{host} não pode mais ler o seu Wappie.", "done_token": "Este token não funciona mais.",
		"dead": "Este link não é mais válido.", "footer": "A Wappie nunca pede sua senha por e-mail.",
	},
	"es": {
		"ask": "¿Revocar esta conexión de asistente?", "ask_body": "Esto revoca solo la conexión de {host} con tu Wappie. Nada más cambia.",
		"ask_token": "Esto revoca solo este token de conexión de la consola. Nada más cambia.", "button": "Revocar solo esta conexión",
		"done": "Conexión revocada", "done_body": "{host} ya no puede leer tu Wappie.", "done_token": "Este token ya no funciona.",
		"dead": "Este enlace ya no es válido.", "footer": "Wappie nunca te pide la contraseña por correo electrónico.",
	},
	"fr": {
		"ask": "Révoquer cette connexion d’assistant ?", "ask_body": "Cela révoque uniquement la connexion de {host} à votre Wappie. Rien d’autre ne change.",
		"ask_token": "Cela révoque uniquement ce jeton de connexion de la console. Rien d’autre ne change.", "button": "Révoquer uniquement cette connexion",
		"done": "Connexion révoquée", "done_body": "{host} ne peut plus lire votre Wappie.", "done_token": "Ce jeton ne fonctionne plus.",
		"dead": "Ce lien n’est plus valide.", "footer": "Wappie ne vous demande jamais votre mot de passe par e-mail.",
	},
	"de": {
		"ask": "Diese Assistenten-Verbindung widerrufen?", "ask_body": "Damit wird nur die Verbindung von {host} zu deinem Wappie widerrufen. Sonst ändert sich nichts.",
		"ask_token": "Damit wird nur dieses Verbindungstoken der Konsole widerrufen. Sonst ändert sich nichts.", "button": "Nur diese Verbindung widerrufen",
		"done": "Verbindung widerrufen", "done_body": "{host} kann dein Wappie nicht mehr lesen.", "done_token": "Dieses Token funktioniert nicht mehr.",
		"dead": "Dieser Link ist nicht mehr gültig.", "footer": "Wappie fragt nie per E-Mail nach deinem Passwort.",
	},
}

// pageLanguage picks the page's language from Accept-Language: the first
// tag, by weight and then order, whose primary language is one of the
// console's; English otherwise.
func pageLanguage(header string) string {
	type choice struct {
		lang string
		q    float64
	}
	var choices []choice
	for _, part := range strings.Split(header, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			parsed, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			q = parsed
		}
		primary, _, _ := strings.Cut(strings.ToLower(tag), "-")
		if _, ok := revokeTexts[primary]; ok && q > 0 {
			choices = append(choices, choice{primary, q})
		}
	}
	slices.SortStableFunc(choices, func(a, b choice) int {
		switch {
		case a.q > b.q:
			return -1
		case a.q < b.q:
			return 1
		}
		return 0
	})
	if len(choices) == 0 {
		return "en"
	}
	return choices[0].lang
}

type revokeView struct {
	Lang, Title, Body, Button, Footer string
}

// writeRevokePage answers with the page in the request's language. host is
// the client's verified host, "" for a token.
func writeRevokePage(w http.ResponseWriter, r *http.Request, status int, state, host string) {
	lang := pageLanguage(r.Header.Get("Accept-Language"))
	t := revokeTexts[lang]
	view := revokeView{Lang: lang, Footer: t["footer"]}
	body := func(client, token string) string {
		if host == "" {
			return t[token]
		}
		return strings.ReplaceAll(t[client], "{host}", host)
	}
	switch state {
	case "ask":
		view.Title, view.Body, view.Button = t["ask"], body("ask_body", "ask_token"), t["button"]
	case "done":
		view.Title, view.Body = t["done"], body("done_body", "done_token")
	default:
		view.Title = t["dead"]
	}
	var out bytes.Buffer
	if err := revokePage.Execute(&out, view); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	//nolint:errcheck,gosec // the browser hung up; G705: a page of fixed texts and an escaped ASCII host
	_, _ = w.Write(out.Bytes())
}

// revokeLinkToken reads the path's token: 43 base64url characters, or "".
func revokeLinkToken(r *http.Request) string {
	token := r.PathValue("token")
	if len(token) != revokeLinkTokenLen || strings.ContainsFunc(token, func(c rune) bool { return !base64urlChar(c) }) {
		return ""
	}
	return token
}

// revokeLinkPage shows what the link would revoke, and changes nothing.
func (h *Handler) revokeLinkPage(w http.ResponseWriter, r *http.Request) {
	if !allow(w, r, h.RevokeLinkLimits, "") {
		return
	}
	token := revokeLinkToken(r)
	if token == "" {
		writeRevokePage(w, r, http.StatusNotFound, "dead", "")
		return
	}
	host, err := h.Connections.RevokeLinkTarget(r.Context(), revokeLinkHash(token))
	switch {
	case errors.Is(err, store.ErrMCPConnectionNotFound):
		writeRevokePage(w, r, http.StatusNotFound, "dead", "")
	case err != nil:
		h.log().Error("could not read a revoke link", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	default:
		writeRevokePage(w, r, http.StatusOK, "ask", host)
	}
}

// revokeLinkPost revokes the one connection the link names and tells its
// reader, once.
func (h *Handler) revokeLinkPost(w http.ResponseWriter, r *http.Request) {
	if !allow(w, r, h.RevokeLinkLimits, "") {
		return
	}
	token := revokeLinkToken(r)
	if token == "" {
		writeRevokePage(w, r, http.StatusNotFound, "dead", "")
		return
	}
	hash := revokeLinkHash(token)
	host, err := h.Connections.RevokeLinkTarget(r.Context(), hash)
	if err == nil {
		var reader, id string
		id, reader, err = h.Connections.RevokeByLink(r.Context(), hash)
		if err == nil {
			h.tellRevoked(r.Context(), reader, id)
			h.log().Info("mcp connection revoked by its notice link", "connection", id, "reason", store.ReasonConsole)
			writeRevokePage(w, r, http.StatusOK, "done", host)
			return
		}
	}
	if errors.Is(err, store.ErrMCPConnectionNotFound) {
		writeRevokePage(w, r, http.StatusNotFound, "dead", "")
		return
	}
	h.log().Error("could not revoke by a link", "error", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}
