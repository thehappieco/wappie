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
// as its SHA-256, minted for each notice e-mail, and good until one of the
// connection's links is used or the connection ends, so a later e-mail
// never makes an earlier one's button a dead end while the assistant still
// reads. A spent or unknown link answers the same page. A mail scanner's GET
// changes nothing. The token is never logged; the path is rate-limited per
// address.
//
// The page's form posts to its own address. Its referrer policy is
// same-origin, never no-referrer: a browser sends a form POST from a
// no-referrer document with Origin: null, which the API's browser-origin
// guard refuses, so the button would never revoke. same-origin still keeps
// the token in the path out of any Referer to another site, and the page
// links nowhere.

// revokeLinkPath is the link's path before its token.
const revokeLinkPath = "/v1/mcp/revoke-link/"

// revokeLinkTokenLen is 32 bytes in unpadded base64url.
const revokeLinkTokenLen = 43

// revokePage is the page in all its states. Its texts are drafts for the
// owner, in the console's five languages, pt and en first.
var revokePage = template.Must(template.New("revoke").Parse(`<!doctype html>
<html lang="{{.Lang}}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="same-origin"><title>Wappie</title>
<style>body{margin:0;background:#f1f5f4;color:#173d34;font:16px/1.5 Arial,Helvetica,sans-serif}main{max-width:520px;margin:48px auto;padding:32px 28px;background:#fff;border:1px solid #dce7e3;border-top:4px solid #087f67;border-radius:16px}h1{font-size:24px;line-height:1.3;margin:0 0 16px}p{margin:0 0 20px;color:#50675f;overflow-wrap:anywhere}button{font:bold 15px Arial,Helvetica,sans-serif;color:#fff;background:#087f67;border:0;border-radius:9px;padding:14px 22px;cursor:pointer}small{display:block;margin-top:28px;color:#71857e}</style></head>
<body><main><h1>{{.Title}}</h1>{{if .Body}}<p>{{.Body}}</p>{{end}}{{if .Button}}<form method="post"><button type="submit">{{.Button}}</button></form>{{end}}<small>{{.Footer}}</small></main></body>
</html>
`))

// revokeTexts are the page's texts by language: the question, its body for a
// client and for a token, the button, the answer and its bodies, the dead
// link and its body, and the footer. {host} is the client's verified host,
// {label} a token's label (the workspace admin's own words). The revocation
// reaches the reader within its minute of status cache, which the answer
// says. The footer is the console's and the notice e-mail's, word for word.
//
//nolint:gosec // G101: words for a reader, not a credential
var revokeTexts = map[string]map[string]string{
	"en": {
		"ask": "Revoke this assistant connection?", "ask_body": "This revokes only the connection of {host} to your Wappie. Nothing else changes.",
		"ask_token": "This revokes only the console connection token “{label}”. Nothing else changes.", "button": "Revoke only this connection",
		"done": "Connection revoked", "done_body": "{host} loses access to your Wappie within a minute.",
		"done_token": "The token “{label}” stops working within a minute.",
		"dead":       "This link no longer works", "dead_body": "It was used already, or the connection it named has ended. Nothing else changed. To check your assistants, open the Wappie console yourself.",
		"footer": "Wappie's e-mails about assistants never ask for your password. Their only button revokes one connection.",
	},
	"pt": {
		"ask": "Revogar esta conexão de assistente?", "ask_body": "Isto revoga só a conexão de {host} ao seu Wappie. Nada mais muda.",
		"ask_token": "Isto revoga só o token de conexão do console “{label}”. Nada mais muda.", "button": "Revogar só esta conexão",
		"done": "Conexão revogada", "done_body": "{host} perde o acesso ao seu Wappie em até um minuto.",
		"done_token": "O token “{label}” para de funcionar em até um minuto.",
		"dead":       "Este link não funciona mais", "dead_body": "Ele já foi usado, ou a conexão que ele indicava já terminou. Nada mais mudou. Para conferir seus assistentes, abra você mesmo o console da Wappie.",
		"footer": "Os e-mails da Wappie sobre assistentes nunca pedem sua senha. O único botão deles revoga uma conexão.",
	},
	"es": {
		"ask": "¿Revocar esta conexión de asistente?", "ask_body": "Esto revoca solo la conexión de {host} con tu Wappie. Nada más cambia.",
		"ask_token": "Esto revoca solo el token de conexión de la consola «{label}». Nada más cambia.", "button": "Revocar solo esta conexión",
		"done": "Conexión revocada", "done_body": "{host} pierde el acceso a tu Wappie en menos de un minuto.",
		"done_token": "El token «{label}» deja de funcionar en menos de un minuto.",
		"dead":       "Este enlace ya no funciona", "dead_body": "Ya se usó, o la conexión que indicaba ya terminó. Nada más cambió. Para revisar tus asistentes, abre tú mismo la consola de Wappie.",
		"footer": "Los correos de Wappie sobre asistentes nunca piden tu contraseña. Su único botón revoca una conexión.",
	},
	"fr": {
		"ask": "Révoquer cette connexion d’assistant ?", "ask_body": "Cela révoque uniquement la connexion de {host} à votre Wappie. Rien d’autre ne change.",
		"ask_token": "Cela révoque uniquement le jeton de connexion de la console « {label} ». Rien d’autre ne change.", "button": "Révoquer uniquement cette connexion",
		"done": "Connexion révoquée", "done_body": "{host} perd l’accès à votre Wappie en moins d’une minute.",
		"done_token": "Le jeton « {label} » cesse de fonctionner en moins d’une minute.",
		"dead":       "Ce lien ne fonctionne plus", "dead_body": "Il a déjà été utilisé, ou la connexion qu’il désignait a pris fin. Rien d’autre n’a changé. Pour vérifier vos assistants, ouvrez vous-même la console Wappie.",
		"footer": "Les e-mails de Wappie sur les assistants ne demandent jamais votre mot de passe. Leur seul bouton révoque une connexion.",
	},
	"de": {
		"ask": "Diese Assistenten-Verbindung widerrufen?", "ask_body": "Damit wird nur die Verbindung von {host} zu Ihrem Wappie widerrufen. Sonst ändert sich nichts.",
		"ask_token": "Damit wird nur das Verbindungstoken „{label}“ der Konsole widerrufen. Sonst ändert sich nichts.", "button": "Nur diese Verbindung widerrufen",
		"done": "Verbindung widerrufen", "done_body": "{host} verliert innerhalb einer Minute den Zugriff auf Ihr Wappie.",
		"done_token": "Das Token „{label}“ funktioniert innerhalb einer Minute nicht mehr.",
		"dead":       "Dieser Link funktioniert nicht mehr", "dead_body": "Er wurde schon benutzt, oder die Verbindung, die er nannte, ist beendet. Sonst hat sich nichts geändert. Um Ihre Assistenten zu prüfen, öffnen Sie selbst die Wappie-Konsole.",
		"footer": "E-Mails von Wappie zu Assistenten fragen nie nach Ihrem Passwort. Ihr einziger Button widerruft eine Verbindung.",
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

// writeRevokePage answers with the page in the request's language, naming
// the connection's client host or, for a token, its label (the zero target
// for a dead link).
func writeRevokePage(w http.ResponseWriter, r *http.Request, status int, state string, target store.RevokeTarget) {
	lang := pageLanguage(r.Header.Get("Accept-Language"))
	t := revokeTexts[lang]
	view := revokeView{Lang: lang, Footer: t["footer"]}
	body := func(client, token string) string {
		if target.Token {
			return strings.ReplaceAll(t[token], "{label}", target.Label)
		}
		return strings.ReplaceAll(t[client], "{host}", target.Host)
	}
	switch state {
	case "ask":
		view.Title, view.Body, view.Button = t["ask"], body("ask_body", "ask_token"), t["button"]
	case "done":
		view.Title, view.Body = t["done"], body("done_body", "done_token")
	default:
		view.Title, view.Body = t["dead"], t["dead_body"]
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
	header.Set("Referrer-Policy", "same-origin")
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
		writeRevokePage(w, r, http.StatusNotFound, "dead", store.RevokeTarget{})
		return
	}
	target, err := h.Connections.RevokeLinkTarget(r.Context(), revokeLinkHash(token))
	switch {
	case errors.Is(err, store.ErrMCPConnectionNotFound):
		writeRevokePage(w, r, http.StatusNotFound, "dead", store.RevokeTarget{})
	case err != nil:
		h.log().Error("could not read a revoke link", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	default:
		writeRevokePage(w, r, http.StatusOK, "ask", target)
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
		writeRevokePage(w, r, http.StatusNotFound, "dead", store.RevokeTarget{})
		return
	}
	hash := revokeLinkHash(token)
	target, err := h.Connections.RevokeLinkTarget(r.Context(), hash)
	if err == nil {
		var reader, id string
		id, reader, err = h.Connections.RevokeByLink(r.Context(), hash)
		if err == nil {
			h.tellRevoked(r.Context(), reader, id)
			h.log().Info("mcp connection revoked by its notice link", "connection", id, "reason", store.ReasonConsole)
			writeRevokePage(w, r, http.StatusOK, "done", target)
			return
		}
	}
	if errors.Is(err, store.ErrMCPConnectionNotFound) {
		writeRevokePage(w, r, http.StatusNotFound, "dead", store.RevokeTarget{})
		return
	}
	h.log().Error("could not revoke by a link", "error", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}
