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
// One message, in one language: the recipient's preferred locale (the
// language their console was last set to, kept on the account since 0047),
// English when the account has none or the language has no words here. The
// five languages of the console all have words. A console token is named by
// its label, the words a workspace admin chose for it, never by anything a
// client said. The texts are drafts for the owner (docs/mcp-enclave.md
// §19.22, §19.30).

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
	// Steps is what to do in place of a button, for a notice with no link
	// (the renewal notice): never a link to a page where a password is typed.
	Steps string
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

var (
	ptMonths = [...]string{"janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"}
	esMonths = [...]string{"enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"}
	frMonths = [...]string{"janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"}
	deMonths = [...]string{"Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"}
)

// plural is a count's words in a language: one, or several.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return fmt.Sprintf(many, n)
}

// The words of each language, English first: the fallback. {who} is the
// client's host and its tier, or the token; {limit} a reading limit;
// {workspace} the workspace's name, quoted by the words; {history} the window
// an untested client or a token reads, empty for the whole history. The
// activation says what the connection may read by its kind: metadata, text,
// or text and attachments.
//
//nolint:gosec,misspell // G101: words for a reader, not a credential; and the Spanish "cuánto" is not the English "not"
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
		question:      "Don’t recognize it?", action: "Revoke only this connection",
		linkHelp: "The button revokes this one connection and nothing else. It needs no password. If it does not work, copy this address into your browser:",
		footer:   "Wappie’s e-mails about assistants never ask for your password. Their only button revokes one connection. To see your assistants, open the Wappie console yourself.",
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
	{
		lang: "es", kicker: "WAPPIE · ASISTENTES",
		tiers:  map[string]string{"tested": "probado por Wappie", "local": "una app en un ordenador, probada por Wappie", "unknown": "no probado por Wappie"},
		limits: map[string]string{"daily_messages": "su límite diario de mensajes", "daily_attachments": "su límite diario de adjuntos", "first_hour_messages": "su límite de mensajes de la primera hora", "first_hour_attachments": "su límite de adjuntos de la primera hora"},
		titles: map[string]string{"activated": "Se conectó un nuevo asistente", "token": "Un nuevo token de conexión", "limit": "Un asistente alcanzó su límite de lectura", "token_limit": "Un token alcanzó su límite de lectura", "network": "Se usó un token desde otra red"},
		token:  "El token de conexión de la consola “%s”", assistant: "%s (%s)", tokenFact: "Token: “%s”",
		numbers: func(n int) string { return plural(n, "1 número", "%d números") },
		reads: func(text, attachments bool, days int) string {
			out := "solo metadatos (quién, cuándo y cuánto), sin el texto"
			switch {
			case text && attachments:
				out = "el texto de los mensajes y los adjuntos"
			case text:
				out = "el texto de los mensajes"
			}
			if days > 0 {
				out += fmt.Sprintf(", de los últimos %d días", days)
			}
			return out
		},
		activated: map[string]string{
			"metadata": "{who} ahora puede ver quién escribió a quién y cuándo, pero no el texto, en {numbers} del espacio de trabajo “{workspace}”{history}.",
			"text":     "{who} ahora puede leer el texto de los mensajes de {numbers} del espacio de trabajo “{workspace}”{history}.",
			"media":    "{who} ahora puede leer el texto de los mensajes y los adjuntos de {numbers} del espacio de trabajo “{workspace}”{history}.",
		},
		history:       ", de los últimos {days} días",
		limit:         "{who} alcanzó {limit} en el espacio de trabajo “{workspace}”. No lee nada más hasta que el límite se reinicie.",
		network:       "Alguien usó {who} desde una red que no permite, en el espacio de trabajo “{workspace}”. Wappie rechazó la llamada.",
		networkClient: "Alguien usó la conexión de {who} desde una red que no permite, en el espacio de trabajo “{workspace}”. Wappie rechazó la llamada.",
		date: func(t time.Time) string {
			t = t.UTC()
			return fmt.Sprintf("%d de %s de %d, %s UTC", t.Day(), esMonths[t.Month()-1], t.Year(), t.Format("15:04"))
		},
		facts:    [6]string{"Asistente: ", "Espacio de trabajo: ", "Números: ", "Qué puede leer: ", "Válido hasta: ", "Cuándo: "},
		question: "¿No lo reconoces?", action: "Revocar solo esta conexión",
		linkHelp: "El botón revoca solo esta conexión y nada más, sin pedir contraseña. Si no funciona, copia esta dirección en el navegador:",
		footer:   "Los correos de Wappie sobre asistentes nunca piden tu contraseña. Su único botón revoca una conexión. Para ver tus asistentes, abre tú mismo la consola de Wappie.",
	},
	{
		lang: "fr", kicker: "WAPPIE · ASSISTANTS",
		tiers:  map[string]string{"tested": "testé par Wappie", "local": "une app sur un ordinateur, testée par Wappie", "unknown": "non testé par Wappie"},
		limits: map[string]string{"daily_messages": "sa limite quotidienne de messages", "daily_attachments": "sa limite quotidienne de pièces jointes", "first_hour_messages": "sa limite de messages de la première heure", "first_hour_attachments": "sa limite de pièces jointes de la première heure"},
		titles: map[string]string{"activated": "Un nouvel assistant s’est connecté", "token": "Un nouveau jeton de connexion", "limit": "Un assistant a atteint sa limite de lecture", "token_limit": "Un jeton a atteint sa limite de lecture", "network": "Un jeton a été utilisé depuis un autre réseau"},
		token:  "Le jeton de connexion de la console « %s »", assistant: "%s (%s)", tokenFact: "Jeton : « %s »",
		numbers: func(n int) string { return plural(n, "1 numéro", "%d numéros") },
		reads: func(text, attachments bool, days int) string {
			out := "les métadonnées seulement (qui, quand et combien), sans le texte"
			switch {
			case text && attachments:
				out = "le texte des messages et les pièces jointes"
			case text:
				out = "le texte des messages"
			}
			if days > 0 {
				out += fmt.Sprintf(", des %d derniers jours", days)
			}
			return out
		},
		activated: map[string]string{
			"metadata": "{who} peut désormais voir qui a écrit à qui et quand, mais pas le texte, sur {numbers} de l’espace de travail « {workspace} »{history}.",
			"text":     "{who} peut désormais lire le texte des messages de {numbers} de l’espace de travail « {workspace} »{history}.",
			"media":    "{who} peut désormais lire le texte des messages et les pièces jointes de {numbers} de l’espace de travail « {workspace} »{history}.",
		},
		history:       ", des {days} derniers jours",
		limit:         "{who} a atteint {limit} dans l’espace de travail « {workspace} ». Il ne lit plus rien jusqu’à la remise à zéro de la limite.",
		network:       "Quelqu’un a utilisé {who} depuis un réseau qu’il n’autorise pas, dans l’espace de travail « {workspace} ». Wappie a refusé l’appel.",
		networkClient: "Quelqu’un a utilisé la connexion de {who} depuis un réseau qu’elle n’autorise pas, dans l’espace de travail « {workspace} ». Wappie a refusé l’appel.",
		date: func(t time.Time) string {
			t = t.UTC()
			return fmt.Sprintf("%d %s %d, %s UTC", t.Day(), frMonths[t.Month()-1], t.Year(), t.Format("15:04"))
		},
		facts:    [6]string{"Assistant : ", "Espace de travail : ", "Numéros : ", "Ce qu’il peut lire : ", "Valable jusqu’au : ", "Quand : "},
		question: "Vous ne le reconnaissez pas ?", action: "Révoquer uniquement cette connexion",
		linkHelp: "Le bouton révoque seulement cette connexion, rien d’autre, et ne demande aucun mot de passe. S’il ne fonctionne pas, copiez cette adresse dans votre navigateur :",
		footer:   "Les e-mails de Wappie sur les assistants ne demandent jamais votre mot de passe. Leur seul bouton révoque une connexion. Pour voir vos assistants, ouvrez vous-même la console Wappie.",
	},
	{
		lang: "de", kicker: "WAPPIE · ASSISTENTEN",
		tiers:  map[string]string{"tested": "von Wappie getestet", "local": "eine App auf einem Computer, von Wappie getestet", "unknown": "nicht von Wappie getestet"},
		limits: map[string]string{"daily_messages": "sein tägliches Limit an Nachrichten", "daily_attachments": "sein tägliches Limit an Anhängen", "first_hour_messages": "sein Limit an Nachrichten für die erste Stunde", "first_hour_attachments": "sein Limit an Anhängen für die erste Stunde"},
		titles: map[string]string{"activated": "Ein neuer Assistent hat sich verbunden", "token": "Ein neues Verbindungstoken", "limit": "Ein Assistent hat sein Leselimit erreicht", "token_limit": "Ein Token hat sein Leselimit erreicht", "network": "Ein Token wurde aus einem anderen Netzwerk verwendet"},
		token:  "Das Verbindungstoken der Konsole „%s“", assistant: "%s (%s)", tokenFact: "Token: „%s“",
		numbers: func(n int) string { return plural(n, "1 Nummer", "%d Nummern") },
		reads: func(text, attachments bool, days int) string {
			out := "nur Metadaten (wer, wann und wie viel), ohne den Text"
			switch {
			case text && attachments:
				out = "den Text der Nachrichten und die Anhänge"
			case text:
				out = "den Text der Nachrichten"
			}
			if days > 0 {
				out += fmt.Sprintf(", aus den letzten %d Tagen", days)
			}
			return out
		},
		activated: map[string]string{
			"metadata": "{who} kann jetzt sehen, wer wem wann geschrieben hat, aber nicht den Text, auf {numbers} im Arbeitsbereich „{workspace}“{history}.",
			"text":     "{who} kann jetzt den Text der Nachrichten lesen, auf {numbers} im Arbeitsbereich „{workspace}“{history}.",
			"media":    "{who} kann jetzt den Text der Nachrichten und die Anhänge lesen, auf {numbers} im Arbeitsbereich „{workspace}“{history}.",
		},
		history:       ", aus den letzten {days} Tagen",
		limit:         "{who} hat {limit} im Arbeitsbereich „{workspace}“ erreicht. Bis das Limit zurückgesetzt wird, wird nichts mehr gelesen.",
		network:       "Jemand hat {who} aus einem Netzwerk verwendet, das es nicht erlaubt, im Arbeitsbereich „{workspace}“. Wappie hat den Aufruf abgelehnt.",
		networkClient: "Jemand hat die Verbindung von {who} aus einem Netzwerk verwendet, das sie nicht erlaubt, im Arbeitsbereich „{workspace}“. Wappie hat den Aufruf abgelehnt.",
		date: func(t time.Time) string {
			t = t.UTC()
			return fmt.Sprintf("%d. %s %d, %s UTC", t.Day(), deMonths[t.Month()-1], t.Year(), t.Format("15:04"))
		},
		facts:    [6]string{"Assistent: ", "Arbeitsbereich: ", "Nummern: ", "Was er lesen kann: ", "Gültig bis: ", "Wann: "},
		question: "Kennen Sie ihn nicht?", action: "Nur diese Verbindung widerrufen",
		linkHelp: "Der Button widerruft nur diese eine Verbindung und sonst nichts, ohne Passwort. Wenn er nicht funktioniert, kopieren Sie diese Adresse in Ihren Browser:",
		footer:   "E-Mails von Wappie zu Assistenten fragen nie nach Ihrem Passwort. Ihr einziger Button widerruft eine Verbindung. Um Ihre Assistenten zu sehen, öffnen Sie selbst die Wappie-Konsole.",
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
	next := m.Question + " " + m.Action + ":\n" + m.Link
	if m.Link == "" {
		next = m.Question + "\n" + m.Steps
	}
	plain := strings.Join([]string{"Wappie · The Happie", m.Title, m.Intro, strings.Join(m.Facts, "\n"), next, m.Footer}, "\n\n") + "\n"
	return plain, html.String(), nil
}

// ---------------------------------------------------------------------------
// The renewal notice
// ---------------------------------------------------------------------------

// MCPRenewal is the renewal notice (docs/mcp-enclave.md §19.30): the Wappie
// reader no longer holds the keys of content connections a person consented
// to in one workspace (it restarted, or the workspace turned text off and on
// again), and they wait for that person to renew them. It goes to that
// person only, once a round, and carries no link at all: renewing asks for a
// passkey or the password, and an e-mail that taught people to click through
// to such a page is what a spoofed one would copy. It says where to go
// instead, and ends with the footer every notice e-mail carries, word for
// word.
type MCPRenewal struct {
	// Workspace is the workspace's name.
	Workspace string
	// Assistants are the waiting connections' names, one each, as the store
	// gives them: a 0.6.0 row's verified client_name (a tested client's name
	// from the reader's list, an untested one's domain, a token's label), an
	// older row's host. Never a name the client gave itself.
	Assistants []string
	// Tokens marks the console tokens among them: Tokens[i] is Assistants[i]'s,
	// and a missing entry is false. A token is named by its label the way the
	// activation notice names one (Token “label”), so that a label such as
	// "Claude" never reads as the tested assistant of that name.
	Tokens []bool
	// OneByOne is how many of them the console's Renew all leaves to their
	// own Renew: an untested client's and a token's.
	OneByOne int
	// Since is when the first of them stopped reading text.
	Since time.Time
	// Lang is the recipient's preferred locale, "" when none.
	Lang string
}

// MCPRenewalNotice sends a renewal notice to one address.
func (s Sender) MCPRenewalNotice(ctx context.Context, email string, n MCPRenewal) error {
	model, err := mcpRenewalEmail(n)
	if err != nil {
		return err
	}
	return s.send(ctx, email, model)
}

// renewalWords are a renewal notice's words in one language. {count} is how
// many connections wait, {workspace} the workspace's name, quoted by the
// words. The steps name the console's own buttons: Renew all renews the
// tested connections with one confirmation, and an untested client's or a
// token's keeps its own Renew, so what the e-mail says depends on which
// wait: all of the first (allOne, allMany), all of the second (eachOne,
// eachMany), or some of each (mixed, never for one connection alone).
// token names a console token in the list of names, by its label.
type renewalWords struct {
	titleOne, titleMany, introOne, introMany  string
	facts                                     [3]string
	token                                     string
	question                                  string
	allOne, allMany, eachOne, eachMany, mixed string
}

//nolint:gosec,misspell // G101: words for a reader, not a credential; and the Spanish "cuánto" is not the English "not"
var renewalLanguages = map[string]renewalWords{
	"en": {
		titleOne: "Your assistant needs renewing", titleMany: "Your assistants need renewing",
		introOne:  "One assistant connection in the workspace “{workspace}” stopped reading message text: the Wappie reader no longer holds its key. It still sees who, when and how much.",
		introMany: "{count} assistant connections in the workspace “{workspace}” stopped reading message text: the Wappie reader no longer holds their keys. They still see who, when and how much.",
		facts:     [3]string{"Assistants: ", "Workspace: ", "Since: "},
		token:     "Token “%s”",
		question:  "What to do",
		allOne:    "Open the Wappie console yourself, go to the MCP tab and choose Renew all. One confirmation renews it; the assistant stays connected.",
		allMany:   "Open the Wappie console yourself, go to the MCP tab and choose Renew all. One confirmation renews them all; the assistants stay connected.",
		eachOne:   "Open the Wappie console yourself, go to the MCP tab and choose Renew beside it. An untested assistant or a token asks its own confirmation; the assistant stays connected.",
		eachMany:  "Open the Wappie console yourself, go to the MCP tab and choose Renew beside each one. An untested assistant or a token asks its own confirmation; the assistants stay connected.",
		mixed:     "Open the Wappie console yourself and go to the MCP tab. An untested assistant or a token asks its own confirmation: choose Renew beside each one. Renew all renews the rest with one confirmation. The assistants stay connected.",
	},
	"pt": {
		titleOne: "Seu assistente precisa ser renovado", titleMany: "Seus assistentes precisam ser renovados",
		introOne:  "Uma conexão de assistente do espaço de trabalho “{workspace}” parou de ler o texto das mensagens: o leitor da Wappie não guarda mais a chave dela. Ela continua vendo quem, quando e quanto.",
		introMany: "{count} conexões de assistentes do espaço de trabalho “{workspace}” pararam de ler o texto das mensagens: o leitor da Wappie não guarda mais as chaves delas. Elas continuam vendo quem, quando e quanto.",
		facts:     [3]string{"Assistentes: ", "Espaço de trabalho: ", "Desde: "},
		token:     "Token “%s”",
		question:  "O que fazer",
		allOne:    "Abra você mesmo o console da Wappie, vá à aba MCP e escolha Renovar todas. Uma só confirmação a renova; o assistente continua conectado.",
		allMany:   "Abra você mesmo o console da Wappie, vá à aba MCP e escolha Renovar todas. Uma só confirmação renova todas; os assistentes continuam conectados.",
		eachOne:   "Abra você mesmo o console da Wappie, vá à aba MCP e escolha Renovar ao lado dela. Um assistente não testado ou um token pede a própria confirmação; o assistente continua conectado.",
		eachMany:  "Abra você mesmo o console da Wappie, vá à aba MCP e escolha Renovar ao lado de cada uma. Um assistente não testado ou um token pede a própria confirmação; os assistentes continuam conectados.",
		mixed:     "Abra você mesmo o console da Wappie e vá à aba MCP. Um assistente não testado ou um token pede a própria confirmação: escolha Renovar ao lado de cada um. Renovar todas renova as demais com uma só confirmação. Os assistentes continuam conectados.",
	},
	"es": {
		titleOne: "Tu asistente necesita renovarse", titleMany: "Tus asistentes necesitan renovarse",
		introOne:  "Una conexión de asistente del espacio de trabajo “{workspace}” dejó de leer el texto de los mensajes: el lector de Wappie ya no guarda su clave. Sigue viendo quién, cuándo y cuánto.",
		introMany: "{count} conexiones de asistentes del espacio de trabajo “{workspace}” dejaron de leer el texto de los mensajes: el lector de Wappie ya no guarda sus claves. Siguen viendo quién, cuándo y cuánto.",
		facts:     [3]string{"Asistentes: ", "Espacio de trabajo: ", "Desde: "},
		token:     "Token “%s”",
		question:  "Qué hacer",
		allOne:    "Abre tú mismo la consola de Wappie, ve a la pestaña MCP y elige Renovar todas. Una sola confirmación la renueva; el asistente sigue conectado.",
		allMany:   "Abre tú mismo la consola de Wappie, ve a la pestaña MCP y elige Renovar todas. Una sola confirmación las renueva todas; los asistentes siguen conectados.",
		eachOne:   "Abre tú mismo la consola de Wappie, ve a la pestaña MCP y elige Renovar junto a ella. Un asistente no probado o un token pide su propia confirmación; el asistente sigue conectado.",
		eachMany:  "Abre tú mismo la consola de Wappie, ve a la pestaña MCP y elige Renovar junto a cada una. Un asistente no probado o un token pide su propia confirmación; los asistentes siguen conectados.",
		mixed:     "Abre tú mismo la consola de Wappie y ve a la pestaña MCP. Un asistente no probado o un token pide su propia confirmación: elige Renovar junto a cada uno. Renovar todas renueva las demás con una sola confirmación. Los asistentes siguen conectados.",
	},
	"fr": {
		titleOne: "Votre assistant doit être renouvelé", titleMany: "Vos assistants doivent être renouvelés",
		introOne:  "Une connexion d’assistant de l’espace de travail « {workspace} » ne lit plus le texte des messages : le lecteur Wappie n’en détient plus la clé. Elle voit toujours qui, quand et combien.",
		introMany: "{count} connexions d’assistants de l’espace de travail « {workspace} » ne lisent plus le texte des messages : le lecteur Wappie n’en détient plus les clés. Elles voient toujours qui, quand et combien.",
		facts:     [3]string{"Assistants : ", "Espace de travail : ", "Depuis : "},
		token:     "Jeton « %s »",
		question:  "Que faire",
		allOne:    "Ouvrez vous-même la console Wappie, allez dans l’onglet MCP et choisissez Tout renouveler. Une seule confirmation la renouvelle ; l’assistant reste connecté.",
		allMany:   "Ouvrez vous-même la console Wappie, allez dans l’onglet MCP et choisissez Tout renouveler. Une seule confirmation les renouvelle toutes ; les assistants restent connectés.",
		eachOne:   "Ouvrez vous-même la console Wappie, allez dans l’onglet MCP et choisissez Renouveler à côté d’elle. Un assistant non testé ou un jeton demande sa propre confirmation ; l’assistant reste connecté.",
		eachMany:  "Ouvrez vous-même la console Wappie, allez dans l’onglet MCP et choisissez Renouveler à côté de chacune. Un assistant non testé ou un jeton demande sa propre confirmation ; les assistants restent connectés.",
		mixed:     "Ouvrez vous-même la console Wappie et allez dans l’onglet MCP. Un assistant non testé ou un jeton demande sa propre confirmation : choisissez Renouveler à côté de chacun. Tout renouveler renouvelle les autres avec une seule confirmation. Les assistants restent connectés.",
	},
	"de": {
		titleOne: "Ihr Assistent muss erneuert werden", titleMany: "Ihre Assistenten müssen erneuert werden",
		introOne:  "Eine Assistentenverbindung im Arbeitsbereich „{workspace}“ liest den Text der Nachrichten nicht mehr: Der Wappie-Leser hat ihren Schlüssel nicht mehr. Sie sieht weiterhin, wer, wann und wie viel.",
		introMany: "{count} Assistentenverbindungen im Arbeitsbereich „{workspace}“ lesen den Text der Nachrichten nicht mehr: Der Wappie-Leser hat ihre Schlüssel nicht mehr. Sie sehen weiterhin, wer, wann und wie viel.",
		facts:     [3]string{"Assistenten: ", "Arbeitsbereich: ", "Seit: "},
		token:     "Token „%s“",
		question:  "Was zu tun ist",
		allOne:    "Öffnen Sie selbst die Wappie-Konsole, gehen Sie zum Tab MCP und wählen Sie Alle erneuern. Eine Bestätigung erneuert sie; der Assistent bleibt verbunden.",
		allMany:   "Öffnen Sie selbst die Wappie-Konsole, gehen Sie zum Tab MCP und wählen Sie Alle erneuern. Eine Bestätigung erneuert alle; die Assistenten bleiben verbunden.",
		eachOne:   "Öffnen Sie selbst die Wappie-Konsole, gehen Sie zum Tab MCP und wählen Sie daneben Erneuern. Ein nicht getesteter Assistent oder ein Token verlangt eine eigene Bestätigung; der Assistent bleibt verbunden.",
		eachMany:  "Öffnen Sie selbst die Wappie-Konsole, gehen Sie zum Tab MCP und wählen Sie bei jeder Verbindung Erneuern. Ein nicht getesteter Assistent oder ein Token verlangt eine eigene Bestätigung; die Assistenten bleiben verbunden.",
		mixed:     "Öffnen Sie selbst die Wappie-Konsole und gehen Sie zum Tab MCP. Ein nicht getesteter Assistent oder ein Token verlangt eine eigene Bestätigung: Wählen Sie jeweils daneben Erneuern. Alle erneuern erneuert die übrigen mit einer Bestätigung. Die Assistenten bleiben verbunden.",
	},
}

func mcpRenewalEmail(n MCPRenewal) (mcpEmail, error) {
	if n.Workspace == "" {
		return mcpEmail{}, errors.New("mailer: the workspace is unnamed")
	}
	total := len(n.Assistants)
	if total == 0 {
		return mcpEmail{}, errors.New("mailer: no connection waits for renewal")
	}
	if n.OneByOne < 0 || n.OneByOne > total {
		return mcpEmail{}, errors.New("mailer: more connections renewed one by one than wait")
	}
	if len(n.Tokens) > total {
		return mcpEmail{}, errors.New("mailer: more tokens than connections wait")
	}
	w := wordsFor(n.Lang)
	r := renewalLanguages[w.lang]
	title, intro := r.titleOne, r.introOne
	if total > 1 {
		title, intro = r.titleMany, r.introMany
	}
	var steps string
	switch {
	case n.OneByOne == 0 && total == 1:
		steps = r.allOne
	case n.OneByOne == 0:
		steps = r.allMany
	case n.OneByOne == total && total == 1:
		steps = r.eachOne
	case n.OneByOne == total:
		steps = r.eachMany
	default:
		steps = r.mixed
	}
	intro = strings.NewReplacer("{count}", fmt.Sprint(total), "{workspace}", n.Workspace).Replace(intro)
	names := make([]string, total)
	for i, name := range n.Assistants {
		names[i] = name
		if i < len(n.Tokens) && n.Tokens[i] {
			names[i] = fmt.Sprintf(r.token, name)
		}
	}
	return mcpEmail{
		Lang: w.lang, Kicker: w.kicker, Subject: title, Preheader: intro, Title: title, Intro: intro,
		Facts:    []string{r.facts[0] + strings.Join(names, ", "), r.facts[1] + n.Workspace, r.facts[2] + w.date(n.Since)},
		Question: r.question, Steps: steps,
		// The footer of every notice e-mail, word for word (D10, 5).
		Footer: w.footer,
	}, nil
}
