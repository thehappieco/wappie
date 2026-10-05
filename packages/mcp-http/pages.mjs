// Every page a person's browser can be shown by this reader, and every word
// on it, in the five languages the console speaks (docs/mcp-enclave.md
// §19.14, §19.29): the authorization server's refusals (as.mjs) and, on the
// attested reader's public listener, the human page at `/` and robots.txt
// (router.mjs). In the enclave image this file is measured into PCR0 like
// every other: a word changes only with a release.
//
// A refusal page carries one sentence per language, the person's own first
// (D10, as the two pages 0.6.0 introduced did), each saying what happened
// and what to do next, then the way back when there is one, then the code in
// small print for support. Nothing on any page comes from the request but the
// order of its languages; the way back comes only from configuration.
import { createHash } from 'node:crypto'

/** The page languages (§19.14's five), in the console's order. */
export const PAGE_LANGUAGES = Object.freeze(['pt', 'en', 'es', 'fr', 'de'])

/**
 * The page languages Accept-Language asks for, by their q-value (a tag's
 * first two letters; `q=0` means not wanted), at most the five once each.
 */
export function askedLanguages(acceptLanguage) {
  const asked = []
  String(acceptLanguage ?? '').slice(0, 1024).split(',').forEach((item, index) => {
    const [range, ...params] = item.trim().split(';')
    const tag = range.trim().slice(0, 2).toLowerCase()
    const q = params.map(param => /^\s*q\s*=\s*([01](?:\.\d{0,3})?)\s*$/i.exec(param)).find(Boolean)
    const weight = q ? Number(q[1]) : 1
    if (PAGE_LANGUAGES.includes(tag) && weight > 0) asked.push({ tag, weight, index })
  })
  asked.sort((a, b) => b.weight - a.weight || a.index - b.index)
  return [...new Set(asked.map(item => item.tag))]
}
/** Every page language in the person's order: those Accept-Language asks for, then the rest in the console's order. */
export function pageLanguages(acceptLanguage) {
  const first = askedLanguages(acceptLanguage)
  return [...first, ...PAGE_LANGUAGES.filter(tag => !first.includes(tag))]
}

/**
 * Each browser-facing refusal, by the code its page shows. `invalid_client`
 * is the `any` policy's one page for every reason (§19.6 step 5), and
 * `invalid_client_allowlist` the 0.5.0 policy's (the hosted reader's), shown
 * with the same code; the three origin codes share one sentence.
 */
export const SENTENCES = Object.freeze({
  invalid_client: Object.freeze({
    pt: 'A Wappie não pôde aceitar este assistente. Ele pode não publicar a página de identidade de que a Wappie precisa, ou o endereço dele não é permitido. Nada foi compartilhado. Você pode conectar um assistente testado ou criar um token de conexão no console da Wappie.',
    en: 'Wappie could not accept this assistant. It may not publish the identity page Wappie needs, or its address is not allowed. Nothing was shared. You can connect a tested assistant, or create a connection token in the Wappie console.',
    es: 'Wappie no pudo aceptar este asistente. Puede que no publique la página de identidad que Wappie necesita, o que su dirección no esté permitida. No se compartió nada. Puedes conectar un asistente probado o crear un token de conexión en la consola de Wappie.',
    fr: 'Wappie n’a pas pu accepter cet assistant. Il ne publie peut-être pas la page d’identité dont Wappie a besoin, ou son adresse n’est pas autorisée. Rien n’a été partagé. Vous pouvez connecter un assistant testé ou créer un jeton de connexion dans la console Wappie.',
    de: 'Wappie konnte diesen Assistenten nicht annehmen. Vielleicht veröffentlicht er nicht die Identitätsseite, die Wappie braucht, oder seine Adresse ist nicht erlaubt. Es wurde nichts geteilt. Sie können einen getesteten Assistenten verbinden oder in der Wappie-Konsole ein Verbindungstoken erstellen.',
  }),
  invalid_client_allowlist: Object.freeze({
    pt: 'A Wappie não pôde aceitar este assistente: este servidor só admite os assistentes que quem o administra permite. Nada foi compartilhado. Conecte um desses assistentes ou fale com quem administra este servidor.',
    en: 'Wappie could not accept this assistant: this server admits only the assistants its operator allows. Nothing was shared. Connect one of those assistants, or ask whoever runs this server.',
    es: 'Wappie no pudo aceptar este asistente: este servidor solo admite los asistentes que permite quien lo administra. No se compartió nada. Conecta uno de esos asistentes o consulta a quien administra este servidor.',
    fr: 'Wappie n’a pas pu accepter cet assistant : ce serveur n’admet que les assistants autorisés par son administrateur. Rien n’a été partagé. Connectez l’un de ces assistants ou contactez la personne qui gère ce serveur.',
    de: 'Wappie konnte diesen Assistenten nicht annehmen: Dieser Server lässt nur die Assistenten zu, die sein Betreiber erlaubt. Es wurde nichts geteilt. Verbinden Sie einen dieser Assistenten oder wenden Sie sich an den Betreiber dieses Servers.',
  }),
  ip_mismatch: Object.freeze({
    pt: 'Esta autorização foi aberta numa rede diferente da que começou a conexão. Volte ao assistente e clique em Conectar de novo. Se você usa VPN ou a Retransmissão Privada do iCloud, desligue para esta etapa e tente de novo.',
    en: 'This authorization was opened on a different network from the one that started the connection. Go back to the assistant and click Connect again. If you use a VPN or iCloud Private Relay, turn it off for this step and try again.',
    es: 'Esta autorización se abrió en una red distinta de la que inició la conexión. Vuelve al asistente y haz clic en Conectar de nuevo. Si usas una VPN o Relay privado de iCloud, desactívalo para este paso y vuelve a intentarlo.',
    fr: 'Cette autorisation a été ouverte sur un autre réseau que celui qui a lancé la connexion. Revenez à l’assistant et cliquez de nouveau sur Connecter. Si vous utilisez un VPN ou le Relais privé iCloud, désactivez-le pour cette étape et réessayez.',
    de: 'Diese Freigabe wurde in einem anderen Netzwerk geöffnet als dem, in dem die Verbindung begann. Gehen Sie zurück zum Assistenten und klicken Sie erneut auf Verbinden. Wenn Sie ein VPN oder iCloud Privat-Relay nutzen, schalten Sie es für diesen Schritt aus und versuchen Sie es noch einmal.',
  }),
  invalid_redirect_uri: Object.freeze({
    pt: 'Este assistente pediu à Wappie para enviar a resposta a um endereço que ele não registrou, e a Wappie parou. Nada foi compartilhado. Comece a conexão de novo pelo assistente; se isso continuar, quem faz o assistente precisa corrigir.',
    en: 'This assistant asked Wappie to send the answer to an address it did not register, so Wappie stopped. Nothing was shared. Start the connection again from the assistant; if this keeps happening, the assistant’s makers need to fix it.',
    es: 'Este asistente pidió a Wappie enviar la respuesta a una dirección que no registró, y Wappie se detuvo. No se compartió nada. Vuelve a iniciar la conexión desde el asistente; si sigue pasando, quienes hacen el asistente deben corregirlo.',
    fr: 'Cet assistant a demandé à Wappie d’envoyer la réponse à une adresse qu’il n’a pas enregistrée, et Wappie s’est arrêté. Rien n’a été partagé. Relancez la connexion depuis l’assistant ; si cela continue, ses éditeurs doivent le corriger.',
    de: 'Dieser Assistent hat Wappie gebeten, die Antwort an eine Adresse zu senden, die er nicht registriert hat, deshalb hat Wappie abgebrochen. Es wurde nichts geteilt. Starten Sie die Verbindung erneut im Assistenten; passiert das weiterhin, müssen seine Hersteller es beheben.',
  }),
  invalid_request: Object.freeze({
    pt: 'A Wappie não conseguiu ler este pedido. Nada foi compartilhado. Comece a conexão de novo pelo seu assistente.',
    en: 'Wappie could not read this request. Nothing was shared. Start the connection again from your assistant.',
    es: 'Wappie no pudo leer esta solicitud. No se compartió nada. Vuelve a iniciar la conexión desde tu asistente.',
    fr: 'Wappie n’a pas pu lire cette demande. Rien n’a été partagé. Relancez la connexion depuis votre assistant.',
    de: 'Wappie konnte diese Anfrage nicht lesen. Es wurde nichts geteilt. Starten Sie die Verbindung erneut in Ihrem Assistenten.',
  }),
  too_many_requests: Object.freeze({
    pt: 'Chegaram pedidos de conexão demais desta rede agora há pouco. Nada foi compartilhado. Espere um minuto e comece de novo pelo seu assistente.',
    en: 'Too many connection requests reached Wappie from this network just now. Nothing was shared. Wait a minute, then start again from your assistant.',
    es: 'Llegaron demasiadas solicitudes de conexión desde esta red hace un momento. No se compartió nada. Espera un minuto y vuelve a empezar desde tu asistente.',
    fr: 'Trop de demandes de connexion sont arrivées de ce réseau à l’instant. Rien n’a été partagé. Attendez une minute, puis recommencez depuis votre assistant.',
    de: 'Gerade kamen zu viele Verbindungsanfragen aus diesem Netzwerk. Es wurde nichts geteilt. Warten Sie eine Minute und beginnen Sie dann erneut in Ihrem Assistenten.',
  }),
  method_not_allowed: Object.freeze({
    pt: 'Este endereço da Wappie não é para ser aberto assim. Comece a conexão pelo seu assistente ou abra o console da Wappie.',
    en: 'This Wappie address is not meant to be opened like this. Start the connection from your assistant, or open the Wappie console.',
    es: 'Esta dirección de Wappie no está pensada para abrirse así. Inicia la conexión desde tu asistente o abre la consola de Wappie.',
    fr: 'Cette adresse Wappie n’est pas faite pour être ouverte ainsi. Lancez la connexion depuis votre assistant ou ouvrez la console Wappie.',
    de: 'Diese Wappie-Adresse ist nicht dafür gedacht, so geöffnet zu werden. Starten Sie die Verbindung in Ihrem Assistenten oder öffnen Sie die Wappie-Konsole.',
  }),
  origin: Object.freeze({
    pt: 'A Wappie não conseguiu confirmar que esta autorização veio do console da Wappie. Nada foi compartilhado. Volte ao console e autorize de novo; se isso continuar, fale com o suporte da Wappie.',
    en: 'Wappie could not confirm that this approval came from the Wappie console. Nothing was shared. Go back to the console and approve again; if this keeps happening, contact Wappie support.',
    es: 'Wappie no pudo confirmar que esta autorización vino de la consola de Wappie. No se compartió nada. Vuelve a la consola y autoriza de nuevo; si sigue pasando, contacta con el soporte de Wappie.',
    fr: 'Wappie n’a pas pu confirmer que cette autorisation venait de la console Wappie. Rien n’a été partagé. Revenez à la console et autorisez de nouveau ; si cela continue, contactez l’assistance Wappie.',
    de: 'Wappie konnte nicht bestätigen, dass diese Freigabe aus der Wappie-Konsole kam. Es wurde nichts geteilt. Gehen Sie zurück zur Konsole und geben Sie erneut frei; passiert das weiterhin, wenden Sie sich an den Wappie-Support.',
  }),
  invalid_proof: Object.freeze({
    pt: 'Não foi possível conferir esta autorização: ela pode ter expirado ou já ter sido usada. Nada foi compartilhado. Comece a conexão de novo pelo seu assistente.',
    en: 'This approval could not be checked: it may have expired or been used already. Nothing was shared. Start the connection again from your assistant.',
    es: 'No se pudo comprobar esta autorización: puede haber caducado o haberse usado ya. No se compartió nada. Vuelve a iniciar la conexión desde tu asistente.',
    fr: 'Cette autorisation n’a pas pu être vérifiée : elle a peut-être expiré ou déjà servi. Rien n’a été partagé. Relancez la connexion depuis votre assistant.',
    de: 'Diese Freigabe ließ sich nicht prüfen: Sie ist vielleicht abgelaufen oder wurde schon verwendet. Es wurde nichts geteilt. Starten Sie die Verbindung erneut in Ihrem Assistenten.',
  }),
  connection_exists: Object.freeze({
    pt: 'Esta conexão já foi concluída. Volte ao seu assistente: ele deve estar conectado. Se não estiver, comece a conexão de novo por lá.',
    en: 'This connection was already completed. Go back to your assistant: it should be connected. If it is not, start the connection again there.',
    es: 'Esta conexión ya se completó. Vuelve a tu asistente: debería estar conectado. Si no lo está, vuelve a iniciar la conexión desde allí.',
    fr: 'Cette connexion a déjà été établie. Revenez à votre assistant : il devrait être connecté. Sinon, relancez la connexion depuis celui-ci.',
    de: 'Diese Verbindung wurde bereits abgeschlossen. Gehen Sie zurück zu Ihrem Assistenten: Er sollte verbunden sein. Falls nicht, starten Sie die Verbindung dort erneut.',
  }),
  activation_failed: Object.freeze({
    pt: 'A Wappie não conseguiu concluir a conexão agora. Nada foi compartilhado. Espere um minuto e comece a conexão de novo pelo seu assistente.',
    en: 'Wappie could not finish the connection just now. Nothing was shared. Wait a minute, then start the connection again from your assistant.',
    es: 'Wappie no pudo completar la conexión en este momento. No se compartió nada. Espera un minuto y vuelve a iniciar la conexión desde tu asistente.',
    fr: 'Wappie n’a pas pu terminer la connexion pour le moment. Rien n’a été partagé. Attendez une minute, puis relancez la connexion depuis votre assistant.',
    de: 'Wappie konnte die Verbindung gerade nicht abschließen. Es wurde nichts geteilt. Warten Sie eine Minute und starten Sie die Verbindung dann erneut in Ihrem Assistenten.',
  }),
  too_many_unknown: Object.freeze({
    pt: 'Este workspace já tem todas as conexões de assistentes não testados e tokens de conexão que pode manter. Revogue uma no console da Wappie e comece a conexão de novo pelo seu assistente.',
    en: 'This workspace already has as many connections of untested assistants and connection tokens as it may keep. Revoke one in the Wappie console, then start the connection again from your assistant.',
    es: 'Este workspace ya tiene todas las conexiones de asistentes no probados y tokens de conexión que puede mantener. Revoca una en la consola de Wappie y vuelve a iniciar la conexión desde tu asistente.',
    fr: 'Cet espace de travail a déjà autant de connexions d’assistants non testés et de jetons de connexion qu’il peut en garder. Révoquez-en une dans la console Wappie, puis relancez la connexion depuis votre assistant.',
    de: 'Dieser Workspace hat bereits so viele Verbindungen ungetesteter Assistenten und Verbindungstokens, wie er behalten darf. Widerrufen Sie eine in der Wappie-Konsole und starten Sie die Verbindung dann erneut in Ihrem Assistenten.',
  }),
})
/** The sentence each page code shows; a code without one would be a bug, and the tests list them all. */
const sentenceOf = { origin_missing: 'origin', opaque_origin: 'origin', invalid_origin: 'origin' }
export const PAGE_CODES = Object.freeze(['invalid_client', 'ip_mismatch', 'invalid_redirect_uri', 'invalid_request', 'too_many_requests', 'method_not_allowed',
  'origin_missing', 'opaque_origin', 'invalid_origin', 'invalid_proof', 'connection_exists', 'activation_failed', 'too_many_unknown'])

export const escapeHTML = value => String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', '\'': '&#39;' })[character])
const sha256 = text => createHash('sha256').update(text, 'utf8').digest('base64')
/** A page's own style, allowed by its hash and nothing else: no script, no image, no request elsewhere. */
const pageStyle = 'body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 16px;overflow-wrap:anywhere}small{color:#555}'
const pageCSP = `default-src 'none'; style-src 'sha256-${sha256(pageStyle)}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
const htmlHead = '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Wappie MCP</title>' +
  `<style>${pageStyle}</style>`
const noStore = { 'Cache-Control': 'no-store', Pragma: 'no-cache' }
export const pageHeaders = Object.freeze({ ...noStore, 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy': pageCSP, 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' })

/**
 * A refusal page: `code` from PAGE_CODES (the `invalid_client` of the 0.5.0
 * policy with `allowlist`), `back` only ever from configuration,
 * `acceptLanguage` the request's header, which orders the sentences and
 * nothing else.
 */
export function refusalPage(status, code, { back = '', acceptLanguage = null, allowlist = false } = {}) {
  const key = code === 'invalid_client' && allowlist ? 'invalid_client_allowlist' : sentenceOf[code] ?? code
  const sentences = SENTENCES[key]
  if (!sentences) throw new Error(`no sentence for ${code}`)
  const body = htmlHead + pageLanguages(acceptLanguage).map(tag => `<p lang="${tag}">${escapeHTML(sentences[tag])}</p>`).join('') +
    (back ? `<p><a href="${escapeHTML(back)}">${escapeHTML(back)}</a></p>` : '') + `<p><small>Wappie MCP: ${code}</small></p>`
  return new Response(body, { status, headers: pageHeaders })
}

/**
 * The human page at `/` of the attested reader's public host (§19.29): what
 * this address is and what to do with it, the console and the documentation,
 * in one language chosen from Accept-Language (or `?lang=`), English when
 * none of the five is asked for.
 */
export const HOME = Object.freeze({
  pt: Object.freeze({ title: 'Conector da Wappie', lead: 'Este é o endereço do conector da Wappie. Adicione-o no seu assistente (Claude, ChatGPT ou outro app compatível com MCP) como conector personalizado: a Wappie abre no seu navegador e pergunta quais números ele pode ler.',
    address: 'Endereço do conector', console: 'Abrir o console da Wappie', docs: 'Ler a documentação', name: 'Português' }),
  en: Object.freeze({ title: 'Wappie connector', lead: 'This is the address of Wappie’s connector. Add it in your assistant (Claude, ChatGPT or another app that supports MCP) as a custom connector: Wappie then opens in your browser and asks which numbers it may read.',
    address: 'Connector address', console: 'Open the Wappie console', docs: 'Read the documentation', name: 'English' }),
  es: Object.freeze({ title: 'Conector de Wappie', lead: 'Esta es la dirección del conector de Wappie. Agrégala en tu asistente (Claude, ChatGPT u otra app compatible con MCP) como conector personalizado: Wappie se abre en tu navegador y te pregunta qué números puede leer.',
    address: 'Dirección del conector', console: 'Abrir la consola de Wappie', docs: 'Leer la documentación', name: 'Español' }),
  fr: Object.freeze({ title: 'Connecteur Wappie', lead: 'Ceci est l’adresse du connecteur Wappie. Ajoutez-la dans votre assistant (Claude, ChatGPT ou une autre application compatible MCP) comme connecteur personnalisé : Wappie s’ouvre alors dans votre navigateur et vous demande quels numéros il peut lire.',
    address: 'Adresse du connecteur', console: 'Ouvrir la console Wappie', docs: 'Lire la documentation', name: 'Français' }),
  de: Object.freeze({ title: 'Wappie-Connector', lead: 'Dies ist die Adresse des Wappie-Connectors. Fügen Sie sie in Ihrem Assistenten (Claude, ChatGPT oder einer anderen App mit MCP) als benutzerdefinierten Connector hinzu: Wappie öffnet sich dann in Ihrem Browser und fragt, welche Nummern er lesen darf.',
    address: 'Connector-Adresse', console: 'Wappie-Konsole öffnen', docs: 'Dokumentation lesen', name: 'Deutsch' }),
})
const HTML_LANG = Object.freeze({ pt: 'pt-BR', en: 'en', es: 'es', fr: 'fr', de: 'de' })
const homeStyle = ':root{color-scheme:light dark;--fg:#16201c;--dim:#55615c;--line:#d5ddd9;--accent:#137659;--bg:#fff}' +
  '@media(prefers-color-scheme:dark){:root{--fg:#e8efec;--dim:#a2b0aa;--line:#33403b;--accent:#5fc7a3;--bg:#111816}}' +
  'body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}' +
  'main{max-width:40rem;margin:0 auto;padding:48px 16px;overflow-wrap:anywhere}img{display:block;border-radius:14px}' +
  'h1{font-size:1.6rem;line-height:1.25;margin:20px 0 12px}p{margin:0 0 16px}' +
  '.address{border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:20px 0}.address small{display:block;color:var(--dim);font-size:.8rem}' +
  'code{font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}ul{padding:0;list-style:none;margin:0 0 32px}li{margin:6px 0}' +
  'a{color:var(--accent)}nav{border-top:1px solid var(--line);padding-top:12px;font-size:.85rem;color:var(--dim)}nav a{margin-right:12px}'
const homeCSP = `default-src 'none'; img-src 'self'; style-src 'sha256-${sha256(homeStyle)}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`

/** The language the home page speaks: a valid `?lang=`, else the person's first of the five, else English. */
export function homeLanguage(url, acceptLanguage) {
  const asked = new URL(url).searchParams.get('lang')
  return PAGE_LANGUAGES.includes(asked) ? asked : askedLanguages(acceptLanguage)[0] ?? 'en'
}

/**
 * GET or HEAD `/`: `site` is `{resource, console, documentation}`, the
 * reader's constants. Cacheable briefly, per language.
 */
export function homePage(request, site) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return Response.json({ code: 'method_not_allowed' }, { status: 405, headers: { ...noStore, Allow: 'GET, HEAD' } })
  const tag = homeLanguage(request.url, request.headers.get('accept-language'))
  const text = HOME[tag]
  const links = [[site.console, text.console], [site.documentation, text.docs]].filter(([href]) => typeof href === 'string' && /^https:\/\//.test(href))
  const body = `<!doctype html><html lang="${HTML_LANG[tag]}"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<title>${escapeHTML(text.title)}</title><link rel="icon" href="/favicon.ico" sizes="32x32"><link rel="icon" type="image/svg+xml" href="/favicon.svg">` +
    '<link rel="icon" type="image/png" sizes="192x192" href="/icon-192.png"><link rel="apple-touch-icon" href="/apple-touch-icon.png">' +
    `<style>${homeStyle}</style><main><img src="/icon-192.png" width="64" height="64" alt="Wappie"><h1>${escapeHTML(text.title)}</h1><p>${escapeHTML(text.lead)}</p>` +
    `<p class="address"><small>${escapeHTML(text.address)}</small><code>${escapeHTML(site.resource)}</code></p>` +
    `<ul>${links.map(([href, label]) => `<li><a href="${escapeHTML(href)}">${escapeHTML(label)}</a></li>`).join('')}</ul>` +
    `<nav>${PAGE_LANGUAGES.map(other => (other === tag ? `<span lang="${other}">${HOME[other].name}</span>` : `<a lang="${other}" href="/?lang=${other}">${HOME[other].name}</a>`)).join(' ')}</nav></main></html>`
  const bytes = Buffer.from(body, 'utf8')
  return new Response(request.method === 'HEAD' ? null : bytes, { headers: {
    'Content-Type': 'text/html; charset=utf-8', 'Content-Length': String(bytes.length), 'Content-Language': HTML_LANG[tag], 'Content-Security-Policy': homeCSP,
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Cross-Origin-Opener-Policy': 'same-origin',
    'Cache-Control': 'public, max-age=300', Vary: 'Accept-Language',
  } })
}

/** robots.txt (§19.29): the page and the icons may be fetched, the protocol endpoints are not for crawlers. */
export const ROBOTS = 'User-agent: *\nAllow: /\nDisallow: /mcp\nDisallow: /attestation\n'
export function robotsResponse(request) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return Response.json({ code: 'method_not_allowed' }, { status: 405, headers: { ...noStore, Allow: 'GET, HEAD' } })
  const bytes = Buffer.from(ROBOTS, 'utf8')
  return new Response(request.method === 'HEAD' ? null : bytes, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': String(bytes.length),
    'Cache-Control': 'public, max-age=86400', 'X-Content-Type-Options': 'nosniff' } })
}
