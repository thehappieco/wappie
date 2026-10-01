// The OAuth 2.1 authorization server: registration, the authorization request
// that hands off to the console, the consent completion that turns a proof into
// a code, the token endpoint and revocation. Everything here is hand-written
// because the SDK ships only the resource-server half; it is deliberately small
// and every branch is exercised by the negative matrix in test/as.test.mjs.
//
// Reader 0.6.0 (docs/mcp-enclave.md §19) runs the `any` policy: a request is
// classified on its own (§19.6), tested only when a measured TESTED_CLIENTS
// entry pins both its client_id and its redirect (never fetched), unknown
// otherwise, with a document the enclave fetched itself; a missing
// `resource` and a wider `scope` are accepted (§19.11); the completion must
// come from the network that started the request (§19.12). The `allowlist`
// policy is 0.5.0's, unchanged, for the hosted reader and the tests.
import { randomBytes } from 'node:crypto'
import { dcrEntryFor, limitsTierOf, loopbackRedirect, redirectAllowed, RegistrationError, testedFor } from './clients.mjs'
import { cimdIdentity } from './cimd.mjs'
import { dummyProof, LinkError, MAX_PROOF_ATTEMPTS, unknownLive, verifyProof } from './link.mjs'
import { GrantError, hash, wellFormed } from './tokens.mjs'
import { SCOPE } from './metadata.mjs'
import { RelayError } from './internal.mjs'
import { sameNetwork } from './limits.mjs'

export const PENDING_MAX = 1000
export const PENDING_UNCONSENTED_MAX = 200
export const PENDING_PER_IP = 10
/** Unconsented requests of one unknown client at once, so one phishing campaign cannot evict every other open consent tab (§19.10). */
export const PENDING_PER_CLIENT = 20
export const TOKEN_PER_IP = 300
export const REGISTER_PER_IP = 5
export const CIMD_FETCH_PER_IP = 3
export const MAX_STATE_CHARS = 512
/** An `invalid_client` page of the `any` policy is never sent sooner than this after the request began (§19.6 step 5). */
export const REFUSAL_FLOOR_MS = 1000
const challengeShape = /^[A-Za-z0-9_-]{43,128}$/
const requestIDShape = /^[A-Za-z0-9_-]{22}$/
const noStore = { 'Cache-Control': 'no-store', Pragma: 'no-cache' }
const scopeToken = /^[\x21\x23-\x5B\x5D-\x7E]{1,64}$/

/**
 * `resource` as §19.11 compares it under the `any` policy: the scheme and
 * host lower-cased and one trailing `/` removed; absent is this server's own.
 */
export function resourceOf(value, resource) {
  if (value === null || value === undefined) return resource
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)(.*)$/s.exec(value)
  if (!match) return value
  const normal = `${match[1].toLowerCase()}://${match[2].toLowerCase()}${match[3]}`
  return normal.endsWith('/') ? normal.slice(0, -1) : normal
}
/** `scope` under the `any` policy: absent, or 1 to 10 RFC 6749 scope tokens of at most 64 characters (§19.11). */
export const scopeAcceptable = value => value === null || (value.length <= 1024 && (() => {
  const items = value.split(' ')
  return items.length >= 1 && items.length <= 10 && items.every(item => scopeToken.test(item))
})())

const oauthError = (status, error, description, extra = {}) => Response.json({ error, error_description: description }, { status, headers: { ...noStore, ...extra } })
const escapeHTML = value => value.replace(/[&<>"]/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[character])
/**
 * Browser-facing failures get a static page; the code comes from a fixed set,
 * never from input, and `back` only ever from configuration. A refusal with no
 * way back strands the owner on this page with a consent already half made, so
 * the routes a browser reaches pass the console here.
 */
const htmlHead = '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Wappie MCP</title>' +
  '<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 16px;overflow-wrap:anywhere}small{color:#555}</style>'
const htmlHeaders = { ...noStore, 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff' }
const page = (status, code, back = '') => new Response(`${htmlHead}<p>Wappie MCP: ${code}.</p>` + (back ? `<p><a href="${escapeHTML(back)}">${escapeHTML(back)}</a></p>` : ''),
  { status, headers: htmlHeaders })
const redirect = location => new Response(null, { status: 302, headers: { ...noStore, Location: location } })
const text = value => (typeof value === 'string' ? value : undefined)
/** The page languages (§19.14's five), the person's first when Accept-Language names one, then the console's order. */
export const PAGE_LANGUAGES = Object.freeze(['pt', 'en', 'es', 'fr', 'de'])
export function pageLanguages(acceptLanguage) {
  const first = String(acceptLanguage ?? '').split(',').map(item => item.trim().slice(0, 2).toLowerCase()).find(tag => PAGE_LANGUAGES.includes(tag))
  return first ? [first, ...PAGE_LANGUAGES.filter(tag => tag !== first)] : [...PAGE_LANGUAGES]
}
/**
 * The two pages with sentences, fixed in the image and drafts the owner
 * approves (D10): the `any` policy's refusal of a client (one page for every
 * reason, §19.6 step 5) and the completion refused on another network
 * (§19.12). The code stays, in small print, for support.
 */
const SENTENCES = {
  invalid_client: {
    pt: 'A Wappie não pôde aceitar este assistente. Ele pode não publicar a página de identidade de que a Wappie precisa, ou o endereço dele não é permitido. Nada foi compartilhado. Você pode conectar um assistente testado ou criar um token de conexão no console da Wappie.',
    en: 'Wappie could not accept this assistant. It may not publish the identity page Wappie needs, or its address is not allowed. Nothing was shared. You can connect a tested assistant, or create a connection token in the Wappie console.',
    es: 'Wappie no pudo aceptar este asistente. Puede que no publique la página de identidad que Wappie necesita, o que su dirección no esté permitida. No se compartió nada. Puedes conectar un asistente probado o crear un token de conexión en la consola de Wappie.',
    fr: 'Wappie n’a pas pu accepter cet assistant. Il ne publie peut-être pas la page d’identité dont Wappie a besoin, ou son adresse n’est pas autorisée. Rien n’a été partagé. Vous pouvez connecter un assistant testé ou créer un jeton de connexion dans la console Wappie.',
    de: 'Wappie konnte diesen Assistenten nicht annehmen. Vielleicht veröffentlicht er nicht die Identitätsseite, die Wappie braucht, oder seine Adresse ist nicht erlaubt. Es wurde nichts geteilt. Sie können einen getesteten Assistenten verbinden oder in der Wappie-Konsole ein Verbindungstoken erstellen.',
  },
  ip_mismatch: {
    pt: 'Esta autorização foi aberta numa rede diferente da que começou a conexão. Volte ao assistente e clique em Conectar de novo. Se você usa VPN ou a Retransmissão Privada do iCloud, desligue para esta etapa e tente de novo.',
    en: 'This authorization was opened on a different network from the one that started the connection. Go back to the assistant and click Connect again. If you use a VPN or iCloud Private Relay, turn it off for this step and try again.',
    es: 'Esta autorización se abrió en una red distinta de la que inició la conexión. Vuelve al asistente y haz clic en Conectar de nuevo. Si usas una VPN o Relay privado de iCloud, desactívalo para este paso y vuelve a intentarlo.',
    fr: 'Cette autorisation a été ouverte sur un autre réseau que celui qui a lancé la connexion. Revenez à l’assistant et cliquez de nouveau sur Connecter. Si vous utilisez un VPN ou le Relais privé iCloud, désactivez-le pour cette étape et réessayez.',
    de: 'Diese Freigabe wurde in einem anderen Netzwerk geöffnet als dem, in dem die Verbindung begann. Gehen Sie zurück zum Assistenten und klicken Sie erneut auf Verbinden. Wenn Sie ein VPN oder iCloud Privat-Relay nutzen, schalten Sie es für diesen Schritt aus und versuchen Sie es noch einmal.',
  },
}
const sentencePage = (code, back, acceptLanguage) => new Response(htmlHead +
  pageLanguages(acceptLanguage).map(tag => `<p lang="${tag}">${escapeHTML(SENTENCES[code][tag])}</p>`).join('') +
  `<p><a href="${escapeHTML(back)}">${escapeHTML(back)}</a></p><p><small>Wappie MCP: ${code}</small></p>`,
{ status: 400, headers: htmlHeaders })
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

/** Parses a form body, refusing anything but urlencoded and any repeated field. */
async function form(request) {
  if (!(request.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase().startsWith('application/x-www-form-urlencoded')) return null
  const params = new URLSearchParams(await request.text())
  for (const name of new Set(params.keys())) if (params.getAll(name).length > 1) return null
  return params
}

/**
 * `newRecipient`, when given, mints a key for every pending request (the
 * enclave: the key the console seals to is the one the attestation names, and
 * it dies with the request). Without it every request shares the reader's key.
 *
 * `content` (the attested reader only) owns requests whose bundle it accepted
 * (`pending.bundle.kind === 'content'`): it checks their proof, adds its
 * fields to the connection record and installs the request's key once Go has
 * activated the connection. Without it no such request can exist.
 */
export function createAuthorizationServer({ state, clients, cimd, tokens, limiter, relay, log, now, publicOrigin, consoleURL, resource, pendingTTLMs, newRecipient, content,
  policy = { mode: 'allowlist' }, counters = {} }) {
  const consoleOrigin = new URL(consoleURL).origin
  const any = policy.mode === 'any'
  const count = name => { counters[name] = (counters[name] ?? 0) + 1 }
  /**
   * The `any` policy's `invalid_client`: one static page and status for every
   * reason, never sooner than REFUSAL_FLOOR_MS after the request began, so a
   * prober learns nothing from it. `started` is when the request began and
   * the languages it accepts, which order the page's sentences and nothing else.
   */
  async function refuseClient(meta, started) {
    meta.code = 'invalid_client'
    const left = (policy.refusalFloorMs ?? REFUSAL_FLOOR_MS) - (performance.now() - started.at)
    if (left > 0) await sleep(left)
    return sentencePage('invalid_client', consoleURL, started.language)
  }
  /**
   * §19.6's classification of one request under the `any` policy:
   * `{request}` (the fields the pending record and the descriptor carry) or
   * `{response}` (a refusal). A tested id asked with a pinned redirect is
   * served from the measured entry and never fetched; another redirect of a
   * tested id is the real document's, as an unknown client (`drift`).
   */
  async function classify(clientID, redirectURI, ip, meta, started) {
    const host = uri => new URL(uri).hostname
    const dcr = clients.get(clientID)
    if (dcr) {
      meta.client = dcr.client_id
      // Every DCR redirect is pinned, whenever the record was made: a 0.5.0 record's other paths are never served.
      const entry = typeof redirectURI === 'string' && dcr.redirect_uris.includes(redirectURI) ? dcrEntryFor(policy.tested, [redirectURI]) : null
      if (!entry) { meta.code = 'invalid_redirect_uri'; return { response: page(400, 'invalid_redirect_uri') } }
      const domain = policy.psl.registrable(host(redirectURI))
      return { request: { client_kind: 'dcr', client_host: host(redirectURI), registrable: domain?.registrable ?? host(redirectURI), shared_suffix: domain?.shared_suffix ?? null,
        client_local: false, trust: 'tested', tested_id: entry.id, drift: false, client_name: entry.name, claimed_name: dcr.claimed_name ?? null,
        name_dropped: dcr.name_dropped === true, profile: entry.profile, ignored_uris: 0 } }
    }
    const identity = cimdIdentity(clientID, policy)
    if (!identity.ok) return { response: await refuseClient(meta, started) }
    meta.client = clientID
    const tested = testedFor(policy.tested, clientID, redirectURI)
    if (tested?.pinned) {
      const { entry } = tested
      return { request: { client_kind: 'cimd', client_host: identity.host, registrable: identity.registrable, shared_suffix: identity.shared_suffix,
        client_local: entry.local, trust: 'tested', tested_id: entry.id, drift: false, client_name: entry.name, claimed_name: null, name_dropped: false,
        profile: entry.profile, ignored_uris: 0 } }
    }
    const resolved = await cimd.resolveAny(clientID, identity, { ip })
    if (resolved.busy) { meta.code = resolved.busy; return { response: page(429, 'too_many_requests') } }
    if (!resolved.record) return { response: await refuseClient(meta, started) }
    const record = resolved.record
    if (!redirectAllowed(record, redirectURI)) { meta.code = 'invalid_redirect_uri'; return { response: page(400, 'invalid_redirect_uri') } }
    if (tested) count('tested_drift')
    return { request: { client_kind: 'cimd', client_host: record.client_host, registrable: record.registrable, shared_suffix: record.shared_suffix,
      client_local: loopbackRedirect(redirectURI) !== null, trust: 'unknown', tested_id: null, drift: Boolean(tested), client_name: record.client_host,
      claimed_name: record.claimed_name, name_dropped: record.name_dropped, profile: 'default', ignored_uris: record.ignored_uris } }
  }
  const tooMany = (meta, retryAfter) => { meta.code = 'rate_limited'; return oauthError(429, 'temporarily_unavailable', 'too many requests', { 'Retry-After': String(retryAfter) }) }
  function expirePending(id, pending) {
    state.pending.delete(id)
    if (pending.connection_id) void relay.revoke(pending.connection_id)
  }
  /** A live pending request, or undefined; expired ones are dropped (and their Go row revoked) on sight. */
  function pendingFor(id) {
    if (!requestIDShape.test(id ?? '')) return undefined
    const pending = state.pending.get(id)
    if (!pending) return undefined
    if (pending.expires_at <= now()) { expirePending(id, pending); return undefined }
    return pending
  }
  /**
   * Room for one more pending request. A request nobody has consented to yet
   * (no bundle) is only a browser tab that may never come back, so the oldest
   * one makes way; only when every slot holds a consented request is the
   * caller refused, and those are bounded by the connections Go allows.
   */
  function makeRoom() {
    const unconsented = [...state.pending.entries()].filter(([, pending]) => !pending.bundle)
    if (unconsented.length < PENDING_UNCONSENTED_MAX && state.pending.size < PENDING_MAX) return true
    if (unconsented.length === 0) return false
    const [oldest] = unconsented.reduce((found, entry) => (entry[1].created_at < found[1].created_at ? entry : found))
    state.pending.delete(oldest)
    return true
  }
  /** The rest of an authorization request under the `any` policy, from the classification on. */
  async function authorizeAny(params, clientID, ip, meta, started) {
    const redirectURI = params.get('redirect_uri')
    const classified = await classify(clientID, redirectURI, ip, meta, started)
    if (classified.response) return classified.response
    const { ignored_uris: ignored, ...client } = classified.request
    client.limits_tier = limitsTierOf(client)
    const resourceDefault = params.get('resource') === null
    meta.flags = { unknown: client.trust === 'unknown', local: client.client_local, cimd: client.client_kind === 'cimd', drift: client.drift, resource_default: resourceDefault }
    log.event('client_resolved', { unknown: client.trust === 'unknown', local: client.client_local, cimd: client.client_kind === 'cimd', drift: client.drift,
      name_dropped: client.name_dropped, ignored_uris: ignored })
    // From here on the redirect target is trusted, so errors travel back to the client.
    const fail = code => {
      meta.code = code
      const location = new URL(redirectURI)
      location.searchParams.set('error', code)
      if (params.has('state')) location.searchParams.set('state', params.get('state'))
      location.searchParams.set('iss', publicOrigin)
      return redirect(location.href)
    }
    if (params.get('response_type') !== 'code') return fail('unsupported_response_type')
    const challenge = params.get('code_challenge') ?? ''
    if (!challengeShape.test(challenge) || params.get('code_challenge_method') !== 'S256') return fail('invalid_request')
    if (resourceOf(params.get('resource'), resource) !== resource) return fail('invalid_target')
    if (!scopeAcceptable(params.get('scope'))) return fail('invalid_scope')
    const stateParam = params.get('state')
    if (stateParam !== null && (stateParam.length === 0 || stateParam.length > MAX_STATE_CHARS)) return fail('invalid_request')
    if (client.trust === 'unknown') {
      let open = 0
      for (const pending of state.pending.values()) if (!pending.bundle && pending.client_id === clientID) open++
      if (open >= PENDING_PER_CLIENT) { meta.code = 'too_many_pending'; return page(429, 'too_many_requests') }
    }
    if (!makeRoom()) { meta.code = 'too_many_pending'; return page(429, 'too_many_requests') }
    const id = randomBytes(16).toString('base64url')
    const recipient = newRecipient ? await newRecipient() : undefined
    state.pending.set(id, {
      id, descriptor_version: 2, client_id: clientID, ...client, limits: structuredClone(policy.limits[client.limits_tier]),
      // 0.5.0's consumers read the host a connection is recorded under: a web client's redirect host, as 0.5.0 wrote it
      // (Claude's pinned claude.com callback is claude.com's), and for a native app the host vouching for it.
      redirect_uri: redirectURI, redirect_host: client.client_local ? client.client_host : new URL(redirectURI).hostname, redirect_local: client.client_local,
      state: stateParam ?? undefined, code_challenge: challenge, resource, scope: SCOPE, ip,
      created_at: now(), expires_at: now() + pendingTTLMs, proof_attempts: 0,
      ...(recipient ? { recipient, prepares: 0 } : {}),
    })
    const location = new URL(consoleURL)
    location.searchParams.set('mcp_connect', id)
    return redirect(location.href)
  }

  return {
    pendingFor,
    sweepPending() { for (const [id, pending] of state.pending) if (pending.expires_at <= now()) expirePending(id, pending) },

    async register(request, ip, meta) {
      if (request.method !== 'POST') return oauthError(405, 'invalid_request', 'POST only', { Allow: 'POST' })
      const taken = limiter.take('register', ip, REGISTER_PER_IP)
      if (!taken.ok) return tooMany(meta, taken.retryAfter)
      let body
      if (!(request.headers.get('content-type') ?? '').toLowerCase().startsWith('application/json')) { meta.code = 'invalid_client_metadata'; return oauthError(400, 'invalid_client_metadata', 'the registration must be application/json') }
      try { body = await request.json() } catch { meta.code = 'invalid_client_metadata'; return oauthError(400, 'invalid_client_metadata', 'the registration must be valid JSON') }
      try {
        const record = clients.register(body)
        meta.client = record.client_id
        await state.save()
        return Response.json(clients.describe(record), { status: 201, headers: noStore })
      } catch (error) {
        if (!(error instanceof RegistrationError)) throw error
        meta.code = error.code
        return oauthError(error.status ?? 400, error.code, error.description, error.status === 429 ? { 'Retry-After': '60' } : {})
      }
    },

    async authorize(request, ip, meta) {
      const started = { at: performance.now(), language: request.headers.get('accept-language') }
      if (request.method !== 'GET') return page(405, 'method_not_allowed')
      // The address budget is spent before anything is looked at, so a refused
      // request (or one that would make the relay fetch a document) costs the
      // caller as much as an accepted one.
      const taken = limiter.take('authorize', ip, 20)
      if (!taken.ok) { meta.code = 'rate_limited'; return page(429, 'too_many_requests') }
      let mine = 0
      for (const pending of state.pending.values()) if (pending.ip === ip) mine++
      if (mine >= PENDING_PER_IP) { meta.code = 'too_many_pending'; return page(429, 'too_many_requests') }
      const params = new URL(request.url).searchParams
      for (const name of new Set(params.keys())) if (params.getAll(name).length > 1) { meta.code = 'invalid_request'; return page(400, 'invalid_request') }
      const clientID = params.get('client_id') ?? ''
      if (any) return authorizeAny(params, clientID, ip, meta, started)
      let starved = false
      const client = clients.get(clientID) ?? await cimd.resolve(clientID, { allowFetch: () => { const budget = limiter.take('cimd', ip, CIMD_FETCH_PER_IP); starved = !budget.ok; return budget.ok } })
      if (starved) { meta.code = 'rate_limited'; return page(429, 'too_many_requests') }
      if (!client) { meta.code = 'invalid_client'; return page(400, 'invalid_client') }
      meta.client = client.client_id
      const redirectURI = params.get('redirect_uri')
      if (!redirectAllowed(client, redirectURI)) { meta.code = 'invalid_redirect_uri'; return page(400, 'invalid_redirect_uri') }
      // From here on the redirect target is trusted, so errors travel back to the client.
      const fail = code => {
        meta.code = code
        const location = new URL(redirectURI)
        location.searchParams.set('error', code)
        if (params.has('state')) location.searchParams.set('state', params.get('state'))
        location.searchParams.set('iss', publicOrigin)
        return redirect(location.href)
      }
      if (params.get('response_type') !== 'code') return fail('unsupported_response_type')
      const challenge = params.get('code_challenge') ?? ''
      if (!challengeShape.test(challenge) || params.get('code_challenge_method') !== 'S256') return fail('invalid_request')
      if (params.get('resource') !== resource) return fail('invalid_target')
      const scope = params.get('scope')
      if (scope !== null && (scope.trim() === '' || scope.split(' ').filter(Boolean).some(item => item !== SCOPE))) return fail('invalid_scope')
      const stateParam = params.get('state')
      if (stateParam !== null && (stateParam.length === 0 || stateParam.length > MAX_STATE_CHARS)) return fail('invalid_request')
      if (!makeRoom()) { meta.code = 'too_many_pending'; return page(429, 'too_many_requests') }
      const id = randomBytes(16).toString('base64url')
      const recipient = newRecipient ? await newRecipient() : undefined
      state.pending.set(id, {
        id, client_id: client.client_id, client_name: client.client_name, redirect_uri: redirectURI, redirect_host: client.redirect_host,
        // The console tells the person where the code goes; for a native app
        // that is their own machine, not the host that vouches for the app.
        redirect_local: client.loopback === true,
        state: stateParam ?? undefined, code_challenge: challenge, resource, scope: SCOPE, ip,
        created_at: now(), expires_at: now() + pendingTTLMs, proof_attempts: 0,
        ...(recipient ? { recipient, prepares: 0 } : {}),
      })
      const location = new URL(consoleURL)
      location.searchParams.set('mcp_connect', id)
      return redirect(location.href)
    },

    async complete(request, ip, meta) {
      if (request.method !== 'POST') return page(405, 'method_not_allowed')
      // CSRF: the consent form is posted by the console, and only by the
      // console. A document served with `Referrer-Policy: no-referrer` makes
      // the browser send the literal `Origin: null` on a top-level post, so
      // that case gets its own code: it names a console misconfiguration, not
      // a hostile page, and the two must not read alike in the journal.
      const sent = request.headers.get('origin')
      if (sent !== consoleOrigin) {
        meta.code = sent === null ? 'origin_missing' : sent === 'null' ? 'opaque_origin' : 'invalid_origin'
        return page(400, meta.code, consoleURL)
      }
      const taken = limiter.take('complete', ip, 10)
      if (!taken.ok) { meta.code = 'rate_limited'; return page(429, 'too_many_requests', consoleURL) }
      const params = await form(request)
      if (!params) { meta.code = 'invalid_request'; return page(400, 'invalid_request', consoleURL) }
      const id = params.get('request') ?? '', proof = params.get('proof') ?? ''
      const pending = pendingFor(id)
      if (!pending || !pending.bundle) { dummyProof(); meta.code = 'invalid_proof'; return page(400, 'invalid_proof', consoleURL) }
      meta.client = pending.client_id
      meta.connection = pending.connection_id
      // §19.12: the consent completes from the network the request started on,
      // or a console link sent to someone else would complete an attacker's flow.
      if (pending.descriptor_version === 2) {
        const mismatch = !sameNetwork(pending.ip, ip)
        meta.flags = { ip_mismatch: mismatch }
        if (mismatch) { count('ip_mismatches'); expirePending(id, pending); meta.code = 'ip_mismatch'; return sentencePage('ip_mismatch', consoleURL, request.headers.get('accept-language')) }
      }
      const withContent = pending.bundle.kind === 'content'
      let bundle = null
      try { bundle = withContent ? (content ? await content.verifyProof(pending, proof) : null) : await verifyProof(state, pending, proof) } catch (error) { if (!(error instanceof LinkError)) throw error }
      if (!bundle) {
        pending.proof_attempts++
        if (pending.proof_attempts >= MAX_PROOF_ATTEMPTS) { expirePending(id, pending); meta.code = 'proof_burned'; return page(400, 'invalid_proof', consoleURL) }
        meta.code = 'invalid_proof'
        return page(400, 'invalid_proof', consoleURL)
      }
      // Go names the connection. The relay routes refuse an id already in use,
      // and this holds whatever interleaved since: a connection that exists
      // here is never replaced, because its tokens belong to another consent.
      const inUse = () => { meta.code = 'connection_exists'; return page(400, 'connection_exists', consoleURL) }
      if (state.connections.has(pending.connection_id)) { expirePending(id, pending); return inUse() }
      // Between leaving state.pending and landing in state.connections the id
      // sits in neither; state.activating keeps it reserved across the await,
      // so connectionTaken refuses a relay naming it meanwhile.
      state.activating ??= new Set()
      state.activating.add(pending.connection_id)
      state.pending.delete(id)
      try {
        try { await relay.activate(pending.connection_id) } catch (error) {
          if (!(error instanceof RelayError)) throw error
          void relay.revoke(pending.connection_id)
          meta.code = 'activation_failed'
          return page(502, 'activation_failed', consoleURL)
        }
        if (state.connections.has(pending.connection_id)) { void relay.revoke(pending.connection_id); return inUse() }
        // §19.10: another unknown connection may have been installed since this one's bundle was accepted.
        if (pending.trust === 'unknown' && unknownLive(state, pending.tenant_id, pending) >= policy.unknownLiveMax) {
          void relay.revoke(pending.connection_id)
          meta.code = 'too_many_unknown'
          return page(409, 'too_many_unknown', consoleURL)
        }
        const record = {
          connection_id: pending.connection_id, tenant_id: pending.tenant_id, workspace_id: bundle.workspace_id, device_ids: bundle.device_ids,
          timezone: bundle.timezone ?? 'UTC', api_key: bundle.token, expires_at: pending.bundle.expires_at, client_id: pending.client_id, created_at: now(),
          // The client this consent was given to, written once (§19.17): no renewal changes it.
          ...(pending.descriptor_version === 2 ? clientFields(pending, bundle) : {}),
        }
        if (withContent) content.install(pending, record)
        state.connections.set(pending.connection_id, record)
      } finally {
        state.activating.delete(pending.connection_id)
      }
      clients.consented(pending.client_id)
      await state.save()
      const code = tokens.issueCode({ client_id: pending.client_id, redirect_uri: pending.redirect_uri, code_challenge: pending.code_challenge, resource, connection_id: pending.connection_id })
      const location = new URL(pending.redirect_uri)
      location.searchParams.set('code', code)
      if (pending.state !== undefined) location.searchParams.set('state', pending.state)
      location.searchParams.set('iss', publicOrigin)
      return redirect(location.href)
    },

    async token(request, ip, meta) {
      if (request.method !== 'POST') return oauthError(405, 'invalid_request', 'POST only', { Allow: 'POST' })
      // Before the grant is known only the address can be charged, and coarsely:
      // client_id is public (one CIMD URL serves every user of an assistant), so
      // a bucket keyed on it would let anyone with a garbage grant starve them
      // all. The fair buckets below key on what the grant itself identifies.
      const taken = limiter.take('token', ip, TOKEN_PER_IP)
      if (!taken.ok) return tooMany(meta, taken.retryAfter)
      const params = await form(request)
      if (!params) { meta.code = 'invalid_request'; return oauthError(400, 'invalid_request', 'the request must be a form without repeated fields') }
      const grant = params.get('grant_type'), clientID = text(params.get('client_id') ?? undefined)
      if (!clientID || clientID.length > 2048) { meta.code = 'invalid_request'; return oauthError(400, 'invalid_request', 'client_id is required') }
      meta.client = clientID
      // Under the `any` policy a missing resource is this server's, and the scheme and host compare case-insensitively (§19.11).
      const target = any ? resourceOf(params.get('resource'), resource) : params.get('resource')
      try {
        if (grant === 'authorization_code') {
          if (target !== resource) { meta.code = 'invalid_target'; return oauthError(400, 'invalid_target', 'resource must name this MCP server') }
          const code = params.get('code') ?? ''
          const connection = wellFormed('code', code) ? state.codes.get(hash(code))?.connection_id : undefined
          if (connection) {
            meta.connection = connection
            const perConnection = limiter.take('token_connection', connection, 20)
            if (!perConnection.ok) return tooMany(meta, perConnection.retryAfter)
          }
          const pair = await tokens.exchangeCode({ code, client_id: clientID, code_verifier: params.get('code_verifier') ?? '', redirect_uri: params.get('redirect_uri') ?? '', resource: target })
          return Response.json(pair, { headers: noStore })
        }
        if (grant === 'refresh_token') {
          if (target !== null && target !== resource) { meta.code = 'invalid_target'; return oauthError(400, 'invalid_target', 'resource must name this MCP server') }
          const presented = params.get('refresh_token') ?? ''
          const known = wellFormed('refresh', presented) ? state.tokens.get(hash(presented)) : undefined
          if (known) {
            meta.connection = known.connection_id
            const perFamily = limiter.take('token_family', known.family_id, 20)
            if (!perFamily.ok) return tooMany(meta, perFamily.retryAfter)
          }
          const pair = await tokens.refresh({ refresh_token: presented, client_id: clientID })
          return Response.json(pair, { headers: noStore })
        }
        meta.code = 'unsupported_grant_type'
        return oauthError(400, 'unsupported_grant_type', 'use authorization_code or refresh_token')
      } catch (error) {
        if (error instanceof GrantError) { meta.code = 'invalid_grant'; return oauthError(400, 'invalid_grant', 'the grant is invalid, expired or revoked') }
        if (error instanceof RelayError) { meta.code = 'archive_unavailable'; return oauthError(503, 'server_error', 'the archive is unavailable', { 'Retry-After': '5' }) }
        throw error
      }
    },

    async revoke(request, meta) {
      if (request.method !== 'POST') return oauthError(405, 'invalid_request', 'POST only', { Allow: 'POST' })
      const params = await form(request)
      if (!params) { meta.code = 'invalid_request'; return oauthError(400, 'invalid_request', 'the request must be a form without repeated fields') }
      meta.client = text(params.get('client_id') ?? undefined)
      // RFC 7009: the answer is 200 whether or not the token was known.
      if (await tokens.revoke(params.get('token') ?? '')) meta.code = 'revoked'
      return new Response(null, { status: 200, headers: noStore })
    },
  }
}

/**
 * The client fields of a connection a v2 request made (§19.17): the
 * request's classification and what the person sealed (a metadata bundle has
 * no second tick; a content one's fields are content.install's).
 */
function clientFields(pending, bundle) {
  return {
    client_kind: pending.client_kind, client_host: pending.client_host, registrable: pending.registrable, shared_suffix: pending.shared_suffix,
    client_local: pending.client_local, client_name: pending.client_name, claimed_name: pending.claimed_name, trust: pending.trust,
    tested_id: pending.tested_id, profile: pending.profile, limits_tier: pending.limits_tier, started_ack: bundle.started_ack === true,
    unknown_ack: bundle.unknown_ack === true, history_days: bundle.history_days ?? null, redirect_host: pending.redirect_host,
  }
}
