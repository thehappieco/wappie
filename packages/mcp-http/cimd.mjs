// Client ID Metadata Documents (SEP-991): a client_id that is an HTTPS URL
// names a JSON document describing the client. A good document is cached, a
// bad or unreachable one is remembered for a minute so a stream of requests
// naming it does not become a stream of outbound fetches.
//
// Two policies (docs/mcp-enclave.md §19.3). `allowlist` is 0.5.0's rule, for
// the hosted reader and the tests: the document's host must be in `hosts`, it
// is fetched by the Go relay (`GET /v1/mcp/internal/cimd`), and it is cached
// for a day. `any` is reader 0.6.0's: a client_id on any host that passes
// §19.5 (`cimdIdentity`), fetched by the enclave itself over TLS it verifies,
// through the parent's byte-only egress proxy (`policy.fetcher`, §19.9), under
// budgets per address, per registrable domain and in all, and cached for what
// the answer's Cache-Control says within five minutes and a day (§19.10).
// Tested clients asked with a pinned redirect never reach this file (as.mjs).
import {
  claimedName, classifyRedirect, makeRoom, makeRoomUnknown, RegistrationError, validateClientName, validateRedirectURIs,
} from './clients.mjs'

export const CIMD_MAX_BYTES = 8 * 1024
export const CIMD_TTL_MS = 24 * 3_600_000
export const CIMD_NEGATIVE_TTL_MS = 60_000
/** The cache lifetime of a fetched document: the answer's max-age within these, the longest when it says nothing (§19.10). */
export const CIMD_TTL_MIN_MS = 300_000
export const CIMD_TTL_MAX_MS = 86_400_000
/** Fetch budgets of the `any` policy (§19.9 enclave step 1): per address (0.5.0's), in all, per registrable domain, and in flight. */
export const CIMD_FETCHES_PER_ADDRESS = 3
export const CIMD_FETCHES_PER_MINUTE = 30
export const CIMD_FETCHES_PER_DOMAIN = 10
export const CIMD_IN_FLIGHT = 4
/** A document's redirect_uris: one to ten strings. */
export const CIMD_REDIRECTS_MAX = 10
export const CIMD_ID_MAX_BYTES = 512
const NEGATIVE_MAX = 1000
/**
 * Special-use names (§19.5 step 4.5): a host that is one of them, or ends in
 * `.` and one of them, never names a client.
 */
export const SPECIAL_USE = Object.freeze(['localhost', 'localdomain', 'local', 'internal', 'intranet', 'private', 'corp', 'home', 'lan', 'arpa',
  'test', 'example', 'invalid', 'onion', 'alt'])

/** The document URL a client_id names on one of `hosts`, or null when it is not a CIMD identifier (0.5.0's rule). */
export function cimdURL(clientID, hosts) {
  if (typeof clientID !== 'string' || clientID.length > 2048) return null
  let url
  try { url = new URL(clientID) } catch { return null }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash || url.pathname === '/' || url.href !== clientID) return null
  return hosts.includes(url.hostname.toLowerCase()) ? url : null
}

const isOrUnder = (host, names) => names.some(name => host === name || host.endsWith(`.${name}`))

/**
 * §19.5 step 4 on a host: `{ok: true, registrable, shared_suffix}` or
 * `{ok: false, reason}`. `rules` is `{psl, own, shared}` (the snapshot,
 * OWN_DOMAINS and SHARED_HOSTS). The parent's egress proxy and Go's create()
 * apply the same predicate to the same vectors.
 */
export function hostVerdict(host, { psl, own, shared }) {
  const refuse = reason => ({ ok: false, reason })
  if (typeof host !== 'string' || host.length < 4 || host.length > 253 || !/^[a-z0-9.-]+$/.test(host)) return refuse('host_chars')
  const labels = host.split('.')
  if (labels.length < 2 || labels.some(label => label.length < 1 || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) return refuse('host_labels')
  const last = labels.at(-1)
  if (last.length < 2 || !(/^[a-z]+$/.test(last) || last.startsWith('xn--'))) return refuse('ip_literal')
  if (isOrUnder(host, SPECIAL_USE)) return refuse('special_use')
  const domain = psl.registrable(host)
  if (domain && own.includes(domain.registrable)) return refuse('own_domain')
  if (!domain) return refuse('public_suffix')
  if (isOrUnder(host, shared)) return refuse('shared_host')
  return { ok: true, registrable: domain.registrable, shared_suffix: domain.shared_suffix }
}

/**
 * §19.5 on a client_id `S`: `{ok: true, host, path, registrable,
 * shared_suffix}` or `{ok: false, reason}`, the reason of the first step that
 * fails (packages/mcp-http/test/vectors/cimd-ids.json holds the cases, which
 * Go's create() and the egress proxy run too).
 *
 * Step 2 asks the WHATWG parser for the canonical serialization: anything it
 * would rewrite (a host in another case, an IPv4 address in another form, a
 * dot segment, a character it percent-encodes, a missing path) is `shape`
 * there, before any later step reads the text. Go, which has no such parser,
 * spells the same rewrites out (internal/netguard), so both name one reason.
 */
export function cimdIdentity(value, rules) {
  const refuse = reason => ({ ok: false, reason })
  // 1. Size and characters.
  if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value, 'utf8') > CIMD_ID_MAX_BYTES || /[\s\p{Cc}]/u.test(value)) return refuse('shape')
  // 2. https, no query, fragment, userinfo or port, and its own canonical serialization.
  // `^` is named here because parsers have treated it differently over the
  // years (a forbidden host code point and a percent-encoded path character
  // only lately): the reason must not depend on the Node that runs this.
  if (!value.startsWith('https://') || value.includes('?') || value.includes('#') || value.includes('^')) return refuse('shape')
  let url
  try { url = new URL(value) } catch { return refuse('shape') }
  if (url.href !== value || url.username || url.password || url.port) return refuse('shape')
  const rest = value.slice('https://'.length)
  const slash = rest.indexOf('/')
  const host = rest.slice(0, slash), path = rest.slice(slash)
  // 3. A path other than the root.
  if (path === '/') return refuse('path_root')
  // 4. The host.
  const verdict = hostVerdict(host, rules)
  if (!verdict.ok) return verdict
  // 5. The path.
  if (path.length < 2 || path.length > 1024 || !/^[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/.test(path) || path.includes('//') ||
    path.split('/').some(segment => segment === '.' || segment === '..') || /%2e|%2f|%5c/i.test(path)) return refuse('path_chars')
  return { ok: true, host, path, registrable: verdict.registrable, shared_suffix: verdict.shared_suffix }
}

/**
 * The cache lifetime of an answer from its Cache-Control (§19.10): max-age
 * clamped to five minutes and a day, no-store and no-cache as five minutes,
 * a day when it says nothing usable.
 */
export function cacheTTL(header) {
  const directives = typeof header === 'string' ? header.toLowerCase().split(',').map(item => item.trim()) : []
  if (directives.some(item => item === 'no-store' || item === 'no-cache' || item.startsWith('no-cache='))) return CIMD_TTL_MIN_MS
  const maxAge = directives.map(item => /^max-age=(?:"(\d{1,10})"|(\d{1,10}))$/.exec(item)).find(Boolean)
  if (!maxAge) return CIMD_TTL_MAX_MS
  return Math.min(CIMD_TTL_MAX_MS, Math.max(CIMD_TTL_MIN_MS, Number(maxAge[1] ?? maxAge[2]) * 1000))
}

/**
 * §19.6 steps 1 to 4 on a fetched body for `identity` (cimdIdentity's):
 * `{ok: true, redirect_uris, ignored_uris, claimed_name, name_dropped}`, the
 * usable redirects only, or `{ok: false, code}` with the code the
 * `cimd_fetch` event carries (`json`, `client_id_mismatch`,
 * `no_usable_redirect`). Every other member is ignored: every client is
 * public, and a logo is never fetched.
 */
export function readDocument(body, clientID, identity) {
  let document
  try { document = JSON.parse(Buffer.from(body).toString('utf8')) } catch { return { ok: false, code: 'json' } }
  if (!document || typeof document !== 'object' || Array.isArray(document)) return { ok: false, code: 'json' }
  if (document.client_id !== clientID) return { ok: false, code: 'client_id_mismatch' }
  const list = document.redirect_uris
  if (!Array.isArray(list) || list.length < 1 || list.length > CIMD_REDIRECTS_MAX || list.some(value => typeof value !== 'string')) return { ok: false, code: 'no_usable_redirect' }
  const usable = [...new Set(list.filter(value => classifyRedirect(value, identity.host) !== null))]
  if (usable.length === 0) return { ok: false, code: 'no_usable_redirect' }
  return { ok: true, redirect_uris: usable, ignored_uris: list.length - list.filter(value => usable.includes(value)).length, ...claimedName(document.client_name) }
}

/**
 * `policy` is startReader's (`{mode: 'allowlist', hosts, cimd}` or `{mode:
 * 'any', …, fetcher, psl, shared, own}`); `limiter` and `log` are only read in
 * `any` mode, where `counters` gains `cimd_fetches` and `cimd_refusals`.
 */
export function createCIMD(state, { relay, now = Date.now, enabled, hosts, policy, limiter, log, counters = {} }) {
  // client_id (and, for network failures, registrable domain) -> when it may be asked for again; in memory only, bounded.
  const failed = new Map(), failedDomains = new Map()
  let inFlight = 0
  function remember(map, key) {
    if (map.size >= NEGATIVE_MAX) {
      for (const [id, until] of map) if (until <= now()) map.delete(id)
      if (map.size >= NEGATIVE_MAX) map.delete(map.keys().next().value)
    }
    map.set(key, now() + CIMD_NEGATIVE_TTL_MS)
    return null
  }
  const refusedRecently = (map, key) => (map.get(key) ?? 0) > now()

  /**
   * `any` mode: the client record for a client_id that passed cimdIdentity,
   * fetched or cached. Resolves to `{record}`, `{refused: true}` (an
   * unusable document, remembered for a minute) or `{busy: code}` (a
   * budget: `rate_limited`, or `cimd_busy` past four fetches in flight).
   */
  async function resolveAny(clientID, identity, { ip }) {
    const cached = state.clients.get(clientID)
    if (cached && cached.source === 'cimd' && cached.client_host !== undefined && now() - cached.cimd_fetched_at < cached.cimd_ttl_ms) { cached.last_used_at = now(); return { record: cached } }
    if (refusedRecently(failed, clientID) || refusedRecently(failedDomains, identity.registrable)) return { refused: true }
    for (const [name, key, perMinute] of [['cimd', ip, CIMD_FETCHES_PER_ADDRESS], ['cimd_all', 'all', CIMD_FETCHES_PER_MINUTE], ['cimd_domain', identity.registrable, CIMD_FETCHES_PER_DOMAIN]]) {
      if (!limiter.take(name, key, perMinute).ok) return { busy: 'rate_limited' }
    }
    if (inFlight >= CIMD_IN_FLIGHT) return { busy: 'cimd_busy' }
    inFlight++
    const started = now()
    let answer
    try { answer = await policy.fetcher.fetch({ host: identity.host, path: identity.path }) } catch { answer = { ok: false, code: 'proxy_refused', network: true } } finally { inFlight-- }
    let code = answer.ok ? 'ok' : answer.code
    const document = answer.ok ? readDocument(answer.body, clientID, identity) : null
    if (document && !document.ok) code = document.code
    counters.cimd_fetches = (counters.cimd_fetches ?? 0) + 1
    log?.event('cimd_fetch', { code, ms: Math.max(0, now() - started) })
    if (code !== 'ok') {
      counters.cimd_refusals = (counters.cimd_refusals ?? 0) + 1
      if (answer.network) remember(failedDomains, identity.registrable)
      remember(failed, clientID)
      return { refused: true }
    }
    if (!cached && !makeRoomUnknown(state, identity.registrable)) return { refused: true }
    failed.delete(clientID)
    const record = {
      client_id: clientID, source: 'cimd', client_host: identity.host, registrable: identity.registrable, shared_suffix: identity.shared_suffix,
      redirect_uris: document.redirect_uris, ignored_uris: document.ignored_uris, claimed_name: document.claimed_name, name_dropped: document.name_dropped,
      created_at: cached?.created_at ?? now(), last_used_at: now(), cimd_fetched_at: now(), cimd_ttl_ms: cacheTTL(answer.cacheControl),
      ...(cached?.authorized_at !== undefined ? { authorized_at: cached.authorized_at } : {}),
    }
    state.clients.set(clientID, record)
    return { record }
  }

  return {
    enabled,
    resolveAny,
    /**
     * The client record for a CIMD client_id, fetched or cached; null when it
     * is not a CIMD id or cannot be resolved. `allowFetch()` is consulted only
     * when a document is about to be fetched, so the caller can budget those.
     * (`allowlist` mode only.)
     */
    async resolve(clientID, { allowFetch = () => true } = {}) {
      if (!enabled) return null
      const url = cimdURL(clientID, hosts)
      if (!url) return null
      const cached = state.clients.get(clientID)
      if (cached && cached.source === 'cimd' && now() - cached.cimd_fetched_at < CIMD_TTL_MS) { cached.last_used_at = now(); return cached }
      if (refusedRecently(failed, clientID)) return null
      if (!allowFetch()) return null
      let body
      try { body = await relay.cimd(url.href) } catch { return remember(failed, clientID) }
      if (!body || body.length > CIMD_MAX_BYTES) return remember(failed, clientID)
      let document
      try { document = JSON.parse(body.toString('utf8')) } catch { return remember(failed, clientID) }
      if (!document || typeof document !== 'object' || Array.isArray(document) || document.client_id !== clientID) return remember(failed, clientID)
      let uris, host, loopback, name
      try {
        ({ uris, host, loopback } = validateRedirectURIs(document.redirect_uris, hosts, { vouchedBy: url.hostname.toLowerCase() }))
        name = validateClientName(document.client_name)
      } catch (error) { if (error instanceof RegistrationError) return remember(failed, clientID); throw error }
      if (!cached && !makeRoom(state, host)) return null
      failed.delete(clientID)
      const record = {
        client_id: clientID, redirect_uris: uris, client_name: name, redirect_host: host, loopback,
        grant_types: ['authorization_code', 'refresh_token'], source: 'cimd', created_at: cached?.created_at ?? now(),
        last_used_at: now(), cimd_fetched_at: now(), authorized_at: cached?.authorized_at,
      }
      state.clients.set(clientID, record)
      return record
    },
  }
}
