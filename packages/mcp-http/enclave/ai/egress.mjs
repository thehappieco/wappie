// The only way anything reaches an AI provider (docs/mcp-enclave.md §18.9):
// one request at a time, to a constant host and a constant route, over the
// enclave's own TLS (`/etc/hosts` sends each host to its own loopback
// address, which entrypoint.sh bridges to the parent's proxy for that host
// alone), with the provider's own key in its own header and nothing else.
//
// Every check is here, before a byte leaves (I1, I7): the host and route
// are AI_PROVIDERS', a query only on the two paged model lists and only with
// their parameters, in their order; a key goes only to its own provider's
// host; an OpenAI Responses body ends with `store: false` and never names a
// previous response. Anything else is refused inside the enclave and logged
// `ai_egress_refused`, with a code and nothing of the request.
//
// `transport` is the fetch the request goes through: the global one in the
// image, a stub in tests. The URL is always built here from the constant
// host, so a test replaces what answers, never where the request goes.
import { AI_ERROR_RULES, AI_GOOGLE_REQUEST_MAX_BYTES, AI_KEY_RE, AI_PROVIDERS, AI_QUERY_VALUE_MAX, AI_RESPONSE_MAX_BYTES, AI_CALL_TIMEOUT_MS, ANTHROPIC_VERSION } from './policy.mjs'

/**
 * A refusal or failure of the egress: `ai_egress_refused` (a check failed),
 * `timeout`, `network`, `aborted` or `response_too_large`. `sent` marks a
 * failure after the request was handed to the transport, with the request's
 * `bytesOut`: the provider may have received it whole and billed it
 * (§18.9's charges), since the parent relays the bytes and can stall or
 * drop the answer once the upload is done.
 */
export class EgressError extends Error {
  constructor(code, why, sent) {
    super(code); this.name = 'EgressError'; this.code = code
    if (why) this.why = why
    if (sent) { this.sent = true; this.bytesOut = sent.bytesOut }
  }
}

/** A provider key, as the enclave holds it: bound to its provider, so it can go nowhere else. */
export function providerKey(provider, secret) {
  if (!Object.hasOwn(AI_PROVIDERS, provider) || typeof secret !== 'string' || !AI_KEY_RE.test(secret)) throw new EgressError('ai_egress_refused', 'key')
  return Object.freeze({ provider, secret })
}

const googleModel = /^[a-z0-9][a-z0-9._-]{0,63}$/
/** The route of `provider` for `method` and `path`, or null. */
function routeOf(provider, method, path) {
  for (const route of AI_PROVIDERS[provider].routes) {
    if (route.method !== method) continue
    if (!route.path.includes('{model}')) { if (route.path === path) return route; continue }
    const [head, tail] = route.path.split('{model}')
    if (path.startsWith(head) && path.endsWith(tail) && googleModel.test(path.slice(head.length, path.length - tail.length))) return route
  }
  return null
}
/** `?a=b&c=d` for exactly the route's parameters, in order, or null when `query` does not fit them. */
function searchOf(route, query) {
  const given = query ?? []
  if (!route.query) return given.length ? null : ''
  if (!Array.isArray(given) || given.length < route.query.length - 1 || given.length > route.query.length) return null
  const parts = []
  for (let index = 0; index < given.length; index++) {
    const [name, fixed] = route.query[index]
    const [givenName, value] = given[index] ?? []
    if (givenName !== name || typeof value !== 'string') return null
    if (fixed !== null ? value !== fixed : (value.length < 1 || value.length > AI_QUERY_VALUE_MAX)) return null
    parts.push(`${name}=${encodeURIComponent(value)}`)
  }
  // A fixed parameter is never optional; the cursor is.
  if (given.length < route.query.length && route.query[given.length][1] !== null) return null
  return `?${parts.join('&')}`
}
/** The key's headers: its provider's, only (never in the URL). */
function authHeaders(key) {
  if (key.provider === 'anthropic') return { 'x-api-key': key.secret, 'anthropic-version': ANTHROPIC_VERSION }
  if (key.provider === 'openai') return { authorization: `Bearer ${key.secret}` }
  return { 'x-goog-api-key': key.secret }
}

/**
 * `request(provider, key, {method, path, query, body, form, signal, timeoutMs})`
 * → `{status, json, bytesOut}`. `body` is a JSON object, `form` a FormData
 * (OpenAI's transcription), neither on a GET. Throws EgressError.
 */
export function createEgress({ transport = globalThis.fetch, log } = {}) {
  function refuse(why) {
    log?.event('ai_egress_refused', { code: why })
    return new EgressError('ai_egress_refused', why)
  }
  async function request(provider, key, { method, path, query, body, form, signal, timeoutMs = AI_CALL_TIMEOUT_MS }) {
    if (!Object.hasOwn(AI_PROVIDERS, provider)) throw refuse('egress_host')
    if (!key || key.provider !== provider || typeof key.secret !== 'string' || !AI_KEY_RE.test(key.secret)) throw refuse('egress_key')
    const route = typeof path === 'string' ? routeOf(provider, method, path) : null
    if (!route) throw refuse('egress_route')
    const search = searchOf(route, query)
    if (search === null) throw refuse('egress_query')
    // Only these (§18.9): the encoding, the key's own header, and the body's type.
    const headers = { 'accept-encoding': 'identity', ...authHeaders(key) }
    let payload, bytesOut = 0
    if (method === 'GET') {
      if (body !== undefined || form !== undefined) throw refuse('egress_body')
    } else if (form !== undefined) {
      if (body !== undefined || !(form instanceof FormData) || !(provider === 'openai' && route.name === 'transcriptions')) throw refuse('egress_body')
      payload = form
      for (const [, value] of form) bytesOut += typeof value === 'string' ? Buffer.byteLength(value) : value.size
    } else {
      if (!body || typeof body !== 'object' || Array.isArray(body) || (provider === 'openai' && route.name === 'transcriptions')) throw refuse('egress_body')
      // OpenAI's Responses keep nothing: store is false, set last, and nothing chains to a stored response (§18.9).
      if (provider === 'openai' && route.name === 'responses') {
        const keys = Object.keys(body)
        if (keys.at(-1) !== 'store' || body.store !== false || Object.hasOwn(body, 'previous_response_id')) throw refuse('egress_store')
      }
      payload = Buffer.from(JSON.stringify(body))
      bytesOut = payload.length
      if (provider === 'google' && payload.length > AI_GOOGLE_REQUEST_MAX_BYTES) throw refuse('egress_size')
      headers['content-type'] = 'application/json'
    }
    const url = `https://${AI_PROVIDERS[provider].host}${path}${search}`
    const deadline = AbortSignal.timeout(timeoutMs)
    const both = signal ? AbortSignal.any([signal, deadline]) : deadline
    // From here the request is the transport's: any failure may come after the provider has it.
    const sent = { bytesOut }
    const failed = () => new EgressError(signal?.aborted ? 'aborted' : deadline.aborted ? 'timeout' : 'network', undefined, sent)
    let response
    try {
      response = await transport(url, { method, headers, body: payload, redirect: 'error', cache: 'no-store', credentials: 'omit', signal: both })
    } catch {
      throw failed()
    }
    const encoding = response.headers.get('content-encoding')
    const cancel = () => response.body?.cancel().catch(() => {})
    if (encoding !== null && encoding.trim().toLowerCase() !== 'identity') { await cancel(); throw new EgressError('network', undefined, sent) }
    const declared = Number(response.headers.get('content-length'))
    if (Number.isFinite(declared) && declared > AI_RESPONSE_MAX_BYTES) { await cancel(); throw new EgressError('response_too_large', undefined, sent) }
    const chunks = []
    let size = 0
    try {
      for await (const chunk of response.body ?? []) {
        size += chunk.length
        if (size > AI_RESPONSE_MAX_BYTES) { await cancel(); throw new EgressError('response_too_large', undefined, sent) }
        chunks.push(chunk)
      }
    } catch (error) {
      if (error instanceof EgressError) throw error
      throw failed()
    }
    const raw = Buffer.concat(chunks, size)
    let json = null
    try { json = JSON.parse(raw.toString('utf8')) } catch { json = null }
    raw.fill(0)
    return { status: response.status, json, bytesOut, route: route.name }
  }
  /**
   * Whether `provider`'s host answers over verified TLS (the health route's
   * reach, §18.16): its model list's route, with no key, no body and the
   * list's fixed parameters, any HTTP status meaning reached. Nothing of it
   * is kept but the boolean.
   */
  async function reach(provider, { timeoutMs = 5_000 } = {}) {
    const route = AI_PROVIDERS[provider]?.routes.find(item => item.name === 'models')
    if (!route) return false
    const search = route.query ? `?${route.query.filter(([, value]) => value !== null).map(([name, value]) => `${name}=${value}`).join('&')}` : ''
    try {
      const response = await transport(`https://${AI_PROVIDERS[provider].host}${route.path}${search}`, {
        method: 'GET', headers: { 'accept-encoding': 'identity' }, redirect: 'error', cache: 'no-store', credentials: 'omit', signal: AbortSignal.timeout(timeoutMs),
      })
      await response.body?.cancel().catch(() => {})
      return true
    } catch { return false }
  }
  return { request, reach }
}

/** What the error map reads of a provider's error body (policy.mjs AI_ERROR_RULES). */
export function errorFacts(provider, json) {
  const error = json && typeof json === 'object' && json.error && typeof json.error === 'object' ? json.error : {}
  const text = value => (typeof value === 'string' ? value : null)
  if (provider === 'google') {
    const details = Array.isArray(error.details) ? error.details : []
    return {
      type: text(error.status), code: null, param: null, message: text(error.message),
      reason: details.map(detail => text(detail?.reason)).filter(Boolean),
      quota: details.flatMap(detail => (Array.isArray(detail?.violations) ? detail.violations : [])).map(violation => text(violation?.quotaId)).filter(Boolean),
    }
  }
  return { type: text(error.type), code: text(error.code), param: text(error.param), message: text(error.message), reason: [], quota: [] }
}

const statusMatches = (rule, status) => (rule === '4xx' ? status >= 400 && status < 500 : rule === '5xx' ? status >= 500 && status < 600 : rule.includes(status))
/**
 * The error map's verdict for a non-200 answer: the first row of
 * AI_ERROR_RULES[provider] that matches, as its `result` ('retry' or a
 * code). An answer no row covers (a 3xx, say) is `ai_provider_failed`.
 */
export function classify(provider, route, status, facts) {
  return AI_ERROR_RULES[provider][ruleOf(provider, route, status, facts)]?.result ?? 'ai_provider_failed'
}

/** The index of the first row of AI_ERROR_RULES[provider] that matches, or -1. */
export function ruleOf(provider, route, status, facts) {
  for (const [index, rule] of AI_ERROR_RULES[provider].entries()) {
    if (!statusMatches(rule.status, status)) continue
    if (rule.route && rule.route !== route) continue
    if (rule.type && !rule.type.includes(facts.type)) continue
    if (rule.code && !rule.code.includes(facts.code)) continue
    if (rule.typeOrCode && !rule.typeOrCode.includes(facts.type) && !rule.typeOrCode.includes(facts.code)) continue
    if (rule.reason && !facts.reason.some(reason => rule.reason.includes(reason))) continue
    if (rule.param && !(typeof facts.param === 'string' && rule.param.test(facts.param))) continue
    if (rule.message && !(typeof facts.message === 'string' && rule.message.test(facts.message))) continue
    if (rule.quota && !facts.quota.some(id => rule.quota.test(id))) continue
    return index
  }
  return -1
}
