// The link with the Go server, in both directions: the relay client this
// reader uses and the `/internal/*` routes Go calls. The hosted reader talks
// to Go over loopback (`/v1/mcp/internal/*`, a shared bearer secret, and a
// loopback peer with no X-Forwarded-For on the inbound side, so nothing
// proxied from the public side can ever reach these routes). The enclave
// reader injects its own inbound guard and a signing relay (enclave/relay.mjs)
// that reuses the client below with HMAC headers instead of the bearer.
import { timingSafeEqual } from 'node:crypto'
import { AttestationError, decodeNonce } from './attestation.mjs'
import { acceptBundle, descriptor, LinkError } from './link.mjs'
import { isLoopback } from './limits.mjs'

const MAX_RELAY_BODY = 64 * 1024

export class RelayError extends Error {
  constructor(code, status = 0) { super(code); this.name = 'RelayError'; this.code = code; this.status = status }
}

/**
 * The relay client. `prefix` is the Go route family; `headersFor(method,
 * target, body)` replaces the bearer header when given (the enclave signs
 * every request). `call` and `body` are exposed for the enclave's state routes.
 */
export function createRelay({ archive, secret, fetch = globalThis.fetch, timeoutMs = 5000, prefix = '/v1/mcp/internal', headersFor }) {
  const base = archive.replace(/\/$/, '')
  async function call(method, path, query, { body: payload, timeout = timeoutMs, headers: extra = {} } = {}) {
    const url = new URL(base + prefix + path)
    if (query) for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value)
    const bytes = payload ?? Buffer.alloc(0)
    // The request-target exactly as it goes on the request line: what an HMAC signs.
    const auth = headersFor ? headersFor(method, url.pathname + url.search, bytes) : { authorization: `Bearer ${secret}` }
    try {
      return await fetch(url, { method, headers: { ...auth, accept: 'application/json', ...extra }, body: payload, redirect: 'error', signal: AbortSignal.timeout(timeout) })
    } catch { throw new RelayError('relay_unavailable') }
  }
  async function body(response, limit = MAX_RELAY_BODY) {
    const declared = Number(response.headers.get('content-length'))
    if (Number.isFinite(declared) && declared > limit) { await response.body?.cancel().catch(() => {}); throw new RelayError('relay_failed', response.status) }
    const chunks = []
    let size = 0
    try {
      for await (const chunk of response.body ?? []) {
        size += chunk.length
        if (size > limit) throw new RelayError('relay_failed', response.status)
        chunks.push(chunk)
      }
    } catch (error) { if (error instanceof RelayError) throw error; throw new RelayError('relay_unavailable', response.status) }
    return Buffer.concat(chunks, size)
  }
  return {
    call, body,
    /** `{status, expires_at}` of a connection, or null when Go does not know it. */
    async status(id) {
      const response = await call('GET', `/connections/${encodeURIComponent(id)}`)
      const data = await body(response)
      if (response.status === 404) return null
      if (response.status !== 200) throw new RelayError('relay_failed', response.status)
      let parsed
      try { parsed = JSON.parse(data.toString('utf8')) } catch { throw new RelayError('relay_failed', response.status) }
      if (!parsed || typeof parsed.status !== 'string' || typeof parsed.expires_at !== 'string') throw new RelayError('relay_failed', response.status)
      return { status: parsed.status, expires_at: parsed.expires_at }
    },
    async activate(id) {
      const response = await call('POST', `/connections/${encodeURIComponent(id)}/activate`)
      await body(response)
      if (response.status === 204) return true
      throw new RelayError(response.status === 409 ? 'connection_state' : response.status === 404 ? 'not_found' : 'relay_failed', response.status)
    },
    /** Best effort: the reader has already forgotten the connection when this is called. */
    async revoke(id) {
      try {
        const response = await call('POST', `/connections/${encodeURIComponent(id)}/revoke`)
        await body(response)
        return response.status === 204
      } catch { return false }
    },
    /** The bytes of a client metadata document fetched by Go, or null. */
    async cimd(url) {
      const response = await call('GET', '/cimd', { url })
      const data = await body(response)
      if (response.status !== 200 || !(response.headers.get('content-type') ?? '').startsWith('application/json')) return null
      return data
    },
  }
}

const json = (value, status = 200) => Response.json(value, { status, headers: { 'Cache-Control': 'no-store' } })

/** Only Go on this host may call these; anything else sees a 404. */
export function internalGuard(request, info, secret) {
  if (!isLoopback(info.remoteAddress) || request.headers.get('x-forwarded-for') !== null) return json({ code: 'not_found' }, 404)
  const header = request.headers.get('authorization') ?? ''
  const given = Buffer.from(header.startsWith('Bearer ') ? header.slice(7) : ''), expected = Buffer.from(secret)
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return json({ code: 'unauthorized' }, 401)
  return undefined
}

/** Documents per consent request (prepare answers 429 after that). */
export const MAX_PREPARES = 10
const noContent = () => new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } })
const ciphertextShape = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
const MAX_CIPHERTEXT = 6144

/** A JSON object body with exactly `keys`, or null. */
async function strictBody(request, keys) {
  let body
  try { body = await request.json() } catch { return null }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null
  const names = Object.keys(body)
  return names.length === keys.length && keys.every(key => names.includes(key)) ? body : null
}

/** Standard padded base64 of 1 to 6144 bytes (a KMS CiphertextBlob), or null. */
export function decodeCiphertext(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(MAX_CIPHERTEXT / 3) * 4 || !ciphertextShape.test(value)) return null
  const bytes = Buffer.from(value, 'base64')
  return bytes.length >= 1 && bytes.length <= MAX_CIPHERTEXT && bytes.toString('base64') === value ? bytes : null
}

/**
 * The routes Go calls. Everything past the hosted reader's set is optional and
 * present only when injected (the enclave):
 * - `auth(request, info)` replaces the loopback guard;
 * - `health()` is the healthz body;
 * - `prepare(pending, nonce)` adds `POST /internal/requests/{id}/prepare`;
 * - `rotateSecret(ciphertext)` adds `POST /internal/relay-secret`.
 */
export function internalRoutes({ state, secret, now, pendingFor, auth, health, prepare, rotateSecret }) {
  const guard = auth ?? ((request, info) => internalGuard(request, info, secret))
  return async (request, info, meta) => {
    const path = new URL(request.url).pathname
    const rejected = await guard(request, info)
    if (rejected) { meta.route = 'internal'; meta.code = rejected.headers.get('x-wappie-code') ?? (rejected.status === 401 ? 'unauthorized' : rejected.status === 503 ? 'unavailable' : 'not_found'); return withoutCode(rejected) }
    let match
    if (path === '/internal/healthz' && request.method === 'GET') { meta.route = 'GET /internal/healthz'; return json(health ? health() : { ok: true }) }
    if (path === '/internal/relay-secret' && request.method === 'POST' && rotateSecret) {
      meta.route = 'POST /internal/relay-secret'
      const body = await strictBody(request, ['ciphertext'])
      const ciphertext = body && decodeCiphertext(body.ciphertext)
      if (!ciphertext) { meta.code = 'bad_request'; return json({ code: 'bad_request' }, 400) }
      try { await rotateSecret(ciphertext) } catch (error) {
        meta.code = error?.code === 'bad_request' ? 'bad_request' : 'kms_failed'
        return json({ code: meta.code }, meta.code === 'bad_request' ? 400 : 502)
      }
      return noContent()
    }
    if ((match = /^\/internal\/requests\/([A-Za-z0-9_-]{22})$/.exec(path)) && request.method === 'GET') {
      meta.route = 'GET /internal/requests/{id}'
      const pending = pendingFor(match[1])
      if (!pending) { meta.code = 'not_found'; return json({ code: 'not_found' }, 404) }
      meta.client = pending.client_id
      return json(descriptor(pending, state))
    }
    if ((match = /^\/internal\/requests\/([A-Za-z0-9_-]{22})\/prepare$/.exec(path)) && request.method === 'POST' && prepare) {
      meta.route = 'POST /internal/requests/{id}/prepare'
      const body = await strictBody(request, ['nonce'])
      const nonce = body && decodeNonce(body.nonce)
      const pending = pendingFor(match[1])
      if (!pending) { meta.code = 'not_found'; return json({ code: 'not_found' }, 404) }
      meta.client = pending.client_id
      if (!nonce) { meta.code = 'bad_request'; return json({ code: 'bad_request' }, 400) }
      // Ten documents per request: enough for a console that reloads, few
      // enough that a request id is not an oracle for fresh NSM signatures.
      if (++pending.prepares > MAX_PREPARES) { meta.code = 'too_many_prepares'; return json({ code: 'too_many_prepares' }, 429) }
      try { return json(await prepare(pending, nonce)) } catch (error) {
        if (error instanceof AttestationError) { meta.code = error.code; return json({ code: error.code }, error.status) }
        throw error
      }
    }
    if ((match = /^\/internal\/requests\/([A-Za-z0-9_-]{22})\/bundle$/.exec(path)) && request.method === 'POST') {
      meta.route = 'POST /internal/requests/{id}/bundle'
      const pending = pendingFor(match[1])
      if (!pending) { meta.code = 'not_found'; return json({ code: 'not_found' }, 404) }
      meta.client = pending.client_id
      let body
      try { body = await request.json() } catch { meta.code = 'bad_request'; return json({ code: 'bad_request' }, 400) }
      try {
        const { connection_id } = await acceptBundle(state, pending, body, { now })
        meta.connection = connection_id
        return noContent()
      } catch (error) {
        if (error instanceof LinkError) { meta.code = error.code; return json({ code: error.code }, error.status) }
        throw error
      }
    }
    if ((match = /^\/internal\/connections\/([0-9a-f-]{36})\/revoke$/.exec(path)) && request.method === 'POST') {
      meta.route = 'POST /internal/connections/{id}/revoke'
      meta.connection = match[1]
      if (state.wipeConnection(match[1].toLowerCase())) await state.save()
      return noContent()
    }
    meta.route = 'internal'; meta.code = 'not_found'
    return json({ code: 'not_found' }, 404)
  }
}

/** A guard may tag its refusal with the code the log should carry; the header never leaves. */
function withoutCode(response) {
  if (!response.headers.has('x-wappie-code')) return response
  const headers = new Headers(response.headers)
  headers.delete('x-wappie-code')
  return new Response(response.body, { status: response.status, headers })
}
