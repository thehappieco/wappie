// The loopback link with the Go server, in both directions: the relay client
// this reader uses (`/v1/mcp/internal/*`) and the `/internal/*` routes Go
// calls. Both sides share one secret, and the inbound side additionally
// requires a loopback peer with no X-Forwarded-For, so nothing proxied from
// the public side can ever reach these routes.
import { timingSafeEqual } from 'node:crypto'
import { acceptBundle, descriptor, LinkError } from './link.mjs'
import { isLoopback } from './limits.mjs'

const MAX_RELAY_BODY = 64 * 1024

export class RelayError extends Error {
  constructor(code, status = 0) { super(code); this.name = 'RelayError'; this.code = code; this.status = status }
}

export function createRelay({ archive, secret, fetch = globalThis.fetch, timeoutMs = 5000 }) {
  const base = archive.replace(/\/$/, '')
  async function call(method, path, query) {
    const url = new URL(base + path)
    if (query) for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value)
    try {
      return await fetch(url, { method, headers: { authorization: `Bearer ${secret}`, accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) })
    } catch { throw new RelayError('relay_unavailable') }
  }
  async function body(response) {
    const data = Buffer.from(await response.arrayBuffer())
    if (data.length > MAX_RELAY_BODY) throw new RelayError('relay_failed', response.status)
    return data
  }
  return {
    /** `{status, expires_at}` of a connection, or null when Go does not know it. */
    async status(id) {
      const response = await call('GET', `/v1/mcp/internal/connections/${encodeURIComponent(id)}`)
      const data = await body(response)
      if (response.status === 404) return null
      if (response.status !== 200) throw new RelayError('relay_failed', response.status)
      let parsed
      try { parsed = JSON.parse(data.toString('utf8')) } catch { throw new RelayError('relay_failed', response.status) }
      if (!parsed || typeof parsed.status !== 'string' || typeof parsed.expires_at !== 'string') throw new RelayError('relay_failed', response.status)
      return { status: parsed.status, expires_at: parsed.expires_at }
    },
    async activate(id) {
      const response = await call('POST', `/v1/mcp/internal/connections/${encodeURIComponent(id)}/activate`)
      await body(response)
      if (response.status === 204) return true
      throw new RelayError(response.status === 409 ? 'connection_state' : response.status === 404 ? 'not_found' : 'relay_failed', response.status)
    },
    /** Best effort: the reader has already forgotten the connection when this is called. */
    async revoke(id) {
      try {
        const response = await call('POST', `/v1/mcp/internal/connections/${encodeURIComponent(id)}/revoke`)
        await body(response)
        return response.status === 204
      } catch { return false }
    },
    /** The bytes of a client metadata document fetched by Go, or null. */
    async cimd(url) {
      const response = await call('GET', '/v1/mcp/internal/cimd', { url })
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

export function internalRoutes({ state, secret, now, pendingFor }) {
  return async (request, info, meta) => {
    const path = new URL(request.url).pathname
    const rejected = internalGuard(request, info, secret)
    if (rejected) { meta.route = 'internal'; meta.code = rejected.status === 401 ? 'unauthorized' : 'not_found'; return rejected }
    let match
    if (path === '/internal/healthz' && request.method === 'GET') { meta.route = 'GET /internal/healthz'; return json({ ok: true }) }
    if ((match = /^\/internal\/requests\/([A-Za-z0-9_-]{22})$/.exec(path)) && request.method === 'GET') {
      meta.route = 'GET /internal/requests/{id}'
      const pending = pendingFor(match[1])
      if (!pending) { meta.code = 'not_found'; return json({ code: 'not_found' }, 404) }
      meta.client = pending.client_id
      return json(descriptor(pending, state))
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
        return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } })
      } catch (error) {
        if (error instanceof LinkError) { meta.code = error.code; return json({ code: error.code }, error.status) }
        throw error
      }
    }
    if ((match = /^\/internal\/connections\/([0-9a-f-]{36})\/revoke$/.exec(path)) && request.method === 'POST') {
      meta.route = 'POST /internal/connections/{id}/revoke'
      meta.connection = match[1]
      if (state.wipeConnection(match[1].toLowerCase())) await state.save()
      return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } })
    }
    meta.route = 'internal'; meta.code = 'not_found'
    return json({ code: 'not_found' }, 404)
  }
}
