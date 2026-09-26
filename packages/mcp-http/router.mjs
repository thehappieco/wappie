// Per-route validation, deliberately not global: the Host check guards every
// public route, an Origin header is refused on the JSON-RPC endpoint (no
// browser ever calls it), the consent completion demands the console's Origin
// as its CSRF proof, and the server-to-server OAuth endpoints never look at
// Origin at all. The internal routes have their own guard.
//
// In the enclave the router serves two listeners (`info.listener`): the public
// one never reaches /internal, the internal one reaches nothing else, and each
// demands its exact Host. The PROXY v2 source is the client address there, so
// X-Forwarded-For is never consulted.
import { createMcpHandler, hostHeaderValidationResponse, requireBearerAuth } from '@whatserver2/mcp/sdk'
import { createServer } from '@whatserver2/mcp'
import { AttestationError, decodeNonce } from './attestation.mjs'
import { clientIP, ipKey } from './limits.mjs'
import { configFor, providerFor } from './provider.mjs'

export const BODY_LIMITS = { mcp: 1024 * 1024, link: 96 * 1024, as: 16 * 1024 }
export const MCP_PER_MINUTE = 60
export const ATTESTATION_PER_MINUTE = 10

/** The body cap for a request, decided before any byte is read. */
export function bodyLimitFor(path) {
  if (path === '/mcp') return BODY_LIMITS.mcp
  if (path.startsWith('/internal/')) return BODY_LIMITS.link
  return BODY_LIMITS.as
}

const rpcError = (status, message, extra = {}) => Response.json({ jsonrpc: '2.0', error: { code: -32000, message }, id: null }, { status, headers: { 'Cache-Control': 'no-store', ...extra } })
const notFound = () => Response.json({ code: 'not_found' }, { status: 404, headers: { 'Cache-Control': 'no-store' } })
const refuse = (status, code) => Response.json({ code }, { status, headers: { 'Cache-Control': 'no-store' } })

/**
 * `listenerHosts` ({public, internal}) turns on the enclave's two-listener
 * mode with exact Host checks; `attestation({nonce})` adds the public
 * `GET /attestation` route; `trustForwarded` false ignores X-Forwarded-For;
 * `content.serverFor(record)` supplies the configuration and provider of a
 * content connection. Without `content` such a record is never served: the
 * metadata configuration and provider are the only ones this file builds.
 */
export function createRouter({ state, metadata, as, internal, verifier, limiter, log, archive, publicHost, listenerHosts, attestation, trustForwarded = true, content }) {
  const gate = requireBearerAuth({ verifier, requiredScopes: ['wappie:read'], resourceMetadataUrl: metadata.resourceMetadataUrl })
  const handler = createMcpHandler(ctx => {
    const connection = state.connections.get(ctx.authInfo?.extra?.connection_id)
    if (!connection) throw new Error('unknown connection')
    if (connection.kind === 'content') {
      if (!content) throw new Error('content connection without a content reader')
      const { config, provider } = content.serverFor(connection)
      return createServer(config, provider)
    }
    return createServer(configFor(connection, archive), providerFor(connection))
  }, { responseMode: 'json', keepAliveMs: 0, onerror: () => log.event('mcp_error') })
  return {
    close: () => handler.close(),
    async handle(request, info, meta) {
      const path = new URL(request.url).pathname
      const internalPath = path === '/internal' || path.startsWith('/internal/')
      if (listenerHosts) {
        const listener = info.listener === 'internal' ? 'internal' : 'public'
        if (internalPath !== (listener === 'internal')) { meta.route = listener === 'internal' ? 'unmatched' : 'internal'; meta.code = 'not_found'; return notFound() }
        if (request.headers.get('host') !== listenerHosts[listener]) { meta.route = listener; meta.code = 'invalid_host'; return refuse(403, 'invalid_host') }
        if (listener === 'internal') return internal(request, info, meta)
      } else {
        if (internalPath) return internal(request, info, meta)
        const badHost = hostHeaderValidationResponse(request, [publicHost])
        if (badHost) { meta.route = 'public'; meta.code = 'invalid_host'; return badHost }
      }
      const served = metadata.respond(request)
      if (served) { meta.route = `${request.method} /.well-known`; return served }
      const ip = ipKey(clientIP(info.remoteAddress, trustForwarded ? request.headers.get('x-forwarded-for') : null))
      if (path === '/attestation' && attestation) {
        meta.route = `${request.method} /attestation`
        if (request.method !== 'GET') return refuse(405, 'method_not_allowed')
        const taken = limiter.take('attestation', ip, ATTESTATION_PER_MINUTE)
        if (!taken.ok) { meta.code = 'rate_limited'; return Response.json({ code: 'rate_limited' }, { status: 429, headers: { 'Cache-Control': 'no-store', 'Retry-After': String(taken.retryAfter) } }) }
        const params = new URL(request.url).searchParams
        const nonce = params.getAll('nonce').length === 1 && [...params.keys()].length === 1 ? decodeNonce(params.get('nonce')) : null
        if (!nonce) { meta.code = 'bad_request'; return refuse(400, 'bad_request') }
        try { return Response.json({ attestation: await attestation({ nonce }) }, { headers: { 'Cache-Control': 'no-store' } }) } catch (error) {
          if (error instanceof AttestationError) { meta.code = error.code; return refuse(error.status, error.code) }
          throw error
        }
      }
      switch (path) {
        case '/mcp': {
          meta.route = `${request.method} /mcp`
          if (request.method !== 'POST') return rpcError(405, 'Method not allowed.', { Allow: 'POST' })
          if (request.headers.get('origin') !== null) { meta.code = 'origin_rejected'; return rpcError(403, 'Origin not allowed.') }
          const auth = await gate(request)
          if (auth instanceof Response) { meta.code = auth.status === 401 ? 'unauthorized' : auth.status === 403 ? 'insufficient_scope' : 'auth_failed'; return auth }
          meta.connection = auth.extra.connection_id
          meta.client = auth.clientId
          const taken = limiter.take('mcp', auth.extra.connection_id, MCP_PER_MINUTE)
          if (!taken.ok) { meta.code = 'rate_limited'; return rpcError(429, 'Too many requests.', { 'Retry-After': String(taken.retryAfter) }) }
          return handler.fetch(request, { authInfo: auth })
        }
        case '/mcp/authorize': meta.route = `${request.method} /mcp/authorize`; return as.authorize(request, ip, meta)
        case '/mcp/authorize/complete': meta.route = `${request.method} /mcp/authorize/complete`; return as.complete(request, ip, meta)
        case '/mcp/token': meta.route = `${request.method} /mcp/token`; return as.token(request, ip, meta)
        case '/mcp/register': meta.route = `${request.method} /mcp/register`; return as.register(request, ip, meta)
        case '/mcp/revoke': meta.route = `${request.method} /mcp/revoke`; return as.revoke(request, meta)
        default: meta.route = 'unmatched'; meta.code = 'not_found'; return notFound()
      }
    },
  }
}
