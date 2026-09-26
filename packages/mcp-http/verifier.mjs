// Bearer verification for /mcp, and the Go status check behind it. A token is
// valid only while its connection is `active` in Go; that answer is cached for
// a minute per connection, and a negative answer wipes the connection here.
//
// A content connection (the attested reader only, through the injected
// `content`) has a third answer, `reseal`: consented, but no key in this
// process. The bearer still authenticates (so tokens keep refreshing) and
// every tool answers `reconsent_required`; only `serve` is ever cached.
import { OAuthError, OAuthErrorCode } from '@whatserver2/mcp/sdk'
import { RelayError } from './internal.mjs'
import { boundTo } from './tokens.mjs'

export const STATUS_TTL_MS = 60_000

/**
 * `checkActive(id, {force})` resolves to 'serve', 'reseal' or false; both
 * strings are truthy, so a caller that only asks "may this family live" can
 * keep treating the answer as a boolean. `content.decide(record, status)`
 * owns the rules for content records (docs/mcp-enclave.md §15.8), and
 * `content.pending(id)` forces a fresh answer while a renewal waits to commit.
 */
/**
 * The deadline to keep for a connection given the one Go answers. Go's is
 * authoritative, except that a content connection never outlives what its
 * owner consented to (`consented_expires_at`, from the bundle): Go may bring
 * the deadline forward, never push it back.
 */
export function deadlineFor(connection, given) {
  const consented = connection?.kind === 'content' ? connection.consented_expires_at : undefined
  if (typeof consented !== 'string') return given
  const at = Date.parse(given), limit = Date.parse(consented)
  return Number.isFinite(at) && Number.isFinite(limit) && at > limit ? consented : given
}

export function createStatusCheck({ state, relay, now = Date.now, ttlMs = STATUS_TTL_MS, onWiped = async () => {}, content }) {
  const cache = new Map()
  return async function checkActive(id, { force = false } = {}) {
    const cached = cache.get(id)
    if (!force && cached && now() - cached.at < ttlMs && !content?.pending(id)) return 'serve'
    const status = await relay.status(id)
    const connection = state.connections.get(id)
    const deadline = status ? deadlineFor(connection, status.expires_at) : null
    const current = status && Date.parse(deadline) > now() ? status : null
    let answer
    if (connection?.kind === 'content') answer = content && current ? await content.decide(connection, current) : false
    else answer = current && current.status === 'active' && (current.kind === undefined || current.kind === 'metadata') ? 'serve' : false
    if (answer !== 'serve') cache.delete(id)
    if (!answer) {
      if (state.wipeConnection(id)) { await state.save(); await onWiped(id) }
      return false
    }
    if (answer === 'serve') cache.set(id, { at: now() })
    // Go's expiry is authoritative (within the consent); keep the local copy in step with it.
    if (connection && connection.expires_at !== deadline) { connection.expires_at = deadline; void state.save().catch(() => {}) }
    return answer
  }
}

/** OAuthTokenVerifier for requireBearerAuth: hash lookup plus the connection check. */
export function createVerifier({ tokens, state, resource, checkActive }) {
  return {
    async verifyAccessToken(token) {
      const record = tokens.access(token)
      const connection = record && state.connections.get(record.connection_id)
      // The token must be of the connection's own family and client, not merely name its id.
      if (!connection || !boundTo(record, connection)) throw new OAuthError(OAuthErrorCode.InvalidToken, 'Unknown or expired token')
      let active
      try { active = await checkActive(record.connection_id) } catch (error) {
        if (error instanceof RelayError) throw new OAuthError(OAuthErrorCode.ServerError, 'The archive is unavailable')
        throw error
      }
      if (!active) throw new OAuthError(OAuthErrorCode.InvalidToken, 'The connection is no longer active')
      return { token, clientId: record.client_id, scopes: ['wappie:read'], expiresAt: Math.floor(record.expires_at / 1000), resource: new URL(resource), extra: { connection_id: record.connection_id } }
    },
  }
}
