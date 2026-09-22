// Bearer verification for /mcp, and the Go status check behind it. A token is
// valid only while its connection is `active` in Go; that answer is cached for
// a minute per connection, and a negative answer wipes the connection here.
import { OAuthError, OAuthErrorCode } from '@whatserver2/mcp/sdk'
import { RelayError } from './internal.mjs'

export const STATUS_TTL_MS = 60_000

export function createStatusCheck({ state, relay, now = Date.now, ttlMs = STATUS_TTL_MS, onWiped = async () => {} }) {
  const cache = new Map()
  return async function checkActive(id, { force = false } = {}) {
    const cached = cache.get(id)
    if (!force && cached && now() - cached.at < ttlMs) return true
    const status = await relay.status(id)
    if (!status || status.status !== 'active' || !(Date.parse(status.expires_at) > now())) {
      cache.delete(id)
      if (state.wipeConnection(id)) { await state.save(); await onWiped(id) }
      return false
    }
    cache.set(id, { at: now() })
    const connection = state.connections.get(id)
    // Go's expiry is authoritative; keep the local copy in step with it.
    if (connection && connection.expires_at !== status.expires_at) { connection.expires_at = status.expires_at; void state.save().catch(() => {}) }
    return true
  }
}

/** OAuthTokenVerifier for requireBearerAuth: hash lookup plus the connection check. */
export function createVerifier({ tokens, state, resource, checkActive }) {
  return {
    async verifyAccessToken(token) {
      const record = tokens.access(token)
      if (!record || !state.connections.has(record.connection_id)) throw new OAuthError(OAuthErrorCode.InvalidToken, 'Unknown or expired token')
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
