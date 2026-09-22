// Client ID Metadata Documents (SEP-991): a client_id that is an HTTPS URL on
// an allowed host names a JSON document describing the client. The reader has
// no egress of its own, so the document is fetched through the Go relay
// (`GET /v1/mcp/internal/cimd`), which applies the same host allowlist, size
// and content-type rules. A good document is cached for a day, a bad or
// unreachable one is remembered for a minute so a stream of requests naming
// it does not become a stream of outbound fetches.
import { makeRoom, RegistrationError, validateClientName, validateRedirectURIs } from './clients.mjs'

export const CIMD_MAX_BYTES = 8 * 1024
export const CIMD_TTL_MS = 24 * 3_600_000
export const CIMD_NEGATIVE_TTL_MS = 60_000
const NEGATIVE_MAX = 1000

/** The document URL a client_id names, or null when it is not a CIMD identifier. */
export function cimdURL(clientID, hosts) {
  if (typeof clientID !== 'string' || clientID.length > 2048) return null
  let url
  try { url = new URL(clientID) } catch { return null }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash || url.pathname === '/' || url.href !== clientID) return null
  return hosts.includes(url.hostname.toLowerCase()) ? url : null
}

export function createCIMD(state, { relay, now = Date.now, enabled, hosts }) {
  // client_id -> when it may be asked for again; in memory only, bounded.
  const failed = new Map()
  function remember(clientID) {
    if (failed.size >= NEGATIVE_MAX) {
      for (const [id, until] of failed) if (until <= now()) failed.delete(id)
      if (failed.size >= NEGATIVE_MAX) failed.delete(failed.keys().next().value)
    }
    failed.set(clientID, now() + CIMD_NEGATIVE_TTL_MS)
    return null
  }
  return {
    enabled,
    /**
     * The client record for a CIMD client_id, fetched or cached; null when it
     * is not a CIMD id or cannot be resolved. `allowFetch()` is consulted only
     * when a document is about to be fetched, so the caller can budget those.
     */
    async resolve(clientID, { allowFetch = () => true } = {}) {
      if (!enabled) return null
      const url = cimdURL(clientID, hosts)
      if (!url) return null
      const cached = state.clients.get(clientID)
      if (cached && cached.source === 'cimd' && now() - cached.cimd_fetched_at < CIMD_TTL_MS) { cached.last_used_at = now(); return cached }
      if ((failed.get(clientID) ?? 0) > now()) return null
      if (!allowFetch()) return null
      let body
      try { body = await relay.cimd(url.href) } catch { return remember(clientID) }
      if (!body || body.length > CIMD_MAX_BYTES) return remember(clientID)
      let document
      try { document = JSON.parse(body.toString('utf8')) } catch { return remember(clientID) }
      if (!document || typeof document !== 'object' || Array.isArray(document) || document.client_id !== clientID) return remember(clientID)
      let uris, host, name
      try {
        ({ uris, host } = validateRedirectURIs(document.redirect_uris, hosts))
        name = validateClientName(document.client_name)
      } catch (error) { if (error instanceof RegistrationError) return remember(clientID); throw error }
      if (!cached && !makeRoom(state, host)) return null
      failed.delete(clientID)
      const record = {
        client_id: clientID, redirect_uris: uris, client_name: name, redirect_host: host,
        grant_types: ['authorization_code', 'refresh_token'], source: 'cimd', created_at: cached?.created_at ?? now(),
        last_used_at: now(), cimd_fetched_at: now(), authorized_at: cached?.authorized_at,
      }
      state.clients.set(clientID, record)
      return record
    },
  }
}
