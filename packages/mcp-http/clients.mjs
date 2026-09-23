// RFC 7591 dynamic client registration. Registration is open (any caller can
// register), so the redirect allowlist, the caps and the TTLs are what bound
// it: a client somebody consented to (`authorized_at`) lives thirty days
// unused, one nobody ever consented to is a cache entry at best and lives an
// hour, and at a cap the oldest of those makes room rather than the caller
// being refused. The authentication method is assigned by this server: every
// client is public (`none`), whatever it asked for.
import { randomBytes } from 'node:crypto'

export const MAX_CLIENTS = 500
export const MAX_CLIENTS_PER_HOST = 200
export const CLIENT_IDLE_MS = 30 * 24 * 3_600_000
export const CLIENT_UNUSED_MS = 3_600_000
const grants = ['authorization_code', 'refresh_token']
const printable = /^[\x20-\x7E\u00A0-\uFFFF]{1,100}$/u

export class RegistrationError extends Error {
  constructor(code, description) { super(description); this.name = 'RegistrationError'; this.code = code; this.description = description }
}

/** The host of an acceptable redirect URI (https, default port, no userinfo or fragment, host in the allowlist), or null. */
export function redirectHost(value, hosts) {
  if (typeof value !== 'string' || value.length > 2048) return null
  let url
  try { url = new URL(value) } catch { return null }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.hash || url.href !== value) return null
  const host = url.hostname.toLowerCase()
  return hosts.includes(host) ? host : null
}

const loopbackHosts = ['127.0.0.1', '[::1]']

/**
 * A native app's loopback redirect (RFC 8252 §7.3): plain http to a loopback
 * IP literal, no userinfo, query or fragment. The app picks a free port when
 * the flow starts, so the port is not part of the identity: `{ host, path }`,
 * or null. `localhost` is never one — RFC 8252 §8.3 advises against it,
 * because a name can be made to resolve elsewhere and an IP literal cannot.
 */
export function loopbackRedirect(value) {
  if (typeof value !== 'string' || value.length > 2048) return null
  let url
  try { url = new URL(value) } catch { return null }
  if (url.protocol !== 'http:' || url.username || url.password || url.search || url.hash) return null
  return loopbackHosts.includes(url.hostname) ? { host: url.hostname, path: url.pathname } : null
}

/**
 * Validates a redirect_uris list the way both DCR and CIMD documents require.
 *
 * `vouchedBy` is set only for a CIMD document, and names the allowed host that
 * served it. Such a document may instead list loopback redirects for a native
 * app — ChatGPT's Codex does — because its identity is the https document, not
 * the redirect: the code goes to a listener on the consenting person's own
 * machine, and PKCE keeps it useless to anything but the app that started the
 * flow. The client's redirect_host is then the vouching host, which is what
 * the consent card names and what the API's allowlist checks. `localhost`
 * entries beside the IP literals are passed over, not fatal. Open registration
 * never gets loopback: nobody vouches for it.
 */
export function validateRedirectURIs(list, hosts, { vouchedBy } = {}) {
  if (!Array.isArray(list) || list.length < 1 || list.length > 5) throw new RegistrationError('invalid_redirect_uri', 'redirect_uris must list one to five HTTPS URIs')
  const uris = [], seen = new Set()
  let host, loopback = false, https = false
  for (const value of list) {
    const found = redirectHost(value, hosts)
    if (found) {
      if (host && host !== found) throw new RegistrationError('invalid_redirect_uri', 'redirect_uris must share one host')
      host = found; https = true
    } else if (vouchedBy && loopbackRedirect(value) && !new URL(value).port) {
      loopback = true
    } else if (vouchedBy && isLocalhost(value)) {
      continue
    } else {
      throw new RegistrationError('invalid_redirect_uri', 'redirect_uris must be HTTPS URIs on an allowed host')
    }
    if (!seen.has(value)) { seen.add(value); uris.push(value) }
  }
  if (loopback && https) throw new RegistrationError('invalid_redirect_uri', 'redirect_uris must be either HTTPS or loopback, not both')
  if (!uris.length) throw new RegistrationError('invalid_redirect_uri', 'redirect_uris must name a loopback IP literal, not localhost')
  return loopback ? { uris, host: vouchedBy, loopback } : { uris, host, loopback }
}
function isLocalhost(value) {
  try { const url = new URL(value); return url.protocol === 'http:' && url.hostname === 'localhost' } catch { return false }
}

/**
 * Whether `requested` is one of the client's redirect URIs. Exact, except for
 * a loopback client, whose registered URIs carry no port: RFC 8252 §7.3 says
 * any port must be accepted there, and the host and path must still match.
 */
export function redirectAllowed(client, requested) {
  if (typeof requested !== 'string') return false
  if (client.redirect_uris.includes(requested)) return true
  if (!client.loopback) return false
  const asked = loopbackRedirect(requested)
  return Boolean(asked) && client.redirect_uris.some(registered => {
    const known = loopbackRedirect(registered)
    return known && known.host === asked.host && known.path === asked.path
  })
}

export function validateClientName(value) {
  if (value === undefined) return 'MCP client'
  if (typeof value !== 'string' || !printable.test(value)) throw new RegistrationError('invalid_client_metadata', 'client_name must be up to 100 printable characters')
  return value
}

/**
 * Room for one more client on `host`: true under the caps, or once the oldest
 * client nobody consented to has been forgotten; false only when the cap is
 * made of consented clients.
 */
export function makeRoom(state, host) {
  for (;;) {
    const all = [...state.clients.values()], mine = all.filter(client => client.redirect_host === host)
    const crowded = mine.length >= MAX_CLIENTS_PER_HOST ? mine : all.length >= MAX_CLIENTS ? all : null
    if (!crowded) return true
    const evictable = crowded.filter(client => !client.authorized_at)
    if (evictable.length === 0) return false
    state.clients.delete(evictable.reduce((oldest, client) => (client.last_used_at < oldest.last_used_at ? client : oldest)).client_id)
  }
}

export function createClients(state, { now = Date.now, hosts }) {
  const live = () => [...state.clients.values()]
  return {
    /** Registers or returns the equivalent existing client; throws RegistrationError or {code:'too_many_clients'}. */
    register(metadata) {
      if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) throw new RegistrationError('invalid_client_metadata', 'the registration must be a JSON object')
      const { uris, host } = validateRedirectURIs(metadata.redirect_uris, hosts)
      const name = validateClientName(metadata.client_name)
      const requested = metadata.grant_types === undefined ? ['authorization_code'] : metadata.grant_types
      if (!Array.isArray(requested) || requested.length === 0 || requested.some(grant => !grants.includes(grant))) throw new RegistrationError('invalid_client_metadata', 'grant_types may only contain authorization_code and refresh_token')
      if (metadata.response_types !== undefined && (!Array.isArray(metadata.response_types) || metadata.response_types.join(' ') !== 'code')) throw new RegistrationError('invalid_client_metadata', 'response_types must be ["code"]')
      if (metadata.token_endpoint_auth_method !== undefined && typeof metadata.token_endpoint_auth_method !== 'string') throw new RegistrationError('invalid_client_metadata', 'token_endpoint_auth_method must be a string')
      const key = uris.slice().sort().join(' ')
      const existing = live().find(client => client.source === 'dcr' && client.client_name === name && client.redirect_uris.slice().sort().join(' ') === key)
      if (existing) { existing.last_used_at = now(); return existing }
      if (!makeRoom(state, host)) {
        const error = new RegistrationError('too_many_clients', 'client registrations are full; try again later')
        error.status = 429
        throw error
      }
      const record = {
        client_id: randomBytes(16).toString('base64url'), redirect_uris: uris, client_name: name, redirect_host: host,
        grant_types: [...new Set(['authorization_code', ...requested])], source: 'dcr', created_at: now(), last_used_at: now(),
      }
      state.clients.set(record.client_id, record)
      return record
    },
    /** The RFC 7591 response body for a stored client. */
    describe(record) {
      return {
        client_id: record.client_id, client_id_issued_at: Math.floor(record.created_at / 1000), client_name: record.client_name,
        redirect_uris: record.redirect_uris, token_endpoint_auth_method: 'none', grant_types: record.grant_types,
        response_types: ['code'], scope: 'wappie:read',
      }
    },
    /** Looks a registered client up and records the use that keeps it alive; CIMD clients go through cimd.resolve. */
    get(clientID) {
      const record = typeof clientID === 'string' ? state.clients.get(clientID) : undefined
      if (!record || record.source !== 'dcr') return undefined
      record.last_used_at = now()
      return record
    },
    /** Records that a user consented to this client, which is what earns it the long TTL. */
    consented(clientID) {
      const record = state.clients.get(clientID)
      if (record) record.authorized_at = now()
    },
    /** Forgets clients unused for thirty days, or an hour when nobody ever consented; returns whether anything changed. */
    sweep() {
      const at = now()
      let changed = false
      for (const [id, client] of state.clients) if (at - client.last_used_at > (client.authorized_at ? CLIENT_IDLE_MS : CLIENT_UNUSED_MS)) { state.clients.delete(id); changed = true }
      return changed
    },
  }
}
