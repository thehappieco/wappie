// Authorization codes, access tokens and rotating refresh tokens. Only sha256
// hashes are stored; a token is `wmcp_<c|a|r>_` plus 32 random bytes in
// base64url. Every /token failure is the same `invalid_grant` after the same
// amount of work, so nothing about which check failed leaks.
//
// From reader 0.6.0 a console connection token (docs/mcp-enclave.md §19.18) is
// a fourth kind, `key`: `wmcp_k_`, 32 random bytes in base64url and six base62
// characters of a CRC-32 checksum, minted in the person's browser. It is a
// bearer for /mcp with no refresh and no rotation, and it is never a grant
// /mcp/token takes; only its hash is kept, in the sealed state.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

export const ACCESS_TTL_MS = 15 * 60_000
export const REFRESH_IDLE_MS = 30 * 24 * 3_600_000
/** A content connection's refresh token dies after a week unused (metadata keeps thirty days). */
export const CONTENT_REFRESH_IDLE_MS = 7 * 24 * 3_600_000
/** The one death Go is told the cause of: someone may hold a copy of a token. */
export const REUSE_DETECTED = 'reuse_detected'
export const CODE_TTL_MS = 60_000
export const ROTATION_GRACE_MS = 30_000
const prefixes = { code: 'wmcp_c_', access: 'wmcp_a_', refresh: 'wmcp_r_' }
const shapes = Object.fromEntries(Object.entries(prefixes).map(([kind, prefix]) => [kind, new RegExp(`^${prefix}[A-Za-z0-9_-]{43}$`)]))
const verifierShape = /^[A-Za-z0-9._~-]{43,128}$/
/** A console connection token's prefix and shape (§19.18). */
export const KEY_PREFIX = 'wmcp_k_'
const keyShape = /^wmcp_k_[A-Za-z0-9_-]{43}[0-9A-Za-z]{6}$/
const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
  return c >>> 0
})
/** CRC-32 (IEEE 802.3, as zlib computes it) of `bytes`, as an unsigned integer. */
export function crc32(bytes) {
  let c = 0xffffffff
  for (const byte of bytes) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}
/**
 * The checksum a console token ends with (§19.18 step 3): the CRC-32 of the
 * UTF-8 of everything before it in base62, most significant digit first,
 * left-padded with `0` to six characters. It lets a secret scanner tell a
 * real token from noise offline; it is no secret and proves nothing.
 */
export function keyChecksum(text) {
  let value = crc32(Buffer.from(text, 'utf8')), out = ''
  for (let digit = 0; digit < 6; digit++) { out = BASE62[value % 62] + out; value = Math.floor(value / 62) }
  return out
}

export class GrantError extends Error {
  constructor(code = 'invalid_grant') { super(code); this.name = 'GrantError'; this.code = code }
}
export const mint = kind => prefixes[kind] + randomBytes(32).toString('base64url')
export const hash = value => createHash('sha256').update(value).digest('hex')
export const wellFormed = (kind, value) => typeof value === 'string' &&
  (kind === 'key' ? keyShape.test(value) && keyChecksum(value.slice(0, -6)) === value.slice(-6) : shapes[kind].test(value))
/**
 * Whether a token (or code) record belongs to the connection record it names:
 * the family the connection's code exchange started and the client it was
 * consented for. A connection id is only a name; a record replaced under it
 * never inherits the tokens of the one before.
 */
export const boundTo = (token, connection) => typeof connection.family_id === 'string' && token.family_id === connection.family_id && token.client_id === connection.client_id

function sameString(a, b) {
  const left = Buffer.from(String(a)), right = Buffer.from(String(b))
  return left.length === right.length && timingSafeEqual(left, right)
}
/** RFC 7636 S256: the verifier hashes to the challenge the authorization request carried. */
export function verifierMatches(codeVerifier, codeChallenge) {
  if (typeof codeVerifier !== 'string' || !verifierShape.test(codeVerifier)) return false
  return sameString(createHash('sha256').update(codeVerifier).digest('base64url'), codeChallenge)
}

/**
 * `checkActive(connectionId, {force})` asks Go whether the connection may still
 * be served (the caller caches). `onFamilyRevoked(connectionId, reason)` lets
 * the caller tell Go; the local wipe happens here. `reason` is
 * 'reuse_detected' for a replayed code, a rotated refresh token presented past
 * the grace window and a refresh from another client, and undefined for every
 * other death (RFC 7009, idle expiry, an inactive connection).
 */
/**
 * How long a connection's refresh token lives unused: its tier's
 * `idle_days` for its kind under reader 0.6.0 (docs/mcp-enclave.md §19.19,
 * with `limits` the image's CLIENT_LIMITS), else 0.5.0's thirty days for
 * metadata and a week for content.
 */
export function idleFor(connection, limits) {
  const kind = connection.kind === 'content' ? 'content' : 'metadata'
  const days = limits && connection.limits_tier ? limits[connection.limits_tier]?.idle_days?.[kind] : undefined
  if (Number.isSafeInteger(days) && days > 0) return days * 24 * 3_600_000
  return kind === 'content' ? CONTENT_REFRESH_IDLE_MS : REFRESH_IDLE_MS
}

export function createTokens(state, { now = Date.now, checkActive, onFamilyRevoked = async () => {}, limits }) {
  const rotating = new Map()
  // family -> the pair its latest rotation issued, for the grace window only.
  // Held in memory on purpose: the persisted records carry hashes and nothing
  // else, so a copy of the state directory never yields a usable token.
  const successors = new Map()
  const seconds = ms => Math.max(1, Math.floor(ms / 1000))
  async function killFamily(family, reason) {
    successors.delete(family)
    const connection = state.revokeFamily(family)
    void state.save().catch(() => {})
    if (connection) await onFamilyRevoked(connection, reason)
  }
  function pairFor(connection, client, family) {
    // A content connection's consent bounds its tokens even before a status answer has clamped expires_at.
    const at = now(), absolute = Math.min(Date.parse(connection.expires_at), Date.parse(connection.consented_expires_at ?? connection.expires_at))
    const access = mint('access'), refresh = mint('refresh')
    const idle = idleFor(connection, limits)
    const accessUntil = Math.min(at + ACCESS_TTL_MS, absolute), refreshUntil = Math.min(at + idle, absolute)
    state.tokens.set(hash(access), { hash: hash(access), kind: 'access', connection_id: connection.connection_id, client_id: client, family_id: family, expires_at: accessUntil })
    state.tokens.set(hash(refresh), { hash: hash(refresh), kind: 'refresh', connection_id: connection.connection_id, client_id: client, family_id: family, expires_at: refreshUntil, issued_at: at })
    return { access_token: access, token_type: 'Bearer', expires_in: seconds(accessUntil - at), refresh_token: refresh, scope: 'wappie:read' }
  }
  return {
    /** Mints the single-use code the consent redirect carries back to the client. */
    issueCode({ client_id, redirect_uri, code_challenge, resource, connection_id }) {
      const code = mint('code')
      state.codes.set(hash(code), { client_id, redirect_uri, code_challenge, resource, connection_id, expires_at: now() + CODE_TTL_MS })
      return code
    },
    async exchangeCode({ code, client_id, code_verifier, redirect_uri, resource }) {
      const record = wellFormed('code', code) ? state.codes.get(hash(code)) : undefined
      const fresh = record && record.expires_at > now()
      // Same work on every path; the comparisons below run against a decoy when nothing matched.
      const target = fresh ? record : { client_id: '', redirect_uri: '', resource: '', code_challenge: mint('access').slice(7) }
      const ok = verifierMatches(code_verifier, target.code_challenge) & sameString(client_id, target.client_id) &
        sameString(redirect_uri, target.redirect_uri) & sameString(resource, target.resource)
      if (record && record.used) {
        // A replayed code means the first exchange may have gone to an attacker: nothing issued from it survives.
        state.codes.delete(hash(code))
        await killFamily(record.family_id, REUSE_DETECTED)
        throw new GrantError()
      }
      if (!fresh || !ok) { if (record) state.codes.delete(hash(code)); throw new GrantError() }
      const connection = state.connections.get(record.connection_id)
      // One exchange per connection, by the client it was consented for: a
      // connection that already has a family never starts a second one.
      if (!connection || connection.family_id !== undefined || !sameString(record.client_id, connection.client_id)) { state.codes.delete(hash(code)); throw new GrantError() }
      const family = randomBytes(16).toString('base64url')
      record.used = true; record.family_id = family
      connection.family_id = family
      const pair = pairFor(connection, client_id, family)
      void state.save().catch(() => {})
      return pair
    },
    /**
     * Rotation with a grace window, serialised per family: the first request
     * for a token rotates it, a second presentation within 30 s receives the
     * identical successor pair (a retried request whose response was lost, or
     * two clients refreshing at once), anything later kills the family. The
     * pair lives only in memory, so after a restart a second presentation is
     * indistinguishable from a replay and is treated as one.
     */
    async refresh({ refresh_token, client_id }) {
      const record = wellFormed('refresh', refresh_token) ? state.tokens.get(hash(refresh_token)) : undefined
      if (!record || record.kind !== 'refresh') { verifierMatches(mint('access').slice(7).repeat(2), ''); throw new GrantError() }
      const family = record.family_id
      const previous = rotating.get(family) ?? Promise.resolve()
      const run = previous.catch(() => {}).then(async () => {
        const current = state.tokens.get(record.hash)
        const connection = current && state.connections.get(current.connection_id)
        // A family that is not its connection's (the record was replaced under
        // the same id) dies alone: the connection it names is someone else's.
        if (connection && !boundTo(current, connection)) { await killFamily(family); throw new GrantError() }
        if (!current || !sameString(client_id, current.client_id)) {
          if (current) await killFamily(family, REUSE_DETECTED)
          throw new GrantError()
        }
        if (current.rotated_to) {
          const successor = state.tokens.get(current.rotated_to), kept = successors.get(family)
          if (!successor || successor.rotated_to || !kept || now() - current.rotated_at > ROTATION_GRACE_MS) { await killFamily(family, REUSE_DETECTED); throw new GrantError() }
          return kept.pair
        }
        if (current.expires_at <= now()) { await killFamily(family); throw new GrantError() }
        if (!connection || !(await checkActive(current.connection_id, { force: true }))) { await killFamily(family); throw new GrantError() }
        const pair = pairFor(connection, current.client_id, family)
        current.rotated_to = hash(pair.refresh_token); current.rotated_at = now()
        successors.set(family, { pair, at: now() })
        void state.save().catch(() => {})
        return pair
      })
      rotating.set(family, run)
      try { return await run } finally { if (rotating.get(family) === run) rotating.delete(family) }
    },
    /**
     * RFC 7009: presenting either token of a family ends the family. A console
     * token is its family's only token, so presenting it ends the connection.
     */
    async revoke(token) {
      for (const kind of ['refresh', 'access', 'key']) {
        if (!wellFormed(kind, token)) continue
        const record = state.tokens.get(hash(token))
        if (record) { await killFamily(record.family_id); return true }
      }
      return false
    },
    /** The live access-token record for a presented token, or null. */
    access(token) {
      const record = wellFormed('access', token) ? state.tokens.get(hash(token)) : undefined
      if (!record || record.kind !== 'access') return null
      if (record.expires_at <= now()) { state.tokens.delete(record.hash); return null }
      return record
    },
    /** The live record of a presented console token (§19.18), or null: its shape and checksum, its hash, its kind, not expired. */
    key(token) {
      const record = wellFormed('key', token) ? state.tokens.get(hash(token)) : undefined
      if (!record || record.kind !== 'key') return null
      if (record.expires_at <= now()) { state.tokens.delete(record.hash); return null }
      return record
    },
    killFamily,
    /** Drops expired codes and tokens; returns whether the durable store changed. */
    sweep() {
      const at = now()
      let changed = false
      for (const [key, code] of state.codes) if (code.expires_at <= at) state.codes.delete(key)
      // A rotated token stays known (so a grandparent replay still kills the
      // family); the pair its rotation issued is only needed inside the grace window.
      for (const [key, token] of state.tokens) {
        const successor = token.rotated_to ? state.tokens.get(token.rotated_to) : undefined
        if (token.expires_at <= at || (token.rotated_to && !successor)) { state.tokens.delete(key); changed = true }
      }
      for (const [family, kept] of successors) if (at - kept.at > ROTATION_GRACE_MS) successors.delete(family)
      return changed
    },
  }
}
