// HMAC request authentication between Go and the enclave reader, both
// directions (docs/mcp-enclave.md §4). TLS authenticates responses; these
// headers authenticate requests. The canonical string names the direction, so
// a request signed for one side cannot be replayed to the other, and the raw
// request-target, so nothing re-serialized ever reaches the comparison.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

export const HMAC_LABEL = 'wappie-mcp-hmac/v1'
export const MAX_SKEW_S = 60
export const REPLAY_TTL_S = 61
export const REPLAY_MAX = 100_000
export const EMPTY_SHA256 = createHash('sha256').update(Buffer.alloc(0)).digest('hex')
const timestampShape = /^(?:0|[1-9][0-9]{0,15})$/
const nonceShape = /^[A-Za-z0-9_-]{22}$/
const signatureShape = /^v1=[0-9a-f]{64}$/

/** The eight fields joined by \n, no trailing newline. */
export function canonicalString({ direction, readerId, method, target, timestamp, nonce, bodySha256 }) {
  return [HMAC_LABEL, direction, readerId, method.toUpperCase(), target, timestamp, nonce, bodySha256].join('\n')
}

/** `v1=` + lowercase hex HMAC-SHA256 keyed by the UTF-8 bytes of the secret as written. */
export function signature(secret, fields) {
  return 'v1=' + createHmac('sha256', Buffer.from(secret, 'utf8')).update(canonicalString(fields), 'utf8').digest('hex')
}

/** The four headers for an outbound request. `body` is the exact bytes sent. */
export function signedHeaders({ secret, direction, readerId, method, target, body = Buffer.alloc(0), now = Date.now }) {
  const timestamp = String(Math.floor(now() / 1000))
  const nonce = randomBytes(16).toString('base64url')
  const bodySha256 = createHash('sha256').update(body).digest('hex')
  return {
    'x-wappie-reader': readerId, 'x-wappie-timestamp': timestamp, 'x-wappie-nonce': nonce,
    'x-wappie-signature': signature(secret, { direction, readerId, method, target, timestamp, nonce, bodySha256 }),
  }
}

/**
 * Nonces seen with a valid signature, each kept until its timestamp + 61 s.
 * Full after sweeping means refusing (503): an attacker who could fill it must
 * already hold a secret, and forgetting a live nonce would admit a replay.
 */
export function createReplayCache({ max = REPLAY_MAX, now = Date.now } = {}) {
  const seen = new Map()
  function sweep() { const at = now() / 1000; for (const [key, until] of seen) if (until <= at) seen.delete(key) }
  return {
    /** 'fresh' (now remembered), 'replay' or 'full'. */
    admit(key, timestamp) {
      const at = now() / 1000
      const until = seen.get(key)
      if (until !== undefined && until > at) return 'replay'
      if (seen.size >= max) { sweep(); if (seen.size >= max) return 'full' }
      seen.set(key, timestamp + REPLAY_TTL_S)
      return 'fresh'
    },
    size: () => seen.size,
  }
}

const refusal = (status, code, logCode) => Response.json({ code }, { status, headers: { 'Cache-Control': 'no-store', 'x-wappie-code': logCode } })

/**
 * The inbound guard (`internalAuth` for startReader), checking `to-reader`
 * requests. `secrets` is the enclave's holder (secrets.mjs): every accepted
 * secret is tried with no early exit, and a request signed with the current
 * one retires the previous. The request body is already bounded by the
 * router's limit; `info.target` is the raw request-target (Node's req.url).
 * Refusals carry `x-wappie-code` for the log line (internal.mjs strips it).
 */
export function createHmacGuard({ readerId, secrets, now = Date.now, replay = createReplayCache({ now }) }) {
  return async function internalAuth(request, info) {
    const header = name => request.headers.get(name)
    const timestamp = header('x-wappie-timestamp') ?? '', nonce = header('x-wappie-nonce') ?? '', given = header('x-wappie-signature') ?? ''
    if (header('x-wappie-reader') !== readerId || !timestampShape.test(timestamp) || !nonceShape.test(nonce) || !signatureShape.test(given)) return refusal(401, 'unauthorized', 'hmac_missing')
    const seconds = Number(timestamp)
    if (Math.abs(now() / 1000 - seconds) > MAX_SKEW_S) return refusal(401, 'unauthorized', 'hmac_stale')
    if (typeof info?.target !== 'string' || !info.target.startsWith('/')) return refusal(401, 'unauthorized', 'hmac_missing')
    const body = Buffer.from(await request.clone().arrayBuffer())
    const fields = { direction: 'to-reader', readerId, method: request.method, target: info.target, timestamp, nonce, bodySha256: createHash('sha256').update(body).digest('hex') }
    const presented = Buffer.from(given)
    let matched = null
    for (const candidate of secrets.accepted()) {
      const expected = Buffer.from(signature(candidate, fields))
      // Every secret is compared, whatever the earlier ones said.
      if (timingSafeEqual(expected, presented) && matched === null) matched = candidate
    }
    if (matched === null) return refusal(401, 'unauthorized', 'hmac_bad')
    const admitted = replay.admit(`to-reader\n${readerId}\n${nonce}`, seconds)
    if (admitted === 'full') return refusal(503, 'replay_cache_full', 'replay_cache_full')
    if (admitted === 'replay') return refusal(401, 'unauthorized', 'hmac_replay')
    secrets.used(matched)
    return undefined
  }
}
