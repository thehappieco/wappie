// In-process token buckets. Provider egress addresses are shared by every
// claude.ai and ChatGPT user, so fairness keys on identities the reader knows
// (connection, family, request id) and per-address buckets are only a coarse
// abuse ceiling. Nothing a caller can choose freely (a client_id is public)
// keys a bucket on its own: that would let one caller starve everyone else.
import { isIP } from 'node:net'

const loopback = address => address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1'

/**
 * The address a request came from. `X-Forwarded-For` is trusted only when the
 * socket peer is loopback (nginx on the same host writes `$remote_addr`, so
 * the last entry is the client); anything else is the socket address itself.
 */
export function clientIP(remoteAddress, forwardedFor) {
  const socket = typeof remoteAddress === 'string' ? remoteAddress : ''
  if (loopback(socket) && typeof forwardedFor === 'string' && forwardedFor.trim()) {
    const last = forwardedFor.split(',').pop().trim()
    if (isIP(last)) return last
  }
  return socket || 'unknown'
}

export const isLoopback = loopback

/**
 * The bucket key for an address. An IPv6 /64 is what a single subscriber
 * holds, so its 2^64 addresses share one key; IPv4 (including the mapped
 * form) keys on the address itself.
 */
export function ipKey(address) {
  if (isIP(address) !== 6) return address
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)
  if (mapped) return mapped[1]
  const [head, tail = ''] = address.split('::')
  const left = head ? head.split(':') : [], right = tail ? tail.split(':') : []
  const groups = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
  return groups.slice(0, 4).map(group => parseInt(group, 16).toString(16)).join(':') + '::/64'
}

/**
 * Whether two ipKey values share a network (docs/mcp-enclave.md §19.12): the
 * first three octets for IPv4, the first 56 bits for IPv6 (whose key is
 * already its /64). Different families, or a key that is no address, differ.
 */
export function sameNetwork(a, b) {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/, v6 = /^([0-9a-f]{1,4}):([0-9a-f]{1,4}):([0-9a-f]{1,4}):([0-9a-f]{1,4})::\/64$/
  const [a4, b4] = [v4.exec(a ?? ''), v4.exec(b ?? '')]
  if (a4 && b4) return a4.slice(1, 4).join('.') === b4.slice(1, 4).join('.')
  const [a6, b6] = [v6.exec(a ?? ''), v6.exec(b ?? '')]
  if (!a6 || !b6) return false
  const groups = match => match.slice(1, 5).map(group => parseInt(group, 16))
  const [x, y] = [groups(a6), groups(b6)]
  return x[0] === y[0] && x[1] === y[1] && x[2] === y[2] && x[3] >> 8 === y[3] >> 8
}

/** Buckets refill continuously at `perMinute`; a full bucket is forgotten on sweep. */
export function createLimiter(now = Date.now) {
  const buckets = new Map()
  let swept = now()
  function sweep() {
    const at = now()
    if (at - swept < 60_000) return
    swept = at
    for (const [key, bucket] of buckets) if (bucket.tokens + (at - bucket.updated) * bucket.rate >= bucket.capacity) buckets.delete(key)
  }
  return {
    /** Takes one token from `name:key`; on refusal reports the seconds until one is back. */
    take(name, key, perMinute) {
      sweep()
      const at = now(), id = `${name}:${key}`
      let bucket = buckets.get(id)
      if (!bucket) { bucket = { capacity: perMinute, rate: perMinute / 60_000, tokens: perMinute, updated: at }; buckets.set(id, bucket) }
      bucket.tokens = Math.min(bucket.capacity, bucket.tokens + Math.max(0, at - bucket.updated) * bucket.rate)
      bucket.updated = at
      if (bucket.tokens >= 1) { bucket.tokens -= 1; return { ok: true } }
      return { ok: false, retryAfter: Math.max(1, Math.ceil((1 - bucket.tokens) / bucket.rate / 1000)) }
    },
    size: () => buckets.size,
  }
}
