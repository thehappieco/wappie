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
