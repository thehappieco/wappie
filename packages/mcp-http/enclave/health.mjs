// The health line (event "health", every 60 s) and the clock check behind it.
// The enclave has no trusted time source of its own, and relative ranges
// ("last 7 days") are computed from `new Date()`, so once a minute it compares
// its clock with the Date header of an unauthenticated HTTPS request to the
// KMS endpoint: TLS verified here, so the parent can delay the answer but not
// forge it, and a 4xx carries a Date without spending any quota.

import { readFile as readFileAsync } from 'node:fs/promises'
import { MEM_SAMPLE_MS } from './media/policy.mjs'

export const HEALTH_EVERY_MS = 60_000
export const CLOCK_URL = 'https://kms.eu-west-1.amazonaws.com/'
const MB = 1024 * 1024

/**
 * Local time minus the server's (its Date header plus half the round trip),
 * in ms, or null when the probe fails. Date has 1 s resolution, and the alarm
 * threshold (2 s) is set with that in mind.
 */
export async function clockSkew({ url = CLOCK_URL, fetch = globalThis.fetch, now = Date.now, timeoutMs = 5000 } = {}) {
  const sent = now()
  let response
  try { response = await fetch(url, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) }) } catch { return null }
  const received = now()
  await response.body?.cancel().catch(() => {})
  const date = Date.parse(response.headers.get('date') ?? '')
  if (!Number.isFinite(date)) return null
  return Math.round(received - (date + (received - sent) / 2))
}

/** First 12 hex of a hash, the log sink's fingerprint shape; undefined otherwise. */
export const prefix = value => (typeof value === 'string' && /^[0-9a-f]{12,}$/.test(value) ? value.slice(0, 12) : undefined)

/**
 * `fields()` returns the reader's own numbers (connections, pending, …); this
 * adds process figures and the last clock probe. Unknown fields are omitted.
 */
export function createHealthLine({ log, fields, probe = () => clockSkew(), everyMs = HEALTH_EVERY_MS, started = Date.now(), now = Date.now }) {
  let timer = null, skew = null
  async function tick() {
    skew = await probe().catch(() => null)
    const memory = process.memoryUsage()
    const entry = {
      uptime_s: Math.floor((now() - started) / 1000), rss_mb: Math.round(memory.rss / MB), heap_mb: Math.round(memory.heapUsed / MB),
      ...(skew === null ? {} : { clock_skew_ms: skew }), ...fields(),
    }
    for (const [key, value] of Object.entries(entry)) if (value === undefined || value === null) delete entry[key]
    log.event('health', entry)
    return entry
  }
  return {
    tick,
    skew: () => skew,
    start() { void tick(); timer = setInterval(() => { void tick() }, everyMs); timer.unref?.() },
    stop() { if (timer) clearInterval(timer); timer = null },
  }
}

/**
 * The lowest `MemAvailable` over a health window (docs/mcp-enclave.md
 * §16.10): sampled every MEM_SAMPLE_MS, reported once per line as
 * `mem_avail_min_mb`, rounded down to a multiple of 64 so the parent learns
 * memory pressure, never one job's size. `take()` returns it (undefined when
 * /proc/meminfo cannot be read) and starts the next window.
 */
export function createMemSampler({ readFile = readFileAsync, everyMs = MEM_SAMPLE_MS } = {}) {
  let timer = null, lowest = Infinity
  async function sample() {
    try {
      const match = /^MemAvailable:\s+(\d+) kB$/m.exec(await readFile('/proc/meminfo', 'utf8'))
      if (match) lowest = Math.min(lowest, Number(match[1]) * 1024)
    } catch { /* not a Linux host: the field is left out */ }
  }
  return {
    sample,
    take() {
      const value = Number.isFinite(lowest) ? Math.floor(lowest / MB / 64) * 64 : undefined
      lowest = Infinity
      return value
    },
    start() { void sample(); timer = setInterval(() => { void sample() }, everyMs); timer.unref?.() },
    stop() { if (timer) clearInterval(timer); timer = null },
  }
}
