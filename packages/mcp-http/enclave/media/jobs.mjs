// Who may open what, and when (docs/mcp-enclave.md §16.9): SLOTS opens run at
// once enclave-wide and up to QUEUE wait for the slot in arrival order; an
// open holds the slot from its keys to the end of its last job, so the
// reader's Node holds at most one plaintext. Per connection, one open is in
// the slot or its queue and up to OPENS_QUEUE_MAX wait behind it (service.mjs
// keeps that line), OPENS_PER_MINUTE are admitted in any 60 s and
// BYTES_PER_HOUR of ciphertext are fetched in any hour.
import { BYTES_PER_HOUR, OPENS_PER_MINUTE, QUEUE, RETRY_AFTER_S, SLOTS } from './policy.mjs'

const MINUTE_MS = 60_000, HOUR_MS = 3_600_000

/** The smallest RETRY_AFTER_S value not below `ms`, and 60 at most. */
export function retryAfter(ms) {
  const seconds = Math.ceil(Math.max(0, ms) / 1000)
  return RETRY_AFTER_S.find(value => value >= seconds) ?? RETRY_AFTER_S.at(-1)
}

/**
 * The slot and its queue. `admit(entry, run, left)` starts `run()` at once
 * when a slot is free, queues it when fewer than QUEUE wait, and otherwise
 * answers false. `run` returns a promise; the next entry starts when it
 * settles, and then `left()` (optional) is called: the entry's place is free
 * again, and its connection may hand the next of its own opens in.
 */
export function createScheduler({ slots = SLOTS, queue = QUEUE } = {}) {
  const running = new Set(), waiting = []
  function start(entry) {
    running.add(entry)
    Promise.resolve().then(entry.run).catch(() => {}).finally(() => {
      running.delete(entry)
      while (running.size < slots && waiting.length) start(waiting.shift())
      // Nothing it throws may become an unhandled rejection of the reader's Node.
      try { entry.left?.() } catch {}
    })
  }
  return {
    admit(entry, run, left) {
      entry.run = run
      entry.left = left
      if (running.size < slots) { start(entry); return true }
      if (waiting.length >= queue) return false
      waiting.push(entry)
      return true
    },
    /** 'running', the entry's place in the queue (0 is next), or null. */
    position(entry) {
      if (running.has(entry)) return 'running'
      const index = waiting.indexOf(entry)
      return index < 0 ? null : index
    },
    /** Takes a queued entry out; true when it was waiting. */
    remove(entry) {
      const index = waiting.indexOf(entry)
      if (index < 0) return false
      waiting.splice(index, 1)
      return true
    },
    queued: () => waiting.length,
    running: () => running.size,
  }
}

/** Per-connection admissions and bytes, in rolling windows. */
export function createBudgets({ now = Date.now } = {}) {
  const admissions = new Map(), fetched = new Map()
  const recent = (map, id, window) => {
    const at = now(), kept = (map.get(id) ?? []).filter(item => at - item.at < window)
    if (kept.length) map.set(id, kept); else map.delete(id)
    return kept
  }
  const push = (map, id, window, item) => { const kept = recent(map, id, window); kept.push(item); map.set(id, kept) }
  return {
    /** Milliseconds until another open may be admitted, 0 when one may now. */
    opensWait(id) {
      const kept = recent(admissions, id, MINUTE_MS)
      return kept.length < OPENS_PER_MINUTE ? 0 : kept[kept.length - OPENS_PER_MINUTE].at + MINUTE_MS - now()
    },
    admit(id) { push(admissions, id, MINUTE_MS, { at: now() }) },
    /** Milliseconds until `bytes` more fit in the hour, 0 when they fit now. */
    bytesWait(id, bytes) {
      const kept = recent(fetched, id, HOUR_MS)
      let used = kept.reduce((sum, item) => sum + item.bytes, 0)
      if (used + bytes <= BYTES_PER_HOUR) return 0
      for (const item of kept) {
        used -= item.bytes
        if (used + bytes <= BYTES_PER_HOUR) return item.at + HOUR_MS - now()
      }
      return HOUR_MS
    },
    charge(id, bytes) { push(fetched, id, HOUR_MS, { at: now(), bytes }) },
    forget(id) { admissions.delete(id); fetched.delete(id) },
  }
}
