// The reading limits of a connection of a client Wappie has not tested and of
// a console token (docs/mcp-enclave.md §19.19, `client_limits_v1`). Without
// them an approved unknown client, or a leaked token, could copy a workspace's
// archive in hours, and the notice, the e-mail and revocation all act after
// the fact; the limits bound what can leave before anyone looks.
//
// The numbers are image constants (CLIENT_LIMITS, measured in PCR0), applied
// whatever a bundle or Go says. Messages count every message a tool returns,
// attachments every open_attachment that returns content (an AI transcript
// included); chat previews and activity counts are not counted. A call is
// checked before it runs: one that starts under the limit is served whole and
// counted, so a counter passes its limit by at most one call's items. Calls
// still running count at the check as the most each may return (its
// reservation): a call that would start under the limit only if they returned
// less waits until one of them has finished, so concurrent calls, and the
// elements of a JSON-RPC batch, cannot all pass a check made before any of
// them was counted.
//
// Counters are per connection and in memory: the day is a rolling 24 hours in
// one-minute buckets, the first hour runs from the record's `created_at`. A
// restart resets them. From 0.6.0 a text connection the restart left without
// its key keeps reading metadata (§19.29), under the fresh counters, as a
// metadata connection always did after a restart; its text waits for the
// renewal, which takes the creator's password. So a restart lets metadata be
// read early, never text, which §19.19 accepts.
//
// At a limit the tool answers `limit_reached` with the time it resets, and Go
// is told the code alone (`budget_hit`), at most once per connection, code and
// window: Go raises the banner and the e-mail. A token used from outside its
// allowed networks is reported the same way, code `network`.
import { ArchiveError } from '@whatserver2/client'
import { fingerprint } from '../log.mjs'

const MINUTE_MS = 60_000
const HOUR_MS = 3_600_000
const DAY_MS = 24 * HOUR_MS
export const BUDGET_KINDS = Object.freeze(['messages', 'attachments'])
/** The ticket of a kind nothing counts. */
const NO_TICKET = Object.freeze({ settle() {}, release() {} })
/** The codes Go may hear (§19.19, §19.18). */
export const BUDGET_CODES = Object.freeze(['daily_messages', 'daily_attachments', 'first_hour_messages', 'first_hour_attachments', 'network'])

/** A record's limits tier (§19.6): a record 0.5.0 wrote is tested web, as it was. */
export const tierOf = record => (typeof record?.limits_tier === 'string' ? record.limits_tier : 'web_tested')

/**
 * `limits` is CLIENT_LIMITS; `onHit(id, code)` tells Go (best effort, never
 * awaited by a tool); `log` gets `budget_hit` with the connection's
 * fingerprint and the code.
 */
export function createReadingLimits({ limits, now = Date.now, onHit = () => {}, log }) {
  // connection id -> { day: {messages: Map<minute, n>, attachments}, hour: {messages, attachments}, quiet: Map<code, until>,
  //   reserved: {messages, attachments} (the most the calls running may still return), waiters: [resolve] }
  const counters = new Map()
  let hits = 0
  function stateOf(id) {
    let entry = counters.get(id)
    if (!entry) {
      entry = { day: { messages: new Map(), attachments: new Map() }, hour: { messages: 0, attachments: 0 }, quiet: new Map(),
        reserved: { messages: 0, attachments: 0 }, waiters: [] }
      counters.set(id, entry)
    }
    return entry
  }
  /** The minute buckets still inside the last 24 hours, and their sum. */
  function dayTotal(buckets, at) {
    let total = 0
    for (const [minute, count] of buckets) {
      if ((minute + 1) * MINUTE_MS + DAY_MS <= at) buckets.delete(minute)
      else total += count
    }
    return total
  }
  /** When the rolling day falls back under `limit`: the oldest buckets leave it one by one. */
  function dayReset(buckets, limit, at) {
    let total = dayTotal(buckets, at), reset = at
    for (const minute of [...buckets.keys()].sort((a, b) => a - b)) {
      if (total < limit) break
      total -= buckets.get(minute)
      reset = (minute + 1) * MINUTE_MS + DAY_MS
    }
    return reset
  }
  /** Tells Go once per connection, code and window (`until`: when the window ends). */
  function report(id, code, until) {
    const entry = stateOf(id)
    if ((entry.quiet.get(code) ?? 0) > now()) return
    entry.quiet.set(code, until)
    hits++
    log?.event('budget_hit', { conn: fingerprint(id), code })
    try { void Promise.resolve(onHit(id, code)).catch(() => {}) } catch { /* best effort */ }
  }
  /** Counts what a served call returned into the day and, inside it, the first hour. */
  function count(entry, kind, n, created) {
    if (!Number.isSafeInteger(n) || n <= 0) return
    const at = now(), minute = Math.floor(at / MINUTE_MS)
    entry.day[kind].set(minute, (entry.day[kind].get(minute) ?? 0) + n)
    if (at < created + HOUR_MS) entry.hour[kind] += n
  }
  /** A running call's reservation: settled once, by its count or by its failure, and then the calls waiting look again. */
  function ticketFor(entry, kind, size, created) {
    let open = true
    const close = () => {
      if (!open) return false
      open = false
      entry.reserved[kind] -= size
      for (const wake of entry.waiters.splice(0)) wake()
      return true
    }
    return {
      settle(n) { if (close()) count(entry, kind, n, created) },
      release() { close() },
    }
  }
  function refuse(id, code, resetAt) {
    report(id, code, resetAt)
    return Object.assign(new ArchiveError('limit_reached', 429), { reset_at: new Date(resetAt).toISOString().replace(/\.\d{3}Z$/, 'Z') })
  }

  return {
    /**
     * `provider.limits` for a record whose tier has reading limits, or null
     * for a tier without them (tested clients). `reserve(kind, most)` waits
     * its turn and answers a ticket, or throws ArchiveError('limit_reached')
     * with `reset_at` at a limit; `most` is the most the call can return.
     * `ticket.settle(n)` counts what the served call returned and frees the
     * reservation; `ticket.release()` frees it uncounted (a call that failed)
     * and does nothing after `settle`.
     */
    forConnection(record) {
      const tier = limits[tierOf(record)]
      if (!tier || (!tier.daily && !tier.first_hour)) return null
      const id = record.connection_id
      const created = Number.isFinite(record.created_at) ? record.created_at : 0
      return {
        async reserve(kind, most = 1) {
          if (!BUDGET_KINDS.includes(kind)) return NO_TICKET
          const size = Number.isSafeInteger(most) && most > 0 ? most : 1
          for (;;) {
            const at = now(), entry = stateOf(id)
            const hourOpen = Boolean(tier.first_hour) && at < created + HOUR_MS
            const day = tier.daily ? dayTotal(entry.day[kind], at) : 0
            if (hourOpen && entry.hour[kind] >= tier.first_hour[kind]) throw refuse(id, `first_hour_${kind}`, created + HOUR_MS)
            if (tier.daily && day >= tier.daily[kind]) throw refuse(id, `daily_${kind}`, dayReset(entry.day[kind], tier.daily[kind], at))
            const running = entry.reserved[kind]
            const room = (!hourOpen || entry.hour[kind] + running < tier.first_hour[kind]) && (!tier.daily || day + running < tier.daily[kind])
            if (running === 0 || room) {
              entry.reserved[kind] += size
              return ticketFor(entry, kind, size, created)
            }
            await new Promise(resolve => entry.waiters.push(resolve))
          }
        },
      }
    },
    /** A token used from outside its allowed networks (§19.18): reported once a day per connection. */
    network(record) { report(record.connection_id, 'network', now() + DAY_MS) },
    /** Forgets the counters of connections that no longer exist and have no call running. */
    sweep(live) {
      for (const [id, entry] of counters) if (!live.has(id) && entry.reserved.messages === 0 && entry.reserved.attachments === 0) counters.delete(id)
    },
    /** The health line's `budget_hits`, since the last call. */
    takeHits() { const value = hits; hits = 0; return value },
  }
}
