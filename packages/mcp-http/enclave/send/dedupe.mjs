// Idempotency (docs/mcp-enclave.md §17.11). Hosts repeat calls: ChatGPT sends
// the same one again, a retry follows a slow answer. An identical call of a
// connection within DEDUPE_WINDOW_MS answers what the first one did, marked
// `duplicate: true`, and costs nothing: no second draft, no second message.
// One still running is joined, not started twice. The map lives in memory
// only and dies with the connection; its key is a hash, and nothing derived
// from a text ever goes to Go (a send's `client_ref` is random).
import { createHash } from 'node:crypto'
import { DEDUPE_WINDOW_MS } from './policy.mjs'

/**
 * SHA-256(connection ‖ 0 ‖ tool ‖ 0 ‖ device ‖ 0 ‖ chat key or "" ‖ 0 ‖ reply
 * or "" ‖ 0 ‖ text), over the text after the rules (which refuse NUL, so the
 * fields cannot run into each other).
 */
export function dedupeKey({ connection, tool, device, chatKey, replyTo, text }) {
  return createHash('sha256').update([connection, tool, device, chatKey ?? '', replyTo ?? '', text].join('\u0000'), 'utf8').digest('hex')
}

/**
 * `run(id, key, work)` answers a live entry's result with `duplicate: true`
 * (or rethrows its kept error), joins a call still running, or runs `work`.
 * A result is kept for the window; an error only when it says `keep` (a send
 * that may have left, which must never be repeated), else it is forgotten
 * and a later call runs again.
 */
export function createDedupe({ now = Date.now } = {}) {
  // connection id -> Map(key -> { at, running?: Promise, result?, error? })
  const connections = new Map()
  const live = entry => entry.running || now() - entry.at < DEDUPE_WINDOW_MS
  function sweep(entries) { for (const [key, entry] of entries) if (!live(entry)) entries.delete(key) }
  const answer = entry => {
    if (entry.error) throw entry.error
    return { ...entry.result, duplicate: true }
  }
  return {
    async run(id, key, work) {
      let entries = connections.get(id)
      if (!entries) connections.set(id, entries = new Map())
      sweep(entries)
      const known = entries.get(key)
      if (known?.running) {
        try { await known.running } catch { /* answered below from what the first call left */ }
        const settled = entries.get(key)
        if (settled && !settled.running) return answer(settled)
        if (known.failure) throw known.failure
      } else if (known) return answer(known)
      const entry = { at: now() }
      entry.running = (async () => work())()
      entries.set(key, entry)
      try {
        const result = await entry.running
        Object.assign(entry, { at: now(), result, running: null })
        return result
      } catch (error) {
        entry.running = null
        entry.failure = error
        if (error?.keep === true) Object.assign(entry, { at: now(), error })
        else if (entries.get(key) === entry) entries.delete(key)
        throw error
      }
    },
    wipe(id) { connections.delete(id) },
    size() { let n = 0; for (const entries of connections.values()) n += entries.size; return n },
    clear() { connections.clear() },
  }
}
