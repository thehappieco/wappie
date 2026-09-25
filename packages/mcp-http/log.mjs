// JSON-lines request log. Identifiers are reduced to sha256 prefixes and the
// entry never carries paths with ids, query strings, bodies, headers, tokens or
// keys: an operator reading journalctl learns what happened, never to whom.
import { createHash } from 'node:crypto'

export const fingerprint = value => createHash('sha256').update(String(value)).digest('hex').slice(0, 12)
const FINGERPRINT = /^[0-9a-f]{12}$/
const CODE = /^[a-z][a-z0-9_]{0,47}$/

/** `sink` receives one complete line per event; the default is stdout. */
export function createLog(sink = line => process.stdout.write(line + '\n'), now = Date.now) {
  function write(entry) {
    try { sink(JSON.stringify(entry)) } catch { /* a failing sink must never take a request down */ }
  }
  return {
    request({ route, status, ms, connection, client, code }) {
      const entry = { ts: new Date(now()).toISOString(), route, status }
      if (typeof ms === 'number') entry.ms = Math.round(ms)
      if (connection) entry.conn = fingerprint(connection)
      if (client) entry.client = fingerprint(client)
      if (code) entry.code = code
      write(entry)
    },
    /**
     * Numbers and booleans only, with two exceptions the enclave's log sink
     * also admits: a string survives when it is a 12-hex fingerprint (a PCR0,
     * SPKI or policy hash prefix), and `code` when it is a snake_case code.
     */
    event(code, fields = {}) {
      const entry = { ts: new Date(now()).toISOString(), event: code }
      for (const [key, value] of Object.entries(fields)) {
        if (typeof value === 'number' || typeof value === 'boolean' || (typeof value === 'string' && (FINGERPRINT.test(value) || (key === 'code' && CODE.test(value))))) entry[key] = value
      }
      write(entry)
    },
  }
}
