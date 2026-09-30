// send_to_self in the enclave (docs/mcp-enclave.md §17.8, §17.11), and the
// windows the enclave counts sends and drafts in. An own-chat note leaves at
// once, without the console, to the number's own chat and nowhere else: Go
// resolves that chat itself, so the tool names none. Nothing it sends is ever
// sent twice: a `client_ref` Go keeps per connection makes a repeated route
// call answer what was recorded, dedupe answers an identical call, and a
// lost answer is `send_uncertain`, final for automation, never repeated.
import { randomBytes } from 'node:crypto'
import { messageURLs } from '../provider.mjs'
import { dedupeKey } from './dedupe.mjs'
import { DRAFTS_PER_HOUR, SEND_MIN_INTERVAL_MS, SEND_ROUTE_TIMEOUT_MS, SENDS_PER_DAY } from './policy.mjs'
import { normalizeNewlines, textRefusal } from './textrules.mjs'

const HOUR_MS = 3_600_000, DAY_MS = 24 * HOUR_MS
const uuidShape = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/**
 * A rolling window per connection: at most `limit` in `span`, and, with
 * `interval`, that long after the last. `take(id)` answers `{slot}`, or
 * `{retry_at}` (RFC 3339 UTC), the moment the refused call would first pass;
 * `release(id, slot)` gives back one that sent nothing, since a refusal is
 * neither a draft nor a send (§17.7).
 */
export function slidingWindow({ limit, span, interval = 0, now = Date.now }) {
  const taken = new Map()
  return {
    take(id) {
      const at = now()
      const list = (taken.get(id) ?? []).filter(slot => at - slot.at < span)
      taken.set(id, list)
      let retry = 0
      if (list.length >= limit) retry = list[list.length - limit].at + span
      const last = list.at(-1)
      if (interval > 0 && last && at - last.at < interval) retry = Math.max(retry, last.at + interval)
      if (retry) return { retry_at: new Date(retry).toISOString() }
      const slot = { at }
      list.push(slot)
      return { slot }
    },
    release(id, slot) {
      const list = taken.get(id)
      const index = list ? list.indexOf(slot) : -1
      if (index >= 0) list.splice(index, 1)
    },
    forget(id) { taken.delete(id) },
  }
}

/** The enclave's own counts (§17.10): drafts per hour, and sends per day with the interval between two. */
export const createWindows = ({ now = Date.now } = {}) => ({
  drafts: slidingWindow({ limit: DRAFTS_PER_HOUR, span: HOUR_MS, now }),
  sends: slidingWindow({ limit: SENDS_PER_DAY, span: DAY_MS, interval: SEND_MIN_INTERVAL_MS, now }),
})

/**
 * Whether Go itself refused a send, so that nothing left: a 4xx carrying one
 * of Go's codes, or Go's 500 `internal`, which it records as refused (§17.19).
 * Every other answer but a well-formed 200 (Go's 502 `send_uncertain`, a
 * status Go never wrote, a body without Go's code) may follow a message that
 * left.
 */
export function refusedByGo({ status, data }) {
  const code = typeof data?.code === 'string' ? data.code : ''
  return (status >= 400 && status < 500 && code !== '') || (status === 500 && code === 'internal')
}

/** A send's reference: 16 random bytes. Nothing derived from the text goes to Go: a hash of a short text could be brute-forced. */
export const clientRef = () => randomBytes(16).toString('base64url')

/** `ctx` is service.mjs's, as for createDrafts. */
export function createSends(ctx) {
  const { relay, consoleURL, dedupe, windows, gate, recordRefusal, event, fromGo, refusal, codeOf, counters } = ctx

  async function deliver(record, input, text) {
    const id = record.connection_id, device = input.device_id
    const taken = windows.sends.take(id)
    if (!taken.slot) {
      await recordRefusal(record, { kind: 'self', device_id: device, code: 'rate_limited' })
      throw refusal('rate_limited', { retry_at: taken.retry_at })
    }
    let answer
    try {
      answer = await relay.sending(id, record.api_key, 'POST', 'send', { timeout: SEND_ROUTE_TIMEOUT_MS, body: { client_ref: clientRef(), kind: 'self', device_id: device, text } })
    } catch {
      // The request may have reached Go and the message WhatsApp: it counts, and it is never sent again.
      event('send_uncertain', id)
      throw refusal('send_uncertain', { keep: true })
    }
    const data = answer.data
    if (answer.status === 200 && data && typeof data.wa_id === 'string' && typeof data.timestamp === 'string' &&
      (data.message_uid === null || (typeof data.message_uid === 'string' && uuidShape.test(data.message_uid)))) {
      counters.sends++
      event('self_sent', id)
      const url = data.message_uid ? messageURLs(consoleURL, record.tenant_id).message(device, data.message_uid) : null
      return { message_uid: data.message_uid, wa_id: data.wa_id, timestamp: data.timestamp, ...(url ? { open_url: url } : {}) }
    }
    if (!refusedByGo(answer)) {
      // Go's 502, or an answer Go did not write: a proxy's 502 or 504 after
      // Go took the send, a restart mid-send, a 200 that does not parse. The
      // message may have left: it counts, and it is never sent again.
      event('send_uncertain', id)
      throw refusal('send_uncertain', { keep: true })
    }
    // Refused before anything left: it does not count.
    windows.sends.release(id, taken.slot)
    throw fromGo(answer)
  }

  /** provider.send.sendSelf for `record`: the §17.8 steps from the gate on. */
  return async function sendSelf(record, input) {
    const id = record.connection_id
    try {
      await gate(record, { self: true })
      const text = normalizeNewlines(input.text)
      const why = textRefusal(text, { links: true })
      if (why) {
        await recordRefusal(record, { kind: 'self', device_id: input.device_id, code: 'text_not_allowed' })
        throw refusal('text_not_allowed', { why })
      }
      const key = dedupeKey({ connection: id, tool: 'send_to_self', device: input.device_id, text })
      return await dedupe.run(id, key, () => deliver(record, input, text))
    } catch (error) {
      if (codeOf(error) !== 'send_uncertain') event('send_refused', id, codeOf(error))
      throw error
    }
  }
}
