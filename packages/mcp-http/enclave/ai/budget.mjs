// The spending bound of each AI authorization (docs/mcp-enclave.md §18.10,
// I9), kept in this process's memory: the month's cost and the day's items.
// Go's own counts (GET …/ai/usage) are read at install and by the 60 s
// sweep; Go can only understate them, so the enclave keeps the larger of
// the two, and the cap is the smaller of the bundle's and Go's. Every 200
// answer is charged by the provider's own usage, or an upper bound of it,
// never by the sender's claim alone.
import { AI_MIN_BYTES_PER_SECOND, AI_OUTPUT_MAX_TOKENS } from './policy.mjs'

const monthOf = at => new Date(at).toISOString().slice(0, 7)
const dayOf = at => new Date(at).toISOString().slice(0, 10)
const MICROCENTS_PER_CENT = 1_000_000

/**
 * What one 200 answer is charged for (§18.10): the provider's token counts,
 * a missing one as `ceil(request body bytes / 4)` input tokens or
 * AI_OUTPUT_MAX_TOKENS[feature] output tokens; and, for audio and video,
 * seconds by the provider's own measure (OpenAI's transcription duration,
 * Google's audio tokens), else `max(claimed, ceil(plaintext bytes ÷
 * AI_MIN_BYTES_PER_SECOND))`, a bound no sender can shrink.
 */
export function measure(feature, usage, { bodyBytes, plaintextBytes = 0, claimedSeconds }) {
  const input = Number.isSafeInteger(usage?.input_tokens) ? usage.input_tokens : Math.ceil(bodyBytes / 4)
  const output = Number.isSafeInteger(usage?.output_tokens) ? usage.output_tokens : AI_OUTPUT_MAX_TOKENS[feature]
  let seconds = 0
  if (feature === 'audio' || feature === 'video') {
    const claimed = Number.isFinite(claimedSeconds) && claimedSeconds > 0 ? Math.ceil(claimedSeconds) : 0
    seconds = Number.isSafeInteger(usage?.seconds) ? usage.seconds : Math.max(claimed, Math.ceil(plaintextBytes / AI_MIN_BYTES_PER_SECOND))
  }
  return { input_tokens: input, output_tokens: output, seconds }
}

/**
 * Microcents for `counts` at `rate` (the bundle's `{in, out, sec}`: US cents
 * per million input tokens, per million output tokens, per 1,000 seconds).
 */
export const costOf = (rate, counts) => rate.in * counts.input_tokens + rate.out * counts.output_tokens + rate.sec * counts.seconds * 1_000

export function createBudgets({ now = Date.now } = {}) {
  // id -> { month, cost, day, items, go: {month, cost, day, items} }
  const books = new Map()
  function book(id) {
    const at = now(), month = monthOf(at), day = dayOf(at)
    let entry = books.get(id)
    if (!entry) books.set(id, entry = { month, cost: 0, day, items: 0, go: null })
    if (entry.month !== month) { entry.month = month; entry.cost = 0 }
    if (entry.day !== day) { entry.day = day; entry.items = 0 }
    return entry
  }
  const goCost = entry => (entry.go?.month === entry.month ? entry.go.cost : 0)
  const goItems = entry => (entry.go?.day === entry.day ? entry.go.items : 0)
  return {
    /** Go's answer `{month, cost_microcents, items_today}`; a malformed one is ignored. */
    fromGo(id, answer) {
      const entry = book(id)
      if (!answer || answer.month !== entry.month || !Number.isSafeInteger(answer.cost_microcents) || answer.cost_microcents < 0 ||
        !Number.isSafeInteger(answer.items_today) || answer.items_today < 0) return
      entry.go = { month: answer.month, cost: answer.cost_microcents, day: entry.day, items: answer.items_today }
    },
    /**
     * Whether a call may be made now: false when the month's spend reached
     * the cap (`min(bundle, Go's)` in US cents) or the day's items reached
     * `request_items_per_day`.
     */
    allows(record, status) {
      const entry = book(record.connection_id)
      const goCap = status?.ai_off?.monthly_usd_cents
      const cents = Number.isSafeInteger(goCap) && goCap > 0 ? Math.min(record.budget.monthly_usd_cents, goCap) : record.budget.monthly_usd_cents
      const used = Math.max(entry.cost, goCost(entry))
      const items = Math.max(entry.items, goItems(entry))
      return used < cents * MICROCENTS_PER_CENT && items < record.budget.request_items_per_day
    },
    /** One provider call made (counted before it leaves, whatever its answer). */
    item(id) { book(id).items++ },
    charge(id, microcents) { book(id).cost += microcents },
    used(id) { const entry = book(id); return { cost: Math.max(entry.cost, goCost(entry)), items: Math.max(entry.items, goItems(entry)) } },
    forget(id) { books.delete(id) },
    clear() { books.clear() },
  }
}
