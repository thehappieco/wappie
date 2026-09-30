// The spending bound of each AI authorization (docs/mcp-enclave.md §18.10,
// I9), kept in this process's memory: the month's cost and the day's items.
// Go's own counts (GET …/ai/usage) are read at install and by the 60 s
// sweep; Go can only understate them, so the enclave keeps the larger of
// the two, and the cap is the smaller of the bundle's and Go's. Every
// attempt at a provider call is an item as it leaves, and the budget is
// checked before each; every 200 answer is charged by the provider's own
// usage, or an upper bound of it, and a call that left and was never
// answered (a timeout, a dropped connection, an abort) at that bound
// (§18.9): never by the sender's claim alone.
import { AI_MIN_BYTES_PER_SECOND, AI_OUTPUT_MAX_TOKENS } from './policy.mjs'

const monthOf = at => new Date(at).toISOString().slice(0, 7)
const dayOf = at => new Date(at).toISOString().slice(0, 10)
const MICROCENTS_PER_CENT = 1_000_000

/**
 * What one call is charged for (§18.10): the provider's token counts, a
 * missing one as `ceil(request body bytes / 4)` input tokens or
 * AI_OUTPUT_MAX_TOKENS[feature] output tokens; and, for audio and video,
 * seconds by the provider's own measure (OpenAI's transcription duration,
 * Google's audio tokens), else `max(claimed, ceil(plaintext bytes ÷
 * AI_MIN_BYTES_PER_SECOND))`, a bound no sender can shrink. A call that left
 * and was never answered has no usage (`{}`): it is charged the bounds.
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

/**
 * What a call's usage row and record report (§18.10), beside `charged`
 * (`measure`'s counts, which the cost always takes): the provider's own
 * counts where the answer carries them; else, for a count the pair's
 * `rate` never charges, what is known without a bound (the claimed length
 * for seconds, 0 for tokens); else the bound itself. So a Gemini video,
 * which Google counts as VIDEO tokens and never as seconds, shows its
 * claimed minutes, and a transcriber billed by duration shows no tokens.
 */
export function reported(feature, usage, charged, rate, claimedSeconds) {
  const tokens = (field, perMillion) => (Number.isSafeInteger(usage?.[field]) ? usage[field] : perMillion === 0 ? 0 : charged[field])
  let seconds = 0
  if (feature === 'audio' || feature === 'video') {
    const claimed = Number.isFinite(claimedSeconds) && claimedSeconds > 0 ? Math.ceil(claimedSeconds) : 0
    seconds = Number.isSafeInteger(usage?.seconds) ? usage.seconds : rate.sec === 0 ? claimed : charged.seconds
  }
  return { input_tokens: tokens('input_tokens', rate.in), output_tokens: tokens('output_tokens', rate.out), seconds }
}

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
     * The limit a call made now would pass, or null when it may be made:
     * `month` when the month's spend reached the cap (`min(bundle, Go's)` in
     * US cents), else `day` when the day's items reached
     * `request_items_per_day`.
     */
    limit(record, status) {
      const entry = book(record.connection_id)
      const goCap = status?.ai_off?.monthly_usd_cents
      const cents = Number.isSafeInteger(goCap) && goCap > 0 ? Math.min(record.budget.monthly_usd_cents, goCap) : record.budget.monthly_usd_cents
      if (Math.max(entry.cost, goCost(entry)) >= cents * MICROCENTS_PER_CENT) return 'month'
      if (Math.max(entry.items, goItems(entry)) >= record.budget.request_items_per_day) return 'day'
      return null
    },
    /** Whether a call may be made now (`limit` is null). */
    allows(record, status) { return this.limit(record, status) === null },
    /** One attempt at a provider call (counted before it leaves, whatever its answer). */
    item(id) { book(id).items++ },
    charge(id, microcents) { book(id).cost += microcents },
    used(id) { const entry = book(id); return { cost: Math.max(entry.cost, goCost(entry)), items: Math.max(entry.items, goItems(entry)) } },
    forget(id) { books.delete(id) },
    clear() { books.clear() },
  }
}
