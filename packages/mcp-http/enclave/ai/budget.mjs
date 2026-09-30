// The safety cap of each AI authorization (docs/mcp-enclave.md §18.10, I9),
// kept in this process's memory: the month's tokens and the day's items.
// Prices vary with each person's plan and model, and billing is their
// account's at each provider, so the cap counts tokens, never money. Go's
// own counts (GET …/ai/usage) are read at install and by the 60 s sweep; Go
// can only understate them, so the enclave keeps the larger of the two, and
// the cap is the smaller of the bundle's and Go's. Every attempt at a
// provider call is an item as it leaves, and the budget is checked before
// each; every 200 answer counts the tokens the provider reports, or an upper
// bound of them, and a call that left and was never answered (a timeout, a
// dropped connection, an abort) counts that bound (§18.9): never the
// sender's claim alone.
import { AI_DURATION_TOKENS_PER_SECOND, AI_MIN_BYTES_PER_SECOND, AI_OUTPUT_MAX_TOKENS } from './policy.mjs'

const monthOf = at => new Date(at).toISOString().slice(0, 7)
const dayOf = at => new Date(at).toISOString().slice(0, 10)
const isCount = value => Number.isSafeInteger(value) && value >= 0
const timed = feature => feature === 'audio' || feature === 'video'
/** The claimed length in whole seconds, or 0 without a claim. */
const claimOf = claimedSeconds => (Number.isFinite(claimedSeconds) && claimedSeconds > 0 ? Math.ceil(claimedSeconds) : 0)

/**
 * The tokens one call counts toward the monthly limit (§18.10): the tokens
 * the provider reports, input plus output (its reasoning or thinking tokens
 * are in the output); for an answer billed by duration (OpenAI's
 * transcription `usage.type` `duration`), its seconds ×
 * AI_DURATION_TOKENS_PER_SECOND. What the answer does not report takes an
 * upper bound: `ceil(request body bytes / 4)` input tokens,
 * AI_OUTPUT_MAX_TOKENS[feature] output tokens, and for audio and video with
 * no measure at all, at least the length bound `max(claimed, ceil(plaintext
 * bytes ÷ AI_MIN_BYTES_PER_SECOND))` × AI_DURATION_TOKENS_PER_SECOND, which
 * no sender can shrink. A call that left and was never answered has no usage
 * (`{}`): it counts the bounds.
 */
export function chargedTokens(feature, usage, { bodyBytes, plaintextBytes = 0, claimedSeconds }) {
  const length = () => Math.max(claimOf(claimedSeconds), Math.ceil(plaintextBytes / AI_MIN_BYTES_PER_SECOND)) * AI_DURATION_TOKENS_PER_SECOND
  if (usage?.duration === true) return isCount(usage.seconds) ? usage.seconds * AI_DURATION_TOKENS_PER_SECOND : length()
  const input = isCount(usage?.input_tokens) ? usage.input_tokens : undefined
  const output = isCount(usage?.output_tokens) ? usage.output_tokens : undefined
  const bounded = (input ?? Math.ceil(bodyBytes / 4)) + (output ?? AI_OUTPUT_MAX_TOKENS[feature])
  return input === undefined && output === undefined && timed(feature) ? Math.max(bounded, length()) : bounded
}

/**
 * What a call's usage row reports beside the tokens it counted (§18.10):
 * the tokens the provider reported, 0 where it reported none, and for audio
 * and video the seconds it measured (OpenAI's duration, Google's AUDIO
 * tokens), else the claimed length. A transcriber billed by duration so
 * shows no tokens, and a Gemini video, which Google counts as VIDEO tokens
 * and never as seconds, its claimed minutes.
 */
export function reported(feature, usage, claimedSeconds) {
  const seconds = timed(feature) ? (isCount(usage?.seconds) ? usage.seconds : claimOf(claimedSeconds)) : 0
  return { input_tokens: isCount(usage?.input_tokens) ? usage.input_tokens : 0, output_tokens: isCount(usage?.output_tokens) ? usage.output_tokens : 0, seconds }
}

export function createBudgets({ now = Date.now } = {}) {
  // id -> { month, tokens, day, items, go: {month, tokens, day, items} }
  const books = new Map()
  function book(id) {
    const at = now(), month = monthOf(at), day = dayOf(at)
    let entry = books.get(id)
    if (!entry) books.set(id, entry = { month, tokens: 0, day, items: 0, go: null })
    if (entry.month !== month) { entry.month = month; entry.tokens = 0 }
    if (entry.day !== day) { entry.day = day; entry.items = 0 }
    return entry
  }
  const goTokens = entry => (entry.go?.month === entry.month ? entry.go.tokens : 0)
  const goItems = entry => (entry.go?.day === entry.day ? entry.go.items : 0)
  return {
    /** Go's answer `{month, charged_tokens, items_today}`; a malformed one is ignored. */
    fromGo(id, answer) {
      const entry = book(id)
      if (!answer || answer.month !== entry.month || !isCount(answer.charged_tokens) || !isCount(answer.items_today)) return
      entry.go = { month: answer.month, tokens: answer.charged_tokens, day: entry.day, items: answer.items_today }
    },
    /**
     * The limit a call made now would pass, or null when it may be made:
     * `month` when the month's tokens reached the cap (`min(bundle, Go's)`),
     * else `day` when the day's items reached `request_items_per_day`.
     */
    limit(record, status) {
      const entry = book(record.connection_id)
      const goCap = status?.ai_off?.monthly_tokens
      const cap = Number.isSafeInteger(goCap) && goCap > 0 ? Math.min(record.budget.monthly_tokens, goCap) : record.budget.monthly_tokens
      if (Math.max(entry.tokens, goTokens(entry)) >= cap) return 'month'
      if (Math.max(entry.items, goItems(entry)) >= record.budget.request_items_per_day) return 'day'
      return null
    },
    /** Whether a call may be made now (`limit` is null). */
    allows(record, status) { return this.limit(record, status) === null },
    /** One attempt at a provider call (counted before it leaves, whatever its answer). */
    item(id) { book(id).items++ },
    charge(id, tokens) { book(id).tokens += tokens },
    used(id) { const entry = book(id); return { tokens: Math.max(entry.tokens, goTokens(entry)), items: Math.max(entry.items, goItems(entry)) } },
    forget(id) { books.delete(id) },
    clear() { books.clear() },
  }
}
