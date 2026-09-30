// Every limit of sending (docs/mcp-enclave.md §17.10), as frozen constants of
// the image. Like constants.mjs this file is measured into PCR0: nothing here
// is read from the environment, a request or Go. They are the ceilings of
// Go's WS_MCP_SEND_* settings (§17.3): the operator can lower a limit there,
// never raise one, and the enclave keeps its own count of what it can see.
// The reader's schemas (packages/mcp/server.mjs) repeat the two text bounds,
// and a test holds them equal.

/** A draft's life: it expires, unsent, a day after it was written. */
export const DRAFT_TTL_MS = 86_400_000
/** Drafts per connection in any rolling hour (the enclave counts too). */
export const DRAFTS_PER_HOUR = 30
/** Pending drafts per connection: Go counts them, the enclave passes Go's 429 on. */
export const DRAFTS_PENDING_MAX = 20
/** A draft's text, in UTF-16 code units. */
export const DRAFT_TEXT_MAX_CHARS = 4_096
/** A draft's envelope; Go refuses a larger one. */
export const DRAFT_SEALED_MAX_BYTES = 16_384
/** An own-chat send's text, in UTF-16 code units. */
export const SELF_TEXT_MAX_CHARS = 1_000
/** Own-chat (and, from S3, direct) sends per connection in any rolling 24 hours. */
export const SENDS_PER_DAY = 20
/** The least time between two sends of a connection. */
export const SEND_MIN_INTERVAL_MS = 30_000
/** How long an identical call answers what the first one did (§17.11). */
export const DEDUPE_WINDOW_MS = 600_000
/**
 * The cross-chat fingerprints (§17.11): their life; the per-connection
 * budgets, one for shingles and one for entities, which shingles never
 * evict; the shingle width; the shingles one text may add; how much of a
 * text is fingerprinted (its first and last halves of this many code units);
 * and the chats a draft names.
 */
export const FP_TTL_MS = 3_600_000
export const FP_SHINGLES_PER_CONNECTION = 20_000
export const FP_ENTITIES_PER_CONNECTION = 5_000
export const FP_SHINGLE_WORDS = 8
export const FP_SHINGLES_PER_TEXT = 2_000
export const FP_TEXT_MAX_CHARS = 16_384
export const FP_CROSS_CHAT_MAX = 5
/** Items per list_outgoing page. */
export const LIST_OUTGOING_MAX = 50

/**
 * How long the enclave waits for Go on each route. A send's covers Go's own
 * minute for the send and its record, so a lost answer is a real loss, which
 * is send_uncertain and is never repeated.
 */
export const DRAFT_ROUTE_TIMEOUT_MS = 15_000
export const SEND_ROUTE_TIMEOUT_MS = 75_000
export const LEDGER_ROUTE_TIMEOUT_MS = 10_000
