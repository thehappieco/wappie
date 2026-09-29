// Every limit of attachments stage A (docs/mcp-enclave.md §16.8), as frozen
// constants of the image. Like constants.mjs this file is measured into PCR0:
// nothing here is read from the environment, a request or Go. The job header
// (§16.11) copies a worker's limits from here, media-jail's compiled-in table
// (§16.6) repeats WORKERS and is checked against it at boot, and the notes the
// reader writes (packages/mcp/server.mjs) quote the values as written.
const freeze = value => Object.freeze(value)

/** Go's kinds (§16.3); a `media_off` word outside them is ignored. */
export const MEDIA_KINDS = freeze(['image', 'pdf', 'office', 'text', 'zip', 'audio', 'video'])
/** The allowlist of `media_type`s and their HKDF labels (§16.5). */
export const MEDIA_TYPES = freeze({
  image: freeze({ family: 'image', label: 'WhatsApp Image Keys' }),
  sticker: freeze({ family: 'image', label: 'WhatsApp Image Keys' }),
  video: freeze({ family: 'video', label: 'WhatsApp Video Keys' }),
  ptv: freeze({ family: 'video', label: 'WhatsApp Video Keys' }),
  audio: freeze({ family: 'audio', label: 'WhatsApp Audio Keys' }),
  ptt: freeze({ family: 'audio', label: 'WhatsApp Audio Keys' }),
  document: freeze({ family: 'document', label: 'WhatsApp Document Keys' }),
})
/** The plaintext, by the claimed `file_length` and by `Content-Length − 26`. */
export const CAP_BYTES = freeze({ image: 16_777_216, document: 33_554_432 })
/** An opened video preview. */
export const THUMB_MAX_BYTES = 262_144
export const TEXT_MIMETYPES = freeze(['text/plain', 'text/csv', 'text/markdown', 'application/json'])
/** Bytes searched for NUL by the plain-text rule. */
export const TEXT_SNIFF_BYTES = 8_192
export const FILENAME_MAX_CHARS = 255
export const CAPTION_MAX_CHARS = 1_000

export const IMAGE_MAX_PIXELS = 40_000_000
export const IMAGE_LONG_EDGE = 1_568
export const IMAGE_FALLBACK_EDGE = 1_024
export const JPEG_QUALITIES = freeze([80, 70, 60])
export const IMAGE_MAX_BYTES = 307_200
export const STICKER_EDGES = freeze([512, 384, 256])
export const STICKER_LONG_EDGE = 512
export const STICKER_MAX_BYTES = 102_400
export const IMAGES_PER_RESULT = 4
export const IMAGES_TOTAL_BYTES = 921_600

export const PART_MAX_CHARS = 60_000
export const RESULT_MAX_BYTES = 1_572_864
export const JOB_TEXT_MAX_BYTES = 4_194_304

export const PDF_MAX_PAGES = 2_000
export const PDF_PAGES_PER_JOB = 300
export const PDF_PAGES_PER_REQUEST = 4
export const PDF_SCANNED_BELOW = 50
export const PDF_MAX_IMAGE_PIXELS = 16_000_000

export const ZIP_MAX_ENTRIES = 2_000
export const ZIP_MAX_INFLATED = 104_857_600
export const ZIP_MAX_RATIO = 100
export const ZIP_LISTED = 200
export const SHEETS_MAX = 50
export const SHEET_ROWS = 2_000

/** Admitted opens per connection, rolling 60 s (the /mcp limit of 60 calls a minute still applies). */
export const OPENS_PER_MINUTE = 10
/**
 * Opens of one connection waiting behind its own, first in first out: a
 * connection holds one place in the slot's queue at a time, so parallel calls
 * wait their turn here rather than fill the queue other connections share.
 */
export const OPENS_QUEUE_MAX = 4
/** Ciphertext fetched per connection, rolling hour. */
export const BYTES_PER_HOUR = 268_435_456
/** Opens running at once, enclave-wide: the light slot. */
export const SLOTS = 1
/** Opens waiting for the slot, enclave-wide, first in first out. */
export const QUEUE = 4
/** The inline wait, from the call's start, by the assistant's host (§16.7). */
export const HOST_WAIT_MS = freeze({ 'chatgpt.com': 25_000, 'claude.ai': 40_000, default: 25_000 })
/** The only `retry_after_s` values. */
export const RETRY_AFTER_S = freeze([5, 10, 20, 40, 60])
/** The ciphertext request, headers to last byte. */
export const FETCH_TIMEOUT_MS = 60_000

/** Each job's memcg, wall, process and /tmp limits; `media-jail --table`'s `max`. */
export const WORKERS = freeze({
  image: freeze({ mem_mb: 256, wall_s: 10, pids: 64, tmp_mb: 16 }),
  pdf: freeze({ mem_mb: 384, wall_s: 20, pids: 64, tmp_mb: 16 }),
  office: freeze({ mem_mb: 384, wall_s: 15, pids: 64, tmp_mb: 16 }),
})
export const JAIL_BIN = '/usr/local/bin/media-jail'
export const JAIL_SLOT = 'light'
export const JAIL_CPUS = '0'
/** Added to `wall_s` for the reader's own watchdog. */
export const JAIL_WATCHDOG_MS = 5_000
/** From SIGTERM to SIGKILL of media-jail. */
export const JAIL_TERM_GRACE_MS = 5_000
/** The job header on a worker's stdin (§16.11). */
export const STDIN_HEADER_MAX = 4_096
/** Payload bytes per stdout frame type (§16.11). */
export const FRAME_MAX = freeze({ 1: 16_384, 2: 65_536, 3: 512, 4: 2 + IMAGE_MAX_BYTES, 8: 256, 9: 64 })

/** A finished open's answer, from completion. */
export const RESULT_TTL_MS = 600_000
/** An attachment's text, from its job. */
export const TEXT_TTL_MS = 3_600_000
/** Both caches, per connection. */
export const CACHE_CONNECTION_BYTES = 16_777_216
/** Both caches, enclave-wide. */
export const CACHE_ENCLAVE_BYTES = 33_554_432
/** /mcp response sizes on media connections. */
export const PAD_BUCKETS = freeze([16_384, 32_768, 65_536, 131_072, 262_144, 524_288, 1_048_576, 1_572_864, 2_097_152])
/** MemAvailable sampling for the health line. */
export const MEM_SAMPLE_MS = 1_000
