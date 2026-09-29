// Response padding for media connections (docs/mcp-enclave.md §16.10). The
// parent sees TLS record lengths, and an attachment's result size says a lot
// about the attachment; so every /mcp response of a media connection is
// buffered whole and padded to the smallest PAD_BUCKETS size at least its
// length, or past the last bucket to the next multiple of 512 KiB. A JSON
// body takes trailing spaces, which JSON allows after its value. An event
// stream (the SDK answers 2025-era clients in SSE whatever its response mode)
// takes a trailing comment line, which every SSE parser ignores.
import { PAD_BUCKETS } from './policy.mjs'

const BEYOND = 524_288

/** The padded length of a body of `length` bytes. */
export function paddedLength(length) {
  return PAD_BUCKETS.find(bucket => bucket >= length) ?? Math.ceil(length / BEYOND) * BEYOND
}

/**
 * The same response with its body padded and Content-Length set to match; a
 * response without a body is left as it is. The caller never passes a
 * `subscriptions/listen` stream, which never ends and carries notifications
 * only (router.mjs).
 */
export async function padResponse(response) {
  if (!response.body) return response
  const body = Buffer.from(await response.arrayBuffer())
  const padded = Buffer.alloc(paddedLength(body.length), 0x20)
  body.copy(padded)
  if ((response.headers.get('content-type') ?? '').startsWith('text/event-stream') && padded.length > body.length) {
    // `:` and spaces, then the line's end: a comment. One byte is an empty line, which dispatches nothing after a complete event.
    if (padded.length - body.length > 1) padded[body.length] = 0x3a
    padded[padded.length - 1] = 0x0a
  }
  const headers = new Headers(response.headers)
  headers.delete('transfer-encoding')
  headers.set('content-length', String(padded.length))
  return new Response(padded, { status: response.status, statusText: response.statusText, headers })
}
