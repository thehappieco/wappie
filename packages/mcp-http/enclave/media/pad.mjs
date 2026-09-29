// Response padding for media connections (docs/mcp-enclave.md §16.10). The
// parent sees TLS record lengths, and an attachment's result size says a lot
// about the attachment; so every /mcp response of a media connection is
// padded with trailing spaces, which JSON allows after its value, to the
// smallest PAD_BUCKETS size at least its length, or past the last bucket to
// the next multiple of 512 KiB.
import { PAD_BUCKETS } from './policy.mjs'

const BEYOND = 524_288

/** The padded length of a body of `length` bytes. */
export function paddedLength(length) {
  return PAD_BUCKETS.find(bucket => bucket >= length) ?? Math.ceil(length / BEYOND) * BEYOND
}

/**
 * The same response with its body padded and Content-Length set to match. A
 * response without a body, and an event stream (a `subscriptions/listen`
 * stream never ends, and carries notifications, never a result), are left as
 * they are.
 */
export async function padResponse(response) {
  if (!response.body || (response.headers.get('content-type') ?? '').startsWith('text/event-stream')) return response
  const body = Buffer.from(await response.arrayBuffer())
  const padded = Buffer.alloc(paddedLength(body.length), 0x20)
  body.copy(padded)
  const headers = new Headers(response.headers)
  headers.set('content-length', String(padded.length))
  return new Response(padded, { status: response.status, statusText: response.statusText, headers })
}
