// The ciphertext of one attachment (docs/mcp-enclave.md §16.5, an open's step
// 2): `GET /v1/media/{uid}` on the archive with the connection's own API key,
// through the enclave's own TLS (`/etc/hosts` sends the archive's name to the
// vsock bridge; the parent only pipes bytes). Go's gate lets only a media
// connection's key through, and serves the blob the WhatsApp CDN served,
// verbatim: nothing here trusts it until wamedia-stream has checked it.
import { ArchiveError } from '@whatserver2/client'
import { refusal } from './gate.mjs'
import { objectLength, MIN_OBJECT } from './wamedia-stream.mjs'
import { FETCH_TIMEOUT_MS } from './policy.mjs'

/**
 * Streams the ciphertext of `uid` into the sink `begin(n)` returns once the
 * length `n` is known and charged (`charge(n)` throws `rate_limited` when the
 * hour has no room). `cap` is the family's plaintext cap. Throws the §16.7
 * refusal; an abort through `signal` (a wipe) ends the request, and the
 * caller, which owns `signal`, knows it for what it is.
 */
export async function fetchCiphertext({ fetch = globalThis.fetch, archive, uid, apiKey, cap, family, signal, charge, begin }) {
  const deadline = AbortSignal.timeout(FETCH_TIMEOUT_MS)
  const both = signal ? AbortSignal.any([signal, deadline]) : deadline
  let response
  try {
    response = await fetch(new URL(`/v1/media/${uid}`, archive), {
      method: 'GET', headers: { authorization: `Bearer ${apiKey}`, 'accept-encoding': 'identity' },
      redirect: 'error', cache: 'no-store', credentials: 'omit', signal: both,
    })
  } catch { throw refusal('read_failed') }
  const cancel = () => response.body?.cancel().catch(() => {})
  if (response.status !== 200) {
    await cancel()
    if (response.status === 409) throw refusal('attachment_pending')
    if (response.status === 404) throw refusal('attachment_not_found')
    if (response.status === 401) throw new ArchiveError('unauthorized', 401)
    throw refusal('read_failed')
  }
  const encoding = response.headers.get('content-encoding')
  const declared = response.headers.get('content-length')
  if ((encoding !== null && encoding.trim().toLowerCase() !== 'identity') || declared === null || !/^\d{1,15}$/.test(declared.trim())) { await cancel(); throw refusal('read_failed') }
  const n = Number(declared.trim())
  if (!objectLength(n)) { await cancel(); throw refusal('attachment_tampered') }
  if (n > cap + MIN_OBJECT) { await cancel(); throw refusal('attachment_too_large', { facts: { size: n - MIN_OBJECT, cap, family } }) }
  try { charge(n) } catch (error) { await cancel(); throw error }
  const sink = begin(n)
  let received = 0
  try {
    for await (const chunk of response.body ?? []) {
      received += chunk.length
      // A byte past the length it declared: the stream stops here.
      if (received > n) { chunk.fill(0); throw refusal('attachment_tampered') }
      sink.update(chunk)
    }
  } catch (error) {
    await cancel()
    if (error instanceof ArchiveError) throw error
    throw refusal('read_failed')
  }
  if (received !== n) throw refusal('attachment_tampered')
  return n
}
