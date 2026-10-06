// Pending AI requests (docs/mcp-enclave.md §18.7 step 1): an owner or admin
// starts an AI authorization in the console, Go relays `POST
// /internal/ai/requests {"nonce"}`, and the enclave mints a key for it alone
// and attests it. The request lives in this process's memory for
// PENDING_TTL_MS; at most AI_REQUESTS_PENDING_MAX live at once. Its bundle
// is sealed to that key; nothing else ever is.
import { randomBytes } from 'node:crypto'
import { LinkError } from '../../link.mjs'
import { AI_REQUESTS_PENDING_MAX } from './policy.mjs'

/**
 * `newRecipient()` mints the key, `attestor.attestation({requestId,
 * publicKey, nonce})` the document; `ttlMs` is PENDING_TTL_MS. With
 * `attestWhole` (reader 0.6.0, §19.12) the descriptor is version 2 and the
 * document binds all of it (user_data v2).
 */
export function createAIRequests({ now = Date.now, ttlMs, newRecipient, attestor, resource, readerVersion, max = AI_REQUESTS_PENDING_MAX, attestWhole = false }) {
  const requests = new Map()
  const live = request => request.expires_at > now()
  function sweep() { for (const [id, request] of requests) if (!live(request)) requests.delete(id) }
  return {
    /** A fresh request and its descriptor (§18.7 step 1); LinkError('too_many_prepares', 429) past the limit, AttestationError when the NSM fails. */
    async create(nonce) {
      sweep()
      if (requests.size >= max) throw new LinkError('too_many_prepares', 429)
      const recipient = await newRecipient()
      const id = randomBytes(16).toString('base64url')
      const expiresAt = now() + ttlMs
      const descriptor = {
        ...(attestWhole ? { descriptor_version: 2 } : {}), request_id: id, kind: 'ai', reader_public_key: recipient.publicKeyEncoded, kid: recipient.kid, resource,
        reader_version: readerVersion, expires_at: new Date(expiresAt).toISOString(),
      }
      const attestation = await attestor.attestation({ requestId: id, publicKey: recipient.publicKey, nonce, ...(attestWhole ? { descriptor } : {}) })
      if (requests.size >= max) throw new LinkError('too_many_prepares', 429)
      const request = { id, recipient, resource, created_at: now(), expires_at: expiresAt }
      requests.set(id, request)
      return { ...descriptor, attestation }
    },
    /** A live request, or undefined. */
    get(id) {
      const request = requests.get(id)
      if (request && !live(request)) { requests.delete(id); return undefined }
      return request
    },
    delete(id) { requests.delete(id) },
    /** Whether a request other than `except` holds, or is accepting, this connection id. */
    names(connectionID, except) {
      for (const request of requests.values()) if (request !== except && (request.connection_id === connectionID || request.accepting === connectionID)) return true
      return false
    },
    sweep,
    size: () => requests.size,
    clear() { requests.clear() },
  }
}
