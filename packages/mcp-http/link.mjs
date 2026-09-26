// The consent link: the descriptor the console reads, the sealed bundle Go
// relays, and the HMAC proof the browser posts back. The bundle is opened
// twice (once to validate on arrival, once to serve the proof) and the
// plaintext bytes are zeroed both times; only the connection's API key
// outlives the handshake, inside the encrypted state.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import * as z from 'zod/v4'
import { hpke } from '@whatserver2/client'
import { validateBundle } from '@whatserver2/mcp/bundle'
import { LocalConfigError } from '@whatserver2/mcp/config'
import { validTimezone } from '@whatserver2/mcp/time'

export const INFO = Buffer.from('wappie-mcp-connect/v1')
export const PROOF_LABEL = Buffer.from('wappie-mcp-link/v1')
export const MAX_SEALED_CHARS = 64 * 1024
export const MAX_PROOF_ATTEMPTS = 3
const ENC_LEN = 32, TAG_LEN = 16
const linkSecretShape = /^[A-Za-z0-9_-]{43}$/
const lower = value => value.toLowerCase()

export class LinkError extends Error {
  constructor(code, status = 400) { super(code); this.name = 'LinkError'; this.code = code; this.status = status }
}

/** Additional data binding a bundle to one request, one reader key and one resource. */
export const aadFor = (requestID, kid, resource) => Buffer.from(JSON.stringify(['wappie/mcp-connect', 1, requestID, kid, resource]))

const uuid = z.string().uuid().transform(lower)
export const bundleBody = z.strictObject({
  connection_id: uuid, tenant_id: uuid,
  kid: z.string().regex(/^[0-9a-f]{16}$/),
  sealed: z.string().min(64).max(MAX_SEALED_CHARS).regex(/^[A-Za-z0-9_-]+$/),
  expires_at: z.string().min(20).max(40),
})

/** The key a request's bundle is sealed to: its own when it has one (the enclave), else the reader's. */
const recipientOf = (pending, state) => pending.recipient ?? state.recipient

/** The public descriptor for a pending request, relayed verbatim by Go. */
export function descriptor(pending, state) {
  const recipient = recipientOf(pending, state)
  return {
    request_id: pending.id, kid: recipient.kid, reader_public_key: recipient.publicKeyEncoded,
    client_id: pending.client_id, client_name: pending.client_name, redirect_host: pending.redirect_host, redirect_local: pending.redirect_local === true,
    code_challenge: pending.code_challenge, resource: pending.resource, expires_at: new Date(pending.expires_at).toISOString(),
  }
}

/**
 * Opens a sealed bundle for `pending` and checks every hosted invariant.
 * Returns the validated bundle; JavaScript strings cannot be zeroed, so the
 * caller keeps the result only as long as it needs the API key and link secret.
 */
export async function openBundle(state, pending, sealed, kid) {
  // A request with its own key accepts nothing else: a bundle sealed to any
  // other key was not sealed to what the console verified.
  const candidates = pending.recipient ? [pending.recipient] : [state.recipient, state.previous]
  const recipient = candidates.find(candidate => candidate && candidate.kid === kid)
  if (!recipient) throw new LinkError('unknown_kid')
  if (sealed.length < ENC_LEN + TAG_LEN) throw new LinkError('invalid_bundle')
  let plain
  try {
    plain = await hpke.open(recipient.privateKey, new Uint8Array(sealed.subarray(0, ENC_LEN)), new Uint8Array(INFO),
      new Uint8Array(aadFor(pending.id, kid, pending.resource)), new Uint8Array(sealed.subarray(ENC_LEN)))
  } catch { throw new LinkError('invalid_bundle') }
  try {
    let value
    try { value = JSON.parse(Buffer.from(plain).toString('utf8')) } catch { throw new LinkError('invalid_bundle') }
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new LinkError('invalid_bundle')
    let bundle
    try { ({ bundle } = await validateBundle(value)) } catch (error) {
      if (error instanceof LocalConfigError) throw new LinkError('invalid_bundle')
      throw error
    }
    // Hosted readers are metadata-only by construction: no plaintext opt-in,
    // no service identity or key, no contact snapshot, and a link secret.
    if (bundle.allow_plaintext !== false || bundle.service_user_id !== undefined || bundle.service_private_key !== undefined ||
      bundle.contacts !== undefined || typeof bundle.link_secret !== 'string' || !linkSecretShape.test(bundle.link_secret) ||
      Buffer.from(bundle.link_secret, 'base64url').toString('base64url') !== bundle.link_secret) throw new LinkError('invalid_bundle')
    // The console derives server_url from the descriptor's resource; anything else is a swapped descriptor.
    if (bundle.server_url !== new URL(pending.resource).origin) throw new LinkError('invalid_bundle')
    if (bundle.workspace_id !== pending.tenant_id) throw new LinkError('invalid_bundle')
    if (bundle.timezone !== undefined && !validTimezone(bundle.timezone)) throw new LinkError('invalid_bundle')
    return bundle
  } finally { plain.fill(0) }
}

/** The expected proof for a request: HMAC-SHA256 under the link secret over the bound fields. */
export function proofFor(linkSecret, { requestID, clientID, codeChallenge, sealed }) {
  const zero = Buffer.from([0])
  const message = Buffer.concat([PROOF_LABEL, zero, Buffer.from(requestID), zero, Buffer.from(clientID), zero,
    Buffer.from(codeChallenge), zero, createHash('sha256').update(sealed).digest()])
  return createHmac('sha256', linkSecret).update(message).digest()
}
export function proofMatches(expected, presented) {
  if (typeof presented !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(presented)) return false
  const given = Buffer.from(presented, 'base64url')
  return given.length === expected.length && timingSafeEqual(given, expected)
}
/** The same work as a real verification, for requests that name nothing. */
export function dummyProof() {
  proofMatches(proofFor(randomBytes(32), { requestID: '', clientID: '', codeChallenge: '', sealed: Buffer.alloc(0) }), randomBytes(32).toString('base64url'))
}

/**
 * Whether `connectionID` already names something here: a connection, or the
 * bundle of another request (attached, or being accepted right now, which
 * `pending.accepting` holds the relayed id for). Go picks the id, so a relay
 * reusing one would bind a new consent to a connection whose tokens someone
 * else already holds; the relay routes refuse it before opening anything.
 */
export function connectionTaken(state, pending, connectionID) {
  if (state.connections.has(connectionID) || state.activating?.has(connectionID)) return true
  for (const other of state.pending.values()) {
    if (other !== pending && (other.connection_id === connectionID || other.accepting === connectionID)) return true
  }
  return false
}

/**
 * Attaches the bundle Go relayed to its pending request after validating it
 * end to end. Throws LinkError with the status the internal route answers.
 * While the bundle opens, `pending.accepting` holds the relayed connection id:
 * a second relay for the request is 409 and one naming that id for another
 * request is refused, however the two interleave.
 */
export async function acceptBundle(state, pending, body, { now = Date.now } = {}) {
  const parsed = bundleBody.safeParse(body)
  if (!parsed.success) throw new LinkError('bad_request')
  const { connection_id, tenant_id, kid, sealed: encoded, expires_at } = parsed.data
  if (pending.bundle || pending.accepting) throw new LinkError('bundle_exists', 409)
  if (connectionTaken(state, pending, connection_id)) throw new LinkError('bad_request')
  const sealed = Buffer.from(encoded, 'base64url')
  if (sealed.toString('base64url') !== encoded) throw new LinkError('bad_request')
  const expiry = Date.parse(expires_at)
  if (!Number.isFinite(expiry) || expiry <= now() || expiry > now() + 366 * 24 * 3_600_000) throw new LinkError('bad_request')
  pending.accepting = connection_id
  pending.tenant_id = tenant_id
  try { await openBundle(state, pending, sealed, kid) } catch (error) { delete pending.tenant_id; throw error } finally { delete pending.accepting }
  pending.bundle = { sealed, kid, connection_id, expires_at: new Date(expiry).toISOString() }
  pending.connection_id = connection_id
  return { connection_id }
}

/** Verifies a posted proof against the stored bundle; on success returns the opened bundle. */
export async function verifyProof(state, pending, proof) {
  const bundle = await openBundle(state, pending, pending.bundle.sealed, pending.bundle.kid)
  const secret = Buffer.from(bundle.link_secret, 'base64url')
  try {
    const expected = proofFor(secret, { requestID: pending.id, clientID: pending.client_id, codeChallenge: pending.code_challenge, sealed: pending.bundle.sealed })
    return proofMatches(expected, proof) ? bundle : null
  } finally { secret.fill(0) }
}
