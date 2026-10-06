// The consent link: the descriptor the console reads, the sealed bundle Go
// relays, and the HMAC proof the browser posts back. The bundle is opened
// twice (once to validate on arrival, once to serve the proof) and the
// plaintext bytes are zeroed both times; only the connection's API key
// outlives the handshake, inside the encrypted state.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import * as z from 'zod/v4'
import { hpke } from '@whatserver2/client'
import { validateBundle, validateLinkBundleV2 } from '@whatserver2/mcp/bundle'
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
/**
 * What Go relays for a request whose descriptor is version 2 (§19.15): the
 * tier the console was shown and the history window, which must equal what
 * the person sealed and what the pending request holds. Go never sends these
 * to an older reader.
 */
export const relayedClient = {
  trust: z.enum(['tested', 'unknown']), client_local: z.boolean(), history_days: z.number().int().min(1).max(366).nullable(),
}
export const bundleBodyV2 = bundleBody.extend(relayedClient)
/** The same three members alone, for a content relay (content.mjs parses the rest itself). */
export const relayedClientSchema = z.strictObject(relayedClient)

const DAY_MS = 24 * 3_600_000, HOUR_MS = 3_600_000
/** A request's limits: the tier's own, which the descriptor states and the console checks against the release (§19.12). */
const limitsOf = pending => pending.limits
/**
 * The workspace's live connections of clients nobody tested and console
 * tokens, with the requests whose consent is attached but not yet complete,
 * other than `pending` (§19.10: at most UNKNOWN_LIVE_MAX).
 */
export function unknownLive(state, tenant, pending) {
  let count = 0
  for (const record of state.connections.values()) if (record.tenant_id === tenant && (record.trust === 'unknown' || record.client_kind === 'token')) count++
  for (const other of state.pending.values()) if (other !== pending && other.bundle && other.tenant_id === tenant && other.trust === 'unknown') count++
  return count
}
/** The history window a v2 request's bundle may name: one of its tier's choices, or null for a tested client. */
export const historyAllowed = (pending, days) => (pending.trust === 'tested' ? days === null : limitsOf(pending).history_days?.choices.includes(days) === true)

/** The key a request's bundle is sealed to: its own when it has one (the enclave), else the reader's. */
const recipientOf = (pending, state) => pending.recipient ?? state.recipient

/**
 * The public descriptor for a pending request, relayed verbatim by Go. A
 * request a 0.6.0 reader made under the `any` policy has descriptor version 2
 * (§19.12, kind `connect`): every field the card shows, the full redirect and
 * the tier's limits, all bound by the attestation (user_data v2, §19.13).
 * `client_name` is a verified string there (the tested entry's name, else the
 * client's host), never what the client calls itself (`claimed_name`).
 */
export function descriptor(pending, state) {
  const recipient = recipientOf(pending, state)
  if (pending.descriptor_version === 2) {
    return {
      descriptor_version: 2, kind: 'connect', request_id: pending.id, kid: recipient.kid, reader_public_key: recipient.publicKeyEncoded,
      client_kind: pending.client_kind, client_id: pending.client_id, tested_id: pending.tested_id,
      client_host: pending.client_host, registrable: pending.registrable, shared_suffix: pending.shared_suffix, client_local: pending.client_local,
      client_name: pending.client_name, claimed_name: pending.claimed_name, name_dropped: pending.name_dropped,
      trust: pending.trust, drift: pending.drift,
      redirect_uri: pending.redirect_uri, redirect_host: pending.redirect_host, redirect_local: pending.redirect_local === true,
      limits_tier: pending.limits_tier, limits: structuredClone(limitsOf(pending)),
      code_challenge: pending.code_challenge, resource: pending.resource, expires_at: new Date(pending.expires_at).toISOString(),
    }
  }
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
    try { bundle = pending.descriptor_version === 2 ? validateLinkBundleV2(value) : (await validateBundle(value)).bundle } catch (error) {
      if (error instanceof LocalConfigError) throw new LinkError('invalid_bundle')
      throw error
    }
    // A link bundle v2 (§19.15) names the request's client and the tier the
    // card showed, carries the "I started this" tick (its schema's literal)
    // and a history window the tier allows; a new consent to 0.6.0 is never
    // a version-1 bundle, which validateLinkBundleV2 refuses.
    if (pending.descriptor_version === 2 && (bundle.client_id !== pending.client_id || bundle.trust !== pending.trust ||
      bundle.started_ack !== true || !historyAllowed(pending, bundle.history_days))) throw new LinkError('invalid_bundle')
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
export async function acceptBundle(state, pending, body, { now = Date.now, unknownLiveMax } = {}) {
  const v2 = pending.descriptor_version === 2
  const parsed = (v2 ? bundleBodyV2 : bundleBody).safeParse(body)
  if (!parsed.success) throw new LinkError('bad_request')
  const { connection_id, tenant_id, kid, sealed: encoded, expires_at } = parsed.data
  if (pending.bundle || pending.accepting) throw new LinkError('bundle_exists', 409)
  if (connectionTaken(state, pending, connection_id)) throw new LinkError('bad_request')
  const sealed = Buffer.from(encoded, 'base64url')
  if (sealed.toString('base64url') !== encoded) throw new LinkError('bad_request')
  const expiry = Date.parse(expires_at)
  // The ceiling of a v2 request is its tier's (§19.19), 0.5.0's year and a day otherwise.
  const ceiling = v2 ? limitsOf(pending).ceiling_hours.metadata * HOUR_MS : 366 * DAY_MS
  if (!Number.isFinite(expiry) || expiry <= now() || expiry > now() + ceiling) throw new LinkError('bad_request')
  // What Go relays about the client must be what this reader classified.
  if (v2 && (parsed.data.trust !== pending.trust || parsed.data.client_local !== pending.client_local)) throw new LinkError('invalid_bundle')
  if (v2 && pending.trust === 'unknown' && unknownLive(state, tenant_id, pending) >= unknownLiveMax) throw new LinkError('too_many_unknown', 409)
  pending.accepting = connection_id
  pending.tenant_id = tenant_id
  let bundle
  try { bundle = await openBundle(state, pending, sealed, kid) } catch (error) { delete pending.tenant_id; throw error } finally { delete pending.accepting }
  if (v2 && bundle.history_days !== parsed.data.history_days) { delete pending.tenant_id; throw new LinkError('invalid_bundle') }
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
