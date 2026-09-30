import { createHash, createHmac, hkdfSync } from 'node:crypto'
import * as z from 'zod/v4'
import { bytes, hpke } from '@whatserver2/client'
import { openContactPack, validateContactPack } from '@whatserver2/client/crypto/contactPack'
import { canonicalJSON } from '@whatserver2/client/crypto/jcs'
import { archiveOrigin } from '@whatserver2/client'
import { LocalConfigError, validateConfig } from './config.mjs'
import { validTimezone } from './time.mjs'

const id = z.string().uuid().transform(value => value.toLowerCase())
/**
 * The browser setup bundle. `link_secret` belongs to the hosted connector flow
 * only (it travels inside the sealed bundle); the local setup import refuses it.
 */
export const bundleSchema = z.strictObject({
  version: z.literal(1),
  server_url: z.string().min(1).max(4096), workspace_id: id,
  device_ids: z.array(id).min(1).max(1000),
  token: z.string().length(52), allow_plaintext: z.boolean(),
  service_user_id: id.optional(), service_private_key: z.string().length(43).optional(),
  timezone: z.string().min(1).max(100).optional(), contacts: z.unknown().optional(),
  link_secret: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional(),
})
function fail(code) { throw new LocalConfigError(code) }
function canonicalKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false
  const decoded = Buffer.from(value, 'base64url')
  try { return decoded.length === 32 && decoded.toString('base64url') === value }
  finally { decoded.fill(0) }
}
/** Validates a parsed bundle and derives the file-mode config it maps to. */
export async function validateBundle(value) {
  const parsed = bundleSchema.safeParse(value)
  if (!parsed.success) fail('invalid_bundle')
  const bundle = parsed.data
  if (new Set(bundle.device_ids).size !== bundle.device_ids.length ||
    !/^[a-f0-9]{8}\./.test(bundle.token) || !canonicalKey(bundle.token.slice(9)) ||
    (bundle.service_private_key !== undefined && !canonicalKey(bundle.service_private_key)) ||
    (bundle.allow_plaintext && (!bundle.service_user_id || !bundle.service_private_key)) ||
    (!bundle.allow_plaintext && bundle.service_private_key !== undefined) ||
    (bundle.contacts !== undefined && !bundle.allow_plaintext)) fail('invalid_bundle')
  const output = {
    server: bundle.server_url, workspace: bundle.workspace_id, device_ids: bundle.device_ids,
    token_file: './token.txt', allow_plaintext: bundle.allow_plaintext,
    ...(bundle.service_user_id ? { service_user_id: bundle.service_user_id } : {}),
    ...(bundle.allow_plaintext ? { service_key_file: './service-key.txt' } : {}),
    ...(bundle.timezone ? { timezone: bundle.timezone } : {}),
    ...(bundle.contacts !== undefined ? { contacts_file: './contacts.enc.json' } : {}),
  }
  // Reuse the runtime's origin, identity and credential-mixing rules. Keep file
  // references relative in the saved config so the private directory is movable.
  const checked = validateConfig(output)
  output.server = checked.server
  if (bundle.contacts !== undefined) {
    const scope = { server_url:checked.server,workspace_id:bundle.workspace_id,service_user_id:bundle.service_user_id,device_ids:bundle.device_ids }
    let raw
    try {
      bundle.contacts = validateContactPack(bundle.contacts,scope)
      raw = Buffer.from(bundle.service_private_key,'base64url')
      // Authenticate and validate before creating any output. Names only exist
      // in memory; the durable file retains the original encrypted snapshot.
      await openContactPack(await hpke.importArchiveKey(raw),bundle.contacts,scope)
    } catch { fail('invalid_bundle') }
    finally { raw?.fill(0) }
  }
  return { bundle, output }
}

/**
 * The consent text versions a content bundle may be sealed under (the card the
 * user saw): 1, 2 from reader 0.4.0 on, which alone could carry `media`
 * (docs/mcp-enclave.md §16.2), and 3 from reader 0.5.0 on, the card with
 * sending, which may carry `media` too (§17.2).
 */
export const CONTENT_CONSENT_VERSIONS = Object.freeze([1, 2, 3])
/**
 * The sending modes this reader installs (§17.2 rule 2): drafts, with the
 * own-chat toggle riding on them (`send_draft_v1`). Direct send (`'direct'`,
 * `send_chats`, `send_signature`) is S3's `send_direct_v1`: this schema
 * refuses all three, so a direct consent fails closed here.
 */
export const SEND_MODES = Object.freeze(['draft'])
/** A content connection lasts at most 90 days; an hour of slack covers clocks and the consent itself. */
const MAX_CONTENT_AHEAD_MS = (90 * 24 + 1) * 60 * 60 * 1000
/**
 * The content bundle (v2) the console seals to an attested reader's
 * per-request key. It never carries a service private key, a contact snapshot
 * or a plaintext flag: the key lives only in the reader, contacts are out of
 * this phase, and content is what `kind` says. Those, like any unknown key, are
 * refused. v1's `validateBundle` accepts `version: 1` only, so no v1 path
 * (the pilot's link, the local import) can take one of these. `media: true`
 * (open attachments too) needs consent version 2 or 3; absent means false.
 * Version 3 is the card with sending (§17.2): `send`, and a device check per
 * number, come with it and only with it; `send_self` and `send_groups` only
 * with `send`.
 */
export const contentBundleSchema = z.strictObject({
  version: z.literal(2), kind: z.literal('content'), purpose: z.enum(['consent', 'renewal']),
  server_url: z.string().min(1).max(4096), workspace_id: id, service_user_id: id,
  device_ids: z.array(id).min(1).max(100),
  token: z.string().length(52),
  key_mode: z.literal('ephemeral'), consent_version: z.union(CONTENT_CONSENT_VERSIONS.map(version => z.literal(version))),
  media: z.boolean().optional(),
  send: z.enum(SEND_MODES).optional(),
  send_self: z.boolean().optional(),
  send_groups: z.boolean().optional(),
  device_checks: z.record(z.string().max(36), z.string().length(43)).optional(),
  expires_at: z.iso.datetime().max(40),
  timezone: z.string().min(1).max(100).optional(),
  link_secret: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional(),
  connection_id: id.optional(),
}).refine(bundle => bundle.media !== true || bundle.consent_version >= 2)
  .refine(bundle => (bundle.consent_version === 3) === (bundle.send !== undefined) && (bundle.send !== undefined) === (bundle.device_checks !== undefined))
  .refine(bundle => bundle.send !== undefined || (bundle.send_self === undefined && bundle.send_groups === undefined))
function httpsOrigin(value) {
  try { return value.startsWith('https://') && archiveOrigin(value) === value } catch { return false }
}
/**
 * Validates a parsed content bundle and returns it frozen; any failure is
 * `invalid_bundle`, with nothing of the input in the error. `now` is for tests.
 */
export function validateContentBundle(value, now = Date.now()) {
  const parsed = contentBundleSchema.safeParse(value)
  if (!parsed.success) fail('invalid_bundle')
  const bundle = parsed.data
  const expires = Date.parse(bundle.expires_at)
  if (!httpsOrigin(bundle.server_url) ||
    new Set(bundle.device_ids).size !== bundle.device_ids.length ||
    !/^[a-f0-9]{8}\./.test(bundle.token) || !canonicalKey(bundle.token.slice(9)) ||
    !Number.isFinite(expires) || expires <= now || expires > now + MAX_CONTENT_AHEAD_MS ||
    (bundle.timezone !== undefined && !validTimezone(bundle.timezone)) ||
    (bundle.purpose === 'consent' && (!canonicalKey(bundle.link_secret) || bundle.connection_id !== undefined)) ||
    (bundle.purpose === 'renewal' && (bundle.link_secret !== undefined || bundle.connection_id === undefined)) ||
    (bundle.device_checks !== undefined && !exactChecks(bundle.device_checks, bundle.device_ids))) fail('invalid_bundle')
  Object.freeze(bundle.device_ids)
  if (bundle.device_checks) Object.freeze(bundle.device_checks)
  return Object.freeze(bundle)
}

/** One canonical 43-character check per number, keyed by its id as the bundle writes it, and nothing else. */
function exactChecks(checks, devices) {
  const keys = Object.keys(checks)
  return keys.length === devices.length && devices.every(device => Object.hasOwn(checks, device) && canonicalKey(checks[device]))
}

/**
 * The device check (docs/mcp-enclave.md §17.2 rule 3). The creator's browser,
 * which holds every covered number's device key (DSK), binds the whole scope
 * of a version-3 consent to each number with a key derived from that DSK; the
 * enclave, which opens the same DSK from the grant it proves, recomputes it.
 * Go holds the grants and the per-request key is public, so without it Go
 * could seal a bundle of its own with a wider scope (sending, attachments,
 * another expiry) and relay it; with it only a holder of each DSK makes a
 * scope the enclave installs.
 */
export const DEVICE_CHECK_LABEL = 'wappie-mcp-device/v1'

/**
 * `scope[d]`: what one number's check covers. `request` is the consent's
 * request id or the renewal id, `kid` the attested key's id, `epoch` the
 * grant's. UUIDs are the bundle's (lower case), `expires_at` its string as
 * sealed; the lists are sorted and the direct-send fields (S3) are there,
 * empty, so the shape never changes.
 */
export function deviceScope(bundle, { deviceID, epoch, request, kid }) {
  return {
    workspace_id: bundle.workspace_id, device_id: deviceID, epoch, service_user_id: bundle.service_user_id, request, kid,
    device_ids: [...bundle.device_ids].sort(), expires_at: bundle.expires_at, consent_version: 3, media: bundle.media === true,
    send: bundle.send, send_self: bundle.send_self === true, send_groups: bundle.send_groups === true,
    send_chats: (bundle.send_chats ?? []).filter(chat => chat.device_id === deviceID).map(chat => chat.chat_key).sort(),
    send_signature: bundle.send_signature ?? null,
  }
}

/**
 * `device_checks[d]`, base64url: HMAC-SHA256 under HKDF-SHA256(DSK(d, e),
 * salt = the grant's namespace, info = label ‖ device ‖ u16be epoch) over
 * label ‖ 0x00 ‖ SHA-256(JCS(scope)). `dsk` is the 32 raw bytes, which the
 * caller owns and zeroes; the derived key is zeroed here.
 */
export function deviceCheck(dsk, { namespace, deviceID, epoch, scope }) {
  if (!(dsk instanceof Uint8Array) || dsk.length !== 32 || !Number.isInteger(epoch) || epoch < 1 || epoch > 65535) throw new LocalConfigError('invalid_bundle')
  const label = Buffer.from(DEVICE_CHECK_LABEL)
  const epochBytes = Buffer.alloc(2)
  epochBytes.writeUInt16BE(epoch)
  const key = Buffer.from(hkdfSync('sha256', dsk, bytes.parseUUID(namespace), Buffer.concat([label, bytes.parseUUID(deviceID), epochBytes]), 32))
  try {
    const digest = createHash('sha256').update(canonicalJSON(scope), 'utf8').digest()
    return createHmac('sha256', key).update(Buffer.concat([label, Buffer.from([0]), digest])).digest('base64url')
  } finally { key.fill(0) }
}
