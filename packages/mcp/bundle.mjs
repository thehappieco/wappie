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
 * The link bundle v2 (docs/mcp-enclave.md §19.15): a metadata consent to a
 * reader 0.6.0, the setup bundle's sibling with the client it was given to,
 * the tier the card showed, the "I started this" tick and the history window
 * the person chose (null: the whole history, for a tested client only). It
 * has no number keys, so the enclave applies the tier from its own pending
 * request and the bundle can only narrow the history. validateBundle takes
 * `version: 1` only, so no 0.5.0 path opens one of these.
 */
export const linkBundleV2Schema = z.strictObject({
  version: z.literal(2), kind: z.literal('metadata'),
  server_url: z.string().min(1).max(4096), workspace_id: id,
  device_ids: z.array(id).min(1).max(1000),
  token: z.string().length(52), allow_plaintext: z.literal(false),
  timezone: z.string().min(1).max(100).optional(),
  link_secret: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  client_id: z.string().min(1).max(512), trust: z.enum(['tested', 'unknown']), started_ack: z.literal(true),
  history_days: z.number().int().min(1).max(366).nullable(),
})
/** Validates a parsed link bundle v2 and returns it frozen; any failure is `invalid_bundle`. */
export function validateLinkBundleV2(value) {
  const parsed = linkBundleV2Schema.safeParse(value)
  if (!parsed.success) fail('invalid_bundle')
  const bundle = parsed.data
  // As for version 1, the archive origin may be loopback http (a local test); the enclave checks it is the resource's.
  if (!sameOrigin(bundle.server_url) || new Set(bundle.device_ids).size !== bundle.device_ids.length ||
    !/^[a-f0-9]{8}\./.test(bundle.token) || !canonicalKey(bundle.token.slice(9)) || !canonicalKey(bundle.link_secret) ||
    Buffer.byteLength(bundle.client_id, 'utf8') > 512 || (bundle.timezone !== undefined && !validTimezone(bundle.timezone))) fail('invalid_bundle')
  Object.freeze(bundle.device_ids)
  return Object.freeze(bundle)
}

/**
 * A network as a console connection token's `allowed_networks` writes it
 * (docs/mcp-enclave.md §19.15): `198.51.100.0/24` or `2001:db8::/48`, in its
 * canonical form only, the address part with no bit past the prefix set:
 * IPv4 as four decimal octets without leading zeros, IPv6 as RFC 5952 §4
 * writes it (lower case, no leading zeros, the longest run of two or more
 * zero groups as `::`, the first of equal runs). `{family, bytes, prefix}`,
 * or null for anything else.
 */
export function parseCIDR(text) {
  if (typeof text !== 'string' || text.length > 49) return null
  const slash = text.indexOf('/')
  if (slash < 0) return null
  const address = parseAddress(text.slice(0, slash)), bits = text.slice(slash + 1)
  if (!address || !/^(?:0|[1-9][0-9]{0,2})$/.test(bits)) return null
  const prefix = Number(bits)
  if (prefix > address.bytes.length * 8) return null
  for (let bit = prefix; bit < address.bytes.length * 8; bit++) if (address.bytes[bit >> 3] & (0x80 >> (bit & 7))) return null
  const network = { family: address.family, bytes: address.bytes, prefix }
  return formatAddress(address) === text.slice(0, slash) ? network : null
}
/** An IP address as `{family: 4 | 6, bytes}` (an IPv4-mapped IPv6 address as IPv4), or null. */
export function parseAddress(text) {
  if (typeof text !== 'string') return null
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text)
  if (v4) {
    const bytes = v4.slice(1).map(Number)
    return bytes.every(value => value <= 255) ? { family: 4, bytes: Uint8Array.from(bytes) } : null
  }
  if (!/^[0-9A-Fa-f:.]{2,45}$/.test(text) || (text.match(/::/g) ?? []).length > 1) return null
  let head = text, tail4 = null
  const dotted = /^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(text)
  if (dotted) { tail4 = parseAddress(dotted[2]); if (!tail4) return null; head = dotted[1] + '0:0' }
  const [left, right] = head.includes('::') ? head.split('::') : [head, null]
  const groups = part => (part === '' ? [] : part.split(':'))
  const leftGroups = groups(left), rightGroups = right === null ? [] : groups(right)
  const missing = 8 - leftGroups.length - rightGroups.length
  if (right === null ? missing !== 0 : missing < 1) return null
  const all = [...leftGroups, ...Array(right === null ? 0 : missing).fill('0'), ...rightGroups]
  if (all.some(group => !/^[0-9A-Fa-f]{1,4}$/.test(group))) return null
  const bytes = new Uint8Array(16)
  all.forEach((group, index) => { const value = parseInt(group, 16); bytes[index * 2] = value >> 8; bytes[index * 2 + 1] = value & 0xff })
  if (tail4) bytes.set(tail4.bytes, 12)
  if (bytes.subarray(0, 10).every(value => value === 0) && bytes[10] === 0xff && bytes[11] === 0xff) return { family: 4, bytes: bytes.slice(12) }
  return { family: 6, bytes }
}
/** The canonical text of an address parseAddress returned (IPv6 by RFC 5952 §4, without the mixed IPv4 form). */
export function formatAddress({ family, bytes }) {
  if (family === 4) return [...bytes].join('.')
  const groups = Array.from({ length: 8 }, (_, index) => (bytes[index * 2] << 8) | bytes[index * 2 + 1])
  let best = -1, length = 0
  for (let start = 0; start < 8; start++) {
    let end = start
    while (end < 8 && groups[end] === 0) end++
    if (end - start > length && end - start >= 2) { best = start; length = end - start }
  }
  const text = groups.map(group => group.toString(16))
  return best < 0 ? text.join(':') : `${text.slice(0, best).join(':')}::${text.slice(best + length).join(':')}`
}
/** Whether `address` (parseAddress's) lies in `network` (parseCIDR's); never across families. */
export function inNetwork(address, network) {
  if (!address || !network || address.family !== network.family) return false
  for (let bit = 0; bit < network.prefix; bit++) {
    const mask = 0x80 >> (bit & 7)
    if ((address.bytes[bit >> 3] & mask) !== (network.bytes[bit >> 3] & mask)) return false
  }
  return true
}
/** `allowed_networks`: 0 to 10 canonical networks, unique, sorted as strings. */
const allowedNetworks = z.array(z.string().max(49)).max(10)
  .refine(list => list.every(item => parseCIDR(item) !== null) && new Set(list).size === list.length && list.every((item, index) => index === 0 || list[index - 1] < item))

/**
 * The consent text versions a content bundle may be sealed under (the card the
 * user saw): 1, 2 from reader 0.4.0 on, which alone could carry `media`
 * (docs/mcp-enclave.md §16.2), 3 from reader 0.5.0 on, the card with
 * sending, which may carry `media` too (§17.2), and 4 from reader 0.6.0 on
 * (§19.15), the card of any client, which names the client it was given to,
 * the tier the card showed, the ticks and the history window, and always
 * carries the device checks.
 */
export const CONTENT_CONSENT_VERSIONS = Object.freeze([1, 2, 3, 4])
/** The client_id a console connection token's consent names (§19.18). */
export const CONSOLE_TOKEN_CLIENT_ID = 'wappie-console-token'
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
const V4_MEMBERS = ['client_id', 'client_kind', 'client_local', 'trust', 'started_ack', 'unknown_ack', 'history_days']
export const contentBundleSchema = z.strictObject({
  version: z.literal(2), kind: z.literal('content'), purpose: z.enum(['consent', 'renewal', 'token']),
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
  // Version 4 (§19.15): the client, the tier, the ticks and the history window.
  client_id: z.string().min(1).max(512).optional(),
  client_kind: z.enum(['cimd', 'dcr', 'token']).optional(),
  client_local: z.boolean().optional(),
  trust: z.enum(['tested', 'unknown']).optional(),
  started_ack: z.literal(true).optional(),
  unknown_ack: z.boolean().optional(),
  history_days: z.number().int().min(1).max(366).nullable().optional(),
  // A console token's (§19.18): the bearer's hash and the networks it may be used from.
  bearer_sha256: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  allowed_networks: allowedNetworks.optional(),
}).refine(bundle => bundle.media !== true || bundle.consent_version >= 2)
  // Version 3 is the card with sending: `send` and the device checks come with it and only with it.
  .refine(bundle => bundle.consent_version === 4 || ((bundle.consent_version === 3) === (bundle.send !== undefined) && (bundle.send !== undefined) === (bundle.device_checks !== undefined)))
  .refine(bundle => bundle.send !== undefined || (bundle.send_self === undefined && bundle.send_groups === undefined))
  // Version 4 ⇔ the client members; it always carries the device checks, and sends only for a tested web client.
  .refine(bundle => V4_MEMBERS.every(name => (bundle[name] !== undefined) === (bundle.consent_version === 4)))
  .refine(bundle => bundle.consent_version !== 4 || (bundle.device_checks !== undefined &&
    (bundle.send === undefined || (bundle.trust === 'tested' && bundle.client_local === false && bundle.client_kind !== 'token'))))
  // An unknown client (a token included) reads text only after the second tick, within a history window; a tested one reads all of it.
  .refine(bundle => bundle.consent_version !== 4 || (bundle.trust === 'unknown' ? bundle.unknown_ack === true && bundle.history_days !== null : bundle.history_days === null))
  // A token's consent (§19.18): version 4, unknown, the token's own client, its hash and networks, and nothing else carries those.
  .refine(bundle => (bundle.purpose === 'token') === (bundle.bearer_sha256 !== undefined) && (bundle.purpose === 'token') === (bundle.allowed_networks !== undefined))
  .refine(bundle => bundle.purpose !== 'token' || (bundle.consent_version === 4 && bundle.client_kind === 'token' && bundle.trust === 'unknown' && bundle.client_local === false))
  .refine(bundle => (bundle.client_kind === 'token') === (bundle.client_id === CONSOLE_TOKEN_CLIENT_ID))
function sameOrigin(value) {
  try { return archiveOrigin(value) === value } catch { return false }
}
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
    // A token has no completion proof and names no connection: the sealed bundle is the consent (§19.18).
    (bundle.purpose === 'token' && (bundle.link_secret !== undefined || bundle.connection_id !== undefined)) ||
    (bundle.client_id !== undefined && Buffer.byteLength(bundle.client_id, 'utf8') > 512) ||
    (bundle.device_checks !== undefined && !exactChecks(bundle.device_checks, bundle.device_ids))) fail('invalid_bundle')
  Object.freeze(bundle.device_ids)
  if (bundle.device_checks) Object.freeze(bundle.device_checks)
  if (bundle.allowed_networks) Object.freeze(bundle.allowed_networks)
  return Object.freeze(bundle)
}

/**
 * A console connection token's metadata bundle (docs/mcp-enclave.md §19.18
 * step 4): no number keys and no link secret (there is no completion proof),
 * the token's expiry, history window, allowed networks and the bearer's hash.
 * Sealed to an attested token request's key, as its content sibling (a
 * content bundle with `purpose: 'token'`) is.
 */
export const tokenBundleSchema = z.strictObject({
  version: z.literal(1), kind: z.literal('metadata'), purpose: z.literal('token'),
  server_url: z.string().min(1).max(4096), workspace_id: id,
  device_ids: z.array(id).min(1).max(100),
  token: z.string().length(52),
  timezone: z.string().min(1).max(100).optional(),
  expires_at: z.iso.datetime().max(40),
  history_days: z.number().int().min(1).max(366),
  allowed_networks: allowedNetworks,
  bearer_sha256: z.string().regex(/^[0-9a-f]{64}$/),
})
/** Validates a parsed token bundle and returns it frozen; any failure is `invalid_bundle`. `now` is for tests. */
export function validateTokenBundle(value, now = Date.now()) {
  const parsed = tokenBundleSchema.safeParse(value)
  if (!parsed.success) fail('invalid_bundle')
  const bundle = parsed.data
  const expires = Date.parse(bundle.expires_at)
  if (!httpsOrigin(bundle.server_url) || new Set(bundle.device_ids).size !== bundle.device_ids.length ||
    !/^[a-f0-9]{8}\./.test(bundle.token) || !canonicalKey(bundle.token.slice(9)) ||
    !Number.isFinite(expires) || expires <= now || expires > now + MAX_CONTENT_AHEAD_MS ||
    (bundle.timezone !== undefined && !validTimezone(bundle.timezone))) fail('invalid_bundle')
  Object.freeze(bundle.device_ids)
  Object.freeze(bundle.allowed_networks)
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
 *
 * A version-4 bundle's scope (§19.15) says `consent_version: 4` and adds the
 * client, the tier, the ticks, the history window and a token's hash and
 * networks, each null when absent (a renewal never carries the last two:
 * the record pins them), so only a holder of each number's DSK makes them.
 * `send` is null when absent there, as it never is on version 3.
 */
export function deviceScope(bundle, { deviceID, epoch, request, kid }) {
  const v4 = bundle.consent_version === 4
  return {
    workspace_id: bundle.workspace_id, device_id: deviceID, epoch, service_user_id: bundle.service_user_id, request, kid,
    device_ids: [...bundle.device_ids].sort(), expires_at: bundle.expires_at, consent_version: v4 ? 4 : 3, media: bundle.media === true,
    send: v4 ? bundle.send ?? null : bundle.send, send_self: bundle.send_self === true, send_groups: bundle.send_groups === true,
    send_chats: (bundle.send_chats ?? []).filter(chat => chat.device_id === deviceID).map(chat => chat.chat_key).sort(),
    send_signature: bundle.send_signature ?? null,
    ...(v4 ? Object.fromEntries(['client_id', 'client_kind', 'client_local', 'trust', 'started_ack', 'unknown_ack', 'history_days', 'bearer_sha256', 'allowed_networks']
      .map(name => [name, bundle[name] === undefined ? null : name === 'allowed_networks' ? [...bundle[name]] : bundle[name]])) : {}),
  }
}

/**
 * `device_checks[d]`, base64url: HMAC-SHA256 under HKDF-SHA256(DSK(d, e),
 * salt = the grant's namespace, info = label ‖ device ‖ u16be epoch) over
 * label ‖ 0x00 ‖ SHA-256(JCS(scope)). `dsk` is the 32 raw bytes, which the
 * caller owns and zeroes; the derived key is zeroed here.
 */
export function deviceCheck(dsk, { namespace, deviceID, epoch, scope }) {
  return scopeTag(DEVICE_CHECK_LABEL, dsk, { namespace, deviceID, epoch, scope })
}

/** A tag of one number's scope under `label` (the device check's construction, §17.2 rule 3, and the AI configuration tag's, §18.7). */
function scopeTag(labelText, dsk, { namespace, deviceID, epoch, scope }) {
  if (!(dsk instanceof Uint8Array) || dsk.length !== 32 || !Number.isInteger(epoch) || epoch < 1 || epoch > 65535) throw new LocalConfigError('invalid_bundle')
  const label = Buffer.from(labelText)
  const epochBytes = Buffer.alloc(2)
  epochBytes.writeUInt16BE(epoch)
  const key = Buffer.from(hkdfSync('sha256', dsk, bytes.parseUUID(namespace), Buffer.concat([label, bytes.parseUUID(deviceID), epochBytes]), 32))
  try {
    const digest = createHash('sha256').update(canonicalJSON(scope), 'utf8').digest()
    return createHmac('sha256', key).update(Buffer.concat([label, Buffer.from([0]), digest])).digest('base64url')
  } finally { key.fill(0) }
}

// ---- AI integrations (docs/mcp-enclave.md §18.7) ------------------------------
//
// The limits below repeat those of packages/mcp-http/enclave/ai/policy.mjs
// (measured in PCR0), which a test there holds equal: this package is the
// reader's, which the enclave imports and never the other way round.

/** Numbers per authorization (AI_DEVICES_MAX). */
export const AI_DEVICES_MAX = 25
/** Which provider may serve which function (AI_FEATURES). */
export const AI_FEATURES = Object.freeze({
  anthropic: Object.freeze(['image', 'document']),
  openai: Object.freeze(['audio', 'image', 'document']),
  google: Object.freeze(['audio', 'video', 'image', 'document']),
})
export const AI_PROVIDER_NAMES = Object.freeze(['anthropic', 'openai', 'google'])
export const AI_FUNCTIONS = Object.freeze(['audio', 'video', 'image', 'document'])
/** A model id's shape (AI_MODEL_RE); which models exist is each key's list. */
export const AI_MODEL_RE = /^[a-z0-9][a-z0-9._:-]{0,63}$/
/** A function's optional language: a BCP 47 tag. */
export const AI_LANG_RE = /^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}$/
/** An API key as the bundle carries it. */
export const AI_KEY_RE = /^[!-~]{20,256}$/
/** Who may ask for a function on a number (§18.10). */
export const AI_REQUESTERS = Object.freeze(['self', 'readers', 'console'])
/** The bundle's ceilings (AI_MONTHLY_TOKENS_MAX, AI_REQUEST_ITEMS_PER_DAY_MAX). */
export const AI_MONTHLY_TOKENS_MAX = 1_000_000_000
export const AI_REQUEST_ITEMS_PER_DAY_MAX = 1_000
/** The configuration tag's label (§18.7 step 4). */
export const AI_CONFIG_LABEL = 'wappie-ai-config/v1'

const aiFunction = z.strictObject({ provider: z.enum(AI_PROVIDER_NAMES), model: z.string().max(64).regex(AI_MODEL_RE) })
const aiFeature = z.strictObject({ mode: z.literal('request'), lang: z.string().max(40).regex(AI_LANG_RE).optional(), requesters: z.enum(AI_REQUESTERS) })
const byFunction = entry => z.strictObject(Object.fromEntries(AI_FUNCTIONS.map(name => [name, entry.optional()])))
/**
 * The AI bundle (§18.7 step 3): a format no other validator takes (`version:
 * 3`, `kind: 'ai'`), sealed to an attested AI request's key. `auto` (B2) is
 * absent, like any key not listed; `mode: 'auto'` is refused. The budget is
 * a safety cap in tokens and attachments, never money (§18.10).
 */
export const aiBundleSchema = z.strictObject({
  version: z.literal(3), kind: z.literal('ai'), purpose: z.enum(['consent', 'renewal']),
  server_url: z.string().min(1).max(4096), workspace_id: id, service_user_id: id,
  device_ids: z.array(id).min(1).max(AI_DEVICES_MAX),
  token: z.string().length(52),
  timezone: z.string().min(1).max(100).optional(),
  key_mode: z.literal('ephemeral'), consent_version: z.literal(1),
  expires_at: z.iso.datetime().max(40),
  connection_id: id.optional(),
  keys: z.strictObject(Object.fromEntries(AI_PROVIDER_NAMES.map(name => [name, z.string().regex(AI_KEY_RE).optional()]))),
  functions: byFunction(aiFunction),
  features: z.record(z.string().max(36), byFunction(aiFeature)),
  budget: z.strictObject({
    monthly_tokens: z.number().int().min(1).max(AI_MONTHLY_TOKENS_MAX),
    request_items_per_day: z.number().int().min(1).max(AI_REQUEST_ITEMS_PER_DAY_MAX),
  }),
  cfg_tags: z.record(z.string().max(36), z.string().length(43)),
})

const sameKeys = (object, keys) => { const names = Object.keys(object); return names.length === keys.length && keys.every(key => Object.hasOwn(object, key)) }

/**
 * Validates a parsed AI bundle and returns it frozen; any failure is
 * `invalid_bundle`, with nothing of the input in the error. `now` is for tests.
 */
export function validateAIBundle(value, now = Date.now()) {
  const parsed = aiBundleSchema.safeParse(value)
  if (!parsed.success) fail('invalid_bundle')
  const bundle = parsed.data
  const expires = Date.parse(bundle.expires_at)
  const named = Object.keys(bundle.functions)
  const providers = [...new Set(Object.values(bundle.functions).map(entry => entry.provider))]
  if (!httpsOrigin(bundle.server_url) || new Set(bundle.device_ids).size !== bundle.device_ids.length ||
    !/^[a-f0-9]{8}\./.test(bundle.token) || !canonicalKey(bundle.token.slice(9)) ||
    !Number.isFinite(expires) || expires <= now || expires > now + MAX_CONTENT_AHEAD_MS ||
    (bundle.timezone !== undefined && !validTimezone(bundle.timezone)) ||
    (bundle.purpose === 'consent') !== (bundle.connection_id === undefined) ||
    named.length === 0 ||
    Object.entries(bundle.functions).some(([name, entry]) => !AI_FEATURES[entry.provider].includes(name) || (entry.provider === 'google' && entry.model.includes(':'))) ||
    !sameKeys(bundle.keys, providers) ||
    !sameKeys(bundle.features, bundle.device_ids) ||
    Object.values(bundle.features).some(features => Object.keys(features).some(name => !named.includes(name))) ||
    !sameKeys(bundle.cfg_tags, bundle.device_ids) || Object.values(bundle.cfg_tags).some(tag => !canonicalKey(tag))) fail('invalid_bundle')
  Object.freeze(bundle.device_ids)
  for (const name of ['keys', 'functions', 'features', 'cfg_tags']) Object.freeze(bundle[name])
  return Object.freeze(bundle)
}

/** `{provider: hex SHA-256 of the key's UTF-8}`: what a configuration tag binds of each key. */
export function keysSHA256(keys) {
  return Object.fromEntries(Object.entries(keys).map(([provider, key]) => [provider, createHash('sha256').update(key, 'utf8').digest('hex')]))
}

/**
 * `config[d]` (§18.7 step 4): what one number's configuration tag covers.
 * `fields` holds the bundle's `workspace_id`, `service_user_id`,
 * `device_ids`, `functions`, `features`, `budget`, `expires_at` and
 * `key_mode`, and `keys_sha256` in place of the keys (the enclave keeps the
 * hashes in the record, the keys only in memory). `request` is the AI
 * request's id or the renewal's, `kid` the attested key's id.
 */
export function aiConfigScope(fields, { deviceID, epoch, request, kid }) {
  return {
    workspace_id: fields.workspace_id, device_id: deviceID, epoch, service_user_id: fields.service_user_id, request, kid,
    device_ids: [...fields.device_ids].sort(), keys_sha256: fields.keys_sha256, functions: fields.functions,
    features: fields.features[deviceID], auto: null, budget: fields.budget, expires_at: fields.expires_at, key_mode: fields.key_mode,
  }
}

/**
 * `cfg_tag[d]`, base64url: the device check's construction under
 * "wappie-ai-config/v1" over `config` (aiConfigScope). `dsk` is DSK(d, e),
 * which the caller zeroes.
 */
export function aiConfigTag(dsk, { namespace, deviceID, epoch, config }) {
  return scopeTag(AI_CONFIG_LABEL, dsk, { namespace, deviceID, epoch, scope: config })
}
