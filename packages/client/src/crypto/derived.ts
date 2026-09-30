// Derived records: what an AI provider made of an attachment (a transcript, a
// description, a summary), sealed in the attested reader and stored in the
// archive beside the message (docs/mcp-enclave.md §18.8).
//
// The key is derived from the number's device key (DSK) that opened the
// source content, so whoever reads the number reads its derived records and
// nobody else does: the console with the person's own DSK, a media
// connection with the DSK its grant opens, and never Go, which holds only
// the device's public key. A record Go made with that public key (HPKE to the
// device, as grants are) is not in this format and fails here (N-AI-3).
//
// The enclave seals in Node (packages/mcp-http/enclave/ai/derived.mjs) and
// the reader opens there too (packages/mcp/reader.mjs); this file is the
// browser's side, WebCrypto only, and testdata/node-derived.json holds the
// records the enclave sealed, which all three open.
//
//   k        = HKDF-SHA256(DSK, salt = ns (16 bytes), info = "wappie-derived/v1" ‖ device_id (16 bytes) ‖ u16be epoch)
//   AAD      = UTF-8 JSON.stringify(['wappie/derived', 1, ns, device_id, message_uid, feature, epoch])
//   envelope = "WDRV" ‖ 0x01 ‖ u16be epoch ‖ IV (12) ‖ AES-256-GCM(k, IV, plaintext, AAD)
//
// The dedupe tag (reuse of a result for the same file within the workspace)
// comes from the same DSK under its own label, over the hash of the
// plaintext the enclave verified itself, never the sender's claimed hash.

import { concat, encodeUTF8, equal, fromHex, i2osp2, parseUUID, type Bytes } from './bytes.js'

export const DERIVED_LABEL = 'wappie-derived/v1'
export const DEDUPE_LABEL = 'wappie-ai-dedupe/v1'
const MAGIC = encodeUTF8('WDRV')
const VERSION = 0x01
const HEADER_LEN = 4 + 1 + 2
const IV_LEN = 12
const TAG_LEN = 16
/** A record's plaintext; the envelope adds its header, IV and tag (Go's CHECK allows 524,323 bytes). */
export const DERIVED_MAX_BYTES = 524_288
/** AI_TEXT_MAX_CHARS (§18.14): a record's text, in UTF-16 code units. */
export const DERIVED_TEXT_MAX_CHARS = 200_000
export const DERIVED_FEATURES = ['audio', 'video', 'image', 'document'] as const
export const DERIVED_PROVIDERS = ['anthropic', 'openai', 'google'] as const
export const DERIVED_FLAGS = ['cut', 'refused', 'no_speech', 'partial', 'redo'] as const
export type Feature = (typeof DERIVED_FEATURES)[number]
export type Provider = (typeof DERIVED_PROVIDERS)[number]
export type Flag = (typeof DERIVED_FLAGS)[number]

/** Where a record belongs: its number, message, function and grant epoch, and the namespace its grant opens under. */
export interface DerivedScope {
  /** `archive_tenant_id` of the grant, else the workspace id. */
  namespace: string
  device_id: string
  message_uid: string
  feature: Feature
  epoch: number
}

export interface DerivedUsage { input_tokens?: number; output_tokens?: number; seconds?: number }

/** A record's plaintext (§18.8), in the order the enclave writes it. */
export interface DerivedRecord {
  v: 1
  feature: Feature
  text: string
  lang?: string
  provider: Provider
  model: string
  prompt_version: string
  created_at: string
  source_sha256: string
  usage: DerivedUsage
  flags: Flag[]
}

export class DerivedError extends Error {
  constructor() {
    super('invalid_derived')
    this.name = 'DerivedError'
  }
}
function fail(): never { throw new DerivedError() }

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const modelShape = /^[a-z0-9][a-z0-9._:-]{0,63}$/
const langShape = /^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}$/
const hex64 = /^[0-9a-f]{64}$/
const isoShape = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/

function scopeOf(scope: DerivedScope): DerivedScope {
  if (!scope || !uuid.test(scope.namespace ?? '') || !uuid.test(scope.device_id ?? '') || !uuid.test(scope.message_uid ?? '') ||
    !(DERIVED_FEATURES as readonly string[]).includes(scope.feature) || !Number.isInteger(scope.epoch) || scope.epoch < 1 || scope.epoch > 65535) fail()
  return scope
}

/** The additional data binding a record to its namespace, number, message, function and epoch. */
export function derivedAAD(scope: DerivedScope): Bytes {
  const s = scopeOf(scope)
  return encodeUTF8(JSON.stringify(['wappie/derived', 1, s.namespace, s.device_id, s.message_uid, s.feature, s.epoch]))
}

/** HKDF-SHA256 over the DSK, as raw bytes: the caller zeroes them. */
async function hkdf(dsk: Bytes, namespace: string, label: string, deviceID: string, epoch: number): Promise<Bytes> {
  if (!(dsk instanceof Uint8Array) || dsk.length !== 32) fail()
  const base = await crypto.subtle.importKey('raw', dsk, 'HKDF', false, ['deriveBits'])
  const info = concat(encodeUTF8(label), parseUUID(deviceID), i2osp2(epoch))
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: parseUUID(namespace), info }, base, 256))
}

/** `k` of a scope, as a non-extractable AES-GCM key. `dsk` is the 32 raw bytes of DSK(device, epoch). */
export async function derivedKey(dsk: Bytes, scope: Pick<DerivedScope, 'namespace' | 'device_id' | 'epoch'>): Promise<CryptoKey> {
  const raw = await hkdf(dsk, scope.namespace, DERIVED_LABEL, scope.device_id, scope.epoch)
  try { return await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']) }
  finally { raw.fill(0) }
}

const usageKeys = ['input_tokens', 'output_tokens', 'seconds']
const recordKeys = ['v', 'feature', 'text', 'lang', 'provider', 'model', 'prompt_version', 'created_at', 'source_sha256', 'usage', 'flags']

/**
 * A record's plaintext as the enclave writes it, checked: every field of
 * §18.8 and nothing else, `feature` the scope's, text within its cap, flags
 * known and once each, and an empty text only for a refusal or a transcript
 * without speech. Throws DerivedError.
 */
export function validateDerivedRecord(value: unknown, feature?: Feature): DerivedRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail()
  const record = value as Record<string, unknown>
  const keys = Object.keys(record)
  if (keys.some(key => !recordKeys.includes(key)) || recordKeys.filter(key => key !== 'lang').some(key => !Object.hasOwn(record, key))) fail()
  const usage = record.usage as Record<string, unknown>
  const flags = record.flags as unknown[]
  if (record.v !== 1 || !(DERIVED_FEATURES as readonly unknown[]).includes(record.feature) || (feature !== undefined && record.feature !== feature) ||
    typeof record.text !== 'string' || record.text.length > DERIVED_TEXT_MAX_CHARS ||
    (record.lang !== undefined && (typeof record.lang !== 'string' || !langShape.test(record.lang))) ||
    !(DERIVED_PROVIDERS as readonly unknown[]).includes(record.provider) || typeof record.model !== 'string' || !modelShape.test(record.model) ||
    typeof record.prompt_version !== 'string' || /^([a-z]+)\/[1-9]\d{0,3}$/.exec(record.prompt_version)?.[1] !== record.feature ||
    typeof record.created_at !== 'string' || !isoShape.test(record.created_at) || !Number.isFinite(Date.parse(record.created_at)) ||
    typeof record.source_sha256 !== 'string' || !hex64.test(record.source_sha256) ||
    !usage || typeof usage !== 'object' || Array.isArray(usage) || Object.keys(usage).some(key => !usageKeys.includes(key)) ||
    Object.values(usage).some(count => !Number.isSafeInteger(count) || (count as number) < 0) ||
    !Array.isArray(flags) || new Set(flags).size !== flags.length || flags.some(flag => !(DERIVED_FLAGS as readonly unknown[]).includes(flag))) fail()
  const empty = record.text === ''
  const refused = flags.includes('refused'), silent = flags.includes('no_speech')
  if ((empty && !refused && !silent) || ((refused || silent) && !empty) || (refused && silent)) fail()
  return record as unknown as DerivedRecord
}

/** The plaintext's JSON, in §18.8's order (`lang` only when set). */
export function derivedPlaintext(record: DerivedRecord): string {
  const r = validateDerivedRecord(record)
  return JSON.stringify({
    v: 1, feature: r.feature, text: r.text, ...(r.lang !== undefined ? { lang: r.lang } : {}), provider: r.provider, model: r.model,
    prompt_version: r.prompt_version, created_at: r.created_at, source_sha256: r.source_sha256, usage: r.usage, flags: r.flags,
  })
}

/** Seals `record` for `scope` under the DSK. The enclave seals in Node; this exists for tests and symmetry. */
export async function sealDerived(dsk: Bytes, scope: DerivedScope, record: DerivedRecord): Promise<Bytes> {
  if (record.feature !== scopeOf(scope).feature) fail()
  const plaintext = encodeUTF8(derivedPlaintext(record))
  try {
    if (plaintext.length > DERIVED_MAX_BYTES) fail()
    const key = await derivedKey(dsk, scope)
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN))
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: derivedAAD(scope), tagLength: 128 }, key, plaintext))
    return concat(MAGIC, new Uint8Array([VERSION]), i2osp2(scope.epoch), iv, sealed)
  } finally { plaintext.fill(0) }
}

/**
 * Opens a record sealed for `scope` with the DSK that opened its source.
 * Anything that is not such a record, for exactly this namespace, number,
 * message, function and epoch, throws DerivedError: another message's
 * record, a moved row, a record Go made, a tampered byte.
 */
export async function openDerived(dsk: Bytes, scope: DerivedScope, envelope: Bytes): Promise<DerivedRecord> {
  const s = scopeOf(scope)
  if (!(envelope instanceof Uint8Array) || envelope.length < HEADER_LEN + IV_LEN + TAG_LEN || envelope.length > DERIVED_MAX_BYTES + HEADER_LEN + IV_LEN + TAG_LEN ||
    !equal(envelope.subarray(0, 4) as Bytes, MAGIC) || envelope[4] !== VERSION || ((envelope[5] << 8) | envelope[6]) !== s.epoch) fail()
  let plaintext: Bytes | undefined
  try {
    const key = await derivedKey(dsk, s)
    try {
      plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: envelope.subarray(HEADER_LEN, HEADER_LEN + IV_LEN), additionalData: derivedAAD(s), tagLength: 128 },
        key, envelope.subarray(HEADER_LEN + IV_LEN)))
    } catch { return fail() }
    let parsed: unknown
    try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)) } catch { return fail() }
    return validateDerivedRecord(parsed, s.feature)
  } finally { plaintext?.fill(0) }
}

/** What a dedupe tag covers besides the number: the verified hash of the file and how it was processed. */
export interface DedupeInput {
  /** 64 hex: SHA-256 of the plaintext the enclave verified. */
  source_sha256: string
  feature: Feature
  provider: Provider
  model: string
  prompt_version: string
  /** The job's language, `features[device][feature].lang`; absent is "". */
  lang?: string
}

/**
 * The dedupe tag of one number (§18.8): HMAC-SHA256 under
 * HKDF(DSK, ns, "wappie-ai-dedupe/v1" ‖ device ‖ u16be epoch) over the label,
 * the hash and every field that makes a result what it is, joined by 0x00.
 * Two tags differ when any of them does, the language included.
 */
export async function dedupeTag(dsk: Bytes, scope: Pick<DerivedScope, 'namespace' | 'device_id' | 'epoch'>, input: DedupeInput): Promise<Bytes> {
  if (!uuid.test(scope?.namespace ?? '') || !uuid.test(scope?.device_id ?? '') || !Number.isInteger(scope.epoch) || scope.epoch < 1 || scope.epoch > 65535 ||
    !hex64.test(input?.source_sha256 ?? '') || !(DERIVED_FEATURES as readonly string[]).includes(input.feature) || !(DERIVED_PROVIDERS as readonly string[]).includes(input.provider) ||
    !modelShape.test(input.model ?? '') || !/^[a-z]+\/[1-9]\d{0,3}$/.test(input.prompt_version ?? '') || (input.lang !== undefined && !langShape.test(input.lang))) fail()
  const raw = await hkdf(dsk, scope.namespace, DEDUPE_LABEL, scope.device_id, scope.epoch)
  try {
    const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    const zero = new Uint8Array([0])
    const message = concat(encodeUTF8(DEDUPE_LABEL), zero, fromHex(input.source_sha256), zero, encodeUTF8(input.feature), zero, encodeUTF8(input.provider), zero,
      encodeUTF8(input.model), zero, encodeUTF8(input.prompt_version), zero, encodeUTF8(input.lang ?? ''))
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, message))
  } finally { raw.fill(0) }
}
