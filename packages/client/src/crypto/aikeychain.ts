// A person's AI provider keys, kept in the archive so they need not paste a
// key again (docs/mcp-enclave.md §18.6). Go stores each item as an opaque
// envelope; only the holder of the account's private key opens or makes one.
//
//   k_kc     = HKDF-SHA256(ikm = X25519(sk_account, pk_account), salt = UTF-8 user_id, info = "wappie/ai-keychain/v1")
//   envelope = "WKC1" ‖ IV (12) ‖ AES-256-GCM(k_kc, IV, plaintext, AAD)
//   AAD      = UTF-8 JSON.stringify(['wappie/ai-keychain', 1, server_origin, user_id, item_id, provider])
//
// X25519 of the account key with its own public key: HPKE here is base mode
// only (hpke.ts), and a key that only the private half derives gives what
// mode_auth would. Go knows the public key and nothing else, so an item it
// made (sealed to the public key, or keyed from it) never opens here (N-AI-2).
//
// The keychain spares a paste; it is not what makes a key someone's. The
// configuration tags of an AI authorization are (§18.7).

import { archiveOrigin } from '../api/rest.js'
import { concat, encodeUTF8, equal, fromBase64, type Bytes } from './bytes.js'
import type { PrivateKey } from './hpke.js'

export const KEYCHAIN_LABEL = 'wappie/ai-keychain/v1'
const MAGIC = encodeUTF8('WKC1')
const IV_LEN = 12
const TAG_LEN = 16
/** An item's plaintext; Go's CHECK allows an envelope of 4,096 bytes. */
export const KEYCHAIN_MAX_PLAINTEXT = 2048
export const KEYCHAIN_PROVIDERS = ['anthropic', 'openai', 'google'] as const
export type KeychainProvider = (typeof KEYCHAIN_PROVIDERS)[number]
/** An API key as the AI bundle takes it (§18.7): printable ASCII, 20 to 256 characters. */
export const API_KEY_SHAPE = /^[!-~]{20,256}$/

/** What `sealKeychainItem` seals, and where. */
export interface KeychainInput {
  /** The archive's origin, as the console talks to it. */
  server_origin: string
  user_id: string
  /** The item's id, chosen by the browser and bound in the envelope. */
  id: string
  provider: KeychainProvider
  api_key: string
  /** 1 to 60 characters. */
  label: string
  created_at: string
}

/** A keychain row as Go lists it, with the origin and account it belongs to. */
export interface KeychainRow {
  server_origin: string
  user_id: string
  id: string
  provider: string
  /** The envelope: bytes, or as Go's JSON carries it (unpadded base64url; padded standard base64 is read too). */
  envelope: Bytes | string
}

export interface KeychainItem { provider: KeychainProvider; api_key: string; label: string; created_at: string }

export class KeychainError extends Error {
  constructor() {
    super('invalid_keychain_item')
    this.name = 'KeychainError'
  }
}
function fail(): never { throw new KeychainError() }

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const isoShape = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/

function origin(value: string): string {
  try {
    const parsed = archiveOrigin(value)
    if (parsed !== value) fail()
    return parsed
  } catch { return fail() }
}

function binding(serverOrigin: string, userID: string, itemID: string, provider: string): Bytes {
  if (!uuid.test(userID ?? '') || !uuid.test(itemID ?? '') || !(KEYCHAIN_PROVIDERS as readonly string[]).includes(provider)) fail()
  return encodeUTF8(JSON.stringify(['wappie/ai-keychain', 1, origin(serverOrigin), userID, itemID, provider]))
}

function validItem(value: unknown): KeychainItem {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail()
  const item = value as Record<string, unknown>
  const keys = Object.keys(item)
  if (keys.length !== 4 || !['provider', 'api_key', 'label', 'created_at'].every(key => keys.includes(key)) ||
    !(KEYCHAIN_PROVIDERS as readonly unknown[]).includes(item.provider) || typeof item.api_key !== 'string' || !API_KEY_SHAPE.test(item.api_key) ||
    typeof item.label !== 'string' || item.label.length < 1 || item.label.length > 60 || /[\u0000-\u001f\u007f-\u009f]/.test(item.label) ||
    typeof item.created_at !== 'string' || !isoShape.test(item.created_at) || !Number.isFinite(Date.parse(item.created_at))) fail()
  return { provider: item.provider as KeychainProvider, api_key: item.api_key, label: item.label, created_at: item.created_at }
}

/**
 * `k_kc` for this account: X25519 of its private key with its own public
 * key, then HKDF under the user id. Non-extractable; the shared secret is
 * zeroed here.
 */
export async function keychainKey(account: PrivateKey, userID: string): Promise<CryptoKey> {
  if (!account || !(account.key instanceof CryptoKey) || !(account.publicRaw instanceof Uint8Array) || account.publicRaw.length !== 32 || !uuid.test(userID ?? '')) fail()
  const own = await crypto.subtle.importKey('raw', account.publicRaw as Bytes, { name: 'X25519' }, false, [])
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: own }, account.key, 256))
  try {
    const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
    return await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: encodeUTF8(userID), info: encodeUTF8(KEYCHAIN_LABEL) },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  } finally { shared.fill(0) }
}

/** The last 4 characters of a key, which Go stores readable for the list. */
export function keychainSuffix(apiKey: string): string {
  if (!API_KEY_SHAPE.test(apiKey)) fail()
  return apiKey.slice(-4)
}

/** Seals one item for the account (`account` is the session's unwrapped key pair). */
export async function sealKeychainItem(account: PrivateKey, input: KeychainInput): Promise<Bytes> {
  const item = validItem({ provider: input?.provider, api_key: input?.api_key, label: input?.label, created_at: input?.created_at })
  const aad = binding(input.server_origin, input.user_id, input.id, item.provider)
  const plaintext = encodeUTF8(JSON.stringify(item))
  try {
    if (plaintext.length > KEYCHAIN_MAX_PLAINTEXT) fail()
    const key = await keychainKey(account, input.user_id)
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN))
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, plaintext))
    return concat(MAGIC, iv, sealed)
  } finally { plaintext.fill(0) }
}

/**
 * An envelope as Go's JSON spells it: unpadded base64url (what the keychain
 * routes take and list), or padded standard base64. Anything else throws.
 */
function envelopeBytes(s: string): Bytes {
  if (/^[A-Za-z0-9_-]*$/.test(s) && s.length % 4 !== 1) return fromBase64(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '='))
  if (/^[A-Za-z0-9+/]*={0,2}$/.test(s) && s.length % 4 === 0) return fromBase64(s)
  throw new Error('not base64')
}

/**
 * Opens a row of the account's keychain. Throws KeychainError on anything
 * but an item this account sealed for exactly this origin, user, item id
 * and provider, the row's provider included: a row whose provider Go
 * changed would otherwise send the key to another provider's host.
 */
export async function openKeychainItem(account: PrivateKey, row: KeychainRow): Promise<KeychainItem> {
  let envelope: Bytes
  try { envelope = typeof row?.envelope === 'string' ? envelopeBytes(row.envelope) : row?.envelope } catch { return fail() }
  if (!(envelope instanceof Uint8Array) || envelope.length < MAGIC.length + IV_LEN + TAG_LEN || envelope.length > MAGIC.length + IV_LEN + KEYCHAIN_MAX_PLAINTEXT + TAG_LEN ||
    !equal(envelope.subarray(0, MAGIC.length) as Bytes, MAGIC)) fail()
  const aad = binding(row.server_origin, row.user_id, row.id, row.provider)
  let plaintext: Bytes | undefined
  try {
    const key = await keychainKey(account, row.user_id)
    try {
      plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: envelope.subarray(MAGIC.length, MAGIC.length + IV_LEN), additionalData: aad, tagLength: 128 },
        key, envelope.subarray(MAGIC.length + IV_LEN)))
    } catch { return fail() }
    let parsed: unknown
    try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)) } catch { return fail() }
    const item = validItem(parsed)
    if (item.provider !== row.provider) fail()
    return item
  } finally { plaintext?.fill(0) }
}
