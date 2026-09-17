import { archiveOrigin } from '../api/rest.js'
import { encodeUTF8, fromBase64, toBase64, type Bytes } from './bytes.js'
import { open, seal, type PrivateKey } from './hpke.js'

export const MAX_CONTACT_PACK_BYTES = 8 * 1024 * 1024
export const MAX_CONTACT_PLAINTEXT_BYTES = 5 * 1024 * 1024
export interface ContactPackContact { name: string; phones: string[] }
export interface ContactPackScope { server_url: string; workspace_id: string; service_user_id: string; device_ids: string[] }
export interface ContactPack extends ContactPackScope { version: 1; enc: string; ciphertext: string }
export interface ContactPackDocument { version: 1; created_at: string; contacts: ContactPackContact[] }

const info = encodeUTF8('wappie/mcp-contacts/hpke/v1')
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const scopeKeys = ['server_url', 'workspace_id', 'service_user_id', 'device_ids']
function fail(): never { throw new Error('invalid_contact_pack') }
function object(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
    Object.keys(value).length !== keys.length || Object.keys(value).some(key => !keys.includes(key))) fail()
  return value as Record<string, unknown>
}
function identifier(value: unknown): string {
  if (typeof value !== 'string' || !uuid.test(value)) fail()
  return value.toLowerCase()
}
function scope(value: ContactPackScope): ContactPackScope {
  if (!value || typeof value.server_url !== 'string' || value.server_url.length > 4096 ||
    !Array.isArray(value.device_ids) || !value.device_ids.length || value.device_ids.length > 1000) fail()
  let server: string
  try { server = archiveOrigin(value.server_url) } catch { return fail() }
  const devices = value.device_ids.map(identifier).sort()
  if (new Set(devices).size !== devices.length) fail()
  return { server_url: server, workspace_id: identifier(value.workspace_id), service_user_id: identifier(value.service_user_id), device_ids: devices }
}
function aad(value: ContactPackScope): Bytes {
  return encodeUTF8(JSON.stringify(['wappie/mcp-contacts', 1, value.server_url, value.workspace_id, value.service_user_id, value.device_ids]))
}
function base64url(value: Bytes): string { return toBase64(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') }
function decoded(value: unknown, minimum: number, maximum: number): Bytes {
  if (typeof value !== 'string' || value.length > Math.ceil(maximum * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) fail()
  let bytes: Bytes
  try { bytes = fromBase64(value.replace(/-/g, '+').replace(/_/g, '/')) } catch { return fail() }
  if (bytes.length < minimum || bytes.length > maximum || base64url(bytes) !== value) { bytes.fill(0); fail() }
  return bytes
}

/** Validate before any disk mutation. Scope comes from trusted local config. */
export function validateContactPack(value: unknown, expected: ContactPackScope): ContactPack {
  const raw = object(value, ['version', ...scopeKeys, 'enc', 'ciphertext'])
  if (raw.version !== 1) fail()
  const actual = scope(raw as unknown as ContactPackScope), wanted = scope(expected)
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) fail()
  const enc = decoded(raw.enc, 32, 32)
  const ciphertext = decoded(raw.ciphertext, 16, MAX_CONTACT_PLAINTEXT_BYTES + 16)
  enc.fill(0); ciphertext.fill(0)
  return { version: 1, ...actual, enc: raw.enc as string, ciphertext: raw.ciphertext as string }
}

/** Only names and canonical phone numbers belong in a personal contact pack. */
export function validateContactPackDocument(value: unknown): ContactPackDocument {
  const raw = object(value, ['version', 'created_at', 'contacts'])
  if (raw.version !== 1 || typeof raw.created_at !== 'string' || raw.created_at.length !== 24 ||
    !Number.isFinite(Date.parse(raw.created_at)) || new Date(raw.created_at).toISOString() !== raw.created_at ||
    !Array.isArray(raw.contacts) || raw.contacts.length > 10_000) fail()
  const contacts = raw.contacts.map(value => {
    const contact = object(value, ['name', 'phones'])
    if (typeof contact.name !== 'string' || !contact.name.trim() || contact.name.length > 256 ||
      /[\u0000-\u001f\u007f]/.test(contact.name) || !Array.isArray(contact.phones) ||
      !contact.phones.length || contact.phones.length > 64 ||
      contact.phones.some(phone => typeof phone !== 'string' || !/^\+[1-9][0-9]{6,14}$/.test(phone)) ||
      new Set(contact.phones).size !== contact.phones.length) fail()
    return { name: contact.name, phones: [...contact.phones] as string[] }
  })
  const document: ContactPackDocument = { version: 1, created_at: raw.created_at, contacts }
  const bytes = encodeUTF8(JSON.stringify(document))
  try { if (bytes.length > MAX_CONTACT_PLAINTEXT_BYTES) fail() }
  finally { bytes.fill(0) }
  return document
}

/** Seal a deliberate snapshot to this connection's service recipient. */
export async function sealContactPack(publicKey: Bytes, expected: ContactPackScope, contacts: ContactPackContact[], createdAt = new Date().toISOString()): Promise<ContactPack> {
  let plaintext: Bytes | undefined
  try {
    const canonical = scope(expected)
    const document = validateContactPackDocument({ version: 1, created_at: createdAt, contacts })
    plaintext = encodeUTF8(JSON.stringify(document))
    if (plaintext.length > MAX_CONTACT_PLAINTEXT_BYTES) fail()
    const sealed = await seal(publicKey, info, aad(canonical), plaintext)
    return { version: 1, ...canonical, enc: base64url(sealed.enc), ciphertext: base64url(sealed.ciphertext) }
  } catch { return fail() }
  finally { plaintext?.fill(0) }
}

/** Plaintext exists only in memory; callers never persist the returned document. */
export async function openContactPack(privateKey: PrivateKey, value: unknown, expected: ContactPackScope): Promise<ContactPackDocument> {
  let plaintext: Bytes | undefined
  try {
    const pack = validateContactPack(value, expected)
    plaintext = await open(privateKey, decoded(pack.enc, 32, 32), info, aad(pack), decoded(pack.ciphertext, 16, MAX_CONTACT_PLAINTEXT_BYTES + 16))
    if (plaintext.length > MAX_CONTACT_PLAINTEXT_BYTES) fail()
    return validateContactPackDocument(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)))
  } catch { return fail() }
  finally { plaintext?.fill(0) }
}
