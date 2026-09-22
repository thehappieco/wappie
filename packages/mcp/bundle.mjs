import * as z from 'zod/v4'
import { hpke } from '@whatserver2/client'
import { openContactPack, validateContactPack } from '@whatserver2/client/crypto/contactPack'
import { LocalConfigError, validateConfig } from './config.mjs'

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
