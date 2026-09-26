import { constants } from 'node:fs'
import { open } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import * as z from 'zod/v4'
import { archiveOrigin } from '@whatserver2/client'

const id = z.string().uuid().transform(value => value.toLowerCase())
const file = z.string().min(1).max(4096)
const schema = z.strictObject({
  server: z.string().min(1), workspace: id,
  session_file: file.optional(), token_file: file.optional(),
  password_file: file.optional(), service_key_file: file.optional(), service_user_id: id.optional(),
  allow_plaintext: z.boolean().default(false),
  contacts_file: file.optional(),
  timezone: z.string().min(1).max(128).default('UTC'),
  max_scan_messages: z.number().int().min(1).max(2000).default(500),
  device_ids: z.array(id).min(1).max(1000).optional(),
  max_text_chars: z.number().int().min(128).max(8192).default(4096),
  // 'provided': a hosted reader supplies the credential in process; no file
  // fields and no plaintext opt-in are allowed (metadata-only by construction).
  // 'enclave': the attested reader supplies the credential and a key handle in
  // process; plaintext is required, files are refused (see readerMode).
  credential_source: z.enum(['files', 'provided', 'enclave']).default('files'),
})
const credentialFiles = ['session_file', 'token_file', 'password_file', 'service_key_file', 'contacts_file']
export class LocalConfigError extends Error {
  constructor(code) { super(code); this.name = 'LocalConfigError'; this.code = code }
}
/** Private regular files only. Never print paths, bytes or parser diagnostics. */
export async function readPrivateFile(path, { maxBytes = 1024 * 1024 } = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 8 * 1024 * 1024) throw new LocalConfigError('private_file_required')
  let handle
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    const stat = await handle.stat()
    if (!stat.isFile() || stat.size > maxBytes || (stat.mode & 0o077) !== 0 ||
      (typeof process.getuid === 'function' && stat.uid !== process.getuid())) throw new LocalConfigError('private_file_required')
    const data = await handle.readFile()
    if (data.length > maxBytes) { data.fill(0); throw new LocalConfigError('private_file_required') }
    return data
  } catch (error) {
    if (error instanceof LocalConfigError) throw error
    throw new LocalConfigError('private_file_unavailable')
  } finally { await handle?.close() }
}
export function validateConfig(value, base = process.cwd()) {
  const result = schema.safeParse(value)
  if (!result.success) throw new LocalConfigError('invalid_config')
  const config = result.data
  try { config.server = archiveOrigin(config.server) } catch { throw new LocalConfigError('invalid_server') }
  if (config.credential_source === 'provided') {
    if (credentialFiles.some(field => config[field]) || config.allow_plaintext) throw new LocalConfigError('provided_credentials_metadata_only')
  } else if (config.credential_source === 'enclave') {
    // Content opened in memory with a key handle the attested reader holds for
    // one service account over an exact set of numbers. Nothing comes from disk.
    if (credentialFiles.some(field => config[field]) || config.allow_plaintext !== true ||
      !config.service_user_id || !config.device_ids) throw new LocalConfigError('enclave_credentials_invalid')
  } else {
    if (Boolean(config.session_file) === Boolean(config.token_file)) throw new LocalConfigError('choose_one_credential')
    if ((config.session_file && (config.service_key_file || config.service_user_id)) ||
      (config.token_file && config.password_file)) throw new LocalConfigError('mixed_credentials')
    if (config.service_key_file && !config.service_user_id) throw new LocalConfigError('service_user_required')
    if (config.allow_plaintext && !(config.session_file ? config.password_file : config.service_key_file)) throw new LocalConfigError('unlock_file_required')
    if (!config.allow_plaintext && (config.password_file || config.service_key_file)) throw new LocalConfigError('plaintext_opt_in_required')
  }
  try { new Intl.DateTimeFormat('en', { timeZone: config.timezone }).format(0) } catch { throw new LocalConfigError('invalid_timezone') }
  if (config.contacts_file && (!config.allow_plaintext || !config.token_file || !config.service_key_file || !config.service_user_id || !config.device_ids)) throw new LocalConfigError('contact_pack_requires_service_scope')
  if (config.device_ids && new Set(config.device_ids).size !== config.device_ids.length) throw new LocalConfigError('invalid_config')
  for (const field of credentialFiles) if (config[field]) config[field] = resolve(base, config[field])
  if (config.device_ids) Object.freeze(config.device_ids)
  return Object.freeze(config)
}
/**
 * Which reader a configuration makes, and so which words every model-facing
 * string uses: 'local' (files, stdio), 'hosted-metadata' (a provided
 * credential that can never open content) or 'hosted-content' (the attested
 * reader, which opens content with a key handle it holds in memory).
 */
export function readerMode(config) {
  switch (config?.credential_source) {
    case 'files': return 'local'
    case 'provided': return 'hosted-metadata'
    case 'enclave': return 'hosted-content'
    default: throw new LocalConfigError('invalid_config')
  }
}
export async function loadConfig(path) {
  const data = await readPrivateFile(path)
  try {
    let parsed
    try { parsed = JSON.parse(data.toString('utf8')) } catch { throw new LocalConfigError('invalid_config') }
    return validateConfig(parsed, dirname(resolve(path)))
  } finally { data.fill(0) }
}
function apiKeyCredential(token) {
  if (typeof token !== 'string' || !token || /\s/.test(token)) throw new LocalConfigError('invalid_token_file')
  return { token, kind: 'api_key' }
}
/**
 * Resolves the credential the reader authenticates with. A provided or enclave
 * config takes it from `provider.token()` (`{token, kind:'api_key'}`), never
 * from disk; an enclave provider throws `reconsent_required` when it holds no key.
 */
export async function loadCredential(config, provider) {
  if (config.credential_source === 'provided' || config.credential_source === 'enclave') {
    if (!provider || typeof provider.token !== 'function') throw new LocalConfigError('credential_provider_required')
    const credential = await provider.token()
    if (!credential || credential.kind !== 'api_key') throw new LocalConfigError('invalid_token_file')
    return apiKeyCredential(credential.token)
  }
  const data = await readPrivateFile(config.session_file || config.token_file)
  try {
    if (config.token_file) return apiKeyCredential(data.toString('utf8').trim())
    let session
    try { session = JSON.parse(data.toString('utf8')) } catch { throw new LocalConfigError('invalid_session') }
    if (session.origin !== config.server || session.tenantID !== config.workspace ||
      typeof session.token !== 'string' || !session.token || /\s/.test(session.token) ||
      typeof session.email !== 'string' || !session.email || !id.safeParse(session.userID).success ||
      !Number.isFinite(Date.parse(session.expiresAt)) || Date.parse(session.expiresAt) <= Date.now()) throw new LocalConfigError('session_expired_or_wrong_scope')
    return { token: session.token, kind: 'session', email: session.email, userID: session.userID }
  } finally { data.fill(0) }
}
