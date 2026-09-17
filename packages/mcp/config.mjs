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
  device_ids: z.array(id).min(1).max(1000).optional(),
  max_text_chars: z.number().int().min(128).max(8192).default(4096),
})
export class LocalConfigError extends Error {
  constructor(code) { super(code); this.name = 'LocalConfigError'; this.code = code }
}
/** Private regular files only. Never print paths, bytes or parser diagnostics. */
export async function readPrivateFile(path) {
  let handle
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    const stat = await handle.stat()
    if (!stat.isFile() || stat.size > 1024 * 1024 || (stat.mode & 0o077) !== 0 ||
      (typeof process.getuid === 'function' && stat.uid !== process.getuid())) throw new LocalConfigError('private_file_required')
    const data = await handle.readFile()
    if (data.length > 1024 * 1024) { data.fill(0); throw new LocalConfigError('private_file_required') }
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
  if (Boolean(config.session_file) === Boolean(config.token_file)) throw new LocalConfigError('choose_one_credential')
  if ((config.session_file && (config.service_key_file || config.service_user_id)) ||
    (config.token_file && config.password_file)) throw new LocalConfigError('mixed_credentials')
  if (config.service_key_file && !config.service_user_id) throw new LocalConfigError('service_user_required')
  if (config.allow_plaintext && !(config.session_file ? config.password_file : config.service_key_file)) throw new LocalConfigError('unlock_file_required')
  if (!config.allow_plaintext && (config.password_file || config.service_key_file)) throw new LocalConfigError('plaintext_opt_in_required')
  for (const field of ['session_file', 'token_file', 'password_file', 'service_key_file']) if (config[field]) config[field] = resolve(base, config[field])
  if (config.device_ids) Object.freeze(config.device_ids)
  return Object.freeze(config)
}
export async function loadConfig(path) {
  const data = await readPrivateFile(path)
  try {
    let parsed
    try { parsed = JSON.parse(data.toString('utf8')) } catch { throw new LocalConfigError('invalid_config') }
    return validateConfig(parsed, dirname(resolve(path)))
  } finally { data.fill(0) }
}
export async function loadCredential(config) {
  const data = await readPrivateFile(config.session_file || config.token_file)
  try {
    if (config.token_file) {
      const token = data.toString('utf8').trim()
      if (!token || /\s/.test(token)) throw new LocalConfigError('invalid_token_file')
      return { token, kind: 'api_key' }
    }
    let session
    try { session = JSON.parse(data.toString('utf8')) } catch { throw new LocalConfigError('invalid_session') }
    if (session.origin !== config.server || session.tenantID !== config.workspace ||
      typeof session.token !== 'string' || !session.token || /\s/.test(session.token) ||
      typeof session.email !== 'string' || !session.email || !id.safeParse(session.userID).success ||
      !Number.isFinite(Date.parse(session.expiresAt)) || Date.parse(session.expiresAt) <= Date.now()) throw new LocalConfigError('session_expired_or_wrong_scope')
    return { token: session.token, kind: 'session', email: session.email, userID: session.userID }
  } finally { data.fill(0) }
}
