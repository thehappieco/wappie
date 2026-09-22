// Durable reader state: the HPKE recipient key the console seals bundles to,
// the key that encrypts the store, and the store itself (registered clients,
// active connections with their API keys, and token hashes). Pending consent
// requests and authorization codes live for minutes and stay in memory; a
// restart in the middle of a consent simply asks for a new one.
//
// Every file is private (0600 inside a 0700 directory), read back through
// readPrivateFile so a loosened mode refuses to start, and written through a
// temporary file created exclusively and renamed into place.
import { constants } from 'node:fs'
import { open, mkdir, stat, rename, unlink } from 'node:fs/promises'
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { dirname, join } from 'node:path'
import { hpke } from '@whatserver2/client'
import { readPrivateFile } from '@whatserver2/mcp/config'

const magic = Buffer.from('WMCP1')
const aad = Buffer.from('wappie-mcp-state/v1')
const persisted = ['clients', 'connections', 'tokens']
const keyOf = { clients: 'client_id', connections: 'connection_id', tokens: 'hash' }

export class StateError extends Error {
  constructor(code) { super(code); this.name = 'StateError'; this.code = code }
}

async function ensureDirectory(path) {
  try { await mkdir(path, { mode: 0o700 }) } catch (error) { if (error.code !== 'EEXIST') throw new StateError('state_dir_unavailable') }
  let info
  try { info = await stat(path) } catch { throw new StateError('state_dir_unavailable') }
  if (!info.isDirectory() || (info.mode & 0o077) !== 0 ||
    (typeof process.getuid === 'function' && info.uid !== process.getuid())) throw new StateError('state_dir_unsafe')
}

/** Exclusive temporary file, fsync, rename: readers see the old or the new file, never a torn one. */
export async function writePrivate(path, data) {
  const temp = `${path}.${randomBytes(6).toString('hex')}.tmp`
  let handle
  try {
    handle = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
    await handle.chmod(0o600)
    await handle.writeFile(data)
    await handle.sync()
    await handle.close()
    handle = undefined
    await rename(temp, path)
    let directory
    try { directory = await open(dirname(path), 'r'); await directory.sync() } catch { /* not every platform syncs directories */ }
    finally { await directory?.close() }
  } catch (error) {
    await handle?.close()
    await unlink(temp).catch(() => {})
    throw error
  }
}

const canonical = value => /^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value, 'base64url').toString('base64url') === value

async function readKey(path) {
  let data
  try { data = await readPrivateFile(path, { maxBytes: 128 }) } catch (error) {
    if (error.code === 'private_file_unavailable') return null
    throw new StateError('state_key_unsafe')
  }
  try {
    const encoded = data.toString('utf8').trim()
    if (!canonical(encoded)) throw new StateError('state_key_invalid')
    return Buffer.from(encoded, 'base64url')
  } finally { data.fill(0) }
}

async function loadOrCreateKey(path, generate) {
  const existing = await readKey(path)
  if (existing) return existing
  const raw = await generate()
  const encoded = Buffer.from(Buffer.from(raw).toString('base64url') + '\n')
  try { await writePrivate(path, encoded) } finally { encoded.fill(0) }
  return Buffer.from(raw)
}

async function recipientFrom(raw) {
  try {
    const privateKey = await hpke.importArchiveKey(new Uint8Array(raw))
    const publicKey = Buffer.from(privateKey.publicRaw)
    return { kid: createHash('sha256').update(publicKey).digest('hex').slice(0, 16), publicKey, publicKeyEncoded: publicKey.toString('base64url'), privateKey }
  } finally { raw.fill(0) }
}

export function encryptState(key, plaintext) {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  cipher.setAAD(aad)
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return Buffer.concat([magic, iv, cipher.getAuthTag(), encrypted])
}

export function decryptState(key, data) {
  if (data.length < magic.length + 12 + 16 || !data.subarray(0, magic.length).equals(magic)) throw new StateError('state_file_invalid')
  const iv = data.subarray(magic.length, magic.length + 12), tag = data.subarray(magic.length + 12, magic.length + 28)
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAAD(aad)
  decipher.setAuthTag(tag)
  try { return Buffer.concat([decipher.update(data.subarray(magic.length + 28)), decipher.final()]) }
  catch { throw new StateError('state_file_invalid') }
}

/**
 * Opens (or initialises) the state directory. The returned object holds the
 * live collections as Maps; `save()` persists the durable ones, coalescing
 * concurrent calls into at most one write in flight plus one queued.
 */
export async function openState(dir) {
  await ensureDirectory(dir)
  await ensureDirectory(join(dir, 'keys'))
  const key = await loadOrCreateKey(join(dir, 'keys', 'state.key'), () => randomBytes(32))
  const recipient = await recipientFrom(await loadOrCreateKey(join(dir, 'keys', 'recipient.key'), async () => {
    const pair = await hpke.generateKeyPair()
    return pair.privateKey
  }))
  const previousRaw = await readKey(join(dir, 'keys', 'recipient.previous'))
  const previous = previousRaw ? await recipientFrom(previousRaw) : null
  const file = join(dir, 'state.json.enc')
  const state = {
    dir, recipient, previous,
    clients: new Map(), pending: new Map(), connections: new Map(), codes: new Map(), tokens: new Map(),
    saves: 0,
  }
  let data
  try { data = await readPrivateFile(file, { maxBytes: 8 * 1024 * 1024 }) } catch (error) {
    if (error.code !== 'private_file_unavailable') throw new StateError('state_file_unsafe')
  }
  if (data) {
    const plain = decryptState(key, data)
    data.fill(0)
    let parsed
    try { parsed = JSON.parse(plain.toString('utf8')) } catch { throw new StateError('state_file_invalid') }
    finally { plain.fill(0) }
    if (!parsed || parsed.version !== 1) throw new StateError('state_file_invalid')
    for (const name of persisted) for (const record of Array.isArray(parsed[name]) ? parsed[name] : []) state[name].set(record[keyOf[name]], record)
  }
  let writing = null, again = false
  async function writeOnce() {
    const plain = Buffer.from(JSON.stringify({ version: 1, ...Object.fromEntries(persisted.map(name => [name, [...state[name].values()]])) }))
    try { await writePrivate(file, encryptState(key, plain)) } finally { plain.fill(0) }
    state.saves++
  }
  state.save = () => {
    if (writing) { again = true; return writing }
    writing = (async () => { do { again = false; await writeOnce() } while (again) })().finally(() => { writing = null })
    return writing
  }
  /** Forgets a connection and everything that could still use it. */
  state.wipeConnection = id => {
    let changed = state.connections.delete(id)
    for (const [hash, token] of state.tokens) if (token.connection_id === id) { state.tokens.delete(hash); changed = true }
    for (const [hash, code] of state.codes) if (code.connection_id === id) state.codes.delete(hash)
    for (const [request, pending] of state.pending) if (pending.connection_id === id) state.pending.delete(request)
    return changed
  }
  /** Kills a token family; returns the connection it served (now wiped) or null. */
  state.revokeFamily = family => {
    let connection = null
    for (const [hash, token] of state.tokens) if (token.family_id === family) { connection = token.connection_id; state.tokens.delete(hash) }
    for (const record of state.connections.values()) if (record.family_id === family) connection = record.connection_id
    if (connection) state.wipeConnection(connection)
    return connection
  }
  state.close = async () => { if (writing) await writing }
  return state
}
