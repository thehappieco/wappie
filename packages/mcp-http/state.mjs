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

/** The recipient record for a raw X25519 private key; the raw bytes are zeroed. */
export async function recipientFrom(raw) {
  try {
    const privateKey = await hpke.importArchiveKey(new Uint8Array(raw))
    const publicKey = Buffer.from(privateKey.publicRaw)
    return { kid: createHash('sha256').update(publicKey).digest('hex').slice(0, 16), publicKey, publicKeyEncoded: publicKey.toString('base64url'), privateKey }
  } finally { raw.fill(0) }
}

/**
 * A fresh recipient that never touches a disk: the pair is generated with a
 * non-extractable private half, so its bytes never exist in this process
 * (no PKCS#8 export to zero, as hpke.generateKeyPair would leave), and it
 * lives exactly as long as the record holding it.
 */
export async function newRecipient() {
  const pair = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])
  const publicKey = Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey))
  return {
    kid: createHash('sha256').update(publicKey).digest('hex').slice(0, 16), publicKey, publicKeyEncoded: publicKey.toString('base64url'),
    privateKey: { key: pair.privateKey, publicRaw: new Uint8Array(publicKey) },
  }
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
 * The live collections and the operations every store shares. `persist()` is
 * the store's own writer; `save()` coalesces concurrent calls into at most one
 * write in flight plus one queued.
 */
function liveState(fields) {
  const state = {
    ...fields,
    clients: new Map(), pending: new Map(), connections: new Map(), codes: new Map(), tokens: new Map(),
    saves: 0,
  }
  /** Forgets a connection and everything that could still use it. */
  state.wipeConnection = id => {
    let changed = state.connections.delete(id)
    for (const [hash, token] of state.tokens) if (token.connection_id === id) { state.tokens.delete(hash); changed = true }
    for (const [hash, code] of state.codes) if (code.connection_id === id) state.codes.delete(hash)
    for (const [request, pending] of state.pending) if (pending.connection_id === id) state.pending.delete(request)
    return changed
  }
  /**
   * Kills a token family; returns the connection it served (now wiped) or
   * null. Only the connection whose record carries the family is wiped: a
   * stale family's tokens may still name an id that now holds another record.
   */
  state.revokeFamily = family => {
    let connection = null
    for (const [hash, token] of state.tokens) if (token.family_id === family) state.tokens.delete(hash)
    for (const record of state.connections.values()) if (record.family_id === family) connection = record.connection_id
    if (connection) state.wipeConnection(connection)
    return connection
  }
  return state
}

function coalesced(writeOnce) {
  let writing = null, again = false
  const save = () => {
    if (writing) { again = true; return writing }
    writing = (async () => { do { again = false; await writeOnce() } while (again) })().finally(() => { writing = null })
    return writing
  }
  return { save, settle: async () => { if (writing) await writing } }
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
  const state = liveState({ dir, recipient, previous })
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
  const writer = coalesced(async () => {
    const plain = Buffer.from(JSON.stringify({ version: 1, ...Object.fromEntries(persisted.map(name => [name, [...state[name].values()]])) }))
    try { await writePrivate(file, encryptState(key, plain)) } finally { plain.fill(0) }
    state.saves++
  })
  state.save = writer.save
  state.close = writer.settle
  return state
}

// ---- Sealed state (the enclave) ----------------------------------------------
//
// The enclave has no disk that outlives it. Each durable collection is sealed
// on its own (see enclave/sealer.mjs for the envelope) and kept by Go, which
// sees only opaque bytes and a generation counter: `store.put` succeeds only
// when the generation it names is still current, so two writers, or a writer
// racing a restored copy, can never silently overwrite each other.

/** The durable collections under their stored names; `infra` is the enclave's own. */
export const SEALED_NAMES = { clients: 'as-clients', connections: 'as-connections', tokens: 'as-tokens' }
export const SEALED_MAX_PLAINTEXT = 11 * 1024 * 1024
export const BACKOFF_START_MS = 1000
export const BACKOFF_MAX_MS = 60_000
// Not unref'd: while the state loads, this wait is all that keeps the process alive.
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

/** A StateError('state_auth_failed') is final; anything else while loading is Go being away. */
const fatal = error => error instanceof StateError && error.code !== 'state_unavailable'

/**
 * One sealed collection: loaded once (retrying with backoff while the store
 * is unreachable), then written only when its plaintext changed, with at most
 * one write in flight and one queued. A failed write keeps it dirty and
 * retries on the same backoff; a generation conflict is handed to
 * `onConflict`, which in the enclave ends the process.
 */
export function sealedCollection({ store, sealer, name, log, onConflict, wait = sleep }) {
  let generation = 0, written = null, loaded = false, dirty = false, failures = 0, timer = null
  let pending = null
  const writer = coalesced(async () => {
    const plain = pending
    pending = null
    if (!plain) return
    const digest = createHash('sha256').update(plain).digest('hex')
    try {
      if (digest === written) { dirty = false; return }
      const envelope = await sealer.seal(name, generation + 1, plain)
      generation = await store.put(name, generation, envelope)
      written = digest; dirty = false; failures = 0
    } catch (error) {
      if (error instanceof StateError && error.code === 'state_conflict') { log.event('state_conflict'); onConflict(); return }
      dirty = true; failures++
      log.event('state_save_failed', { failures })
      schedule()
    } finally { plain.fill(0) }
  })
  let serialize = null
  function schedule() {
    if (timer) return
    const delay = Math.min(BACKOFF_MAX_MS, BACKOFF_START_MS * 2 ** Math.min(failures - 1, 10))
    timer = setTimeout(() => { timer = null; void collection.save() }, delay)
    timer.unref?.()
  }
  const collection = {
    name,
    get generation() { return generation },
    get dirty() { return dirty },
    /** The opened plaintext, or null when the store never held this name. */
    async load() {
      for (let attempt = 0; ; attempt++) {
        try {
          const found = await store.get(name)
          loaded = true
          if (!found) {
            // Nothing to write until something changes: an empty collection Go never held stays absent.
            if (serialize) { const empty = serialize(); written = createHash('sha256').update(empty).digest('hex'); empty.fill(0) }
            return null
          }
          const plain = await sealer.open(name, found.generation, found.blob)
          generation = found.generation
          written = createHash('sha256').update(plain).digest('hex')
          return plain
        } catch (error) {
          if (fatal(error)) throw error
          loaded = false
          log.event('state_load_retry', { attempt: attempt + 1 })
          await wait(Math.min(BACKOFF_MAX_MS, BACKOFF_START_MS * 2 ** Math.min(attempt, 10)))
        }
      }
    },
    /** `serialize()` returns the plaintext Buffer to write (zeroed here once sealed). */
    bind(fn) { serialize = fn },
    save() {
      if (!loaded) throw new StateError('state_not_loaded')
      const plain = serialize()
      if (plain.length > SEALED_MAX_PLAINTEXT) { plain.fill(0); dirty = true; log.event('state_too_large'); return Promise.resolve() }
      pending?.fill(0)
      pending = plain
      return writer.save()
    },
    async close() { if (timer) { clearTimeout(timer); timer = null }; await writer.settle() },
  }
  return collection
}

/** The records of an `as-*` plaintext, or StateError('state_auth_failed') for any other shape. */
function recordsOf(plain, name) {
  let parsed
  try { parsed = JSON.parse(plain.toString('utf8')) } catch { throw new StateError('state_auth_failed') }
  finally { plain.fill(0) }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || parsed.version !== 1 || parsed.name !== name ||
    !Array.isArray(parsed.records) || Object.keys(parsed).length !== 3) throw new StateError('state_auth_failed')
  return parsed.records
}

/**
 * The enclave's state: the same object openState returns (without a reader
 * key: the enclave mints one per request), backed by three sealed
 * collections. Resolves only once all three are loaded. `onConflict` defaults
 * to throwing, and the enclave passes one that exits.
 */
export async function openSealedState({ store, sealer, log, onConflict = () => { throw new StateError('state_conflict') }, wait }) {
  const state = liveState({})
  const collections = Object.entries(SEALED_NAMES).map(([field, name]) => {
    const collection = sealedCollection({ store, sealer, name, log, onConflict, wait })
    collection.bind(() => Buffer.from(JSON.stringify({ version: 1, name, records: [...state[field].values()] })))
    return [field, collection]
  })
  for (const [field, collection] of collections) {
    const plain = await collection.load()
    if (!plain) continue
    for (const record of recordsOf(plain, collection.name)) {
      const key = record && typeof record === 'object' ? record[keyOf[field]] : undefined
      if (typeof key !== 'string') throw new StateError('state_auth_failed')
      state[field].set(key, record)
    }
  }
  state.save = async () => {
    await Promise.all(collections.map(([, collection]) => collection.save()))
    state.saves++
  }
  /** How many collections hold changes Go has not accepted yet (the health line's `state_dirty`). */
  state.dirty = () => collections.filter(([, collection]) => collection.dirty).length
  state.close = async () => { await Promise.all(collections.map(([, collection]) => collection.close())) }
  return state
}
