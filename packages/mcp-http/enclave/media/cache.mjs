// The two per-connection caches of stage A (docs/mcp-enclave.md §16.9).
//
// - The result cache keeps an open's outcome under its open key for
//   RESULT_TTL_MS from completion, so an identical call (ChatGPT repeats
//   them) fetches nothing.
// - The text cache keeps, per attachment, what its jobs read: the rendered
//   text of an office file, zip listing or plain-text file, a PDF's page texts
//   by job window, and the facts the header repeats. A new cursor needs no
//   fetch; images are never in it.
//
// Both count 2 bytes per string code unit plus every Buffer's length, within
// CACHE_CONNECTION_BYTES per connection and CACHE_ENCLAVE_BYTES in all. The
// least recently used entry goes first, the same connection's before anyone
// else's. There is no cross-connection deduplication: it would tell one
// connection what another opened.
import { CACHE_CONNECTION_BYTES, CACHE_ENCLAVE_BYTES, RESULT_TTL_MS, TEXT_TTL_MS } from './policy.mjs'

/** Bytes an entry holds, by the rule above. */
export function sizeOf(value) {
  if (typeof value === 'string') return value.length * 2
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return value.length
  if (Array.isArray(value)) return value.reduce((sum, item) => sum + sizeOf(item), 0)
  if (value && typeof value === 'object') return Object.entries(value).reduce((sum, [key, item]) => sum + key.length * 2 + sizeOf(item), 0)
  return 8
}

/** Zeroes every Buffer a cached value holds (image blocks); strings cannot be. */
function zero(value) {
  for (const image of value?.outcome?.result?.images ?? []) image.data.fill(0)
}

export function createCaches({ now = Date.now, connectionBytes = CACHE_CONNECTION_BYTES, enclaveBytes = CACHE_ENCLAVE_BYTES } = {}) {
  // One map for both caches: its order is recency, oldest first.
  const entries = new Map()
  const perConnection = new Map()
  let total = 0
  const keyOf = (type, connection, name) => `${type}\u0000${connection}\u0000${name}`

  function remove(key) {
    const entry = entries.get(key)
    if (!entry) return
    entries.delete(key)
    total -= entry.bytes
    const left = (perConnection.get(entry.connection) ?? 0) - entry.bytes
    if (left > 0) perConnection.set(entry.connection, left); else perConnection.delete(entry.connection)
    zero(entry.value)
  }
  function prune() {
    const at = now()
    for (const [key, entry] of entries) if (entry.expires <= at) remove(key)
  }
  /** Evicts the least recently used entries of `connection` first, then anyone's, until `fits()`. */
  function evict(connection, fits) {
    for (const [key, entry] of entries) { if (fits()) return; if (entry.connection === connection) remove(key) }
    for (const key of entries.keys()) { if (fits()) return; remove(key) }
  }
  function put(type, connection, name, value, ttl) {
    const key = keyOf(type, connection, name)
    remove(key)
    prune()
    const bytes = sizeOf(value)
    // Refused, it stays its owner's: only what the cache holds is zeroed when it goes.
    if (bytes > connectionBytes || bytes > enclaveBytes) return false
    evict(connection, () => (perConnection.get(connection) ?? 0) + bytes <= connectionBytes && total + bytes <= enclaveBytes)
    entries.set(key, { connection, value, bytes, expires: now() + ttl })
    perConnection.set(connection, (perConnection.get(connection) ?? 0) + bytes)
    total += bytes
    return true
  }
  function get(type, connection, name) {
    const key = keyOf(type, connection, name)
    const entry = entries.get(key)
    if (!entry) return undefined
    if (entry.expires <= now()) { remove(key); return undefined }
    entries.delete(key)
    entries.set(key, entry)
    return entry.value
  }
  function drop(connection, test = () => true) {
    for (const [key, entry] of [...entries]) if (entry.connection === connection && test(entry.value)) remove(key)
  }
  return {
    result: {
      /** `{outcome, kinds}` of an open key, while it lives. */
      get: (connection, openKey) => get('result', connection, openKey),
      set: (connection, openKey, value) => put('result', connection, openKey, value, RESULT_TTL_MS),
    },
    text: {
      /** `{uid, kind, facts, text?, windows?}` of an attachment, while it lives. */
      get: (connection, uid) => get('text', connection, uid),
      set: (connection, uid, value) => put('text', connection, uid, value, TEXT_TTL_MS),
    },
    /** Everything of a connection, or of it whose kinds `test` names. */
    drop,
    dropKinds(connection, kinds) { drop(connection, value => (value.kinds ?? [value.kind]).some(kind => kinds.includes(kind))) },
    bytes: connection => (connection === undefined ? total : perConnection.get(connection) ?? 0),
    size: () => entries.size,
    clear() { for (const key of [...entries.keys()]) remove(key) },
  }
}
