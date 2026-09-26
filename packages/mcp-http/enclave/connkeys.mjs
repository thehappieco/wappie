// The per-connection keys of content connections (docs/mcp-enclave.md §15.5),
// in ephemeral mode: memory only, never in sealed state, gone with the
// process. Each is the X25519 key the console verified in an attestation, the
// service account's public key and what every grant of the connection is
// sealed to; it is held as a non-extractable CryptoKey, so nothing here, nor
// anything that reaches this map, can turn it back into bytes. Wiping drops
// the reference: a CryptoKey cannot be overwritten, and the garbage collector
// is the only thing that can end it.

/** A non-extractable X25519 private CryptoKey with its 32-byte public half. */
function acceptable(privateKey) {
  const key = privateKey?.key, publicRaw = privateKey?.publicRaw
  return typeof CryptoKey === 'function' && key instanceof CryptoKey && key.type === 'private' && key.extractable === false &&
    key.algorithm?.name === 'X25519' && publicRaw instanceof Uint8Array && publicRaw.length === 32
}

export class ConnKeyError extends Error {
  constructor(code) { super(code); this.name = 'ConnKeyError'; this.code = code }
}

/**
 * `set(id, privateKey)` takes the `hpke.PrivateKey` shape (`{key, publicRaw}`)
 * and keeps its own copy of the public half; `get(id)` returns the stored
 * pair (callers hand out copies of `publicRaw`, never this one).
 */
export function createConnKeys() {
  const keys = new Map()
  return {
    set(id, privateKey) {
      if (!acceptable(privateKey)) throw new ConnKeyError('connkey_extractable')
      keys.set(id, Object.freeze({ key: privateKey.key, publicRaw: new Uint8Array(privateKey.publicRaw) }))
    },
    get: id => keys.get(id),
    has: id => keys.has(id),
    wipe(id) {
      const held = keys.get(id)
      if (!held) return false
      held.publicRaw.fill(0)
      return keys.delete(id)
    },
    wipeAll() { for (const id of [...keys.keys()]) this.wipe(id) },
    size: () => keys.size,
  }
}
