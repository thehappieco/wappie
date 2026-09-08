// The vault: where the archive key lives in this browser.
//
// The key is the whole product. Whoever holds it reads everything; whoever
// loses it loses everything, permanently, including the people running the
// server. So it is never stored as it was typed: a passphrase derives a
// wrapping key, the archive key is sealed under it with AES-256-GCM, and only
// that sealed blob reaches IndexedDB.
//
// The honest limits, because "encrypted in the browser" is read as more than it
// is:
//
//   - Key derivation is PBKDF2-HMAC-SHA256 at 600,000 iterations, which is what
//     WebCrypto offers. Argon2id resists a GPU far better and is not available
//     without shipping WASM, which would put the archive key behind code that
//     is harder to audit than this file. A weak passphrase is weak.
//   - Anything that executes script in this origin can ask the unlocked session
//     for plaintext. The content security policy in index.html is what keeps
//     that surface to this page's own code.
//   - Unlocked, the key is a non-extractable CryptoKey: it can decrypt, and
//     nothing — including this code — can read its bytes back out.

import { type Bytes, encodeUTF8, fromBase64, fromHex, toBase64 } from './bytes'
import { importArchiveKey, publicFromPrivate } from './hpke'
import { fromPastedKey, type Session } from '../state/session'

const DB_NAME = 'whatserver2'
const DB_VERSION = 1
const STORE = 'vault'
const RECORD_ID = 'archive'

/** ITERATIONS follows the OWASP guidance for PBKDF2-HMAC-SHA256. */
const ITERATIONS = 600_000
const SALT_LEN = 16
const NONCE_LEN = 12

/** StoredVault is what sits in IndexedDB. Everything secret in it is sealed. */
export interface StoredVault {
  id: string
  version: 1
  /** Label is shown on the unlock screen so several profiles are tellable apart. */
  label: string
  serverURL: string
  iterations: number
  salt: Bytes
  nonce: Bytes
  /** Sealed holds the archive private key and the API key, as JSON. */
  sealed: Bytes
  /** The public half, kept in the clear so a wrong passphrase is caught early. */
  publicKey: Bytes
  createdAt: number
}

/** Secrets is what the sealed blob holds once opened. */
interface Secrets {
  archiveKey: string // base64
  apiKey: string
}



export class VaultError extends Error {
  constructor(
    message: string,
    readonly code: 'no_vault' | 'passphrase' | 'key_format' | 'unsupported',
  ) {
    super(message)
    this.name = 'VaultError'
  }
}

// ---------------------------------------------------------------------------
// IndexedDB
// ---------------------------------------------------------------------------

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new VaultError('este navegador não tem IndexedDB', 'unsupported'))
      return
    }
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: 'id' })
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

function transact<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>) {
  return openDB().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const tx = db.transaction(STORE, mode)
        const request = run(tx.objectStore(STORE))
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error)
        tx.oncomplete = () => db.close()
      }),
  )
}

export async function loadVault(): Promise<StoredVault | null> {
  const found = await transact<StoredVault | undefined>('readonly', (s) => s.get(RECORD_ID))
  return found ?? null
}

export async function forgetVault(): Promise<void> {
  await transact('readwrite', (s) => s.delete(RECORD_ID))
}

// ---------------------------------------------------------------------------
// Wrapping
// ---------------------------------------------------------------------------

async function wrappingKey(
  passphrase: string,
  salt: Bytes,
  iterations: number,
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', encodeUTF8(passphrase), 'PBKDF2', false, [
    'deriveKey',
  ])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

/**
 * parseArchiveKey accepts what `whatserverd archive-key` printed.
 *
 * Base64 is what it prints; hexadecimal is accepted too, because a key copied
 * out of a password manager often comes back in the other form and being
 * refused for that would send someone looking for a key they already have.
 */
export function parseArchiveKey(input: string): Bytes {
  const text = input.trim()
  if (!text) throw new VaultError('cole a chave do arquivo', 'key_format')

  let raw: Bytes | null = null
  if (/^[0-9a-fA-F\s:-]+$/.test(text)) {
    try {
      raw = fromHex(text)
    } catch {
      raw = null
    }
  }
  if (!raw) {
    try {
      raw = fromBase64(text.replace(/\s+/g, ''))
    } catch {
      throw new VaultError('a chave não é base64 nem hexadecimal', 'key_format')
    }
  }
  if (raw.length !== 32) {
    throw new VaultError(`a chave tem ${raw.length} bytes, e uma chave X25519 tem 32`, 'key_format')
  }
  return raw
}

/**
 * createVault wraps the archive key under a passphrase and stores it.
 *
 * The raw key is used once here and again to open a session; nothing keeps a
 * copy of the bytes.
 */
export async function createVault(input: {
  label: string
  serverURL: string
  apiKey: string
  archiveKey: string
  passphrase: string
}): Promise<Session> {
  const raw = parseArchiveKey(input.archiveKey)
  if (input.passphrase.length < 8) {
    throw new VaultError('a senha precisa de pelo menos 8 caracteres', 'passphrase')
  }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN))
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN))
  const key = await wrappingKey(input.passphrase, salt, ITERATIONS)

  const secrets: Secrets = { archiveKey: toBase64(raw), apiKey: input.apiKey }
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      encodeUTF8(JSON.stringify(secrets)),
    ),
  )

  const record: StoredVault = {
    id: RECORD_ID,
    version: 1,
    label: input.label || 'arquivo',
    serverURL: input.serverURL,
    iterations: ITERATIONS,
    salt,
    nonce,
    sealed,
    publicKey: await publicFromPrivate(raw),
    createdAt: Date.now(),
  }
  await transact('readwrite', (s) => s.put(record))

  return fromPastedKey({
    label: record.label,
    serverURL: record.serverURL,
    apiKey: input.apiKey,
    archive: await importArchiveKey(raw),
  })
}

/** unlock opens a stored vault. A wrong passphrase fails authentication, nothing more specific. */
export async function unlock(passphrase: string): Promise<Session> {
  const record = await loadVault()
  if (!record) throw new VaultError('não há chave guardada neste navegador', 'no_vault')

  const key = await wrappingKey(passphrase, record.salt, record.iterations)
  let secrets: Secrets
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: record.nonce },
      key,
      record.sealed,
    )
    secrets = JSON.parse(new TextDecoder().decode(plaintext)) as Secrets
  } catch {
    throw new VaultError('senha incorreta', 'passphrase')
  }

  return fromPastedKey({
    label: record.label,
    serverURL: record.serverURL,
    apiKey: secrets.apiKey,
    archive: await importArchiveKey(fromBase64(secrets.archiveKey)),
  })
}

/**
 * openOnce unlocks without storing anything, for a machine that should keep no
 * trace. Nothing reaches IndexedDB and closing the tab ends it.
 */
export async function openOnce(input: {
  serverURL: string
  apiKey: string
  archiveKey: string
}): Promise<Session> {
  const raw = parseArchiveKey(input.archiveKey)
  return fromPastedKey({
    label: 'sessão temporária',
    serverURL: input.serverURL,
    apiKey: input.apiKey,
    archive: await importArchiveKey(raw),
  })
}

export type { Session }
