import type { PrivateKey } from '../crypto/hpke'
import { encodeUTF8 } from '../crypto/bytes'
import { openBrowserAccountKey, validBrowserKeyEnvelope, type BrowserKeyEnvelope } from '../crypto/browserAccount'

/** An authorized browser session, never a password or an exportable private key. */
export interface BrowserLogin {
  id: string
  realm: string
  serverURL: string
  token: string
  expiresAt: number
  userID: string
  tenantID: string
  accountKey: PrivateKey
  accountEnvelope?: BrowserKeyEnvelope
  /** Public browser generation; it grants no authorization. */
  epoch?: string
}

interface StoredToken {
  wrappingKey: CryptoKey
  nonce: Uint8Array<ArrayBuffer>
  ciphertext: ArrayBuffer
}
type StoredLogin = StoredToken & (Omit<BrowserLogin, 'token'> & { version: 1 }
  | Omit<BrowserLogin, 'token' | 'accountKey' | 'accountEnvelope'> & { version: 2; accountEnvelope: BrowserKeyEnvelope })

export interface SessionChange { id: string; kind: 'cleared' }
const database = 'wappie-browser-session'
const storeName = 'session'
const current = 'current'
const listeners = new Set<(change: SessionChange) => void>()
let channel: BroadcastChannel | undefined

function notify(change: SessionChange) {
  for (const listener of listeners) listener(change)
  getChannel()?.postMessage(change)
}

function getChannel() {
  if (!channel && typeof window !== 'undefined' && typeof BroadcastChannel !== 'undefined') {
    channel = new BroadcastChannel('wappie-browser-session')
    channel.onmessage = event => {
      if (event.data?.kind !== 'cleared' || typeof event.data.id !== 'string') return
      for (const listener of listeners) listener(event.data as SessionChange)
    }
  }
  return channel
}

export function observeLocalSession(listener: (change: SessionChange) => void): () => void {
  getChannel()
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') { reject(new Error('browser storage unavailable')); return }
    const request = indexedDB.open(database, 1)
    request.onupgradeneeded = () => request.result.createObjectStore(storeName)
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
    request.onblocked = () => reject(new Error('browser storage blocked'))
  })
}

async function transaction<T>(mode: IDBTransactionMode, operation: (store: IDBObjectStore, done: (result: T) => void) => void): Promise<T> {
  const db = await openDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, mode)
    let result: T
    tx.oncomplete = () => { db.close(); resolve(result) }
    tx.onabort = tx.onerror = () => { db.close(); reject(tx.error ?? new Error('browser storage failed')) }
    try { operation(tx.objectStore(storeName), value => { result = value }) }
    catch (error) { tx.abort(); reject(error) }
  })
}

export function validBrowserLogin(value: unknown): value is BrowserLogin {
  if (!value || typeof value !== 'object') return false
  const login = value as BrowserLogin
  const key = login.accountKey?.key
  return typeof login.id === 'string' && login.id.length === 36 && typeof login.realm === 'string'
    && typeof login.serverURL === 'string' && typeof login.token === 'string' && login.token.length > 0 && login.token.length <= 4096
    && Number.isFinite(login.expiresAt) && typeof login.userID === 'string' && typeof login.tenantID === 'string'
    && typeof CryptoKey !== 'undefined' && key instanceof CryptoKey && key.type === 'private' && !key.extractable
    && key.algorithm.name === 'X25519' && key.usages.includes('deriveBits')
    && login.accountKey.publicRaw instanceof Uint8Array && login.accountKey.publicRaw.length === 32
}

function aad(login: Pick<BrowserLogin, 'id' | 'realm' | 'serverURL' | 'userID' | 'tenantID' | 'expiresAt' | 'epoch'>): Uint8Array<ArrayBuffer> {
  return encodeUTF8(JSON.stringify(['wappie/browser-session', 1, login.id, login.realm, login.serverURL, login.userID, login.tenantID, login.expiresAt, login.epoch ?? '']))
}

/** New records contain AES CryptoKeys and ciphertext only. Keep version 1
 * readable for browsers that already persisted X25519 handles successfully. */
export async function saveLocalSession(login: BrowserLogin): Promise<void> {
  if (!validBrowserLogin(login) || login.expiresAt <= Date.now()) throw new Error('invalid browser session')
  if (login.accountEnvelope && !validBrowserKeyEnvelope(login.accountEnvelope)) throw new Error('invalid browser account key')
  const wrappingKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(login) }, wrappingKey, encodeUTF8(login.token))
  const { token: _token, accountKey, accountEnvelope, ...metadata } = login
  const stored: StoredLogin = accountEnvelope
    ? { ...metadata, accountEnvelope, version: 2, wrappingKey, nonce, ciphertext }
    : { ...metadata, accountKey, version: 1, wrappingKey, nonce, ciphertext }
  let replaced: string | undefined
  const saved = await transaction<boolean>('readwrite', (store, done) => {
    // A delayed write must not restore a login that logout already cleared.
    const tombstone = store.get('revoked:' + login.id)
    tombstone.onsuccess = () => {
      if (tombstone.result) { done(false); return }
      const before = store.get(current)
      before.onsuccess = () => {
        const old = before.result as StoredLogin | undefined
        if (old && old.id !== login.id) {
          replaced = old.id
          store.put(Date.now(), 'revoked:' + old.id)
        }
        store.put(stored, current)
        done(true)
      }
    }
  })
  if (!saved) throw new Error('browser session was cleared')
  if (replaced) notify({ kind: 'cleared', id: replaced })
}

export async function loadLocalSession(): Promise<BrowserLogin | null> {
  const stored = await transaction<StoredLogin | undefined>('readonly', (store, done) => {
    const request = store.get(current)
    request.onsuccess = () => done(request.result as StoredLogin | undefined)
  })
  if (!stored) return null
  try {
    if (![1, 2].includes(stored.version) || stored.expiresAt <= Date.now() || stored.wrappingKey.extractable) throw new Error('expired or invalid browser session')
    const bytes = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: stored.nonce, additionalData: aad(stored) }, stored.wrappingKey, stored.ciphertext)
    const token = new TextDecoder().decode(bytes)
    new Uint8Array(bytes).fill(0)
    const accountKey = stored.version === 2 ? await openBrowserAccountKey(stored.accountEnvelope, stored.userID) : stored.accountKey
    const login: BrowserLogin = { id: stored.id, realm: stored.realm, serverURL: stored.serverURL, userID: stored.userID,
      tenantID: stored.tenantID, expiresAt: stored.expiresAt, accountKey, token, epoch: stored.epoch,
      accountEnvelope: stored.version === 2 ? stored.accountEnvelope : undefined }
    if (!validBrowserLogin(login) || await localSessionWasCleared(login.id)) throw new Error('invalid browser session')
    return login
  } catch (error) {
    // A browser/provider lacking an algorithm cannot establish corruption.
    // Keep the ciphertext for a compatible browser version or a later retry.
    if (error instanceof DOMException && ['NotSupportedError', 'InvalidAccessError', 'UnknownError'].includes(error.name)) throw error
    await clearLocalSession(stored.id)
    return null
  }
}

export async function localSessionWasCleared(id: string): Promise<boolean> {
  return transaction<boolean>('readonly', (store, done) => {
    const request = store.get('revoked:' + id)
    request.onsuccess = () => done(Boolean(request.result))
  })
}

/** Conditional deletion cannot erase a newer account while an old tab is closing. */
export async function clearLocalSession(id: string): Promise<void> {
  await transaction<void>('readwrite', (store, done) => {
    store.put(Date.now(), 'revoked:' + id)
    const request = store.get(current)
    request.onsuccess = () => {
      if ((request.result as StoredLogin | undefined)?.id === id) store.delete(current)
      done(undefined)
    }
  })
  notify({ kind: 'cleared', id })
}
