import { encodeUTF8, toBase64, type Bytes } from './bytes'
import { importArchiveKey, type PrivateKey } from './hpke'

/** Local ciphertext protected by a non-extractable browser AES key. WebKit
 * currently loses IndexedDB records containing an X25519 CryptoKey. */
export interface BrowserKeyEnvelope {
  version: 1
  key: CryptoKey
  nonce: Bytes
  ciphertext: ArrayBuffer
  publicRaw: Bytes
}

function aad(userID: string, publicRaw: Bytes): Bytes {
  return encodeUTF8(JSON.stringify(['wappie/browser-account-key', 1, userID, toBase64(publicRaw)]))
}

export function validBrowserKeyEnvelope(value: unknown): value is BrowserKeyEnvelope {
  const envelope = value as BrowserKeyEnvelope | undefined
  const key = envelope?.key
  return envelope?.version === 1 && typeof CryptoKey !== 'undefined' && key instanceof CryptoKey
    && key.type === 'secret' && !key.extractable && key.algorithm.name === 'AES-GCM'
    && (key.algorithm as AesKeyAlgorithm).length === 256 && key.usages.includes('encrypt') && key.usages.includes('decrypt')
    && envelope.nonce instanceof Uint8Array && envelope.nonce.length === 12
    && envelope.ciphertext instanceof ArrayBuffer && envelope.ciphertext.byteLength === 48
    && envelope.publicRaw instanceof Uint8Array && envelope.publicRaw.length === 32
}

/** Called only while sign-in already holds the decrypted raw key. Never
 * exports an existing CryptoKey, persists plaintext, or sends this to a server. */
export async function sealBrowserAccountKey(raw: Bytes, publicRaw: Bytes, userID: string): Promise<BrowserKeyEnvelope> {
  if (raw.length !== 32 || publicRaw.length !== 32) throw new Error('invalid account key')
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(userID, publicRaw) }, key, raw)
  return { version: 1, key, nonce, ciphertext, publicRaw: publicRaw.slice() }
}

export async function openBrowserAccountKey(envelope: BrowserKeyEnvelope, userID: string): Promise<PrivateKey> {
  if (!validBrowserKeyEnvelope(envelope)) throw new Error('invalid browser account key')
  const raw = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: envelope.nonce,
    additionalData: aad(userID, envelope.publicRaw) }, envelope.key, envelope.ciphertext))
  try {
    const account = await importArchiveKey(raw)
    if (!account.publicRaw.every((byte, index) => byte === envelope.publicRaw[index])) throw new Error('invalid browser account key')
    return account
  } finally { raw.fill(0) }
}
