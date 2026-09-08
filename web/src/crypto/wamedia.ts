// WhatsApp's media encryption scheme, decrypting side.
//
// Mirrors internal/crypto/wamedia. The server stores the ciphertext the CDN
// served, verbatim, and seals only the 32-byte mediaKey — so the bytes that
// arrive here over /v1/media/{uid} are useless to anything that intercepts
// them, and this is the first place in the whole system where an attachment
// exists in the clear.
//
// Pinned against Go by test/wamedia.spec.ts.

import { type Bytes, concat, equal } from './bytes'

export const KEY_LEN = 32
export const MAC_LEN = 10
const BLOCK_SIZE = 16

export type MediaType = 'image' | 'sticker' | 'video' | 'ptv' | 'audio' | 'ptt' | 'document'

// Several types deliberately share a label. That is WhatsApp's scheme, not an
// oversight: stickers use the image keys, and the round video note and the
// voice note ride on video and audio respectively.
const infoString: Record<MediaType, string> = {
  image: 'WhatsApp Image Keys',
  sticker: 'WhatsApp Image Keys',
  video: 'WhatsApp Video Keys',
  ptv: 'WhatsApp Video Keys',
  audio: 'WhatsApp Audio Keys',
  ptt: 'WhatsApp Audio Keys',
  document: 'WhatsApp Document Keys',
}

export class MediaError extends Error {
  constructor(
    message: string,
    readonly code: 'type' | 'key_length' | 'short' | 'block' | 'mac' | 'padding',
  ) {
    super(message)
    this.name = 'MediaError'
  }
}

export interface MediaKeys {
  iv: Bytes // 16
  cipher: Bytes // 32
  mac: Bytes // 32
}

/**
 * deriveKeys expands a mediaKey into the IV, cipher key and MAC key.
 *
 * WhatsApp expands to 112 bytes and uses the first 80. The trailing 32 are a
 * refKey this scheme never consumes, but truncating the expansion would change
 * the first 80 — so the full 112 are derived.
 */
export async function deriveKeys(mediaKey: Bytes, type: MediaType): Promise<MediaKeys> {
  const info = infoString[type]
  if (!info) throw new MediaError(`tipo de mídia desconhecido: ${type}`, 'type')
  if (mediaKey.length !== KEY_LEN) {
    throw new MediaError(`a mediaKey tem ${mediaKey.length} bytes, esperava ${KEY_LEN}`, 'key_length')
  }

  const key = await crypto.subtle.importKey('raw', mediaKey, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      // Empty rather than absent. HMAC pads a short key with zeros, so an
      // empty salt and the 32 zero bytes Go's nil salt becomes are the same
      // input.
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(info),
    },
    key,
    112 * 8,
  )
  const expanded = new Uint8Array(bits)
  return {
    iv: expanded.subarray(0, 16),
    cipher: expanded.subarray(16, 48),
    mac: expanded.subarray(48, 80),
  }
}

/**
 * decrypt reverses the scheme. Input is exactly what the CDN serves:
 * ciphertext followed by ten MAC bytes.
 *
 * The MAC is verified before anything is decrypted, which is what keeps the
 * padding check that WebCrypto performs afterwards from acting as an oracle.
 */
export async function decrypt(
  enc: Bytes,
  mediaKey: Bytes,
  type: MediaType,
): Promise<Bytes> {
  const k = await deriveKeys(mediaKey, type)

  if (enc.length < MAC_LEN + BLOCK_SIZE) throw new MediaError('cifra curta demais', 'short')
  const ciphertext = enc.subarray(0, enc.length - MAC_LEN)
  const mac = enc.subarray(enc.length - MAC_LEN)
  if (ciphertext.length % BLOCK_SIZE !== 0) {
    throw new MediaError('a cifra não é múltipla do bloco', 'block')
  }

  if (!(await verifyMAC(k, ciphertext, mac))) {
    throw new MediaError('MAC não confere', 'mac')
  }

  const key = await crypto.subtle.importKey('raw', k.cipher, { name: 'AES-CBC' }, false, ['decrypt'])
  try {
    // WebCrypto strips the PKCS#7 padding itself and refuses a malformed one,
    // which is the same check Go does by hand.
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: k.iv }, key, ciphertext)
    return new Uint8Array(plaintext)
  } catch {
    throw new MediaError('preenchimento inválido', 'padding')
  }
}

/** The MAC covers the IV as well as the ciphertext, and is truncated to ten bytes. */
async function verifyMAC(k: MediaKeys, ciphertext: Bytes, want: Bytes): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    'raw',
    k.mac,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const full = new Uint8Array(await crypto.subtle.sign('HMAC', key, concat(k.iv, ciphertext)))
  return equal(full.subarray(0, MAC_LEN), want)
}

/** sha256 is used to check a download against the hash the message carried. */
export async function sha256(data: Bytes): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data))
}
