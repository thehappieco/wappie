// WhatsApp's media encryption, decrypting side, streamed (docs/mcp-enclave.md
// §16.5). The same scheme as internal/crypto/wamedia and
// packages/client/src/crypto/wamedia.ts, pinned against Go's vectors, but with
// one plaintext buffer instead of two copies, and with nothing of the
// plaintext reachable before both checks pass: CBC is malleable, and the row's
// `file_enc_sha256` alone is the archive server's word.
//
// The object O of length n is C = O[0, n−10) then T = O[n−10, n). The HMAC
// covers iv ‖ C and is truncated to ten bytes; the SHA-256 covers all of O.
import { createDecipheriv, createHash, createHmac, hkdfSync, timingSafeEqual } from 'node:crypto'
import { refusal } from './gate.mjs'

export const KEY_LEN = 32
export const MAC_LEN = 10
const BLOCK = 16
/** The smallest object: one block of padding and the MAC. */
export const MIN_OBJECT = BLOCK + MAC_LEN
const tampered = () => refusal('attachment_tampered')

/** Whether `n` is a length a WhatsApp object can have. */
export const objectLength = n => Number.isSafeInteger(n) && n >= MIN_OBJECT && (n - MAC_LEN) % BLOCK === 0

/**
 * A decryption for one object of `length` bytes: `update(chunk)` for each
 * chunk in order (each is zeroed after use), then `finish(encSHA256)`, which
 * returns the plaintext as a view of the one buffer, or throws
 * `attachment_tampered` with that buffer zeroed. `wipe()` zeroes it whatever
 * happened; the caller calls it when the open ends. The caller zeroes
 * `mediaKey`; every key derived from it is zeroed here before this returns.
 */
export function createMediaStream({ mediaKey, label, length }) {
  if (!(mediaKey instanceof Uint8Array) || mediaKey.length !== KEY_LEN || !objectLength(length) || typeof label !== 'string') throw tampered()
  const okm = new Uint8Array(hkdfSync('sha256', mediaKey, Buffer.alloc(32), label, 112))
  const iv = okm.subarray(0, 16), encKey = okm.subarray(16, 48), macKey = okm.subarray(48, 80)
  let hash, hmac, decipher
  try {
    hash = createHash('sha256')
    hmac = createHmac('sha256', macKey).update(iv)
    decipher = createDecipheriv('aes-256-cbc', encKey, iv).setAutoPadding(false)
  } finally { okm.fill(0) }
  const body = length - MAC_LEN
  const plain = Buffer.alloc(body)
  const tag = Buffer.alloc(MAC_LEN)
  let offset = 0, written = 0, done = false
  function decrypt(part) {
    const out = decipher.update(part)
    out.copy(plain, written)
    written += out.length
    out.fill(0)
  }
  return {
    /** Feeds the next bytes of O; more than `length` in all is `attachment_tampered`. */
    update(chunk) {
      try {
        if (done || offset + chunk.length > length) throw tampered()
        hash.update(chunk)
        const cipherEnd = Math.max(0, Math.min(chunk.length, body - offset))
        if (cipherEnd > 0) {
          const part = chunk.subarray(0, cipherEnd)
          hmac.update(part)
          decrypt(part)
        }
        if (cipherEnd < chunk.length) tag.set(chunk.subarray(cipherEnd), Math.max(0, offset - body))
        offset += chunk.length
      } catch (error) { plain.fill(0); throw error } finally { chunk.fill(0) }
    },
    /** Checks the hash and the MAC in constant time, then the PKCS#7 padding; the plaintext is a view of the buffer. */
    finish(encSHA256) {
      done = true
      try {
        if (offset !== length || !(encSHA256 instanceof Uint8Array) || encSHA256.length !== 32) throw tampered()
        const digest = hash.digest()
        const mac = hmac.digest().subarray(0, MAC_LEN)
        const rest = decipher.final()
        if (rest.length) { rest.fill(0); throw tampered() }
        // Both comparisons run whatever the first one says.
        const hashOK = timingSafeEqual(digest, encSHA256)
        const macOK = timingSafeEqual(mac, tag)
        if (!hashOK || !macOK || written !== body) throw tampered()
        const pad = plain[body - 1]
        if (pad < 1 || pad > BLOCK) throw tampered()
        for (let index = body - pad; index < body; index++) if (plain[index] !== pad) throw tampered()
        return plain.subarray(0, body - pad)
      } catch (error) { plain.fill(0); throw error } finally { tag.fill(0) }
    },
    wipe() { done = true; plain.fill(0); tag.fill(0) },
  }
}
