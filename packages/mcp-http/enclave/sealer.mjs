// Envelope v1 for sealed state (docs/mcp-enclave.md §8): AES-256-GCM under a
// KMS data key that only this image can open (GenerateDataKey and Decrypt,
// both with Recipient and the reader key's id pinned). Go stores the envelope
// as opaque bytes. The KMS encryption context binds the purpose, the reader,
// the origin and the collection; the GCM additional data binds the collection
// and the generation it was written as, so Go cannot hand back one
// collection's blob as another's, nor an older blob under a newer generation.
//
//   0      8   ASCII WMCPSEAL
//   8      1   version 0x01
//   9      2   L = length of the KMS CiphertextBlob, 1 to 6144 (big-endian)
//   11     L   CiphertextBlob of the data key
//   11+L   12  IV (random per write)
//   23+L   16  tag
//   39+L   …   ciphertext
import { createCipheriv, createDecipheriv, createSecretKey, randomBytes } from 'node:crypto'
import { StateError } from '../state.mjs'
import { refusedByKms } from './kms.mjs'

export const MAGIC = Buffer.from('WMCPSEAL', 'ascii')
export const VERSION = 1
const MAX_BLOB = 6144
const HEADER = MAGIC.length + 1 + 2

/** The KMS encryption context for a stored name. */
export function contextFor({ readerId, origin }, name) {
  if (name === 'infra') return { purpose: 'wappie-mcp-reader-infra', reader_id: readerId, origin }
  return { purpose: 'wappie-mcp-reader-state', reader_id: readerId, origin, name }
}

export const aadFor = (readerId, name, generation) => Buffer.from(JSON.stringify(['wappie-mcp-state', VERSION, readerId, name, generation]), 'utf8')

export function encodeEnvelope({ ciphertextBlob, iv, tag, ciphertext }) {
  if (ciphertextBlob.length < 1 || ciphertextBlob.length > MAX_BLOB || iv.length !== 12 || tag.length !== 16) throw new StateError('state_envelope_invalid')
  const length = Buffer.alloc(2)
  length.writeUInt16BE(ciphertextBlob.length)
  return Buffer.concat([MAGIC, Buffer.from([VERSION]), length, ciphertextBlob, iv, tag, ciphertext])
}

/** The four parts of an envelope, or StateError('state_auth_failed') for any other shape. */
export function decodeEnvelope(envelope) {
  const bad = () => { throw new StateError('state_auth_failed') }
  if (!Buffer.isBuffer(envelope) || envelope.length < HEADER + 1 + 28) bad()
  if (!envelope.subarray(0, MAGIC.length).equals(MAGIC) || envelope[MAGIC.length] !== VERSION) bad()
  const length = envelope.readUInt16BE(MAGIC.length + 1)
  if (length < 1 || length > MAX_BLOB || envelope.length < HEADER + length + 28) bad()
  const at = HEADER + length
  return {
    ciphertextBlob: envelope.subarray(HEADER, at), iv: envelope.subarray(at, at + 12), tag: envelope.subarray(at + 12, at + 28), ciphertext: envelope.subarray(at + 28),
  }
}

/**
 * `kms` is createKms()'s result; `keyArn` the reader key. The first write of a
 * name in this boot asks KMS for its data key; later writes reuse it with a
 * fresh IV. Opening always asks KMS (with the KeyId pinned), so a blob whose
 * data key came from anything but this key and this context never opens.
 * A KMS that cannot be reached is `state_unavailable` (the loader retries);
 * a KMS that refuses, or any shape, tag or AAD failure, is `state_auth_failed`.
 */
export function createSealer({ kms, keyArn, readerId, origin }) {
  const keys = new Map()
  async function dataKeyFor(name) {
    let entry = keys.get(name)
    if (!entry) {
      let generated
      try { generated = await kms.dataKey(keyArn, contextFor({ readerId, origin }, name)) } catch { throw new StateError('state_unavailable') }
      entry = { key: createSecretKey(generated.key), ciphertextBlob: generated.ciphertextBlob }
      generated.key.fill(0)
      keys.set(name, entry)
    }
    return entry
  }
  return {
    async seal(name, generation, plaintext) {
      const { key, ciphertextBlob } = await dataKeyFor(name)
      const iv = randomBytes(12)
      const cipher = createCipheriv('aes-256-gcm', key, iv)
      cipher.setAAD(aadFor(readerId, name, generation))
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
      return encodeEnvelope({ ciphertextBlob, iv, tag: cipher.getAuthTag(), ciphertext })
    },
    async open(name, generation, envelope) {
      const parts = decodeEnvelope(envelope)
      let raw
      try { raw = await kms.decrypt(keyArn, Buffer.from(parts.ciphertextBlob), contextFor({ readerId, origin }, name)) } catch (error) {
        throw new StateError(refusedByKms(error) || /^cms_/.test(error?.message ?? '') ? 'state_auth_failed' : 'state_unavailable')
      }
      let head
      try {
        if (raw.length !== 32) throw new Error('bad key')
        const decipher = createDecipheriv('aes-256-gcm', raw, parts.iv, { authTagLength: 16 })
        decipher.setAAD(aadFor(readerId, name, generation))
        decipher.setAuthTag(parts.tag)
        head = decipher.update(parts.ciphertext) // unauthenticated until final() checks the tag
        return Buffer.concat([head, decipher.final()])
      } catch {
        throw new StateError('state_auth_failed')
      } finally {
        raw.fill(0)
        head?.fill(0)
      }
    },
  }
}
