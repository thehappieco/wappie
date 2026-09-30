import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL } from 'node:url'

import { encodeUTF8, toHex, type Bytes } from '../src/crypto/bytes'
import { generateKeyPair, seal as hpkeSeal } from '../src/crypto/hpke'
import { dedupeTag, DerivedError, derivedAAD, openDerived, sealDerived, validateDerivedRecord, type DedupeInput, type DerivedRecord, type DerivedScope } from '../src/crypto/derived'

// AI results (docs/mcp-enclave.md §18.8): the attested reader seals them in
// Node (packages/mcp-http/enclave/ai/derived.mjs) and stores them in the
// archive; the console opens them here, with the person's own DSK. The
// records in testdata/node-derived.json were sealed there, and reader.mjs
// opens the same file. A record opens for exactly its namespace, number,
// message, function and epoch, and one Go made with the device's public key
// never does (N-AI-3). Dedupe tags match the enclave's, and differ when only
// the language does (N-AI-6).

interface Vectors {
  dsk: string
  namespace: string
  device_id: string
  epoch: number
  records: { name: string; message_uid: string; feature: DerivedScope['feature']; plaintext: string; sealed: string }[]
  negatives: { why: string; scope: DerivedScope; sealed: string }[]
  dedupe: { name: string; scope: Pick<DerivedScope, 'namespace' | 'device_id' | 'epoch'>; input: DedupeInput; tag: string }[]
}
const vectors: Vectors = JSON.parse(readFileSync(fileURLToPath(new URL('../testdata/node-derived.json', import.meta.url)), 'utf8'))
const url = (value: string): Bytes => new Uint8Array(Buffer.from(value, 'base64url'))
const dsk = url(vectors.dsk)
const scopeOf = (item: Vectors['records'][number]): DerivedScope => ({ namespace: vectors.namespace, device_id: vectors.device_id, epoch: vectors.epoch, message_uid: item.message_uid, feature: item.feature })

describe('records sealed in Node, opened in the browser', () => {
  for (const item of vectors.records) {
    it(`opens ${item.name}`, async () => {
      const record = await openDerived(dsk, scopeOf(item), url(item.sealed))
      expect(record).toEqual(JSON.parse(item.plaintext))
    })
  }

  for (const item of vectors.negatives) {
    it(`refuses ${item.why}`, async () => {
      await expect(openDerived(dsk, item.scope, url(item.sealed))).rejects.toThrow(DerivedError)
    })
  }

  it('refuses a record Go sealed to the device public key (N-AI-3)', async () => {
    // Go holds each number's public key and nothing that derives k: an HPKE
    // seal to that key, in any header, is not a record.
    const pair = await generateKeyPair()
    const item = vectors.records[0]
    const scope = scopeOf(item)
    const { enc, ciphertext } = await hpkeSeal(pair.publicKey, encodeUTF8('wappie-derived/v1'), derivedAAD(scope), encodeUTF8(item.plaintext))
    const header = new Uint8Array([...encodeUTF8('WDRV'), 1, 0, scope.epoch])
    const forged = new Uint8Array([...header, ...enc, ...ciphertext])
    await expect(openDerived(pair.privateKey, scope, forged)).rejects.toThrow(DerivedError)
  })

  it('refuses a DSK of the wrong length and a scope that is not one', async () => {
    const item = vectors.records[0]
    await expect(openDerived(dsk.subarray(0, 31) as Bytes, scopeOf(item), url(item.sealed))).rejects.toThrow(DerivedError)
    await expect(openDerived(dsk, { ...scopeOf(item), epoch: 0 }, url(item.sealed))).rejects.toThrow(DerivedError)
    await expect(openDerived(dsk, { ...scopeOf(item), device_id: 'not-a-uuid' }, url(item.sealed))).rejects.toThrow(DerivedError)
  })
})

describe('the browser\'s own seal', () => {
  it('opens in the browser, for its scope only', async () => {
    const item = vectors.records[0]
    const record = JSON.parse(item.plaintext) as DerivedRecord
    const sealed = await sealDerived(dsk, scopeOf(item), record)
    expect(await openDerived(dsk, scopeOf(item), sealed)).toEqual(record)
    await expect(openDerived(dsk, { ...scopeOf(item), feature: 'video' }, sealed)).rejects.toThrow(DerivedError)
  })

  it('validates what it seals and what it opens the same way', () => {
    const record = JSON.parse(vectors.records[0].plaintext)
    expect(validateDerivedRecord(record, 'audio')).toEqual(record)
    expect(() => validateDerivedRecord({ ...record, text: '' })).toThrow(DerivedError)
    expect(() => validateDerivedRecord({ ...record, flags: ['refused'] })).toThrow(DerivedError)
    expect(() => validateDerivedRecord({ ...record, extra: true })).toThrow(DerivedError)
    expect(() => validateDerivedRecord(record, 'video')).toThrow(DerivedError)
  })
})

describe('dedupe tags', () => {
  for (const item of vectors.dedupe) {
    it(`match the enclave's: ${item.name}`, async () => {
      expect(toHex(await dedupeTag(dsk, item.scope, item.input))).toBe(item.tag)
    })
  }

  it('differ when only the language does (N-AI-6)', () => {
    const [reference, pt, none] = vectors.dedupe
    expect(pt.input).toEqual({ ...reference.input, lang: 'pt' })
    expect(none.input.lang).toBeUndefined()
    expect(new Set([reference.tag, pt.tag, none.tag]).size).toBe(3)
  })
})
