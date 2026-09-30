// Derived records and dedupe tags (docs/mcp-enclave.md §18.8): sealed here
// in Node as the enclave seals them, and written to
// packages/client/testdata/node-derived.json, which the browser
// (packages/client, derived.spec.ts) and the reader (packages/mcp,
// ai.test.mjs) open. A record opens for exactly its namespace, number,
// message, function and epoch, and a record Go made with the device's public
// key never opens (N-AI-3). Tags differ whenever anything a result depends
// on does, the language included (N-AI-6).
//
// Regenerate the vectors with: cd packages/mcp-http/enclave && WS_REGEN_VECTORS=1 npm test
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { hpke } from '@whatserver2/client'
import { openDerived, validateDerivedRecord } from '@whatserver2/mcp/reader'
import { dedupeTag, reusable } from '../ai/dedupe.mjs'
import { derivedKey, makeRecord, openDerivedWith, sealDerived, sealDerivedWith } from '../ai/derived.mjs'

const FILE = new URL('../../../client/testdata/node-derived.json', import.meta.url)
const DSK = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 11 + 3) & 0xff))
const OTHER_DSK = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 13 + 5) & 0xff))
const scope = { namespace: '018f3a2b-0000-7000-8000-000000000021', device_id: '018f3a2b-0000-7000-8000-000000000022', epoch: 2 }
const uids = ['018f3a2b-0000-7000-8000-000000000031', '018f3a2b-0000-7000-8000-000000000032', '018f3a2b-0000-7000-8000-000000000033']
const source = createHash('sha256').update('synthetic voice note').digest('hex')

function makeVectors() {
  const records = [
    { name: 'an audio transcript, pt-BR, with its usage', message_uid: uids[0], record: makeRecord({ feature: 'audio', text: 'Oi, aqui é a sonda. A reunião ficou para quinta, às 15:30.\n[inaudible]', lang: 'pt-BR', provider: 'google', model: 'gemini-synthetic-flash', prompt_version: 'audio/1', created_at: '2026-10-01T09:30:15.123Z', source_sha256: source, usage: { input_tokens: 424, output_tokens: 741, seconds: 15 } }) },
    { name: 'a refusal: no text, stored so the file is not sent again', message_uid: uids[1], record: makeRecord({ feature: 'image', text: '', provider: 'anthropic', model: 'claude-synthetic-5', prompt_version: 'image/1', created_at: '2026-10-01T09:31:00.000Z', source_sha256: source, usage: { input_tokens: 504, output_tokens: 0 }, flags: ['refused'] }) },
    { name: 'a video, cut, partial and redone, no language', message_uid: uids[2], record: makeRecord({ feature: 'video', text: 'Transcript:\nOlá.\n\nShown:\nUm círculo azul.', provider: 'google', model: 'gemini-synthetic-flash', prompt_version: 'video/1', created_at: '2026-10-01T09:32:00Z', source_sha256: source, usage: { input_tokens: 1160, output_tokens: 393, seconds: 12 }, flags: ['cut', 'partial', 'redo'] }) },
    { name: 'no speech: an OpenAI transcript without text', message_uid: uids[1], record: makeRecord({ feature: 'audio', text: '', lang: 'pt', provider: 'openai', model: 'gpt-synthetic-transcribe', prompt_version: 'audio/1', created_at: '2026-10-01T09:33:00.000Z', source_sha256: source, usage: { seconds: 3 }, flags: ['no_speech'] }) },
  ].map(item => ({ ...item, feature: item.record.feature, plaintext: JSON.stringify(item.record), sealed: sealDerived(DSK, { ...scope, message_uid: item.message_uid, feature: item.record.feature }, item.record).toString('base64url') }))
  const first = records[0]
  const negatives = [
    ['another message', { message_uid: uids[2] }],
    ['another function', { feature: 'video' }],
    ['another number', { device_id: '018f3a2b-0000-7000-8000-000000000023' }],
    ['another epoch', { epoch: 3 }],
    ['another namespace', { namespace: '018f3a2b-0000-7000-8000-000000000024' }],
  ].map(([why, change]) => ({ why, scope: { ...scope, message_uid: first.message_uid, feature: 'audio', ...change }, sealed: first.sealed }))
  const tampered = Buffer.from(first.sealed, 'base64url')
  tampered[tampered.length - 20] ^= 1
  negatives.push({ why: 'a flipped byte', scope: { ...scope, message_uid: first.message_uid, feature: 'audio' }, sealed: tampered.toString('base64url') })
  negatives.push({ why: 'another key (the right format, the wrong DSK)', scope: { ...scope, message_uid: first.message_uid, feature: 'audio' },
    sealed: sealDerived(OTHER_DSK, { ...scope, message_uid: first.message_uid, feature: 'audio' }, first.record).toString('base64url') })
  const input = { source_sha256: source, feature: 'audio', provider: 'google', model: 'gemini-synthetic-flash', prompt_version: 'audio/1', lang: 'pt-BR' }
  const dedupe = [
    ['the reference', scope, input],
    ['only the language differs (pt)', scope, { ...input, lang: 'pt' }],
    ['no language', scope, { ...input, lang: undefined }],
    ['another number of the workspace', { ...scope, device_id: '018f3a2b-0000-7000-8000-000000000023' }, input],
    ['another workspace (namespace)', { ...scope, namespace: '018f3a2b-0000-7000-8000-000000000024' }, input],
    ['another function', scope, { ...input, feature: 'video', prompt_version: 'video/1' }],
    ['another provider', scope, { ...input, provider: 'openai' }],
    ['another model', scope, { ...input, model: 'gemini-synthetic-pro' }],
    ['another prompt version', scope, { ...input, prompt_version: 'audio/2' }],
    ['another file', scope, { ...input, source_sha256: createHash('sha256').update('another file').digest('hex') }],
  ].map(([name, where, what]) => ({ name, scope: where, input: Object.fromEntries(Object.entries(what).filter(([, value]) => value !== undefined)), tag: dedupeTag(DSK, where, what).toString('hex') }))
  return {
    note: 'Derived records (docs/mcp-enclave.md §18.8) sealed in Node by packages/mcp-http/enclave/test/ai-derived.test.mjs with enclave/ai/derived.mjs, as the enclave seals them, and dedupe tags computed with enclave/ai/dedupe.mjs; opened in the browser (packages/client/test/derived.spec.ts) and in the reader (packages/mcp/test/ai.test.mjs). The DSK is fixture material that opens nothing. Regenerate with: cd packages/mcp-http/enclave && WS_REGEN_VECTORS=1 npm test',
    dsk: DSK.toString('base64url'), ...scope, records, negatives, dedupe,
  }
}

test('vectors: written when asked, and every record in them opens here and in reader.mjs, for exactly its scope', { concurrency: false }, () => {
  if (process.env.WS_REGEN_VECTORS === '1') writeFileSync(FILE, JSON.stringify(makeVectors(), null, 2) + '\n')
  const vectors = JSON.parse(readFileSync(FILE, 'utf8'))
  const dsk = Buffer.from(vectors.dsk, 'base64url')
  for (const item of vectors.records) {
    const where = { namespace: vectors.namespace, device_id: vectors.device_id, epoch: vectors.epoch, message_uid: item.message_uid, feature: item.feature }
    const opened = openDerived(dsk, where, Buffer.from(item.sealed, 'base64url'))
    assert.deepEqual(opened, JSON.parse(item.plaintext), item.name)
    assert.equal(JSON.stringify(opened), item.plaintext, `${item.name}: §18.8's order`)
  }
  for (const item of vectors.negatives) assert.throws(() => openDerived(dsk, item.scope, Buffer.from(item.sealed, 'base64url')), { code: 'invalid_derived' }, item.why)
  for (const item of vectors.dedupe) assert.equal(dedupeTag(dsk, item.scope, item.input).toString('hex'), item.tag, item.name)
  const tags = vectors.dedupe.map(item => item.tag)
  assert.equal(new Set(tags).size, tags.length, 'every change makes another tag (N-AI-6)')
})

test('N-AI-3: a record Go made with the device\'s public key (HPKE, as grants are) never opens, whatever its header', async () => {
  const pair = await hpke.generateKeyPair()
  const dsk = Buffer.from(pair.privateKey)
  const where = { ...scope, message_uid: uids[0], feature: 'audio' }
  const record = makeRecord({ feature: 'audio', text: 'Go wrote this.', provider: 'google', model: 'gemini-synthetic-flash', prompt_version: 'audio/1', created_at: '2026-10-01T09:30:15.123Z', source_sha256: source })
  const plain = new Uint8Array(Buffer.from(JSON.stringify(record)))
  const aad = new Uint8Array(Buffer.from(JSON.stringify(['wappie/derived', 1, where.namespace, where.device_id, where.message_uid, 'audio', where.epoch])))
  const { enc, ciphertext } = await hpke.seal(pair.publicKey, new Uint8Array(Buffer.from('wappie-derived/v1')), aad, plain)
  const header = Buffer.from([...Buffer.from('WDRV'), 1, 0, where.epoch])
  for (const forged of [Buffer.concat([header, enc, ciphertext]), Buffer.concat([header, enc.subarray(0, 12), ciphertext])]) {
    assert.throws(() => openDerived(dsk, where, forged), { code: 'invalid_derived' })
  }
  // The genuine format under that DSK opens: the refusal above is the key's, not the header's.
  assert.equal(openDerived(dsk, where, sealDerived(dsk, where, record)).text, 'Go wrote this.')
  dsk.fill(0)
})

test('the record: §18.8\'s fields only, text within 200,000 characters, known flags, no empty text but a refusal or no speech', () => {
  const base = { v: 1, feature: 'audio', text: 'x', provider: 'openai', model: 'gpt-synthetic-transcribe', prompt_version: 'audio/1', created_at: '2026-10-01T09:30:15.123Z', source_sha256: source, usage: {}, flags: [] }
  assert.equal(validateDerivedRecord(base).text, 'x')
  for (const [why, change] of [
    ['an unknown field', { extra: 1 }], ['version 2', { v: 2 }], ['another function than expected', { feature: 'video', prompt_version: 'video/1' }],
    ['text over the cap', { text: 'x'.repeat(200_001) }], ['a prompt version of another function', { prompt_version: 'video/1' }], ['a bad model', { model: 'Bad Model' }],
    ['an unknown provider', { provider: 'mistral' }], ['a negative count', { usage: { input_tokens: -1 } }], ['an unknown usage field', { usage: { cost: 1 } }],
    ['an unknown flag', { flags: ['great'] }], ['a flag twice', { flags: ['cut', 'cut'] }], ['empty text without a reason', { text: '' }],
    ['a refusal with text', { flags: ['refused'] }], ['both refused and no speech', { text: '', flags: ['refused', 'no_speech'] }],
    ['a hash that is not 64 hex', { source_sha256: 'ABC' }], ['a time that is not RFC 3339 UTC', { created_at: '2026-10-01 09:30' }],
  ]) assert.throws(() => validateDerivedRecord({ ...base, ...change }, 'audio'), { code: 'invalid_derived' }, why)
  assert.throws(() => makeRecord({ ...base, text: 'x'.repeat(300_000) }), { code: 'invalid_derived' })
})

test('sealing: one key per scope, a fresh IV per seal, and the key zeroed by the callers that derive it', () => {
  const where = { ...scope, message_uid: uids[0], feature: 'audio' }
  const record = makeRecord({ feature: 'audio', text: 'twice', provider: 'google', model: 'gemini-synthetic-flash', prompt_version: 'audio/1', created_at: '2026-10-01T09:30:15.123Z', source_sha256: source })
  const key = derivedKey(DSK, where)
  const a = sealDerivedWith(key, where, record), b = sealDerivedWith(key, where, record)
  assert.notDeepEqual(a, b)
  assert.equal(openDerivedWith(key, where, a).text, 'twice')
  assert.deepEqual([...a.subarray(0, 7)], [...Buffer.from('WDRV'), 1, 0, 2])
  assert.throws(() => sealDerivedWith(key, { ...where, feature: 'video' }, record))
  key.fill(0)
  assert.equal(reusable(record, { source_sha256: source, feature: 'audio', provider: 'google', model: 'gemini-synthetic-flash', prompt_version: 'audio/1' }), true)
  assert.equal(reusable(record, { source_sha256: source, feature: 'audio', provider: 'google', model: 'gemini-synthetic-flash', prompt_version: 'audio/1', lang: 'pt' }), false, 'a result in no language is not one in pt')
  assert.equal(reusable({ ...record, lang: 'pt' }, { source_sha256: source, feature: 'audio', provider: 'google', model: 'gemini-synthetic-flash', prompt_version: 'audio/1', lang: 'pt-BR' }), false)
})
