// Sealed state (docs/mcp-enclave.md §8): envelope v1 under a KMS data key,
// AAD bound to the collection and generation, compare-and-set generations in
// Go, and the save discipline (only changed collections, at most one write in
// flight, Go away = dirty and retried, conflict = exit).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { openSealedState, SEALED_MAX_PLAINTEXT, sealedCollection, StateError } from '../../state.mjs'
import { aadFor, contextFor, createSealer, decodeEnvelope, MAGIC } from '../sealer.mjs'
import { fakeKms } from './fixtures.mjs'

const READER_KEY = 'arn:aws:kms:eu-west-1:768406580484:key/11111111-1111-4111-8111-111111111111'
const ORIGIN = 'https://mcp.wappie.thehappie.co'
const quietLog = () => { const events = []; return { events, event: (code, fields) => events.push({ code, ...fields }) } }

/** Go's state table in memory: CAS on generation, as `UPDATE … WHERE generation=$3` does. */
function memoryStore() {
  const rows = new Map()
  const store = {
    rows, down: false, puts: 0, gets: 0, inFlight: 0, maxInFlight: 0, delay: 0,
    async get(name) { store.gets++; if (store.down) throw new Error('relay_unavailable'); const row = rows.get(name); return row ? { generation: row.generation, blob: Buffer.from(row.blob) } : null },
    async put(name, ifGeneration, blob) {
      store.inFlight++; store.maxInFlight = Math.max(store.maxInFlight, store.inFlight)
      try {
        if (store.delay) await new Promise(resolve => setTimeout(resolve, store.delay))
        if (store.down) throw new Error('relay_unavailable')
        if ((rows.get(name)?.generation ?? 0) !== ifGeneration) throw new StateError('state_conflict')
        store.puts++
        rows.set(name, { generation: ifGeneration + 1, blob: Buffer.from(blob) })
        return ifGeneration + 1
      } finally { store.inFlight-- }
    },
  }
  return store
}
const noWait = () => Promise.resolve()

test('envelope v1: layout, contexts and AAD exactly as the contract writes them', async () => {
  const kms = fakeKms()
  const sealer = createSealer({ kms, keyArn: READER_KEY, readerId: 'enclave', origin: ORIGIN })
  const envelope = await sealer.seal('as-tokens', 3, Buffer.from('{"version":1}'))
  assert.deepEqual(envelope.subarray(0, 8), MAGIC)
  assert.equal(envelope[8], 1)
  const length = envelope.readUInt16BE(9)
  const parts = decodeEnvelope(envelope)
  assert.equal(parts.ciphertextBlob.length, length)
  assert.equal(parts.iv.length, 12)
  assert.equal(parts.tag.length, 16)
  assert.equal(envelope.length, 39 + length + parts.ciphertext.length)
  assert.deepEqual(kms.calls[0], { op: 'dataKey', keyArn: READER_KEY, context: { purpose: 'wappie-mcp-reader-state', reader_id: 'enclave', origin: ORIGIN, name: 'as-tokens' } })
  assert.deepEqual(contextFor({ readerId: 'enclave', origin: ORIGIN }, 'infra'), { purpose: 'wappie-mcp-reader-infra', reader_id: 'enclave', origin: ORIGIN })
  assert.equal(aadFor('enclave', 'as-tokens', 3).toString(), '["wappie-mcp-state",1,"enclave","as-tokens",3]')
  assert.equal((await sealer.open('as-tokens', 3, envelope)).toString(), '{"version":1}')
  // One data key per name per boot; the next write reuses it with a fresh IV.
  const again = await sealer.seal('as-tokens', 4, Buffer.from('{"version":1}'))
  assert.equal(kms.calls.filter(call => call.op === 'dataKey').length, 1)
  assert.notDeepEqual(decodeEnvelope(again).iv, parts.iv)
})

test('envelope v1: a flipped byte anywhere, another generation, another name, another reader or origin all fail as state_auth_failed', async () => {
  const kms = fakeKms()
  const sealer = createSealer({ kms, keyArn: READER_KEY, readerId: 'enclave', origin: ORIGIN })
  const envelope = await sealer.seal('as-clients', 2, Buffer.from('x'.repeat(100)))
  for (let index = 0; index < envelope.length; index += 7) {
    const copy = Buffer.from(envelope); copy[index] ^= 0x01
    await assert.rejects(sealer.open('as-clients', 2, copy), { code: 'state_auth_failed' }, `byte ${index}`)
  }
  await assert.rejects(sealer.open('as-clients', 3, envelope), { code: 'state_auth_failed' })
  await assert.rejects(sealer.open('as-tokens', 2, envelope), { code: 'state_auth_failed' })
  const otherReader = createSealer({ kms, keyArn: READER_KEY, readerId: 'staging', origin: ORIGIN })
  await assert.rejects(otherReader.open('as-clients', 2, envelope), { code: 'state_auth_failed' })
  const otherOrigin = createSealer({ kms, keyArn: READER_KEY, readerId: 'enclave', origin: 'https://evil.example' })
  await assert.rejects(otherOrigin.open('as-clients', 2, envelope), { code: 'state_auth_failed' })
  const otherKey = createSealer({ kms, keyArn: READER_KEY.replace('1111-4111', '2222-4222'), readerId: 'enclave', origin: ORIGIN })
  await assert.rejects(otherKey.open('as-clients', 2, envelope), { code: 'state_auth_failed' })
  await assert.rejects(sealer.open('as-clients', 2, envelope.subarray(0, 30)), { code: 'state_auth_failed' })
  // A KMS that cannot be reached is not tampering: the loader retries.
  kms.down = true
  await assert.rejects(sealer.open('as-clients', 2, envelope), { code: 'state_unavailable' })
})

test('sealed state: loads all three collections, survives a restart with every record, writes only what changed', async () => {
  const kms = fakeKms(), store = memoryStore(), log = quietLog()
  const sealer = () => createSealer({ kms, keyArn: READER_KEY, readerId: 'enclave', origin: ORIGIN })
  const state = await openSealedState({ store, sealer: sealer(), log, wait: noWait })
  assert.equal(state.recipient, undefined, 'the enclave has no shared reader key')
  assert.equal(store.gets, 3)
  state.clients.set('c1', { client_id: 'c1', client_name: 'Claude' })
  state.connections.set('k1', { connection_id: 'k1', api_key: 'secret-api-key' })
  state.tokens.set('h1', { hash: 'h1', connection_id: 'k1', family_id: 'f' })
  await state.save()
  assert.deepEqual([...store.rows.keys()].sort(), ['as-clients', 'as-connections', 'as-tokens'])
  assert.ok([...store.rows.values()].every(row => row.generation === 1))
  for (const row of store.rows.values()) assert.equal(row.blob.includes(Buffer.from('secret-api-key')), false, 'Go sees ciphertext only')
  state.tokens.set('h2', { hash: 'h2', connection_id: 'k1', family_id: 'f' })
  await state.save()
  assert.equal(store.rows.get('as-tokens').generation, 2)
  assert.equal(store.rows.get('as-clients').generation, 1, 'an unchanged collection is not written')
  await state.close()
  const reopened = await openSealedState({ store, sealer: sealer(), log, wait: noWait })
  assert.equal(reopened.connections.get('k1').api_key, 'secret-api-key')
  assert.equal(reopened.tokens.size, 2)
  reopened.wipeConnection('k1')
  await reopened.save()
  assert.equal(store.rows.get('as-connections').generation, 2)
  assert.equal(store.rows.get('as-tokens').generation, 3)
  assert.equal(reopened.dirty(), 0)
})

test('sealed state: Go away at boot retries with backoff; after boot a failed write stays dirty, is retried, and serving goes on', async () => {
  const kms = fakeKms(), store = memoryStore(), log = quietLog()
  const waits = []
  store.down = true
  let attempts = 0
  const opening = openSealedState({ store, sealer: createSealer({ kms, keyArn: READER_KEY, readerId: 'enclave', origin: ORIGIN }), log, wait: async ms => { waits.push(ms); if (++attempts === 3) store.down = false } })
  const state = await opening
  assert.deepEqual(waits, [1000, 2000, 4000])
  assert.equal(log.events.filter(event => event.code === 'state_load_retry').length, 3)
  store.down = true
  state.clients.set('c1', { client_id: 'c1' })
  await state.save()
  assert.equal(state.dirty(), 1)
  assert.equal(log.events.some(event => event.code === 'state_save_failed'), true)
  store.down = false
  await state.save()
  assert.equal(state.dirty(), 0)
  assert.equal(store.rows.get('as-clients').generation, 1)
  await state.close()
})

test('sealed state: a generation conflict (a second writer) calls onConflict; a tampered blob refuses the boot', async () => {
  const kms = fakeKms(), store = memoryStore(), log = quietLog()
  const sealer = createSealer({ kms, keyArn: READER_KEY, readerId: 'enclave', origin: ORIGIN })
  let conflicts = 0
  const state = await openSealedState({ store, sealer, log, wait: noWait, onConflict: () => { conflicts++ } })
  state.clients.set('c1', { client_id: 'c1' })
  await state.save()
  // Someone else wrote generation 2 behind the reader's back.
  store.rows.set('as-clients', { generation: 2, blob: store.rows.get('as-clients').blob })
  state.clients.set('c2', { client_id: 'c2' })
  await state.save()
  assert.equal(conflicts, 1)
  assert.equal(log.events.some(event => event.code === 'state_conflict'), true)
  // The blob now claims generation 2 but was sealed as generation 1: the AAD refuses it.
  await assert.rejects(openSealedState({ store, sealer: createSealer({ kms, keyArn: READER_KEY, readerId: 'enclave', origin: ORIGIN }), log, wait: noWait }), { code: 'state_auth_failed' })
  // A well-sealed plaintext of the wrong shape is refused the same way.
  const bad = memoryStore()
  bad.rows.set('as-tokens', { generation: 1, blob: await sealer.seal('as-tokens', 1, Buffer.from('{"version":1,"name":"as-clients","records":[]}')) })
  await assert.rejects(openSealedState({ store: bad, sealer, log, wait: noWait }), { code: 'state_auth_failed' })
})

test('sealed state: at most one write in flight per collection, the last change wins, and a plaintext over 11 MiB is refused', async () => {
  const kms = fakeKms(), store = memoryStore(), log = quietLog()
  const collection = sealedCollection({ store, sealer: createSealer({ kms, keyArn: READER_KEY, readerId: 'enclave', origin: ORIGIN }), name: 'as-clients', log, onConflict: () => {} })
  await collection.load()
  let value = 0
  collection.bind(() => Buffer.from(JSON.stringify({ version: 1, name: 'as-clients', records: [{ client_id: String(value) }] })))
  store.delay = 20
  const saves = []
  for (value = 1; value <= 5; value++) saves.push(collection.save())
  await Promise.all(saves)
  assert.equal(store.maxInFlight, 1)
  assert.ok(store.puts <= 2, `coalesced into ${store.puts} writes`)
  const last = await createSealer({ kms, keyArn: READER_KEY, readerId: 'enclave', origin: ORIGIN }).open('as-clients', store.rows.get('as-clients').generation, store.rows.get('as-clients').blob)
  assert.equal(JSON.parse(last).records[0].client_id, '5')
  collection.bind(() => Buffer.alloc(SEALED_MAX_PLAINTEXT + 1, 0x20))
  await collection.save()
  assert.equal(log.events.at(-1).code, 'state_too_large')
  assert.equal(collection.dirty, true)
  await collection.close()
  const unloaded = sealedCollection({ store, sealer: createSealer({ kms, keyArn: READER_KEY, readerId: 'enclave', origin: ORIGIN }), name: 'as-tokens', log, onConflict: () => {} })
  unloaded.bind(() => Buffer.from('{}'))
  assert.throws(() => unloaded.save(), { code: 'state_not_loaded' }, 'never PUT a collection that was not loaded')
})
