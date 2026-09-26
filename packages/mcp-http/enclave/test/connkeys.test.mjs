// The per-connection key holder and the content provider (docs/mcp-enclave.md
// §15.5): only non-extractable handles are held, a wipe drops them, and the
// provider hands the reader a handle with a copy of the public half, never
// bytes of the key, refusing with reconsent_required once the key is gone.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { hpke } from '@whatserver2/client'
import { newRecipient } from '../../state.mjs'
import { createConnKeys } from '../connkeys.mjs'
import { contentConfigFor, contentProviderFor, renewalURL } from '../provider.mjs'

const CONSOLE = 'https://app.wappie.thehappie.co/console'

test('connkeys: non-extractable X25519 handles only; wipe drops the key and zeroes the kept public half', async () => {
  const keys = createConnKeys()
  const recipient = await newRecipient()
  keys.set('a', recipient.privateKey)
  assert.equal(keys.has('a'), true)
  assert.equal(keys.size(), 1)
  const held = keys.get('a')
  assert.equal(held.key, recipient.privateKey.key)
  assert.notEqual(held.publicRaw, recipient.privateKey.publicRaw, 'its own copy of the public half')
  // Extractable keys, raw bytes, strings and public keys are all refused.
  const pair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])
  const raw = await hpke.generateKeyPair()
  for (const bad of [{ key: pair.privateKey, publicRaw: new Uint8Array(32) }, { key: pair.publicKey, publicRaw: new Uint8Array(32) }, raw.privateKey, 'x'.repeat(43),
    { key: recipient.privateKey.key, publicRaw: new Uint8Array(31) }, null]) assert.throws(() => keys.set('b', bad), { code: 'connkey_extractable' })
  raw.privateKey.fill(0)
  assert.equal(keys.wipe('a'), true)
  assert.equal(held.publicRaw.every(byte => byte === 0), true)
  assert.equal(keys.wipe('a'), false)
  keys.set('c', recipient.privateKey); keys.set('d', (await newRecipient()).privateKey)
  keys.wipeAll()
  assert.equal(keys.size(), 0)
})

test('content provider: a handle and a copy, the consented epochs, the renewal link, no contacts, and reconsent_required without a key', async () => {
  const keys = createConnKeys()
  const recipient = await newRecipient()
  const id = randomUUID(), device = randomUUID(), service = randomUUID()
  const record = { connection_id: id, workspace_id: randomUUID(), device_ids: [device], timezone: 'UTC', api_key: 'key', service_user_id: service, epochs: { [device]: 3 } }
  const provider = contentProviderFor(record, keys, CONSOLE)
  await assert.rejects(provider.token(), { name: 'LocalConfigError', code: 'reconsent_required' })
  await assert.rejects(provider.serviceKey(), { code: 'reconsent_required' })
  keys.set(id, recipient.privateKey)
  assert.deepEqual(await provider.token(), { token: 'key', kind: 'api_key' })
  const handed = await provider.serviceKey()
  assert.equal(handed.key, recipient.privateKey.key)
  assert.equal(handed.key.extractable, false)
  // The reader may zero what it is handed; the held copy survives.
  handed.publicRaw.fill(0)
  assert.deepEqual(Buffer.from((await provider.serviceKey()).publicRaw), Buffer.from(recipient.publicKey))
  assert.equal(provider.expectedEpoch(device), 3)
  assert.equal(provider.expectedEpoch(randomUUID()), undefined)
  assert.equal(provider.expectedEpoch('__proto__'), undefined)
  assert.equal(provider.renewalURL(), `${CONSOLE}?mcp_renew=${id}`)
  assert.equal(renewalURL(CONSOLE, id), `${CONSOLE}?mcp_renew=${id}`)
  assert.equal(await provider.contactPack(), null)
  keys.wipe(id)
  await assert.rejects(provider.token(), { code: 'reconsent_required' })

  const config = contentConfigFor(record, 'https://api.wappie.thehappie.co')
  assert.equal(config.credential_source, 'enclave')
  assert.equal(config.allow_plaintext, true)
  assert.equal(config.service_user_id, service)
  assert.equal(config.max_scan_messages, 500)
  assert.deepEqual([...config.device_ids], [device])
})

test('newRecipient: the private half is born non-extractable, so no PKCS#8 export ever exists to zero', async t => {
  const exported = []
  const exportKey = crypto.subtle.exportKey
  crypto.subtle.exportKey = function (format, key) { exported.push(format); return exportKey.call(this, format, key) }
  t.after(() => { crypto.subtle.exportKey = exportKey })
  const recipient = await newRecipient()
  crypto.subtle.exportKey = exportKey
  assert.deepEqual(exported, ['raw'], 'only the public half is ever exported')
  assert.equal(recipient.privateKey.key.extractable, false)
  assert.equal(recipient.privateKey.key.algorithm.name, 'X25519')
  await assert.rejects(crypto.subtle.exportKey('pkcs8', recipient.privateKey.key))
  assert.deepEqual(Buffer.from(recipient.privateKey.publicRaw), recipient.publicKey)
  assert.equal(recipient.publicKeyEncoded, recipient.publicKey.toString('base64url'))
  assert.equal(recipient.kid, createHash('sha256').update(recipient.publicKey).digest('hex').slice(0, 16))
  // It opens what is sealed to it, and connkeys accepts it.
  const info = new Uint8Array([1]), aad = new Uint8Array([2])
  const { enc, ciphertext } = await hpke.seal(new Uint8Array(recipient.publicKey), info, aad, new Uint8Array([7, 8, 9]))
  assert.deepEqual(Array.from(await hpke.open(recipient.privateKey, enc, info, aad, ciphertext)), [7, 8, 9])
  createConnKeys().set('a', recipient.privateKey)
})

test('content provider: a wipe mid-read leaves the handed copy intact, and onStaleGrant reaches the enclave without the number', async () => {
  const keys = createConnKeys()
  const recipient = await newRecipient()
  const id = randomUUID(), device = randomUUID()
  const record = { connection_id: id, workspace_id: randomUUID(), device_ids: [device], timezone: 'UTC', api_key: 'key', service_user_id: randomUUID(), epochs: { [device]: 1 } }
  const told = []
  const provider = contentProviderFor(record, keys, CONSOLE, { onStaleGrant: (...args) => told.push(args) })
  keys.set(id, recipient.privateKey)
  const handed = await provider.serviceKey()
  keys.wipe(id)
  assert.deepEqual(Buffer.from(handed.publicRaw), recipient.publicKey, 'an in-flight read keeps the bytes it was given')
  provider.onStaleGrant({ device_id: device })
  assert.deepEqual(told, [[]])
  // Without a hook the reader's call is a no-op.
  assert.doesNotThrow(() => contentProviderFor(record, keys, CONSOLE).onStaleGrant({ device_id: device }))
})
