import { test } from 'node:test'
import assert from 'node:assert/strict'
import { rm } from 'node:fs/promises'
import { join } from 'node:path'
import { hpke, ArchiveError } from '@whatserver2/client'
import { LocalConfigError, readerMode, validateConfig } from '../config.mjs'
import { createReader } from '../reader.mjs'
import { createServer } from '../server.mjs'
import { McpServer } from '../sdk.mjs'
import { fixture, noSecrets, vector, body, workspace, user, plain } from './fixture.mjs'

// The hosted reader's provider: a token in memory, and nothing that could open content.
const metadataOnly = token => ({
  token: async () => ({ token, kind: 'api_key' }),
  serviceKey: () => { throw new LocalConfigError('plaintext_opt_in_required') },
  contactPack: () => { throw new LocalConfigError('plaintext_opt_in_required') },
})
const providedConfig = f => validateConfig({ server: f.server, workspace, device_ids: [vector.device], credential_source: 'provided' })

test('a provided credential reaches the archive without any file read and stays metadata-only', async () => {
  const f = await fixture()
  try {
    // No credential file exists anywhere the reader could look; the provider is the only source.
    await rm(join(f.directory, 'token'))
    const reader = await createReader(providedConfig(f), metadataOnly(f.token))
    const numbers = await reader.listNumbers()
    assert.equal(numbers.numbers.length, 1)
    assert.equal(numbers.plaintext_enabled, false)
    // A provided credential has no switch to throw, and says so: the false above
    // otherwise reads like a setting somebody forgot to turn on.
    assert.equal(numbers.plaintext_available, false)
    const message = await reader.getMessage({ device_id: vector.device, uid: body.row })
    assert.equal(message.message.body.state, 'locked')
    const chats = await reader.listChats({ device_id: vector.device, limit: 10 })
    assert.equal(chats.chats[0].name.state, 'locked')
    assert.ok(f.state.requests.length >= 3)
    assert.ok(f.state.requests.every(item => item.auth === `Bearer ${f.token}` && item.method === 'GET'))
    assert.equal(f.state.requests.some(item => /keys|grants|auth/.test(item.path)), false, 'metadata reads never ask for keys')
    noSecrets({ numbers, message, chats }, f.secret)
    // Not plaintext_required_for_text_search: that code names a local opt-in,
    // and there is none here. See the locked reason below for the same reason.
    await assert.rejects(reader.searchMessages({ device_id: vector.device, query: 'anything', period: 'all' }), { code: 'content_sealed_metadata_only' })
    assert.match(message.message.body.reason, /metadata only/)
    assert.equal(/enabled|local/i.test(message.message.body.reason), false, 'a sealed reason must not read like an unset option')
  } finally { await f.close() }
})

test('provided-mode readers refuse a missing provider and surface a rejected token as not_authorized', async () => {
  const f = await fixture()
  try {
    await assert.rejects(createReader(providedConfig(f)), { code: 'credential_provider_required' })
    const reader = await createReader(providedConfig(f), metadataOnly('synthetic-wrong-credential-never-returned'))
    await assert.rejects(reader.listNumbers(), { code: 'not_authorized' })
    noSecrets(f.state.requests.map(item => item.path), f.secret)
  } finally { await f.close() }
})

test('createServer hands the provider to every tool call and builds the shared SDK server class', async () => {
  const f = await fixture()
  try {
    let asked = 0
    const provider = { ...metadataOnly(f.token), token: async () => { asked++; return { token: f.token, kind: 'api_key' } } }
    const server = createServer(providedConfig(f), provider)
    assert.ok(server instanceof McpServer)
    // Register-time only: the credential is fetched when a tool runs, never at construction.
    assert.equal(asked, 0)
  } finally { await f.close() }
})

test('a provided config never opens content, even hand-built with plaintext and a provider that hands over the key', async () => {
  const f = await fixture()
  try {
    // validateConfig refuses allow_plaintext in provided mode; this config is
    // built by hand to show the reader itself holds the line: the mode, not
    // the flag or the provider, decides that nothing opens.
    const config = Object.freeze({ ...providedConfig(f), allow_plaintext: true, service_user_id: user })
    assert.equal(readerMode(config), 'hosted-metadata')
    const asked = { serviceKey: 0, contactPack: 0, expectedEpoch: 0 }
    const handle = await hpke.importArchiveKey(Buffer.from(f.secret, 'base64url'))
    for (const key of [async () => f.secret, async () => Buffer.from(f.secret, 'base64url'), async () => handle]) {
      const reader = await createReader(config, { ...metadataOnly(f.token),
        serviceKey: async () => { asked.serviceKey++; return key() },
        contactPack: async () => { asked.contactPack++; return null },
        expectedEpoch: () => { asked.expectedEpoch++; return 1 } })
      const message = await reader.getMessage({ device_id: vector.device, uid: body.row })
      assert.equal(message.message.body.state, 'locked')
      assert.match(message.message.body.reason, /metadata only/)
      assert.equal((await reader.listChats({ device_id: vector.device, limit: 10 })).chats[0].name.state, 'locked')
      const numbers = await reader.listNumbers()
      assert.equal(numbers.plaintext_enabled, false)
      assert.equal(numbers.plaintext_available, false)
      await assert.rejects(reader.searchMessages({ device_id: vector.device, query: 'anything', period: 'all' }), { code: 'content_sealed_metadata_only' })
      const named = await reader.resolveContact({ device_id: vector.device, query: 'roberto' })
      assert.equal(named.names_searchable, false)
      noSecrets({ message, numbers, named }, f.secret)
    }
    assert.deepEqual(asked, { serviceKey: 0, contactPack: 0, expectedEpoch: 0 }, 'a provided reader never asks for a key')
    assert.equal(f.state.requests.some(item => /keys|grants|auth/.test(item.path)), false, 'metadata reads never ask for keys')
    // The pilot's own provider shape is still refused content at the config layer.
    assert.throws(() => validateConfig({ server: f.server, workspace, device_ids: [vector.device], credential_source: 'provided', allow_plaintext: true }), { code: 'provided_credentials_metadata_only' })
  } finally { await f.close() }
})

// The attested reader's provider: a token, a key handle and the consented epochs.
const contentProvider = (f, handle, extra = {}) => ({
  token: async () => ({ token: f.token, kind: 'api_key' }),
  serviceKey: async () => handle,
  expectedEpoch: () => 1,
  contactPack: () => { throw new Error('the attested reader never asks for a contact snapshot') },
  ...extra,
})
const contentConfig = f => validateConfig({ server: f.server, workspace, device_ids: [vector.device], timezone: 'UTC',
  allow_plaintext: true, credential_source: 'enclave', service_user_id: user, max_scan_messages: 500 })

test('an enclave provider hands over a key handle that opens content with no import and nothing zeroed', async () => {
  const f = await fixture()
  try {
    const config = contentConfig(f)
    assert.equal(readerMode(config), 'hosted-content')
    const handle = await hpke.importArchiveKey(Buffer.from(f.secret, 'base64url'))
    assert.equal(handle.key.extractable, false)
    const publicCopy = Uint8Array.from(handle.publicRaw)
    let handed = 0
    const reader = await createReader(config, contentProvider(f, handle, { serviceKey: async () => { handed++; return handle } }))
    const message = await reader.getMessage({ device_id: vector.device, uid: body.row })
    assert.equal(message.message.body.value, plain)
    const chats = await reader.listChats({ device_id: vector.device, limit: 10 })
    assert.equal(chats.chats[0].preview.value, plain)
    const numbers = await reader.listNumbers()
    assert.equal(numbers.plaintext_enabled, true)
    assert.equal(numbers.plaintext_available, true)
    assert.equal(handed, 2, 'the handle is asked for on every content read')
    assert.deepEqual(handle.publicRaw, publicCopy, 'nothing of the provider\'s handle is zeroed')
    assert.equal(f.state.requests.filter(item => item.path === '/v1/grants').length, 2, 'grants are fetched on every content read')
    assert.equal(f.state.requests.some(item => item.path.startsWith('/v1/auth')), false, 'no password path')
    // The same handle keeps working: it was never consumed.
    assert.equal((await reader.getMessage({ device_id: vector.device, uid: body.row })).message.body.value, plain)
    noSecrets({ message, chats, numbers }, f.secret)
  } finally { await f.close() }
})

test('an enclave provider must hand over a handle: bytes, strings and extractable keys are invalid_service_key', async () => {
  const f = await fixture()
  try {
    const config = contentConfig(f)
    const handle = await hpke.importArchiveKey(Buffer.from(f.secret, 'base64url'))
    const pair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])
    const raw = Buffer.from(f.secret, 'base64url')
    for (const bad of [f.secret, raw, new Uint8Array(raw), null, 42, {}, { key: handle.key }, { key: handle.key, publicRaw: handle.publicRaw.subarray(1) },
      { key: handle.key, publicRaw: Array.from(handle.publicRaw) }, { key: pair.privateKey, publicRaw: handle.publicRaw }, { key: pair.publicKey, publicRaw: handle.publicRaw }]) {
      const reader = await createReader(config, contentProvider(f, bad))
      await assert.rejects(reader.getMessage({ device_id: vector.device, uid: body.row }), { code: 'invalid_service_key' })
    }
    assert.ok(raw.some(byte => byte !== 0), 'refused bytes are not touched either')
    raw.fill(0)
    // A provider without the epochs it consented to is not an enclave provider.
    await assert.rejects(createReader(config, { ...contentProvider(f, handle), expectedEpoch: undefined }), { code: 'credential_provider_required' })
    await assert.rejects(createReader(config, { ...contentProvider(f, handle), serviceKey: undefined }), { code: 'credential_provider_required' })
    await assert.rejects(createReader(config), { code: 'credential_provider_required' })
  } finally { await f.close() }
})

test('the attested reader answers stale_grant for a changed epoch or a grant its key cannot open, and reconsent_required without a key', async () => {
  const f = await fixture()
  try {
    const config = contentConfig(f)
    const handle = await hpke.importArchiveKey(Buffer.from(f.secret, 'base64url'))
    const moved = await createReader(config, contentProvider(f, handle, { expectedEpoch: () => 2 }))
    const before = f.state.requests.length
    await assert.rejects(moved.getMessage({ device_id: vector.device, uid: body.row }), error => error instanceof ArchiveError && error.code === 'stale_grant')
    assert.equal(f.state.requests.slice(before).some(item => item.path.endsWith('/keys')), false, 'no content key was asked for')
    const unknown = await createReader(config, contentProvider(f, handle, { expectedEpoch: () => undefined }))
    await assert.rejects(unknown.getMessage({ device_id: vector.device, uid: body.row }), { code: 'stale_grant' })
    const other = await hpke.importArchiveKey(crypto.getRandomValues(new Uint8Array(32)))
    const wrong = await createReader(config, contentProvider(f, other))
    await assert.rejects(wrong.getMessage({ device_id: vector.device, uid: body.row }), { code: 'stale_grant' })
    let keyAsked = 0
    await assert.rejects(createReader(config, contentProvider(f, handle, {
      token: async () => { throw new LocalConfigError('reconsent_required') }, serviceKey: async () => { keyAsked++; return handle } })), { code: 'reconsent_required' })
    assert.equal(keyAsked, 0)
  } finally { await f.close() }
})

test('the attested reader tells the provider about each stale_grant, best effort, and nothing else', async () => {
  const f = await fixture()
  try {
    const config = contentConfig(f)
    const handle = await hpke.importArchiveKey(Buffer.from(f.secret, 'base64url'))
    const told = []
    const onStaleGrant = event => { told.push(event) }
    // A current grant that opens is not stale: the hook stays silent.
    const fine = await createReader(config, contentProvider(f, handle, { onStaleGrant }))
    await fine.getMessage({ device_id: vector.device, uid: body.row })
    assert.deepEqual(told, [])
    // A changed epoch and a grant the key cannot open each report the number once.
    const moved = await createReader(config, contentProvider(f, handle, { expectedEpoch: () => 2, onStaleGrant }))
    await assert.rejects(moved.getMessage({ device_id: vector.device, uid: body.row }), { code: 'stale_grant' })
    const other = await hpke.importArchiveKey(crypto.getRandomValues(new Uint8Array(32)))
    const wrong = await createReader(config, contentProvider(f, other, { onStaleGrant }))
    await assert.rejects(wrong.getMessage({ device_id: vector.device, uid: body.row }), { code: 'stale_grant' })
    assert.deepEqual(told, [{ device_id: vector.device }, { device_id: vector.device }])
    // Other refusals are not stale grants.
    await assert.rejects(moved.getMessage({ device_id: '00000000-0000-4000-8000-000000000000', uid: body.row }), { code: 'not_authorized' })
    assert.equal(told.length, 2)
    // A hook that throws, rejects or never settles changes neither the answer nor its timing.
    let unhandled = 0
    const count = () => { unhandled++ }
    process.on('unhandledRejection', count)
    try {
      for (const hook of [() => { throw new Error('log sink down') }, async () => { throw new Error('log sink down') }, () => new Promise(() => {})]) {
        const reader = await createReader(config, contentProvider(f, handle, { expectedEpoch: () => 2, onStaleGrant: hook }))
        await assert.rejects(reader.getMessage({ device_id: vector.device, uid: body.row }), error => error instanceof ArchiveError && error.code === 'stale_grant')
      }
      await new Promise(resolve => setImmediate(resolve))
    } finally { process.off('unhandledRejection', count) }
    assert.equal(unhandled, 0)
    // The hook is optional.
    const silent = await createReader(config, contentProvider(f, handle, { expectedEpoch: () => 2, onStaleGrant: 'not a function' }))
    await assert.rejects(silent.getMessage({ device_id: vector.device, uid: body.row }), { code: 'stale_grant' })
  } finally { await f.close() }
})
