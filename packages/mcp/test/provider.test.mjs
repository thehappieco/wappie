import { test } from 'node:test'
import assert from 'node:assert/strict'
import { rm } from 'node:fs/promises'
import { join } from 'node:path'
import { LocalConfigError, validateConfig } from '../config.mjs'
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

test('a provider may hand over the service key as text or raw bytes; provided bytes are zeroed after use', async () => {
  const f = await fixture()
  try {
    // Plaintext through a provider is a later phase: validateConfig refuses it, so
    // the reader is exercised on a hand-built config to pin the zeroing contract.
    const config = Object.freeze({ ...providedConfig(f), allow_plaintext: true, service_user_id: user })
    const asText = await createReader(config, { ...metadataOnly(f.token), serviceKey: async () => f.secret })
    const opened = await asText.getMessage({ device_id: vector.device, uid: body.row })
    assert.equal(opened.message.body.value, plain)
    const raw = Buffer.from(f.secret, 'base64url')
    const handed = []
    const asBytes = await createReader(config, { ...metadataOnly(f.token), serviceKey: async () => { const copy = Buffer.from(raw); handed.push(copy); return copy } })
    assert.equal((await asBytes.getMessage({ device_id: vector.device, uid: body.row })).message.body.value, plain)
    assert.equal(handed.length, 1)
    assert.ok(handed[0].every(byte => byte === 0), 'the provided key buffer is wiped once the content is opened')
    for (const bad of [async () => 'not-a-key', async () => Buffer.alloc(31), async () => 42]) {
      const reader = await createReader(config, { ...metadataOnly(f.token), serviceKey: bad })
      await assert.rejects(reader.getMessage({ device_id: vector.device, uid: body.row }), { code: 'invalid_service_key' })
    }
    const refusing = await createReader(config, metadataOnly(f.token))
    await assert.rejects(refusing.getMessage({ device_id: vector.device, uid: body.row }), { code: 'plaintext_opt_in_required' })
    noSecrets(opened, f.secret)
    raw.fill(0)
  } finally { await f.close() }
})
