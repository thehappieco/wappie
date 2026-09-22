import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { readFile, rename, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { auth } from '@modelcontextprotocol/client'
import { hpke } from '@whatserver2/client'
import { harness, authorize, clientProvider, consent, proof, raw, rpc, sealBundle, secretsAbsent, vector, workspace, DAY } from './harness.mjs'
import { LinkError, openBundle, proofFor } from '../link.mjs'

const kidOf = publicKey => createHash('sha256').update(publicKey).digest('hex').slice(0, 16)

test('descriptor and internal guard: loopback, no X-Forwarded-For, the relay secret; unknown requests are 404', async t => {
  const h = await harness(t)
  const provider = clientProvider()
  assert.equal(await auth(provider, { serverUrl: h.resource }), 'REDIRECT')
  const started = await consent(h, provider.store.authorizationUrl, { until: 'authorize' })
  const described = await h.internal(`/internal/requests/${started.id}`)
  assert.equal(described.status, 200)
  const descriptor = described.json()
  assert.deepEqual(Object.keys(descriptor).sort(), ['client_id', 'client_name', 'code_challenge', 'expires_at', 'kid', 'reader_public_key', 'redirect_host', 'request_id', 'resource'])
  assert.equal(descriptor.request_id, started.id)
  assert.equal(descriptor.client_id, provider.store.client.client_id)
  assert.equal(descriptor.client_name, 'Claude')
  assert.equal(descriptor.redirect_host, 'claude.ai')
  assert.equal(descriptor.resource, h.resource)
  assert.match(descriptor.reader_public_key, /^[A-Za-z0-9_-]{43}$/)
  assert.equal(descriptor.kid, kidOf(Buffer.from(descriptor.reader_public_key, 'base64url')))
  assert.equal(descriptor.code_challenge, provider.store.authorizationUrl.searchParams.get('code_challenge'))
  assert.ok(Date.parse(descriptor.expires_at) - h.clock.now() <= 20 * 60_000)
  assert.ok(Date.parse(descriptor.expires_at) - h.clock.now() > 19 * 60_000)
  assert.equal((await h.internal('/internal/requests/AAAAAAAAAAAAAAAAAAAAAA')).status, 404)
  assert.equal((await h.internal('/internal/requests/short')).status, 404)
  assert.equal((await h.internal('/internal/healthz')).json().ok, true)
  assert.equal((await h.request(`/internal/requests/${started.id}`)).status, 401, 'no secret')
  assert.equal((await h.request(`/internal/requests/${started.id}`, { headers: { authorization: `Bearer ${h.secret.slice(0, -1)}x` } })).status, 401, 'wrong secret')
  assert.equal((await h.request(`/internal/requests/${started.id}`, { headers: { authorization: `Bearer ${h.secret}`, 'x-forwarded-for': '127.0.0.1' } })).status, 404, 'anything proxied is refused')
  assert.equal((await h.internal('/internal/healthz', { headers: { 'x-forwarded-for': '203.0.113.1' } })).status, 404)
  assert.equal((await h.internal('/internal/other')).status, 404)
  assert.equal((await raw(h, { path: '/internal/healthz', headers: { host: 'evil.example', authorization: `Bearer ${h.secret}` } })).status, 200, 'internal routes are keyed on the peer, not the Host header')
  h.clock.advance(21 * 60_000)
  assert.equal((await h.internal(`/internal/requests/${started.id}`)).status, 404, 'expired')
  secretsAbsent(h)
})

test('bundle invariants: plaintext, service identity, contacts, origin, tenant, link secret, token, timezone, key id, AAD and ciphertext', async t => {
  const h = await harness(t)
  const cases = [
    ['allow_plaintext', { bundle: { allow_plaintext: true } }],
    ['service_private_key', { bundle: { service_private_key: randomBytes(32).toString('base64url') } }],
    ['service_user_id', { bundle: { service_user_id: randomUUID() } }],
    ['contacts', { bundle: { contacts: { version: 1 } } }],
    ['server_url is another origin', { serverURL: 'https://api.example.test' }],
    ['server_url with a path', { serverURL: `${h.publicOrigin}/` }],
    ['workspace differs from tenant', { tenantId: randomUUID() }],
    ['bundle workspace differs from tenant', { bundle: { workspace_id: randomUUID() } }],
    ['missing link_secret', { omit: ['link_secret'] }],
    ['short link_secret', { linkSecret: 'A'.repeat(42) }],
    ['non-canonical link_secret', { linkSecret: 'A'.repeat(42) + 'B' }],
    ['token shape', { bundle: { token: 'not-an-api-key' } }],
    ['token tail', { bundle: { token: `${'a'.repeat(8)}.${'A'.repeat(42)}=` } }],
    ['timezone', { bundle: { timezone: 'Mars/Olympus' } }],
    ['duplicate device', { bundle: { device_ids: [vector.device, vector.device] } }],
    ['no devices', { bundle: { device_ids: [] } }],
    ['unknown field', { bundle: { extra: 1 } }],
    ['version', { bundle: { version: 2 } }],
    ['AAD request id', { aadRequestID: 'AAAAAAAAAAAAAAAAAAAAAA' }],
    ['AAD kid', { aadKid: '0'.repeat(16) }],
    ['AAD resource', { aadResource: 'https://other.example/mcp' }],
    ['wrong recipient key', { readerPublicKey: Buffer.from((await hpke.generateKeyPair()).publicKey) }],
  ]
  for (const [name, overrides] of cases) {
    h.clock.advance(13_000) // stays under the per-address registration and authorization rates
    const provider = clientProvider()
    assert.equal(await auth(provider, { serverUrl: h.resource }), 'REDIRECT')
    const result = await consent(h, provider.store.authorizationUrl, { until: 'bundle', ...overrides })
    assert.equal(result.relayed.status, 400, name)
    assert.equal(result.relayed.json().code, 'invalid_bundle', name)
    assert.equal(h.reader.state.pending.get(result.id).bundle, undefined, `${name}: nothing attached`)
    h.reader.state.pending.delete(result.id)
  }
  const provider = clientProvider()
  assert.equal(await auth(provider, { serverUrl: h.resource }), 'REDIRECT')
  const unknownKid = await consent(h, provider.store.authorizationUrl, { until: 'bundle', kid: 'f'.repeat(16) })
  assert.equal(unknownKid.relayed.status, 400)
  assert.equal(unknownKid.relayed.json().code, 'unknown_kid')
  for (const relay of [{ kid: 'short' }, { connection_id: 'x' }, { tenant_id: 'y' }, { sealed: 'not base64url!' }, { sealed: 'AAAA' }, { expires_at: 'soon' }, { expires_at: new Date(h.clock.now() - 1000).toISOString() }, { expires_at: new Date(h.clock.now() + 400 * DAY).toISOString() }, { extra: true }]) {
    h.clock.advance(13_000)
    const other = clientProvider()
    assert.equal(await auth(other, { serverUrl: h.resource }), 'REDIRECT')
    const result = await consent(h, other.store.authorizationUrl, { until: 'bundle', relay })
    assert.equal(result.relayed.status, 400, JSON.stringify(relay))
    assert.equal(result.relayed.json().code, 'bad_request', JSON.stringify(relay))
    h.reader.state.pending.delete(result.id)
  }
  assert.equal((await h.internal(`/internal/requests/${unknownKid.id}/bundle`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{' })).json().code, 'bad_request')
  assert.equal((await h.internal('/internal/requests/AAAAAAAAAAAAAAAAAAAAAA/bundle', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status, 404)
  const good = clientProvider()
  assert.equal(await auth(good, { serverUrl: h.resource }), 'REDIRECT')
  const attached = await consent(h, good.store.authorizationUrl, { until: 'bundle' })
  assert.equal(attached.relayed.status, 204)
  const second = await h.internal(`/internal/requests/${attached.id}/bundle`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ connection_id: randomUUID(), tenant_id: workspace, kid: attached.descriptor.kid, sealed: attached.sealed, expires_at: attached.expiresAt }) })
  assert.equal(second.status, 409)
  assert.equal(second.json().code, 'bundle_exists')
  const optional = clientProvider()
  assert.equal(await auth(optional, { serverUrl: h.resource }), 'REDIRECT')
  const withoutTimezone = await consent(h, optional.store.authorizationUrl, { omit: ['timezone'] })
  assert.equal(withoutTimezone.completed.status, 302)
  assert.equal(h.reader.state.connections.get(withoutTimezone.connectionId).timezone, 'UTC')
  const many = clientProvider()
  assert.equal(await auth(many, { serverUrl: h.resource }), 'REDIRECT')
  const oversized = await consent(h, many.store.authorizationUrl, { until: 'bundle', bundle: { device_ids: Array.from({ length: 1001 }, () => randomUUID()) } })
  assert.equal(oversized.relayed.status, 400)
  assert.equal(oversized.relayed.json().code, 'invalid_bundle')
  secretsAbsent(h, { linkSecrets: [attached.linkSecret, withoutTimezone.linkSecret] })
})

test('the proof vector: derived from a seed, verified by the reader, and the reader never keeps the plaintext', async t => {
  const h = await harness(t)
  // The same derivation the console test suite uses: everything from one seed, nothing token-shaped on disk.
  const seed = 'wappie-mcp-link-vector-2026'
  const linkSecret = createHash('sha256').update(`${seed}:link_secret`).digest().toString('base64url')
  const provider = clientProvider()
  assert.equal(await auth(provider, { serverUrl: h.resource }), 'REDIRECT')
  const done = await consent(h, provider.store.authorizationUrl, { linkSecret })
  assert.equal(done.completed.status, 302)
  const expected = proofFor(Buffer.from(linkSecret, 'base64url'), { requestID: done.id, clientID: done.descriptor.client_id, codeChallenge: done.descriptor.code_challenge, sealed: done.sealedBytes }).toString('base64url')
  assert.equal(done.proof, expected, 'the harness and the reader agree on the vector byte for byte')
  assert.notEqual(proof(linkSecret, { requestID: done.id, clientID: 'other', codeChallenge: done.descriptor.code_challenge, sealedBytes: done.sealedBytes }), expected)
  assert.notEqual(proof(linkSecret, { requestID: done.id, clientID: done.descriptor.client_id, codeChallenge: done.descriptor.code_challenge, sealedBytes: Buffer.concat([done.sealedBytes, Buffer.from([0])]) }), expected)
  const connection = h.reader.state.connections.get(done.connectionId)
  assert.equal(connection.api_key, h.apiKey)
  assert.deepEqual(connection.device_ids, [vector.device])
  assert.equal(connection.workspace_id, workspace)
  assert.equal(connection.timezone, 'America/Sao_Paulo')
  assert.equal(connection.link_secret, undefined)
  assert.equal(JSON.stringify([...h.reader.state.connections.values()]).includes(linkSecret), false)
  assert.equal(h.reader.state.pending.has(done.id), false)
  const pending = { id: done.id, resource: done.descriptor.resource, tenant_id: workspace }
  await assert.rejects(openBundle(h.reader.state, pending, done.sealedBytes, 'e'.repeat(16)), error => error instanceof LinkError && error.code === 'unknown_kid')
  const tampered = Buffer.from(done.sealedBytes)
  tampered[tampered.length - 1] ^= 1
  await assert.rejects(openBundle(h.reader.state, pending, tampered, done.descriptor.kid), { code: 'invalid_bundle' })
  await assert.rejects(openBundle(h.reader.state, pending, done.sealedBytes.subarray(0, 40), done.descriptor.kid), { code: 'invalid_bundle' })
  const plaintextOnly = await sealBundle(done.descriptor, 'not an object', {})
  await assert.rejects(openBundle(h.reader.state, pending, plaintextOnly.sealedBytes, done.descriptor.kid), { code: 'invalid_bundle' })
  const notJSON = await hpke.seal(new Uint8Array(Buffer.from(done.descriptor.reader_public_key, 'base64url')), new Uint8Array(Buffer.from('wappie-mcp-connect/v1')), new Uint8Array(Buffer.from(JSON.stringify(['wappie/mcp-connect', 1, done.id, done.descriptor.kid, done.descriptor.resource]))), new Uint8Array(Buffer.from('{')))
  await assert.rejects(openBundle(h.reader.state, pending, Buffer.concat([Buffer.from(notJSON.enc), Buffer.from(notJSON.ciphertext)]), done.descriptor.kid), { code: 'invalid_bundle' })
  secretsAbsent(h, { linkSecrets: [linkSecret], proofs: [done.proof] })
})

test('key rotation: a bundle sealed to the previous recipient key still opens, the descriptor advertises the new one', async t => {
  const h = await harness(t)
  const first = (await h.internal('/internal/healthz')).status
  assert.equal(first, 200)
  const before = h.reader.state.recipient
  await h.reader.close()
  await rename(join(h.stateDir, 'keys', 'recipient.key'), join(h.stateDir, 'keys', 'recipient.previous'))
  await h.restart()
  assert.notEqual(h.reader.state.recipient.kid, before.kid)
  assert.equal(h.reader.state.previous.kid, before.kid)
  const provider = clientProvider()
  assert.equal(await auth(provider, { serverUrl: h.resource }), 'REDIRECT')
  const started = await consent(h, provider.store.authorizationUrl, { until: 'authorize' })
  const descriptor = (await h.internal(`/internal/requests/${started.id}`)).json()
  assert.equal(descriptor.kid, h.reader.state.recipient.kid)
  const stale = clientProvider()
  assert.equal(await auth(stale, { serverUrl: h.resource }), 'REDIRECT')
  const sealedToPrevious = await consent(h, stale.store.authorizationUrl, { readerPublicKey: before.publicKey, kid: before.kid, aadKid: before.kid })
  assert.equal(sealedToPrevious.relayed.status, 204)
  assert.equal(sealedToPrevious.completed.status, 302)
  const current = await consent(h, provider.store.authorizationUrl)
  assert.equal(current.completed.status, 302)
  for (const name of ['keys/recipient.key', 'keys/recipient.previous', 'keys/state.key', 'state.json.enc']) assert.equal((await stat(join(h.stateDir, name))).mode & 0o777, 0o600)
  const encrypted = await readFile(join(h.stateDir, 'state.json.enc'))
  assert.equal(encrypted.includes(h.apiKey), false)
  assert.equal(encrypted.includes('service_private_key'), false)
  const recipient = (await readFile(join(h.stateDir, 'keys', 'recipient.key'), 'utf8')).trim()
  assert.match(recipient, /^[A-Za-z0-9_-]{43}$/)
  assert.equal(kidOf(Buffer.from(await hpke.publicFromPrivate(new Uint8Array(Buffer.from(recipient, 'base64url'))))), h.reader.state.recipient.kid)
  secretsAbsent(h, { linkSecrets: [sealedToPrevious.linkSecret, current.linkSecret], extra: [recipient] })
})

test('authorized reads survive a restart and every archive call carries the bundled key, never a file', async t => {
  const h = await harness(t)
  const { provider, done } = await authorize(h, { auth })
  assert.equal((await rpc(h, provider.store.tokens.access_token)).status, 200)
  await h.restart()
  const listing = await rpc(h, provider.store.tokens.access_token)
  assert.equal(listing.status, 200)
  const tools = await rpc(h, provider.store.tokens.access_token, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'list_numbers', arguments: {} } })
  assert.equal(tools.status, 200)
  assert.equal(h.f.state.requests.every(item => item.auth === `Bearer ${h.apiKey}`), true)
  secretsAbsent(h, { linkSecrets: [done.linkSecret], tokens: [provider.store.tokens.access_token] })
})
