import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { readFile, rename, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { auth } from '@modelcontextprotocol/client'
import { hpke } from '@whatserver2/client'
import { harness, apiKey, authorize, authorizeURL, clientProvider, consent, pkce, proof, raw, register, rpc, sealBundle, secretsAbsent, session, vector, workspace, CONSOLE_ORIGIN, DAY } from './harness.mjs'
import { acceptBundle, LinkError, openBundle, proofFor } from '../link.mjs'
import { newRecipient } from '../state.mjs'

const kidOf = publicKey => createHash('sha256').update(publicKey).digest('hex').slice(0, 16)

test('descriptor and internal guard: loopback, no X-Forwarded-For, the relay secret; unknown requests are 404', async t => {
  const h = await harness(t)
  const provider = clientProvider()
  assert.equal(await auth(provider, { serverUrl: h.resource }), 'REDIRECT')
  const started = await consent(h, provider.store.authorizationUrl, { until: 'authorize' })
  const described = await h.internal(`/internal/requests/${started.id}`)
  assert.equal(described.status, 200)
  const descriptor = described.json()
  assert.deepEqual(Object.keys(descriptor).sort(), ['client_id', 'client_name', 'code_challenge', 'expires_at', 'kid', 'reader_public_key', 'redirect_host', 'redirect_local', 'request_id', 'resource'])
  assert.equal(descriptor.redirect_local, false, 'a web client sends the browser back to its own host')
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

test('connection ids: a relay naming one already in use is 400 with nothing attached, and a completion never replaces a connection', async t => {
  const h = await harness(t)
  const state = h.reader.state
  const fresh = async () => {
    h.clock.advance(13_000)
    const clientId = (await register(h, { client_name: `Ids ${randomBytes(3).toString('hex')}` })).json().client_id
    return authorizeURL(h, { clientId, challenge: pkce().challenge })
  }
  const nothingAttached = (pending, label) => {
    for (const field of ['bundle', 'connection_id', 'tenant_id', 'accepting']) assert.equal(pending[field], undefined, `${label}: ${field}`)
  }
  // An existing connection's id, relayed for another consent.
  const s = await session(h)
  const X = s.done.connectionId
  const record = state.connections.get(X)
  const goRow = { ...h.go.connections.get(X) }
  const reused = await consent(h, await fresh(), { connectionId: X, until: 'bundle' })
  assert.equal(reused.relayed.status, 400)
  assert.equal(reused.relayed.json().code, 'bad_request')
  nothingAttached(state.pending.get(reused.id), 'existing id')
  assert.equal(state.connections.get(X), record)
  h.go.connections.set(X, goRow)
  assert.equal((await rpc(h, s.tokens.access_token)).status, 200, 'the connection under X still serves its own family')

  // Two requests, one id.
  const shared = randomUUID()
  const first = await consent(h, await fresh(), { connectionId: shared, until: 'bundle' })
  assert.equal(first.relayed.status, 204)
  const second = await consent(h, await fresh(), { connectionId: shared, until: 'bundle' })
  assert.equal(second.relayed.status, 400)
  nothingAttached(state.pending.get(second.id), 'shared id')
  assert.equal(state.pending.get(first.id).connection_id, shared)

  // A connection that appears under a request's id between relay and proof is never replaced.
  const late = await consent(h, await fresh(), { until: 'bundle' })
  assert.equal(late.relayed.status, 204)
  const sentinel = { connection_id: late.connectionId, family_id: 'someone-else', client_id: 'someone-else', expires_at: late.expiresAt, created_at: h.clock.now() }
  state.connections.set(late.connectionId, sentinel)
  const activations = h.go.activations
  const signature = proof(late.linkSecret, { requestID: late.id, clientID: late.descriptor.client_id, codeChallenge: late.descriptor.code_challenge, sealedBytes: late.sealedBytes })
  const completed = await h.form('/mcp/authorize/complete', { request: late.id, proof: signature }, { origin: CONSOLE_ORIGIN })
  assert.equal(completed.status, 400)
  assert.match(completed.body, /connection_exists/)
  assert.equal(state.connections.get(late.connectionId), sentinel)
  assert.equal(state.pending.has(late.id), false)
  assert.equal(h.go.activations, activations, 'nothing was activated')
  assert.equal(h.logs.map(line => JSON.parse(line)).filter(entry => entry.code === 'connection_exists').length, 1)
})

test('connection ids: an id stays reserved while its completion awaits Go\'s activation, and is released once it lands or fails', async t => {
  const h = await harness(t)
  const state = h.reader.state
  const fresh = async () => {
    h.clock.advance(13_000)
    const clientId = (await register(h, { client_name: `Held ${randomBytes(3).toString('hex')}` })).json().client_id
    return authorizeURL(h, { clientId, challenge: pkce().challenge })
  }
  const nothingAttached = (pending, label) => {
    for (const field of ['bundle', 'connection_id', 'tenant_id', 'accepting']) assert.equal(pending[field], undefined, `${label}: ${field}`)
  }
  // Go's activation, held open until the test lets it answer.
  const hold = () => {
    let arrived, open
    const reached = new Promise(resolve => { arrived = resolve })
    const gate = new Promise(resolve => { open = resolve })
    h.go.holdActivate = id => { arrived(id); return gate }
    return { reached, release: () => { h.go.holdActivate = null; open() } }
  }
  const complete = done => h.form('/mcp/authorize/complete', {
    request: done.id, proof: proof(done.linkSecret, { requestID: done.id, clientID: done.descriptor.client_id, codeChallenge: done.descriptor.code_challenge, sealedBytes: done.sealedBytes }),
  }, { origin: CONSOLE_ORIGIN })
  // Another request, its bundle sealed before anything is held; `relay(id)` posts it as Go would, naming `id`.
  const rival = async () => {
    const started = await consent(h, await fresh(), { until: 'authorize' })
    const descriptor = (await h.internal(`/internal/requests/${started.id}`)).json()
    const { sealed } = await sealBundle(descriptor, {
      version: 1, server_url: new URL(descriptor.resource).origin, workspace_id: workspace, device_ids: [vector.device], token: h.apiKey, allow_plaintext: false, timezone: 'UTC', link_secret: randomBytes(32).toString('base64url'),
    })
    const relay = connectionId => h.internal(`/internal/requests/${started.id}/bundle`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
      connection_id: connectionId, tenant_id: workspace, kid: descriptor.kid, sealed, expires_at: new Date(h.clock.now() + 90 * DAY).toISOString(),
    }) })
    return { id: started.id, relay }
  }

  // Activation succeeds: while it is in flight the id is in neither pending nor connections, and still refused.
  const first = await consent(h, await fresh(), { until: 'bundle' })
  assert.equal(first.relayed.status, 204)
  const A = first.connectionId
  const other = await rival()
  const activations = h.go.activations
  const held = hold()
  const completing = complete(first)
  assert.equal(await held.reached, A)
  assert.equal(state.pending.has(first.id), false, 'the request has left pending')
  assert.equal(state.connections.has(A), false, 'and has not landed yet')
  assert.equal(state.activating?.has(A), true, 'the id is reserved across the await')
  const refused = await other.relay(A)
  assert.equal(refused.status, 400)
  assert.equal(refused.json().code, 'bad_request')
  nothingAttached(state.pending.get(other.id), 'relay during activation')
  held.release()
  const completed = await completing
  assert.equal(completed.status, 302, completed.body)
  assert.equal(state.connections.get(A).client_id, first.descriptor.client_id, 'the first consent owns the id')
  assert.equal(state.activating.has(A), false, 'the reservation ends when the connection lands')
  assert.equal(h.go.activations, activations + 1)
  assert.equal(h.go.connections.get(A).status, 'active')
  assert.equal((await other.relay(randomUUID())).status, 204, 'only the id was refused, not the request')

  // Activation fails (Go lost the row: 404, a RelayError): 502, and the reservation goes with the attempt.
  const second = await consent(h, await fresh(), { until: 'bundle' })
  assert.equal(second.relayed.status, 204)
  const B = second.connectionId
  const another = await rival()
  const failing = hold()
  const attempt = complete(second)
  assert.equal(await failing.reached, B)
  assert.equal(state.activating.has(B), true)
  assert.equal((await another.relay(B)).status, 400)
  nothingAttached(state.pending.get(another.id), 'relay during a failing activation')
  h.go.connections.delete(B)
  failing.release()
  const failed = await attempt
  assert.equal(failed.status, 502)
  assert.match(failed.body, /activation_failed/)
  assert.equal(state.activating.has(B), false, 'a failed activation clears the reservation')
  assert.equal(state.connections.has(B), false)
  assert.equal(state.pending.has(second.id), false)
  assert.equal(h.logs.map(line => JSON.parse(line)).filter(entry => entry.code === 'activation_failed').length, 1)
  assert.equal((await another.relay(B)).status, 204, 'the id is not held after the attempt')
  secretsAbsent(h, { linkSecrets: [first.linkSecret, second.linkSecret] })
})

test('acceptBundle (2a): concurrent relays for one request are one 204 and one 409; two requests racing for one id get one bundle', async () => {
  const resource = 'https://mcp.example.test/mcp'
  const state = { connections: new Map(), pending: new Map() }
  const request = async id => { const pending = { id, recipient: await newRecipient(), resource }; state.pending.set(id, pending); return pending }
  const relayFor = async (pending, connectionId) => {
    const descriptor = { request_id: pending.id, kid: pending.recipient.kid, reader_public_key: pending.recipient.publicKeyEncoded, resource }
    const bundle = { version: 1, server_url: 'https://mcp.example.test', workspace_id: workspace, device_ids: [vector.device], token: apiKey(), allow_plaintext: false, timezone: 'UTC', link_secret: randomBytes(32).toString('base64url') }
    const { sealed } = await sealBundle(descriptor, bundle)
    return { connection_id: connectionId, tenant_id: workspace, kid: pending.recipient.kid, sealed, expires_at: new Date(Date.now() + DAY).toISOString() }
  }
  // Every body is sealed before either call starts, so the two really interleave.
  const one = await request('A'.repeat(22))
  const bodies = [await relayFor(one, randomUUID()), await relayFor(one, randomUUID())]
  const [won, lost] = await Promise.allSettled(bodies.map(body => acceptBundle(state, one, body)))
  assert.equal(won.status, 'fulfilled')
  assert.equal(lost.status, 'rejected')
  assert.equal(lost.reason.status, 409)
  assert.equal(one.connection_id, bodies[0].connection_id, 'the first relay\'s bundle, never overwritten')
  assert.equal(one.accepting, undefined)

  const shared = randomUUID()
  const two = await request('B'.repeat(22)), three = await request('C'.repeat(22))
  const racing = [await relayFor(two, shared), await relayFor(three, shared)]
  const [first, second] = await Promise.allSettled([acceptBundle(state, two, racing[0]), acceptBundle(state, three, racing[1])])
  assert.equal(first.status, 'fulfilled')
  assert.equal(second.status, 'rejected')
  assert.equal(second.reason.code, 'bad_request')
  assert.equal(three.bundle, undefined)
  assert.equal(three.tenant_id, undefined)

  const four = await request('D'.repeat(22))
  const existing = randomUUID()
  state.connections.set(existing, { connection_id: existing })
  await assert.rejects(acceptBundle(state, four, await relayFor(four, existing)), { code: 'bad_request' })
  assert.equal(four.bundle, undefined)
})
