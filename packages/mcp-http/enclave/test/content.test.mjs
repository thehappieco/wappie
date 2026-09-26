// Milestone 2b in the enclave (docs/mcp-enclave.md §15): content bundles v2
// accepted only after the grant proof, the key held in memory and wiped on
// every path that ends a connection, `reseal` after a restart with the token
// family intact, renewal that keeps the connection id, the 60 s sweep that
// wipes an idle key without a token and wipes nothing while Go is away, the
// reuse reason reaching Go, and a sink that never carries content, names,
// queries, tokens or keys. Fake NSM, KMS, Go and archive (fixtures.mjs).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes, randomUUID } from 'node:crypto'
import { chatName, plain, vector, workspace } from '@whatserver2/mcp/test/fixture'
import { decodeAttestationDocument } from '../../attestation.mjs'
import { CONTENT_SWEEP_MS } from '../../server.mjs'
import { CONTENT_REFRESH_IDLE_MS } from '../../tokens.mjs'
import { PROOF_TIMEOUT_MS, proveGrants } from '../content.mjs'
import { lineAllowed } from '../logsink.mjs'
import { newRecipient } from '../../state.mjs'
import {
  callTool, connect, connectContent, consentLabels, contentGrants, DAY, form, newApiKey, ORIGIN, prepareRequest, renewLabels, RESOURCE, rpc, sealContent, world,
} from './world.mjs'

const events = w => w.lines.map(line => JSON.parse(line)).filter(entry => entry.event)
const eventCount = (w, name) => events(w).filter(entry => entry.event === name).length
const refresh = (w, done) => w.public('/mcp/token', { ...form({ grant_type: 'refresh_token', refresh_token: done.tokens.refresh_token, client_id: done.clientId, resource: RESOURCE }), source: done.source })

test('content consent: the v2 bundle opens only with the attested key, the grant proof runs before 204, and the tools read text', async t => {
  const w = await world(t)
  const e = await w.start()
  const done = await connectContent(w)
  assert.equal(done.relayed.status, 204, done.relayed.body)
  assert.equal(done.completed.status, 302, done.completed.body)
  // The proof asked the archive for the grants with the bundle's key, before Go ever activated anything.
  assert.ok(w.go.archiveRequests.some(item => item.path === '/v1/grants' && item.token === done.token))
  const record = e.state.connections.get(done.connectionId)
  assert.equal(record.kind, 'content')
  assert.equal(record.service_user_id, done.service)
  assert.equal(record.key_mode, 'ephemeral')
  assert.equal(record.consent_version, 1)
  assert.deepEqual(record.epochs, { [vector.device]: 1 })
  assert.equal(e.reader.state.pending.size, 0)
  assert.equal(record.expires_at, new Date(done.expiresAt).toISOString())
  assert.equal(e.facts.content.holds(done.connectionId), true)
  // The key is a handle only: nothing of it is in the sealed state Go stores.
  const held = e.facts.content.connkeys.get(done.connectionId)
  assert.equal(held.key.extractable, false)
  assert.deepEqual(Buffer.from(held.publicRaw), Buffer.from(done.prepared.reader_public_key, 'base64url'))
  for (const row of w.go.state.values()) for (const value of [done.token, done.linkSecret, done.prepared.reader_public_key]) assert.equal(row.blob.includes(Buffer.from(value)), false)

  const numbers = await callTool(w, done.tokens.access_token, 'list_numbers')
  assert.equal(numbers.isError, false, numbers.text)
  assert.equal(numbers.data.plaintext_enabled, true)
  const chats = await callTool(w, done.tokens.access_token, 'list_chats', { device_id: vector.device })
  assert.equal(chats.isError, false, chats.text)
  const page = await callTool(w, done.tokens.access_token, 'list_messages', { device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net' })
  assert.equal(page.isError, false, page.text)
  assert.equal(page.data.messages[0].body.state, 'ok')
  assert.equal(page.data.messages[0].body.value, plain)
  const query = `sentinel${randomBytes(6).toString('hex')}`
  const search = await callTool(w, done.tokens.access_token, 'search_messages', { device_id: vector.device, query, period: 'all' })
  assert.equal(search.status, 200)
  // The archive saw only the service's key, never the fixture's own.
  assert.ok(w.go.archiveRequests.every(item => item.token === done.token))

  const expectedEvents = ['content_accepted', 'connkey_installed']
  for (const name of expectedEvents) assert.equal(eventCount(w, name), 1, name)
  const name = Buffer.from(chatName.plaintext, 'base64').toString('utf8')
  const forbidden = [plain, name, query, done.token, done.linkSecret, done.signature, done.sealed, done.tokens.access_token, done.tokens.refresh_token, done.nonce.toString('base64url'), done.prepared.reader_public_key, vector.private_key, 'wmcp_']
  for (const line of w.lines) {
    assert.equal(lineAllowed(line), true, line)
    for (const value of forbidden) assert.equal(line.includes(value), false, 'secret or content in the sink')
  }
})

test('content refusals: every one is 400 before any proof exists, and nothing is attached to the request', async t => {
  const w = await world(t)
  await w.start()
  const other = (await prepareRequest(w)).prepared
  const cases = [
    ['v1 labels', { labels: { info: 'wappie-mcp-connect/v1', aad: null } }, 'invalid_bundle'],
    ['v2 labels, v1 AAD', { labels: 'v1aad' }, 'invalid_bundle'],
    ['another request key', { sealTo: other.reader_public_key }, 'invalid_bundle'],
    ['a kid that is not the request\'s', { relay: { kid: other.kid } }, 'unknown_kid'],
    ['service_private_key', { bundle: { service_private_key: randomBytes(32).toString('base64url') } }, 'invalid_bundle'],
    ['contacts', { bundle: { contacts: { version: 1 } } }, 'invalid_bundle'],
    ['allow_plaintext', { bundle: { allow_plaintext: true } }, 'invalid_bundle'],
    ['version 1', { bundle: { version: 1 } }, 'invalid_bundle'],
    ['renewal purpose on the consent route', { bundle: { purpose: 'renewal', connection_id: randomUUID() }, omit: ['link_secret'] }, 'invalid_bundle'],
    ['no link secret', { omit: ['link_secret'] }, 'invalid_bundle'],
    ['server_url of the pilot', { bundle: { server_url: 'https://api.wappie.thehappie.co' } }, 'invalid_bundle'],
    ['workspace is not the tenant', { bundle: { workspace_id: randomUUID() } }, 'invalid_bundle'],
    ['persisted key mode', { bundle: { key_mode: 'persisted' } }, 'invalid_bundle'],
    ['beyond 90 days', { bundleExpiresAt: new Date(Date.now() + 92 * DAY).toISOString() }, 'invalid_bundle'],
    // Without the label the relay takes the 2a path, where no v2 bundle opens.
    ['no kind in the relay', { relay: { kind: undefined } }, 'invalid_bundle'],
    ['grants of another account', { grants: { user: randomUUID() } }, 'grant_proof_failed'],
    ['a grant too many', { grants: { devices: [vector.device, randomUUID()] } }, 'grant_proof_failed'],
    ['no grants', { grants: { devices: [] } }, 'grant_proof_failed'],
    ['a grant sealed to another key', { grants: { sealTo: other.reader_public_key } }, 'grant_proof_failed'],
    ['a grant bound to another epoch', { grants: { rowEpoch: 2 } }, 'grant_proof_failed'],
  ]
  for (const [label, overrides, code] of cases) {
    const request = await prepareRequest(w, { source: `198.18.0.${cases.findIndex(item => item[0] === label) + 1}` })
    if (overrides.labels === 'v1aad') overrides.labels = { info: 'wappie-mcp-connect/v2', aad: JSON.stringify(['wappie/mcp-connect', 1, request.id, request.prepared.kid, RESOURCE]) }
    else if (overrides.labels?.aad === null) overrides.labels = { info: overrides.labels.info, aad: JSON.stringify(['wappie/mcp-connect', 1, request.id, request.prepared.kid, RESOURCE]) }
    const done = await connectContent(w, { ...overrides, request, until: 'bundle' })
    assert.equal(done.relayed.status, 400, `${label}: ${done.relayed.body}`)
    assert.equal(JSON.parse(done.relayed.body).code, code, label)
    const pending = w.enclave.reader.state.pending.get(request.id)
    assert.equal(pending.bundle, undefined, `${label}: nothing attached`)
    assert.equal(pending.content, undefined, `${label}: no bundle kept`)
    // With nothing attached, a proof is refused like any other.
    const refused = await w.public('/mcp/authorize/complete', { ...form({ request: request.id, proof: randomBytes(32).toString('base64url') }), headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://app.wappie.thehappie.co' }, source: request.source })
    assert.equal(refused.status, 400, label)
  }
  assert.equal(eventCount(w, 'grant_proof_failed'), 5)
  assert.equal(w.go.activations, 0)
})

test('expiry is the earlier of the bundle\'s and Go\'s, and a second bundle is 409', async t => {
  const w = await world(t)
  const e = await w.start()
  const early = new Date(Date.now() + 10 * DAY).toISOString()
  const one = await connectContent(w, { bundleExpiresAt: early })
  assert.equal(e.state.connections.get(one.connectionId).expires_at, early)
  const goEarly = new Date(Date.now() + 5 * DAY).toISOString()
  const two = await connectContent(w, { expiresAt: goEarly, bundleExpiresAt: new Date(Date.now() + 20 * DAY).toISOString() })
  assert.equal(e.state.connections.get(two.connectionId).expires_at, goEarly)
  const three = await connectContent(w, { until: 'bundle' })
  const again = await w.internal(`/internal/requests/${three.id}/bundle`, { method: 'POST', body: { connection_id: three.connectionId, tenant_id: workspace, kid: three.prepared.kid, sealed: three.sealed, expires_at: three.expiresAt, kind: 'content' } })
  assert.equal(again.status, 409)
})

test('a metadata bundle labelled kind: metadata still takes the 2a path in the enclave', async t => {
  const w = await world(t)
  const e = await w.start()
  const done = await connect(w)
  const record = e.state.connections.get(done.connectionId)
  assert.equal(record.kind, undefined)
  assert.equal(e.facts.content.holds(done.connectionId), false)
})

test('wipes: Go revoke, Go answering revoked or expired or another service, and reseal keep nothing but what they must', async t => {
  const w = await world(t)
  const e = await w.start()
  const reader = e.reader
  const content = e.facts.content

  // Revoke from Go: key and record gone at once.
  const a = await connectContent(w)
  assert.equal((await w.internal(`/internal/connections/${a.connectionId}/revoke`, { method: 'POST' })).status, 204)
  assert.equal(content.holds(a.connectionId), false)
  assert.equal(e.state.connections.has(a.connectionId), false)

  // Idle connections, no token presented: the sweep asks Go about every one of them.
  const revoked = await connectContent(w), expired = await connectContent(w), moved = await connectContent(w), resealed = await connectContent(w), kept = await connectContent(w)
  w.go.connections.get(revoked.connectionId).status = 'revoked'
  w.go.connections.get(expired.connectionId).expires_at = new Date(Date.now() - 1000).toISOString()
  w.go.connections.get(moved.connectionId).service_user_id = randomUUID()
  w.go.connections.get(resealed.connectionId).status = 'reseal'
  const swept = await reader.contentSweep()
  assert.deepEqual(swept, { checked: 5, wiped: 4, unreachable: 0 })
  for (const done of [revoked, expired, moved]) {
    assert.equal(content.holds(done.connectionId), false)
    assert.equal(e.state.connections.has(done.connectionId), false)
  }
  assert.equal(eventCount(w, 'service_mismatch'), 1)
  // Reseal: no key, the record and its token family stay, every tool asks for a renewal.
  assert.equal(content.holds(resealed.connectionId), false)
  assert.equal(e.state.connections.has(resealed.connectionId), true)
  const answer = await callTool(w, resealed.tokens.access_token, 'list_numbers')
  assert.equal(answer.isError, true)
  assert.match(answer.text, /reconsent_required/)
  assert.ok(answer.text.includes(`https://app.wappie.thehappie.co/console?mcp_renew=${resealed.connectionId}`), answer.text)
  assert.equal((await refresh(w, resealed)).status, 200, 'the family survives reseal')
  // The untouched one still serves.
  assert.equal(content.holds(kept.connectionId), true)
  assert.equal((await callTool(w, kept.tokens.access_token, 'list_numbers')).isError, false)
  assert.equal(CONTENT_SWEEP_MS, 60_000, 'an idle key is gone within a minute of a revocation')
  const sweeps = events(w).filter(entry => entry.event === 'content_sweep')
  assert.deepEqual(sweeps.at(-1), { ts: sweeps.at(-1).ts, event: 'content_sweep', checked: 5, wiped: 4, unreachable: 0 })

  // Local expiry (the 30 s sweep) wipes the key too.
  const late = await connectContent(w)
  e.state.connections.get(late.connectionId).expires_at = new Date(Date.now() - 1).toISOString()
  await reader.sweep()
  assert.equal(content.holds(late.connectionId), false)
})

test('Go away: the sweep wipes nothing, the verifier answers 503 once the cache lapses, and serving resumes', async t => {
  const w = await world(t)
  const e = await w.start()
  const done = await connectContent(w)
  w.go.down = true
  const swept = await e.reader.contentSweep()
  assert.deepEqual(swept, { checked: 1, wiped: 0, unreachable: 1 })
  assert.equal(e.facts.content.holds(done.connectionId), true)
  assert.equal(e.state.connections.has(done.connectionId), true)
  w.skew = CONTENT_SWEEP_MS + 1000
  const refused = await rpc(w, done.tokens.access_token)
  assert.ok(refused.status >= 500, `the verifier refuses while Go is away (${refused.status})`)
  assert.equal(e.facts.content.holds(done.connectionId), true)
  w.go.down = false
  assert.equal((await callTool(w, done.tokens.access_token, 'list_numbers')).isError, false)
})

test('restart: every content connection is resealed in Go, tools answer reconsent_required, the family survives; a row Go lost is wiped', async t => {
  const w = await world(t)
  const e = await w.start()
  const done = await connectContent(w)
  const lost = await connectContent(w)
  assert.equal((await callTool(w, done.tokens.access_token, 'list_numbers')).isError, false)
  await e.close()
  w.go.connections.delete(lost.connectionId)
  const again = await w.start()
  assert.equal(again.facts.content.holds(done.connectionId), false)
  assert.equal(w.go.connections.get(done.connectionId).status, 'reseal')
  assert.ok(w.go.reseals.includes(done.connectionId))
  assert.equal(again.state.connections.has(done.connectionId), true)
  assert.equal(again.state.connections.has(lost.connectionId), false, '404 on reseal wipes the record')
  const answer = await callTool(w, done.tokens.access_token, 'search_messages', { device_id: vector.device, query: 'anything', period: 'all' })
  assert.equal(answer.isError, true)
  assert.match(answer.text, /reconsent_required/)
  assert.ok(answer.text.includes(`mcp_renew=${done.connectionId}`))
  const refreshed = await refresh(w, done)
  assert.equal(refreshed.status, 200, refreshed.body)
  assert.ok(eventCount(w, 'reseal_requested') >= 2)
})

test('restart while Go cannot reseal: records are kept, reseal is retried in the background, and the verifier asks for one itself', async t => {
  const w = await world(t)
  const e = await w.start()
  const done = await connectContent(w)
  await e.close()
  w.go.resealDown = true
  const again = await w.start()
  assert.equal(again.state.connections.has(done.connectionId), true)
  assert.equal(w.go.connections.get(done.connectionId).status, 'active')
  w.go.resealDown = false
  for (let i = 0; i < 100 && w.go.connections.get(done.connectionId).status !== 'reseal'; i++) await new Promise(resolve => setTimeout(resolve, 50))
  assert.equal(w.go.connections.get(done.connectionId).status, 'reseal', 'the background retry reached Go')
  // Go active with no key here (a reseal Go had not recorded): the check asks for one and answers reseal.
  w.go.connections.get(done.connectionId).status = 'active'
  const answer = await callTool(w, done.tokens.access_token, 'list_numbers')
  assert.match(answer.text, /reconsent_required/)
  assert.equal(w.go.connections.get(done.connectionId).status, 'reseal')
})

/** The console's renewal: prepare through Go, grants and a renewal bundle for a new service, then Go's swap. */
async function renew(w, done, overrides = {}) {
  const nonce = randomBytes(32)
  const prepared = await w.internal(`/internal/connections/${done.connectionId}/renewal`, { method: 'POST', body: { nonce: nonce.toString('base64url') } })
  if (prepared.status !== 200) return { prepared }
  const renewal = JSON.parse(prepared.body)
  const service = overrides.service ?? randomUUID()
  const token = newApiKey()
  await contentGrants(w, renewal.reader_public_key, { service, token })
  const connection = w.go.connections.get(done.connectionId)
  const bundle = {
    version: 2, kind: 'content', purpose: 'renewal', server_url: ORIGIN, workspace_id: workspace, service_user_id: service, device_ids: [vector.device],
    token, key_mode: 'ephemeral', consent_version: 1, expires_at: connection.expires_at, connection_id: done.connectionId, ...overrides.bundle,
  }
  const { sealed } = await sealContent(renewal.reader_public_key, bundle, overrides.labels ?? renewLabels(renewal.renewal_id, done.connectionId, renewal.kid))
  const relayed = await w.internal(`/internal/connections/${done.connectionId}/renewal/${renewal.renewal_id}/bundle`, { method: 'POST', body: {
    connection_id: done.connectionId, tenant_id: workspace, kid: renewal.kid, sealed, expires_at: connection.expires_at, kind: 'content', ...overrides.relay,
  } })
  return { nonce, prepared, renewal, service, token, sealed, relayed }
}
/** What Go does on POST /v1/mcp/connections/{id}/renew: the new service is live, the old key is revoked. */
function goSwap(w, done, renewed) {
  const connection = w.go.connections.get(done.connectionId)
  w.go.tokens.delete(done.token)
  connection.service_user_id = renewed.service
  connection.status = 'active'
}

test('renewal after a restart: attested per-renewal key, staged bundle, Go swaps, the next tool call commits; same connection id and family', async t => {
  const w = await world(t)
  const e = await w.start()
  const done = await connectContent(w)
  await e.close()
  const again = await w.start()
  assert.match((await callTool(w, done.tokens.access_token, 'list_numbers')).text, /reconsent_required/)

  const renewed = await renew(w, done)
  assert.equal(renewed.prepared.status, 200, renewed.prepared.body)
  const { renewal } = renewed
  assert.deepEqual(Object.keys(renewal), ['renewal_id', 'connection_id', 'kid', 'reader_public_key', 'resource', 'device_ids', 'expires_at', 'connection_expires_at', 'attestation'])
  assert.match(renewal.renewal_id, /^[A-Za-z0-9_-]{22}$/)
  assert.equal(renewal.connection_id, done.connectionId)
  assert.equal(renewal.resource, RESOURCE)
  assert.deepEqual(renewal.device_ids, [vector.device])
  assert.equal(renewal.connection_expires_at, new Date(done.expiresAt).toISOString())
  assert.equal(renewal.attestation.request_id, renewal.renewal_id)
  const document = decodeAttestationDocument(Buffer.from(renewal.attestation.document, 'base64url'))
  assert.deepEqual(document.publicKey, Buffer.from(renewal.reader_public_key, 'base64url'))
  assert.deepEqual(document.nonce, renewed.nonce)
  assert.notEqual(renewal.reader_public_key, done.prepared.reader_public_key)
  assert.equal(renewed.relayed.status, 204, renewed.relayed.body)
  assert.equal(eventCount(w, 'renewal_staged'), 1)

  // Before Go swaps, the old service is still the one Go names: nothing commits.
  assert.match((await callTool(w, done.tokens.access_token, 'list_numbers')).text, /reconsent_required/)
  goSwap(w, done, renewed)
  const numbers = await callTool(w, done.tokens.access_token, 'list_numbers')
  assert.equal(numbers.isError, false, numbers.text)
  const record = again.state.connections.get(done.connectionId)
  assert.equal(record.service_user_id, renewed.service)
  assert.equal(record.api_key, renewed.token)
  assert.equal(again.facts.content.holds(done.connectionId), true)
  assert.deepEqual(Buffer.from(again.facts.content.connkeys.get(done.connectionId).publicRaw), Buffer.from(renewal.reader_public_key, 'base64url'))
  assert.equal(eventCount(w, 'renewal_committed'), 1)
  const page = await callTool(w, done.tokens.access_token, 'list_messages', { device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net' })
  assert.equal(page.data.messages[0].body.value, plain)
  // Same family: the refresh token issued at consent still rotates.
  assert.equal((await refresh(w, done)).status, 200)
  for (const line of w.lines) {
    assert.equal(lineAllowed(line), true, line)
    for (const value of [renewed.token, renewal.renewal_id, renewed.nonce.toString('base64url'), renewal.reader_public_key, plain]) assert.equal(line.includes(value), false)
  }
})

test('renewal of a live connection: the old key serves until Go swaps, then the new one does', async t => {
  const w = await world(t)
  const e = await w.start()
  const done = await connectContent(w)
  assert.equal((await callTool(w, done.tokens.access_token, 'list_numbers')).isError, false)
  const renewed = await renew(w, done)
  assert.equal(renewed.relayed.status, 204, renewed.relayed.body)
  goSwap(w, done, renewed)
  // The cached `serve` does not hide a staged renewal.
  assert.equal((await callTool(w, done.tokens.access_token, 'list_chats', { device_id: vector.device })).isError, false)
  assert.equal(e.state.connections.get(done.connectionId).api_key, renewed.token)
})

test('renewal refusals: unknown or metadata connections, the same service, other numbers, another deadline, twice, eleven an hour', async t => {
  const w = await world(t)
  const e = await w.start()
  const done = await connectContent(w)
  const metadata = await connect(w)
  const nonce = { nonce: randomBytes(32).toString('base64url') }
  assert.equal((await w.internal(`/internal/connections/${randomUUID()}/renewal`, { method: 'POST', body: nonce })).status, 404)
  assert.equal((await w.internal(`/internal/connections/${metadata.connectionId}/renewal`, { method: 'POST', body: nonce })).status, 404)
  assert.equal((await w.internal(`/internal/connections/${done.connectionId}/renewal`, { method: 'POST', body: { nonce: 'short' } })).status, 400)
  const cases = [
    ['the same service', { service: done.service }, 'invalid_bundle'],
    ['other numbers', { bundle: { device_ids: [vector.device, randomUUID()] } }, 'invalid_bundle'],
    ['an earlier deadline', { bundle: { expires_at: new Date(Date.now() + 10 * DAY).toISOString() } }, 'invalid_bundle'],
    ['consent labels', { labels: 'consent' }, 'invalid_bundle'],
    ['another connection id inside', { bundle: { connection_id: randomUUID() } }, 'invalid_bundle'],
    ['a link secret', { bundle: { link_secret: randomBytes(32).toString('base64url') } }, 'invalid_bundle'],
  ]
  for (const [label, overrides, code] of cases) {
    if (overrides.labels === 'consent') overrides.labels = consentLabels('AAAAAAAAAAAAAAAAAAAAAA', 'x')
    const attempt = await renew(w, done, overrides)
    assert.equal(attempt.relayed.status, 400, `${label}: ${attempt.relayed.body}`)
    assert.equal(JSON.parse(attempt.relayed.body).code, code, label)
  }
  const good = await renew(w, done)
  assert.equal(good.relayed.status, 204)
  const twice = await w.internal(`/internal/connections/${done.connectionId}/renewal/${good.renewal.renewal_id}/bundle`, { method: 'POST', body: { connection_id: done.connectionId, tenant_id: workspace, kid: good.renewal.kid, sealed: good.sealed, expires_at: done.expiresAt, kind: 'content' } })
  assert.equal(twice.status, 409)
  assert.equal((await w.internal(`/internal/connections/${done.connectionId}/renewal/${'B'.repeat(22)}/bundle`, { method: 'POST', body: {} })).status, 404)
  // Ten renewals per connection per hour (seven so far), then 429.
  const statuses = []
  for (let i = 0; i < 4; i++) statuses.push((await w.internal(`/internal/connections/${done.connectionId}/renewal`, { method: 'POST', body: { nonce: randomBytes(32).toString('base64url') } })).status)
  assert.deepEqual(statuses, [200, 200, 200, 429])
  // A stage that never commits dies with its renewal.
  w.skew = 21 * 60_000
  e.facts.content.sweep()
  assert.equal(e.facts.content.pending(done.connectionId), false)
})

test('families: a reuse reaches Go with its reason, an RFC 7009 revoke without one, and content refresh tokens idle out after a week', async t => {
  const w = await world(t)
  const e = await w.start()
  const done = await connectContent(w)
  const first = await refresh(w, done)
  assert.equal(first.status, 200)
  w.skew = 31_000 // past the rotation grace window
  assert.equal((await refresh(w, done)).status, 400)
  const reuse = w.go.revokes.find(item => item.id === done.connectionId)
  assert.deepEqual(reuse, { id: done.connectionId, body: '{"reason":"reuse_detected"}' })
  assert.equal(e.facts.content.holds(done.connectionId), false)
  assert.equal(eventCount(w, 'family_reuse'), 1)

  const other = await connectContent(w)
  const revoked = await w.public('/mcp/revoke', { ...form({ token: other.tokens.refresh_token, client_id: other.clientId }), source: other.source })
  assert.equal(revoked.status, 200)
  assert.deepEqual(w.go.revokes.find(item => item.id === other.connectionId), { id: other.connectionId, body: '' })
  assert.equal(e.facts.content.holds(other.connectionId), false)

  const idle = await connectContent(w)
  const record = [...e.state.tokens.values()].find(token => token.connection_id === idle.connectionId && token.kind === 'refresh')
  assert.ok(record.expires_at - record.issued_at <= CONTENT_REFRESH_IDLE_MS)
  assert.equal(CONTENT_REFRESH_IDLE_MS, 7 * DAY)
})

test('health line and close: content counts, and every key is wiped at exit', async t => {
  const w = await world(t)
  const e = await w.start()
  await connectContent(w)
  await connect(w)
  const line = await e.health.tick()
  assert.equal(line.content_connections, 1)
  assert.equal(line.content_keys, 1)
  const content = e.facts.content
  await e.close()
  w.enclave = null
  assert.equal(content.connkeys.size(), 0)
})

// ---- Review fixes: connection ids Go picks, consented deadlines, and the minors ----

/** A consent sealed for `request` but not relayed yet: the relay body Go would post. */
async function sealedConsent(w, request, connectionId) {
  const service = randomUUID(), token = newApiKey()
  await contentGrants(w, request.prepared.reader_public_key, { service, token })
  const expiresAt = new Date(Date.now() + 30 * DAY).toISOString()
  const bundle = {
    version: 2, kind: 'content', purpose: 'consent', server_url: ORIGIN, workspace_id: workspace, service_user_id: service, device_ids: [vector.device],
    token, key_mode: 'ephemeral', consent_version: 1, expires_at: expiresAt, timezone: 'UTC', link_secret: randomBytes(32).toString('base64url'),
  }
  const { sealed } = await sealContent(request.prepared.reader_public_key, bundle, consentLabels(request.id, request.prepared.kid))
  w.go.connections.set(connectionId, { status: 'pending', expires_at: expiresAt, kind: 'content', service_user_id: service })
  return { connection_id: connectionId, tenant_id: workspace, kid: request.prepared.kid, sealed, expires_at: expiresAt, kind: 'content' }
}
const nothingAttached = (pending, label) => {
  assert.equal(pending.bundle, undefined, `${label}: no bundle`)
  assert.equal(pending.content, undefined, `${label}: no opened bundle`)
  assert.equal(pending.connection_id, undefined, `${label}: no connection id`)
  assert.equal(pending.accepting, undefined, `${label}: no claim left behind`)
}

test('regression (PoC overwrite): a consent relayed under a connection id already in use is refused, and the old family never reads it', async t => {
  const w = await world(t)
  const e = await w.start()
  // The operator's own earlier connection X, with its tokens.
  const attacker = await connect(w)
  const X = attacker.connectionId
  const before = e.state.connections.get(X)
  const goRow = { ...w.go.connections.get(X) }
  const activations = w.go.activations
  // A victim's content consent, relayed by a hostile Go under connection id X.
  const victim = await connectContent(w, { connectionId: X })
  assert.equal(victim.relayed.status, 400, victim.relayed.body)
  assert.equal(JSON.parse(victim.relayed.body).code, 'bad_request')
  assert.equal(victim.completed, undefined, 'no proof was ever asked for')
  nothingAttached(e.state.pending.get(victim.id), 'metadata id')
  assert.equal(e.state.connections.get(X), before, 'the record under X is untouched')
  assert.equal(e.facts.content.holds(X), false, 'no key was installed under X')
  assert.equal(w.go.activations, activations)
  assert.equal(eventCount(w, 'content_accepted'), 0)
  // Go's row as it was: the operator's own connection opens no content (it was never a content consent).
  w.go.connections.set(X, goRow)
  const page = await callTool(w, attacker.tokens.access_token, 'list_messages', { device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net' })
  assert.equal(page.isError, false, page.text)
  assert.notEqual(page.data.messages[0].body.value, plain, 'the operator read the victim\'s text')

  // The same with a content connection's id: its key and service stay its own.
  const first = await connectContent(w)
  const second = await connectContent(w, { connectionId: first.connectionId })
  assert.equal(second.relayed.status, 400, second.relayed.body)
  nothingAttached(e.state.pending.get(second.id), 'content id')
  assert.equal(e.state.connections.get(first.connectionId).service_user_id, first.service)
  assert.deepEqual(Buffer.from(e.facts.content.connkeys.get(first.connectionId).publicRaw), Buffer.from(first.prepared.reader_public_key, 'base64url'))
})

test('two pending requests never share a connection id: attached, or relayed at the same time', async t => {
  const w = await world(t)
  const e = await w.start()
  const shared = randomUUID()
  const a = await connectContent(w, { connectionId: shared, until: 'bundle' })
  assert.equal(a.relayed.status, 204, a.relayed.body)
  const b = await connectContent(w, { connectionId: shared, until: 'bundle' })
  assert.equal(b.relayed.status, 400, b.relayed.body)
  nothingAttached(e.state.pending.get(b.id), 'second request')
  assert.equal(e.state.pending.get(a.id).connection_id, shared, 'the first request keeps its bundle')

  // Both relays in flight at once: exactly one wins, the other attaches nothing.
  const racing = randomUUID()
  const one = await prepareRequest(w), two = await prepareRequest(w)
  const bodies = [await sealedConsent(w, one, racing), await sealedConsent(w, two, racing)]
  const answers = await Promise.all([one, two].map((request, index) => w.internal(`/internal/requests/${request.id}/bundle`, { method: 'POST', body: bodies[index] })))
  assert.deepEqual(answers.map(answer => answer.status).sort(), [204, 400], answers.map(answer => answer.body).join(' '))
  const loser = answers[0].status === 400 ? one : two
  nothingAttached(e.state.pending.get(loser.id), 'racing request')
  const winner = loser === one ? two : one
  assert.equal(e.state.pending.get(winner.id).connection_id, racing)
})

test('regression (PoC expiry): Go cannot push a content connection past its consented deadline; status, refresh and renewal keep it', async t => {
  const w = await world(t)
  const e = await w.start()
  const consented = new Date(Date.now() + 2 * DAY).toISOString()
  const done = await connectContent(w, { expiresAt: consented })
  const record = e.state.connections.get(done.connectionId)
  assert.equal(record.consented_expires_at, consented)
  // Later answers from Go, one within the relay bound and the PoC's five years: the record keeps the consent.
  for (const later of [60 * DAY, 5 * 365 * DAY]) {
    Object.assign(w.go.connections.get(done.connectionId), { status: 'active', expires_at: new Date(Date.now() + later).toISOString() })
    assert.equal(await e.reader.checkActive(done.connectionId, { force: true }), 'serve')
    assert.equal(record.expires_at, consented)
  }
  w.go.connections.get(done.connectionId).expires_at = new Date(Date.now() + 60 * DAY).toISOString()
  // Refresh: the new refresh token's absolute limit is the consented date.
  const refreshed = await refresh(w, done)
  assert.equal(refreshed.status, 200, refreshed.body)
  const successor = [...e.state.tokens.values()].find(token => token.connection_id === done.connectionId && token.kind === 'refresh' && !token.rotated_to)
  assert.equal(successor.expires_at, Date.parse(consented))
  // Renewal: prepare names the consented date and a bundle carrying it is the one accepted.
  const renewed = await renew(w, done, { bundle: { expires_at: consented } })
  assert.equal(renewed.prepared.status, 200, renewed.prepared.body)
  assert.equal(renewed.renewal.connection_expires_at, consented)
  assert.equal(renewed.relayed.status, 204, renewed.relayed.body)
  goSwap(w, done, renewed)
  assert.equal((await callTool(w, done.tokens.access_token, 'list_numbers')).isError, false)
  assert.equal(record.service_user_id, renewed.service, 'the renewal committed')
  assert.equal(record.consented_expires_at, consented, 'a renewal commit keeps the consent')
  assert.equal(await e.reader.checkActive(done.connectionId, { force: true }), 'serve')
  assert.equal(record.expires_at, consented)
  // Go may still bring the deadline forward.
  const earlier = new Date(Date.now() + DAY).toISOString()
  w.go.connections.get(done.connectionId).expires_at = earlier
  assert.equal(await e.reader.checkActive(done.connectionId, { force: true }), 'serve')
  assert.equal(record.expires_at, earlier)
})

test('regression (renewal narrowing): a committed renewal narrows the consent to the deadline it carried, and Go cannot widen it back', async t => {
  const w = await world(t)
  const e = await w.start()
  const consented = new Date(Date.now() + 30 * DAY).toISOString()
  const done = await connectContent(w, { expiresAt: consented })
  const record = e.state.connections.get(done.connectionId)
  assert.equal(record.consented_expires_at, consented)
  // Go brings the deadline forward to day 5 of the 30-day consent.
  const narrowed = new Date(Date.now() + 5 * DAY).toISOString()
  Object.assign(w.go.connections.get(done.connectionId), { status: 'active', expires_at: narrowed })
  assert.equal(await e.reader.checkActive(done.connectionId, { force: true }), 'serve')
  assert.equal(record.expires_at, narrowed)
  assert.equal(record.consented_expires_at, consented, 'a status answer alone does not touch the consent')
  // A renewal under the narrowed deadline: prepare names it, the bundle carries it, Go swaps, a tool call commits.
  const renewed = await renew(w, done)
  assert.equal(renewed.prepared.status, 200, renewed.prepared.body)
  assert.equal(renewed.renewal.connection_expires_at, narrowed)
  assert.equal(renewed.relayed.status, 204, renewed.relayed.body)
  goSwap(w, done, renewed)
  assert.equal((await callTool(w, done.tokens.access_token, 'list_numbers')).isError, false)
  assert.equal(record.service_user_id, renewed.service, 'the renewal committed')
  assert.equal(record.consented_expires_at, narrowed, 'the commit narrows the consent to the renewed deadline')
  // Go answers the original consented date again: the record stays at day 5.
  w.go.connections.get(done.connectionId).expires_at = consented
  assert.equal(await e.reader.checkActive(done.connectionId, { force: true }), 'serve')
  assert.equal(record.expires_at, narrowed)
  assert.equal(record.consented_expires_at, narrowed)
  // The next renewal names day 5, and a bundle carrying the original date is refused.
  const next = await renew(w, done)
  assert.equal(next.prepared.status, 200, next.prepared.body)
  assert.equal(next.renewal.connection_expires_at, narrowed)
  assert.equal(next.relayed.status, 400, next.relayed.body)
  assert.equal(JSON.parse(next.relayed.body).code, 'invalid_bundle')
  assert.equal(record.consented_expires_at, narrowed)
})

test('a service mismatch wipe is told to Go as a revoke', async t => {
  const w = await world(t)
  const e = await w.start()
  const done = await connectContent(w)
  w.go.connections.get(done.connectionId).service_user_id = randomUUID()
  assert.equal(await e.reader.checkActive(done.connectionId, { force: true }), false)
  assert.equal(eventCount(w, 'service_mismatch'), 1)
  assert.deepEqual(w.go.revokes.filter(item => item.id === done.connectionId), [{ id: done.connectionId, body: '' }])
  assert.equal(w.go.connections.get(done.connectionId).status, 'revoked')
})

test('boot while Go cannot reseal: one attempt, the rest go straight to the background retry', async t => {
  const w = await world(t)
  const e = await w.start()
  const done = [await connectContent(w), await connectContent(w), await connectContent(w)]
  await e.close()
  w.go.resealDown = true
  const before = w.go.reseals.length
  const again = await w.start()
  assert.equal(w.go.reseals.length - before, 1, 'the boot asked Go once, not once per record')
  for (const item of done) assert.equal(again.state.connections.has(item.connectionId), true)
  w.go.resealDown = false
  const resealed = () => done.every(item => w.go.connections.get(item.connectionId).status === 'reseal')
  for (let i = 0; i < 100 && !resealed(); i++) await new Promise(resolve => setTimeout(resolve, 50))
  assert.equal(resealed(), true, 'the background retry reached Go for every record')
})

test('the grant proof gives up at 8 s, under Go\'s 10 s relay timeout', async t => {
  assert.equal(PROOF_TIMEOUT_MS, 8000)
  const bundle = { workspace_id: workspace, token: newApiKey(), service_user_id: randomUUID(), device_ids: [vector.device] }
  const hang = (_url, init) => new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason)))
  const key = (await newRecipient()).privateKey
  const asked = []
  const timeout = AbortSignal.timeout
  AbortSignal.timeout = ms => { asked.push(ms); return timeout.call(AbortSignal, 20) }
  t.after(() => { AbortSignal.timeout = timeout })
  await assert.rejects(proveGrants(key, bundle, { archive: 'http://127.0.0.1:9', fetch: hang }), { code: 'grant_proof_failed' })
  AbortSignal.timeout = timeout
  assert.deepEqual(asked, [PROOF_TIMEOUT_MS])
})

test('a stale grant is logged as stale_grant with the connection only', async t => {
  const w = await world(t)
  await w.start()
  const done = await connectContent(w)
  // The number's grant moves to epoch 2 after consent.
  await contentGrants(w, done.prepared.reader_public_key, { service: done.service, token: done.token, epoch: 2 })
  const answer = await callTool(w, done.tokens.access_token, 'list_chats', { device_id: vector.device })
  assert.equal(answer.isError, true)
  assert.match(answer.text, /stale_grant/)
  for (let i = 0; i < 20 && eventCount(w, 'stale_grant') === 0; i++) await new Promise(resolve => setTimeout(resolve, 10))
  const logged = events(w).filter(entry => entry.event === 'stale_grant')
  assert.equal(logged.length, 1)
  assert.deepEqual(Object.keys(logged[0]).sort(), ['conn', 'event', 'ts'])
  for (const line of w.lines) assert.equal(line.includes(vector.device), false)
})
