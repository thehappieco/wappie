// Console connection tokens in the enclave (docs/mcp-enclave.md §19.18,
// `console_token_v1`): an attested request of kind `token`, a bundle sealed in
// the person's browser that carries only the bearer's hash, the token tier,
// allowed networks, revocation by Go and by RFC 7009, restarts, expiry, and
// never a refresh grant. The bearer is minted here as the browser mints it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { CONSOLE_TOKEN_CLIENT_ID } from '@whatserver2/mcp/bundle'
import { vector, workspace } from '@whatserver2/mcp/test/fixture'
import { attestationUserDataV2, decodeAttestationDocument, descriptorSHA256 } from '../../attestation.mjs'
import { keyChecksum } from '../../tokens.mjs'
import { CLIENT_LIMITS } from '../constants.mjs'
import { TOKEN_REQUESTS_PENDING_MAX } from '../tokens.mjs'
import { callTool, contentGrants, DAY, deviceChecks, form, newApiKey, ORIGIN, resealed, RESOURCE, result, rpc, sealContent, world } from './world.mjs'

const sha256 = value => createHash('sha256').update(value).digest('hex')
/** A bearer as the console's browser mints it (§19.18 step 3): prefix, 43 random base64url characters, six of checksum. */
function mintBearer() {
  const head = `wmcp_k_${randomBytes(32).toString('base64url')}`
  return head + keyChecksum(head)
}
const tokenLabels = (requestId, kid) => ({ info: 'wappie-mcp-token/v1', aad: JSON.stringify(['wappie/mcp-token', 1, requestId, kid, RESOURCE]) })

async function tokenWorld(t) {
  const w = await world(t)
  w.clientPolicy = { refusalFloorMs: 0 }
  const e = await w.start()
  return { w, e }
}

/** POST /internal/token-requests: the attested descriptor of a fresh request. */
async function requestToken(w) {
  const nonce = randomBytes(32)
  const answer = await w.internal('/internal/token-requests', { method: 'POST', body: { nonce: nonce.toString('base64url') } })
  return { status: answer.status, body: answer.body, nonce, descriptor: answer.status === 200 ? JSON.parse(answer.body) : null }
}

/**
 * The token page and Go (§19.18 steps 2 to 6): a metadata or text bundle with
 * the bearer's hash and networks, sealed to the request's key, and Go's relay.
 * Every piece is overridable for the negative cases.
 */
async function installToken(w, { kind = 'metadata', bearer = mintBearer(), networks = [], history = 30, days = kind === 'content' ? 1 : 30, bundle: fields = {}, relay = {},
  request, labels, row = true, media = false } = {}) {
  const d = request ?? (await requestToken(w)).descriptor
  const expiresAt = new Date(Date.now() + days * DAY).toISOString()
  let bundle, service = null, token = w.apiKey
  if (kind === 'content') {
    service = randomUUID()
    token = newApiKey()
    await contentGrants(w, d.reader_public_key, { service, token })
    bundle = { version: 2, kind: 'content', purpose: 'token', server_url: ORIGIN, workspace_id: workspace, service_user_id: service, device_ids: [vector.device], token,
      key_mode: 'ephemeral', consent_version: 4, expires_at: expiresAt, timezone: 'UTC', client_id: CONSOLE_TOKEN_CLIENT_ID, client_kind: 'token', client_local: false,
      trust: 'unknown', started_ack: true, unknown_ack: true, history_days: history, bearer_sha256: sha256(bearer), allowed_networks: networks, ...(media ? { media: true } : {}), ...fields }
    for (const name of Object.keys(bundle)) if (bundle[name] === undefined) delete bundle[name]
    bundle.device_checks = deviceChecks(bundle, { request: d.request_id, kid: d.kid })
  } else {
    bundle = { version: 1, kind: 'metadata', purpose: 'token', server_url: ORIGIN, workspace_id: workspace, device_ids: [vector.device], token, timezone: 'UTC',
      expires_at: expiresAt, history_days: history, allowed_networks: networks, bearer_sha256: sha256(bearer), ...fields }
    for (const name of Object.keys(bundle)) if (bundle[name] === undefined) delete bundle[name]
  }
  const { sealed } = await sealContent(d.reader_public_key, bundle, labels ?? tokenLabels(d.request_id, d.kid))
  const connectionId = randomUUID()
  if (row) {
    w.go.connections.set(connectionId, { status: 'pending', expires_at: expiresAt,
      ...(kind === 'content' ? { kind: 'content', service_user_id: service, api_key: token, extra: { media, media_off: [], send: null, send_self: false } } : {}) })
  }
  const relayed = await w.internal(`/internal/token-requests/${d.request_id}/bundle`, { method: 'POST', body: {
    kind, connection_id: connectionId, tenant_id: workspace, kid: d.kid, sealed, expires_at: expiresAt, history_days: history, ...(media ? { media: true } : {}), ...relay } })
  return { request: d, bearer, bundle, connectionId, expiresAt, relayed, service, token }
}

test('the checksum (§19.18 step 3): the contract\'s vector, and a scanner can tell a real token from noise', () => {
  const head = `wmcp_k_${'A'.repeat(43)}`
  assert.equal(keyChecksum(head), '2I7pFC')
  assert.equal(sha256(head + '2I7pFC'), 'a60aed65d2620a197e14f253c6406048e638b0cc9d9e437b01fd7476bf167966')
  const bearer = mintBearer()
  assert.match(bearer, /^wmcp_k_[A-Za-z0-9_-]{43}[0-9A-Za-z]{6}$/)
  assert.equal(bearer.length, 56)
})

test('a token request (§19.18 step 1): an attested descriptor of kind token with the token tier\'s limits, user_data v2 over it; at most twenty live', async t => {
  const { w } = await tokenWorld(t)
  const { status, descriptor: d, nonce } = await requestToken(w)
  assert.equal(status, 200)
  assert.deepEqual(Object.keys(d), ['descriptor_version', 'kind', 'request_id', 'kid', 'reader_public_key', 'client_kind', 'trust', 'limits_tier', 'limits', 'resource',
    'reader_version', 'expires_at', 'attestation'])
  assert.deepEqual([d.descriptor_version, d.kind, d.client_kind, d.trust, d.limits_tier, d.resource, d.reader_version], [2, 'token', 'token', 'unknown', 'token', RESOURCE, '0.6.0'])
  assert.deepEqual(d.limits, CLIENT_LIMITS.token)
  assert.equal(d.limits.durations_days.content.default, 1, 'text tokens last a day by default')
  const document = decodeAttestationDocument(Buffer.from(d.attestation.document, 'base64url'))
  assert.deepEqual(document.userData, attestationUserDataV2(d.attestation, descriptorSHA256(d)))
  assert.deepEqual([document.publicKey, document.nonce], [Buffer.from(d.reader_public_key, 'base64url'), nonce])
  for (let n = 1; n < TOKEN_REQUESTS_PENDING_MAX; n++) assert.equal((await requestToken(w)).status, 200)
  const refused = await requestToken(w)
  assert.deepEqual([refused.status, JSON.parse(refused.body).code], [429, 'too_many_prepares'])
  assert.equal((await w.internal('/internal/token-requests', { method: 'POST', body: { nonce: 'short' } })).status, 400)
})

test('a metadata token: activated in Go, kept as its hash only, a bearer for /mcp with no refresh; RFC 7009 with the bearer ends it', async t => {
  const { w, e } = await tokenWorld(t)
  const done = await installToken(w, { history: 7 })
  assert.equal(done.relayed.status, 204, done.relayed.body)
  assert.equal(w.go.connections.get(done.connectionId).status, 'active', 'the enclave activated it')
  const record = e.state.connections.get(done.connectionId)
  assert.deepEqual([record.client_kind, record.client_id, record.trust, record.limits_tier, record.profile, record.history_days, record.client_host, record.client_name, record.kind],
    ['token', CONSOLE_TOKEN_CLIENT_ID, 'unknown', 'token', 'default', 7, null, null, undefined])
  const kept = e.state.tokens.get(sha256(done.bearer))
  assert.deepEqual([kept.kind, kept.connection_id, kept.client_id, kept.family_id], ['key', done.connectionId, CONSOLE_TOKEN_CLIENT_ID, record.family_id])
  assert.equal(kept.expires_at, Date.parse(done.expiresAt))
  assert.equal([...e.state.tokens.values()].filter(token => token.connection_id === done.connectionId).length, 1, 'no access or refresh token')
  for (const line of w.lines) assert.equal(line.includes(done.bearer) || line.includes(sha256(done.bearer)), false, 'neither the bearer nor its hash is logged')
  assert.deepEqual(w.lines.map(line => JSON.parse(line)).filter(entry => entry.event === 'token_installed').length, 1)
  // The bearer serves; a changed checksum, another bearer or a refresh grant do not.
  assert.equal((await rpc(w, done.bearer)).status, 200)
  const numbers = await callTool(w, done.bearer, 'list_numbers')
  assert.equal(numbers.isError, false, numbers.text)
  const flipped = done.bearer.slice(0, -1) + (done.bearer.endsWith('A') ? 'B' : 'A')
  assert.equal((await rpc(w, flipped)).status, 401)
  assert.equal((await rpc(w, mintBearer())).status, 401)
  const refresh = await w.public('/mcp/token', form({ grant_type: 'refresh_token', refresh_token: done.bearer, client_id: CONSOLE_TOKEN_CLIENT_ID, resource: RESOURCE }))
  assert.deepEqual([refresh.status, JSON.parse(refresh.body).error], [400, 'invalid_grant'])
  // RFC 7009: whoever holds the bearer can end it.
  const revoked = await w.public('/mcp/revoke', form({ token: done.bearer, client_id: CONSOLE_TOKEN_CLIENT_ID }))
  assert.equal(revoked.status, 200)
  assert.equal(e.state.connections.has(done.connectionId), false)
  assert.ok(w.go.revokes.some(item => item.id === done.connectionId), 'Go hears of it')
  assert.equal((await rpc(w, done.bearer)).status, 401)
})

test('allowed networks (§19.18): a call from elsewhere is 401 with the resource metadata, and Go hears budget_hit network once', async t => {
  const { w } = await tokenWorld(t)
  const done = await installToken(w, { networks: ['198.51.100.0/24', '2001:db8::/48'] })
  assert.equal(done.relayed.status, 204, done.relayed.body)
  const call = source => w.public('/mcp', { method: 'POST', source, headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${done.bearer}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) })
  assert.equal((await call('198.51.100.77')).status, 200)
  assert.equal((await call('2001:db8:0:5::1')).status, 200)
  const refused = await call('203.0.113.9')
  assert.equal(refused.status, 401)
  assert.match(refused.headers['www-authenticate'], /error="invalid_token".*resource_metadata=/)
  assert.equal((await call('2001:db9::1')).status, 401)
  assert.deepEqual(w.go.budgetHits, [{ id: done.connectionId, code: 'network' }], 'once a day per connection')
  assert.equal((await call('203.0.113.9')).status, 401)
  assert.equal(w.go.budgetHits.length, 1, 'still once')
  const open = await installToken(w, { networks: [] })
  assert.equal((await rpc(w, open.bearer)).status, 200, 'no networks: any network')
})

test('token refusals: a known hash, a window or expiry the tier lacks, another label, a fourth untested connection, sending, a missing row; nothing kept', async t => {
  const { w, e } = await tokenWorld(t)
  const first = await installToken(w)
  assert.equal(first.relayed.status, 204)
  const cases = [
    ['the same bearer again', { bearer: first.bearer }, 400, 'invalid_bundle'],
    ['a window the tier lacks', { history: 14 }, 400, 'invalid_bundle'],
    ['Go relays another window', { relay: { history_days: 90 } }, 400, 'invalid_bundle'],
    ['metadata past 90 days and an hour', { days: 91 }, 400, 'bad_request'],
    ['text past 30 days and an hour', { kind: 'content', days: 31 }, 400, 'bad_request'],
    ['sealed under the consent labels', { labels: { info: 'wappie-mcp-connect/v2', aad: '[]' } }, 400, 'invalid_bundle'],
    ['a link secret (there is no completion)', { bundle: { link_secret: randomBytes(32).toString('base64url') } }, 400, 'invalid_bundle'],
    ['text without the second tick', { kind: 'content', bundle: { unknown_ack: false } }, 400, 'invalid_bundle'],
    ['text that drafts', { kind: 'content', bundle: { send: 'draft' } }, 400, 'invalid_bundle'],
    ['text sealed as tested', { kind: 'content', bundle: { trust: 'tested', unknown_ack: false, history_days: null } }, 400, 'invalid_bundle'],
    ['attachments Go does not record', { kind: 'content', bundle: { media: true } }, 400, 'invalid_bundle'],
    ['metadata with attachments', { relay: { media: true } }, 400, 'bad_request'],
    ['another key', { relay: { kid: '0000000000000000' } }, 400, 'unknown_kid'],
    ['no row in Go', { row: false }, 502, 'relay_failed'],
  ]
  for (const [label, options, status, code] of cases) {
    const done = await installToken(w, options)
    assert.deepEqual([done.relayed.status, JSON.parse(done.relayed.body).code], [status, code], label)
    assert.equal(e.state.connections.has(done.connectionId), false, label)
  }
  // Two more fill the workspace's three; the fourth is refused.
  assert.equal((await installToken(w, { kind: 'content' })).relayed.status, 204)
  assert.equal((await installToken(w)).relayed.status, 204)
  const fourth = await installToken(w)
  assert.deepEqual([fourth.relayed.status, JSON.parse(fourth.relayed.body).code], [409, 'too_many_unknown'])
  // A refusal once the bundle is being opened is logged by its code (the relay's own shape is refused before that).
  const failures = w.lines.map(line => JSON.parse(line)).filter(entry => entry.event === 'token_install_failed').map(entry => entry.code)
  for (const code of ['invalid_bundle', 'relay_failed']) assert.ok(failures.includes(code), code)
})

test('restarts, expiry, Go\'s revocation and the unclaimed sweep (§19.18): metadata survives a restart; text waits in reseal; a token is never unclaimed', async t => {
  const { w, e } = await tokenWorld(t)
  const metadata = await installToken(w)
  const text = await installToken(w, { kind: 'content' })
  assert.equal(text.relayed.status, 204, text.relayed.body)
  assert.equal((await callTool(w, text.bearer, 'list_numbers')).isError, false)
  const textRecord = e.state.connections.get(text.connectionId)
  assert.deepEqual([textRecord.kind, textRecord.consent_version, textRecord.unknown_ack, textRecord.limits_tier, textRecord.media], ['content', 4, true, 'token', false])
  await e.close()
  const again = await w.start()
  assert.equal((await callTool(w, metadata.bearer, 'list_numbers')).isError, false, 'a metadata token survives a restart')
  // A text token waits for its renewal: metadata reads on, text is refused with the link (§19.29).
  assert.equal((await resealed(w, text.bearer, text.connectionId)).numbers.data.connection.tier, 'token')
  // Its renewal descriptor names the token, never its hash or networks.
  const renewal = JSON.parse((await w.internal(`/internal/connections/${text.connectionId}/renewal`, { method: 'POST', body: { nonce: randomBytes(32).toString('base64url') } })).body)
  assert.deepEqual([renewal.kind, renewal.client_kind, renewal.client_id, renewal.trust, renewal.limits_tier, renewal.history_days, renewal.unknown_ack],
    ['renewal', 'token', CONSOLE_TOKEN_CLIENT_ID, 'unknown', 'token', 30, true])
  assert.equal(JSON.stringify(renewal).includes(sha256(text.bearer)), false)
  // The unclaimed sweep (5 minutes without a code exchange) never revokes a token: its family exists from install.
  w.skew += 10 * 60_000
  await again.reader.sweep()
  assert.equal(again.state.connections.has(metadata.connectionId), true)
  assert.equal(w.go.revokes.some(item => item.id === metadata.connectionId), false)
  w.skew = 0
  // Go revokes it in the console: within the status cache, the bearer stops.
  w.go.connections.get(metadata.connectionId).status = 'revoked'
  assert.equal((await w.internal(`/internal/connections/${metadata.connectionId}/revoke`, { method: 'POST' })).status, 204)
  assert.equal((await rpc(w, metadata.bearer)).status, 401)
  // Expiry: past the token's validity it is gone.
  w.skew += 2 * DAY
  assert.equal((await rpc(w, text.bearer)).status, 401)
})

test('a text token\'s version-4 renewal (§19.16): the same bearer reads again once Go swaps; a renewal carrying the hash or the networks, or changing the window, is refused', async t => {
  const { w, e } = await tokenWorld(t)
  const text = await installToken(w, { kind: 'content', networks: ['203.0.113.0/24'] })
  assert.equal(text.relayed.status, 204, text.relayed.body)
  const source = { source: '203.0.113.9' }
  const before = e.state.connections.get(text.connectionId)
  const family = before.family_id
  await e.close()
  const again = await w.start()
  const call = () => w.public('/mcp', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${text.bearer}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_numbers', arguments: {} } }), ...source })
  const waiting = result((await call()).body)
  assert.equal(waiting.isError, undefined, 'metadata reads on while the token waits for its renewal (§19.29)')
  assert.equal(JSON.parse(waiting.content[0].text).renewal.renew_url, `https://app.wappie.thehappie.co/console?mcp_renew=${text.connectionId}`)
  const renew = async (fields = {}) => {
    const prepared = await w.internal(`/internal/connections/${text.connectionId}/renewal`, { method: 'POST', body: { nonce: randomBytes(32).toString('base64url') } })
    assert.equal(prepared.status, 200, prepared.body)
    const renewal = JSON.parse(prepared.body)
    const service = randomUUID(), token = newApiKey()
    await contentGrants(w, renewal.reader_public_key, { service, token })
    const connection = w.go.connections.get(text.connectionId)
    const bundle = { version: 2, kind: 'content', purpose: 'renewal', server_url: ORIGIN, workspace_id: workspace, service_user_id: service, device_ids: [vector.device], token,
      key_mode: 'ephemeral', consent_version: 4, expires_at: connection.expires_at, connection_id: text.connectionId,
      client_id: CONSOLE_TOKEN_CLIENT_ID, client_kind: 'token', client_local: false, trust: 'unknown', started_ack: true, unknown_ack: true, history_days: 30, ...fields }
    for (const name of Object.keys(bundle)) if (bundle[name] === undefined) delete bundle[name]
    bundle.device_checks = deviceChecks(bundle, { request: renewal.renewal_id, kid: renewal.kid })
    const labels = { info: 'wappie-mcp-renew/v1', aad: JSON.stringify(['wappie/mcp-renew', 1, renewal.renewal_id, text.connectionId, renewal.kid, RESOURCE]) }
    const { sealed } = await sealContent(renewal.reader_public_key, bundle, labels)
    const relayed = await w.internal(`/internal/connections/${text.connectionId}/renewal/${renewal.renewal_id}/bundle`, { method: 'POST', body: {
      connection_id: text.connectionId, tenant_id: workspace, kid: renewal.kid, sealed, expires_at: connection.expires_at, kind: 'content' } })
    return { renewal, service, relayed }
  }
  for (const [label, fields] of [
    ['the bearer\'s hash', { bearer_sha256: sha256(text.bearer) }], ['the allowed networks', { allowed_networks: [] }],
    ['another window', { history_days: 7 }], ['text without the second tick', { unknown_ack: false }],
  ]) {
    const refused = await renew(fields)
    assert.deepEqual([refused.relayed.status, JSON.parse(refused.relayed.body).code], [400, 'invalid_bundle'], label)
  }
  const renewed = await renew()
  assert.deepEqual([renewed.renewal.client_kind, renewed.renewal.limits_tier, 'bearer_sha256' in renewed.renewal, 'allowed_networks' in renewed.renewal], ['token', 'token', false, false])
  assert.equal(renewed.relayed.status, 204, renewed.relayed.body)
  // Go swaps, and the next call with the same bearer commits: the token keeps its hash, family and networks.
  const connection = w.go.connections.get(text.connectionId)
  connection.service_user_id = renewed.service
  connection.status = 'active'
  const answer = await call()
  assert.equal(answer.status, 200, answer.body)
  assert.doesNotMatch(answer.body, /reconsent_required|isError":true|mcp_renew=/)
  const record = again.state.connections.get(text.connectionId)
  assert.deepEqual([record.client_kind, record.limits_tier, record.family_id, record.allowed_networks, record.history_days], ['token', 'token', family, ['203.0.113.0/24'], 30])
  assert.equal([...again.state.tokens.values()].filter(item => item.kind === 'key' && item.connection_id === text.connectionId && item.hash === sha256(text.bearer)).length, 1)
  assert.equal((await w.public('/mcp', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${text.bearer}` }, body: '{}', source: '198.51.100.7' })).status, 401, 'still bound to its networks')
})
