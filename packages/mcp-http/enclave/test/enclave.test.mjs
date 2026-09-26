// The whole enclave reader (main.mjs startEnclave) with fake NSM, KMS, Go and
// ACME: boot order, TLS behind PROXY v2 on both listeners, HMAC in both
// directions, a consent through prepare with a per-request key and a fresh
// attestation, the eight tools behind the token, the public /attestation
// route, a Node restart that reloads the sealed state and keeps the tokens,
// relay-secret rotation, and a log sink that carries nothing secret.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { attestationUserData, decodeAttestationDocument } from '../../attestation.mjs'
import { pkce } from '../../test/harness.mjs'
import * as constants from '../constants.mjs'
import { EXIT_BOOT_FAILED, startEnclave } from '../main.mjs'
import { lineAllowed } from '../logsink.mjs'
import { policySha256 } from '../policy.mjs'
import { spkiSha256 } from '../x509.mjs'
import { goHeaders, PCR0 } from './fixtures.mjs'
import { BOOT_KEY, connect, form, READER_KEY, REDIRECT_URI, relayContext, RESOURCE, result, rpc, world, POLICY } from './world.mjs'

test('boot, consent through an attested prepare, tools, restart with tokens intact, and nothing secret in the sink', async t => {
  const w = await world(t)
  const e = await w.start()
  assert.deepEqual(w.exits, [])
  // Boot: relay secret under the boot key, policy read, state loaded, ACME account sealed in infra, a certificate for both names.
  assert.deepEqual(w.kms.calls.find(call => call.op === 'decrypt'), { op: 'decrypt', keyArn: BOOT_KEY, context: relayContext })
  assert.equal(w.go.state.has('infra'), true)
  assert.equal(w.acme.issued, 1)
  assert.deepEqual(e.names, ['mcp.wappie.thehappie.co', `${e.material.bootId}.boot.mcp.wappie.thehappie.co`])

  const health = await w.internal('/internal/healthz')
  assert.equal(health.status, 200, health.body)
  const object = JSON.parse(health.body)
  assert.deepEqual(Object.keys(object), ['ok', 'reader_id', 'reader_version', 'boot_id', 'state', 'pcr0', 'tls_spki_sha256', 'cert_not_after', 'policy_sha256', 'acme_account_uri', 'relay_secrets'])
  assert.equal(object.state, 'ready')
  assert.equal(object.pcr0, PCR0)
  assert.equal(object.tls_spki_sha256, spkiSha256(e.material.spki))
  assert.equal(object.policy_sha256, policySha256(POLICY))
  assert.match(object.acme_account_uri, /\/acme\/acct\/\d+$/)
  assert.match(object.cert_not_after, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/)
  assert.equal(object.relay_secrets, 1)
  assert.equal(health.headers['cache-control'], 'no-store')

  const done = await connect(w)
  // The descriptor names the request's own key, and prepare attests exactly that key, this nonce and these fields.
  const { preparedDescriptor: prepared, descriptor, nonce } = done
  assert.equal(prepared.reader_public_key, descriptor.reader_public_key)
  assert.equal(prepared.kid, descriptor.kid)
  const attestation = prepared.attestation
  assert.deepEqual(Object.keys(attestation), ['format', 'document', 'request_id', 'resource', 'reader_id', 'reader_version', 'tls_spki_sha256', 'policy_sha256', 'pcr0'])
  assert.equal(attestation.request_id, done.id)
  assert.equal(attestation.resource, RESOURCE)
  assert.equal(attestation.tls_spki_sha256, object.tls_spki_sha256)
  const decoded = decodeAttestationDocument(Buffer.from(attestation.document, 'base64url'))
  assert.deepEqual(decoded.publicKey, Buffer.from(descriptor.reader_public_key, 'base64url'))
  assert.deepEqual(decoded.nonce, nonce)
  assert.deepEqual(decoded.userData, attestationUserData(attestation))
  // Another request gets another key.
  const second = await w.public(`/mcp/authorize?${new URLSearchParams({ response_type: 'code', client_id: done.clientId, redirect_uri: REDIRECT_URI, code_challenge: pkce().challenge, code_challenge_method: 'S256', resource: RESOURCE })}`)
  const secondId = new URL(second.headers.location).searchParams.get('mcp_connect')
  assert.notEqual(JSON.parse((await w.internal(`/internal/requests/${secondId}`)).body).kid, descriptor.kid)

  const listed = await rpc(w, done.tokens.access_token)
  assert.equal(listed.status, 200, listed.body)
  assert.equal(result(listed.body).tools.length, 8)
  const numbers = await rpc(w, done.tokens.access_token, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'list_numbers', arguments: {} } })
  assert.equal(result(numbers.body).structuredContent.plaintext_enabled, false)
  assert.equal(w.go.activations, 1)
  assert.ok(w.f.state.requests.filter(item => item.path !== '/clock').every(item => item.auth === `Bearer ${w.apiKey}`), 'archive reads carry the bundled key (the clock probe carries nothing)')

  // A Node restart within the same enclave boot: same key and certificate, the sealed state reloads, tokens still work.
  await e.close()
  const issued = w.acme.issued
  const again = await w.start()
  assert.equal(w.acme.issued, issued, 'the certificate in /run/wappie is reused')
  assert.equal(again.material.bootId, e.material.bootId)
  assert.equal((await rpc(w, done.tokens.access_token)).status, 200)
  const refreshed = await w.public('/mcp/token', form({ grant_type: 'refresh_token', refresh_token: done.tokens.refresh_token, client_id: done.clientId, resource: RESOURCE }))
  assert.equal(refreshed.status, 200, refreshed.body)

  // Every sink line passes the parent's schema, and nothing secret is anywhere in it.
  const forbidden = [w.apiKey, w.relaySecret, done.linkSecret, done.signature, done.tokens.access_token, done.tokens.refresh_token, JSON.parse(refreshed.body).access_token, 'wmcp_']
  for (const line of w.lines) {
    assert.equal(lineAllowed(line), true, line)
    for (const value of forbidden) assert.equal(line.includes(value), false, 'secret in the sink')
  }
  assert.ok(w.lines.some(line => JSON.parse(line).event === 'health'))
  assert.ok(w.lines.some(line => JSON.parse(line).route === 'POST /internal/requests/{id}/prepare' && JSON.parse(line).status === 200))
  // Go only ever stored ciphertext.
  for (const row of w.go.state.values()) for (const value of [w.apiKey, done.connectionId]) assert.equal(row.blob.includes(Buffer.from(value)), false)
})

test('listeners: /internal never on the public port, nothing else on the internal one, exact Host on both, HMAC before anything', async t => {
  const w = await world(t)
  await w.start()
  assert.equal((await w.public('/internal/healthz', { headers: goHeaders(w.relaySecret, { method: 'GET', target: '/internal/healthz' }) })).status, 404)
  assert.equal((await w.public('/internal')).status, 404)
  assert.equal((await w.internal('/.well-known/oauth-protected-resource')).status, 404)
  assert.equal((await w.internal('/mcp', { method: 'POST', body: {} })).status, 404)
  assert.equal((await w.public('/.well-known/oauth-protected-resource', { headers: { host: 'evil.example' } })).status, 403)
  assert.equal((await w.internal('/internal/healthz', { headers: { host: 'mcp.wappie.thehappie.co' } })).status, 403)
  const prm = await w.public('/.well-known/oauth-protected-resource')
  assert.equal(JSON.parse(prm.body).resource, RESOURCE)
  // No signature, a wrong secret, a replay: 401 with no detail.
  const unsigned = await w.internal('/internal/healthz', { signed: {} })
  assert.equal(unsigned.status, 401)
  assert.deepEqual(JSON.parse(unsigned.body), { code: 'unauthorized' })
  assert.equal((await w.internal('/internal/healthz', { secret: 'x'.repeat(43) })).status, 401)
  const signed = goHeaders(w.relaySecret, { method: 'GET', target: '/internal/healthz' })
  assert.equal((await w.internal('/internal/healthz', { signed })).status, 200)
  assert.equal((await w.internal('/internal/healthz', { signed })).status, 401)
  await new Promise(resolve => setTimeout(resolve, 50)) // a line is written once its response has gone out
  const codes = w.lines.map(line => JSON.parse(line).code).filter(Boolean)
  for (const code of ['hmac_missing', 'hmac_bad', 'hmac_replay']) assert.ok(codes.includes(code), code)
  // X-Forwarded-For is never trusted: the PROXY source is the client.
  for (let i = 0; i < 10; i++) assert.equal((await w.public(`/attestation?nonce=${randomBytes(16).toString('base64url')}`, { source: '192.0.2.1', headers: { 'x-forwarded-for': `10.0.0.${i}` } })).status, 200)
  const limited = await w.public(`/attestation?nonce=${randomBytes(16).toString('base64url')}`, { source: '192.0.2.1', headers: { 'x-forwarded-for': '10.9.9.9' } })
  assert.equal(limited.status, 429)
  assert.equal((await w.public(`/attestation?nonce=${randomBytes(16).toString('base64url')}`, { source: '192.0.2.2' })).status, 200)
})

test('attestation routes: fresh documents, no public_key on /attestation, bad nonces, ten prepares per request, no CORS', async t => {
  const w = await world(t)
  await w.start()
  const nonce = randomBytes(64)
  const open = await w.public(`/attestation?nonce=${nonce.toString('base64url')}`)
  assert.equal(open.status, 200, open.body)
  assert.equal(open.headers['access-control-allow-origin'], undefined)
  const { attestation } = JSON.parse(open.body)
  assert.equal(attestation.request_id, '')
  const decoded = decodeAttestationDocument(Buffer.from(attestation.document, 'base64url'))
  assert.equal(decoded.publicKey, null)
  assert.deepEqual(decoded.nonce, nonce)
  const before = w.nsmCalls.length
  await w.public(`/attestation?nonce=${nonce.toString('base64url')}`)
  assert.equal(w.nsmCalls.length, before + 1, 'never cached')
  for (const bad of ['', 'nonce=' + randomBytes(15).toString('base64url'), 'nonce=' + randomBytes(65).toString('base64url'), `nonce=${randomBytes(16).toString('base64url')}&nonce=${randomBytes(16).toString('base64url')}`]) {
    assert.equal((await w.public(`/attestation?${bad}`, { source: '192.0.2.50' })).status, 400, bad)
  }
  const authorized = await w.public(`/mcp/authorize?${new URLSearchParams({ response_type: 'code', client_id: 'https://claude.ai/nope', redirect_uri: REDIRECT_URI, code_challenge: pkce().challenge, code_challenge_method: 'S256', resource: RESOURCE })}`)
  assert.equal(authorized.status, 400, 'an unknown client is refused before any request exists')
  const registered = JSON.parse((await w.public('/mcp/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: 'Claude', redirect_uris: [REDIRECT_URI] }) })).body)
  const id = new URL((await w.public(`/mcp/authorize?${new URLSearchParams({ response_type: 'code', client_id: registered.client_id, redirect_uri: REDIRECT_URI, code_challenge: pkce().challenge, code_challenge_method: 'S256', resource: RESOURCE })}`)).headers.location).searchParams.get('mcp_connect')
  for (const body of [{}, { nonce: 'short' }, { nonce: randomBytes(32).toString('base64url'), extra: 1 }, 'not json']) {
    assert.equal((await w.internal(`/internal/requests/${id}/prepare`, { method: 'POST', body })).status, 400, JSON.stringify(body))
  }
  assert.equal((await w.internal(`/internal/requests/${'A'.repeat(22)}/prepare`, { method: 'POST', body: { nonce: randomBytes(32).toString('base64url') } })).status, 404)
  const statuses = []
  for (let i = 0; i < 11; i++) statuses.push((await w.internal(`/internal/requests/${id}/prepare`, { method: 'POST', body: { nonce: randomBytes(32).toString('base64url') } })).status)
  // Refused bodies do not count; ten documents per request, then 429.
  assert.deepEqual(statuses, [...Array(10).fill(200), 429])
  // Without a fresh policy hash there is no attestation.
  w.kms.down = true
  await w.enclave.policy.refresh()
  w.skew = 21 * 60_000
  const refused = await w.public(`/attestation?nonce=${randomBytes(16).toString('base64url')}`, { source: '192.0.2.60' })
  assert.equal(refused.status, 503)
  assert.deepEqual(JSON.parse(refused.body), { code: 'policy_unknown' })
})

test('relay secret rotation at runtime: new ciphertext under the boot key, both accepted until Go switches, then the old one dies', async t => {
  const w = await world(t)
  await w.start()
  const next = randomBytes(32).toString('base64url')
  const refused = await w.internal('/internal/relay-secret', { method: 'POST', body: { ciphertext: w.kms.encrypt(READER_KEY, Buffer.from(next), relayContext).toString('base64') } })
  assert.equal(refused.status, 502, 'a ciphertext under any other key is a KMS failure')
  assert.equal((await w.internal('/internal/relay-secret', { method: 'POST', body: { ciphertext: 'not base64!' } })).status, 400)
  assert.equal((await w.internal('/internal/relay-secret', { method: 'POST', body: { ciphertext: w.kms.encrypt(BOOT_KEY, Buffer.from('short'), relayContext).toString('base64') } })).status, 400)
  const rotated = await w.internal('/internal/relay-secret', { method: 'POST', body: { ciphertext: w.kms.encrypt(BOOT_KEY, Buffer.from(next + '\n'), relayContext).toString('base64') } })
  assert.equal(rotated.status, 204, rotated.body)
  // Go (SECRET=S, SECRET_NEXT=S′) accepts either; the enclave now signs with S′.
  w.goSecrets.push(next)
  assert.equal(JSON.parse((await w.internal('/internal/healthz', { secret: w.relaySecret })).body).relay_secrets, 2)
  const refusedBefore = w.go.refused
  const done = await connect(w)
  assert.equal(w.go.refused, refusedBefore, 'every to-go call verified')
  assert.ok(done.connectionId)
  // Go switches to S′: the first request under it retires S.
  assert.equal(JSON.parse((await w.internal('/internal/healthz', { secret: next })).body).relay_secrets, 1)
  assert.equal((await w.internal('/internal/healthz', { secret: w.relaySecret })).status, 401)
  for (const line of w.lines) assert.equal(line.includes(next), false)
})

test('boot refuses a boot.json with an extra key (exit 78, boot_failed in the sink)', async t => {
  const w = await world(t, { bootJson: JSON.stringify({ relay_secret_ciphertext: 'AAAA', api_key: 'x' }) })
  await assert.rejects(w.start(), { code: 'boot_json_invalid' })
  assert.deepEqual(w.exits, [EXIT_BOOT_FAILED])
  const failed = w.lines.map(line => JSON.parse(line)).find(entry => entry.event === 'boot_failed')
  assert.equal(failed.code, 'boot_json_invalid')
})

test('an image that still carries the @@KMS_*@@ markers fails boot the same way (exit 78, one boot_failed constants_invalid line)', async () => {
  assert.throws(() => constants.imageConstants(), { message: 'constants_invalid' }) // this checkout is unbuilt
  const lines = [], exits = []
  let drained = 0
  const sink = { write: line => lines.push(line), dropped: () => 0, drain: async () => { drained++ } }
  await assert.rejects(startEnclave({ sink, exit: code => exits.push(code), readLocal: () => { throw new Error('boot.json must not be read') } }), { name: 'BootFailure', code: 'constants_invalid' })
  assert.deepEqual(exits, [EXIT_BOOT_FAILED])
  assert.equal(drained, 1)
  assert.equal(lines.length, 1)
  assert.ok(lineAllowed(lines[0]))
  const entry = JSON.parse(lines[0])
  assert.equal(entry.event, 'boot_failed')
  assert.equal(entry.code, 'constants_invalid')
})
