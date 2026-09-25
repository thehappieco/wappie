// The whole enclave reader (main.mjs startEnclave) with fake NSM, KMS, Go and
// ACME: boot order, TLS behind PROXY v2 on both listeners, HMAC in both
// directions, a consent through prepare with a per-request key and a fresh
// attestation, the eight tools behind the token, the public /attestation
// route, a Node restart that reloads the sealed state and keeps the tokens,
// relay-secret rotation, and a log sink that carries nothing secret.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes, randomUUID } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { createServer as createNetServer } from 'node:net'
import { join } from 'node:path'
import { fixture, vector, workspace } from '@whatserver2/mcp/test/fixture'
import { attestationUserData, decodeAttestationDocument } from '../../attestation.mjs'
import { pkce, proof, sealBundle } from '../../test/harness.mjs'
import { attest } from '../attest.mjs'
import * as constants from '../constants.mjs'
import { EXIT_BOOT_FAILED, startEnclave } from '../main.mjs'
import { lineAllowed } from '../logsink.mjs'
import { policySha256 } from '../policy.mjs'
import { encodeProxyV2 } from '../proxy.mjs'
import { spkiSha256 } from '../x509.mjs'
import { createEnclaveGo, createFakeAcme, fakeKms, fakeNsm, goHeaders, PCR0, proxiedRequest, testCA } from './fixtures.mjs'

const READER_KEY = 'arn:aws:kms:eu-west-1:768406580484:key/11111111-1111-4111-8111-111111111111'
const BOOT_KEY = 'arn:aws:kms:eu-west-1:768406580484:key/22222222-2222-4222-8222-222222222222'
const RESOURCE = 'https://mcp.wappie.thehappie.co/mcp'
const CONSOLE_ORIGIN = 'https://app.wappie.thehappie.co'
const REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback'
const POLICY = '{"Version":"2012-10-17","Statement":[{"Sid":"EnclaveUse","Effect":"Allow"}]}'
const relayContext = { purpose: 'wappie-mcp-relay', reader_id: 'enclave' }

/** Everything the enclave talks to, plus a way to (re)start it the way entrypoint.sh would. */
async function world(t, { bootJson } = {}) {
  const apiKey = `${randomBytes(4).toString('hex')}.${randomBytes(32).toString('base64url')}`
  const f = await fixture({ token: apiKey })
  const relaySecret = randomBytes(32).toString('base64url')
  const goSecrets = [relaySecret]
  const go = await createEnclaveGo({ upstream: f.server, secrets: () => goSecrets }).listen()
  const ca = testCA()
  // The challenge listener opens during boot, before startEnclave returns, so its port is chosen here.
  const challengePort = await freePort()
  const acme = await createFakeAcme({ ca, challengePort: () => challengePort }).listen()
  const bin = await fakeNsm()
  const nsmCalls = []
  const nsm = fields => { nsmCalls.push(fields); return attest(fields, { bin }) }
  const kms = fakeKms({ policy: POLICY, attest: nsm })
  const bootCiphertext = kms.encrypt(BOOT_KEY, Buffer.from(relaySecret), relayContext)
  const runDir = join(await mkdtemp(join(tmpdir(), 'wappie-enclave-')), 'run')
  const lines = [], exits = []
  const sink = { write: line => { lines.push(line); if (process.env.ENCLAVE_TEST_DEBUG) process.stderr.write(line + '\n') }, dropped: () => 0, drain: async () => {} }
  const boot = Buffer.from(bootJson ?? JSON.stringify({ relay_secret_ciphertext: bootCiphertext.toString('base64') }))
  const c = { ...Object.fromEntries(Object.entries(constants).filter(([, value]) => typeof value !== 'function')), KMS_READER_KEY_ARN: READER_KEY, KMS_BOOT_KEY_ARN: BOOT_KEY }
  const w = {
    f, go, ca, acme, kms, nsmCalls, lines, exits, apiKey, relaySecret, goSecrets, runDir, enclave: null, skew: 0,
    async start() {
      w.enclave = await startEnclave({
        constants: c, sink, kms, attest: nsm, now: () => Date.now() + w.skew, exit: code => exits.push(code), wait: () => new Promise(resolve => setTimeout(resolve, 5)),
        readLocal: async port => { if (port === 7001) return boot; throw new Error('unexpected port') },
        overrides: { archive: go.url, acmeDirectory: acme.directory, runDir, clockUrl: `${go.url}/clock`, ports: { public: 0, internal: 0, challenge: challengePort } },
      })
      return w.enclave
    },
    /** A public request as haproxy would forward it, from `source`. */
    public(path, { method = 'GET', headers = {}, body, source = '203.0.113.10' } = {}) {
      return proxiedRequest({ port: w.enclave.ports.public, proxy: encodeProxyV2({ address: source, port: 40000 }), ca: ca.pem, method, path, headers, body })
    },
    /** A Go request to the internal listener, HMAC-signed `to-reader`. */
    internal(path, { method = 'GET', body, secret = w.goSecrets[0], headers = {}, signed } = {}) {
      const bytes = body === undefined ? Buffer.alloc(0) : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body))
      const auth = signed ?? goHeaders(secret, { method, target: path, body: bytes })
      return proxiedRequest({ port: w.enclave.ports.internal, proxy: encodeProxyV2({ address: '198.51.100.20', port: 50000 }), ca: ca.pem, method, path, body: bytes.length ? bytes : undefined,
        headers: { host: 'mcp.wappie.thehappie.co:8443', ...(bytes.length ? { 'content-type': 'application/json' } : {}), ...auth, ...headers } })
    },
    async close() { await w.enclave?.close(); await go.close(); await acme.close(); await f.close(); await rm(join(runDir, '..'), { recursive: true, force: true }) },
  }
  t.after(() => w.close())
  return w
}

function freePort() {
  return new Promise(resolve => { const server = createNetServer(); server.listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)) }) })
}

const form = fields => ({ method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() })

/** Registration, authorize, prepare, bundle, consent completion and code exchange, as the assistant, Go and the console do them. */
async function connect(w, { source = '203.0.113.10' } = {}) {
  const registered = await w.public('/mcp/register', { method: 'POST', source, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: 'Claude', redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: 'none' }) })
  assert.equal(registered.status, 201, registered.body)
  const clientId = JSON.parse(registered.body).client_id
  const { verifier, challenge } = pkce()
  const query = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: REDIRECT_URI, code_challenge: challenge, code_challenge_method: 'S256', resource: RESOURCE, scope: 'wappie:read', state: 'st' })
  const authorized = await w.public(`/mcp/authorize?${query}`, { source })
  assert.equal(authorized.status, 302, authorized.body)
  const location = new URL(authorized.headers.location)
  assert.equal(location.origin + location.pathname, 'https://app.wappie.thehappie.co/console')
  const id = location.searchParams.get('mcp_connect')
  const described = await w.internal(`/internal/requests/${id}`)
  assert.equal(described.status, 200, described.body)
  const descriptor = JSON.parse(described.body)
  const nonce = randomBytes(32)
  const prepared = await w.internal(`/internal/requests/${id}/prepare`, { method: 'POST', body: { nonce: nonce.toString('base64url') } })
  assert.equal(prepared.status, 200, prepared.body)
  const preparedDescriptor = JSON.parse(prepared.body)
  const linkSecret = randomBytes(32).toString('base64url')
  const bundle = { version: 1, server_url: 'https://mcp.wappie.thehappie.co', workspace_id: workspace, device_ids: [vector.device], token: w.apiKey, allow_plaintext: false, timezone: 'UTC', link_secret: linkSecret }
  const { sealed, sealedBytes } = await sealBundle(preparedDescriptor, bundle)
  const connectionId = randomUUID()
  const expiresAt = new Date(Date.now() + 90 * 86_400_000).toISOString()
  w.go.connections.set(connectionId, { status: 'pending', expires_at: expiresAt })
  const relayed = await w.internal(`/internal/requests/${id}/bundle`, { method: 'POST', body: { connection_id: connectionId, tenant_id: workspace, kid: preparedDescriptor.kid, sealed, expires_at: expiresAt } })
  assert.equal(relayed.status, 204, relayed.body)
  const signature = proof(linkSecret, { requestID: id, clientID: clientId, codeChallenge: challenge, sealedBytes })
  const completed = await w.public('/mcp/authorize/complete', { ...form({ request: id, proof: signature }), headers: { 'content-type': 'application/x-www-form-urlencoded', origin: CONSOLE_ORIGIN }, source })
  assert.equal(completed.status, 302, completed.body)
  const code = new URL(completed.headers.location).searchParams.get('code')
  const exchanged = await w.public('/mcp/token', { ...form({ grant_type: 'authorization_code', code, client_id: clientId, code_verifier: verifier, redirect_uri: REDIRECT_URI, resource: RESOURCE }), source })
  assert.equal(exchanged.status, 200, exchanged.body)
  return { id, clientId, descriptor, preparedDescriptor, nonce, linkSecret, signature, connectionId, tokens: JSON.parse(exchanged.body) }
}

/** A JSON-RPC result from either response form the SDK may choose. */
const result = body => JSON.parse(body.startsWith('event:') ? body.split('\n').find(line => line.startsWith('data: ')).slice(6) : body).result
const rpc = (w, token, body = { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) => w.public('/mcp', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${token}` }, body: JSON.stringify(body) })

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
