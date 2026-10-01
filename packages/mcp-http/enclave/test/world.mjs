// The enclave test world: startEnclave with fake NSM, KMS, Go and ACME, the
// consent flow as the assistant, Go and the console perform it, and a JSON-RPC
// helper. Shared by enclave.test.mjs (2a) and content.test.mjs (2b).
import assert from 'node:assert/strict'
import { randomBytes, randomUUID } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { createServer as createNetServer } from 'node:net'
import { join } from 'node:path'
import { bytes, hpke, seal } from '@whatserver2/client'
import { aiConfigScope, aiConfigTag, deviceCheck, deviceScope, keysSHA256 } from '@whatserver2/mcp/bundle'
import { fixture, vector, workspace } from '@whatserver2/mcp/test/fixture'
import { pkce, proof, sealBundle } from '../../test/harness.mjs'
import { attest } from '../attest.mjs'
import * as constants from '../constants.mjs'
import { startEnclave } from '../main.mjs'
import { encodeProxyV2 } from '../proxy.mjs'
import { STUB_KEYS } from './ai-stubs.mjs'
import { createEnclaveGo, createFakeAcme, fakeKms, fakeNsm, goHeaders, proxiedRequest, testCA } from './fixtures.mjs'

export const READER_KEY = 'arn:aws:kms:eu-west-1:768406580484:key/11111111-1111-4111-8111-111111111111'
export const BOOT_KEY = 'arn:aws:kms:eu-west-1:768406580484:key/22222222-2222-4222-8222-222222222222'
export const RESOURCE = 'https://mcp.wappie.thehappie.co/mcp'
export const CONSOLE_ORIGIN = 'https://app.wappie.thehappie.co'
export const REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback'
export const POLICY = '{"Version":"2012-10-17","Statement":[{"Sid":"EnclaveUse","Effect":"Allow"}]}'
export const relayContext = { purpose: 'wappie-mcp-relay', reader_id: 'enclave' }
/** 0.5.0's client rule, which the tests written before reader 0.6.0 run under (main.mjs's `overrides.clientPolicy`). */
export const LEGACY_POLICY = Object.freeze({ mode: 'allowlist', hosts: ['claude.ai', 'chatgpt.com'] })

/**
 * Everything the enclave talks to, plus a way to (re)start it the way
 * entrypoint.sh would. `archive(apiKey)` replaces the synthetic archive (it
 * returns a fixture with `server` and `close`); `w.jail`, when set before a
 * start, replaces media-jail (media tests).
 *
 * The client policy is 0.5.0's allowlist unless `w.clientPolicy` says
 * otherwise before a start: the tests written before reader 0.6.0 run the
 * rules they were written for, and the 0.6.0 tests (any-enclave.test.mjs)
 * set `{}` for the image's `any` policy, with `w.cimdFetcher` answering for
 * the parent's egress proxy. `constants` replaces image constants (a test's
 * smaller CLIENT_LIMITS, say), as a rebuilt image would.
 */
export async function world(t, { bootJson, archive, constants: replaced = {} } = {}) {
  const apiKey = `${randomBytes(4).toString('hex')}.${randomBytes(32).toString('base64url')}`
  const f = await (archive ?? (token => fixture({ token })))(apiKey)
  const relaySecret = randomBytes(32).toString('base64url')
  const goSecrets = [relaySecret]
  const go = await createEnclaveGo({ upstream: f.server, secrets: () => goSecrets, upstreamToken: apiKey, workspace, now: () => Date.now() + (w?.skew ?? 0) }).listen()
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
  const c = { ...Object.fromEntries(Object.entries(constants).filter(([, value]) => typeof value !== 'function')), KMS_READER_KEY_ARN: READER_KEY, KMS_BOOT_KEY_ARN: BOOT_KEY, ...replaced }
  const w = {
    f, go, ca, acme, kms, nsmCalls, lines, exits, apiKey, relaySecret, goSecrets, runDir, enclave: null, skew: 0, jail: null, aiTransport: null, mediaDelay: null,
    clientPolicy: LEGACY_POLICY, cimdFetcher: null,
    async start() {
      w.enclave = await startEnclave({
        constants: c, sink, kms, attest: nsm, now: () => Date.now() + w.skew, exit: code => exits.push(code), wait: () => new Promise(resolve => setTimeout(resolve, 5)),
        ...(w.jail ? { jail: w.jail } : {}),
        // Never a real provider: the AI egress goes to w.aiTransport (ai-stubs.mjs), or fails.
        aiTransport: (url, init) => (w.aiTransport ? w.aiTransport(url, init) : Promise.reject(new TypeError('fetch failed'))),
        ...(w.mediaDelay ? { mediaDelay: w.mediaDelay } : {}),
        readLocal: async port => { if (port === 7001) return boot; throw new Error('unexpected port') },
        overrides: { archive: go.url, acmeDirectory: acme.directory, runDir, clockUrl: `${go.url}/clock`, ports: { public: 0, internal: 0, challenge: challengePort },
          clientPolicy: w.clientPolicy, cimdFetcher: w.cimdFetcher ?? { fetch: async () => ({ ok: false, code: 'proxy_refused', network: true }) } },
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

export function freePort() {
  return new Promise(resolve => { const server = createNetServer(); server.listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)) }) })
}

export const form = fields => ({ method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() })

/** Registration, authorize, prepare, bundle, consent completion and code exchange, as the assistant, Go and the console do them. */
export async function connect(w, { source = '203.0.113.10' } = {}) {
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
export const result = body => JSON.parse(body.startsWith('event:') ? body.split('\n').find(line => line.startsWith('data: ')).slice(6) : body).result
export const rpc = (w, token, body = { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) => w.public('/mcp', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${token}` }, body: JSON.stringify(body) })

// ---- Content connections (2b) ------------------------------------------------------
//
// The console's side of §15.4 and §15.9, written from the contract rather than
// from content.mjs: grants sealed to the attested key for a fresh service
// account, and a v2 bundle sealed under the versioned labels.

export const ORIGIN = 'https://mcp.wappie.thehappie.co'
export const DAY = 24 * 3_600_000
export const consentLabels = (requestId, kid) => ({ info: 'wappie-mcp-connect/v2', aad: JSON.stringify(['wappie/mcp-connect', 2, requestId, kid, RESOURCE]) })
export const renewLabels = (renewalId, connectionId, kid) => ({ info: 'wappie-mcp-renew/v1', aad: JSON.stringify(['wappie/mcp-renew', 1, renewalId, connectionId, kid, RESOURCE]) })
export const newApiKey = () => `${randomBytes(4).toString('hex')}.${randomBytes(32).toString('base64url')}`

/** HPKE to the attested key under `labels`; `enc ‖ ciphertext` as base64url. */
export async function sealContent(publicKeyEncoded, bundle, { info, aad }) {
  const { enc, ciphertext } = await hpke.seal(new Uint8Array(Buffer.from(publicKeyEncoded, 'base64url')), new Uint8Array(Buffer.from(info)), new Uint8Array(Buffer.from(aad)), new Uint8Array(Buffer.from(JSON.stringify(bundle))))
  const sealedBytes = Buffer.concat([Buffer.from(enc), Buffer.from(ciphertext)])
  return { sealedBytes, sealed: sealedBytes.toString('base64url') }
}

/**
 * Registers `token` with the fake archive for `service` and seals the vector
 * device key (or `dsk`, a forged one) to `publicKeyEncoded` as each device's grant. `devices` defaults
 * to the one number the synthetic archive holds; `epoch` and `rowEpoch` differ
 * only in a negative case.
 */
export async function contentGrants(w, publicKeyEncoded, { service, token, devices = [vector.device], epoch = 1, rowEpoch = epoch, user = service, sealTo = publicKeyEncoded, dsk = bytes.fromBase64(vector.private_key) }) {
  const namespace = bytes.parseUUID(vector.tenant)
  const grants = []
  for (const device of devices) {
    const row = await seal.grantRow(namespace, bytes.parseUUID(device), bytes.parseUUID(service), rowEpoch)
    const sealed = await seal.sealDirect(new Uint8Array(Buffer.from(sealTo, 'base64url')), seal.Kind.DeviceGrant, namespace, row, rowEpoch, dsk)
    grants.push({ device_id: device, archive_tenant_id: vector.tenant, epoch, sealed_dsk: bytes.toBase64(sealed) })
  }
  w.go.tokens.add(token)
  w.go.grants.set(token, { user_id: user, grants })
}

/** Register, authorize and prepare: a pending request and its attested descriptor. */
export async function prepareRequest(w, { source = `198.19.${randomBytes(1)[0]}.${1 + (randomBytes(1)[0] % 250)}` } = {}) {
  const registered = await w.public('/mcp/register', { method: 'POST', source, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: `Claude ${randomBytes(3).toString('hex')}`, redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: 'none' }) })
  assert.equal(registered.status, 201, registered.body)
  const clientId = JSON.parse(registered.body).client_id
  const { verifier, challenge } = pkce()
  const query = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: REDIRECT_URI, code_challenge: challenge, code_challenge_method: 'S256', resource: RESOURCE, scope: 'wappie:read', state: 'st' })
  const authorized = await w.public(`/mcp/authorize?${query}`, { source })
  assert.equal(authorized.status, 302, authorized.body)
  const id = new URL(authorized.headers.location).searchParams.get('mcp_connect')
  const nonce = randomBytes(32)
  const prepared = await w.internal(`/internal/requests/${id}/prepare`, { method: 'POST', body: { nonce: nonce.toString('base64url') } })
  assert.equal(prepared.status, 200, prepared.body)
  return { id, clientId, verifier, challenge, nonce, source, prepared: JSON.parse(prepared.body) }
}

/**
 * The content consent, step by step as §15.11 orders it, with every piece
 * overridable for the negative cases. Stops after the bundle relay when it is
 * refused, or when `until: 'bundle'`.
 */
export async function connectContent(w, overrides = {}) {
  const request = overrides.request ?? await prepareRequest(w, overrides)
  const { id, prepared } = request
  const service = overrides.service ?? randomUUID()
  const token = overrides.token ?? newApiKey()
  await contentGrants(w, prepared.reader_public_key, { service, token, ...overrides.grants })
  const linkSecret = randomBytes(32).toString('base64url')
  const expiresAt = overrides.expiresAt ?? new Date(Date.now() + 30 * DAY).toISOString()
  const bundle = {
    version: 2, kind: 'content', purpose: 'consent', server_url: ORIGIN, workspace_id: workspace, service_user_id: service,
    device_ids: [vector.device], token, key_mode: 'ephemeral', consent_version: 1, expires_at: overrides.bundleExpiresAt ?? expiresAt,
    timezone: 'America/Sao_Paulo', link_secret: linkSecret, ...overrides.bundle,
  }
  for (const name of overrides.omit ?? []) delete bundle[name]
  const { sealed, sealedBytes } = await sealContent(overrides.sealTo ?? prepared.reader_public_key, bundle, overrides.labels ?? consentLabels(id, prepared.kid))
  const connectionId = overrides.connectionId ?? randomUUID()
  w.go.connections.set(connectionId, { status: 'pending', expires_at: expiresAt, kind: 'content', service_user_id: service })
  const relayed = await w.internal(`/internal/requests/${id}/bundle`, { method: 'POST', body: {
    connection_id: connectionId, tenant_id: workspace, kid: prepared.kid, sealed, expires_at: expiresAt, kind: 'content', ...overrides.relay,
  } })
  const done = { ...request, service, token, linkSecret, bundle, sealed, sealedBytes, connectionId, expiresAt, relayed }
  if (relayed.status !== 204 || overrides.until === 'bundle') return done
  done.signature = proof(linkSecret, { requestID: id, clientID: request.clientId, codeChallenge: request.challenge, sealedBytes })
  done.completed = await w.public('/mcp/authorize/complete', { ...form({ request: id, proof: overrides.proof ?? done.signature }), headers: { 'content-type': 'application/x-www-form-urlencoded', origin: CONSOLE_ORIGIN }, source: request.source })
  if (done.completed.status !== 302) return done
  const code = new URL(done.completed.headers.location).searchParams.get('code')
  const exchanged = await w.public('/mcp/token', { ...form({ grant_type: 'authorization_code', code, client_id: request.clientId, code_verifier: request.verifier, redirect_uri: REDIRECT_URI, resource: RESOURCE }), source: request.source })
  assert.equal(exchanged.status, 200, exchanged.body)
  done.code = code
  done.tokens = JSON.parse(exchanged.body)
  return done
}

/** A tool call over JSON-RPC: the structured result, or the error text. */
export async function callTool(w, token, name, args = {}) {
  const response = await rpc(w, token, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name, arguments: args } })
  if (response.status !== 200) return { status: response.status, body: response.body }
  const value = result(response.body)
  return { status: 200, isError: value.isError === true, data: value.structuredContent, text: value.content?.[0]?.text ?? '' }
}

// ---- Media connections (A1) --------------------------------------------------------

/** A content consent that includes attachments (§16.2), and Go's status saying so. */
export async function connectMedia(w, overrides = {}) {
  const done = await connectContent(w, { ...overrides, bundle: { consent_version: 2, media: true, ...overrides.bundle }, relay: { media: true, ...overrides.relay } })
  w.go.connections.get(done.connectionId).extra = { media: true, media_off: [] }
  return done
}

/** open_attachment over /mcp: the HTTP answer and the JSON-RPC result. */
export async function openAttachment(w, done, args) {
  const response = await rpc(w, done.tokens.access_token, { jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'open_attachment', arguments: { device_id: vector.device, ...args } } })
  assert.equal(response.status, 200, response.body)
  return { response, value: result(response.body) }
}

// ---- Sending (S1) ------------------------------------------------------------------

/** The number's device key, as the creator's browser holds it: the fixture's archive key. */
export const DSK = () => bytes.fromBase64(vector.private_key)

/**
 * The device checks the creator's browser computes (§17.2 rule 3) for
 * `bundle` (the fields the scope reads), with the DSK the grants carry, under
 * the consent's request id (or a renewal's id) and the attested key's id.
 */
export function deviceChecks(bundle, { request, kid, epoch = 1, dsk = DSK(), devices = bundle.device_ids }) {
  return Object.fromEntries(devices.map(device => [device, deviceCheck(dsk, { namespace: vector.tenant, deviceID: device, epoch,
    scope: deviceScope(bundle, { deviceID: device, epoch, request, kid }) })]))
}

/**
 * A content consent with sending (§17.2): version 3, `send: 'draft'` plus
 * `options.send` (send_self, send_groups, media), a device check per number,
 * and Go relaying the same fields. `options.scope` changes only what the
 * checks were computed over (a forged or stale scope), `options.checks`
 * replaces them. Go's row takes the connection's API key and a status that
 * says sending is on.
 */
export async function connectSending(w, options = {}) {
  const request = options.request ?? await prepareRequest(w)
  const service = options.service ?? randomUUID()
  const token = options.token ?? newApiKey()
  const expiresAt = options.expiresAt ?? new Date(Date.now() + 30 * DAY).toISOString()
  const fields = { consent_version: 3, send: 'draft', ...options.send }
  const scoped = { workspace_id: workspace, service_user_id: service, device_ids: [vector.device], expires_at: expiresAt, ...fields, ...options.scope }
  const checks = options.checks ?? deviceChecks(scoped, { request: options.checkRequest ?? request.id, kid: request.prepared.kid, devices: options.bundle?.device_ids ?? [vector.device] })
  const relay = { send: 'draft', ...(fields.send_self ? { send_self: true } : {}), ...(fields.send_groups ? { send_groups: true } : {}), ...(fields.media ? { media: true } : {}), ...options.relay }
  for (const name of Object.keys(relay)) if (relay[name] === undefined) delete relay[name]
  const done = await connectContent(w, { ...options, request, service, token, expiresAt, bundle: { ...fields, device_checks: checks, ...options.bundle }, relay })
  const row = w.go.connections.get(done.connectionId)
  row.api_key = token
  row.extra = { media: fields.media === true, media_off: [], send: 'draft', send_self: fields.send_self === true, send_groups: fields.send_groups === true }
  return done
}

// ---- AI integrations (B1) ---------------------------------------------------------
//
// The console's side of §18.7, written from the contract: an attested AI
// request, grants sealed to its key for a fresh service account, the AI
// bundle with its configuration tags computed from each number's DSK, sealed
// under the AI labels, and Go's relay with `"kind": "ai"`.

export const aiConnectLabels = (requestId, kid) => ({ info: 'wappie-ai-connect/v1', aad: JSON.stringify(['wappie/ai-connect', 1, requestId, kid, RESOURCE]) })
export const aiRenewLabels = (renewalId, connectionId, kid) => ({ info: 'wappie-ai-renew/v1', aad: JSON.stringify(['wappie/ai-renew', 1, renewalId, connectionId, kid, RESOURCE]) })
/** Go's `ai_off` for a row nothing narrows. */
export const aiOff = (change = {}) => ({ functions: [], providers: [], paused: false, monthly_tokens: null, ...change })

/** POST /internal/ai/requests: the attested descriptor of a fresh AI request. */
export async function requestAI(w, { nonce = randomBytes(32) } = {}) {
  const answer = await w.internal('/internal/ai/requests', { method: 'POST', body: { nonce: nonce.toString('base64url') } })
  return { status: answer.status, body: answer.body, descriptor: answer.status === 200 ? JSON.parse(answer.body) : null, nonce }
}

/** `cfg_tags` of `bundle` as the creator's browser computes them (§18.7 step 4), with `dsk` for every number. */
export function aiTags(bundle, { request, kid, epoch = 1, dsk = DSK(), namespace = vector.tenant }) {
  const fields = { ...bundle, keys_sha256: keysSHA256(bundle.keys) }
  return Object.fromEntries(bundle.device_ids.map(device => [device, aiConfigTag(dsk, { namespace, deviceID: device, epoch, config: aiConfigScope(fields, { deviceID: device, epoch, request, kid }) })]))
}

/** The functions, keys, features and budget of a bundle for `functions` ({feature: [provider, model]}) on the fixture's number. */
export function aiScope(functions, { lang, requesters = 'self', devices = [vector.device], keys = {}, tokens = 5_000_000, items = 100 } = {}) {
  const entries = Object.fromEntries(Object.entries(functions).map(([feature, [provider, model]]) => [feature, { provider, model }]))
  const providers = [...new Set(Object.values(entries).map(entry => entry.provider))]
  return {
    keys: Object.fromEntries(providers.map(provider => [provider, keys[provider] ?? STUB_KEYS[provider]])),
    functions: entries,
    features: Object.fromEntries(devices.map(device => [device, Object.fromEntries(Object.keys(entries).map(feature => [feature, { mode: 'request', ...(lang ? { lang } : {}), requesters }]))])),
    budget: { monthly_tokens: tokens, request_items_per_day: items },
  }
}

/**
 * An AI consent as §18.7 orders it, every piece overridable: `scope` (aiScope),
 * `bundle` fields, `tags` (in place of the browser's), `tagDSK` (the DSK the
 * tags are made with), `grants` (contentGrants' options), `relay` fields.
 * Go's row takes the service's API key and a status with `ai_off`.
 */
export async function connectAI(w, options = {}) {
  const request = options.request ?? (await requestAI(w)).descriptor
  const service = options.service ?? randomUUID()
  const token = options.token ?? newApiKey()
  const expiresAt = options.expiresAt ?? new Date(Date.now() + 30 * DAY).toISOString()
  await contentGrants(w, request.reader_public_key, { service, token, ...options.grants })
  const scope = options.scope ?? aiScope({ audio: ['google', 'gemini-synthetic-flash'] })
  const bundle = {
    version: 3, kind: 'ai', purpose: 'consent', server_url: ORIGIN, workspace_id: workspace, service_user_id: service, device_ids: [vector.device],
    token, key_mode: 'ephemeral', consent_version: 1, expires_at: expiresAt, ...scope, ...options.bundle,
  }
  bundle.cfg_tags = options.tags ?? aiTags(bundle, { request: request.request_id, kid: request.kid, ...(options.tagDSK ? { dsk: options.tagDSK } : {}) })
  const { sealed } = await sealContent(options.sealTo ?? request.reader_public_key, bundle, options.labels ?? aiConnectLabels(request.request_id, request.kid))
  const connectionId = options.connectionId ?? randomUUID()
  w.go.connections.set(connectionId, { status: 'pending', expires_at: expiresAt, kind: 'ai', service_user_id: service, api_key: token, extra: { media: false, media_off: [], ai_off: aiOff() } })
  const relayed = await w.internal(`/internal/ai/requests/${request.request_id}/bundle`, { method: 'POST', body: {
    connection_id: connectionId, tenant_id: workspace, kid: request.kid, sealed, expires_at: expiresAt, kind: 'ai', ...options.relay,
  } })
  return { request, service, token, bundle, sealed, connectionId, expiresAt, relayed }
}
