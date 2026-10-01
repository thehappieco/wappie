// Reader 0.6.0's admission of any MCP client (docs/mcp-enclave.md §19.4 to
// §19.12), in the shared modules: which client_id is a CIMD identifier (the
// shared vectors), what a fetched document keeps, how a request is
// classified and never fetched when a tested entry pins it, the fetch
// budgets, the loosened request checks, the network check at completion,
// descriptor v2, and a metadata consent sealed as link bundle v2.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { CLIENT_LIMITS, OWN_DOMAINS, SHARED_HOSTS, TESTED_CLIENTS, UNKNOWN_LIVE_MAX } from '../enclave/constants.mjs'
import { cacheTTL, CIMD_FETCHES_PER_DOMAIN, CIMD_FETCHES_PER_MINUTE, cimdIdentity, readDocument } from '../cimd.mjs'
import {
  claimedName, classifyRedirect, dcrEntryFor, highlyRestrictive, makeRoomRegistered, makeRoomUnknown, MAX_CLIENTS_PER_HOST, pins, redirectAllowed, testedFor,
  UNKNOWN_CLIENTS_MAX, UNKNOWN_CLIENTS_PER_DOMAIN,
} from '../clients.mjs'
import { PENDING_PER_CLIENT, resourceOf, scopeAcceptable } from '../as.mjs'
import { sameNetwork } from '../limits.mjs'
import { createPSL, loadPSL, PSL_FILE } from '../psl.mjs'
import { attestationUserDataV2, descriptorSHA256, userDataPreimageV2 } from '../attestation.mjs'
import { CONTENT_REFRESH_IDLE_MS, idleFor, REFRESH_IDLE_MS } from '../tokens.mjs'
import { authorizeURL, DAY, exchange, harness, pkce, proof, register, rpc, sealBundle, vector } from './harness.mjs'

/** The snapshot's SHA-256, pinned here and in Go's netguard tests: the copies cannot drift (§19.5). */
export const PSL_SHA256 = 'c525730712d4db475211ced98ddac44b06e4b288e50d95b69c68adb1e4e83e80'
const psl = loadPSL()
const rules = { psl, own: OWN_DOMAINS, shared: SHARED_HOSTS }
const vectors = JSON.parse(readFileSync(new URL('./vectors/cimd-ids.json', import.meta.url), 'utf8'))

/** A fetcher over a table of documents by URL, recording every fetch; nothing leaves the process. */
function documents() {
  const docs = new Map(), calls = []
  return {
    docs, calls,
    async fetch({ host, path }) {
      const url = `https://${host}${path}`
      calls.push(url)
      const entry = docs.get(url)
      if (!entry) return { ok: false, code: 'status' }
      if (entry.hold) await entry.hold
      if (entry.fail) return entry.fail
      return { ok: true, body: Buffer.from(typeof entry.body === 'string' ? entry.body : JSON.stringify(entry.body)), cacheControl: entry.cacheControl }
    },
  }
}
const anyPolicy = (fetcher, extra = {}) => ({ mode: 'any', tested: TESTED_CLIENTS, limits: CLIENT_LIMITS, unknownLiveMax: UNKNOWN_LIVE_MAX, shared: SHARED_HOSTS,
  own: OWN_DOMAINS, psl, fetcher, refusalFloorMs: 0, ...extra })
async function anyHarness(t, extra) {
  const fetcher = documents()
  const h = await harness(t, { clientPolicy: anyPolicy(fetcher, extra) })
  h.fetcher = fetcher
  return h
}
const from = address => ({ headers: { 'x-forwarded-for': address } })
let addresses = 0
/** A fresh address per call, so the per-address budgets of one test never meet another's. */
const fresh = () => from(`198.51.${100 + (++addresses >> 8)}.${addresses & 255}`)
const CLAUDE = 'https://claude.ai/oauth/mcp-oauth-client-metadata'
const CODE = 'https://claude.ai/oauth/claude-code-client-metadata'
const CODEX = 'https://chatgpt.com/oauth/codex/client.json'
const AGENT = 'https://agent.example.com/oauth/client.json'
const AGENT_REDIRECT = 'https://agent.example.com/oauth/callback'

/** An authorize request; the descriptor Go would read, when it got as far as the console. */
async function start(h, { clientId, redirectUri, address = fresh(), ...rest }) {
  const { verifier, challenge } = pkce()
  const url = authorizeURL(h, { clientId, redirectUri, challenge, ...rest })
  const response = await h.request(url.pathname + url.search, address)
  const result = { response, verifier, challenge, address }
  if (response.status !== 302 || !response.location.startsWith(h.consoleOrigin)) return result
  result.id = new URL(response.location).searchParams.get('mcp_connect')
  result.descriptor = (await h.internal(`/internal/requests/${result.id}`)).json()
  return result
}

/** The console and Go after an authorize: link bundle v2 sealed and relayed, then the proof posted. */
async function consentV2(h, started, { bundle = {}, relay = {}, address = started.address, expiresAt } = {}) {
  const { descriptor } = started
  const linkSecret = randomBytes(32).toString('base64url')
  const history = descriptor.trust === 'unknown' ? descriptor.limits.history_days.default : null
  const sealedBundle = { version: 2, kind: 'metadata', server_url: new URL(descriptor.resource).origin, workspace_id: h.workspace, device_ids: [vector.device], token: h.apiKey,
    allow_plaintext: false, timezone: 'UTC', link_secret: linkSecret, client_id: descriptor.client_id, trust: descriptor.trust, started_ack: true, history_days: history, ...bundle }
  for (const [name, value] of Object.entries(bundle)) if (value === undefined) delete sealedBundle[name]
  const { sealed, sealedBytes } = await sealBundle(descriptor, sealedBundle)
  const connectionId = randomUUID()
  const expires = expiresAt ?? new Date(h.clock.now() + 30 * DAY).toISOString()
  h.go.connections.set(connectionId, { status: 'pending', expires_at: expires })
  const relayed = await h.internal(`/internal/requests/${started.id}/bundle`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
    kind: 'metadata', connection_id: connectionId, tenant_id: h.workspace, kid: descriptor.kid, sealed, expires_at: expires,
    trust: descriptor.trust, client_local: descriptor.client_local, history_days: history, ...relay,
  }) })
  const result = { relayed, connectionId, linkSecret }
  if (relayed.status !== 204) return result
  const signature = proof(linkSecret, { requestID: started.id, clientID: descriptor.client_id, codeChallenge: descriptor.code_challenge, sealedBytes })
  result.completed = await h.request('/mcp/authorize/complete', { method: 'POST', body: new URLSearchParams({ request: started.id, proof: signature }).toString(),
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: h.consoleOrigin, ...address.headers } })
  return result
}

test('the CIMD-id vectors (§19.5), and the Public Suffix List snapshot pinned by its SHA-256', () => {
  assert.equal(createHash('sha256').update(readFileSync(PSL_FILE)).digest('hex'), PSL_SHA256)
  assert.ok(vectors.length > 150)
  const reasons = new Set()
  for (const vector of vectors) {
    const got = cimdIdentity(vector.id, rules)
    if (vector.ok) assert.deepEqual({ ok: got.ok, host: got.host, registrable: got.registrable, shared_suffix: got.shared_suffix },
      { ok: true, host: vector.host, registrable: vector.registrable, shared_suffix: vector.shared_suffix }, vector.id)
    else { assert.deepEqual(got, { ok: false, reason: vector.reason }, vector.id); reasons.add(vector.reason) }
  }
  assert.deepEqual([...reasons].sort(), ['host_chars', 'host_labels', 'ip_literal', 'own_domain', 'path_chars', 'path_root', 'public_suffix', 'shape', 'shared_host', 'special_use'])
  // Every SHARED_HOSTS entry and a subdomain of it, and every special-use word.
  for (const host of SHARED_HOSTS) assert.ok(vectors.some(item => item.id === `https://tenant.${host}/x` && item.reason === 'shared_host'), host)
})

test('user_data v2 (§19.13): the contract vectors and a whole descriptor of every kind, its attestation member left out', () => {
  const v2 = JSON.parse(readFileSync(new URL('./vectors/attest-v2.json', import.meta.url), 'utf8'))
  for (const item of v2.contract) assert.equal(attestationUserDataV2(item.fields, item.descriptor_sha256).toString('hex'), item.user_data, item.name)
  assert.deepEqual([...new Set(v2.descriptors.map(item => item.kind))].sort(), ['ai', 'ai_renewal', 'connect', 'live_list', 'renewal', 'token'])
  for (const item of v2.descriptors) {
    const { attestation: _attestation, ...bare } = item.descriptor
    assert.equal(descriptorSHA256(item.descriptor), item.descriptor_sha256, item.name)
    assert.equal(descriptorSHA256(bare), item.descriptor_sha256, item.name)
    assert.equal(createHash('sha256').update(item.jcs).digest('hex'), item.descriptor_sha256, item.name)
    assert.equal(attestationUserDataV2(item.fields, item.descriptor_sha256).toString('hex'), item.user_data, item.name)
  }
  const fields = v2.contract[0].fields
  assert.equal(userDataPreimageV2(fields, '').toString().split('\0').length, 7)
  for (const bad of ['C'.repeat(64), 'c'.repeat(65), null]) assert.throws(() => userDataPreimageV2(fields, bad), /attest_bad_input/)
  assert.throws(() => userDataPreimageV2({ ...fields, resource: 'a\0b' }, ''), /attest_bad_input/)
  assert.throws(() => descriptorSHA256({ kind: 'connect', missing: undefined }), /attest_bad_input/)
  assert.throws(() => descriptorSHA256([]), /attest_bad_input/)
})

test('the Public Suffix List: the longest rule, wildcards, exceptions and the private section', () => {
  const list = createPSL({ format: 'wappie-psl/v1', icann: ['uk', 'co.uk', '*.ck', '!www.ck', 'jp', '*.kobe.jp', '!city.kobe.jp'], private: ['github.io', 's3.amazonaws.com'] })
  assert.deepEqual(list.registrable('a.b.example.co.uk'), { registrable: 'example.co.uk', shared_suffix: null })
  assert.equal(list.registrable('co.uk'), null)
  assert.equal(list.registrable('foo.ck'), null)
  assert.deepEqual(list.registrable('www.ck'), { registrable: 'www.ck', shared_suffix: null })
  assert.deepEqual(list.registrable('city.kobe.jp'), { registrable: 'city.kobe.jp', shared_suffix: null })
  assert.deepEqual(list.registrable('a.b.kobe.jp'), { registrable: 'a.b.kobe.jp', shared_suffix: null })
  assert.deepEqual(list.registrable('team.github.io'), { registrable: 'team.github.io', shared_suffix: 'github.io' })
  assert.deepEqual(list.registrable('x.bucket.s3.amazonaws.com'), { registrable: 'bucket.s3.amazonaws.com', shared_suffix: 's3.amazonaws.com' })
  // The default rule: an unlisted top-level label is the suffix.
  assert.deepEqual(list.registrable('example.unlisted'), { registrable: 'example.unlisted', shared_suffix: null })
  assert.deepEqual(psl.registrable('claude.ai.example.com'), { registrable: 'example.com', shared_suffix: null })
})

test('client documents (§19.6): same-host https and loopback kept, every other entry ignored, refusals by code', () => {
  const identity = cimdIdentity(AGENT, rules)
  const read = body => readDocument(Buffer.from(JSON.stringify(body)), AGENT, identity)
  const doc = (redirect_uris, extra = {}) => ({ client_id: AGENT, redirect_uris, ...extra })
  assert.deepEqual(read(doc([AGENT_REDIRECT])), { ok: true, redirect_uris: [AGENT_REDIRECT], ignored_uris: 0, claimed_name: null, name_dropped: false })
  const mixed = read(doc([AGENT_REDIRECT, 'http://127.0.0.1/callback', 'http://localhost:33418/cb', 'http://[::1]:8080/cb', 'https://agent.example.com/cb?x=1']))
  assert.equal(mixed.redirect_uris.length, 5, 'https and loopback mix, loopback with or without a port, an https query is kept')
  // Claude's document plus a claude.com callback, Codex's plus an https entry on another host, a custom scheme: kept, those entries ignored.
  const claude = cimdIdentity(CLAUDE, rules)
  const kept = readDocument(Buffer.from(JSON.stringify({ client_id: CLAUDE, redirect_uris: ['https://claude.ai/api/mcp/auth_callback', 'https://claude.com/api/mcp/auth_callback'] })), CLAUDE, claude)
  assert.deepEqual([kept.redirect_uris, kept.ignored_uris], [['https://claude.ai/api/mcp/auth_callback'], 1])
  const codex = readDocument(Buffer.from(JSON.stringify({ client_id: CODEX, redirect_uris: ['http://127.0.0.1/callback', 'https://openai.com/cb'] })), CODEX, cimdIdentity(CODEX, rules))
  assert.deepEqual([codex.redirect_uris, codex.ignored_uris], [['http://127.0.0.1/callback'], 1])
  const scheme = read(doc(['cursor://anysphere.cursor-retrieval/oauth/callback', AGENT_REDIRECT, 'https://agent.example.com:8443/cb', 'https://user@agent.example.com/cb',
    'https://agent.example.com/cb#f', 'https://Agent.example.com/cb', 'http://agent.example.com/cb', 'http://127.0.0.1/cb?x=1', 'http://192.168.1.2/cb', 'not a url']))
  assert.deepEqual([scheme.redirect_uris, scheme.ignored_uris], [[AGENT_REDIRECT], 9])
  // Refusals.
  assert.deepEqual(read(doc(['cursor://x/cb'])), { ok: false, code: 'no_usable_redirect' })
  assert.deepEqual(read(doc([])), { ok: false, code: 'no_usable_redirect' })
  assert.deepEqual(read(doc(Array(11).fill(AGENT_REDIRECT))), { ok: false, code: 'no_usable_redirect' })
  assert.deepEqual(read(doc([AGENT_REDIRECT, 7])), { ok: false, code: 'no_usable_redirect' })
  assert.deepEqual(read({ ...doc([AGENT_REDIRECT]), client_id: 'https://agent.example.com/oauth/other.json' }), { ok: false, code: 'client_id_mismatch' })
  assert.deepEqual(readDocument(Buffer.from('{"client_id":'), AGENT, identity), { ok: false, code: 'json' })
  assert.deepEqual(readDocument(Buffer.from('[]'), AGENT, identity), { ok: false, code: 'json' })
  // Names: dropped, never fatal.
  for (const name of ['Cl‮aude', 'Cl​aude', 'Claude  Code', 'Сlaude', 'Agent \u{1F469}‍\u{1F4BB}', ' Claude', 'Claude ', '', 'x'.repeat(101), 'A﻿', 'A\u{E0041}', 7, null]) {
    const result = read(doc([AGENT_REDIRECT], { client_name: name }))
    assert.deepEqual([result.ok, result.claimed_name, result.name_dropped], [true, null, true], JSON.stringify(name))
  }
  for (const name of ['Claude', 'VS Code', 'Zed', 'goose', 'Agente Ação', '日本語のエージェント Agent', '한국어 Agent 漢字', 'Ελληνικά', 'Agent \u{1F600}', 'x'.repeat(100)]) {
    assert.deepEqual(claimedName(name), { claimed_name: name, name_dropped: false }, name)
  }
  assert.equal(claimedName('Café').claimed_name, 'Café', 'normalized to NFC')
  assert.equal(highlyRestrictive('Latin Ελληνικά'), false)
  assert.deepEqual(read(doc([AGENT_REDIRECT], { logo_uri: 'https://x/logo.png', jwks_uri: 'https://x', token_endpoint_auth_method: 'private_key_jwt' })).ok, true)
})

test('matching (§19.6): https exactly, loopback by hostname and path with any port, no 127.0.0.1/localhost equivalence', () => {
  const record = { client_id: AGENT, client_host: 'agent.example.com', redirect_uris: [AGENT_REDIRECT, 'http://127.0.0.1/callback', 'http://localhost:8000/cb'] }
  assert.equal(redirectAllowed(record, AGENT_REDIRECT), true)
  assert.equal(redirectAllowed(record, AGENT_REDIRECT + '/'), false)
  assert.equal(redirectAllowed(record, AGENT_REDIRECT + '?x=1'), false)
  for (const port of ['', ':1', ':1455', ':65535']) assert.equal(redirectAllowed(record, `http://127.0.0.1${port}/callback`), true, port)
  assert.equal(redirectAllowed(record, 'http://localhost:4444/callback'), false, 'no equivalence')
  assert.equal(redirectAllowed(record, 'http://localhost:4444/cb'), true)
  assert.equal(redirectAllowed(record, 'http://127.0.0.1:4444/cb'), false)
  assert.equal(redirectAllowed(record, 'http://127.0.0.1:4444/callback/x'), false)
  assert.equal(classifyRedirect('http://[::1]:9/cb', 'x.com'), 'loopback')
  // The tested entries pin their redirects exactly, or by hostname and path for loopback.
  const codex = TESTED_CLIENTS.find(entry => entry.id === 'codex')
  assert.equal(pins(codex, 'http://127.0.0.1:1455/callback'), true)
  assert.equal(pins(codex, 'http://localhost:1455/callback'), true)
  assert.equal(pins(codex, 'http://[::1]:1455/callback'), false)
  assert.equal(pins(codex, 'http://127.0.0.1:1455/auth/callback'), false)
})

test('tested entries (§19.4): exact before patterns, the same {cb} in the id and the redirect, DCR pinned only', () => {
  assert.equal(testedFor(TESTED_CLIENTS, CODEX, 'http://127.0.0.1:1/callback').entry.id, 'codex', 'an exact entry wins over the callback-id pattern')
  const cb = testedFor(TESTED_CLIENTS, 'https://chatgpt.com/oauth/abc_1/client.json', 'https://chatgpt.com/connector/oauth/abc_1')
  assert.deepEqual([cb.entry.id, cb.cb, cb.pinned], ['chatgpt_cb', 'abc_1', true])
  assert.equal(testedFor(TESTED_CLIENTS, 'https://chatgpt.com/oauth/abc_1/client.json', 'https://chatgpt.com/connector/oauth/xyz').pinned, false)
  assert.equal(testedFor(TESTED_CLIENTS, 'https://chatgpt.com/oauth/a.b/client.json', 'https://chatgpt.com/connector/oauth/a.b'), null, 'the callback id\'s pattern')
  assert.equal(testedFor(TESTED_CLIENTS, 'https://chatgpt.com/oauth//client.json', 'https://chatgpt.com/connector/oauth/'), null)
  assert.equal(testedFor(TESTED_CLIENTS, 'https://chatgpt.com/oauth/x/client.jsonx', 'https://chatgpt.com/connector/oauth/x'), null)
  assert.equal(testedFor(TESTED_CLIENTS, AGENT, AGENT_REDIRECT), null)
  assert.equal(dcrEntryFor(TESTED_CLIENTS, ['https://chatgpt.com/connector/oauth/abc_1']).id, 'chatgpt_dcr')
  assert.equal(dcrEntryFor(TESTED_CLIENTS, ['https://claude.ai/api/mcp/auth_callback', 'https://claude.com/api/mcp/auth_callback']).id, 'claude_dcr')
  assert.equal(dcrEntryFor(TESTED_CLIENTS, ['https://claude.ai/api/mcp/auth_callback', 'https://chatgpt.com/connector_platform_oauth_redirect']), null, 'one entry pins them all')
  assert.equal(dcrEntryFor(TESTED_CLIENTS, ['https://claude.ai/other']), null)
  assert.equal(dcrEntryFor(TESTED_CLIENTS, ['http://127.0.0.1/callback']), null, 'DCR never gets loopback')
})

test('the loosened request checks (§19.11) and the network comparison (§19.12)', () => {
  const resource = 'https://mcp.wappie.thehappie.co/mcp'
  for (const value of [null, resource, 'HTTPS://MCP.WAPPIE.THEHAPPIE.CO/mcp', resource + '/', 'https://Mcp.Wappie.Thehappie.Co/mcp/']) assert.equal(resourceOf(value, resource), resource, value)
  for (const value of ['https://mcp.wappie.thehappie.co/MCP', resource + '//', 'https://mcp.wappie.thehappie.co', 'https://evil.example/mcp', '']) assert.notEqual(resourceOf(value, resource), resource, value)
  for (const value of [null, 'wappie:read', 'wappie:read offline_access', 'openid profile email', 'a b c d e f g h i j']) assert.equal(scopeAcceptable(value), true, value)
  for (const value of ['', ' ', 'wappie:read  openid', 'a b c d e f g h i j k', 'x'.repeat(65), 'a"b', 'a\\b']) assert.equal(scopeAcceptable(value), false, value)
  assert.equal(sameNetwork('203.0.113.10', '203.0.113.250'), true)
  assert.equal(sameNetwork('203.0.113.10', '203.0.114.10'), false)
  assert.equal(sameNetwork('2001:db8:1:ab::/64', '2001:db8:1:cd::/64'), true, 'the same /56')
  assert.equal(sameNetwork('2001:db8:1:ab::/64', '2001:db8:1:1ab::/64'), false, 'another /56')
  assert.equal(sameNetwork('203.0.113.10', '2001:db8:1:ab::/64'), false, 'another family')
  assert.equal(sameNetwork('unknown', 'unknown'), false)
})

test('cache lifetimes (§19.10): max-age within five minutes and a day, no-store and no-cache short, a day by default', () => {
  assert.equal(cacheTTL(undefined), 86_400_000)
  assert.equal(cacheTTL('public'), 86_400_000)
  assert.equal(cacheTTL('max-age=3600'), 3_600_000)
  assert.equal(cacheTTL('public, max-age=60'), 300_000)
  assert.equal(cacheTTL('max-age=31536000'), 86_400_000)
  assert.equal(cacheTTL('max-age="600"'), 600_000)
  assert.equal(cacheTTL('no-store'), 300_000)
  assert.equal(cacheTTL('max-age=86400, no-cache'), 300_000)
  assert.equal(cacheTTL('max-age=abc'), 86_400_000)
})

test('a tested client asked with a pinned redirect is tested and never fetched; each kind of tested entry', async t => {
  const h = await anyHarness(t)
  const cases = [
    [CLAUDE, 'https://claude.ai/api/mcp/auth_callback', 'claude', 'Claude', false, 'claude.ai'],
    [CLAUDE, 'https://claude.com/api/mcp/auth_callback', 'claude', 'Claude', false, 'claude.ai'],
    ['https://chatgpt.com/oauth/client.json', 'https://chatgpt.com/connector_platform_oauth_redirect', 'chatgpt', 'ChatGPT', false, 'chatgpt.com'],
    ['https://chatgpt.com/oauth/Ab9_-x/client.json', 'https://chatgpt.com/connector/oauth/Ab9_-x', 'chatgpt_cb', 'ChatGPT', false, 'chatgpt.com'],
    [CODEX, 'http://127.0.0.1:1455/callback', 'codex', 'Codex', true, 'chatgpt.com'],
    [CODEX, 'http://localhost:9/callback', 'codex', 'Codex', true, 'chatgpt.com'],
    [CODE, 'http://localhost:54545/callback', 'claude_code', 'Claude Code', true, 'claude.ai'],
  ]
  for (const [clientId, redirectUri, testedId, name, local, host] of cases) {
    const started = await start(h, { clientId, redirectUri })
    assert.equal(started.response.status, 302, `${clientId} ${redirectUri}: ${started.response.body}`)
    const d = started.descriptor
    assert.deepEqual([d.descriptor_version, d.kind, d.trust, d.tested_id, d.client_name, d.client_local, d.client_host, d.registrable, d.claimed_name, d.drift, d.client_kind],
      [2, 'connect', 'tested', testedId, name, local, host, host, null, false, 'cimd'], clientId)
    assert.equal(d.redirect_uri, redirectUri)
    assert.equal(d.limits_tier, local ? 'local_tested' : 'web_tested')
    assert.deepEqual(d.limits, CLIENT_LIMITS[d.limits_tier])
  }
  assert.deepEqual(h.fetcher.calls, [], 'no document was fetched')
  // The authorize lines say what kind of client, never which.
  const lines = h.logs.map(line => JSON.parse(line)).filter(entry => entry.route === 'GET /mcp/authorize')
  assert.equal(lines.length, cases.length)
  for (const entry of lines) assert.deepEqual([entry.unknown, entry.cimd, entry.drift, entry.resource_default], [false, true, false, false])
  assert.deepEqual(lines.map(entry => entry.local), cases.map(item => item[4]))
  for (const line of h.logs) for (const host of ['claude.ai', 'chatgpt.com', 'claude.com']) assert.equal(line.includes(host), false, line)
})

test('a tested id with another redirect is fetched: unknown with drift when the document lists it, refused otherwise', async t => {
  const h = await anyHarness(t)
  h.fetcher.docs.set(CLAUDE, { body: { client_id: CLAUDE, client_name: 'Claude', redirect_uris: ['https://claude.ai/api/mcp/auth_callback', 'https://claude.ai/new_callback'] } })
  const drifted = await start(h, { clientId: CLAUDE, redirectUri: 'https://claude.ai/new_callback' })
  assert.equal(drifted.response.status, 302, drifted.response.body)
  const d = drifted.descriptor
  assert.deepEqual([d.trust, d.drift, d.tested_id, d.client_name, d.claimed_name, d.limits_tier], ['unknown', true, null, 'claude.ai', 'Claude', 'unknown'])
  assert.deepEqual(h.fetcher.calls, [CLAUDE])
  assert.equal(h.reader.counters.tested_drift, 1)
  const refused = await start(h, { clientId: CLAUDE, redirectUri: 'https://claude.ai/not_listed' })
  assert.equal(refused.response.status, 400)
  assert.match(refused.response.body, /invalid_redirect_uri/)
  assert.equal(h.fetcher.calls.length, 1, 'served from the cache')
  // A callback-id pattern with a mismatched {cb}: the document decides, and this one does not list it.
  const pattern = 'https://chatgpt.com/oauth/abc/client.json'
  h.fetcher.docs.set(pattern, { body: { client_id: pattern, redirect_uris: ['https://chatgpt.com/connector/oauth/abc'] } })
  const mismatched = await start(h, { clientId: pattern, redirectUri: 'https://chatgpt.com/connector/oauth/xyz' })
  assert.equal(mismatched.response.status, 400)
  assert.equal(h.logs.map(line => JSON.parse(line)).filter(entry => entry.route === 'GET /mcp/authorize' && entry.drift === true).length, 1)
})

test('DCR (§19.8): pinned redirects only, tested with the entry\'s id; the ChatGPT callback forms share a tier', async t => {
  const h = await anyHarness(t)
  for (const uris of [['https://claude.ai/other'], ['https://claude.ai/api/mcp/auth_callback', 'https://claude.ai/x'], ['http://127.0.0.1/callback'],
    ['https://claude.ai/api/mcp/auth_callback', 'https://chatgpt.com/connector_platform_oauth_redirect'], ['https://agent.example.com/cb']]) {
    h.clock.advance(13_000)
    const refused = await register(h, { redirect_uris: uris })
    assert.equal(refused.status, 400, JSON.stringify(uris))
    assert.equal(refused.json().error, 'invalid_redirect_uri')
  }
  h.clock.advance(13_000)
  const claude = await register(h, { client_name: 'Сlaude', redirect_uris: ['https://claude.ai/api/mcp/auth_callback', 'https://claude.com/api/mcp/auth_callback'] })
  assert.equal(claude.status, 201, claude.body)
  assert.equal(claude.json().client_name, undefined, 'a dropped name is not echoed')
  const started = await start(h, { clientId: claude.json().client_id, redirectUri: 'https://claude.com/api/mcp/auth_callback' })
  const d = started.descriptor
  assert.deepEqual([d.client_kind, d.trust, d.tested_id, d.client_name, d.claimed_name, d.name_dropped, d.client_host, d.registrable, d.limits_tier],
    ['dcr', 'tested', 'claude_dcr', 'Claude', null, true, 'claude.com', 'claude.com', 'web_tested'])
  h.clock.advance(13_000)
  const chatgpt = await register(h, { client_name: 'ChatGPT', redirect_uris: ['https://chatgpt.com/connector/oauth/cb_1'] })
  assert.equal(chatgpt.status, 201)
  const viaDCR = await start(h, { clientId: chatgpt.json().client_id, redirectUri: 'https://chatgpt.com/connector/oauth/cb_1' })
  const viaCIMD = await start(h, { clientId: 'https://chatgpt.com/oauth/cb_1/client.json', redirectUri: 'https://chatgpt.com/connector/oauth/cb_1' })
  assert.deepEqual([viaDCR.descriptor.trust, viaDCR.descriptor.limits_tier, viaDCR.descriptor.claimed_name], ['tested', 'web_tested', 'ChatGPT'])
  assert.deepEqual([viaCIMD.descriptor.trust, viaCIMD.descriptor.limits_tier], ['tested', 'web_tested'])
  // A registered client asking for a redirect it did not register is refused.
  const other = await start(h, { clientId: chatgpt.json().client_id, redirectUri: 'https://chatgpt.com/connector/oauth/cb_2' })
  assert.equal(other.response.status, 400)
  assert.deepEqual(h.fetcher.calls, [])
  // A 0.5.0 record that registered any path on an allowed host is served only for a pinned redirect.
  h.reader.state.clients.set('legacy-dcr-record-00000', { client_id: 'legacy-dcr-record-00000', source: 'dcr', client_name: 'Claude', redirect_host: 'claude.ai',
    redirect_uris: ['https://claude.ai/open-redirect', 'https://claude.ai/api/mcp/auth_callback'], grant_types: ['authorization_code'], created_at: h.clock.now(), last_used_at: h.clock.now() })
  assert.equal((await start(h, { clientId: 'legacy-dcr-record-00000', redirectUri: 'https://claude.ai/open-redirect' })).response.status, 400)
  assert.equal((await start(h, { clientId: 'legacy-dcr-record-00000', redirectUri: 'https://claude.ai/api/mcp/auth_callback' })).descriptor.trust, 'tested')
})

test('an unknown client: fetched, cached by Cache-Control, the display name its host, and its loopback requests local', async t => {
  const h = await anyHarness(t)
  h.fetcher.docs.set(AGENT, { body: { client_id: AGENT, client_name: 'Example Agent', redirect_uris: [AGENT_REDIRECT, 'http://127.0.0.1/callback', 'cursor://x'] }, cacheControl: 'max-age=600' })
  const web = await start(h, { clientId: AGENT, redirectUri: AGENT_REDIRECT })
  assert.equal(web.response.status, 302, web.response.body)
  assert.deepEqual(Object.keys(web.descriptor).sort(), ['claimed_name', 'client_host', 'client_id', 'client_kind', 'client_local', 'client_name', 'code_challenge', 'descriptor_version', 'drift',
    'expires_at', 'kid', 'kind', 'limits', 'limits_tier', 'name_dropped', 'reader_public_key', 'redirect_host', 'redirect_local', 'redirect_uri', 'registrable', 'request_id', 'resource',
    'shared_suffix', 'tested_id', 'trust'])
  const d = web.descriptor
  assert.deepEqual([d.client_kind, d.client_host, d.registrable, d.shared_suffix, d.client_local, d.client_name, d.claimed_name, d.trust, d.tested_id, d.redirect_host, d.redirect_local],
    ['cimd', 'agent.example.com', 'example.com', null, false, 'agent.example.com', 'Example Agent', 'unknown', null, 'agent.example.com', false])
  assert.deepEqual(d.limits, CLIENT_LIMITS.unknown)
  const local = await start(h, { clientId: AGENT, redirectUri: 'http://127.0.0.1:49152/callback' })
  assert.deepEqual([local.descriptor.client_local, local.descriptor.redirect_local, local.descriptor.limits_tier, local.descriptor.redirect_uri],
    [true, true, 'unknown', 'http://127.0.0.1:49152/callback'])
  assert.equal(h.fetcher.calls.length, 1)
  const record = h.reader.state.clients.get(AGENT)
  assert.deepEqual([record.ignored_uris, record.cimd_ttl_ms, record.registrable], [1, 600_000, 'example.com'])
  assert.equal((await start(h, { clientId: AGENT, redirectUri: 'cursor://x' })).response.status, 400, 'an ignored entry is never asked for')
  h.clock.advance(601_000)
  await start(h, { clientId: AGENT, redirectUri: AGENT_REDIRECT })
  assert.equal(h.fetcher.calls.length, 2, 'refetched after its lifetime')
  const event = h.logs.map(line => JSON.parse(line)).find(entry => entry.event === 'client_resolved' && entry.unknown)
  assert.deepEqual([event.local, event.cimd, event.drift, event.name_dropped, event.ignored_uris], [false, true, false, false, 1])
  for (const line of h.logs) assert.equal(/example\.com|Example Agent/.test(line), false, line)
  // A shared host's tenant: admitted, its suffix named.
  const pages = 'https://team.github.io/client.json'
  h.fetcher.docs.set(pages, { body: { client_id: pages, redirect_uris: ['https://team.github.io/callback.html'] } })
  const shared = await start(h, { clientId: pages, redirectUri: 'https://team.github.io/callback.html' })
  assert.deepEqual([shared.descriptor.registrable, shared.descriptor.shared_suffix], ['team.github.io', 'github.io'])
})

test('refusals (§19.6 step 5): one static invalid_client page for every reason, never sooner than a second, remembered for a minute', async t => {
  const h = await anyHarness(t, { refusalFloorMs: undefined })
  h.fetcher.docs.set(AGENT, { fail: { ok: false, code: 'tls_failed', network: true } })
  const bodies = new Set()
  for (const clientId of ['https://127.0.0.1/x', 'https://thehappie.co/client.json', 'https://github.io/x', 'https://raw.githubusercontent.com/a/b', AGENT,
    'https://missing.example.org/oauth/client.json', 'https://claude.ai/', 'not-a-client']) {
    const begun = performance.now()
    const refused = await start(h, { clientId, redirectUri: AGENT_REDIRECT })
    assert.ok(performance.now() - begun >= 990, `${clientId} answered after ${performance.now() - begun} ms`)
    assert.equal(refused.response.status, 400, clientId)
    bodies.add(refused.response.body)
  }
  assert.equal(bodies.size, 1)
  assert.match([...bodies][0], /invalid_client/)
  // Both the client_id and, after a network failure, its registrable domain are remembered for a minute.
  const fetched = h.fetcher.calls.length
  h.fetcher.docs.set('https://other.example.com/client.json', { body: { client_id: 'https://other.example.com/client.json', redirect_uris: ['https://other.example.com/cb'] } })
  await start(h, { clientId: AGENT, redirectUri: AGENT_REDIRECT })
  await start(h, { clientId: 'https://other.example.com/client.json', redirectUri: 'https://other.example.com/cb' })
  assert.equal(h.fetcher.calls.length, fetched)
  h.clock.advance(61_000)
  const later = await start(h, { clientId: 'https://other.example.com/client.json', redirectUri: 'https://other.example.com/cb' })
  assert.equal(later.response.status, 302)
  assert.equal(h.reader.counters.cimd_refusals, 2)
  const fetches = h.logs.map(line => JSON.parse(line)).filter(entry => entry.event === 'cimd_fetch')
  assert.deepEqual(fetches.map(entry => entry.code), ['tls_failed', 'status', 'ok'])
  for (const entry of fetches) assert.deepEqual(Object.keys(entry).sort(), ['code', 'event', 'ms', 'ts'])
})

test('fetch budgets (§19.9 step 1): three a minute per address, ten per registrable domain, thirty in all, four in flight', async t => {
  const h = await anyHarness(t)
  const doc = n => `https://c${n}.budget.com/client.json`
  for (let n = 0; n < 60; n++) h.fetcher.docs.set(doc(n), { body: { client_id: doc(n), redirect_uris: [`https://c${n}.budget.com/cb`] } })
  const ask = (n, address = fresh()) => start(h, { clientId: doc(n), redirectUri: `https://c${n}.budget.com/cb`, address })
  const one = fresh()
  for (let n = 0; n < 3; n++) assert.equal((await ask(n, one)).response.status, 302)
  const starved = await ask(3, one)
  assert.equal(starved.response.status, 429)
  assert.match(starved.response.body, /too_many_requests/)
  // Per registrable domain: wildcard subdomains do not multiply the budget.
  for (let n = 3; n < 10; n++) assert.equal((await ask(n)).response.status, 302, String(n))
  assert.equal((await ask(10)).response.status, 429, 'the eleventh document of budget.com this minute')
  h.clock.advance(61_000)
  // In all: thirty a minute across every domain.
  const other = n => `https://agent${n}.example${n}.com/client.json`
  for (let n = 0; n < 31; n++) h.fetcher.docs.set(other(n), { body: { client_id: other(n), redirect_uris: [`https://agent${n}.example${n}.com/cb`] } })
  let accepted = 0
  for (let n = 0; n < 31; n++) if ((await start(h, { clientId: other(n), redirectUri: `https://agent${n}.example${n}.com/cb` })).response.status === 302) accepted++
  assert.equal(accepted, CIMD_FETCHES_PER_MINUTE)
  assert.equal(CIMD_FETCHES_PER_DOMAIN, 10)
  h.clock.advance(61_000)
  // A fifth fetch in flight is cimd_busy; tested ids never reach the budget.
  let release
  const hold = new Promise(resolve => { release = resolve })
  const slow = n => `https://slow${n}.wait${n}.com/client.json`
  for (let n = 0; n < 5; n++) h.fetcher.docs.set(slow(n), { body: { client_id: slow(n), redirect_uris: [`https://slow${n}.wait${n}.com/cb`] }, hold })
  const waiting = [0, 1, 2, 3].map(n => start(h, { clientId: slow(n), redirectUri: `https://slow${n}.wait${n}.com/cb` }))
  while (h.fetcher.calls.filter(url => url.includes('slow')).length < 4) await new Promise(resolve => setTimeout(resolve, 5))
  const busy = await start(h, { clientId: slow(4), redirectUri: `https://slow4.wait4.com/cb` })
  assert.equal(busy.response.status, 429)
  assert.equal((await start(h, { clientId: CLAUDE, redirectUri: 'https://claude.ai/api/mcp/auth_callback' })).response.status, 302)
  release()
  for (const result of await Promise.all(waiting)) assert.equal(result.response.status, 302)
  const codes = h.logs.map(line => JSON.parse(line)).filter(entry => entry.route === 'GET /mcp/authorize' && entry.status === 429).map(entry => entry.code)
  assert.ok(codes.includes('cimd_busy') && codes.includes('rate_limited'), JSON.stringify(codes))
})

test('pending requests (§19.10): twenty unconsented per unknown client at once', async t => {
  const h = await anyHarness(t)
  h.fetcher.docs.set(AGENT, { body: { client_id: AGENT, redirect_uris: [AGENT_REDIRECT] } })
  for (let n = 0; n < PENDING_PER_CLIENT; n++) assert.equal((await start(h, { clientId: AGENT, redirectUri: AGENT_REDIRECT })).response.status, 302)
  const refused = await start(h, { clientId: AGENT, redirectUri: AGENT_REDIRECT })
  assert.equal(refused.response.status, 429)
  // A tested client is not held back by it.
  assert.equal((await start(h, { clientId: CLAUDE, redirectUri: 'https://claude.ai/api/mcp/auth_callback' })).response.status, 302)
})

test('request checks (§19.11): resource absent or normalized, a wider scope, and the grant always wappie:read', async t => {
  const h = await anyHarness(t)
  const redirectUri = 'https://claude.ai/api/mcp/auth_callback'
  const absent = await start(h, { clientId: CLAUDE, redirectUri, resource: null })
  assert.equal(absent.response.status, 302, absent.response.body)
  assert.equal(absent.descriptor.resource, h.resource)
  assert.equal(JSON.parse(h.logs.findLast(line => line.includes('/mcp/authorize'))).resource_default, true)
  const upper = await start(h, { clientId: CLAUDE, redirectUri, resource: h.resource.replace('http://', 'HTTP://') + '/', scope: 'wappie:read offline_access openid' })
  assert.equal(upper.response.status, 302, upper.response.body)
  const wrong = await start(h, { clientId: CLAUDE, redirectUri, resource: h.resource + '/other' })
  assert.equal(new URL(wrong.response.location).searchParams.get('error'), 'invalid_target')
  const malformed = await start(h, { clientId: CLAUDE, redirectUri, scope: 'a  b' })
  assert.equal(new URL(malformed.response.location).searchParams.get('error'), 'invalid_scope')
  // The whole flow without a resource anywhere, then every token says wappie:read.
  const done = await consentV2(h, absent)
  assert.equal(done.completed.status, 302, done.completed.body)
  const code = new URL(done.completed.location).searchParams.get('code')
  const exchanged = await exchange(h, { code, clientId: CLAUDE, verifier: absent.verifier, redirectUri, resource: null })
  assert.equal(exchanged.status, 200, exchanged.body)
  assert.equal(exchanged.json().scope, 'wappie:read')
})

test('the network check (§19.12): the same /24 completes; another /24, /56 or family is ip_mismatch and drops the request', async t => {
  const h = await anyHarness(t)
  const redirectUri = 'https://claude.ai/api/mcp/auth_callback'
  const same = await start(h, { clientId: CLAUDE, redirectUri, address: from('203.0.113.10') })
  const ok = await consentV2(h, same, { address: from('203.0.113.200') })
  assert.equal(ok.completed.status, 302, ok.completed.body)
  assert.equal(JSON.parse(h.logs.findLast(line => line.includes('/mcp/authorize/complete'))).ip_mismatch, false)
  for (const [first, second] of [['203.0.113.10', '203.0.114.10'], ['2001:db8:1:ab::1', '2001:db8:1:1ab::1'], ['203.0.113.10', '2001:db8::1']]) {
    const started = await start(h, { clientId: CLAUDE, redirectUri, address: from(first) })
    const refused = await consentV2(h, started, { address: from(second) })
    assert.equal(refused.completed.status, 400)
    assert.match(refused.completed.body, /ip_mismatch/)
    assert.match(refused.completed.body, /different network/)
    assert.match(refused.completed.body, /rede diferente/)
    assert.equal(h.reader.state.pending.has(started.id), false, 'the request is dropped')
    assert.equal(h.go.connections.get(refused.connectionId).status, 'revoked')
    assert.equal(JSON.parse(h.logs.findLast(line => line.includes('/mcp/authorize/complete'))).ip_mismatch, true)
  }
  const v6 = await start(h, { clientId: CLAUDE, redirectUri, address: from('2001:db8:1:ab::1') })
  assert.equal((await consentV2(h, v6, { address: from('2001:db8:1:cd::99') })).completed.status, 302, 'the same /56')
  assert.equal(h.reader.counters.ip_mismatches, 3)
})

test('link bundle v2 (§19.15): a metadata consent of a tested and an unknown client, every refusal, and the record it writes', async t => {
  const h = await anyHarness(t)
  const redirectUri = 'https://claude.ai/api/mcp/auth_callback'
  h.fetcher.docs.set(AGENT, { body: { client_id: AGENT, client_name: 'Example Agent', redirect_uris: [AGENT_REDIRECT] } })
  // Refusals, each on its own request.
  const refusals = [
    [{ bundle: { started_ack: undefined } }, 400, 'invalid_bundle'],
    [{ bundle: { started_ack: false } }, 400, 'invalid_bundle'],
    [{ bundle: { trust: 'tested' } }, 400, 'invalid_bundle'],
    [{ bundle: { client_id: 'https://agent.example.com/other' } }, 400, 'invalid_bundle'],
    [{ bundle: { history_days: null }, relay: { history_days: null } }, 400, 'invalid_bundle'],
    [{ bundle: { history_days: 14 }, relay: { history_days: 14 } }, 400, 'invalid_bundle'],
    [{ bundle: { history_days: 7 } }, 400, 'invalid_bundle'],
    [{ relay: { trust: 'tested' } }, 400, 'invalid_bundle'],
    [{ relay: { client_local: true } }, 400, 'invalid_bundle'],
    [{ relay: { trust: undefined } }, 400, 'bad_request'],
    [{ bundle: { version: 1 } }, 400, 'invalid_bundle'],
    [{ expiresAt: new Date(h.clock.now() + 91 * DAY).toISOString() }, 400, 'bad_request'],
  ]
  for (const [options, status, code] of refusals) {
    const started = await start(h, { clientId: AGENT, redirectUri: AGENT_REDIRECT })
    const relay = { ...options.relay }
    for (const [name, value] of Object.entries(relay)) if (value === undefined) relay[name] = undefined
    const result = await consentV2(h, started, { ...options, relay })
    assert.equal(result.relayed.status, status, JSON.stringify(options))
    assert.equal(result.relayed.json().code, code, JSON.stringify(options))
  }
  // A tested web client: history null, a year's ceiling.
  const tested = await start(h, { clientId: CLAUDE, redirectUri })
  const testedDone = await consentV2(h, tested, { expiresAt: new Date(h.clock.now() + 365 * DAY).toISOString() })
  assert.equal(testedDone.completed.status, 302, testedDone.completed.body)
  const record = h.reader.state.connections.get(testedDone.connectionId)
  assert.deepEqual([record.client_kind, record.client_host, record.trust, record.tested_id, record.profile, record.limits_tier, record.started_ack, record.unknown_ack, record.history_days, record.redirect_host],
    ['cimd', 'claude.ai', 'tested', 'claude', 'claude.ai', 'web_tested', true, false, null, 'claude.ai'])
  // An unknown client: the history window it chose, and at most three live unknown connections in the workspace.
  for (let n = 0; n < UNKNOWN_LIVE_MAX; n++) {
    const started = await start(h, { clientId: AGENT, redirectUri: AGENT_REDIRECT })
    const done = await consentV2(h, started, n === 0 ? { bundle: { history_days: 7 }, relay: { history_days: 7 } } : {})
    assert.equal(done.completed.status, 302, done.completed.body)
    const unknown = h.reader.state.connections.get(done.connectionId)
    assert.deepEqual([unknown.trust, unknown.client_name, unknown.claimed_name, unknown.limits_tier, unknown.history_days, unknown.profile],
      ['unknown', 'agent.example.com', 'Example Agent', 'unknown', n === 0 ? 7 : 30, 'default'])
    if (n === 0) {
      // The tier's lifetimes (§19.19): a metadata refresh token of an unknown client dies after seven days unused.
      const code = new URL(done.completed.location).searchParams.get('code')
      const exchanged = await exchange(h, { code, clientId: AGENT, verifier: started.verifier, redirectUri: AGENT_REDIRECT })
      assert.equal(exchanged.status, 200, exchanged.body)
      const refreshRecord = [...h.reader.state.tokens.values()].find(item => item.kind === 'refresh' && item.connection_id === done.connectionId)
      assert.equal(refreshRecord.expires_at - refreshRecord.issued_at, 7 * DAY)
    }
  }
  const fourth = await start(h, { clientId: AGENT, redirectUri: AGENT_REDIRECT })
  const crowded = await consentV2(h, fourth)
  assert.equal(crowded.relayed.status, 409)
  assert.equal(crowded.relayed.json().code, 'too_many_unknown')
  // A version-1 link bundle never opens on a 0.6.0 request.
  const old = await start(h, { clientId: CLAUDE, redirectUri })
  const { sealed } = await sealBundle(old.descriptor, { version: 1, server_url: new URL(old.descriptor.resource).origin, workspace_id: h.workspace, device_ids: [vector.device],
    token: h.apiKey, allow_plaintext: false, link_secret: randomBytes(32).toString('base64url') })
  const connectionId = randomUUID()
  h.go.connections.set(connectionId, { status: 'pending', expires_at: new Date(h.clock.now() + DAY).toISOString() })
  const v1 = await h.internal(`/internal/requests/${old.id}/bundle`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
    kind: 'metadata', connection_id: connectionId, tenant_id: h.workspace, kid: old.descriptor.kid, sealed, expires_at: new Date(h.clock.now() + DAY).toISOString(),
    trust: 'tested', client_local: false, history_days: null }) })
  assert.equal(v1.status, 400)
  assert.equal(v1.json().code, 'invalid_bundle')
  // The connection serves; a token's tools list works.
  const code = new URL(testedDone.completed.location).searchParams.get('code')
  const pair = (await exchange(h, { code, clientId: CLAUDE, verifier: tested.verifier, redirectUri })).json()
  assert.equal((await rpc(h, pair.access_token)).status, 200)
})

test('client caps (§19.10): 20 documents per registrable domain and 300 in all, 200 registrations per host; the oldest record no live connection names makes way, unconsented first', () => {
  const state = { clients: new Map(), connections: new Map() }
  const add = (id, fields) => state.clients.set(id, { client_id: id, ...fields })
  for (let n = 0; n < UNKNOWN_CLIENTS_PER_DOMAIN; n++) add(`https://a${n}.crowded.com/c`, { source: 'cimd', client_host: `a${n}.crowded.com`, registrable: 'crowded.com', last_used_at: n, ...(n < 2 ? { authorized_at: 1 } : {}) })
  // A consent alone protects nothing; a live connection does.
  state.connections.set('k', { connection_id: 'k', client_id: 'https://a2.crowded.com/c' })
  assert.equal(makeRoomUnknown(state, 'crowded.com'), true)
  assert.equal(state.clients.has('https://a3.crowded.com/c'), false, 'the oldest unconsented record no connection names')
  add('https://a3.crowded.com/c', { source: 'cimd', client_host: 'a3.crowded.com', registrable: 'crowded.com', last_used_at: 50 })
  assert.equal(state.clients.has('https://a2.crowded.com/c'), true, 'a live connection protects its record')
  // Room is made before each record goes in, as cimd.mjs does.
  for (let n = 0; n < 20; n++) { assert.equal(makeRoomUnknown(state, 'crowded.com'), true); add(`https://b${n}.crowded.com/c`, { source: 'cimd', client_host: `b${n}.crowded.com`, registrable: 'crowded.com', last_used_at: 100 + n }) }
  assert.equal([...state.clients.values()].filter(client => client.registrable === 'crowded.com').length, UNKNOWN_CLIENTS_PER_DOMAIN)
  assert.equal(state.clients.has('https://a0.crowded.com/c'), true, 'a consented record outlasts every unconsented one, even newer')
  assert.equal(state.clients.has('https://b0.crowded.com/c'), false)
  assert.equal(state.clients.has('https://b19.crowded.com/c'), true)
  // Only consented and connected records left: the oldest consented one with no live connection goes next.
  for (let n = 3; n < 20; n++) state.clients.get(`https://b${n}.crowded.com/c`).authorized_at = 2
  assert.equal(makeRoomUnknown(state, 'crowded.com'), true)
  assert.equal(state.clients.has('https://a0.crowded.com/c'), false, 'consented, but no live connection: it goes once the unconsented have')
  assert.equal(makeRoomUnknown(state, 'other.com'), true, 'another domain has room')
  // Every record of the domain serving a live connection: no room.
  const full = { clients: new Map(), connections: new Map() }
  for (let n = 0; n < UNKNOWN_CLIENTS_PER_DOMAIN; n++) {
    full.clients.set(`https://f${n}.full.com/c`, { client_id: `https://f${n}.full.com/c`, source: 'cimd', client_host: `f${n}.full.com`, registrable: 'full.com', last_used_at: n })
    full.connections.set(String(n), { connection_id: String(n), client_id: `https://f${n}.full.com/c` })
  }
  assert.equal(makeRoomUnknown(full, 'full.com'), false)
  assert.equal(UNKNOWN_CLIENTS_MAX, 300)
  // Registrations count apart from documents: 200 a host.
  const dcr = { clients: new Map(), connections: new Map() }
  for (let n = 0; n < MAX_CLIENTS_PER_HOST; n++) dcr.clients.set(`r${n}`, { client_id: `r${n}`, source: 'dcr', redirect_host: 'claude.ai', last_used_at: n })
  for (let n = 0; n < 50; n++) dcr.clients.set(`d${n}`, { client_id: `d${n}`, source: 'cimd', client_host: 'x.example.com', registrable: 'example.com', redirect_host: 'claude.ai', last_used_at: n })
  dcr.connections.set('k', { connection_id: 'k', client_id: 'r0' })
  assert.equal(makeRoomRegistered(dcr, 'claude.ai'), true)
  assert.deepEqual([dcr.clients.has('r0'), dcr.clients.has('r1'), dcr.clients.size], [true, false, MAX_CLIENTS_PER_HOST - 1 + 50])
})

test('refresh idle times by tier (§19.19): tested web as 0.5.0, a local app a week, an unknown client a week and three days for text; a record 0.5.0 wrote as before', () => {
  const idle = (limits_tier, kind) => idleFor({ limits_tier, ...(kind ? { kind } : {}) }, CLIENT_LIMITS) / DAY
  assert.deepEqual([idle('web_tested'), idle('web_tested', 'content')], [30, 7])
  assert.deepEqual([idle('local_tested'), idle('local_tested', 'content')], [7, 7])
  assert.deepEqual([idle('unknown'), idle('unknown', 'content')], [7, 3])
  assert.deepEqual([idleFor({}, CLIENT_LIMITS), idleFor({ kind: 'content' }, CLIENT_LIMITS)], [REFRESH_IDLE_MS, CONTENT_REFRESH_IDLE_MS])
  assert.deepEqual([idleFor({ limits_tier: 'unknown' }), idleFor({ limits_tier: 'token' }, CLIENT_LIMITS)], [REFRESH_IDLE_MS, REFRESH_IDLE_MS], 'no table, or a tier with no refresh: 0.5.0\'s')
})
