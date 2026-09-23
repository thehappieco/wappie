import { test } from 'node:test'
import assert from 'node:assert/strict'
import { auth, Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client'
import { harness, authorize, authorizeURL, clientProvider, consent, exchange, pkce, secretsAbsent, REDIRECT_URI } from './harness.mjs'
import { cimdURL } from '../cimd.mjs'

const CIMD = 'https://claude.ai/.well-known/oauth-client'
const document = (overrides = {}) => JSON.stringify({ client_id: CIMD, client_name: 'Claude (CIMD)', redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], ...overrides })
const relayCalls = h => h.go.calls.filter(item => item.path === '/v1/mcp/internal/cimd').length

test('a URL client_id on an allowed host is resolved through the Go relay, cached for a day and used end to end', async t => {
  const h = await harness(t)
  h.go.cimd.set(CIMD, { body: document() })
  assert.equal(h.reader.state.clients.size, 0)
  const { challenge } = pkce()
  const url = authorizeURL(h, { clientId: CIMD, challenge })
  const first = await h.request(url.pathname + url.search)
  assert.equal(first.status, 302)
  assert.equal(new URL(first.location).origin, h.consoleOrigin)
  assert.equal(relayCalls(h), 1)
  assert.equal(h.go.calls.find(item => item.path === '/v1/mcp/internal/cimd').query.get('url'), CIMD)
  const cached = h.reader.state.clients.get(CIMD)
  assert.equal(cached.source, 'cimd')
  assert.equal(cached.redirect_host, 'claude.ai')
  assert.equal((await h.request(url.pathname + url.search)).status, 302)
  assert.equal(relayCalls(h), 1, 'served from the cache')
  h.clock.advance(25 * 3_600_000)
  assert.equal((await h.request(url.pathname + url.search)).status, 302)
  assert.equal(relayCalls(h), 2, 'refetched after a day')
  const other = authorizeURL(h, { clientId: CIMD, challenge, redirectUri: 'https://claude.ai/other' })
  const wrongRedirect = await h.request(other.pathname + other.search)
  assert.equal(wrongRedirect.status, 400)
  assert.match(wrongRedirect.body, /invalid_redirect_uri/)
  // The SDK client picks the CIMD identity by itself once the AS advertises support, and never registers.
  const provider = clientProvider({ clientMetadataUrl: CIMD })
  const { done } = await authorize(h, { auth, provider })
  assert.equal(provider.store.client.client_id, CIMD)
  assert.equal(h.logs.some(line => JSON.parse(line).route === 'POST /mcp/register'), false)
  const transport = new StreamableHTTPClientTransport(new URL(h.resource), { authProvider: provider })
  const client = new Client({ name: 'synthetic-wappie-test', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } })
  await client.connect(transport)
  try { assert.equal((await client.listTools()).tools.length, 8) } finally { await client.close() }
  assert.equal(done.descriptor.client_id, CIMD)
  assert.equal(done.descriptor.client_name, 'Claude (CIMD)')
  // Documents not yet cached are fetched three a minute per address; cached ones cost nothing.
  const ip = { headers: { 'x-forwarded-for': '198.51.100.7' } }
  const others = Array.from({ length: 4 }, (_, index) => `https://claude.ai/.well-known/oauth-client-${index}`)
  for (const id of others) h.go.cimd.set(id, { body: document({ client_id: id }) })
  const fetched = relayCalls(h)
  const start = id => { const target = authorizeURL(h, { clientId: id, challenge }); return target.pathname + target.search }
  for (const id of others.slice(0, 3)) assert.equal((await h.request(start(id), ip)).status, 302)
  const starved = await h.request(start(others[3]), ip)
  assert.equal(starved.status, 429)
  assert.match(starved.body, /too_many_requests/)
  assert.equal(relayCalls(h), fetched + 3, 'the fourth document was not asked for')
  assert.equal((await h.request(url.pathname + url.search, ip)).status, 302, 'a cached document is served without a fetch')
  assert.equal(relayCalls(h), fetched + 3)
  assert.equal((await h.request(start(others[3]))).status, 302, 'another address has its own budget')
  assert.equal(relayCalls(h), fetched + 4)
  secretsAbsent(h, { linkSecrets: [done.linkSecret], tokens: [provider.store.tokens.access_token] })
})

test('CIMD refusals: root path, foreign host, oversize document, relay failure, mismatched or malformed documents', async t => {
  const h = await harness(t)
  const { challenge } = pkce()
  const refused = async (clientId, redirectUri = REDIRECT_URI) => {
    const url = authorizeURL(h, { clientId, challenge, redirectUri })
    const response = await h.request(url.pathname + url.search)
    assert.equal(response.status, 400, clientId)
    assert.match(response.body, /invalid_client/)
  }
  const before = relayCalls(h)
  await refused('https://claude.ai/')
  await refused('https://claude.ai')
  await refused('https://evil.claude.ai/.well-known/oauth-client')
  await refused('https://claude.ai.attacker.com/client')
  await refused('http://claude.ai/.well-known/oauth-client')
  await refused('https://claude.ai:8443/.well-known/oauth-client')
  await refused('https://user@claude.ai/.well-known/oauth-client')
  await refused('https://claude.ai/.well-known/oauth-client?x=1')
  await refused('https://claude.ai/.well-known/oauth-client#f')
  assert.equal(relayCalls(h), before, 'nothing that fails the URL rules reaches the relay')
  assert.equal(cimdURL('https://claude.ai/', ['claude.ai']), null)
  assert.equal(cimdURL(CIMD, ['claude.ai']).href, CIMD)
  assert.equal(cimdURL(CIMD, ['chatgpt.com']), null)
  await refused(CIMD)
  assert.equal(relayCalls(h), before + 1, 'the relay answered 502')
  await refused(CIMD)
  assert.equal(relayCalls(h), before + 1, 'a document that failed is not asked for again for a minute')
  // Once that minute is over each bad document is fetched exactly once and refused.
  const bad = [
    { body: document(), type: 'text/html' },
    { body: JSON.stringify({ client_id: CIMD, redirect_uris: [REDIRECT_URI], padding: 'x'.repeat(9 * 1024) }) },
    { body: document({ client_id: 'https://claude.ai/.well-known/other' }) },
    { body: document({ redirect_uris: ['https://evil.example/cb'] }) },
    { body: document({ redirect_uris: [] }) },
    { body: document({ client_name: 'x'.repeat(101) }) },
    { body: '[1]' },
    { body: '{' },
    { body: document(), status: 500 },
  ]
  let fetched = before + 1
  for (const entry of bad) {
    h.go.cimd.set(CIMD, entry)
    h.clock.advance(61_000)
    await refused(CIMD)
    assert.equal(relayCalls(h), ++fetched, JSON.stringify(entry).slice(0, 60))
  }
  assert.equal(h.reader.state.clients.size, 0, 'no refused document is cached')
  h.go.cimd.set(CIMD, { body: document({ redirect_uris: ['https://claude.ai/one', REDIRECT_URI] }) })
  h.clock.advance(61_000)
  const url = authorizeURL(h, { clientId: CIMD, challenge })
  assert.equal((await h.request(url.pathname + url.search)).status, 302)
  const consented = await consent(h, url)
  assert.equal(consented.completed.status, 302)
  secretsAbsent(h, { linkSecrets: [consented.linkSecret] })
})

test('with CIMD off the AS does not advertise it, URL client_ids are unknown and the relay is never asked', async t => {
  const h = await harness(t, { env: { WAPPIE_MCP_CIMD: 'off' } })
  h.go.cimd.set(CIMD, { body: document() })
  const as = (await h.request('/.well-known/oauth-authorization-server')).json()
  assert.equal(as.client_id_metadata_document_supported, undefined)
  const { challenge } = pkce()
  const url = authorizeURL(h, { clientId: CIMD, challenge })
  const response = await h.request(url.pathname + url.search)
  assert.equal(response.status, 400)
  assert.match(response.body, /invalid_client/)
  assert.equal(relayCalls(h), 0)
  const provider = clientProvider({ clientMetadataUrl: CIMD })
  const { done } = await authorize(h, { auth, provider })
  assert.notEqual(provider.store.client.client_id, CIMD, 'the SDK falls back to registration')
  assert.equal(done.completed.status, 302)
  secretsAbsent(h, { linkSecrets: [done.linkSecret] })
})

// The document ChatGPT serves for Codex, in the shape it really has: a native
// app on the user's machine, portless loopback redirects, and a localhost one.
const CODEX = 'https://chatgpt.com/oauth/codex/client.json'
const codex = (overrides = {}) => JSON.stringify({ client_id: CODEX, client_uri: 'https://chatgpt.com/codex', application_type: 'native',
  redirect_uris: ['http://127.0.0.1/callback', 'http://localhost/callback'], token_endpoint_auth_method: 'none',
  token_endpoint_auth_methods_supported: ['none'], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], client_name: 'Codex', ...overrides })

test('a native app vouched for by an allowed host gets its code on its own loopback port, and nowhere else', async t => {
  const h = await harness(t)
  h.go.cimd.set(CODEX, { body: codex() })
  const { challenge, verifier } = pkce()
  const redirectUri = 'http://127.0.0.1:58936/callback'
  const url = authorizeURL(h, { clientId: CODEX, challenge, redirectUri })
  const done = await consent(h, url)
  assert.equal(done.authorize.status, 302, 'the request that ended in invalid_client on the pilot')
  const record = h.reader.state.clients.get(CODEX)
  assert.equal(record.loopback, true)
  assert.equal(record.redirect_host, 'chatgpt.com', 'the host that vouches for the app, which the API allowlist checks')
  assert.deepEqual(record.redirect_uris, ['http://127.0.0.1/callback'], 'localhost is passed over, not trusted')
  // The consent card must say where the code really goes.
  assert.equal(done.descriptor.redirect_local, true)
  assert.equal(done.descriptor.client_name, 'Codex')
  assert.equal(done.completed.status, 302)
  const back = new URL(done.completed.location)
  assert.equal(back.origin + back.pathname, redirectUri, 'the code goes to the port the app asked for')
  const code = back.searchParams.get('code')
  const pair = await exchange(h, { code, clientId: CODEX, verifier, redirectUri })
  assert.equal(pair.status, 200)
  assert.equal((await exchange(h, { code, clientId: CODEX, verifier, redirectUri })).status, 400, 'a code is single-use')
  // RFC 8252 §7.3: any port. Host, path and scheme must still match exactly.
  assert.equal((await h.request(authorizeURL(h, { clientId: CODEX, challenge, redirectUri: 'http://127.0.0.1:1/callback' }).href.replace(h.publicOrigin, ''))).status, 302)
  for (const refused of ['http://127.0.0.1:58936/other', 'http://localhost:58936/callback', 'https://127.0.0.1:58936/callback',
    'http://127.0.0.2:58936/callback', 'http://127.0.0.1:58936/callback?next=x', 'http://[::1]:58936/callback', 'http://user@127.0.0.1:58936/callback']) {
    const target = authorizeURL(h, { clientId: CODEX, challenge, redirectUri: refused })
    const answer = await h.request(target.pathname + target.search)
    assert.equal(answer.status, 400, refused)
    assert.match(answer.body, /invalid_redirect_uri/, refused)
  }
  secretsAbsent(h, { linkSecrets: [done.linkSecret], tokens: [pair.json().access_token, pair.json().refresh_token] })
})

test('loopback redirects need a vouching document: open registration, mixed lists, ports and localhost alone are refused', async t => {
  const h = await harness(t)
  const registered = await h.request('/mcp/register', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'Local app', redirect_uris: ['http://127.0.0.1/callback'], token_endpoint_auth_method: 'none' }) })
  assert.equal(registered.status, 400, 'nobody vouches for a client that registers itself')
  assert.match(registered.body, /invalid_redirect_uri/)
  const { challenge } = pkce()
  const cases = {
    'https://chatgpt.com/oauth/codex/mixed.json': ['http://127.0.0.1/callback', 'https://chatgpt.com/callback'],
    'https://chatgpt.com/oauth/codex/port.json': ['http://127.0.0.1:8080/callback'],
    'https://chatgpt.com/oauth/codex/localhost.json': ['http://localhost/callback'],
    'https://chatgpt.com/oauth/codex/elsewhere.json': ['http://127.0.0.1/callback', 'http://evil.example/callback'],
  }
  // One address per document: fetching a fourth from the same one is the
  // fetch budget's 429, which is not what these cases test.
  for (const [index, [id, uris]] of Object.entries(cases).entries()) {
    h.go.cimd.set(id, { body: codex({ client_id: id, redirect_uris: uris }) })
    const target = authorizeURL(h, { clientId: id, challenge, redirectUri: 'http://127.0.0.1:58936/callback' })
    const answer = await h.request(target.pathname + target.search, { headers: { 'x-forwarded-for': `198.51.100.${10 + index}` } })
    assert.equal(answer.status, 400, id)
    assert.match(answer.body, /invalid_client/, id)
  }
  assert.equal(h.reader.state.clients.size, 0)
})

test('a consent whose code never reaches the app frees its slot in Go within minutes', async t => {
  // Codex waits on its loopback port only so long. If the owner approves after
  // it gave up, the browser's last hop is refused and the code is never
  // exchanged — and the connection used to stay active in Go for its whole
  // lifetime, one of the workspace's five.
  const h = await harness(t)
  h.go.cimd.set(CODEX, { body: codex() })
  const abandoned = await consent(h, authorizeURL(h, { clientId: CODEX, challenge: pkce().challenge, redirectUri: 'http://127.0.0.1:58936/callback' }))
  assert.equal(abandoned.completed.status, 302)
  const used = pkce()
  const kept = await consent(h, authorizeURL(h, { clientId: CODEX, challenge: used.challenge, redirectUri: 'http://127.0.0.1:58937/callback' }))
  const code = new URL(kept.completed.location).searchParams.get('code')
  assert.equal((await exchange(h, { code, clientId: CODEX, verifier: used.verifier, redirectUri: 'http://127.0.0.1:58937/callback' })).status, 200)
  h.clock.advance(4 * 60_000)
  await h.reader.sweep()
  assert.equal(h.go.connections.get(abandoned.connectionId).status, 'active', 'a slow exchange is not an abandoned one')
  h.clock.advance(2 * 60_000)
  await h.reader.sweep()
  assert.equal(h.go.connections.get(abandoned.connectionId).status, 'revoked')
  assert.equal(h.reader.state.connections.has(abandoned.connectionId), false)
  assert.equal(h.go.connections.get(kept.connectionId).status, 'active', 'an exchanged connection is left alone')
  assert.equal(h.reader.state.connections.has(kept.connectionId), true)
  assert.ok(h.logs.some(line => JSON.parse(line).event === 'unclaimed_connection_revoked'))
})
