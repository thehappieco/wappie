import { test } from 'node:test'
import assert from 'node:assert/strict'
import { auth, Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client'
import { harness, authorize, authorizeURL, clientProvider, consent, pkce, secretsAbsent, REDIRECT_URI } from './harness.mjs'
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
