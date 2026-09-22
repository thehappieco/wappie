import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { chmod, readFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { auth, Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client'
import { McpServer } from '@whatserver2/mcp/sdk'
import { createServer } from '@whatserver2/mcp'
import { harness, authorize, clientProvider, consent, call, parsed, raw, rpc, session, secretsAbsent, vector, workspace, DAY } from './harness.mjs'
import { configFor, providerFor } from '../provider.mjs'
import { BODY_LIMITS } from '../router.mjs'

const tools = ['list_numbers', 'list_chats', 'list_messages', 'get_message', 'list_revisions', 'resolve_contact', 'search_messages', 'activity_summary']

test('claude.ai-style client: discovery, DCR assigned none, consent, PKCE exchange, eight metadata-only tools', async t => {
  const h = await harness(t)
  const { provider, done } = await authorize(h, { auth, provider: clientProvider({ authMethod: 'client_secret_post' }) })
  assert.equal(provider.store.client.token_endpoint_auth_method, 'none', 'the AS assigns the method whatever was requested')
  assert.equal(new URL(done.completed.location).searchParams.get('iss'), h.publicOrigin)
  assert.equal(h.go.activations, 1)
  assert.equal(h.go.connections.get(done.connectionId).status, 'active')
  const transport = new StreamableHTTPClientTransport(new URL(h.resource), { authProvider: provider })
  const client = new Client({ name: 'synthetic-wappie-test', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } })
  await client.connect(transport)
  try {
    assert.equal(client.getServerVersion().name, 'wappie-readonly')
    const listing = await client.listTools()
    assert.deepEqual(listing.tools.map(tool => tool.name), tools)
    for (const tool of listing.tools) assert.equal(tool.annotations.readOnlyHint, true)
    const numbers = parsed(await call(client, 'list_numbers'))
    assert.equal(numbers.numbers.length, 1)
    assert.equal(numbers.plaintext_enabled, false)
    const chats = await call(client, 'list_chats', { device_id: vector.device })
    assert.equal(parsed(chats).chats[0].name.state, 'locked')
    assert.equal(parsed(chats).chats[0].preview.state, 'locked')
    const messages = await call(client, 'list_messages', { device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net', limit: 3 })
    assert.equal(parsed(messages).messages[0].body.state, 'locked')
    const search = await call(client, 'search_messages', { device_id: vector.device, query: 'anything', period: 'all' })
    assert.equal(search.isError, true)
    assert.match(search.content[0].text, /plaintext_required_for_text_search/)
    const archive = h.f.state.requests
    assert.ok(archive.length >= 3)
    assert.ok(archive.every(item => item.method === 'GET' && item.auth === `Bearer ${h.apiKey}`))
    assert.equal(archive.some(item => /keys|grants|auth/.test(item.path)), false, 'metadata reads never ask for keys')
    secretsAbsent(h, { linkSecrets: [done.linkSecret], proofs: [done.proof], tokens: [provider.store.tokens.access_token, provider.store.tokens.refresh_token, new URL(done.completed.location).searchParams.get('code')] })
    assert.equal(h.logs.some(line => JSON.parse(line).route === 'POST /mcp' && JSON.parse(line).status === 200), true)
  } finally { await client.close() }
})

test('the reader builds the shared SDK server class and resolves exactly one MCP SDK copy', async t => {
  const h = await harness(t)
  const connection = { connection_id: 'x', workspace_id: workspace, device_ids: [vector.device], timezone: 'UTC', api_key: h.apiKey }
  const server = createServer(configFor(connection, h.go.url), providerFor(connection))
  assert.ok(server instanceof McpServer)
  const config = configFor(connection, h.go.url)
  assert.equal(config.credential_source, 'provided')
  assert.equal(config.allow_plaintext, false)
  assert.equal(config.max_scan_messages, 500)
  assert.throws(() => providerFor(connection).serviceKey(), { code: 'plaintext_opt_in_required' })
  assert.throws(() => providerFor(connection).contactPack(), { code: 'plaintext_opt_in_required' })
  const mcp = fileURLToPath(new URL('../../mcp/package.json', import.meta.url))
  const fromMcp = createRequire(mcp).resolve('@modelcontextprotocol/server')
  const fromSdk = createRequire(await import.meta.resolve('@whatserver2/mcp/sdk')).resolve('@modelcontextprotocol/server')
  assert.equal(fromSdk, fromMcp)
  let fromHere
  try { fromHere = createRequire(import.meta.url).resolve('@modelcontextprotocol/server') } catch { fromHere = undefined }
  assert.ok(fromHere === undefined || fromHere === fromMcp, 'a second SDK copy under packages/mcp-http would break class identity')
})

test('well-known metadata is identical on all four paths; /mcp challenges, refuses other methods, Host spoofing and browser origins', async t => {
  const h = await harness(t)
  const bodies = []
  for (const path of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
    const response = await h.request(path)
    assert.equal(response.status, 200)
    assert.equal(response.headers.get('access-control-allow-origin'), '*')
    bodies.push(response.body)
  }
  assert.equal(bodies[0], bodies[1])
  const prm = JSON.parse(bodies[0])
  assert.equal(prm.resource, h.resource)
  assert.deepEqual(prm.authorization_servers, [h.publicOrigin])
  assert.deepEqual(prm.scopes_supported, ['wappie:read'])
  const documents = []
  for (const path of ['/.well-known/oauth-authorization-server', '/.well-known/oauth-authorization-server/mcp']) {
    const response = await h.request(path)
    assert.equal(response.status, 200)
    documents.push(response.body)
  }
  assert.equal(documents[0], documents[1])
  const as = JSON.parse(documents[0])
  assert.equal(as.issuer, h.publicOrigin)
  assert.equal(as.authorization_endpoint, `${h.publicOrigin}/mcp/authorize`)
  assert.equal(as.token_endpoint, `${h.publicOrigin}/mcp/token`)
  assert.equal(as.registration_endpoint, `${h.publicOrigin}/mcp/register`)
  assert.equal(as.revocation_endpoint, `${h.publicOrigin}/mcp/revoke`)
  assert.deepEqual(as.code_challenge_methods_supported, ['S256'])
  assert.deepEqual(as.token_endpoint_auth_methods_supported, ['none'])
  assert.deepEqual(as.grant_types_supported, ['authorization_code', 'refresh_token'])
  assert.deepEqual(as.response_types_supported, ['code'])
  assert.equal(as.authorization_response_iss_parameter_supported, true)
  assert.equal(as.client_id_metadata_document_supported, true)
  assert.equal((await h.request('/.well-known/oauth-authorization-server', { method: 'POST' })).status, 405)
  const challenge = await rpc(h, null)
  assert.equal(challenge.status, 401)
  assert.match(challenge.headers.get('www-authenticate'), /^Bearer /)
  assert.ok(challenge.headers.get('www-authenticate').includes(`resource_metadata="${h.publicOrigin}/.well-known/oauth-protected-resource/mcp"`))
  assert.equal((await h.request('/mcp')).status, 405)
  assert.equal((await h.request('/mcp', { method: 'DELETE' })).status, 405)
  const spoofed = await raw(h, { method: 'POST', path: '/mcp', headers: { host: 'evil.example', 'content-type': 'application/json' }, body: '{}' })
  assert.equal(spoofed.status, 403)
  assert.equal((await raw(h, { path: '/.well-known/oauth-protected-resource', headers: { host: `evil.example:${h.reader.port}` } })).status, 403)
  assert.equal((await raw(h, { path: '/mcp/authorize', headers: { host: 'evil.example' } })).status, 403)
  const withOrigin = await rpc(h, null, undefined, { origin: h.publicOrigin })
  assert.equal(withOrigin.status, 403)
  assert.equal((await h.request('/nothing')).status, 404)
  assert.equal((await h.request('/v1/mcp/internal/connections/x')).status, 404)
  const unknownBearer = await rpc(h, `wmcp_a_${'A'.repeat(43)}`)
  assert.equal(unknownBearer.status, 401)
  secretsAbsent(h)
})

test('Go stays the authority: a revoked connection is refused within a minute, an expired access token immediately', async t => {
  const h = await harness(t)
  const { tokens, done } = await session(h)
  assert.equal((await rpc(h, tokens.access_token)).status, 200)
  h.go.connections.get(done.connectionId).status = 'revoked'
  assert.equal((await rpc(h, tokens.access_token)).status, 200, 'the cached status is honoured for up to a minute')
  h.clock.advance(61_000)
  const refused = await rpc(h, tokens.access_token)
  assert.equal(refused.status, 401)
  assert.equal(h.reader.state.connections.size, 0, 'local wipe')
  assert.equal((await rpc(h, tokens.access_token)).status, 401)
  const again = await session(h)
  h.clock.advance(16 * 60_000)
  assert.equal((await rpc(h, again.tokens.access_token)).status, 401)
  const third = await session(h)
  const revoked = await h.internal(`/internal/connections/${third.done.connectionId}/revoke`, { method: 'POST' })
  assert.equal(revoked.status, 204)
  assert.equal((await rpc(h, third.tokens.access_token)).status, 401)
  assert.equal((await rpc(h, third.tokens.access_token)).status, 401)
  secretsAbsent(h, { tokens: [tokens.access_token, again.tokens.access_token, third.tokens.access_token], linkSecrets: [done.linkSecret] })
})

test('/mcp is limited per connection and the largest bodies are capped before parsing', async t => {
  const h = await harness(t)
  const first = await session(h), second = await session(h)
  let limited
  for (let index = 0; index < 60; index++) assert.equal((await rpc(h, first.tokens.access_token)).status, 200)
  limited = await rpc(h, first.tokens.access_token)
  assert.equal(limited.status, 429)
  assert.ok(Number(limited.headers.get('retry-after')) >= 1)
  assert.equal((await rpc(h, second.tokens.access_token)).status, 200, 'another connection is unaffected')
  h.clock.advance(60_000)
  assert.equal((await rpc(h, first.tokens.access_token)).status, 200)
  const big = 'x'.repeat(BODY_LIMITS.mcp + 1)
  assert.equal((await h.request('/mcp', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${first.tokens.access_token}` }, body: big })).status, 413)
  assert.equal((await h.request('/mcp/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'a='.padEnd(BODY_LIMITS.as + 1, 'b') })).status, 413)
  assert.equal((await h.request('/mcp/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: ['x'.repeat(BODY_LIMITS.as)] }) })).status, 413)
  assert.equal((await h.internal('/internal/requests/AAAAAAAAAAAAAAAAAAAAAA/bundle', { method: 'POST', headers: { 'content-type': 'application/json' }, body: 'x'.repeat(BODY_LIMITS.link + 1) })).status, 413)
  assert.equal((await h.request('/mcp', { method: 'POST', headers: { 'content-type': 'text/plain', authorization: `Bearer ${first.tokens.access_token}` }, body: '{}' })).status, 415)
  assert.equal(h.reader.state.connections.size, 2)
})

test('state survives a restart encrypted and private; loosened files refuse to start; reconciliation drops what Go no longer serves', async t => {
  const h = await harness(t)
  const kept = await session(h), dropped = await session(h)
  assert.equal((await stat(h.stateDir)).mode & 0o777, 0o700)
  for (const name of ['keys/state.key', 'keys/recipient.key', 'state.json.enc']) assert.equal((await stat(join(h.stateDir, name))).mode & 0o777, 0o600)
  const encrypted = await readFile(join(h.stateDir, 'state.json.enc'))
  assert.equal(encrypted.subarray(0, 5).toString(), 'WMCP1')
  for (const secret of [h.apiKey, kept.tokens.access_token, kept.tokens.refresh_token, 'service_private_key']) assert.equal(encrypted.includes(secret), false)
  h.go.connections.get(dropped.done.connectionId).status = 'revoked'
  await h.restart()
  assert.equal(h.reader.state.connections.size, 1)
  assert.equal((await rpc(h, kept.tokens.access_token)).status, 200, 'an active connection outlives a restart')
  assert.equal((await rpc(h, dropped.tokens.access_token)).status, 401)
  await h.reader.close()
  await chmod(join(h.stateDir, 'state.json.enc'), 0o644)
  await assert.rejects(h.restart(), { code: 'state_file_unsafe' })
  await chmod(join(h.stateDir, 'state.json.enc'), 0o600)
  await chmod(join(h.stateDir, 'keys', 'state.key'), 0o640)
  await assert.rejects(h.restart(), { code: 'state_key_unsafe' })
  await chmod(join(h.stateDir, 'keys', 'state.key'), 0o600)
  await chmod(h.stateDir, 0o755)
  await assert.rejects(h.restart(), { code: 'state_dir_unsafe' })
  await chmod(h.stateDir, 0o700)
  await h.restart()
  assert.equal((await rpc(h, kept.tokens.access_token)).status, 200)
  secretsAbsent(h, { tokens: [kept.tokens.access_token, dropped.tokens.access_token] })
})

test('an active connection dies with its expiry and a consent left unfinished is revoked in Go', async t => {
  const h = await harness(t)
  const short = await session(h, { consent: { expiresAt: new Date(h.clock.now() + 2 * DAY).toISOString() } })
  assert.equal((await rpc(h, short.tokens.access_token)).status, 200)
  h.clock.advance(3 * DAY)
  await h.reader.sweep()
  assert.equal(h.reader.state.connections.size, 0)
  assert.equal((await rpc(h, short.tokens.access_token)).status, 401)
  const provider = clientProvider()
  assert.equal(await auth(provider, { serverUrl: h.resource }), 'REDIRECT')
  const abandoned = await consent(h, provider.store.authorizationUrl, { until: 'bundle' })
  assert.equal(abandoned.relayed.status, 204)
  h.clock.advance(21 * 60_000)
  await h.reader.sweep()
  await new Promise(resolve => setTimeout(resolve, 50))
  assert.equal(h.go.connections.get(abandoned.connectionId).status, 'revoked')
  assert.equal((await h.internal(`/internal/requests/${abandoned.id}`)).status, 404)
})

test('configuration is validated up front; an unreachable Go keeps state at startup and answers server_error later', async t => {
  const { readEnv, ConfigError } = await import('../server.mjs')
  const base = { WAPPIE_MCP_CONSOLE_URL: 'https://app.example.test/console', WAPPIE_MCP_RELAY_SECRET_FILE: '/tmp/x', WAPPIE_MCP_PUBLIC_ORIGIN: 'https://api.example.test' }
  const parsed = readEnv(base)
  assert.equal(parsed.listen.host, '127.0.0.1'); assert.equal(parsed.listen.port, 18093)
  assert.equal(parsed.publicOrigin, 'https://api.example.test')
  assert.equal(parsed.archive, 'http://127.0.0.1:18090')
  assert.deepEqual(parsed.hosts, ['claude.ai', 'chatgpt.com'])
  assert.equal(parsed.cimd, true); assert.equal(parsed.pendingTTLMs, 1_200_000); assert.equal(parsed.stateDir, '/var/lib/wappie-mcp')
  assert.equal(readEnv({ ...base, WAPPIE_MCP_LISTEN: '[::1]:0', WAPPIE_MCP_PUBLIC_ORIGIN: '' }).listen.host, '::1')
  const refused = [
    ['invalid_listen', { WAPPIE_MCP_LISTEN: 'nope' }], ['invalid_listen', { WAPPIE_MCP_LISTEN: '127.0.0.1:70000' }],
    ['invalid_public_origin', { WAPPIE_MCP_PUBLIC_ORIGIN: 'http://api.example.test' }], ['invalid_public_origin', { WAPPIE_MCP_PUBLIC_ORIGIN: 'https://api.example.test/mcp' }],
    ['invalid_public_origin', { WAPPIE_MCP_PUBLIC_ORIGIN: 'https://u:p@api.example.test' }], ['invalid_public_origin', { WAPPIE_MCP_PUBLIC_ORIGIN: 'not a url' }],
    ['public_origin_required', { WAPPIE_MCP_PUBLIC_ORIGIN: '', WAPPIE_MCP_LISTEN: '0.0.0.0:18093' }],
    ['console_url_required', { WAPPIE_MCP_CONSOLE_URL: '' }], ['invalid_console_url', { WAPPIE_MCP_CONSOLE_URL: 'http://app.example.test/console' }], ['invalid_console_url', { WAPPIE_MCP_CONSOLE_URL: '::' }],
    ['relay_secret_file_required', { WAPPIE_MCP_RELAY_SECRET_FILE: '' }], ['invalid_archive_url', { WAPPIE_MCP_ARCHIVE_URL: 'http://archive.example.test' }],
    ['invalid_redirect_hosts', { WAPPIE_MCP_REDIRECT_HOSTS: ' , ' }], ['invalid_redirect_hosts', { WAPPIE_MCP_REDIRECT_HOSTS: 'claude.ai,bad host' }],
    ['invalid_cimd', { WAPPIE_MCP_CIMD: 'maybe' }], ['invalid_pending_ttl', { WAPPIE_MCP_PENDING_TTL_SECONDS: '5' }], ['invalid_pending_ttl', { WAPPIE_MCP_PENDING_TTL_SECONDS: 'soon' }],
  ]
  for (const [code, env] of refused) assert.throws(() => readEnv({ ...base, ...env }), error => error instanceof ConfigError && error.code === code, code)
  const h = await harness(t)
  const { tokens, clientId } = await session(h)
  await h.reader.close()
  await h.go.close()
  await h.restart()
  assert.equal(h.reader.state.connections.size, 1, 'nothing is dropped when Go cannot be asked')
  assert.equal(h.logs.some(line => JSON.parse(line).event === 'reconcile_skipped'), true)
  h.clock.advance(61_000)
  const unavailable = await rpc(h, tokens.access_token)
  assert.equal(unavailable.status, 500)
  assert.equal(unavailable.json().error, 'server_error')
  const refreshed = await h.form('/mcp/token', { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientId })
  assert.equal(refreshed.status, 503)
  assert.equal(refreshed.json().error, 'server_error')
  assert.equal(h.reader.state.connections.size, 1, 'a transient failure revokes nothing')
  h.go.close = async () => {}
})
