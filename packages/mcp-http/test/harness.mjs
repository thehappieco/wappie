// Test harness for the hosted reader: the synthetic archive from
// @whatserver2/mcp, a fake Go server implementing /v1/mcp/internal/* in front
// of it (with an injectable delay and a fake clock), the reader on an ephemeral
// loopback port, a scripted console that seals bundles and posts proofs, and a
// scripted OAuth client. Every response body and log line is kept so a test
// can assert that no secret ever left the process.
import { createServer as createHTTPServer, request as httpRequest } from 'node:http'
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import assert from 'node:assert/strict'
import { hpke } from '@whatserver2/client'
import { fixture, vector, workspace } from '@whatserver2/mcp/test/fixture'
import { startReader } from '../server.mjs'

export { vector, workspace }
export const REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback'
export const CONSOLE_URL = 'https://console.example.test/console'
export const CONSOLE_ORIGIN = new URL(CONSOLE_URL).origin
export const DAY = 24 * 3_600_000

/** A synthetic 52-character API key, minted per run so no token-shaped literal exists on disk. */
export const apiKey = () => `${randomBytes(4).toString('hex')}.${randomBytes(32).toString('base64url')}`
export const fakeClock = () => { const clock = { offset: 0, now: () => Date.now() + clock.offset, advance(ms) { clock.offset += ms } }; return clock }

/**
 * Go's /v1/mcp/internal/* in front of the synthetic archive REST server.
 * `go.holdActivate(id)`, when set, is awaited before an activation is looked
 * at, so a test can hold one open and act while the reader waits on it.
 */
export function createFakeGo({ upstream, secret, now }) {
  const go = { connections: new Map(), cimd: new Map(), calls: [], delay: 0, activations: 0, holdActivate: null }
  const json = (res, value, status = 200) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)) }
  const http = createHTTPServer(async (req, res) => {
    const url = new URL(req.url, 'http://go')
    if (!url.pathname.startsWith('/v1/mcp/internal/')) {
      // Everything else is the archive REST API the reader queries with the API key.
      const body = req.method === 'GET' ? undefined : await new Promise(resolve => { const chunks = []; req.on('data', chunk => chunks.push(chunk)); req.on('end', () => resolve(Buffer.concat(chunks))) })
      const forwarded = await fetch(upstream + req.url, { method: req.method, headers: req.headers.authorization ? { authorization: req.headers.authorization } : {}, body })
      res.writeHead(forwarded.status, { 'content-type': forwarded.headers.get('content-type') ?? 'application/json' })
      res.end(Buffer.from(await forwarded.arrayBuffer()))
      return
    }
    go.calls.push({ method: req.method, path: url.pathname, query: url.searchParams, forwardedFor: req.headers['x-forwarded-for'] })
    if (req.headers.authorization !== `Bearer ${secret}`) return json(res, { code: 'unauthorized' }, 401)
    if (go.delay) await new Promise(resolve => setTimeout(resolve, go.delay))
    let match
    if ((match = /^\/v1\/mcp\/internal\/connections\/([^/]+)$/.exec(url.pathname)) && req.method === 'GET') {
      const connection = go.connections.get(match[1])
      return connection ? json(res, { status: connection.status, expires_at: connection.expires_at }) : json(res, { code: 'not_found' }, 404)
    }
    if ((match = /^\/v1\/mcp\/internal\/connections\/([^/]+)\/activate$/.exec(url.pathname)) && req.method === 'POST') {
      if (go.holdActivate) await go.holdActivate(match[1])
      const connection = go.connections.get(match[1])
      if (!connection) return json(res, { code: 'not_found' }, 404)
      if (connection.status !== 'pending') return json(res, { code: 'connection_state' }, 409)
      connection.status = 'active'; connection.activated_at = new Date(now()).toISOString(); go.activations++
      res.writeHead(204); res.end(); return
    }
    if ((match = /^\/v1\/mcp\/internal\/connections\/([^/]+)\/revoke$/.exec(url.pathname)) && req.method === 'POST') {
      const connection = go.connections.get(match[1])
      if (connection) connection.status = 'revoked'
      res.writeHead(204); res.end(); return
    }
    if (url.pathname === '/v1/mcp/internal/cimd' && req.method === 'GET') {
      const entry = go.cimd.get(url.searchParams.get('url'))
      if (!entry) return json(res, { code: 'cimd_unavailable' }, 502)
      res.writeHead(entry.status ?? 200, { 'content-type': entry.type ?? 'application/json' }); res.end(entry.body); return
    }
    json(res, { code: 'not_found' }, 404)
  })
  go.listen = async () => { await new Promise(resolve => http.listen(0, '127.0.0.1', resolve)); go.url = `http://127.0.0.1:${http.address().port}`; return go }
  go.close = () => new Promise(resolve => { http.closeAllConnections?.(); http.close(resolve) })
  return go
}

/** Boots archive + fake Go + reader; `t.after` tears everything down. */
export async function harness(t, options = {}) {
  const clock = options.clock ?? fakeClock()
  const key = apiKey()
  const f = await fixture({ token: key })
  const secret = randomBytes(32).toString('base64url')
  const go = await createFakeGo({ upstream: f.server, secret, now: clock.now }).listen()
  const directory = await mkdtemp(join(tmpdir(), 'wappie-mcp-http-'))
  const secretFile = join(directory, 'relay-secret')
  await writeFile(secretFile, secret + '\n', { mode: 0o600 })
  const stateDir = join(directory, 'state')
  const logs = [], responses = []
  const env = {
    WAPPIE_MCP_LISTEN: '127.0.0.1:0', WAPPIE_MCP_CONSOLE_URL: CONSOLE_URL, WAPPIE_MCP_STATE_DIR: stateDir,
    WAPPIE_MCP_RELAY_SECRET_FILE: secretFile, WAPPIE_MCP_ARCHIVE_URL: go.url, WAPPIE_MCP_REDIRECT_HOSTS: 'claude.ai,chatgpt.com',
    WAPPIE_MCP_CIMD: 'on', WAPPIE_MCP_PENDING_TTL_SECONDS: '1200', ...options.env,
  }
  const start = () => startReader({ env, now: clock.now, logSink: line => logs.push(line) })
  let reader = await start()
  const h = {
    f, go, clock, secret, directory, stateDir, env, logs, responses, apiKey: key, workspace, consoleOrigin: CONSOLE_ORIGIN,
    get reader() { return reader }, get publicOrigin() { return reader.publicOrigin }, get resource() { return reader.resource },
    /** A request against the reader, never following redirects; the body is recorded for the secrets sweep. */
    async request(path, init = {}) {
      const response = await fetch(reader.publicOrigin + path, { redirect: 'manual', ...init })
      const body = await response.text()
      responses.push({ path: path.split('?')[0], status: response.status, body })
      return { status: response.status, headers: response.headers, body, location: response.headers.get('location'), json: () => JSON.parse(body) }
    },
    internal(path, init = {}) { return h.request(path, { ...init, headers: { authorization: `Bearer ${secret}`, ...(init.headers ?? {}) } }) },
    form(path, fields, headers = {}) { return h.request(path, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(fields).toString() }) },
    /** Stops the reader and starts a fresh one over the same state directory (same port is not guaranteed). */
    async restart(extraEnv = {}) { await reader.close(); Object.assign(env, extraEnv); reader = await start(); return reader },
    async close() { await reader.close(); await go.close(); await f.close(); await rm(directory, { recursive: true, force: true }) },
  }
  t.after(() => h.close())
  return h
}

/** The scripted claude.ai-style OAuth client used with the SDK's auth() and transport. */
export function clientProvider({ redirectUri = REDIRECT_URI, name = 'Claude', authMethod = 'client_secret_post', clientMetadataUrl } = {}) {
  const store = { client: undefined, tokens: undefined, verifier: undefined, discovery: undefined, authorizationUrl: undefined, state: randomBytes(9).toString('base64url') }
  return {
    store, redirectUrl: redirectUri, clientMetadataUrl,
    get clientMetadata() { return { client_name: name, redirect_uris: [redirectUri], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: authMethod } },
    state: () => store.state,
    clientInformation: () => store.client, saveClientInformation: info => { store.client = info },
    tokens: () => store.tokens, saveTokens: tokens => { store.tokens = tokens },
    redirectToAuthorization: url => { store.authorizationUrl = url },
    saveCodeVerifier: verifier => { store.verifier = verifier }, codeVerifier: () => store.verifier,
    discoveryState: () => store.discovery, saveDiscoveryState: discovery => { store.discovery = discovery },
    invalidateCredentials: scope => { if (scope === 'all' || scope === 'tokens') store.tokens = undefined; if (scope === 'all' || scope === 'client') store.client = undefined },
  }
}

/** The AAD and proof exactly as CONTRACT.md defines them, independent of the reader's own code. */
export const aad = (requestID, kid, resource) => Buffer.from(JSON.stringify(['wappie/mcp-connect', 1, requestID, kid, resource]))
export function proof(linkSecret, { requestID, clientID, codeChallenge, sealedBytes }) {
  const zero = Buffer.from([0])
  const message = Buffer.concat([Buffer.from('wappie-mcp-link/v1'), zero, Buffer.from(requestID), zero, Buffer.from(clientID), zero,
    Buffer.from(codeChallenge), zero, createHash('sha256').update(sealedBytes).digest()])
  return createHmac('sha256', Buffer.from(linkSecret, 'base64url')).update(message).digest('base64url')
}

/** Seals a bundle the way the console does; `overrides` inject the negative cases. */
export async function sealBundle(descriptor, bundle, overrides = {}) {
  const publicKey = overrides.readerPublicKey ?? Buffer.from(descriptor.reader_public_key, 'base64url')
  const additional = aad(overrides.aadRequestID ?? descriptor.request_id, overrides.aadKid ?? descriptor.kid, overrides.aadResource ?? descriptor.resource)
  const { enc, ciphertext } = await hpke.seal(new Uint8Array(publicKey), new Uint8Array(Buffer.from('wappie-mcp-connect/v1')), new Uint8Array(additional), new Uint8Array(Buffer.from(JSON.stringify(bundle))))
  const sealedBytes = Buffer.concat([Buffer.from(enc), Buffer.from(ciphertext)])
  return { sealedBytes, sealed: sealedBytes.toString('base64url') }
}

/**
 * Plays the console: GET /mcp/authorize (from the client's authorization URL),
 * descriptor, sealed bundle relayed as Go would, then the proof form POST.
 * Stops early when `overrides.until` names a step ('authorize' | 'bundle').
 */
export async function consent(h, authorizationUrl, overrides = {}) {
  const target = new URL(authorizationUrl)
  const authorize = await h.request(target.pathname + target.search, { headers: overrides.authorizeHeaders ?? {} })
  const result = { authorize }
  if (authorize.status !== 302) return result
  result.id = new URL(authorize.location).searchParams.get('mcp_connect')
  if (overrides.until === 'authorize') return result
  const described = await h.internal(`/internal/requests/${result.id}`)
  result.descriptor = described.status === 200 ? described.json() : null
  if (!result.descriptor) return result
  result.linkSecret = overrides.linkSecret ?? randomBytes(32).toString('base64url')
  result.bundle = {
    version: 1, server_url: overrides.serverURL ?? new URL(result.descriptor.resource).origin, workspace_id: h.workspace, device_ids: [vector.device],
    token: h.apiKey, allow_plaintext: false, timezone: 'America/Sao_Paulo', link_secret: result.linkSecret, ...overrides.bundle,
  }
  for (const name of overrides.omit ?? []) delete result.bundle[name]
  Object.assign(result, await sealBundle(result.descriptor, result.bundle, overrides))
  result.connectionId = overrides.connectionId ?? randomUUID()
  result.expiresAt = overrides.expiresAt ?? new Date(h.clock.now() + 90 * DAY).toISOString()
  h.go.connections.set(result.connectionId, { status: 'pending', expires_at: result.expiresAt })
  result.relayed = await h.internal(`/internal/requests/${result.id}/bundle`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
    connection_id: result.connectionId, tenant_id: overrides.tenantId ?? h.workspace, kid: overrides.kid ?? result.descriptor.kid, sealed: result.sealed, expires_at: result.expiresAt, ...overrides.relay,
  }) })
  if (result.relayed.status !== 204 || overrides.until === 'bundle') return result
  result.proof = proof(result.linkSecret, { requestID: result.id, clientID: result.descriptor.client_id, codeChallenge: result.descriptor.code_challenge, sealedBytes: result.sealedBytes })
  result.completed = await h.form('/mcp/authorize/complete', { request: result.id, proof: overrides.proof ?? result.proof }, { origin: overrides.origin ?? CONSOLE_ORIGIN })
  return result
}

/** Runs the SDK client through the whole handshake and returns the authorized provider. */
export async function authorize(h, { auth, provider = clientProvider(), overrides = {} } = {}) {
  assert.equal(await auth(provider, { serverUrl: h.resource }), 'REDIRECT')
  const done = await consent(h, provider.store.authorizationUrl, overrides)
  assert.equal(done.completed?.status, 302, JSON.stringify({ authorize: done.authorize?.status, relayed: done.relayed?.status, completed: done.completed?.status }))
  const back = new URL(done.completed.location)
  assert.equal(back.searchParams.get('state'), provider.store.state)
  assert.equal(await auth(provider, { serverUrl: h.resource, authorizationCode: back.searchParams.get('code'), iss: back.searchParams.get('iss') }), 'AUTHORIZED')
  return { provider, done, back }
}

/**
 * Nothing secret in any response body or log line: the API key, the archive
 * private key, the reader's keys and relay secret, every link secret, every
 * proof, plus whatever the test adds. Tokens are allowed only in the token
 * endpoint's own responses.
 */
export function secretsAbsent(h, { linkSecrets = [], proofs = [], tokens = [], extra = [] } = {}) {
  const forbidden = [h.apiKey, h.f.secret, h.secret, vector.private_key, ...linkSecrets, ...proofs, ...extra].filter(Boolean)
  const everywhere = [...h.responses.map(item => item.body), ...h.logs]
  for (const value of forbidden) for (const text of everywhere) assert.equal(text.includes(value), false, `secret found in output`)
  for (const value of tokens) {
    for (const line of h.logs) assert.equal(line.includes(value), false, 'token found in log')
    for (const item of h.responses) if (item.path !== '/mcp/token') assert.equal(item.body.includes(value), false, `token found in ${item.path}`)
  }
  for (const line of h.logs) {
    const entry = JSON.parse(line)
    assert.equal('path' in entry || 'query' in entry || 'headers' in entry || 'body' in entry, false)
  }
}
export const call = (client, name, args = {}) => client.callTool({ name, arguments: args })
export const parsed = result => result.structuredContent || JSON.parse(result.content[0].text)

/** Registers a client directly (defaults are a claude.ai public client). */
export async function register(h, metadata = {}, headers = {}) {
  return h.request('/mcp/register', { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify({
    client_name: 'Claude', redirect_uris: [REDIRECT_URI], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none', ...metadata,
  }) })
}
/** A PKCE pair computed with node:crypto, independent of the SDK. */
export function pkce() {
  const verifier = randomBytes(32).toString('base64url')
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') }
}
/** The authorization URL a client would open, with every parameter overridable (null removes one). */
export function authorizeURL(h, { clientId, redirectUri = REDIRECT_URI, challenge, ...rest } = {}) {
  const url = new URL('/mcp/authorize', h.publicOrigin)
  const params = { response_type: 'code', client_id: clientId, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: 'S256', resource: h.resource, scope: 'wappie:read', state: 'st-' + randomBytes(6).toString('base64url'), ...rest }
  for (const [name, value] of Object.entries(params)) if (value !== null && value !== undefined) url.searchParams.set(name, value)
  return url
}
/** A manual code exchange at /mcp/token. */
export function exchange(h, { code, clientId, verifier, redirectUri = REDIRECT_URI, resource = h.resource, ...rest }) {
  const fields = { grant_type: 'authorization_code', code, client_id: clientId, code_verifier: verifier, redirect_uri: redirectUri, resource, ...rest }
  for (const name of Object.keys(fields)) if (fields[name] === null || fields[name] === undefined) delete fields[name]
  return h.form('/mcp/token', fields)
}
export function refresh(h, { refreshToken, clientId, resource = h.resource, ...rest }) {
  const fields = { grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId, resource, ...rest }
  for (const name of Object.keys(fields)) if (fields[name] === null || fields[name] === undefined) delete fields[name]
  return h.form('/mcp/token', fields)
}
/** A raw JSON-RPC tools/list against /mcp with a bearer; returns the response record. */
export function rpc(h, token, body = { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }, headers = {}) {
  return h.request('/mcp', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers }, body: JSON.stringify(body) })
}
/**
 * Registers a client, authorizes through the scripted console and exchanges
 * the code by hand; returns everything a token test needs.
 */
export async function session(h, overrides = {}) {
  // A distinct client per session (identical registrations collapse into one), spaced out under the per-address registration budget.
  h.clock.advance(13_000)
  const registered = await register(h, { client_name: `Session ${randomBytes(4).toString('hex')}`, ...overrides.client })
  assert.equal(registered.status, 201)
  const clientId = registered.json().client_id
  const { verifier, challenge } = pkce()
  const done = await consent(h, authorizeURL(h, { clientId, challenge, ...overrides.authorize }), overrides.consent)
  assert.equal(done.completed?.status, 302, JSON.stringify({ authorize: done.authorize?.status, relayed: done.relayed?.status, completed: done.completed?.status, body: done.completed?.body }))
  const code = new URL(done.completed.location).searchParams.get('code')
  const exchanged = await exchange(h, { code, clientId, verifier })
  assert.equal(exchanged.status, 200, exchanged.body)
  return { clientId, verifier, challenge, code, done, tokens: exchanged.json() }
}
/** A request over node:http with any headers at all (fetch drops Host); recorded like the others. */
export function raw(h, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(h.publicOrigin)
    const req = httpRequest({ host: url.hostname, port: url.port, method, path, headers }, res => {
      const chunks = []
      res.on('data', chunk => chunks.push(chunk))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8')
        h.responses.push({ path: path.split('?')[0], status: res.statusCode, body: text })
        resolve({ status: res.statusCode, headers: new Headers(Object.entries(res.headers).filter(([, value]) => typeof value === 'string')), body: text, location: res.headers.location ?? null, json: () => JSON.parse(text) })
      })
    })
    req.once('error', reject)
    req.end(body)
  })
}
