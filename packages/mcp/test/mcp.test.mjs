import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer as createHTTPServer } from 'node:http'
import { mkdtemp, readFile, writeFile, rm, chmod, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Client } from '@modelcontextprotocol/client'
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio'
import { bytes, hpke, seal } from '@whatserver2/client'
import { derive, freshSalt, wrapPrivateKey } from '@whatserver2/client/crypto/account'
import { loadConfig, loadCredential, readPrivateFile, validateConfig } from '../config.mjs'

const vector = JSON.parse(await readFile(new URL('../../../internal/crypto/seal/testdata/vectors.json', import.meta.url), 'utf8'))
const body = vector.batch.find(item => item.kind === seal.Kind.Body)
const chatName = vector.batch.find(item => item.kind === seal.Kind.ContactName)
const workspace = '018f3a2b-2222-7000-8000-00000000bbbb'
const user = '018f3a2b-2222-7000-8000-00000000aaaa'
const hiddenDevice = '018f3a2b-2222-7000-8000-00000000eeee'
const token = 'synthetic-mcp-credential-never-returned'
const password = 'synthetic-mcp-password-never-returned'
const plain = Buffer.from(body.plaintext, 'base64').toString('utf8')
const privateFile = (path, data) => writeFile(path, data, { mode: 0o600 })

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'wappie-mcp-'))
  const account = await hpke.generateKeyPair()
  const namespace = bytes.parseUUID(vector.tenant), device = bytes.parseUUID(vector.device)
  const grant = await seal.sealDirect(account.publicKey, seal.Kind.DeviceGrant, namespace,
    await seal.grantRow(namespace, device, bytes.parseUUID(user), 1), 1, bytes.fromBase64(vector.private_key))
  const salt = freshSalt(), params = { alg: 'argon2id', m: 32, t: 1, p: 1 }
  const proof = await derive(password, salt, params)
  const wrapped = await wrapPrivateKey(account.privateKey, proof.wrapKey, 'synthetic@example.test')
  const secret = Buffer.from(account.privateKey).toString('base64url')
  account.privateKey.fill(0)
  const state = { authorized: true, tenant: workspace, grantsUser: user, sessionUser: user, grantEnabled: true, tampered: false, largeDirectory: false,
    kdfParams: params, oversizedMe: false, requests: [] }
  const sealedMessage = () => {
    const encrypted = Buffer.from(body.sealed, 'base64')
    if (state.tampered) encrypted[encrypted.length - 1] ^= 1
    return { uid: body.row, device_id: vector.device, seq: 42, wa_id: 'synthetic-wa-id', chat_key: '5511999990000@s.whatsapp.net',
      ts: '2026-09-01T12:00:00Z', is_from_me: false, kind: 'message', type: 'text', source: 'live',
      content_key_id: vector.content_key.id, body_sealed: encrypted.toString('base64'),
    }
  }
  const grants = () => state.grantEnabled ? [{ device_id: vector.device, archive_tenant_id: vector.tenant, epoch: 1, sealed_dsk: bytes.toBase64(grant) }] : []
  const http = createHTTPServer((request, response) => {
    const url = new URL(request.url, 'http://localhost'), path = url.pathname
    state.requests.push({ path, method: request.method, auth: request.headers.authorization, query: url.searchParams })
    const json = (value, status = 200) => { response.writeHead(status, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(value)) }
    const reply = value => json({ tenant_id: state.tenant, ...value })
    if (path === '/v1/auth/challenge' && request.method === 'POST') return json({ salt: bytes.toBase64(salt), params: state.kdfParams })
    if (!state.authorized || request.headers.authorization !== `Bearer ${token}`) return json({ code: 'not_authorized', message: `Never echo ${token} ${password}` }, 403)
    if (path === '/v1/auth/me' && state.oversizedMe) return json({ padding: 'x'.repeat(4 * 1024 * 1024) })
    if (path === '/v1/auth/me') return json({ user: {
      id: state.sessionUser, tenant_id: state.tenant, email: 'synthetic@example.test', public_key: bytes.toBase64(account.publicKey), wrapped_usk: bytes.toBase64(wrapped),
    }, grants: grants() })
    if (request.method !== 'GET') return json({ code: 'bad_request' }, 400)
    if (path === '/v1/devices') return reply({ devices: state.largeDirectory
      ? Array.from({ length: 150 }, (_, index) => ({ id: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`, label: 'x'.repeat(8192), status: 'online' }))
      : [{ id: vector.device, label: 'Número autorizado', status: 'online' }, { id: hiddenDevice, label: 'Outro número', status: 'online' }] })
    if (path === `/v1/devices/${vector.device}/chats`) return reply({ device_id: vector.device, limit: 50, truncated: false, chats: [{
      uid: chatName.row, chat_key: '5511999990000@s.whatsapp.net', last_seq: 42, name_key_id: vector.content_key.id, name_sealed: chatName.sealed,
      last_uid: body.row, last_body_key_id: vector.content_key.id, last_body_sealed: body.sealed,
    }] })
    if (path === `/v1/devices/${vector.device}/messages`) return reply({ chat_key: '5511999990000@s.whatsapp.net', messages: [sealedMessage()],
      has_more: !url.searchParams.has('before_seq'), ...(!url.searchParams.has('before_seq') ? { next_ts: '2026-09-01T12:00:00Z', next_seq: 42 } : {}),
    })
    if (path === `/v1/messages/${body.row}`) return reply(sealedMessage())
    if (path === `/v1/messages/${body.row}/history`) return reply({ requested_uid: body.row, device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net', wa_id: 'synthetic-wa-id',
      versions: [{ revision: 0, message: sealedMessage() }, { revision: 1, message: sealedMessage() }],
    })
    if (path === '/v1/grants') return reply({ user_id: state.grantsUser, grants: grants() })
    if (path === `/v1/devices/${vector.device}/keys`) return reply({ device_id: vector.device, archive_tenant_id: vector.tenant, keys: [vector.content_key] })
    return json({ code: 'not_found' }, 404)
  })
  await new Promise(resolve => http.listen(0, '127.0.0.1', resolve))
  const server = `http://127.0.0.1:${http.address().port}`
  await privateFile(join(directory, 'token'), token + '\n')
  await privateFile(join(directory, 'service-key'), secret + '\n')
  await privateFile(join(directory, 'password'), password + '\n')
  await privateFile(join(directory, 'session.json'), JSON.stringify({ origin: server, token, expiresAt: new Date(Date.now() + 60_000).toISOString(), email: 'synthetic@example.test', tenantID: workspace, userID: user }))
  const handles = []
  return {
    state, directory, secret, server,
    async connect(extra = {}) {
      const configPath = join(directory, `config-${handles.length}.json`)
      await privateFile(configPath, JSON.stringify({ server, workspace, token_file: './token', device_ids: [vector.device], ...extra }))
      const transport = new StdioClientTransport({ command: process.execPath, args: [fileURLToPath(new URL('../cli.mjs', import.meta.url)), '--config', configPath], stderr: 'pipe' })
      let stderr = ''
      transport.stderr?.on('data', chunk => { stderr += String(chunk) })
      const client = new Client({ name: 'synthetic-wappie-test', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } })
      handles.push(client)
      await client.connect(transport)
      return { client, stderr: () => stderr }
    },
    async close() {
      for (const client of handles) await client.close()
      await new Promise(resolve => http.close(resolve))
      await rm(directory, { recursive: true, force: true })
    },
  }
}
const call = (client, name, args = {}) => client.callTool({ name, arguments: args })
const parsed = result => result.structuredContent || JSON.parse(result.content[0].text)
function noSecrets(result, secret) {
  const text = JSON.stringify(result)
  for (const value of [token, password, secret, vector.private_key, vector.content_key.sealed, body.sealed]) assert.equal(text.includes(value), false)
  assert.equal(text.includes('body_sealed'), false)
  assert.equal(text.includes('sealed_dsk'), false)
}

test('stdio initializes and lists only five bounded read-only tools; locked metadata never asks for keys', async () => {
  const f = await fixture()
  try {
    const { client, stderr } = await f.connect()
    assert.equal(client.getServerVersion().name, 'wappie-readonly')
    const listing = await client.listTools()
    assert.deepEqual(listing.tools.map(tool => tool.name), ['list_numbers', 'list_chats', 'list_messages', 'get_message', 'list_revisions'])
    for (const tool of listing.tools) {
      assert.equal(tool.annotations.readOnlyHint, true)
      assert.equal(tool.annotations.destructiveHint, false)
      assert.equal(tool.inputSchema.additionalProperties, false)
    }
    const numbers = await call(client, 'list_numbers')
    assert.equal(parsed(numbers).numbers.length, 1)
    const result = await call(client, 'list_messages', { device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net', limit: 3 })
    assert.equal(parsed(result).messages[0].body.state, 'locked')
    assert.equal(parsed(result).has_more, true)
    assert.equal(f.state.requests.some(item => /keys|grants|auth/.test(item.path)), false)
    noSecrets(result, f.secret)
    assert.equal(stderr(), '')
  } finally { await f.close() }
})

test('service-key grants decrypt Go ciphertext locally after a move; pagination, names and revisions work', async () => {
  const f = await fixture()
  try {
    const { client, stderr } = await f.connect({ allow_plaintext: true, service_key_file: './service-key', service_user_id: user })
    const input = { device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net' }
    const first = await call(client, 'list_messages', input)
    assert.deepEqual(parsed(first).messages[0].body, { state: 'ok', value: plain, truncated: false })
    const next = await call(client, 'list_messages', { ...input, before: parsed(first).next })
    assert.equal(parsed(next).has_more, false)
    const chats = await call(client, 'list_chats', { device_id: vector.device })
    assert.equal(parsed(chats).chats[0].name.value, Buffer.from(chatName.plaintext, 'base64').toString('utf8'))
    assert.equal(parsed(chats).chats[0].preview.value, plain)
    const message = await call(client, 'get_message', { device_id: vector.device, uid: body.row })
    assert.equal(parsed(message).message.body.value, plain)
    const revisions = await call(client, 'list_revisions', { device_id: vector.device, uid: body.row, limit: 1 })
    assert.equal(parsed(revisions).revisions.length, 1)
    assert.equal(parsed(revisions).truncated, true)
    assert.equal(parsed(revisions).revisions[0].message.body.value, plain)
    assert.equal(f.state.requests.filter(item => item.path === '/v1/grants').length, 5, 'fresh grants for every content call')
    for (const result of [first, next, chats, message, revisions]) noSecrets(result, f.secret)
    assert.equal(stderr(), '')
    assert.equal(f.state.requests.some(item => item.method !== 'GET'), false)
  } finally { await f.close() }
})

test('a private wsctl session plus password opt-in uses local USK unlocking without creating sessions', async () => {
  const f = await fixture()
  try {
    const { client, stderr } = await f.connect({ token_file: undefined, session_file: './session.json', allow_plaintext: true, password_file: './password' })
    const result = await call(client, 'get_message', { device_id: vector.device, uid: body.row })
    assert.equal(parsed(result).message.body.value, plain)
    assert.equal(f.state.requests.filter(item => item.path === '/v1/auth/me').length, 1)
    assert.deepEqual(f.state.requests.filter(item => item.method === 'POST').map(item => item.path), ['/v1/auth/challenge'])
    assert.equal(stderr(), '')
    noSecrets(result, f.secret)
    f.state.sessionUser = workspace
    assert.equal((await call(client, 'get_message', { device_id: vector.device, uid: body.row })).isError, true, 'session identity is pinned before opening the USK')
  } finally { await f.close() }
})

test('permission revocation, workspace/account mismatch and absent grants fail closed on subsequent calls', async () => {
  const f = await fixture()
  try {
    const { client } = await f.connect({ allow_plaintext: true, service_key_file: './service-key', service_user_id: user })
    const input = { device_id: vector.device, uid: body.row }
    assert.equal(parsed(await call(client, 'get_message', input)).message.body.value, plain)
    f.state.authorized = false
    const forbidden = await call(client, 'get_message', input)
    assert.equal(forbidden.isError, true); noSecrets(forbidden, f.secret)
    f.state.authorized = true; f.state.tenant = user
    const moved = await call(client, 'get_message', input)
    assert.equal(moved.isError, true); assert.match(moved.content[0].text, /workspace_mismatch/)
    f.state.tenant = workspace; f.state.grantsUser = workspace
    const wrongUser = await call(client, 'get_message', input)
    assert.equal(wrongUser.isError, true); assert.match(wrongUser.content[0].text, /account_mismatch/)
    f.state.grantsUser = user; f.state.grantEnabled = false
    assert.equal((await call(client, 'get_message', input)).isError, true)
    f.state.grantEnabled = true; f.state.tampered = true
    assert.equal(parsed(await call(client, 'get_message', input)).message.body.state, 'tampered')
    await privateFile(join(f.directory, 'service-key'), Buffer.alloc(32, 17).toString('base64url') + '\n')
    const wrongKey = await call(client, 'get_message', input)
    assert.equal(wrongKey.isError, true); noSecrets(wrongKey, f.secret)
  } finally { await f.close() }
})

test('tool arguments cannot select origins, credentials, workspace, paths or oversized limits', async () => {
  const f = await fixture()
  try {
    const { client } = await f.connect()
    for (const arguments_ of [
      { server: 'https://other.example.test' }, { token_file: '/private/token' }, { workspace: user },
    ]) {
      const result = await call(client, 'list_numbers', arguments_)
      assert.equal(result.isError, true)
    }
    for (const limit of [0, 101, 1.5]) assert.equal((await call(client, 'list_chats', { device_id: vector.device, limit })).isError, true)
    assert.equal((await call(client, 'get_message', { device_id: vector.device, uid: '../auth/me' })).isError, true)
    assert.equal((await call(client, 'list_chats', { device_id: hiddenDevice })).isError, true)
    assert.equal(f.state.requests.length, 0, 'invalid scope never reaches the archive')
  } finally { await f.close() }
})

test('configuration rejects mixed identity, implicit plaintext, world-readable files, symlinks and expired sessions', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wappie-mcp-config-'))
  try {
    const base = { server: 'https://example.test', workspace, token_file: 'token' }
    assert.throws(() => validateConfig({ ...base, session_file: 'session' }))
    assert.throws(() => validateConfig({ ...base, password_file: 'password' }))
    assert.throws(() => validateConfig({ ...base, service_key_file: 'key', service_user_id: user }))
    assert.throws(() => validateConfig({ ...base, allow_plaintext: true }))
    assert.throws(() => validateConfig({ ...base, allow_plaintext: true, service_key_file: 'key' }))
    assert.throws(() => validateConfig({ ...base, server: 'https://token@example.test' }))
    assert.throws(() => validateConfig({ ...base, server: 'http://public.example.test' }))
    const path = join(directory, 'secret')
    await privateFile(path, token)
    await chmod(path, 0o644)
    await assert.rejects(readPrivateFile(path), /private_file_required/)
    await chmod(path, 0o600)
    const linked = join(directory, 'linked')
    await symlink(path, linked)
    await assert.rejects(readPrivateFile(linked), /private_file_unavailable/)
    await privateFile(join(directory, 'config.json'), JSON.stringify(base))
    assert.equal((await loadConfig(join(directory, 'config.json'))).token_file, join(directory, 'token'))
    await privateFile(join(directory, 'session'), JSON.stringify({ origin: base.server, tenantID: workspace, token, email: 'synthetic@example.test', userID: user, expiresAt: '2000-01-01T00:00:00Z' }))
    await assert.rejects(loadCredential(validateConfig({ ...base, token_file: undefined, session_file: 'session' }, directory)), /session_expired_or_wrong_scope/)
  } finally { await rm(directory, { recursive: true, force: true }) }
})

test('oversized directory results are refused without breaking the stdio connection', async () => {
  const f = await fixture()
  try {
    const { client } = await f.connect({ device_ids: undefined })
    f.state.largeDirectory = true
    const result = await call(client, 'list_numbers')
    assert.equal(result.isError, true)
    assert.match(result.content[0].text, /result_too_large/)
    f.state.largeDirectory = false
    assert.equal(parsed(await call(client, 'list_numbers')).numbers.length, 2)
  } finally { await f.close() }
})

test('hostile password challenges and oversized auth responses fail before unlocking; stdio remains usable', async () => {
  const f = await fixture()
  try {
    const { client } = await f.connect({ token_file: undefined, session_file: './session.json', allow_plaintext: true, password_file: './password' })
    const input = { device_id: vector.device, uid: body.row }
    const baseline = f.state.kdfParams
    for (const costs of [
      { m: 2147483647 }, { t: 1000000 }, { p: 1000 }, { m: 0 }, { t: -1 }, { p: 1.5 }, { m: '65536' }, { t: null },
    ]) {
      f.state.kdfParams = { ...baseline, ...costs }
      const result = await call(client, 'get_message', input)
      assert.equal(result.isError, true)
      assert.match(result.content[0].text, /kdf_cost_exceeded/)
      noSecrets(result, f.secret)
    }
    assert.equal(f.state.requests.some(request => request.path === '/v1/auth/me'), false, 'invalid costs are refused before account/key unlocking')
    f.state.kdfParams = baseline; f.state.oversizedMe = true
    const large = await call(client, 'get_message', input)
    assert.equal(large.isError, true); assert.match(large.content[0].text, /response_too_large/)
    f.state.oversizedMe = false
    assert.equal(parsed(await call(client, 'get_message', input)).message.body.value, plain)
  } finally { await f.close() }
})
