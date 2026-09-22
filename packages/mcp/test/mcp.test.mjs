import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm, chmod, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { loadConfig, loadCredential, readPrivateFile, validateConfig } from '../config.mjs'
import { fixture, call, parsed, noSecrets, privateFile, vector, body, chatName, workspace, user, hiddenDevice, token, password, plain } from './fixture.mjs'

test('stdio initializes and lists eight bounded read-only tools; locked metadata never asks for keys', async () => {
  const f = await fixture()
  try {
    const { client, stderr } = await f.connect()
    assert.equal(client.getServerVersion().name, 'wappie-readonly')
    const listing = await client.listTools()
    assert.deepEqual(listing.tools.map(tool => tool.name), ['list_numbers', 'list_chats', 'list_messages', 'get_message', 'list_revisions', 'resolve_contact', 'search_messages', 'activity_summary'])
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
