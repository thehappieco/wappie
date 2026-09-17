import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, stat, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { serverOrigin, sessionPath, saveSession, loadSession, execute, request } from '../lib.mjs'

const signed = { token: 'opaque-session', email: 'owner@example.test', tenantID: 'workspace', userID: 'owner', expiresAt: new Date(Date.now() + 60_000), accountKey: 'private-never-persist', password: 'password-never-persist' }
async function fixture(t) { const dir = await mkdtemp(join(tmpdir(), 'wsctl-')); t.after(() => rm(dir, { recursive: true, force: true })); return dir }
test('origin restrictions and sessions isolate installations', async t => {
 const dir = await fixture(t)
 assert.equal(serverOrigin('https://EXAMPLE.test:443/'), 'https://example.test')
 for (const url of ['http://public.test', 'https://user:pass@a.test', 'https://a.test/path', 'https://a.test#x']) assert.throws(() => serverOrigin(url))
 await saveSession(dir, 'https://one.test', signed)
 const path = sessionPath(dir, 'https://one.test')
 assert.equal((await stat(path)).mode & 0o777, 0o600)
 const stored = await readFile(path, 'utf8')
 assert.ok(!stored.includes('private-never-persist') && !stored.includes('password-never-persist'))
 assert.equal((await loadSession(dir, 'https://one.test')).token, signed.token)
 await assert.rejects(loadSession(dir, 'https://two.test'))
})
test('login uses public SDK, saves no password and prints no token', async t => {
 const dir = await fixture(t); const output = []; let input
 await execute(['login', '--server', 'https://one.test', '--email', signed.email, '--state-dir', dir], { secret: async () => 'entered-password', print: value => output.push(value) }, { auth: { signIn: async value => { input = value; return signed } } })
 assert.equal(input.password, 'entered-password')
 assert.equal((await loadSession(dir, 'https://one.test')).token, signed.token)
 assert.ok(!JSON.stringify(output).includes(signed.token))
})
test('authenticated request cannot leave selected origin or follow redirects', async () => {
 let called = false
 await assert.rejects(request('https://one.test', 'secret', 'GET', '//two.test/v1/steal', undefined, async () => { called = true }))
 assert.equal(called, false)
 const result = await request('https://one.test', 'secret', 'GET', '/v1/auth/me', undefined, async (url, options) => {
  assert.equal(url.origin, 'https://one.test'); assert.equal(options.redirect, 'error'); assert.equal(options.headers.Authorization, 'Bearer secret')
  return new Response('{"ok":true}')
 })
 assert.deepEqual(result, { ok: true })
})
test('websocket request uses bound session and closes after response', async t => {
 const dir = await fixture(t); await saveSession(dir, 'https://one.test', signed)
 let closed = false; const output = []
 await execute(['ws', 'devices.list', '--reply', 'devices', '--server', 'https://one.test', '--state-dir', dir], { print: value => output.push(value) }, { Connection: { connect: async options => {
  assert.equal(options.credential.kind, 'session'); assert.equal(options.credential.token, signed.token)
  return { request: async (type, payload, reply) => { assert.equal(type, 'devices.list'); assert.equal(reply, 'devices'); return { devices: [] } }, close: () => { closed = true } }
 } } })
 assert.equal(closed, true); assert.deepEqual(output, [{ devices: [] }])
})
test('signup reserves recovery output privately and never overwrites', async t => {
 const dir = await fixture(t); const recovery = join(dir, 'recovery.txt'); let calls = 0
 const argv = ['signup', '--email', signed.email, '--server', 'https://one.test', '--state-dir', dir, '--recovery-out', recovery]
 const io = { print: () => {}, secret: async () => 'password' }
 const sdk = { auth: { signUp: async () => { calls++; return { session: signed, recoveryCode: 'safe-code' } } } }
 await execute(argv, io, sdk)
 assert.equal(await readFile(recovery, 'utf8'), 'safe-code\n')
 assert.equal((await stat(recovery)).mode & 0o777, 0o600)
 await assert.rejects(execute(argv, io, sdk)); assert.equal(calls, 1)
})

test('real public SDK login derives proof locally and opens account key', async t => {
 const { createServer } = await import('node:http')
 const { derive, freshSalt, generateAccountKeys, wrapPrivateKey } = await import('@whatserver2/client/crypto/account')
 const { toBase64 } = await import('@whatserver2/client/crypto/bytes')
 const { randomUUID } = await import('node:crypto')
 const dir = await fixture(t); const password = 'private CLI password'
 const salt = freshSalt(); const params = { alg: 'argon2id', m: 32, t: 1, p: 1 }
 const keys = await generateAccountKeys(); const derived = await derive(password, salt, params)
 const user = { id: randomUUID(), tenant_id: randomUUID(), email: 'owner@example.test', role: 'owner', public_key: toBase64(keys.publicKey), wrapped_usk: toBase64(await wrapPrivateKey(keys.privateKey, derived.wrapKey, 'owner@example.test')), has_recovery: true }
 let loginProof
 const server = createServer(async (req, res) => {
  let body = ''; for await (const chunk of req) body += chunk
  res.setHeader('content-type', 'application/json')
  if (req.url === '/v1/auth/challenge') res.end(JSON.stringify({ salt: toBase64(salt), params }))
  else if (req.url === '/v1/auth/login') { loginProof = JSON.parse(body); res.end(JSON.stringify({ token: 'real-sdk-token', expires_at: new Date(Date.now() + 60_000).toISOString(), user })) }
  else if (req.url === '/v1/auth/me') res.end(JSON.stringify({ user, grants: [] }))
  else { res.statusCode = 404; res.end('{}') }
 })
 await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); t.after(() => new Promise(resolve => server.close(resolve)))
 const origin = `http://127.0.0.1:${server.address().port}`
 await execute(['login', '--email', user.email, '--server', origin, '--state-dir', dir], { secret: async () => password, print: () => {} })
 assert.equal(loginProof.auth_key, derived.authKey)
 assert.equal(loginProof.password, undefined)
 assert.equal((await loadSession(dir, origin)).token, 'real-sdk-token')
 keys.privateKey.fill(0)
})

test('grant seals only to verified workspace recipient and sends no raw key', async t => {
 const dir = await fixture(t); await saveSession(dir, 'https://one.test', signed)
 const sent = []; let closed = false
 const sdk = {
  Connection: { connect: async () => ({ request: async (type, payload) => {
   sent.push({ type, payload })
   return type === 'users.list' ? { users: [{ id: 'recipient', public_key: 'verified-key' }] } : { readers: [] }
  }, close: () => { closed = true } }) },
  auth: { withDeviceKey: async (input, use) => use(new Uint8Array([99]), 7) },
  bytes: { parseUUID: value => value, fromBase64: value => value, toBase64: () => 'sealed-envelope' },
  seal: { Kind: { DeviceGrant: 4 }, grantRow: async () => 'bound-row', sealDirect: async (key, kind, tenant, row, epoch, raw) => {
   assert.equal(key, 'verified-key'); assert.equal(tenant, signed.tenantID); assert.equal(epoch, 7); assert.equal(raw[0], 99)
   return new Uint8Array([1])
  } },
 }
 await execute(['grant', '--server', 'https://one.test', '--state-dir', dir, '--device', 'device', '--user', 'recipient'], { secret: async () => 'password', print: () => {} }, sdk)
 assert.deepEqual(sent[1], { type: 'grant.add', payload: { device_id: 'device', user_id: 'recipient', epoch: 7, sealed_dsk: 'sealed-envelope' } })
 assert.equal(closed, true)
})
