// Synthetic archive fixture shared by the MCP test suites: an HPKE account, a
// sealed device grant over the Go seal vectors and a node:http REST stand-in
// that records every request. Nothing here is a real credential.
import { createServer as createHTTPServer } from 'node:http'
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { Client } from '@modelcontextprotocol/client'
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio'
import { bytes, hpke, seal } from '@whatserver2/client'
import { derive, freshSalt, wrapPrivateKey } from '@whatserver2/client/crypto/account'

export const vector = JSON.parse(await readFile(new URL('../../../internal/crypto/seal/testdata/vectors.json', import.meta.url), 'utf8'))
export const body = vector.batch.find(item => item.kind === seal.Kind.Body)
export const chatName = vector.batch.find(item => item.kind === seal.Kind.ContactName)
export const workspace = '018f3a2b-2222-7000-8000-00000000bbbb'
export const user = '018f3a2b-2222-7000-8000-00000000aaaa'
export const hiddenDevice = '018f3a2b-2222-7000-8000-00000000eeee'
const defaultToken = 'synthetic-mcp-credential-never-returned'
export const token = defaultToken
export const password = 'synthetic-mcp-password-never-returned'
export const plain = Buffer.from(body.plaintext, 'base64').toString('utf8')
export const privateFile = (path, data) => writeFile(path, data, { mode: 0o600 })

/**
 * Starts the synthetic REST server and private credential files in a fresh
 * directory. `options.token` substitutes the bearer the stand-in accepts (a
 * hosted reader needs the 52-char API-key shape); `connect` spawns the real
 * stdio CLI against it and `close` tears everything down.
 */
export async function fixture(options = {}) {
  const token = options.token ?? defaultToken
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
    state, directory, secret, server, token,
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
export const call = (client, name, args = {}) => client.callTool({ name, arguments: args })
export const parsed = result => result.structuredContent || JSON.parse(result.content[0].text)
export function noSecrets(result, secret, extra = []) {
  const text = JSON.stringify(result)
  for (const value of [token, password, secret, vector.private_key, vector.content_key.sealed, body.sealed, ...extra]) assert.equal(text.includes(value), false)
  assert.equal(text.includes('body_sealed'), false)
  assert.equal(text.includes('sealed_dsk'), false)
}
