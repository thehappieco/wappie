import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Client } from '@modelcontextprotocol/client'
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio'
import { bytes, hpke, seal } from '@whatserver2/client'
import { sealContactPack } from '@whatserver2/client/crypto/contactPack'
const vector = JSON.parse(await readFile(new URL('../../../internal/crypto/seal/testdata/vectors.json', import.meta.url), 'utf8'))
const workspace = '018f3a2b-2222-7000-8000-00000000bbbb'
const user = '018f3a2b-2222-7000-8000-00000000aaaa'
const device = vector.device
const uid = n => `018f3a2b-2222-7000-8000-${String(n).padStart(12, '0')}`
const token = 'synthetic-search-token'
const phone = '5511999990000@s.whatsapp.net'
const lid = '777@lid'
const privateFile = (path, data) => writeFile(path, data, { mode: 0o600 })
const parsed = result => { assert.notEqual(result.isError, true, result.content?.[0]?.text); return result.structuredContent || JSON.parse(result.content[0].text) }
const call = (client, name, args) => client.callTool({ name, arguments: args })
async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'wappie-search-'))
  const account = await hpke.generateKeyPair()
  const namespace = bytes.parseUUID(vector.tenant), deviceBytes = bytes.parseUUID(device)
  const rawKey = crypto.getRandomValues(new Uint8Array(32))
  const aes = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt'])
  const keyID = 99
  const keyName = new Uint8Array(20); keyName.set(deviceBytes); new DataView(keyName.buffer).setUint32(16, keyID, false)
  const keyRow = await bytes.uuidV5(namespace, keyName)
  const sealedKey = await seal.sealDirect(bytes.fromBase64(vector.public_key), seal.Kind.ContentKey, namespace, keyRow, 1, rawKey)
  rawKey.fill(0)
  const grant = await seal.sealDirect(account.publicKey, seal.Kind.DeviceGrant, namespace,
    await seal.grantRow(namespace, deviceBytes, bytes.parseUUID(user), 1), 1, bytes.fromBase64(vector.private_key))
  async function encrypt(row, kind, text) {
    const header = new Uint8Array([0x57, 0x53, 1, 1, 2, 0, 1, 0])
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const aad = bytes.concat(bytes.encodeUTF8('wsv1'), new Uint8Array([kind]), namespace, bytes.parseUUID(row), header)
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, aes, bytes.encodeUTF8(text)))
    const id = new Uint8Array(4); new DataView(id.buffer).setUint32(0, keyID, false)
    return bytes.toBase64(bytes.concat(header, id, nonce, ciphertext))
  }
  const rows = []
  for (let seq = 1; seq <= 5; seq++) {
    const row = { uid: uid(seq), seq, device_id: device, wa_id: `synthetic-${seq}`, chat_key: seq === 5 ? '123@g.us' : phone,
      sender_key: lid, sender_lid: lid, sender_pn: phone, is_group: seq === 5, is_from_me: seq === 4,
      ts: '2026-09-15T20:00:00.000Z', order_ts: '2026-09-15T20:00:00.000Z', kind: 'message', type: seq === 3 ? 'document' : 'text', source: 'live', content_key_id: keyID }
    row.body_sealed = await encrypt(row.uid, seal.Kind.Body, seq === 4 ? 'x '.repeat(1000) + 'A reunião será amanhã.' : seq === 3 ? 'Segue o arquivo.' : 'Resultado do exame disponível.')
    if (seq === 3) row.media = { media_type: 'document', mimetype: 'application/vnd.ms-excel', file_length: 15, download_status: 'downloaded', filename_sealed: await encrypt(row.uid, seal.Kind.ContactName, 'planilha-exame.xlsx') }
    if (seq === 4) row.reply_to = 'synthetic-reply-target'
    rows.push(row)
  }
  const contact = { uid: uid(20), contact_key: lid, contact_lid: lid, contact_pn: phone, content_key_id: keyID,
    full_name_sealed: await encrypt(uid(20), seal.Kind.FullName, 'Archived Roberto') }
  const state = { authorized: true, grants: true, requests: [], revokeAfterContacts: false, revokeAfterHistory: false, tamper: false, contactsMore: false, zeroScan: false, loop: false }
  const http = createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost'), path = url.pathname
    state.requests.push({ path, query: Object.fromEntries(url.searchParams), method: request.method })
    const send = (value, status = 200) => { response.writeHead(status, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(value)) }
    const reply = value => send({ tenant_id: workspace, ...value })
    if (!state.authorized || request.headers.authorization !== `Bearer ${token}`) return send({ code: 'not_authorized' }, 403)
    if (request.method !== 'GET') return send({ code: 'bad_request' }, 400)
    if (path === '/v1/grants') return reply({ user_id: user, grants: state.grants ? [{ device_id: device, epoch: 1, archive_tenant_id: vector.tenant, sealed_dsk: bytes.toBase64(grant) }] : [] })
    if (path.endsWith('/keys')) return reply({ device_id: device, archive_tenant_id: vector.tenant, keys: [{ id: keyID, epoch: 1, sealed: bytes.toBase64(sealedKey) }] })
    if (path.endsWith('/chats')) return reply({ device_id: device, limit: Number(url.searchParams.get('limit')), truncated: false, chats: [] })
    if (path.endsWith('/contacts')) {
      if (state.revokeAfterContacts) state.grants = false
      return reply({ device_id: device, contacts: url.searchParams.has('after_key') ? [] : [contact], has_more: state.contactsMore && !url.searchParams.has('after_key'), ...(state.contactsMore && !url.searchParams.has('after_key') ? { next_key: lid } : {}) })
    }
    if (path.endsWith('/messages/scan')) {
      const from = url.searchParams.get('from'), until = url.searchParams.get('until')
      let selected = state.zeroScan ? [] : rows.filter(row => row.order_ts >= from && row.order_ts < until)
      const before = url.searchParams.get('before_seq')
      if (before && !state.loop) selected = selected.filter(row => row.seq < Number(before))
      const senderKeys = url.searchParams.get('sender_keys')?.split(',')
      if (senderKeys) selected = selected.filter(row => senderKeys.some(key => [row.sender_key, row.sender_pn, row.sender_lid].includes(key)))
      for (const field of ['type', 'kind', 'chat_key']) if (url.searchParams.has(field)) selected = selected.filter(row => row[field] === url.searchParams.get(field))
      if (url.searchParams.has('direction')) selected = selected.filter(row => row.is_from_me === (url.searchParams.get('direction') === 'outgoing'))
      selected = selected.sort((a, b) => b.seq - a.seq)
      const limit = Math.min(Number(url.searchParams.get('limit')), 2)
      const page = selected.slice(0, limit).reverse().map(row => ({ ...row }))
      if (state.tamper && page.length) { const sealed = Buffer.from(page[0].body_sealed, 'base64'); sealed[sealed.length - 1] ^= 1; page[0].body_sealed = sealed.toString('base64') }
      const more = selected.length > limit
      return reply({ device_id: device, from, until, messages: page, has_more: more, ...(more ? { next_ts: page[0].order_ts, next_seq: page[0].seq } : {}) })
    }
    if (path.endsWith('/history')) {
      const row = rows.find(item => path.includes(item.uid))
      if (!row) return send({ code: 'not_found' }, 404)
      if (state.revokeAfterHistory) state.authorized = false
      return reply({ requested_uid: row.uid, device_id: device, chat_key: row.chat_key, wa_id: row.wa_id, versions: [{ revision: 0, from: row.ts, message: row }],
        ...(row.seq === 2 ? { deletion: { at: '2026-09-16T20:00:00Z', by_author: true, message: { ...row, uid: uid(50), kind: 'delete' } } } : {}) })
    }
    return send({ code: 'not_found' }, 404)
  })
  await new Promise(resolve => http.listen(0, '127.0.0.1', resolve))
  const server = `http://127.0.0.1:${http.address().port}`
  const scope = { server_url: server, workspace_id: workspace, service_user_id: user, device_ids: [device] }
  const pack = await sealContactPack(account.publicKey, scope, [{ name: 'Robérto Personal', phones: ['+5511999990000'] }])
  await privateFile(join(directory, 'token'), token)
  await privateFile(join(directory, 'key'), Buffer.from(account.privateKey).toString('base64url'))
  await privateFile(join(directory, 'contacts.enc.json'), JSON.stringify(pack))
  account.privateKey.fill(0)
  const clients = []
  return { state, pack, directory,
    async connect(extra = {}) {
      const config = { server, workspace, token_file: './token', service_key_file: './key', service_user_id: user, allow_plaintext: true,
        device_ids: [device], contacts_file: './contacts.enc.json', timezone: 'America/Sao_Paulo', max_text_chars: 128, ...extra }
      const configPath = join(directory, `config-${clients.length}.json`)
      await privateFile(configPath, JSON.stringify(config))
      const transport = new StdioClientTransport({ command: process.execPath, args: [fileURLToPath(new URL('../cli.mjs', import.meta.url)), '--config', configPath], stderr: 'pipe' })
      const client = new Client({ name: 'synthetic-context-test', version: '1' }, { versionNegotiation: { mode: 'auto' } })
      clients.push(client); await client.connect(transport); return client
    },
    async close() { for (const client of clients) await client.close(); await new Promise(resolve => http.close(resolve)); await rm(directory, { recursive: true, force: true }) },
  }
}
const interval = { device_id: device, from: '2026-09-15T00:00:00.000Z', until: '2026-09-16T00:00:00.000Z' }
test('cross-chat search decrypts complete text and filenames, continues within pages, and labels deleted history', async () => {
  const f = await fixture()
  try {
    const client = await f.connect()
    const first = parsed(await call(client, 'search_messages', { ...interval, query: 'exame', limit: 1 }))
    assert.equal(first.messages[0].is_group, true)
    assert.equal(first.has_more, true)
    const second = parsed(await call(client, 'search_messages', first.next))
    assert.equal(second.messages[0].attachment.filename.value, 'planilha-exame.xlsx')
    const third = parsed(await call(client, 'search_messages', second.next))
    assert.equal(third.messages[0].archive_status.state, 'deleted')
    const fourth = parsed(await call(client, 'search_messages', third.next))
    assert.equal(fourth.has_more, false)
    assert.equal(fourth.coverage.interval_exhausted, true)
    assert.equal(new Set([first, second, third, fourth].flatMap(result => result.messages.map(row => row.uid))).size, 4)
    const meeting = parsed(await call(client, 'search_messages', { ...interval, query: 'reuniao amanha' }))
    assert.equal(meeting.messages.length, 1)
    assert.match(meeting.messages[0].body.value, /reunião/)
    assert.equal(meeting.messages[0].reply_to, 'synthetic-reply-target')
    assert.equal(meeting.messages[0].source.device_id, device)
    for (const result of [first, second, third, fourth, meeting]) {
      const json = JSON.stringify(result)
      for (const secret of [token, 'body_sealed', 'sealed_dsk', vector.private_key]) assert.equal(json.includes(secret), false)
    }
    assert.equal(f.state.requests.every(item => item.method === 'GET'), true)
  } finally { await f.close() }
})
test('bounded scans report partial empty results and metadata activity keeps chats and directions distinct', async () => {
  const f = await fixture()
  try {
    const client = await f.connect({ max_scan_messages: 2 })
    const result = parsed(await call(client, 'search_messages', { ...interval, query: 'not present' }))
    assert.equal(result.messages.length, 0)
    assert.equal(result.coverage.examined, 2)
    assert.equal(result.coverage.interval_exhausted, false)
    assert.equal(result.has_more, true)
    const metadata = await f.connect({ allow_plaintext: false, service_key_file: undefined, service_user_id: undefined, contacts_file: undefined })
    const summary = parsed(await call(metadata, 'activity_summary', interval))
    assert.equal(summary.activity.reduce((sum, item) => sum + item.archived_messages, 0), 5)
    assert.equal(summary.activity.length, 3)
    assert.equal(summary.activity.filter(item => item.is_group).length, 1)
    assert.equal((await call(metadata, 'search_messages', { ...interval, query: 'exame' })).isError, true)
  } finally { await f.close() }
})
test('contact resolution opens only a scoped optional snapshot, exposes explicit aliases and rejects revoked access', async () => {
  const f = await fixture()
  try {
    const client = await f.connect()
    const result = parsed(await call(client, 'resolve_contact', { device_id: device, query: 'roberto' }))
    assert.equal(result.candidates.length, 1)
    assert.deepEqual(result.candidates[0].identifiers, [lid, phone])
    assert.equal(result.candidates[0].names.some(item => item.name === 'Robérto Personal'), true)
    assert.equal(result.coverage.complete, true)
    f.state.contactsMore = true
    const partial = parsed(await call(client, 'resolve_contact', { device_id: device, query: 'unknown' }))
    assert.equal(partial.coverage.complete, false)
    assert.equal(partial.next.after_key, lid)
    f.state.revokeAfterContacts = true
    const revoked = await call(client, 'resolve_contact', { device_id: device, query: 'roberto' })
    assert.equal(revoked.isError, true)
    assert.equal(JSON.stringify(revoked).includes('Robérto Personal'), false)
  } finally { await f.close() }
})
test('filters stay scoped, tampered text is not matched, and mid-search revocation discards plaintext', async () => {
  const f = await fixture()
  try {
    const client = await f.connect()
    const result = parsed(await call(client, 'search_messages', { ...interval, query: 'planilha', sender_keys: [lid, phone], has_attachment: true, type: 'document', direction: 'incoming' }))
    assert.equal(result.messages.length, 1)
    assert.equal(f.state.requests.find(item => item.path.endsWith('/scan')).query.sender_keys, `${lid},${phone}`)
    assert.equal((await call(client, 'search_messages', { ...interval, period: 'today' })).isError, true)
    assert.equal((await call(client, 'search_messages', { device_id: device, period: 'today', before: { ts: interval.from, seq: 1 } })).isError, true)
    f.state.tamper = true
    const damaged = parsed(await call(client, 'search_messages', { ...interval, query: 'reuniao' }))
    assert.equal(damaged.messages.length, 0)
    assert.ok(damaged.coverage.tampered > 0)
    f.state.tamper = false; f.state.revokeAfterHistory = true
    const revoked = await call(client, 'search_messages', { ...interval, query: 'exame' })
    assert.equal(revoked.isError, true)
    assert.equal(JSON.stringify(revoked).includes('Resultado'), false)
  } finally { await f.close() }
})
test('contact ciphertext moved to another scope is rejected without leaking snapshot data', async () => {
  const f = await fixture()
  try {
    const client = await f.connect()
    await privateFile(join(f.directory, 'contacts.enc.json'), JSON.stringify({ ...f.pack, workspace_id: user }))
    const result = await call(client, 'resolve_contact', { device_id: device, query: 'roberto' })
    assert.equal(result.isError, true)
    assert.match(result.content[0].text, /invalid_contact_pack/)
    assert.equal(JSON.stringify(result).includes('Personal'), false)
  } finally { await f.close() }
})
