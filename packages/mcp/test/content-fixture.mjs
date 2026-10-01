// A larger synthetic archive for the hosted modes: many sealed messages in one
// interval, contacts across several pages and a history route that can be
// slowed down. It records every request's method and raw target, so tests can
// compare what the archive saw. Nothing here is a real credential.
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { bytes, hpke, seal } from '@whatserver2/client'

export const vector = JSON.parse(await readFile(new URL('../../../internal/crypto/seal/testdata/vectors.json', import.meta.url), 'utf8'))
export const workspace = '018f3a2b-2222-7000-8000-00000000bbbb'
export const service = '018f3a2b-2222-7000-8000-00000000aaaa'
export const device = vector.device
export const token = `a1b2c3d4.${Buffer.alloc(32, 42).toString('base64url')}`
export const uid = n => `018f3a2b-2222-7000-8000-${String(n).padStart(12, '0')}`
export const at = '2026-09-15T20:00:00.000Z'
export const interval = { device_id: device, from: '2026-09-15T00:00:00.000Z', until: '2026-09-16T00:00:00.000Z' }
export const hitText = 'Resultado do exame disponível.'
export const missText = 'Bom dia, tudo certo por aqui.'
export const contactKey = n => `${String(n).padStart(6, '0')}@lid`

/**
 * `rows` messages at seq 1..rows (even seqs carry `hitText`, odd ones
 * `missText`), `contacts` contacts served 500 per page in key order (the
 * first is named 'Archived Roberto'), and `scanPage`, the most rows one scan
 * page returns. `state.historyDelayMs` slows the history route, and
 * `state.maxHistoryInFlight` records the most history requests open at once.
 * `addMedia(fields)` adds a message with an attachment, served only by
 * `GET /v1/messages/{uid}`, its media key, preview, filename and caption
 * sealed like the archive seals them. `addChat(fields)` adds a chat, and
 * `state.number` fields (`pn`, `lid`) join the number's device row. `token`
 * replaces the bearer it accepts.
 */
export async function contentFixture({ rows: rowCount = 120, contacts: contactCount = 2200, scanPage = 40, token: bearer = token } = {}) {
  const account = await hpke.generateKeyPair()
  const namespace = bytes.parseUUID(vector.tenant), deviceBytes = bytes.parseUUID(device)
  const rawKey = crypto.getRandomValues(new Uint8Array(32))
  const aes = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt'])
  const keyID = 99
  const keyName = new Uint8Array(20); keyName.set(deviceBytes); new DataView(keyName.buffer).setUint32(16, keyID, false)
  const sealedKey = await seal.sealDirect(bytes.fromBase64(vector.public_key), seal.Kind.ContentKey, namespace, await bytes.uuidV5(namespace, keyName), 1, rawKey)
  rawKey.fill(0)
  const grantFor = async epoch => bytes.toBase64(await seal.sealDirect(account.publicKey, seal.Kind.DeviceGrant, namespace,
    await seal.grantRow(namespace, deviceBytes, bytes.parseUUID(service), epoch), epoch, bytes.fromBase64(vector.private_key)))
  const grants = { 1: await grantFor(1), 2: await grantFor(2) }
  async function encrypt(row, kind, value) {
    const header = new Uint8Array([0x57, 0x53, 1, 1, 2, 0, 1, 0])
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const aad = bytes.concat(bytes.encodeUTF8('wsv1'), new Uint8Array([kind]), namespace, bytes.parseUUID(row), header)
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, aes, typeof value === 'string' ? bytes.encodeUTF8(value) : value))
    const id = new Uint8Array(4); new DataView(id.buffer).setUint32(0, keyID, false)
    return bytes.toBase64(bytes.concat(header, id, nonce, ciphertext))
  }
  const rows = []
  for (let seq = 1; seq <= rowCount; seq++) {
    const row = { uid: uid(seq), seq, device_id: device, wa_id: `synthetic-${seq}`, chat_key: '5511999990000@s.whatsapp.net',
      ts: at, order_ts: at, is_from_me: false, kind: 'message', type: 'text', source: 'live', content_key_id: keyID }
    row.body_sealed = await encrypt(row.uid, seal.Kind.Body, seq % 2 === 0 ? hitText : missText)
    rows.push(row)
  }
  const contacts = []
  for (let n = 1; n <= contactCount; n++) {
    const contact = { uid: uid(10_000 + n), contact_key: contactKey(n), contact_lid: contactKey(n), content_key_id: keyID }
    if (n === 1) contact.full_name_sealed = await encrypt(contact.uid, seal.Kind.FullName, 'Archived Roberto')
    contacts.push(contact)
  }
  const messages = new Map()
  /**
   * A message with an attachment: `key` (32 bytes) is sealed as its media
   * key, `thumbnail` as its preview, `filename` and `caption` as the archive
   * seals them. `tamper` flips a byte of the sealed key; `keyID` names a
   * content key the archive does not serve (the key is then locked);
   * `object` is the ciphertext `GET /v1/media/{uid}` serves.
   */
  const objects = new Map()
  async function addMedia({ uid: id = uid(50_000 + messages.size), device_id = device, key, thumbnail, filename, caption, tamper = false, keyID: sealedUnder = keyID, media = {}, object, ...fields } = {}) {
    if (object) objects.set(id, object)
    const row = { uid: id, seq: 1, device_id, wa_id: `synthetic-media-${messages.size}`, chat_key: '5511999990000@s.whatsapp.net', ts: at, is_from_me: false,
      kind: 'message', type: media.media_type ?? 'image', source: 'live', content_key_id: sealedUnder, ...fields, media: { download_status: 'done', ...media } }
    if (key) {
      const sealed = bytes.fromBase64(await encrypt(id, seal.Kind.MediaKey, key))
      if (tamper) sealed[sealed.length - 1] ^= 1
      row.media.media_key_sealed = bytes.toBase64(sealed)
    }
    if (thumbnail) row.media.thumb_sealed = await encrypt(id, seal.Kind.Thumbnail, thumbnail)
    if (filename) row.media.filename_sealed = await encrypt(id, seal.Kind.ContactName, filename)
    if (caption) row.body_sealed = await encrypt(id, seal.Kind.Body, caption)
    messages.set(id, row)
    return row
  }
  /**
   * Chats the chats route serves (none unless added): `addChat` seals a
   * chat's name under its uid and its preview under `last_uid`, as the
   * archive does; `chat_key=` narrows the list to one, as §17.3's filter does.
   */
  const chats = []
  async function addChat({ chat_key, name, preview, is_group = false, chat_pn, chat_lid, keys, last_ts, uid: id = uid(70_000 + chats.length) } = {}) {
    const chat = { uid: id, chat_key, last_seq: 1, is_group, ...(chat_pn ? { chat_pn } : {}), ...(chat_lid ? { chat_lid } : {}), ...(keys ? { keys } : {}), ...(last_ts ? { last_ts } : {}) }
    if (name !== undefined) { chat.name_key_id = keyID; chat.name_sealed = await encrypt(id, seal.Kind.ContactName, name) }
    if (preview !== undefined) { chat.last_uid = uid(80_000 + chats.length); chat.last_body_key_id = keyID; chat.last_body_sealed = await encrypt(chat.last_uid, seal.Kind.Body, preview) }
    chats.push(chat)
    return chat
  }
  const state = { requests: [], grantEpoch: 1, historyDelayMs: 0, historyInFlight: 0, maxHistoryInFlight: 0, number: {} }
  const http = createServer(async (request, response) => {
    const url = new URL(request.url, 'http://localhost'), path = url.pathname
    state.requests.push({ method: request.method, target: request.url, path })
    const send = (value, status = 200) => { response.writeHead(status, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(value)) }
    const reply = value => send({ tenant_id: workspace, ...value })
    if (request.headers.authorization !== `Bearer ${bearer}` || request.method !== 'GET') return send({ code: 'not_authorized' }, 403)
    if (path.startsWith('/v1/media/')) {
      const object = objects.get(path.slice('/v1/media/'.length))
      if (!object) return send({ code: 'not_found' }, 404)
      response.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': String(object.length) })
      return response.end(object)
    }
    if (path.startsWith('/v1/messages/') && !path.endsWith('/history')) {
      const row = messages.get(path.slice('/v1/messages/'.length)) ?? rows.find(item => path.endsWith(item.uid))
      return row ? reply(row) : send({ code: 'not_found' }, 404)
    }
    if (path === '/v1/devices') return reply({ devices: [{ id: device, label: 'Número autorizado', status: 'online', ...state.number }] })
    if (path === '/v1/grants') return reply({ user_id: service, grants: [{ device_id: device, epoch: state.grantEpoch, archive_tenant_id: vector.tenant, sealed_dsk: grants[state.grantEpoch] }] })
    if (path.endsWith('/chats')) {
      const key = url.searchParams.get('chat_key')
      return reply({ device_id: device, limit: Number(url.searchParams.get('limit')), truncated: false, chats: key === null ? chats : chats.filter(chat => chat.chat_key === key) })
    }
    if (path.endsWith('/keys')) return reply({ device_id: device, archive_tenant_id: vector.tenant,
      keys: (url.searchParams.get('ids') ?? '').split(',').includes(String(keyID)) ? [{ id: keyID, epoch: 1, sealed: bytes.toBase64(sealedKey) }] : [] })
    if (path.endsWith('/contacts')) {
      const after = url.searchParams.get('after_key')
      const limit = Number(url.searchParams.get('limit'))
      const rest = after ? contacts.filter(item => item.contact_key > after) : contacts
      const page = rest.slice(0, limit)
      const more = rest.length > limit
      return reply({ device_id: device, contacts: page, has_more: more, ...(more ? { next_key: page.at(-1).contact_key } : {}) })
    }
    if (path.endsWith('/messages/scan')) {
      const from = url.searchParams.get('from'), until = url.searchParams.get('until')
      let selected = rows.filter(row => row.order_ts >= from && row.order_ts < until)
      const before = url.searchParams.get('before_seq')
      if (before) selected = selected.filter(row => row.seq < Number(before))
      selected = selected.sort((a, b) => b.seq - a.seq)
      const limit = Math.min(Number(url.searchParams.get('limit')), scanPage)
      const page = selected.slice(0, limit).reverse()
      const more = selected.length > limit
      return reply({ device_id: device, from, until, messages: page, has_more: more, ...(more ? { next_ts: page[0].order_ts, next_seq: page[0].seq } : {}) })
    }
    if (path.endsWith('/history')) {
      const row = rows.find(item => path.includes(item.uid))
      if (!row) return send({ code: 'not_found' }, 404)
      state.historyInFlight++
      state.maxHistoryInFlight = Math.max(state.maxHistoryInFlight, state.historyInFlight)
      await new Promise(resolve => setTimeout(resolve, state.historyDelayMs))
      state.historyInFlight--
      return reply({ requested_uid: row.uid, device_id: device, chat_key: row.chat_key, wa_id: row.wa_id, versions: [{ revision: 0, from: row.ts, message: row }] })
    }
    return send({ code: 'not_found' }, 404)
  })
  await new Promise(resolve => http.listen(0, '127.0.0.1', resolve))
  const server = `http://127.0.0.1:${http.address().port}`
  const secret = Buffer.from(account.privateKey)
  account.privateKey.fill(0)
  return {
    state, server, rows, contacts, addMedia, addChat,
    /** The service key as the attested reader holds it: a non-extractable handle. */
    handle: () => hpke.importArchiveKey(Buffer.from(secret)),
    /** The raw service key, for tests that prove bytes are refused. */
    secretBytes: () => Buffer.from(secret),
    /** Every request since `mark`, as method plus raw target (path and query). */
    since: mark => state.requests.slice(mark).map(item => `${item.method} ${item.target}`),
    async close() { secret.fill(0); await new Promise(resolve => http.close(resolve)) },
  }
}
