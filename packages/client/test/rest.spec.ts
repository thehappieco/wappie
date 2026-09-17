import { afterEach, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { ArchiveClient } from '../src/api/rest.js'
import { Opener } from '../src/api/opener.js'
import { fromBase64, parseUUID } from '../src/crypto/bytes.js'
import { importArchiveKey } from '../src/crypto/hpke.js'
import { Kind } from '../src/crypto/seal.js'

const tenant = '018f3a2b-2222-7000-8000-00000000bbbb'
const device = '018f3a2b-2222-7000-8000-00000000dddd'
const uid = '018f3a2b-2222-7000-8000-00000000eeee'
const client = (fetcher: typeof fetch) => new ArchiveClient({ serverURL: 'https://archive.example.test', workspaceID: tenant, token: 'synthetic-secret', fetch: fetcher })
const json = (data: object, status = 200) => new Response(JSON.stringify({ tenant_id: tenant, ...data }), { status })
afterEach(() => vi.unstubAllGlobals())

it('scopes fixed read-only REST routes, encodes chat keys, and preserves server pagination', async () => {
  const fetcher = vi.fn<typeof fetch>(async () => json({ chat_key: 'group+1@g.us', messages: [], has_more: true, next_ts: '2026-09-01T12:00:00Z', next_seq: 35 }))
  const page = await client(fetcher).listMessages(device, { chatKey: 'group+1@g.us', limit: 12, before: { ts: '2026-09-01T12:01:00Z', seq: 42 } })
  const [url, init] = fetcher.mock.calls[0]
  expect(new URL(String(url)).pathname).toBe(`/v1/devices/${device}/messages`)
  expect(new URL(String(url)).searchParams.get('chat_key')).toBe('group+1@g.us')
  expect(new URL(String(url)).searchParams.get('before_seq')).toBe('42')
  expect(init).toMatchObject({ method: 'GET', redirect: 'error', cache: 'no-store', credentials: 'omit', headers: { Authorization: 'Bearer synthetic-secret' } })
  expect(page).toMatchObject({ has_more: true, next_seq: 35 })
})

it('rejects another workspace and never reflects a server error message or token', async () => {
  await expect(client(vi.fn(async () => json({ tenant_id: uid, devices: [] }))).listDevices()).rejects.toMatchObject({ code: 'workspace_mismatch' })
  await expect(client(vi.fn(async () => json({ code: 'not_authorized', message: 'synthetic-secret' }, 403))).listDevices()).rejects.toMatchObject({ code: 'not_authorized', status: 403 })
  await expect(client(vi.fn(async () => json({ code: 'not_authorized', message: 'synthetic-secret' }, 403))).listDevices()).rejects.not.toThrow('synthetic-secret')
})

it('rejects arbitrary origins, paths and invalid page/key limits before network access', async () => {
  const fetcher = vi.fn<typeof fetch>()
  for (const serverURL of ['http://archive.example.test', 'https://name:secret@example.test', 'https://example.test/a', 'https://example.test/?x=1']) {
    expect(() => new ArchiveClient({ serverURL, workspaceID: tenant, token: 'synthetic-secret', fetch: fetcher })).toThrow()
  }
  const api = client(fetcher)
  await expect(api.listChats('../../auth/me')).rejects.toThrow()
  await expect(api.listMessages(device, { chatKey: 'x', limit: 201 })).rejects.toThrow()
  await expect(api.listMessages(device, { chatKey: 'x', before: { ts: 'invalid', seq: 1 } })).rejects.toThrow()
  await expect(api.listMessages(device, { chatKey: 'x', before: { ts: '2026-09-01T12:00:00Z', seq: 0 } })).rejects.toThrow()
  await expect(api.contentKeys(device, Array.from({ length: 501 }, (_, index) => index + 1))).rejects.toThrow()
  await expect(api.contentKeys(device, [2147483648])).rejects.toThrow()
  expect(fetcher).not.toHaveBeenCalled()
})

it('rejects swapped message, history and chat identities from a compatible external server', async () => {
  const row = { uid, device_id: device, chat_key: 'one', wa_id: 'wa-one', seq: 1, is_from_me: false, kind: 'message', type: 'text', source: 'live' }
  await expect(client(vi.fn(async () => json({ ...row, uid: device }))).getMessage(uid)).rejects.toMatchObject({ code: 'message_mismatch' })
  await expect(client(vi.fn(async () => json({ requested_uid: device, device_id: device, chat_key: 'one', wa_id: 'wa-one', versions: [{ revision: 0, message: row }] }))).history(uid)).rejects.toMatchObject({ code: 'message_mismatch' })
  await expect(client(vi.fn(async () => json({ requested_uid: uid, device_id: device, chat_key: 'one', wa_id: 'wa-one', versions: [{ revision: 0, message: { ...row, device_id: uid } }] }))).history(uid)).rejects.toMatchObject({ code: 'device_mismatch' })
  await expect(client(vi.fn(async () => json({ requested_uid: uid, device_id: device, chat_key: 'one', wa_id: 'wa-one', versions: [{ revision: 0, message: { ...row, uid: device } }] }))).history(uid)).resolves.toMatchObject({ requested_uid: uid })
  await expect(client(vi.fn(async () => json({ chat_key: 'two', messages: [row], has_more: false }))).listMessages(device, { chatKey: 'one' })).rejects.toMatchObject({ code: 'chat_mismatch' })
})

it('reports malformed response shapes using sanitized ArchiveError codes', async () => {
  const cases: [object, (api: ArchiveClient) => Promise<unknown>][] = [
    [{ devices: null }, api => api.listDevices()],
    [{ device_id: device, chats: [null], limit: 1, truncated: false }, api => api.listChats(device)],
    [{ chat_key: 'x', messages: {}, has_more: false }, api => api.listMessages(device, { chatKey: 'x' })],
    [{ uid, device_id: device, body_sealed: 'synthetic-secret' }, api => api.getMessage(uid)],
    [{ device_id: device, chat_key: 'x', wa_id: 'a', versions: null }, api => api.history(uid)],
    [{ user_id: device, grants: [{ device_id: device, epoch: 'synthetic-secret' }] }, api => api.grants()],
    [{ device_id: device, keys: [{ id: 3, sealed: 'synthetic-secret' }] }, api => api.contentKeys(device, [1])],
  ]
  for (const [data, invoke] of cases) {
    await expect(invoke(client(vi.fn(async () => json(data))))).rejects.toMatchObject({ name: 'ArchiveError', code: 'invalid_response' })
  }
})

it('limits the Opener adapter to keys.get and to its pinned device', async () => {
  const fetcher = vi.fn<typeof fetch>(async () => json({ device_id: device, keys: [] }))
  const source = client(fetcher).keySource(device)
  await expect(source.request('messages.send', {}, 'sent')).rejects.toThrow()
  await expect(source.request('keys.get', { device_id: uid, ids: [1] }, 'keys')).rejects.toThrow()
  expect(fetcher).not.toHaveBeenCalled()
  await source.request('keys.get', { device_id: device, ids: [1] }, 'keys')
  expect(new URL(String(fetcher.mock.calls[0][0])).pathname).toBe(`/v1/devices/${device}/keys`)
})

it('opens a Go-generated ciphertext over REST after a workspace move', async () => {
  const vector = JSON.parse(readFileSync(new URL('../../../internal/crypto/seal/testdata/vectors.json', import.meta.url), 'utf8'))
  const fetcher = vi.fn<typeof fetch>(async () => json({ device_id: vector.device, archive_tenant_id: vector.tenant, keys: [vector.content_key] }))
  const api = client(fetcher)
  const opener = new Opener(api.keySource(vector.device), parseUUID(tenant), parseUUID(vector.device), vector.device, await importArchiveKey(fromBase64(vector.private_key)))
  const body = vector.batch.find((item: { kind: number }) => item.kind === Kind.Body)
  expect(await opener.raw(vector.content_key.id, body.row, Kind.Body, body.sealed)).toEqual({ state: 'ok', value: fromBase64(body.plaintext) })
})

it('reads bounded encrypted contact pages without starting contact discovery', async () => {
 const contacts = [{uid,contact_key:'100@lid',content_key_id:1,full_name_sealed:'c2VhbGVk'}]
 const fetcher=vi.fn<typeof fetch>(async()=>json({device_id:device,contacts,has_more:true,next_key:'100@lid'}))
 await expect(client(fetcher).listContacts(device,{limit:2,afterKey:'099@lid'})).resolves.toMatchObject({contacts,next_key:'100@lid'})
 const url=new URL(String(fetcher.mock.calls[0][0]))
 expect(url.pathname).toBe(`/v1/devices/${device}/contacts`)
 expect(url.searchParams.get('after_key')).toBe('099@lid')
 await expect(client(vi.fn(async()=>json({device_id:uid,contacts:[],has_more:false}))).listContacts(device)).rejects.toMatchObject({code:'device_mismatch'})
 await expect(client(vi.fn(async()=>json({device_id:device,contacts:[{uid,contact_key:'x',content_key_id:-1}],has_more:false}))).listContacts(device)).rejects.toMatchObject({code:'invalid_response'})
 await expect(client(vi.fn(async()=>json({device_id:device,contacts,has_more:true,next_key:'099@lid'}))).listContacts(device,{afterKey:'099@lid'})).rejects.toMatchObject({code:'invalid_response'})
})
const scanFrom='2026-09-17T00:00:00.000000001Z',scanUntil='2026-09-18T00:00:00Z'
const scanMessage={uid,device_id:device,sender_key:'123@lid',chat_key:'one',wa_id:'wa-one',seq:1,is_from_me:false,kind:'message',type:'text',source:'live',order_ts:scanFrom}
it('scans a whole device using exact sender aliases and effective timestamp cursors',async()=>{
 const fetcher=vi.fn<typeof fetch>(async()=>json({device_id:device,from:scanFrom,until:scanUntil,messages:[scanMessage],has_more:true,next_ts:scanFrom,next_seq:1}))
 const reply=await client(fetcher).scanMessages(device,{from:scanFrom,until:scanUntil,senderKeys:['123@lid','15551234567@s.whatsapp.net'],chatKey:'one',direction:'incoming',type:'text',kind:'message',limit:2})
 expect(reply.messages[0].ts).toBeUndefined()
 const url=new URL(String(fetcher.mock.calls[0][0]))
 expect(url.pathname).toBe(`/v1/devices/${device}/messages/scan`)
 expect(url.searchParams.get('sender_keys')).toBe('123@lid,15551234567@s.whatsapp.net')
 expect(url.searchParams.get('from')).toBe(scanFrom)
})
it('rejects device scans with invalid bounds and malformed or unrelated results',async()=>{
 const fetcher=vi.fn<typeof fetch>()
 const api=client(fetcher)
 for(const options of [{from:scanUntil,until:scanFrom},{from:scanFrom,until:scanFrom},{from:'today',until:scanUntil},{from:scanFrom,until:scanUntil,senderKeys:['a','b','c','d']},{from:scanFrom,until:scanUntil,senderKeys:['a,b']},{from:scanFrom,until:scanUntil,limit:201}]) await expect(api.scanMessages(device,options)).rejects.toThrow()
 expect(fetcher).not.toHaveBeenCalled()
 const base={device_id:device,from:scanFrom,until:scanUntil,messages:[scanMessage],has_more:false}
 for(const patch of [{device_id:uid},{from:scanUntil},{messages:[{...scanMessage,device_id:uid}]},{messages:[{...scanMessage,order_ts:'2026-09-17T00:00:00Z'}]},{messages:[{...scanMessage,order_ts:scanUntil}]},{messages:[{...scanMessage,ts:scanUntil}]},{has_more:true,next_ts:scanUntil,next_seq:1},{messages:[scanMessage,scanMessage]}]) await expect(client(vi.fn(async()=>json({...base,...patch}))).scanMessages(device,{from:scanFrom,until:scanUntil})).rejects.toThrow()
})
