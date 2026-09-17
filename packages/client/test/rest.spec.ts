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
