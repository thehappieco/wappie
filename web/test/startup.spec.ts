import { afterEach, describe, expect, it, vi } from 'vitest'
import { WebSocketServer } from 'ws'

import * as P from '../src/api/protocol'
import { Opener } from '../src/api/opener'
import { Media, type MediaState } from '../src/api/media'
import { importArchiveKey } from '../src/crypto/hpke'
import { avatars, connection, conversationPagingContext, fetchMedia, loadOlder, openChat, people, preferredReadableDevice, refreshChats, refreshDevices, selectDevice, start, state, stop, type MessageView } from '../src/state/archive'
import { readLastDevice, rememberLastDevice } from '../src/ui/lastDevice'
import { fromPastedKey } from '../src/state/session'
import { sweepDone, sweepUnsupported } from '../src/state/reproject'

const TENANT = '018f3a2b-2222-7000-8000-00000000aaaa'
const FIRST = '018f3a2b-2222-7000-8000-00000000bbbb'
const SECOND = '018f3a2b-2222-7000-8000-00000000cccc'
const FIRST_CHAT = '1111@s.whatsapp.net'
const SECOND_CHAT = '2222@s.whatsapp.net'
const UID = '018f3a2b-2222-7000-8000-00000000dddd'

type Respond = (payload: unknown, type?: string) => void
interface Fake {
  tenant: string
  devices: P.DeviceInfo[]
  url: string
  requests: P.Frame[]
  hold: Map<string, Respond[]>
  held: Set<string>
  chats: Map<string, P.ChatSummary[]>
  errors: Map<string, P.WireError>
  disconnect(): void
  close(): Promise<void>
}
const servers: Fake[] = []
const key = (type: string, device: string) => `${type}/${device}`

async function serve(): Promise<Fake> {
  const wss = new WebSocketServer({ port: 0 })
  await new Promise<void>((resolve) => wss.on('listening', resolve))
  const fake: Fake = {
    tenant: TENANT, devices: [FIRST, SECOND].map(id => ({ id, label: id, status: 'online', receipt_mode: 'passive', running: true, created_at: new Date().toISOString() })),
    url: `http://127.0.0.1:${(wss.address() as { port: number }).port}`,
    requests: [], hold: new Map(), held: new Set(), errors: new Map(),
    chats: new Map([
      [FIRST, [{ uid: UID, chat_key: FIRST_CHAT, last_seq: 1 }]],
      [SECOND, [{ uid: UID, chat_key: SECOND_CHAT, last_seq: 1 }]],
    ]),
    disconnect: () => wss.clients.forEach((socket) => socket.terminate()),
    close: () => new Promise<void>((resolve) => {
      wss.clients.forEach((socket) => socket.terminate())
      wss.close(() => resolve())
    }),
  }
  wss.on('connection', (socket) => socket.on('message', (data) => {
    const frame = JSON.parse(String(data)) as P.Frame
    fake.requests.push(frame)
    const device = (frame.p as { device_id?: string })?.device_id ?? ''
    const error = fake.errors.get(key(frame.t, device))
    if (error) {
      socket.send(JSON.stringify({ t: P.TypeError, r: frame.r, p: error }))
      return
    }
    const respond = (type: string, payload: unknown) => {
      const send: Respond = (value, replyType = type) => socket.send(JSON.stringify({ t: replyType, r: frame.r, p: value }))
      const heldKey = key(frame.t, device)
      if (fake.held.has(heldKey)) {
        const pending = fake.hold.get(heldKey) ?? []
        pending.push(send)
        fake.hold.set(heldKey, pending)
      } else send(payload)
    }
    switch (frame.t) {
      case P.TypeHello:
        respond(P.TypeWelcome, { version: P.VERSION, tenant_id: fake.tenant, features: [], server_ts: 0 })
        break
      case P.TypeDevicesList:
        respond(P.TypeDevices, { devices: fake.devices })
        break
      case P.TypeContacts:
      case P.TypeResolve:
        respond(P.TypeContactList, { device_id: device, contacts: [] })
        break
      case P.TypeChatsList:
        respond(P.TypeChats, { device_id: device, chats: fake.chats.get(device) ?? [] })
        break
      case P.TypeKeysGet:
        respond(P.TypeKeys, { device_id: device, keys: [] })
        break
      case P.TypeChatPage:
        respond(P.TypePage, { device_id: device, messages: [], has_more: false })
        break
      case P.TypeReprojectGet:
        respond(P.TypeUnsupportedRows, { device_id: device, rows: [] })
        break
    }
  }))
  servers.push(fake)
  return fake
}

async function boot(fake: Fake): Promise<void> {
  await start(fromPastedKey({
    label: 'test', serverURL: fake.url, apiKey: 'fixture-token',
    archive: await importArchiveKey(new Uint8Array(32).fill(7) as Uint8Array<ArrayBuffer>),
  }))
}

async function until(check: () => boolean, timeout = 1000): Promise<void> {
  for (let i = 0; i < timeout / 5; i++) {
    if (check()) return
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
  throw new Error('condition never held')
}

async function pending(fake: Fake, type: string, device: string): Promise<Respond> {
  const heldKey = key(type, device)
  await until(() => !!fake.hold.get(heldKey)?.length, 5000)
  return fake.hold.get(heldKey)!.shift()!
}

afterEach(async () => {
  stop()
  while (servers.length) await servers.pop()!.close()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('opening a large archive', () => {
  it('clears the previous workspace into loading while retaining login during navigation', async () => {
    const fake = await serve()
    await boot(fake)
    expect(state.phase).toBe('ready')
    expect(state.tenantID).toBe(TENANT)
    stop({ logout: false, transitioning: true })
    expect(state.phase).toBe('connecting')
    expect(state.tenantID).toBe('')
    expect(state.devices).toEqual([])
    expect(state.timeline).toEqual([])
    expect(connection()).toBeNull()
    stop()
    expect(state.phase).toBe('locked')
  })

  it.each([P.TypeDevicesList, P.TypeChatsList, P.TypeKeysGet])('reports %s failure instead of keeping the initial spinner', async (type) => {
    const fake = await serve()
    fake.chats.set(FIRST, [{ uid: UID, chat_key: FIRST_CHAT, last_seq: 1,
      last_uid: UID, last_body_key_id: 12, last_body_sealed: 'AA==',
    }])
    fake.errors.set(key(type, type === P.TypeDevicesList ? '' : FIRST), {
      code: P.ErrInternal, message: 'fixture initialization failure',
    })
    await boot(fake)
    expect(state.phase).toBe('error')
    expect(state.error).toBe('fixture initialization failure')
    expect(state.connected).toBe(false)
    expect(connection()).toBeNull()
    expect(state.reconnectIn).toBe(0)
    expect(state.initializingConnection).toBe(false)
  })

  it('uses names learned between decryption batches and resolves remaining unknown identities', async () => {
    const fake = await serve()
    const stranger = '9999@s.whatsapp.net'
    const secondBatch = 'second-batch@g.us'
    fake.chats.set(FIRST, Array.from({ length: 25 }, (_, i) => ({
      uid: UID, chat_key: i === 0 ? FIRST_CHAT : i === 1 ? stranger : i === 24 ? secondBatch : `${i}@g.us`,
      last_seq: i,
    })))
    fake.held.add(key(P.TypeContacts, FIRST))
    let releaseBatch!: () => void
    const gate = new Promise<void>((resolve) => { releaseBatch = resolve })
    let batchWaiting = false
    const original = Opener.prototype.chatName
    vi.spyOn(Opener.prototype, 'chatName').mockImplementation(function (this: Opener, chat) {
      if (chat.chat_key === secondBatch) {
        batchWaiting = true
        return gate.then(() => original.call(this, chat))
      }
      return original.call(this, chat)
    })
    vi.spyOn(Opener.prototype, 'contactNames').mockResolvedValue({
      full: { state: 'ok', value: 'Ana' }, business: { state: 'absent' }, push: { state: 'absent' },
    })

    const opening = boot(fake)
    const contacts = await pending(fake, P.TypeContacts, FIRST)
    await until(() => batchWaiting)
    // The first 24 rows have finished decryption. The address book finishes
    // while the second batch is pending and before any chat list is published.
    contacts({ device_id: FIRST, contacts: [{ uid: UID, contact_key: FIRST_CHAT }] })
    await until(() => state.contactsLoaded === 1)
    expect(state.chats).toEqual([])
    releaseBatch()
    await opening

    expect(state.chats.find((chat) => chat.key === FIRST_CHAT)?.name).toBe('Ana')
    await until(() => fake.requests.some((frame) => frame.t === P.TypeResolve))
    const resolved = fake.requests.filter((frame) => frame.t === P.TypeResolve)
      .flatMap((frame) => (frame.p as P.ContactsResolveRequest).contact_keys)
    expect(resolved).toContain(stranger)
    expect(resolved).not.toContain(FIRST_CHAT)
  })

  it('draws the chat list while the independent address book is still loading', async () => {
    const fake = await serve()
    fake.held.add(key(P.TypeContacts, FIRST))
    await boot(fake)
    expect(state.phase).toBe('ready')
    expect(state.chats[0]?.key).toBe(FIRST_CHAT)
    expect(state.contactsLoaded).toBe(0)
    const contacts = await pending(fake, P.TypeContacts, FIRST)
    contacts({ device_id: FIRST, contacts: [{ uid: UID, contact_key: FIRST_CHAT }] })
    await until(() => state.contactsLoaded === 1)
  })

  it('prefetches every preview key in one request and keeps that cache on refresh', async () => {
    const fake = await serve()
    fake.chats.set(FIRST, [11, 12, 13].map((id) => ({
      uid: UID, chat_key: `${id}@g.us`, last_seq: id, name_key_id: 4,
      last_uid: UID, last_body_key_id: id, last_body_sealed: 'AA==',
    })))
    await boot(fake)
    const requests = () => fake.requests.filter((frame) => frame.t === P.TypeKeysGet)
    expect(requests()).toHaveLength(1)
    expect((requests()[0]!.p as P.KeysRequest).ids).toEqual([4, 11, 12, 13])
    await refreshChats()
    expect(requests()).toHaveLength(1)
    expect(state.chats).toHaveLength(3)
  })

  it('keeps large preview-key batches within the server limit', async () => {
    const fake = await serve()
    fake.chats.set(FIRST, Array.from({ length: 503 }, (_, i) => ({
      uid: UID, chat_key: `${i}@g.us`, last_seq: i, last_uid: UID,
      last_body_key_id: i + 1, last_body_sealed: 'AA==',
    })))
    await boot(fake)
    const requests = fake.requests.filter((frame) => frame.t === P.TypeKeysGet)
    expect(requests.map((frame) => (frame.p as P.KeysRequest).ids.length)).toEqual([500, 3])
    expect(state.chats).toHaveLength(503)
  })
})

describe('conversation paging context and progress', () => {
  it('requires an open conversation and invalidates its snapshot after sign-out', async () => {
    expect(conversationPagingContext()).toBeNull()
    const fake = await serve()
    await boot(fake)
    expect(conversationPagingContext()).toBeNull()
    await openChat(FIRST_CHAT)
    const context = conversationPagingContext()!
    expect(context.current()).toBe(true)
    expect(context.cursor()).toBeNull()
    stop()
    expect(context.current()).toBe(false)
    expect(conversationPagingContext()).toBeNull()
  })

  it.each([FIRST_CHAT, SECOND_CHAT])('invalidates an earlier snapshot when opening %s, even after returning to the same chat', async nextChat => {
    const fake = await serve()
    await boot(fake)
    await openChat(FIRST_CHAT)
    const original = conversationPagingContext()!
    expect(original.current()).toBe(true)
    const reopening = openChat(nextChat)
    expect(original.current()).toBe(false)
    await reopening
    const replacement = conversationPagingContext()!
    expect(replacement.current()).toBe(true)
    await openChat(FIRST_CHAT)
    expect(original.current()).toBe(false)
    expect(replacement.current()).toBe(false)
    expect(conversationPagingContext()!.current()).toBe(true)
  })

  it('keeps snapshots invalid after changing device and returning to the same device and chat', async () => {
    const fake = await serve()
    await boot(fake)
    await openChat(FIRST_CHAT)
    const first = conversationPagingContext()!
    await selectDevice(SECOND)
    expect(first.current()).toBe(false)
    expect(conversationPagingContext()).toBeNull()
    await openChat(FIRST_CHAT)
    const second = conversationPagingContext()!
    expect(second.current()).toBe(true)
    await selectDevice(FIRST)
    await openChat(FIRST_CHAT)
    expect(state.deviceID).toBe(FIRST)
    expect(state.openChatKey).toBe(FIRST_CHAT)
    expect(first.current()).toBe(false)
    expect(second.current()).toBe(false)
    expect(conversationPagingContext()!.current()).toBe(true)
  })

  it('reports cursor progress on empty metadata-only pages, including changes to sequence alone', async () => {
    const fake = await serve()
    await boot(fake)
    fake.held.add(key(P.TypeChatPage, FIRST))
    const timestamp = '2026-09-01T00:00:00Z'
    const opening = openChat(FIRST_CHAT)
    ;(await pending(fake, P.TypeChatPage, FIRST))({
      device_id: FIRST, messages: [], has_more: true, next_ts: timestamp, next_seq: 40,
    })
    await opening
    const context = conversationPagingContext()!
    expect(context.cursor()).toBe(JSON.stringify([timestamp, 40]))

    const older = loadOlder()
    const reply = await pending(fake, P.TypeChatPage, FIRST)
    const sent = fake.requests.filter(frame => frame.t === P.TypeChatPage)
    expect(sent.at(-1)!.p).toMatchObject({ device_id: FIRST, chat_key: FIRST_CHAT, before_ts: timestamp, before_seq: 40 })
    expect(await loadOlder()).toEqual({ status: 'idle' })
    expect(fake.requests.filter(frame => frame.t === P.TypeChatPage)).toHaveLength(sent.length)
    // A page can contain only cursor metadata and no messages property at all.
    reply({ device_id: FIRST, has_more: true, next_ts: timestamp, next_seq: 25 })
    expect(await older).toEqual({ status: 'loaded', before: JSON.stringify([timestamp, 40]), after: JSON.stringify([timestamp, 25]) })
    expect(state.timeline).toEqual([])
    expect(context.current()).toBe(true)
    expect(context.cursor()).toBe(JSON.stringify([timestamp, 25]))
    expect(state.hasOlder).toBe(true)

    const final = loadOlder()
    ;(await pending(fake, P.TypeChatPage, FIRST))({ device_id: FIRST, messages: [], has_more: false })
    expect(await final).toEqual({ status: 'loaded', before: JSON.stringify([timestamp, 25]), after: null })
    expect(context.cursor()).toBeNull()
    expect(state.hasOlder).toBe(false)
    expect(state.loadingOlder).toBe(false)
    expect(await loadOlder()).toEqual({ status: 'idle' })
  })

  it('returns stale for an older page from a previous opening of the same chat without clearing the new request', async () => {
    const fake = await serve()
    await boot(fake)
    fake.held.add(key(P.TypeChatPage, FIRST))
    const timestamp = '2026-09-01T00:00:00Z'
    const first = openChat(FIRST_CHAT)
    ;(await pending(fake, P.TypeChatPage, FIRST))({ device_id: FIRST, messages: [], has_more: true, next_ts: timestamp, next_seq: 40 })
    await first
    const original = conversationPagingContext()!
    const oldLoading = loadOlder()
    const oldReply = await pending(fake, P.TypeChatPage, FIRST)
    const reopening = openChat(FIRST_CHAT)
    ;(await pending(fake, P.TypeChatPage, FIRST))({ device_id: FIRST, messages: [], has_more: true, next_ts: timestamp, next_seq: 80 })
    await reopening
    const replacement = conversationPagingContext()!
    const newLoading = loadOlder()
    const newReply = await pending(fake, P.TypeChatPage, FIRST)

    oldReply({ device_id: FIRST, messages: [], has_more: false })
    expect(await oldLoading).toEqual({ status: 'stale' })
    expect(original.current()).toBe(false)
    expect(replacement.current()).toBe(true)
    expect(replacement.cursor()).toBe(JSON.stringify([timestamp, 80]))
    expect(state.loadingOlder).toBe(true)
    expect(state.hasOlder).toBe(true)

    newReply({ device_id: FIRST, messages: [], has_more: true, next_ts: timestamp, next_seq: 60 })
    expect(await newLoading).toEqual({ status: 'loaded', before: JSON.stringify([timestamp, 80]), after: JSON.stringify([timestamp, 60]) })
    expect(state.loadingOlder).toBe(false)
  })

  it('returns stale after a device change and preserves the new conversation’s cursor', async () => {
    const fake = await serve()
    await boot(fake)
    fake.held.add(key(P.TypeChatPage, FIRST))
    const first = openChat(FIRST_CHAT)
    ;(await pending(fake, P.TypeChatPage, FIRST))({ device_id: FIRST, messages: [], has_more: true, next_ts: '2026-09-01T00:00:00Z', next_seq: 40 })
    await first
    const original = conversationPagingContext()!
    const older = loadOlder()
    const oldReply = await pending(fake, P.TypeChatPage, FIRST)
    await selectDevice(SECOND)
    await openChat(SECOND_CHAT)
    const replacement = conversationPagingContext()!
    oldReply({ device_id: FIRST, messages: [], has_more: true, next_ts: '2026-08-01T00:00:00Z', next_seq: 20 })
    expect(await older).toEqual({ status: 'stale' })
    expect(original.current()).toBe(false)
    expect(replacement.current()).toBe(true)
    expect(replacement.cursor()).toBeNull()
    expect(state.openChatKey).toBe(SECOND_CHAT)
    expect(state.hasOlder).toBe(false)
    expect(state.loadingOlder).toBe(false)
  })
})

describe('changing devices while requests are outstanding', () => {
  it.each([P.TypeHello, P.TypeDevicesList])('keeps reconnect and live subscription intact while %s is pending', async (type) => {
    const fake = await serve()
    await boot(fake)
    await sweepDone()
    const subscriptions = () => fake.requests.filter((frame) => frame.t === P.TypeSubscribe).length
    await until(() => subscriptions() === 1)
    fake.held.add(key(type, ''))
    fake.disconnect()
    await until(() => !state.connected)
    await expect(selectDevice(SECOND)).rejects.toThrow('Aguarde a reconexão')
    const reply = await pending(fake, type, '')
    expect(state.initializingConnection).toBe(true)
    await expect(selectDevice(SECOND)).rejects.toThrow('Aguarde a reconexão')
    expect(state.deviceID).toBe(FIRST)
    reply(type === P.TypeHello
      ? { version: P.VERSION, tenant_id: TENANT, features: [], server_ts: 0 }
      : { devices: [FIRST, SECOND].map((id) => ({
        id, label: id, status: 'online', receipt_mode: 'passive', running: true,
        created_at: new Date().toISOString(),
      })) })
    await until(() => !state.initializingConnection && subscriptions() === 2)
    expect(state.connected).toBe(true)
    await selectDevice(SECOND)
    expect(state.chats[0]?.key).toBe(SECOND_CHAT)
  })

  it('resets older-page loading when opening another conversation', async () => {
    const fake = await serve()
    await boot(fake)
    fake.held.add(key(P.TypeChatPage, FIRST))
    const first = openChat(FIRST_CHAT)
    ;(await pending(fake, P.TypeChatPage, FIRST))({
      device_id: FIRST, messages: [], has_more: true, next_ts: '2026-09-01T00:00:00Z', next_seq: 2,
    })
    await first
    const older = loadOlder()
    const oldReply = await pending(fake, P.TypeChatPage, FIRST)
    expect(state.loadingOlder).toBe(true)
    const second = openChat(SECOND_CHAT)
    expect(state.loadingOlder).toBe(false)
    expect(state.hasOlder).toBe(false)
    ;(await pending(fake, P.TypeChatPage, FIRST))({
      device_id: FIRST, messages: [], has_more: true, next_ts: '2026-09-02T00:00:00Z', next_seq: 4,
    })
    await second
    oldReply({ device_id: FIRST, messages: [], has_more: false })
    expect(await older).toEqual({ status: 'stale' })
    expect(state.loadingOlder).toBe(false)
    expect(state.hasOlder).toBe(true)
    const more = loadOlder()
    ;(await pending(fake, P.TypeChatPage, FIRST))({ device_id: FIRST, messages: [], has_more: false })
    await more
    expect(state.loadingOlder).toBe(false)
    expect(state.hasOlder).toBe(false)
  })

  it('can retry the selected device after its chat list failed', async () => {
    const fake = await serve()
    await boot(fake)
    const failureKey = key(P.TypeChatsList, SECOND)
    fake.errors.set(failureKey, { code: P.ErrInternal, message: 'fixture switch failure' })
    await expect(selectDevice(SECOND)).rejects.toThrow('fixture switch failure')
    expect(state.deviceID).toBe(SECOND)
    expect(state.chats).toEqual([])
    expect(state.loadingChat).toBe(false)
    expect(state.loadingOlder).toBe(false)
    fake.errors.delete(failureKey)
    await selectDevice(SECOND)
    expect(state.chats[0]?.key).toBe(SECOND_CHAT)
    expect(state.actionError).toBe('')
  })

  it('does not publish a failed selection after another device has opened', async () => {
    const fake = await serve()
    await boot(fake)
    fake.held.add(key(P.TypeChatsList, SECOND))
    const selecting = selectDevice(SECOND)
    const reply = await pending(fake, P.TypeChatsList, SECOND)
    await selectDevice(FIRST)
    reply({ code: P.ErrInternal, message: 'old selection failed' }, P.TypeError)
    await selecting
    expect(state.deviceID).toBe(FIRST)
    expect(state.chats[0]?.key).toBe(FIRST_CHAT)
    expect(state.actionError).toBe('')
  })

  it('does not start an old attachment download after changing device during key opening', async () => {
    const fake = await serve()
    await boot(fake)
    let unlock!: () => void
    const gate = new Promise<void>((resolve) => { unlock = resolve })
    vi.spyOn(Opener.prototype, 'mediaKey').mockImplementation(async () => {
      await gate
      return { state: 'ok', value: new Uint8Array(32) }
    })
    const download = vi.spyOn(Media.prototype, 'open')
    const view = { entry: { row: { uid: UID, device_id: FIRST, media: {} } }, media: {} } as MessageView
    const loading = fetchMedia(view)
    await selectDevice(SECOND)
    unlock()
    await loading
    expect(download).not.toHaveBeenCalled()
    expect(view.media?.full).toBeUndefined()
  })

  it('does not publish an attachment result after sign-out', async () => {
    const fake = await serve()
    await boot(fake)
    vi.spyOn(Opener.prototype, 'mediaKey').mockResolvedValue({ state: 'ok', value: new Uint8Array(32) })
    let finish!: (result: MediaState) => void
    const download = vi.spyOn(Media.prototype, 'open').mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    const view = { entry: { row: { uid: UID, device_id: FIRST, media: {} } }, media: {} } as MessageView
    const loading = fetchMedia(view)
    await until(() => download.mock.calls.length > 0)
    stop()
    finish({ state: 'ready', url: 'blob:old-session', bytes: 1 })
    await loading
    expect(view.media?.full?.state).toBe('pending')
    expect(state.phase).toBe('locked')
  })

  it('does not add the former device contacts to the new directory', async () => {
    const fake = await serve()
    fake.held.add(key(P.TypeContacts, FIRST))
    await boot(fake)
    const contacts = await pending(fake, P.TypeContacts, FIRST)
    await selectDevice(SECOND)
    contacts({ device_id: FIRST, contacts: [{ uid: UID, contact_key: FIRST_CHAT }] })
    await new Promise((resolve) => setTimeout(resolve, 25))
    expect(state.deviceID).toBe(SECOND)
    expect(state.chats[0]?.key).toBe(SECOND_CHAT)
    expect(people().find(FIRST_CHAT)).toBeUndefined()
    expect(state.contactsLoaded).toBe(0)
  })

  it('discards the former device chat refresh and clears its cached pictures and panels', async () => {
    const fake = await serve()
    await boot(fake)
    fake.held.add(key(P.TypeChatsList, FIRST))
    const refreshing = refreshChats()
    const chats = await pending(fake, P.TypeChatsList, FIRST)
    avatars.set(FIRST_CHAT, URL.createObjectURL(new Blob(['fixture'])))
    state.selectedUID = UID
    state.groupPanel = true
    await selectDevice(SECOND)
    chats({ device_id: FIRST, chats: fake.chats.get(FIRST) })
    await refreshing
    expect(state.chats[0]?.key).toBe(SECOND_CHAT)
    expect(avatars.size).toBe(0)
    expect(state.selectedUID).toBe('')
    expect(state.groupPanel).toBe(false)
  })

  it('discards a conversation page that arrives after changing device', async () => {
    const fake = await serve()
    await boot(fake)
    fake.held.add(key(P.TypeChatPage, FIRST))
    const opening = openChat(FIRST_CHAT)
    const page = await pending(fake, P.TypeChatPage, FIRST)
    await selectDevice(SECOND)
    page({ device_id: FIRST, messages: [{
      uid: UID, device_id: FIRST, seq: 1, wa_id: 'old-device-message',
      chat_key: FIRST_CHAT, kind: 'message', type: 'text',
    }], has_more: true })
    await opening
    expect(state.timeline).toEqual([])
    expect(state.openChatKey).toBe('')
    expect(state.hasOlder).toBe(false)
    expect(state.loadingChat).toBe(false)
  })

  it('discards a conversation page when the mobile reader returns to the list', async () => {
    const fake = await serve()
    await boot(fake)
    fake.held.add(key(P.TypeChatPage, FIRST))
    const opening = openChat(FIRST_CHAT)
    const page = await pending(fake, P.TypeChatPage, FIRST)
    state.openChatKey = ''
    state.loadingChat = false
    page({ device_id: FIRST, messages: [], has_more: true })
    await opening
    expect(state.hasOlder).toBe(false)
    expect(state.loadingChat).toBe(false)
  })

  it('cancels the old maintenance pass before opening or sending its rows', async () => {
    const fake = await serve()
    await boot(fake)
    await sweepDone()
    fake.held.add(key(P.TypeReprojectGet, FIRST))
    const sweeping = sweepUnsupported()
    const rows = await pending(fake, P.TypeReprojectGet, FIRST)
    await selectDevice(SECOND)
    rows({ device_id: FIRST, rows: [{
      uid: UID, seq: 1, wa_id: 'old-maintenance-row', content_key_id: 991, raw_sealed: 'AA==',
    }] })
    await sweeping
    await sweepDone()
    expect(fake.requests.filter((frame) => frame.t === P.TypeReprojectPut)).toEqual([])
    expect(fake.requests.filter((frame) => frame.t === P.TypeKeysGet)).toEqual([])
    expect(state.unsupported.total).toBe(0)
    expect(state.unsupported.lastRun?.unreadable).toBe(0)
  })
})

it('ignores a devices refresh that belongs to the previous workspace', async () => {
  const fake = await serve()
  await boot(fake)
  fake.held.add(key(P.TypeDevicesList, ''))
  const refresh = refreshDevices()
  const respond = await pending(fake, P.TypeDevicesList, '')
  state.tenantID = '018f3a2b-2222-7000-8000-00000000eeee'
  state.devices = []
  respond({devices:[{id:FIRST,label:'Previous workspace',status:'online',receipt_mode:'passive',running:true,created_at:new Date().toISOString()}]})
  await refresh
  expect(state.devices).toEqual([])
})


const USER = '018f3a2b-2222-7000-8000-000000001111'
const OTHER_USER = '018f3a2b-2222-7000-8000-000000002222'
const OTHER_TENANT = '018f3a2b-2222-7000-8000-000000003333'
function deviceStorage() {
  const saved = new Map<string, string>()
  vi.stubGlobal('localStorage', { getItem: (key: string) => saved.get(key) ?? null, setItem: (key: string, value: string) => saved.set(key, value) })
  vi.stubGlobal('location', new URL('https://client.example.test/'))
  vi.stubGlobal('history', { state: { retained: 'browser-state' }, replaceState: vi.fn((_state, _title, url: string) => { vi.stubGlobal('location', new URL(url)) }) })
  return saved
}
function scope(fake: Fake, userID = USER, workspaceID = fake.tenant) {
  return { serverOrigin: fake.url, userID, workspaceID }
}
async function accountBoot(fake: Fake, userID = USER, readable = [FIRST, SECOND], workspace = fake.tenant) {
  const session = fromPastedKey({ label: 'Synthetic account', serverURL: fake.url, apiKey: 'synthetic-bearer',
    archive: await importArchiveKey(new Uint8Array(32).fill(7) as Uint8Array<ArrayBuffer>) })
  session.credential.kind = 'session'
  session.account = { userID, email: 'person@example.test', tenantID: workspace, hasRecovery: true }
  session.readable = readable.map(deviceID => ({ deviceID, label: deviceID }))
  await start(session)
  return session
}

describe('remembering an account number within its workspace', () => {
  it('restores the last successfully opened number after logout and a fresh sign-in', async () => {
    const saved = deviceStorage(), fake = await serve()
    await accountBoot(fake)
    await selectDevice(SECOND)
    expect(readLastDevice(scope(fake))).toBe(SECOND)
    expect(new URLSearchParams(location.search).get('device')).toBe(SECOND)
    expect([...saved.values()]).toEqual([SECOND])
    expect(JSON.stringify([...saved])).not.toMatch(/person@example|synthetic-bearer/)
    stop()
    expect(new URLSearchParams(location.search).has('device')).toBe(false)
    expect(readLastDevice(scope(fake))).toBe(SECOND)
    await accountBoot(fake)
    expect(state.deviceID).toBe(SECOND)
  })
  it('keeps different users, workspaces and servers independent', async () => {
    deviceStorage(); const fake = await serve()
    await accountBoot(fake); await selectDevice(SECOND); stop()
    await accountBoot(fake, OTHER_USER); expect(state.deviceID).toBe(FIRST); stop()
    fake.tenant = OTHER_TENANT
    await accountBoot(fake); expect(state.deviceID).toBe(FIRST); stop()
    fake.tenant = TENANT
    await accountBoot(fake); expect(state.deviceID).toBe(SECOND); stop()
    const other = await serve()
    await accountBoot(other); expect(state.deviceID).toBe(FIRST)
  })
  it('gives an explicitly linked authorized number priority over the saved choice', async () => {
    deviceStorage(); const fake = await serve()
    rememberLastDevice(scope(fake), SECOND)
    vi.stubGlobal('location', new URL(`https://client.example.test/?workspace=${TENANT}&device=${FIRST}`))
    await accountBoot(fake)
    expect(state.deviceID).toBe(FIRST)
    expect(readLastDevice(scope(fake))).toBe(FIRST)
  })
  it.each(['missing', 'unauthorized', 'other-workspace'])('ignores a %s linked number and restores the allowed saved choice', async kind => {
    deviceStorage(); const fake = await serve()
    rememberLastDevice(scope(fake), FIRST)
    const workspace = kind === 'other-workspace' ? OTHER_TENANT : TENANT
    const device = kind === 'missing' ? '018f3a2b-2222-7000-8000-000000009999' : SECOND
    vi.stubGlobal('location', new URL(`https://client.example.test/?workspace=${workspace}&device=${device}`))
    await accountBoot(fake, USER, kind === 'unauthorized' ? [FIRST] : [FIRST, SECOND])
    expect(state.deviceID).toBe(FIRST)
    expect(fake.requests.filter(frame => frame.t === P.TypeChatsList).map(frame => (frame.p as {device_id:string}).device_id)).toEqual([FIRST])
  })
  it('ignores a revoked saved choice and a revoked retained choice instead of opening an unreadable device', async () => {
    deviceStorage(); const fake = await serve()
    rememberLastDevice(scope(fake), SECOND)
    state.deviceID = SECOND
    await accountBoot(fake, USER, [FIRST])
    expect(state.deviceID).toBe(FIRST)
    expect(readLastDevice(scope(fake))).toBe(FIRST)
    await selectDevice(SECOND)
    expect(state.deviceID).toBe(FIRST)
    expect(readLastDevice(scope(fake))).toBe(FIRST)
  })
  it('opens the console when there are no readable devices and never stores an unauthorized choice', async () => {
    const saved = deviceStorage(), fake = await serve()
    await accountBoot(fake, USER, [])
    expect(state.view).toBe('admin'); expect(state.deviceID).toBe('')
    expect(fake.requests.some(frame => frame.t === P.TypeChatsList)).toBe(false)
    expect(saved.size).toBe(0)
  })
  it('uses the same preferred number when returning from a freshly loaded console', async () => {
    deviceStorage(); const fake = await serve()
    rememberLastDevice(scope(fake), SECOND)
    vi.stubGlobal('location', new URL('https://client.example.test/console'))
    await accountBoot(fake)
    expect(state.view).toBe('admin'); expect(state.deviceID).toBe('')
    expect(preferredReadableDevice()?.id).toBe(SECOND)
    expect(fake.requests.some(frame => frame.t === P.TypeChatsList)).toBe(false)
  })
  it('does not write preferences for pasted keys or a mismatched authenticated workspace', async () => {
    const saved = deviceStorage(), fake = await serve()
    await boot(fake); await selectDevice(SECOND)
    expect(saved.size).toBe(0); stop()
    await accountBoot(fake, USER, [FIRST, SECOND], OTHER_TENANT)
    expect(saved.size).toBe(0)
  })
  it('retains the current authorized choice on reconnect even if browser history cannot replace an old link', async () => {
    deviceStorage(); const fake = await serve()
    vi.stubGlobal('location', new URL(`https://client.example.test/?device=${FIRST}`))
    vi.stubGlobal('history', { state: null, replaceState() { throw new Error('history denied') } })
    await accountBoot(fake); await selectDevice(SECOND)
    expect(new URLSearchParams(location.search).get('device')).toBe(FIRST)
    fake.disconnect()
    await until(() => !state.connected)
    await until(() => state.connected && !state.initializingConnection, 5000)
    expect(state.deviceID).toBe(SECOND)
  })
  it('clears the previous conversation and device data when reconnect falls back from a removed number', async () => {
    deviceStorage(); const fake = await serve()
    await accountBoot(fake); await openChat(FIRST_CHAT)
    expect(state.openChatKey).toBe(FIRST_CHAT)
    fake.devices = fake.devices.filter(device => device.id === SECOND)
    fake.requests = []
    fake.disconnect(); await until(() => !state.connected)
    await until(() => state.connected && !state.initializingConnection, 5000)
    expect(state.deviceID).toBe(SECOND); expect(state.openChatKey).toBe('')
    expect(fake.requests.some(frame => frame.t === P.TypeChatPage)).toBe(false)
    expect(state.chats[0]?.key).toBe(SECOND_CHAT)
  })
  it('does not remember a late device response after logout', async () => {
    deviceStorage(); const fake = await serve()
    await accountBoot(fake)
    fake.held.add(key(P.TypeChatsList, SECOND))
    const switching = selectDevice(SECOND)
    const response = await pending(fake, P.TypeChatsList, SECOND)
    // Keep the synthetic transport alive so an already in-flight response can
    // arrive after local logout; production disconnect may discard it sooner.
    vi.spyOn(connection()!, 'close').mockImplementation(() => {})
    stop(); response({ device_id: SECOND, chats: [] })
    await switching
    expect(readLastDevice(scope(fake))).toBe(FIRST)
    expect(state.phase).toBe('locked')
    expect(new URLSearchParams(location.search).has('device')).toBe(false)
  })
})
