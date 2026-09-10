import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ProtocolError } from '../src/api/client'
import * as P from '../src/api/protocol'
import type { MessageView, MediaView } from '../src/state/archive'

const fixture = vi.hoisted(() => {
  const conn = { request: vi.fn(), welcome: { features: ['message.send', 'message.send.media', 'chat.start'] } }
  return { conn, current: conn as typeof conn | null, token: 'token-a', serverURL: 'https://api.example.test',
    upload: vi.fn(), readMediaBlob: vi.fn(), fetch: vi.fn(), people: [] as { key: string; pn?: string; lid?: string }[],
    state: { tenantID: 'tenant-a', deviceID: 'device-a', openChatKey: '1111@lid', view: 'archive', connected: true, initializingConnection: false, unreadable: false,
      devices: [{ id: 'device-a', running: true, can_send: true }], chats: [] as { key: string; keys: string[]; isStatus?: boolean }[] } }
})
vi.mock('../src/state/archive', async () => {
  const { reactive } = await import('vue')
  fixture.state = reactive(fixture.state)
  return { state: fixture.state, connection: () => fixture.current, credential: () => ({ token: fixture.token, serverURL: fixture.serverURL }), readMediaBlob: fixture.readMediaBlob, people: () => ({ all: () => fixture.people }) }
})
vi.mock('../src/api/upload', () => ({ uploadAttachment: fixture.upload }))
vi.mock('../src/state/conversationActions', () => ({ normalizePhone: (value: string) => /^\+\d{7,15}$/.test(value) ? value : '' }))
import { canForward, createForwardBatch, createForwarder, destinationJID, forwardableContent, forwardOptions, forwardRecipientResolver, MAX_FORWARD_RECIPIENTS } from '../src/state/forwarding'

const to = '2222@lid'
const reference = { type: 'image', url: 'https://cdn.example.test/fresh', direct_path: '/fresh', media_key: 'new-key', file_sha256: 'new-hash', file_enc_sha256: 'new-encrypted-hash', file_length: 7 }
const controllers: { dispose(): void }[] = []
function message(over: Partial<MessageView> = {}): MessageView {
  return { uid: 'source-uid', waID: 'SOURCE-WA-ID', chatKey: '1111@lid', type: 'text', body: ' original text ', bodyState: 'ok',
    pending: undefined, deleted: false, isStatus: false, viewOnce: false, forwarded: true, forwardingScore: 9,
    replyTo: 'original-quote', payload: { mentions: ['3333@lid'] }, expiration: 600, ephemeral: true,
    entry: { row: { device_id: 'device-a', media: { media_key_sealed: 'never send this key' } } }, ...over } as MessageView
}
function media(type = 'image'): MediaView {
  return { type, mimetype: type === 'document' ? 'application/pdf' : type === 'sticker' ? 'image/webp' : `${type}/fixture`, fileLength: 7,
    fileName: 'original.bin', width: 120, height: 80, seconds: 3, status: 'ready', isGIF: false, full: { state: 'ready', url: 'blob:verified-attachment', bytes: 7 } }
}
function forwarder(source = message()) {
  const value = createForwarder(source); controllers.push(value); return value
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done }); return { promise, resolve } }
beforeEach(() => {
  vi.clearAllMocks()
  fixture.current = fixture.conn; fixture.token = 'token-a'; fixture.serverURL = 'https://api.example.test'; fixture.people = []; fixture.state.chats = []
  Object.assign(fixture.state, { tenantID: 'tenant-a', deviceID: 'device-a', openChatKey: '1111@lid', view: 'archive', connected: true, initializingConnection: false, unreadable: false,
    devices: [{ id: 'device-a', running: true, can_send: true }] })
  fixture.conn.welcome.features = [P.TypeSend, P.TypeSendMedia, P.TypeChatStart]
  fixture.conn.request.mockResolvedValue({ uid: 'sent-uid' })
  fixture.fetch.mockImplementation(async () => ({ ok: true, blob: async () => new Blob(['decoded']) }))
  fixture.upload.mockImplementation(async (request: { kind: string }) => ({ ...reference, type: request.kind }))
  fixture.readMediaBlob.mockResolvedValue(new Blob(['decoded']))
  vi.stubGlobal('fetch', fixture.fetch)
})
afterEach(() => { for (const controller of controllers.splice(0)) controller.dispose(); vi.unstubAllGlobals() })

describe('forwarding choices and access', () => {
  it('explicitly clears the score when removing a label and resets many-times to ordinary forwarding', () => {
    expect(forwardOptions('none')).toEqual({ forwarded: false, forwarding_score: 0 })
    expect(forwardOptions('forwarded')).toEqual({ forwarded: true, forwarding_score: 1 })
    expect(forwardOptions('many')).toEqual({ forwarded: true, forwarding_score: 5 })
  })
  it('supports captionless media without treating a locked caption as empty', () => {
    expect(forwardableContent(message({ media: media('video'), body: '', bodyState: 'absent' }))).toBe(true)
    expect(forwardableContent(message({ media: media('ptt'), body: '', bodyState: 'absent' }))).toBe(true)
    for (const bodyState of ['locked', 'tampered'] as const) expect(forwardableContent(message({ media: media('video'), bodyState }))).toBe(false)
    const absentCipher = message({ media: media('video'), bodyState: 'absent' }); absentCipher.entry.row.body_sealed = 'sealed-caption'
    expect(forwardableContent(absentCipher)).toBe(false)
    for (const over of [{ type: 'poll' }, { deleted: true }, { viewOnce: true }, { pending: 'sending' }, { bodyState: 'absent' }] as Partial<MessageView>[]) {
      expect(forwardableContent(message(over))).toBe(false)
    }
  })
  it('requires the sending permission, readable source device and advertised feature', async () => {
    fixture.state.devices[0]!.can_send = false
    expect(canForward(message())).toBe(false)
    expect((await forwarder().forward(to, 'forwarded')).ok).toBe(false)
    fixture.state.devices[0]!.can_send = true; fixture.conn.welcome.features = []
    expect(canForward(message())).toBe(false)
    fixture.conn.welcome.features = [P.TypeSend]; fixture.state.unreadable = true
    expect(canForward(message())).toBe(false)
    fixture.state.unreadable = false
    const foreign = message(); foreign.entry.row.device_id = 'device-b'
    expect(canForward(foreign)).toBe(false)
    expect(fixture.conn.request).not.toHaveBeenCalled()
  })
  it('accepts only individual and group destinations', () => {
    for (const jid of ['5511999999999@s.whatsapp.net', '1234@lid', '1234-5678@g.us']) expect(destinationJID(jid)).toBe(jid)
    for (const jid of ['status@broadcast', '1234@newsletter', '1111@evil.example', '1234:2@lid', '']) expect(destinationJID(jid)).toBe('')
  })
})

describe('sending the forwarded copy', () => {
  it.each(['none', 'forwarded', 'many'] as const)('sends text with %s and no original quote, mentions, sender or expiration', async mark => {
    const action = forwarder()
    expect(await action.forward(to, mark)).toMatchObject({ ok: true, chat: to })
    const request = fixture.conn.request.mock.calls[0]!
    expect(request[0]).toBe(P.TypeSend)
    expect(request[1]).toEqual({ device_id: 'device-a', chat: to, body: 'original text', id: expect.stringMatching(/^[A-F0-9]{32}$/), ...forwardOptions(mark) })
    expect(request[2]).toBe(P.TypeSendResult)
    expect(await action.forward(to, mark)).toMatchObject({ ok: true })
    expect(fixture.conn.request).toHaveBeenCalledOnce()
  })
  it('resolves an explicitly selected phone without navigating the original chat', async () => {
    fixture.conn.request.mockResolvedValueOnce({ chat: to }).mockResolvedValueOnce({ uid: 'sent' })
    expect((await forwarder().forward('+5511999999999', 'none')).ok).toBe(true)
    expect(fixture.conn.request.mock.calls[0]).toEqual([P.TypeChatStart, { device_id: 'device-a', phone: '+5511999999999' }, P.TypeChatStarted])
    expect(fixture.conn.request.mock.calls[1]![1]).toMatchObject({ chat: to })
    expect(fixture.state.openChatKey).toBe('1111@lid')
  })
  it('refuses an invalid phone-resolution response before sending any message', async () => {
    fixture.conn.request.mockResolvedValueOnce({ chat: 'status@broadcast' })
    expect((await forwarder().forward('+5511999999999', 'none')).ok).toBe(false)
    expect(fixture.conn.request).toHaveBeenCalledOnce()
  })
  it.each(['image', 'video', 'ptv', 'audio', 'ptt', 'document', 'sticker'])('decrypts and reuploads %s with a fresh matching upload reference', async kind => {
    const source = message({ type: kind, media: media(kind) })
    source.media!.full = undefined
    const action = forwarder(source)
    expect((await action.forward(to, 'none')).ok).toBe(true)
    expect(fixture.readMediaBlob).toHaveBeenCalledExactlyOnceWith(source)
    expect(fixture.fetch).not.toHaveBeenCalled() // CSP only permits API requests, not fetch(blob:).
    const uploaded = fixture.upload.mock.calls[0]![0]
    expect(uploaded).toMatchObject({ deviceID: 'device-a', kind, serverURL: fixture.serverURL, token: fixture.token })
    expect(await uploaded.blob.text()).toBe('decoded')
    const [type, request] = fixture.conn.request.mock.calls[0]!
    expect(type).toBe(P.TypeSendMedia)
    expect(request).toMatchObject({ type: kind, chat: to, device_id: 'device-a', upload: { ...reference, type: kind }, forwarded: false, forwarding_score: 0 })
    expect(request.reply_to).toBeUndefined(); expect(request.reply_sender).toBeUndefined(); expect(request.mentions).toBeUndefined(); expect(request.expiration).toBeUndefined(); expect(request.view_once).toBeUndefined()
    if (['image', 'video', 'document'].includes(kind)) expect(request.caption).toBe('original text')
    else expect(request.caption).toBeUndefined()
  })
  it('forwards a video without a caption and keeps bytes intact', async () => {
    const source = message({ type: 'video', media: media('video'), body: '', bodyState: 'absent' })
    expect((await forwarder(source).forward(to, 'forwarded')).ok).toBe(true)
    expect(fixture.conn.request.mock.calls[0]![1].caption).toBeUndefined()
    expect(await fixture.upload.mock.calls[0]![0].blob.text()).toBe('decoded')
  })
  it('does not send a thumbnail or a pending/expired attachment instead of the full file', async () => {
    fixture.readMediaBlob.mockResolvedValue(undefined)
    const source = message({ media: { ...media(), full: { state: 'expired' }, thumbURL: 'blob:thumbnail' } })
    const result = await forwarder(source).forward(to, 'forwarded')
    expect(result).toMatchObject({ ok: false, error: expect.any(String) })
    expect(fixture.fetch).not.toHaveBeenCalled(); expect(fixture.upload).not.toHaveBeenCalled(); expect(fixture.conn.request).not.toHaveBeenCalled()
  })
  it('refuses a mismatched upload type before a message can reference wrong encryption', async () => {
    fixture.upload.mockResolvedValue({ ...reference, type: 'document' })
    expect((await forwarder(message({ media: media() })).forward(to, 'none')).ok).toBe(false)
    expect(fixture.conn.request).not.toHaveBeenCalled()
  })
  it('reports successful unarchived delivery without inviting a duplicate', async () => {
    fixture.conn.request.mockResolvedValue({ uid: '' })
    const action = forwarder()
    expect(await action.forward(to, 'none')).toMatchObject({ ok: true, warning: expect.any(String) })
    await action.forward(to, 'none')
    expect(fixture.conn.request).toHaveBeenCalledOnce()
  })
})

describe('forwarding context and duplicate protection', () => {
  it.each(['device', 'tenant', 'token', 'connection', 'chat', 'view', 'permission'])('does not upload after %s changes during decryption', async change => {
    const waiting = deferred<Blob | undefined>(); fixture.readMediaBlob.mockReturnValue(waiting.promise)
    const source = message({ media: { ...media(), full: undefined } })
    const pending = forwarder(source).forward(to, 'none')
    if (change === 'device') fixture.state.deviceID = 'device-b'
    if (change === 'tenant') fixture.state.tenantID = 'tenant-b'
    if (change === 'token') fixture.token = 'token-b'
    if (change === 'connection') fixture.current = { ...fixture.conn }
    if (change === 'chat') fixture.state.openChatKey = '3333@lid'
    if (change === 'view') fixture.state.view = 'admin'
    if (change === 'permission') fixture.state.devices[0]!.can_send = false
    waiting.resolve(new Blob(['decoded']))
    expect(await pending).toMatchObject({ ok: false, stale: true })
    expect(fixture.upload).not.toHaveBeenCalled(); expect(fixture.conn.request).not.toHaveBeenCalled()
  })
  it('closing cancels preparation and releases the source without waiting for a shared download', async () => {
    const waiting = deferred<Blob | undefined>(); fixture.readMediaBlob.mockReturnValueOnce(waiting.promise)
    const source = message({ media: media() })
    const action = forwarder(source); const pending = action.forward(to, 'none')
    action.dispose()
    expect(await pending).toMatchObject({ ok: false, stale: true })
    expect(fixture.upload).not.toHaveBeenCalled()
    expect((await forwarder(source).forward(to, 'none')).ok).toBe(true)
    expect(fixture.upload).toHaveBeenCalledOnce()
    waiting.resolve(new Blob(['late original']))
    await Promise.resolve(); await Promise.resolve()
    expect(fixture.upload).toHaveBeenCalledOnce()
    expect(fixture.conn.request).toHaveBeenCalledOnce()
  })
  it('closing aborts a pending upload without waiting for its result or dispatching a message', async () => {
    const waiting = deferred<P.UploadRef>(); fixture.upload.mockReturnValue(waiting.promise)
    const action = forwarder(message({ media: media() })); const pending = action.forward(to, 'none')
    await vi.waitFor(() => expect(fixture.upload).toHaveBeenCalledOnce())
    action.dispose()
    expect(await pending).toMatchObject({ ok: false, stale: true })
    expect(fixture.upload.mock.calls[0]![0].signal.aborted).toBe(true)
    waiting.resolve(reference); await Promise.resolve(); await Promise.resolve()
    expect(fixture.conn.request).not.toHaveBeenCalled()
  })
  it('blocks dispatch after navigation during upload', async () => {
    const waiting = deferred<P.UploadRef>(); fixture.upload.mockReturnValue(waiting.promise)
    const action = forwarder(message({ media: media() }))
    const pending = action.forward(to, 'none')
    await vi.waitFor(() => expect(fixture.upload).toHaveBeenCalledOnce())
    fixture.state.deviceID = 'device-b'; waiting.resolve(reference)
    expect(await pending).toMatchObject({ ok: false, stale: true })
    expect(fixture.conn.request).not.toHaveBeenCalled()
    expect(fixture.upload.mock.calls[0]![0].signal.aborted).toBe(true)
  })
  it('blocks duplicate clicks and another dialog forwarding the same source while in flight', async () => {
    const waiting = deferred<P.SendResult>(); fixture.conn.request.mockReturnValue(waiting.promise)
    const first = forwarder(); const pending = first.forward(to, 'none')
    expect((await first.forward(to, 'none')).ok).toBe(false)
    expect((await forwarder().forward(to, 'none')).ok).toBe(false)
    waiting.resolve({ uid: 'sent' } as P.SendResult); await pending
    expect(fixture.conn.request).toHaveBeenCalledOnce()
  })
  it('never retries a send after a lost acknowledgement or an ambiguous provider refusal', async () => {
    fixture.conn.request.mockRejectedValue(new ProtocolError('conflict', 'provider timeout'))
    const action = forwarder()
    expect(await action.forward(to, 'none')).toMatchObject({ ok: false, uncertain: true })
    await action.forward(to, 'none')
    expect(fixture.conn.request).toHaveBeenCalledOnce()
  })
})


it('closing after dispatch keeps the source busy until acknowledgement and never repeats that send', async () => {
  const waiting = deferred<P.SendResult>(); fixture.conn.request.mockReturnValueOnce(waiting.promise)
  const action = forwarder(); const pending = action.forward(to, 'none')
  expect(fixture.conn.request).toHaveBeenCalledOnce()
  action.dispose()
  expect(await forwarder().forward(to, 'none')).toMatchObject({ ok: false, error: expect.any(String) })
  waiting.resolve({ uid: 'sent' } as P.SendResult)
  expect(await pending).toMatchObject({ ok: true, stale: true })
  await action.forward(to, 'none')
  expect(fixture.conn.request).toHaveBeenCalledOnce()
})


function batch(source = message()) { const value = createForwardBatch(source); controllers.push(value); return value }
const recipients = (keys: string[]) => keys.map(key => ({ key, name: 'Person ' + key }))

describe('forwarding to several recipients', () => {
  it('deduplicates exact PN/LID/contact/chat aliases and normalized phones without guessing equal digits', () => {
    fixture.people = [{ key: '1111@lid', pn: '5511999999999@s.whatsapp.net', lid: '1111@lid' }]
    fixture.state.chats = [{ key: '2222@lid', keys: ['2222@lid', '5511888888888@s.whatsapp.net'] }]
    const identity = forwardRecipientResolver()
    expect(identity('+5511999999999')).toBe(identity('1111@lid'))
    expect(identity('5511888888888@s.whatsapp.net')).toBe(identity('2222@lid'))
    expect(identity('1234@lid')).not.toBe(identity('1234@s.whatsapp.net'))
    expect(identity('1234@g.us')).not.toBe(identity('1234@s.whatsapp.net'))
  })
  it('requires a bounded concrete list before any operation', async () => {
    expect((await batch().forward([], 'none')).error).toBeTruthy()
    expect((await batch().forward(recipients(Array.from({ length: MAX_FORWARD_RECIPIENTS + 1 }, (_, i) => `${i + 1}@lid`)), 'none')).error).toBeTruthy()
    expect(fixture.conn.request).not.toHaveBeenCalled()
  })
  it('uses one unique ID per destination, applies the chosen label and never repeats a completed batch', async () => {
    const action = batch()
    const targets = recipients(['2222@lid', '3333@lid', '4444@g.us'])
    const outcome = await action.forward(targets, 'many')
    expect(outcome.results.map(row => row.state)).toEqual(['sent', 'sent', 'sent'])
    const payloads = fixture.conn.request.mock.calls.map(call => call[1])
    expect(payloads.map(payload => payload.chat)).toEqual(targets.map(target => target.key))
    expect(new Set(payloads.map(payload => payload.id)).size).toBe(3)
    for (const payload of payloads) expect(payload).toMatchObject(forwardOptions('many'))
    await action.forward(targets, 'none')
    expect(fixture.conn.request).toHaveBeenCalledTimes(3)
  })
  it('resolves all new numbers before sending and deduplicates provider-confirmed aliases', async () => {
    fixture.conn.request.mockImplementation(async (type: string, payload: { phone?: string }) => type === P.TypeChatStart
      ? { chat: payload.phone === '+5511999999999' ? '2222@lid' : '3333@lid' } : { uid: 'sent' })
    const outcome = await batch().forward(recipients(['2222@lid', '+5511999999999', '+5511888888888']), 'none')
    expect(fixture.conn.request.mock.calls.map(call => call[0])).toEqual([P.TypeChatStart, P.TypeChatStart, P.TypeSend, P.TypeSend])
    expect(outcome.results.map(row => row.state)).toEqual(['sent', 'duplicate', 'sent'])
    expect(fixture.conn.request.mock.calls.filter(call => call[0] === P.TypeSend).map(call => call[1].chat)).toEqual(['2222@lid', '3333@lid'])
  })
  it('deduplicates a plain phone and a PN JID before sending without conflating unrelated LIDs', async () => {
    fixture.conn.request.mockImplementation(async (type: string) => type === P.TypeChatStart ? { chat: '5511999999999@s.whatsapp.net' } : { uid: 'sent' })
    const outcome = await batch().forward(recipients(['+5511999999999', '5511999999999@s.whatsapp.net', '5511999999999@lid']), 'forwarded')
    expect(outcome.results.map(row => row.state)).toEqual(['sent', 'duplicate', 'sent'])
    expect(fixture.conn.request.mock.calls.filter(call => call[0] === P.TypeSend)).toHaveLength(2)
  })
  it('separates confirmed success, definitive failure and unknown delivery without automatic retries', async () => {
    fixture.conn.request.mockResolvedValueOnce({ uid: 'sent' }).mockRejectedValueOnce(new ProtocolError('not_authorized', 'recipient permission denied'))
      .mockRejectedValueOnce(new ProtocolError('conflict', 'provider timeout')).mockResolvedValueOnce({ uid: 'sent-last' })
    const action = batch()
    const targets = recipients(['2222@lid', '3333@lid', '4444@lid', '5555@lid'])
    const progress: string[][] = []
    const result = await action.forward(targets, 'none', rows => { progress.push(rows.map(row => row.state)) })
    expect(result.results.map(row => row.state)).toEqual(['sent', 'failed', 'uncertain', 'sent'])
    expect(progress).toContainEqual(['sent', 'failed', 'uncertain', 'sending'])
    await action.forward(targets, 'none')
    expect(fixture.conn.request).toHaveBeenCalledTimes(4)
  })
  it('isolates a failed phone lookup and never forwards to its unconfirmed address', async () => {
    fixture.conn.request.mockRejectedValueOnce(new ProtocolError('not_found', 'not registered')).mockResolvedValue({ uid: 'sent' })
    const outcome = await batch().forward(recipients(['+5511999999999', '3333@lid']), 'none')
    expect(outcome.results.map(row => row.state)).toEqual(['failed', 'sent'])
    expect(fixture.conn.request.mock.calls.filter(call => call[0] === P.TypeSend).map(call => call[1].chat)).toEqual(['3333@lid'])
  })
  it('stops pending recipients on close while preserving the first send acknowledgement', async () => {
    const waiting = deferred<P.SendResult>(); fixture.conn.request.mockReturnValueOnce(waiting.promise)
    const action = batch(); const targets = recipients(['2222@lid', '3333@lid'])
    const pending = action.forward(targets, 'none')
    expect(fixture.conn.request).toHaveBeenCalledOnce()
    action.dispose(); waiting.resolve({ uid: 'sent' } as P.SendResult)
    expect(await pending).toMatchObject({ stale: true, results: [{ state: 'sent' }, { state: 'cancelled' }] })
    expect(fixture.conn.request).toHaveBeenCalledOnce()
  })
  it('aborts a pending phone lookup on close and releases the batch without waiting for it', async () => {
    const waiting = deferred<P.ChatStarted>(); fixture.conn.request.mockReturnValueOnce(waiting.promise)
    const action = batch(); const pending = action.forward(recipients(['+5511999999999', '3333@lid']), 'none')
    action.dispose()
    expect(await pending).toMatchObject({ stale: true, results: [{ state: 'cancelled' }, { state: 'cancelled' }] })
    expect((await batch().forward(recipients(['4444@lid']), 'none')).results[0]?.state).toBe('sent')
    waiting.resolve({ chat: '2222@lid' }); await Promise.resolve(); await Promise.resolve()
    expect(fixture.conn.request.mock.calls.filter(call => call[0] === P.TypeSend)).toHaveLength(1)
  })
  it.each(['device', 'tenant', 'token', 'server', 'connection', 'chat', 'view', 'permission'])('does not send any batch copy after %s changes while resolving recipients', async change => {
    const waiting = deferred<P.ChatStarted>(); fixture.conn.request.mockReturnValueOnce(waiting.promise)
    const pending = batch().forward(recipients(['+5511999999999', '3333@lid']), 'none')
    if (change === 'device') fixture.state.deviceID = 'device-b'
    if (change === 'tenant') fixture.state.tenantID = 'tenant-b'
    if (change === 'token') fixture.token = 'token-b'
    if (change === 'server') fixture.serverURL = 'https://another.example.test'
    if (change === 'connection') fixture.current = { ...fixture.conn }
    if (change === 'chat') fixture.state.openChatKey = '7777@lid'
    if (change === 'view') fixture.state.view = 'admin'
    if (change === 'permission') fixture.state.devices[0]!.can_send = false
    waiting.resolve({ chat: '2222@lid' })
    expect((await pending).stale).toBe(true)
    expect(fixture.conn.request.mock.calls.filter(call => call[0] === P.TypeSend)).toHaveLength(0)
  })
  it('closing during shared media preparation cancels the whole remaining list immediately', async () => {
    const waiting = deferred<Blob | undefined>(); fixture.readMediaBlob.mockReturnValueOnce(waiting.promise)
    const action = batch(message({ media: media() }))
    const pending = action.forward(recipients(['2222@lid', '3333@lid']), 'none')
    action.dispose()
    expect((await pending).results.map(row => row.state)).toEqual(['cancelled', 'cancelled'])
    waiting.resolve(new Blob(['late'])); await Promise.resolve(); await Promise.resolve()
    expect(fixture.upload).not.toHaveBeenCalled(); expect(fixture.conn.request).not.toHaveBeenCalled()
  })
  it('does not continue after permission removal and rejects overlapping batches for the same source', async () => {
    const waiting = deferred<P.SendResult>(); fixture.conn.request.mockReturnValueOnce(waiting.promise)
    const action = batch(); const targets = recipients(['2222@lid', '3333@lid'])
    const pending = action.forward(targets, 'none')
    expect(action.forward(targets, 'none')).toBe(pending)
    expect((await batch().forward(targets, 'none')).error).toBeTruthy()
    fixture.state.devices[0]!.can_send = false
    waiting.resolve({ uid: 'sent' } as P.SendResult)
    expect((await pending).results.map(row => row.state)).toEqual(['sent', 'cancelled'])
    expect(fixture.conn.request).toHaveBeenCalledOnce()
  })
  it('freezes the confirmed recipient list while resolving numbers', async () => {
    const waiting = deferred<P.ChatStarted>(); fixture.conn.request.mockReturnValueOnce(waiting.promise)
    const targets = recipients(['+5511999999999', '3333@lid'])
    const pending = batch().forward(targets, 'none')
    targets[1]!.key = '9999@lid'; targets.push({ key: '7777@lid', name: 'Injected' })
    waiting.resolve({ chat: '2222@lid' }); await pending
    expect(fixture.conn.request.mock.calls.filter(call => call[0] === P.TypeSend).map(call => call[1].chat)).toEqual(['2222@lid', '3333@lid'])
  })
  it('preserves captionless media bytes and fresh upload references for each recipient', async () => {
    const source = message({ type: 'video', body: '', bodyState: 'absent', media: media('video') })
    const outcome = await batch(source).forward(recipients(['2222@lid', '3333@lid']), 'none')
    expect(outcome.results.map(row => row.state)).toEqual(['sent', 'sent'])
    expect(fixture.upload).toHaveBeenCalledTimes(2)
    for (const [upload] of fixture.upload.mock.calls) expect(await upload.blob.text()).toBe('decoded')
    for (const [, request] of fixture.conn.request.mock.calls) {
      expect(request).toMatchObject({ type: 'video', forwarded: false, forwarding_score: 0, upload: { ...reference, type: 'video' } })
      expect(request.caption).toBeUndefined(); expect(request.reply_to).toBeUndefined()
    }
  })
})
