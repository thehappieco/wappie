import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ProtocolError } from '../src/api/client'
import * as P from '../src/api/protocol'
const fixture = vi.hoisted(() => {
  const request = vi.fn()
  const conn = { request, welcome: { features: ['chat.start', 'group.create', 'group.participants.update', 'group.leave', 'message.poll.create'] } }
  return { conn, current: conn as typeof conn | null, token: 'session-a', loadChats: vi.fn(), openChat: vi.fn(), loadGroup: vi.fn(),
    state: { connected: true, initializingConnection: false, unreadable: false, tenantID: 'space-a', deviceID: 'phone-a', openChatKey: 'chat-a', view: 'archive',
      devices: [{ id: 'phone-a', running: true, can_send: true, can_manage: true }] }, groups: new Map() }
})
vi.mock('../src/state/archive', () => ({ state: fixture.state, connection: () => fixture.current, credential: () => ({ token: fixture.token }), loadChats: fixture.loadChats, openChat: fixture.openChat }))
vi.mock('../src/state/groups', () => ({ groups: fixture.groups, loadGroup: fixture.loadGroup }))
import { sendLocation, locationValidation, canChangeGroup, canConversationAction, changeGroupParticipants, conversationOperations, createGroup, createPoll, groupValidation, leaveGroup, normalizePhone, participantsFromText, participantsValidation, pollValidation, startConversation } from '../src/state/conversationActions'

beforeEach(() => {
  vi.clearAllMocks(); fixture.current = fixture.conn; fixture.token = 'session-a'; conversationOperations.clear(); fixture.groups.clear()
  Object.assign(fixture.state, { connected: true, initializingConnection: false, unreadable: false, tenantID: 'space-a', deviceID: 'phone-a', openChatKey: 'chat-a', view: 'archive' })
  fixture.state.devices = [{ id: 'phone-a', running: true, can_send: true, can_manage: true }]
  fixture.conn.welcome.features = ['chat.start', 'group.create', 'group.participants.update', 'group.leave', 'message.poll.create']
  fixture.loadChats.mockResolvedValue(undefined); fixture.loadGroup.mockResolvedValue(undefined)
  fixture.openChat.mockImplementation(async (chat: string) => { fixture.state.openChatKey = chat })
})
const poll = { question: 'Qual horário?', options: ['Manhã', 'Tarde'], multiple: true }
function deferred<T>() { let resolve!: (value: T) => void; let reject!: (reason: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no }); return { promise, resolve, reject } }

describe('conversation forms', () => {
  it('normalizes international phone formatting without guessing a country', () => {
    expect(normalizePhone('+55 (11) 99999-9999')).toBe('+5511999999999')
    expect(normalizePhone('44.20.1234.5678')).toBe('+442012345678')
    for (const phone of ['012345678', '123', '+55alice12345', '+1+234567890', '1234567890123456']) expect(normalizePhone(phone)).toBe('')
  })
  it('validates participant counts, identifiers and phone aliases', () => {
    expect(participantsFromText('+5511999999999; +442012345678\n123456@lid')).toHaveLength(3)
    expect(participantsValidation(['+5511999999999', '123456@lid'])).toBe('')
    expect(participantsValidation(['+5511999999999', '5511999999999@s.whatsapp.net'])).not.toBe('')
    expect(participantsValidation(['person@evil.example'])).not.toBe('')
    expect(participantsValidation(Array.from({ length: 33 }, (_, i) => '+551199999' + String(i).padStart(4, '0')))).not.toBe('')
    expect(groupValidation({ name: '😀'.repeat(100), participants: ['+5511999999999'] })).toBe('')
    expect(groupValidation({ name: '😀'.repeat(101), participants: ['+5511999999999'] })).not.toBe('')
  })
  it('matches poll Unicode limits and case-insensitive option uniqueness', () => {
    expect(pollValidation({ question: '😀'.repeat(255), options: ['😀'.repeat(100), 'No'], multiple: false })).toBe('')
    for (const input of [{ ...poll, question: '😀'.repeat(256) }, { ...poll, options: ['One'] }, { ...poll, options: [' Yes ', 'yes'] }, { ...poll, options: ['One', '  '] }, { ...poll, options: Array.from({ length: 13 }, (_, i) => String(i)) }]) expect(pollValidation(input)).not.toBe('')
  })
})
describe('authorized conversation actions', () => {
  it('requires server feature, device scope and a ready connection', async () => {
    fixture.state.devices[0]!.can_send = false
    expect(canConversationAction(P.TypeChatStart)).toBe(false)
    expect((await createPoll(poll)).ok).toBe(false)
    fixture.state.devices[0]!.can_send = true; fixture.conn.welcome.features = []
    expect(canConversationAction(P.TypeChatStart)).toBe(false)
    fixture.conn.welcome.features = [P.TypeChatStart]; fixture.state.initializingConnection = true
    expect(canConversationAction(P.TypeChatStart)).toBe(false)
    expect(fixture.conn.request).not.toHaveBeenCalled()
  })
  it('opens a new metadata-only conversation after the server confirms it', async () => {
    fixture.conn.request.mockResolvedValue({ chat: 'new-contact@lid' })
    expect((await startConversation('+55 11 99999-9999')).ok).toBe(true)
    expect(fixture.conn.request).toHaveBeenCalledExactlyOnceWith(P.TypeChatStart, { device_id: 'phone-a', phone: '+5511999999999' }, P.TypeChatStarted)
    expect(fixture.loadChats).toHaveBeenCalledOnce(); expect(fixture.openChat).toHaveBeenCalledExactlyOnceWith('new-contact@lid')
  })
  it('reports successful creation and partial participants without retrying', async () => {
    fixture.conn.request.mockResolvedValue({ chat: 'new@g.us', action: 'create', participants: [{ jid: 'ok@lid' }, { jid: 'refused@lid', error: 403 }], refreshed: true })
    const result = await createGroup({ name: ' Team ', participants: ['+5511999999999'] })
    expect(result).toMatchObject({ ok: true, chat: 'new@g.us', failed: ['refused@lid'] })
    expect(fixture.conn.request).toHaveBeenCalledOnce()
    expect(fixture.conn.request.mock.calls[0]![1]).toMatchObject({ name: 'Team', participants: ['+5511999999999'] })
  })
  it('does not present a confirmed creation as failed if refreshing the list fails', async () => {
    fixture.conn.request.mockResolvedValue({ chat: 'created@lid' }); fixture.loadChats.mockRejectedValue(new Error('offline'))
    expect(await startConversation('+5511999999999')).toMatchObject({ ok: true, chat: 'created@lid', warning: expect.any(String) })
    expect(fixture.conn.request).toHaveBeenCalledOnce()
  })
  it.each(['device', 'connection', 'account', 'chat', 'view'])('ignores a late creation after changing %s', async change => {
    const waiting = deferred<P.ChatStarted>(); fixture.conn.request.mockReturnValue(waiting.promise)
    const action = startConversation('+5511999999999')
    if (change === 'device') fixture.state.deviceID = 'phone-b'
    if (change === 'connection') fixture.current = { ...fixture.conn }
    if (change === 'account') fixture.token = 'session-b'
    if (change === 'chat') fixture.state.openChatKey = 'other@lid'
    if (change === 'view') fixture.state.view = 'admin'
    waiting.resolve({ chat: 'new@lid' })
    expect(await action).toMatchObject({ ok: false, stale: true })
    expect(fixture.loadChats).not.toHaveBeenCalled(); expect(fixture.openChat).not.toHaveBeenCalled()
  })
  it('prevents duplicate in-flight polls and never resends on timeout', async () => {
    const waiting = deferred<unknown>(); fixture.conn.request.mockReturnValue(waiting.promise)
    const first = createPoll(poll)
    expect((await createPoll(poll)).ok).toBe(false)
    waiting.reject(new ProtocolError('internal', 'timeout'))
    expect(await first).toMatchObject({ ok: false, uncertain: true })
    expect(fixture.conn.request).toHaveBeenCalledExactlyOnceWith(P.TypePollCreate, { device_id: 'phone-a', chat: 'chat-a', question: poll.question, options: poll.options, selectable_count: 0 }, P.TypeSendResult)
    expect(conversationOperations.size).toBe(0)
  })
  it('sends single-choice polls explicitly and preserves definitive server refusals', async () => {
    fixture.conn.request.mockRejectedValue(new ProtocolError('not_authorized', 'not permitted'))
    expect(await createPoll({ ...poll, multiple: false })).toMatchObject({ ok: false, uncertain: false })
    expect(fixture.conn.request.mock.calls[0]![1]).toMatchObject({ selectable_count: 1 })
  })
  it('treats WhatsApp creation errors as uncertain even when the wire code is conflict', async () => {
    fixture.conn.request.mockRejectedValue(new ProtocolError(P.ErrConflict, 'context deadline exceeded'))
    expect(await createPoll(poll)).toMatchObject({ ok: false, uncertain: true })
    expect(await createGroup({ name: 'Team', participants: ['+5511999999999'] })).toMatchObject({ ok: false, uncertain: true })
    fixture.groups.set('chat-a', { permissions_known: true, refreshed: true, is_member: true, can_manage: true })
    expect(await changeGroupParticipants('add', ['+5511999999999'])).toMatchObject({ ok: false, uncertain: true })
    expect(await leaveGroup()).toMatchObject({ ok: false, uncertain: true })
    expect(fixture.conn.request).toHaveBeenCalledTimes(4)
  })
  it('requires fresh WhatsApp membership authority for participant management', async () => {
    fixture.groups.set('chat-a', { permissions_known: true, refreshed: true, is_member: true, can_manage: false })
    expect(canChangeGroup('add')).toBe(false); expect(canChangeGroup('leave')).toBe(true)
    expect((await changeGroupParticipants('remove', ['12345@lid'])).ok).toBe(false)
    fixture.groups.get('chat-a').can_manage = true; fixture.groups.get('chat-a').refreshed = false
    expect(canChangeGroup('add')).toBe(false)
    fixture.groups.get('chat-a').refreshed = true; fixture.state.devices[0]!.can_manage = false
    expect(canChangeGroup('add')).toBe(false)
    expect(fixture.conn.request).not.toHaveBeenCalled()
  })
  it('refreshes confirmed membership changes and marks a confirmed leave locally', async () => {
    fixture.groups.set('chat-a', { permissions_known: true, refreshed: true, is_member: true, can_manage: true, members: [] })
    fixture.conn.request.mockResolvedValue({ chat: 'chat-a', action: 'remove', participants: [{ jid: '12345@lid', error: 403 }], refreshed: true })
    expect(await changeGroupParticipants('remove', ['12345@lid'])).toMatchObject({ ok: true, failed: ['12345@lid'] })
    expect(fixture.loadGroup).toHaveBeenCalledExactlyOnceWith('chat-a')
    fixture.conn.request.mockResolvedValue({ chat: 'chat-a', action: 'leave', refreshed: true })
    expect((await leaveGroup()).ok).toBe(true)
    expect(fixture.groups.get('chat-a')).toMatchObject({ is_member: false, can_manage: false })
  })
  it('removes only the departed device’s known aliases after acknowledgement', async () => {
    Object.assign(fixture.state.devices[0]!, { pn: '5511999999999@s.whatsapp.net', lid: '12345@lid' })
    const remaining = [{ key: '12346@lid', is_admin: true }, { key: '5511999999998@s.whatsapp.net' }]
    const members = [{ key: '12345@lid', is_admin: true }, { key: 'other-alias@lid', pn: '5511999999999@s.whatsapp.net' }, ...remaining]
    fixture.groups.set('chat-a', { permissions_known: true, refreshed: true, is_member: true, can_manage: true, members })
    const waiting = deferred<P.GroupChanged>(); fixture.conn.request.mockReturnValue(waiting.promise)
    const pending = leaveGroup()
    expect(fixture.groups.get('chat-a').members).toEqual(members)
    waiting.resolve({ chat: 'chat-a', action: 'leave', refreshed: true })
    expect((await pending).ok).toBe(true)
    expect(fixture.groups.get('chat-a')).toMatchObject({ is_member: false, can_manage: false, members: remaining })
    expect(fixture.groups.get('chat-a').members).toHaveLength(2)
    expect(fixture.loadGroup).not.toHaveBeenCalled()
  })
  it('preserves the recorded participants when this device has no known identity', async () => {
    const members = [{ key: '12345@lid', is_super_admin: true }, { key: '98765@lid' }]
    fixture.groups.set('chat-a', { permissions_known: true, refreshed: true, is_member: true, can_manage: true, members })
    fixture.conn.request.mockResolvedValue({ chat: 'chat-a', action: 'leave', refreshed: true })
    expect((await leaveGroup()).ok).toBe(true)
    expect(fixture.groups.get('chat-a').members).toEqual(members)
  })
})


describe('fixed location sending', () => {
  beforeEach(() => { fixture.conn.welcome.features.push(P.TypeLocationSend) })
  it('validates boundaries and never sends missing or nonfinite coordinates', async () => {
    for (const input of [{lat: NaN, lon: 0}, {lat: 91, lon: 0}, {lat: 0, lon: Infinity}, {lat: 0, lon: -181}, {lat: 0, lon: 0, accuracy_m: -1}, {lat: 0, lon: 0, name: 'a'.repeat(101)}]) {
      expect(locationValidation(input)).not.toBe('')
      expect((await sendLocation(input)).ok).toBe(false)
    }
    expect(fixture.conn.request).not.toHaveBeenCalled()
  })
  it('requires send permission and the advertised capability, not device management', async () => {
    fixture.state.devices[0]!.can_manage = false
    expect(canConversationAction(P.TypeLocationSend)).toBe(true)
    fixture.state.devices[0]!.can_send = false
    expect((await sendLocation({lat: 0, lon: 0})).ok).toBe(false)
    expect(fixture.conn.request).not.toHaveBeenCalled()
  })
  it('sends a fixed position including zero, with an independent message ID and no live flags', async () => {
    fixture.conn.request.mockResolvedValue({ id: 'position-a' })
    expect(await sendLocation({lat: 0, lon: 0, name: '  Home  ', address: ' Road ', accuracy_m: 15})).toMatchObject({ok: true})
    expect(fixture.conn.request).toHaveBeenCalledExactlyOnceWith(P.TypeLocationSend, {device_id:'phone-a',chat:'chat-a',id:expect.any(String),lat:0,lon:0,name:'Home',address:'Road',accuracy_m:15}, P.TypeSendResult)
  })
  it('deduplicates pending confirmations and treats an ambiguous rejection as uncertain', async () => {
    const pending = deferred<unknown>(); fixture.conn.request.mockReturnValue(pending.promise)
    const first = sendLocation({lat:1,lon:2})
    expect((await sendLocation({lat:1,lon:2})).ok).toBe(false)
    pending.reject(new ProtocolError(P.ErrConflict, 'send location: disconnected'))
    expect(await first).toMatchObject({ok:false,uncertain:true})
    expect(fixture.conn.request).toHaveBeenCalledTimes(1)
  })
  it('ignores confirmation after changing the active workspace', async () => {
    const pending = deferred<unknown>(); fixture.conn.request.mockReturnValue(pending.promise)
    const first = sendLocation({lat:1,lon:2})
    fixture.state.tenantID='another-space';pending.resolve({})
    expect(await first).toMatchObject({ok:false,stale:true})
  })
})
