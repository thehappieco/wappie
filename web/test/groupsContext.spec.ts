import { beforeEach, describe, expect, it, vi } from 'vitest'
const fixture = vi.hoisted(() => {
  const conn = { request: vi.fn() }
  return { conn, current: conn as typeof conn | null, state: { deviceID: 'phone-a', tenantID: 'space-a', actionError: '' } }
})
vi.mock('../src/state/archive', () => ({ state: fixture.state, connection: () => fixture.current, applyChatUpdate: vi.fn() }))
import { forgetGroups, groups, loadGroup, loadingGroup } from '../src/state/groups'
beforeEach(() => { vi.clearAllMocks(); fixture.current = fixture.conn; Object.assign(fixture.state, { deviceID: 'phone-a', tenantID: 'space-a', actionError: '' }); forgetGroups(); loadingGroup.key = '' })
const group = { chat_key: 'group@g.us', members: [], refreshed: true, permissions_known: true, is_member: true, can_manage: true }
describe('group refresh context', () => {
  it('stores fresh group permissions for the requested device', async () => {
    fixture.conn.request.mockResolvedValue(group); await loadGroup('group@g.us')
    expect(groups.get('group@g.us')).toEqual(group)
    expect(fixture.conn.request.mock.calls[0]![1]).toEqual({ device_id: 'phone-a', chat: 'group@g.us', refresh: true })
  })
  it.each(['device', 'workspace', 'connection'])('ignores an old group result after changing %s', async changed => {
    let resolve!: (value: typeof group) => void; fixture.conn.request.mockReturnValue(new Promise(done => { resolve = done }))
    const pending = loadGroup('group@g.us')
    if (changed === 'device') fixture.state.deviceID = 'phone-b'
    if (changed === 'workspace') fixture.state.tenantID = 'space-b'
    if (changed === 'connection') fixture.current = { ...fixture.conn }
    resolve(group); await pending; expect(groups.size).toBe(0)
  })
  it('does not show another device’s late error in the current conversation', async () => {
    let reject!: (reason: Error) => void; fixture.conn.request.mockReturnValue(new Promise((_done, fail) => { reject = fail }))
    const pending = loadGroup('group@g.us'); fixture.state.deviceID = 'phone-b'; reject(new Error('old device failed')); await pending
    expect(fixture.state.actionError).toBe('')
  })
})
