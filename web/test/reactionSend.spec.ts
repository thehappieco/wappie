import { beforeEach, describe, expect, it, vi } from 'vitest'
const mock = vi.hoisted(() => ({ request: vi.fn(), state: { deviceID: 'device-a', openChatKey: 'peer@lid', actionError: '' } }))
vi.mock('../src/state/archive', () => ({ connection: () => ({ request: mock.request }), state: mock.state, openChat: vi.fn(), redrawTimeline: vi.fn(), refreshChats: vi.fn() }))
import { react } from '../src/state/actions'
import type { MessageView } from '../src/state/archive'
const message = (emoji = '') => ({ waID: 'message-a', senderKey: 'sender@lid', fromMe: false, reactions: emoji ? [{ emoji, fromMe: true, who: 'me' }] : [] }) as unknown as MessageView
beforeEach(() => { mock.request.mockReset().mockResolvedValue({}); mock.state.actionError = '' })
describe('reaction transport', () => {
  it('does not send text or multiple emoji', async () => {
    for (const value of ['hello', '👍👍', ' ', 'a\uFE0F', '🏻']) await react(message(), value)
    expect(mock.request).not.toHaveBeenCalled(); expect(mock.state.actionError).not.toBe('')
  })
  it('sends a whole composed emoji with the original message target', async () => {
    await react(message(), '👩🏽‍💻')
    expect(mock.request).toHaveBeenCalledExactlyOnceWith('message.react', { device_id: 'device-a', chat: 'peer@lid', target_id: 'message-a', sender: 'sender@lid', emoji: '👩🏽‍💻' }, 'message.sent')
  })
  it('canonicalizes presentation aliases and uses empty to remove the same reaction', async () => {
    await react(message(), '❤')
    expect(mock.request.mock.calls[0]![1].emoji).toBe('❤️')
    await react(message('❤'), '❤️')
    expect(mock.request.mock.calls[1]![1].emoji).toBe('')
    await react(message('👍'), '')
    expect(mock.request.mock.calls[2]![1].emoji).toBe('')
  })
})
