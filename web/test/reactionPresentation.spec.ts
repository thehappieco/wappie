import { createSSRApp, reactive, ref } from 'vue'
import { renderToString } from '@vue/server-renderer'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { HistoryView, MessageView } from '../src/state/archive'

const mocks = vi.hoisted(() => ({ state: {} as Record<string, unknown> }))
vi.mock('../src/state/archive', () => ({ state: mocks.state, canSend: () => false, discardFailed: vi.fn(), loadHistory: vi.fn(), people: () => ({ nameFor: () => '', find: () => undefined }) }))
vi.mock('../src/state/actions', () => ({ nowTick: ref(new Date('2026-01-01').getTime()) }))
vi.mock('../src/components/MessageActions.vue', () => ({ default: { render: () => null } }))
vi.mock('../src/components/MessageTicks.vue', () => ({ default: { render: () => null } }))
vi.mock('../src/components/MediaBlock.vue', () => ({ default: { render: () => null } }))
vi.mock('../src/components/PayloadBlock.vue', () => ({ default: { render: () => null } }))

mocks.state = reactive({ selectedUID: 'message', timeline: [] as MessageView[], history: null as HistoryView | null, historyLoading: false, historyError: '', devices: [], deviceID: 'device' })
const reaction = (emoji: string, who: string, fromMe = false) => ({ emoji, who, fromMe })
function message(): MessageView {
  return { uid: 'message', waID: 'wa-message', ts: new Date('2026-01-01'), seq: 1, fromMe: false, isGroup: true, isStatus: false,
    senderName: 'Sender', senderKey: '123@s.whatsapp.net', chatKey: 'group@g.us', body: 'Hello', bodyState: 'ok', type: 'text', unsupported: '',
    reactions: [reaction('👍', 'Alex'), reaction('❤️', 'Sam'), reaction('❤', 'Jo'), reaction('👍', 'Alex', true), reaction('😂', 'Lee'), reaction('😮', 'Kim'), reaction('🎉', 'Dana'), reaction('🙏', 'Rui')],
    edited: true, deleted: true, viewOnce: true, ephemeral: true, expiration: 3600, expiresAt: new Date('2050-01-01'), versionCount: 2,
  } as MessageView
}
beforeEach(() => { Object.assign(mocks.state, { selectedUID: 'message', timeline: [message()], history: null, historyLoading: false, historyError: '' }) })

describe('message reaction presentation', () => {
  it('renders four grouped emoji/count buttons and the exact overflow without expanding one row per participant', async () => {
    const Bubble = (await import('../src/components/MessageBubble.vue')).default
    const html = await renderToString(createSSRApp(Bubble, { message: message(), showSender: true }))
    expect(html.match(/class="reaction-emoji"/g)).toHaveLength(4)
    expect(html).toContain('Mais 2 tipos de reação. Ver todas.')
    expect(html).toContain('👍: 2 reações. Ver participantes. Inclui sua reação.')
    expect(html).toContain('❤️: 2 reações. Ver participantes.')
    expect(html.indexOf('👍: 2')).toBeLessThan(html.indexOf('❤️: 2'))
    expect(html).not.toContain('class="reaction-emoji" aria-hidden="true">🎉')
    expect(html).toContain('Reações da mensagem: 8.')
  })
  it('keeps distinguishable icons and accessible meanings for every colored message mark', async () => {
    const Bubble = (await import('../src/components/MessageBubble.vue')).default
    const html = await renderToString(createSSRApp(Bubble, { message: message(), showSender: false }))
    expect(html).toMatch(/message-mark mark-once[^>]*role="img"[^>]*aria-label="Mensagem de visualização única"/)
    expect(html).toMatch(/message-mark mark-timer[^>]*aria-label="Mensagem temporária até/)
    expect(html).toMatch(/message-mark mark-edited[^>]*aria-label="Mensagem editada · 2 versões"/)
    expect(html).toMatch(/message-mark mark-deleted[^>]*aria-label="Mensagem apagada"/)
  })
  it('shows current participants separately and preserves historical removals and replacements', async () => {
    mocks.state.history = { uid: 'message', waID: 'wa-message', versions: [{ revision: 0, body: 'Original', bodyState: 'ok' }], readers: [], reactions: [
      { emoji: '💔', who: 'Historical Alex', superseded: true, revoked: false, at: new Date('2025-01-01') },
      { emoji: '👍', who: 'Historical Alex', superseded: false, revoked: true, revokedAt: new Date('2025-02-01') },
      { emoji: '', who: 'Other person', superseded: false, revoked: false },
    ] }
    const Panel = (await import('../src/components/ForensicPanel.vue')).default
    const html = await renderToString(createSSRApp(Panel))
    const current = html.slice(html.indexOf('current-reactions'), html.indexOf('Histórico de reações'))
    expect(current).toContain('Reações atuais'); expect(current).toContain('Você'); expect(current).toContain('Sua reação')
    expect(current).toContain('Alex'); expect(current).toContain('Dana'); expect(current).toContain('Rui')
    expect(html).toContain('Histórico de reações (3)'); expect(html).toContain('Historical Alex')
    expect(html).toContain('· trocada'); expect(html).toContain('· removida'); expect(html).toContain('· retirada (emoji vazio)')
    expect(html).toContain('Original')
  })
  it('does not infer active reactions from historical rows', async () => {
    const current = message(); current.reactions = []; mocks.state.timeline = [current]
    mocks.state.history = { uid: 'message', waID: 'wa-message', versions: [], readers: [], reactions: [{ emoji: '👍', who: 'Past person', superseded: false, revoked: true }] }
    const Panel = (await import('../src/components/ForensicPanel.vue')).default
    const html = await renderToString(createSSRApp(Panel))
    expect(html).toContain('Nenhuma reação ativa.'); expect(html).not.toContain('class="current-reaction-group"')
    expect(html).toContain('Past person'); expect(html).toContain('Histórico de reações (1)')
  })
})
