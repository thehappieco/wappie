import { createRenderer, nextTick, reactive, ssrContextKey } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({ state: {} as Record<string, unknown>, start: vi.fn(), create: vi.fn(), allowed: vi.fn() }))
vi.mock('../src/state/archive', () => ({ state: mocks.state }))
vi.mock('../src/state/conversationActions', () => ({ canConversationAction: mocks.allowed, startConversation: mocks.start, createGroup: mocks.create,
  normalizePhone: (phone: string) => phone.startsWith('+') ? phone : '', participantsFromText: (text: string) => text.split('\n'), groupValidation: () => '' }))
vi.mock('../src/ui/i18n', () => ({ t: (text: string) => text }))
interface Node { parent: Node | null; children: Node[] }
const node = (): Node => ({ parent: null, children: [] })
const renderer = createRenderer<Node, Node>({ createElement: node, createText: node, createComment: node, patchProp() {}, setText() {}, setElementText() {}, parentNode: n => n.parent, nextSibling: () => null,
  insert(n, parent) { n.parent = parent; parent.children.push(n) }, remove(n) { if (n.parent) n.parent.children = n.parent.children.filter(child => child !== n) } })
interface Form { mode: 'chat' | 'group'; phone: string; name: string; participants: string; busy: boolean; result?: { ok: boolean; uncertain?: boolean; failed?: string[] }; submit(): Promise<void>; close(): void; setMode(mode: 'chat' | 'group'): void }
const closed = vi.fn(); let unmount: (() => void) | undefined
mocks.state = reactive({ deviceID: 'a', tenantID: 'space', connected: true, view: 'archive' })
beforeEach(() => { vi.resetModules(); vi.clearAllMocks(); Object.assign(mocks.state, { deviceID: 'a', tenantID: 'space', connected: true, view: 'archive' }); mocks.allowed.mockReturnValue(true); mocks.start.mockResolvedValue({ ok: true }); mocks.create.mockResolvedValue({ ok: true }) })
afterEach(() => { unmount?.(); unmount = undefined })
async function mount(): Promise<Form> {
  const Dialog = (await import('../src/components/NewConversationDialog.vue')).default
  const app = renderer.createApp({ ...Dialog, render: () => null }, { onClose: closed }); app.provide(ssrContextKey, {})
  const instance = app.mount(node()) as unknown as { $: { setupState: Form } }; unmount = () => app.unmount()
  await nextTick(); instance.$.setupState.phone = '+5511999999999'; return instance.$.setupState
}
describe('new conversation form', () => {
  it('opens a contact only after explicit submission', async () => { const form = await mount(); expect(mocks.start).not.toHaveBeenCalled(); await form.submit(); expect(mocks.start).toHaveBeenCalledOnce(); expect(closed).toHaveBeenCalledOnce() })
  it('keeps partial group creation results visible and never creates again', async () => {
    const form = await mount(); form.setMode('group'); form.name = 'Team'; form.participants = '+5511999999999\n+442012345678'
    mocks.create.mockResolvedValue({ ok: true, failed: ['refused@lid'] }); await form.submit(); await form.submit()
    expect(mocks.create).toHaveBeenCalledExactlyOnceWith({ name: 'Team', participants: ['+5511999999999', '+442012345678'] }); expect(form.result?.failed).toEqual(['refused@lid']); expect(closed).not.toHaveBeenCalled()
  })
  it('blocks duplicate clicks and closing while awaiting WhatsApp', async () => {
    const form = await mount(); let resolve!: (value: unknown) => void; mocks.start.mockReturnValue(new Promise(done => { resolve = done }))
    const pending = form.submit(); await form.submit(); form.close(); expect(mocks.start).toHaveBeenCalledOnce(); expect(closed).not.toHaveBeenCalled(); resolve({ ok: true }); await pending; expect(closed).toHaveBeenCalledOnce()
  })
  it('does not offer retries after an uncertain response', async () => {
    const form = await mount(); mocks.start.mockRejectedValue(new Error('timeout')); await form.submit(); await form.submit(); expect(form.result?.uncertain).toBe(true); expect(mocks.start).toHaveBeenCalledOnce(); form.close(); expect(closed).toHaveBeenCalledOnce()
  })
  it('ignores late results after the device changes', async () => {
    const form = await mount(); let resolve!: (value: unknown) => void; mocks.start.mockReturnValue(new Promise(done => { resolve = done })); const pending = form.submit(); mocks.state.deviceID = 'b'; resolve({ ok: true }); await pending
    expect(closed).toHaveBeenCalledOnce(); expect(form.result).toBeUndefined()
  })
})
