import { createRenderer, nextTick, reactive, ssrContextKey } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ state: {} as Record<string, unknown>, forward: vi.fn(), dispose: vi.fn(), create: vi.fn(), allowed: vi.fn() }))
vi.mock('../src/state/archive', () => ({ state: mocks.state, credential: () => ({ token: 'session-a' }), connection: () => ({ welcome: { features: ['chat.start'] } }),
  people: () => ({ find: () => undefined, all: () => [], nameFor: (key: string) => key }), avatars: new Map(), avatarFor: vi.fn() }))
vi.mock('../src/state/forwarding', () => ({ canForward: mocks.allowed, createForwarder: mocks.create, destinationJID: (value: string) => value.endsWith('@lid') ? value : '' }))
vi.mock('../src/state/conversationActions', () => ({ normalizePhone: () => '' }))
vi.mock('../src/ui/i18n', () => ({ t: (value: string) => value }))
vi.mock('../src/ui/format', () => ({ typeLabel: (value: string) => value }))
interface Node { parent: Node | null; children: Node[] }
const node = (): Node => ({ parent: null, children: [] })
const renderer = createRenderer<Node, Node>({ createElement: node, createText: node, createComment: node, patchProp() {}, setText() {}, setElementText() {}, parentNode: n => n.parent, nextSibling: () => null,
  insert(n, parent) { n.parent = parent; parent.children.push(n) }, remove(n) { if (n.parent) n.parent.children = n.parent.children.filter(child => child !== n) } })
interface Form {
  selected: string; selectedName: string; mark: 'forwarded' | 'many' | 'none'; busy: boolean; result?: { ok: boolean; uncertain?: boolean }
  choose(key: string, name: string): void; submit(): Promise<void>; close(): void; anotherRecipient(): void
}
const closed = vi.fn()
let unmount: (() => void) | undefined
mocks.state = reactive({ tenantID: 'tenant-a', deviceID: 'device-a', openChatKey: '1111@lid', view: 'archive', connected: true, chats: [], contactsLoaded: 0 })
beforeEach(() => {
  vi.resetModules(); vi.clearAllMocks()
  Object.assign(mocks.state, { tenantID: 'tenant-a', deviceID: 'device-a', openChatKey: '1111@lid', view: 'archive', connected: true })
  mocks.allowed.mockReturnValue(true); mocks.forward.mockResolvedValue({ ok: true }); mocks.create.mockImplementation(() => ({ forward: mocks.forward, dispose: mocks.dispose }))
})
afterEach(() => { unmount?.(); unmount = undefined })
async function mount(): Promise<Form> {
  const Dialog = (await import('../src/components/ForwardDialog.vue')).default
  const app = renderer.createApp({ ...Dialog, render: () => null }, { message: { uid: 'message-a', type: 'text', body: 'original', forwardingScore: 9 }, onClose: closed })
  app.provide(ssrContextKey, {})
  const instance = app.mount(node()) as unknown as { $: { setupState: Form } }; unmount = () => app.unmount()
  await nextTick(); return instance.$.setupState
}

describe('forward confirmation dialog', () => {
  it('only sends after selecting a recipient and confirming, with the explicitly chosen mark', async () => {
    const form = await mount()
    expect(form.mark).toBe('many')
    await form.submit(); expect(mocks.forward).not.toHaveBeenCalled()
    form.choose('2222@lid', 'Selected person'); expect(mocks.forward).not.toHaveBeenCalled()
    form.mark = 'none'; await form.submit()
    expect(mocks.forward).toHaveBeenCalledExactlyOnceWith('2222@lid', 'none')
    expect(form.result?.ok).toBe(true)
    await form.submit(); expect(mocks.forward).toHaveBeenCalledOnce()
  })
  it('allows closing during preparation while preventing changed recipients and repeated clicks', async () => {
    const form = await mount(); form.choose('2222@lid', 'First')
    let resolve!: (value: unknown) => void; mocks.forward.mockReturnValue(new Promise(done => { resolve = done }))
    const pending = form.submit(); form.choose('3333@lid', 'Other'); form.close(); await form.submit()
    expect(form.selected).toBe('2222@lid'); expect(closed).toHaveBeenCalledOnce(); expect(mocks.dispose).toHaveBeenCalled(); expect(mocks.forward).toHaveBeenCalledOnce()
    resolve({ ok: true }); await pending; expect(form.result).toBeUndefined()
  })
  it('requires a new recipient choice and explicit confirmation to forward another copy', async () => {
    const form = await mount(); form.choose('2222@lid', 'First'); await form.submit()
    form.anotherRecipient(); expect(form.selected).toBe(''); expect(mocks.create).toHaveBeenCalledTimes(2)
    await form.submit(); expect(mocks.forward).toHaveBeenCalledOnce()
    form.choose('3333@lid', 'Other'); await form.submit(); expect(mocks.forward).toHaveBeenCalledTimes(2)
  })
  it('keeps an uncertain send locked against retries, including unexpected failures', async () => {
    const form = await mount(); form.choose('2222@lid', 'First'); mocks.forward.mockRejectedValue(new Error('lost response'))
    await form.submit(); expect(form.result?.uncertain).toBe(true)
    form.anotherRecipient(); await form.submit(); expect(mocks.forward).toHaveBeenCalledOnce()
    form.close(); expect(closed).toHaveBeenCalledOnce()
  })
  it('disposes on navigation and ignores a late confirmation', async () => {
    const form = await mount(); form.choose('2222@lid', 'First')
    let resolve!: (value: unknown) => void; mocks.forward.mockReturnValue(new Promise(done => { resolve = done }))
    const pending = form.submit(); mocks.state.deviceID = 'device-b'; resolve({ ok: true }); await pending
    expect(mocks.dispose).toHaveBeenCalled(); expect(closed).toHaveBeenCalledOnce(); expect(form.result).toBeUndefined()
  })
})
