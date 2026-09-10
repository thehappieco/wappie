import { createRenderer, nextTick, reactive, ssrContextKey } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ state: {} as Record<string, unknown>, forward: vi.fn(), dispose: vi.fn(), create: vi.fn(), allowed: vi.fn() }))
vi.mock('../src/state/archive', () => ({ state: mocks.state, credential: () => ({ token: 'session-a' }), connection: () => ({ welcome: { features: ['chat.start'] } }),
  people: () => ({ find: () => undefined, all: () => [], nameFor: (key: string) => key }), avatars: new Map(), avatarFor: vi.fn() }))
vi.mock('../src/state/forwarding', () => ({ canForward: mocks.allowed, createForwardBatch: mocks.create, MAX_FORWARD_RECIPIENTS: 10,
  destinationJID: (value: string) => value.endsWith('@lid') ? value : '',
  forwardRecipientResolver: () => (value: string) => value === '+5511999999999' ? '2222@lid' : value }))
vi.mock('../src/state/conversationActions', () => ({ normalizePhone: () => '' }))
vi.mock('../src/ui/i18n', () => ({ t: (value: string) => value }))
vi.mock('../src/ui/format', () => ({ typeLabel: (value: string) => value }))
interface Node { parent: Node | null; children: Node[] }
const node = (): Node => ({ parent: null, children: [] })
const renderer = createRenderer<Node, Node>({ createElement: node, createText: node, createComment: node, patchProp() {}, setText() {}, setElementText() {}, parentNode: n => n.parent, nextSibling: () => null,
  insert(n, parent) { n.parent = parent; parent.children.push(n) }, remove(n) { if (n.parent) n.parent.children = n.parent.children.filter(child => child !== n) } })
interface Recipient { key: string; name: string }
interface Result { recipient: Recipient; state: string }
interface Form {
  selected: Recipient[]; query: string; mark: 'forwarded' | 'many' | 'none'; busy: boolean; result?: { results: Result[] }; results: Result[]
  resultGroups: { state: string; rows: Result[] }[]
  choose(key: string, name: string): void; submit(): Promise<void>; close(): void; anotherRecipients(): void
}
const closed = vi.fn()
let unmount: (() => void) | undefined
mocks.state = reactive({ tenantID: 'tenant-a', deviceID: 'device-a', openChatKey: '1111@lid', view: 'archive', connected: true, chats: [], contactsLoaded: 0 })
beforeEach(() => {
  vi.resetModules(); vi.clearAllMocks()
  Object.assign(mocks.state, { tenantID: 'tenant-a', deviceID: 'device-a', openChatKey: '1111@lid', view: 'archive', connected: true })
  mocks.allowed.mockReturnValue(true)
  mocks.forward.mockImplementation(async (recipients: Recipient[]) => ({ results: recipients.map(recipient => ({ recipient, state: 'sent' })) }))
  mocks.create.mockImplementation(() => ({ forward: mocks.forward, dispose: mocks.dispose }))
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
  it('only sends the selected list after explicit confirmation with the chosen label', async () => {
    const form = await mount()
    expect(form.mark).toBe('many')
    await form.submit(); expect(mocks.forward).not.toHaveBeenCalled()
    form.choose('2222@lid', 'First'); form.choose('3333@lid', 'Second')
    expect(mocks.forward).not.toHaveBeenCalled()
    form.mark = 'none'; await form.submit()
    expect(mocks.forward).toHaveBeenCalledExactlyOnceWith([{ key: '2222@lid', name: 'First' }, { key: '3333@lid', name: 'Second' }], 'none', expect.any(Function))
    expect(form.results.map(row => row.state)).toEqual(['sent', 'sent'])
    await form.submit(); expect(mocks.forward).toHaveBeenCalledOnce()
  })
  it('keeps choices across searches, toggles exact aliases and enforces the limit', async () => {
    const form = await mount()
    form.choose('2222@lid', 'First'); form.query = 'another name'
    expect(form.selected).toEqual([{ key: '2222@lid', name: 'First' }])
    form.choose('+5511999999999', 'Same person')
    expect(form.selected).toEqual([])
    for (let i = 1; i <= 11; i++) form.choose(`${i}@lid`, `Person ${i}`)
    expect(form.selected).toHaveLength(10)
    form.choose('1@lid', 'Person 1'); form.choose('11@lid', 'Person 11')
    expect(form.selected).toHaveLength(10); expect(form.selected.at(-1)?.key).toBe('11@lid')
    expect(mocks.forward).not.toHaveBeenCalled()
  })
  it('allows closing during preparation while preventing changed recipients and repeated clicks', async () => {
    const form = await mount(); form.choose('2222@lid', 'First')
    let resolve!: (value: unknown) => void; mocks.forward.mockReturnValue(new Promise(done => { resolve = done }))
    const pending = form.submit(); form.choose('3333@lid', 'Other'); form.close(); await form.submit()
    expect(form.selected).toEqual([{ key: '2222@lid', name: 'First' }]); expect(closed).toHaveBeenCalledOnce(); expect(mocks.dispose).toHaveBeenCalled(); expect(mocks.forward).toHaveBeenCalledOnce()
    resolve({ results: [{ recipient: { key: '2222@lid', name: 'First' }, state: 'sent' }] }); await pending; expect(form.result).toBeUndefined()
  })
  it('requires a fresh selection and explicit confirmation to forward another copy', async () => {
    const form = await mount(); form.choose('2222@lid', 'First'); await form.submit()
    form.anotherRecipients(); expect(form.selected).toEqual([]); expect(mocks.create).toHaveBeenCalledTimes(2)
    await form.submit(); expect(mocks.forward).toHaveBeenCalledOnce()
    form.choose('3333@lid', 'Other'); await form.submit(); expect(mocks.forward).toHaveBeenCalledTimes(2)
  })
  it('presents individual partial results and never retries an uncertain batch', async () => {
    const form = await mount()
    for (const [key, name] of [['2222@lid', 'Confirmed'], ['3333@lid', 'Failed'], ['4444@lid', 'Uncertain']]) form.choose(key!, name!)
    mocks.forward.mockImplementation(async (recipients: Recipient[]) => ({ results: recipients.map((recipient, i) => ({ recipient, state: ['sent', 'failed', 'uncertain'][i] })) }))
    await form.submit()
    expect(form.resultGroups.map(group => ({ state: group.state, names: group.rows.map(row => row.recipient.name) }))).toEqual([
      { state: 'sent', names: ['Confirmed'] }, { state: 'failed', names: ['Failed'] }, { state: 'uncertain', names: ['Uncertain'] },
    ])
    form.anotherRecipients(); await form.submit(); expect(mocks.forward).toHaveBeenCalledOnce()
    form.close(); expect(closed).toHaveBeenCalledOnce()
  })
  it('preserves successes and treats only the active send as uncertain on unexpected failure', async () => {
    const form = await mount()
    form.choose('2222@lid', 'Sent'); form.choose('3333@lid', 'Sending'); form.choose('4444@lid', 'Waiting')
    mocks.forward.mockImplementation(async (recipients: Recipient[], _mark: string, update: (rows: Result[]) => void) => {
      update(recipients.map((recipient, i) => ({ recipient, state: ['sent', 'sending', 'pending'][i]! })))
      throw new Error('lost response')
    })
    await form.submit()
    expect(form.results.map(row => row.state)).toEqual(['sent', 'uncertain', 'cancelled'])
    form.anotherRecipients(); await form.submit(); expect(mocks.forward).toHaveBeenCalledOnce()
  })
  it('disposes on navigation and ignores a late confirmation', async () => {
    const form = await mount(); form.choose('2222@lid', 'First')
    let resolve!: (value: unknown) => void; mocks.forward.mockReturnValue(new Promise(done => { resolve = done }))
    const pending = form.submit(); mocks.state.deviceID = 'device-b'; resolve({ results: [] }); await pending
    expect(mocks.dispose).toHaveBeenCalled(); expect(closed).toHaveBeenCalledOnce(); expect(form.result).toBeUndefined()
  })
})
