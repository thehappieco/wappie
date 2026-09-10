import { createRenderer, nextTick, reactive, ssrContextKey } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({ state: {} as Record<string, unknown>, prepare: vi.fn(), discard: vi.fn(), begin: vi.fn(), conn: {} }))
vi.mock('../src/state/archive', () => ({ state: mocks.state, canSend: () => true, connection: () => mocks.conn, noMarks: () => ({}), sendMedia: vi.fn(), sendText: vi.fn() }))
vi.mock('../src/state/presence', () => ({ startTyping: vi.fn(), stopTyping: vi.fn() }))
vi.mock('../src/state/actions', () => ({ edit: vi.fn(), editableFor: () => 0 }))
vi.mock('../src/state/conversationActions', () => ({ canConversationAction: () => true }))
vi.mock('../src/media/record', () => ({ available: () => true, begin: mocks.begin }))
vi.mock('../src/media/prepare', () => ({ prepare: mocks.prepare, discard: mocks.discard }))
vi.mock('../src/ui/i18n', () => ({ t: (text: string) => text }))
interface Node { parent: Node | null; children: Node[] }
const node = (): Node => ({ parent: null, children: [] })
const renderer = createRenderer<Node, Node>({ createElement: node, createText: node, createComment: node, patchProp() {}, setText() {}, setElementText() {}, parentNode: n => n.parent, nextSibling: () => null, insert(n, p) { n.parent = p; p.children.push(n) }, remove() {} })
interface Form { attached: unknown; picked: File | null; attachError: string; measuring: boolean; recording: unknown; videoOpen: boolean; prepareFile(file: File, choice: string): Promise<void>; clearAttachment(): void; startRecording(): Promise<void> }
const file = new File(['video'], 'a.mp4', { type: 'video/mp4' })
const ready = () => ({ previewURL: 'blob:preview', plan: { captionAllowed: true, viewOnceAllowed: true } })
let unmount: (() => void) | undefined
mocks.state = reactive({ chats: [], devices: [], timeline: [], openChatKey: 'a', deviceID: 'one', tenantID: 'work', connected: true })
beforeEach(() => { vi.clearAllMocks(); Object.assign(mocks.state, { openChatKey: 'a', deviceID: 'one', tenantID: 'work', connected: true }); mocks.conn = {} })
afterEach(() => { unmount?.(); unmount = undefined })
async function mount(): Promise<Form> {
  const Composer = (await import('../src/components/Composer.vue')).default
  const app = renderer.createApp({ ...Composer, render: () => null }); app.provide(ssrContextKey, {}); const instance = app.mount(node()) as unknown as { $: { setupState: Form } }
  unmount = () => app.unmount(); return instance.$.setupState
}
describe('composer media context', () => {
  it.each(['openChatKey', 'deviceID', 'tenantID'])('aborts preparation on %s change and discards a late result', async field => {
    const form = await mount(); let finish!: (value: unknown) => void
    mocks.prepare.mockImplementation(() => new Promise(resolve => { finish = resolve }))
    const pending = form.prepareFile(file, 'video')
    const signal = mocks.prepare.mock.calls[0]![3].signal as AbortSignal
    mocks.state[field] = 'other'; await nextTick()
    expect(signal.aborted).toBe(true); expect(form.videoOpen).toBe(false)
    const attachment = ready(); finish(attachment); await pending
    expect(form.attached).toBe(null); expect(mocks.discard).toHaveBeenCalledWith(attachment)
  })
  it('does not let an older cancelled operation overwrite or unlock a new one', async () => {
    const form = await mount(); const finishes: ((value: unknown) => void)[] = []
    mocks.prepare.mockImplementation(() => new Promise(resolve => { finishes.push(resolve) }))
    const first = form.prepareFile(file, 'video'); form.clearAttachment()
    const second = form.prepareFile(file, 'video_hd')
    finishes[0]!(ready()); await first; expect(form.measuring).toBe(true); expect(form.attached).toBe(null)
    const secondResult = ready(); finishes[1]!(secondResult); await second; expect(form.attached).toEqual(secondResult)
  })
  it('keeps the original file after a conversion error so another format can be chosen', async () => {
    const form = await mount(); mocks.prepare.mockRejectedValue(new Error('Unsupported codec'))
    await form.prepareFile(file, 'video'); expect(form.picked).toBe(file); expect(form.attachError).toBe('Unsupported codec')
  })
  it('stops a microphone granted after a workspace switch', async () => {
    const form = await mount(); let finish!: (value: unknown) => void
    mocks.begin.mockImplementation(() => new Promise(resolve => { finish = resolve }))
    const opening = form.startRecording(); mocks.state.tenantID = 'other'; await nextTick()
    const cancel = vi.fn(); finish({ cancel }); await opening
    expect(cancel).toHaveBeenCalledOnce(); expect(form.recording).toBe(null)
  })
  it('rejects a prepared file from a replaced connection even if its chat still matches', async () => {
    const form = await mount(); let finish!: (value: unknown) => void
    mocks.prepare.mockImplementation(() => new Promise(resolve => { finish = resolve }))
    const pending = form.prepareFile(file, 'video'); mocks.conn = {}; const attachment = ready(); finish(attachment); await pending
    expect(form.attached).toBe(null); expect(mocks.discard).toHaveBeenCalledWith(attachment)
  })
})
