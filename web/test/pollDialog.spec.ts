import { createRenderer, nextTick, reactive, ssrContextKey } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ state: {} as Record<string, unknown>, createPoll: vi.fn(), pollValidation: vi.fn() }))
vi.mock('../src/state/archive', () => ({ state: mocks.state }))
vi.mock('../src/state/conversationActions', () => ({ createPoll: mocks.createPoll, pollValidation: mocks.pollValidation }))
vi.mock('../src/ui/i18n', () => ({ t: (text: string) => text }))

interface Node { parent: Node | null; children: Node[] }
const node = (): Node => ({ parent: null, children: [] })
const renderer = createRenderer<Node, Node>({
  createElement: node, createText: node, createComment: node, patchProp() {}, setText() {}, setElementText() {},
  parentNode: value => value.parent, nextSibling: () => null,
  insert(value, parent) { value.parent = parent; parent.children.push(value) },
  remove(value) { if (value.parent) value.parent.children = value.parent.children.filter(child => child !== value) },
})
interface Form {
  question: string; options: { id: number; text: string }[]; multiple: boolean; busy: boolean; uncertain: boolean; error: string
  submit(): Promise<void>; dismiss(): void; addOption(): Promise<void>; removeOption(index: number): Promise<void>; characters(value: string): number
}
const closed = vi.fn()
let unmount: (() => void) | undefined
mocks.state = reactive({ deviceID: 'phone-a', openChatKey: 'chat-a' })

beforeEach(() => {
  vi.resetModules(); vi.clearAllMocks()
  Object.assign(mocks.state, { deviceID: 'phone-a', openChatKey: 'chat-a' })
  mocks.pollValidation.mockReturnValue('')
  mocks.createPoll.mockResolvedValue({ ok: true })
})
afterEach(() => { unmount?.(); unmount = undefined })

async function mount(): Promise<Form> {
  const Dialog = (await import('../src/components/PollDialog.vue')).default
  // Exercise the component's real submission and lifecycle in Node. Native
  // dialog focus, layout and keyboard behavior are checked in the browser.
  const app = renderer.createApp({ ...Dialog, render: () => null }, { onClose: closed })
  app.provide(ssrContextKey, {})
  const instance = app.mount(node()) as unknown as { $: { setupState: Form } }
  unmount = () => app.unmount()
  const form = instance.$.setupState
  form.question = '  Lunch?  '
  form.options[0]!.text = '  Pizza  '
  form.options[1]!.text = '  Salad  '
  await nextTick()
  return form
}

describe('new poll form', () => {
  it('trims the question and options while retaining the multiple-choice setting', async () => {
    const form = await mount()
    form.multiple = false
    await form.submit()
    expect(mocks.createPoll).toHaveBeenCalledExactlyOnceWith({ question: 'Lunch?', options: ['Pizza', 'Salad'], multiple: false })
    expect(closed).toHaveBeenCalledOnce()
  })

  it('shows validation without submitting or discarding the form', async () => {
    const form = await mount()
    mocks.pollValidation.mockReturnValue('Choose different options')
    await form.submit()
    expect(mocks.createPoll).not.toHaveBeenCalled()
    expect(form.error).toBe('Choose different options')
    expect(form.question).toBe('  Lunch?  ')
    expect(closed).not.toHaveBeenCalled()
  })

  it('blocks duplicate submissions and dismissal while awaiting confirmation', async () => {
    const form = await mount()
    let finish!: (value: { ok: boolean }) => void
    mocks.createPoll.mockImplementation(() => new Promise(resolve => { finish = resolve }))
    const pending = form.submit()
    await form.submit()
    form.dismiss()
    expect(form.busy).toBe(true)
    expect(mocks.createPoll).toHaveBeenCalledOnce()
    expect(closed).not.toHaveBeenCalled()
    finish({ ok: true })
    await pending
    expect(closed).toHaveBeenCalledOnce()
  })

  it.each(['uncertain', 'throws'])('prevents retries after an %s outcome but permits closing to check the conversation', async outcome => {
    const form = await mount()
    if (outcome === 'throws') mocks.createPoll.mockRejectedValue(new Error('connection lost'))
    else mocks.createPoll.mockResolvedValue({ ok: false, uncertain: true })
    await form.submit()
    expect(form.uncertain).toBe(true)
    expect(form.busy).toBe(false)
    await form.submit()
    await form.addOption()
    expect(mocks.createPoll).toHaveBeenCalledOnce()
    expect(form.options).toHaveLength(2)
    expect(form.question).toBe('  Lunch?  ')
    form.dismiss()
    expect(closed).toHaveBeenCalledOnce()
  })

  it('permits correcting and resubmitting a definitively rejected poll', async () => {
    const form = await mount()
    mocks.createPoll.mockResolvedValueOnce({ ok: false, error: 'Not connected' })
    await form.submit()
    expect(form.uncertain).toBe(false)
    expect(form.error).toBe('Not connected')
    await form.submit()
    expect(mocks.createPoll).toHaveBeenCalledTimes(2)
    expect(closed).toHaveBeenCalledOnce()
  })

  it.each(['deviceID', 'openChatKey'])('closes on a changed %s and ignores late results from the old conversation', async key => {
    const form = await mount()
    let finish!: (value: { ok: boolean; uncertain: boolean }) => void
    mocks.createPoll.mockImplementation(() => new Promise(resolve => { finish = resolve }))
    const pending = form.submit()
    mocks.state[key] = 'different'
    expect(closed).toHaveBeenCalledOnce()
    finish({ ok: false, uncertain: true })
    await pending
    expect(form.uncertain).toBe(false)
    expect(closed).toHaveBeenCalledOnce()
  })

  it('counts Unicode code points and keeps two to twelve stable option rows', async () => {
    const form = await mount()
    expect(form.characters('  😀😀  ')).toBe(2)
    expect(form.characters('😀'.repeat(255))).toBe(255)
    await form.removeOption(0)
    expect(form.options).toHaveLength(2)
    for (let index = 0; index < 15; index++) await form.addOption()
    expect(form.options).toHaveLength(12)
    const lastID = form.options.at(-1)!.id
    await form.removeOption(4)
    await form.addOption()
    expect(form.options).toHaveLength(12)
    expect(form.options.at(-1)!.id).toBeGreaterThan(lastID)
  })
})
