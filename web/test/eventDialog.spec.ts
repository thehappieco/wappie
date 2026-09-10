import { createRenderer, nextTick, reactive, ssrContextKey } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const fixture = vi.hoisted(() => ({
  state: {} as Record<string, unknown>, runtime: {} as { allowed: boolean; token: string; conn: object }, createEvent: vi.fn(), eventValidation: vi.fn(),
}))
vi.mock('../src/state/archive', () => ({ state: fixture.state, connection: () => fixture.runtime.conn, credential: () => ({ token: fixture.runtime.token }) }))
vi.mock('../src/state/conversationActions', () => ({ eventValidation: fixture.eventValidation, canConversationAction: () => fixture.runtime.allowed, createEvent: fixture.createEvent }))
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
  name: string; description: string; start: string; end: string; hasEnd: boolean; location: string; link: string
  busy: boolean; uncertain: boolean; error: string; locked: boolean; allowed: boolean; zoneLabel: string
  submit(): Promise<void>; dismiss(): void; toggleEnd(): void; instant(value: string): string
}
const closed = vi.fn()
let unmount: (() => void) | undefined
fixture.state = reactive({ deviceID: 'phone-a', openChatKey: 'chat-a', tenantID: 'space-a', view: 'archive', connected: true })
fixture.runtime = reactive({ allowed: true, token: 'token-a', conn: {} })

beforeEach(() => {
  vi.resetModules(); vi.clearAllMocks()
  vi.stubEnv('TZ', 'UTC')
  Object.assign(fixture.state, { deviceID: 'phone-a', openChatKey: 'chat-a', tenantID: 'space-a', view: 'archive', connected: true })
  Object.assign(fixture.runtime, { allowed: true, token: 'token-a', conn: {} })
  fixture.createEvent.mockResolvedValue({ ok: true }); fixture.eventValidation.mockReturnValue('')
})
afterEach(() => { unmount?.(); unmount = undefined; vi.unstubAllEnvs() })

async function mount(): Promise<Form> {
  const Dialog = (await import('../src/components/EventDialog.vue')).default
  // Execute the real form setup and lifecycle. Native dialog layout and focus
  // are checked separately in the integrated browser fixture.
  const app = renderer.createApp({ ...Dialog, render: () => null }, { onClose: closed })
  app.provide(ssrContextKey, {})
  const instance = app.mount(node()) as unknown as { $: { setupState: Form } }
  unmount = () => app.unmount()
  await nextTick()
  const form = instance.$.setupState
  form.name = '  Team meeting  '; form.start = '2030-09-10T10:00'
  return form
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done }); return { promise, resolve } }

describe('calendar event creation form', () => {
  it('sends only on confirmation, trims text and converts the selected local time to an unambiguous instant', async () => {
    vi.stubEnv('TZ', 'America/Sao_Paulo')
    const form = await mount()
    form.description = '  Bring the report  '; form.location = '  Office  '; form.link = '  https://call.whatsapp.com/video/test  '
    expect(fixture.createEvent).not.toHaveBeenCalled()
    expect(form.zoneLabel).toContain('UTC−03:00')
    await form.submit()
    expect(fixture.createEvent).toHaveBeenCalledExactlyOnceWith({
      name: 'Team meeting', description: 'Bring the report', start_time: '2030-09-10T13:00:00.000Z', end_time: undefined,
      location_name: 'Office', join_link: 'https://call.whatsapp.com/video/test',
    })
    expect(closed).toHaveBeenCalledOnce()
  })
  it('suggests a one-hour ending only when requested, and omits it when disabled again', async () => {
    const form = await mount()
    expect(form.hasEnd).toBe(false); expect(form.end).toBe('')
    form.hasEnd = true; form.toggleEnd(); expect(form.end).toBe('2030-09-10T11:00')
    form.end = '2030-09-10T12:30'; form.hasEnd = false; form.toggleEnd(); form.hasEnd = true; form.toggleEnd()
    expect(form.end).toBe('2030-09-10T12:30')
    form.hasEnd = false
    await form.submit()
    expect(fixture.createEvent.mock.calls[0]![0].end_time).toBeUndefined()
  })
  it('refuses impossible dates and a daylight-saving gap instead of silently changing the chosen time', async () => {
    vi.stubEnv('TZ', 'America/New_York')
    const form = await mount()
    for (const value of ['2030-02-30T10:00', '2030-03-10T02:30', '2030-09-10T10:00Z']) {
      form.start = value; await form.submit()
      expect(form.error).toContain('fuso horário')
    }
    expect(fixture.createEvent).not.toHaveBeenCalled()
    expect(form.instant('2030-03-10T03:30')).toBe('2030-03-10T07:30:00.000Z')
  })
  it('requires a valid end when enabled and retains the form after a validation failure', async () => {
    const form = await mount(); form.hasEnd = true
    await form.submit(); expect(fixture.createEvent).not.toHaveBeenCalled(); expect(form.error).toContain('fuso horário')
    form.end = '2030-09-10T11:00'
    fixture.eventValidation.mockReturnValue('The event name is too long')
    await form.submit(); expect(form.error).toBe('The event name is too long'); expect(form.name).toBe('  Team meeting  ')
    expect(fixture.createEvent).not.toHaveBeenCalled(); expect(closed).not.toHaveBeenCalled()
  })
  it('rechecks permission at confirmation', async () => {
    const form = await mount(); fixture.runtime.allowed = false
    await form.submit(); expect(form.allowed).toBe(false); expect(fixture.createEvent).not.toHaveBeenCalled()
  })
  it('blocks duplicate sends and dismissal while confirmation is pending', async () => {
    const form = await mount(); const wait = deferred<{ ok: boolean }>(); fixture.createEvent.mockReturnValue(wait.promise)
    const pending = form.submit(); await form.submit(); form.dismiss()
    expect(form.busy).toBe(true); expect(fixture.createEvent).toHaveBeenCalledOnce(); expect(closed).not.toHaveBeenCalled()
    wait.resolve({ ok: true }); await pending; expect(closed).toHaveBeenCalledOnce()
  })
  it.each(['uncertain', 'throws'])('keeps an %s outcome locked until the user closes and checks the conversation', async outcome => {
    const form = await mount()
    if (outcome === 'throws') fixture.createEvent.mockRejectedValue(new Error('Connection lost'))
    else fixture.createEvent.mockResolvedValue({ ok: false, uncertain: true })
    await form.submit(); expect(form.uncertain).toBe(true); expect(form.locked).toBe(true)
    await form.submit(); expect(fixture.createEvent).toHaveBeenCalledOnce()
    form.dismiss(); await form.submit(); expect(closed).toHaveBeenCalledOnce(); expect(fixture.createEvent).toHaveBeenCalledOnce()
  })
  it.each(['deviceID', 'openChatKey', 'tenantID', 'view', 'connected', 'connection', 'token'])('ignores late results after %s changes', async key => {
    const form = await mount(); const wait = deferred<{ ok: boolean; uncertain: boolean; error: string }>(); fixture.createEvent.mockReturnValue(wait.promise)
    const pending = form.submit()
    if (key === 'connection') fixture.runtime.conn = {}
    else if (key === 'token') fixture.runtime.token = 'token-b'
    else fixture.state[key] = key === 'connected' ? false : 'different'
    expect(closed).toHaveBeenCalledOnce()
    wait.resolve({ ok: false, uncertain: true, error: 'Old conversation error' }); await pending
    expect(form.uncertain).toBe(false); expect(form.error).toBe(''); await form.submit(); expect(fixture.createEvent).toHaveBeenCalledOnce()
  })
  it('ignores results after unmount and allows correction only after a definite rejection', async () => {
    const form = await mount(); fixture.createEvent.mockResolvedValueOnce({ ok: false, error: 'Not allowed' })
    await form.submit(); expect(form.uncertain).toBe(false); expect(form.error).toBe('Not allowed')
    const wait = deferred<{ ok: boolean }>(); fixture.createEvent.mockReturnValue(wait.promise)
    const pending = form.submit(); unmount?.(); unmount = undefined; wait.resolve({ ok: true }); await pending
    expect(fixture.createEvent).toHaveBeenCalledTimes(2); expect(closed).not.toHaveBeenCalled()
  })
})
