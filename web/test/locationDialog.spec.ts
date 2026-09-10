import { createRenderer, nextTick, reactive, ssrContextKey } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const fixture = vi.hoisted(() => ({
  state: {} as Record<string, unknown>, runtime: {} as { allowed: boolean; token: string; conn: object }, sendLocation: vi.fn(),
}))
vi.mock('../src/state/archive', () => ({ state: fixture.state, connection: () => fixture.runtime.conn, credential: () => ({ token: fixture.runtime.token }) }))
vi.mock('../src/state/conversationActions', async original => {
  const actual = await original<typeof import('../src/state/conversationActions')>()
  return { locationValidation: actual.locationValidation, canConversationAction: () => fixture.runtime.allowed, sendLocation: fixture.sendLocation }
})
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
  lat: string; lon: string; name: string; address: string; accuracy: number; locating: boolean; busy: boolean; uncertain: boolean; error: string
  valid: boolean; locked: boolean; allowed: boolean; locate(): Promise<void>; submit(): Promise<void>; close(): void; editedCoordinates(): void
}
const closed = vi.fn()
let unmount: (() => void) | undefined
let position: PositionCallback, positionError: PositionErrorCallback
const getCurrentPosition = vi.fn((success: PositionCallback, error: PositionErrorCallback) => { position = success; positionError = error })
fixture.state = reactive({ deviceID: 'phone-a', openChatKey: 'chat-a', tenantID: 'space-a', view: 'archive', connected: true })
fixture.runtime = reactive({ allowed: true, token: 'token-a', conn: {} })

beforeEach(() => {
  vi.resetModules(); vi.clearAllMocks()
  Object.assign(fixture.state, { deviceID: 'phone-a', openChatKey: 'chat-a', tenantID: 'space-a', view: 'archive', connected: true })
  Object.assign(fixture.runtime, { allowed: true, token: 'token-a', conn: {} })
  fixture.sendLocation.mockResolvedValue({ ok: true })
  vi.stubGlobal('navigator', { geolocation: { getCurrentPosition } })
})
afterEach(() => { unmount?.(); unmount = undefined; vi.unstubAllGlobals() })

async function mount(): Promise<Form> {
  const Dialog = (await import('../src/components/LocationDialog.vue')).default
  // Run real setup, GPS helper, submission guards and lifecycle. Native dialog
  // layout and focus are covered by the integrated browser fixture.
  const app = renderer.createApp({ ...Dialog, render: () => null }, { onClose: closed })
  app.provide(ssrContextKey, {})
  const instance = app.mount(node()) as unknown as { $: { setupState: Form } }
  unmount = () => app.unmount()
  await nextTick()
  return instance.$.setupState
}
function gps(lat = -23.5, lon = -46.6, accuracy = 12.5) {
  position({ coords: { latitude: lat, longitude: lon, accuracy } } as GeolocationPosition)
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done }); return { promise, resolve } }

describe('location dialog confirmation and lifecycle', () => {
  it('starts empty without requesting GPS or silently treating empty coordinates as zero', async () => {
    const form = await mount()
    expect(form.valid).toBe(false)
    await form.submit()
    expect(getCurrentPosition).not.toHaveBeenCalled(); expect(fixture.sendLocation).not.toHaveBeenCalled()
    form.lat = '0'; form.lon = '0'
    expect(form.valid).toBe(true)
    form.lon = ' '
    await form.submit()
    expect(form.valid).toBe(false); expect(fixture.sendLocation).not.toHaveBeenCalled()
  })
  it('requests GPS only on explicit action and still requires a separate send confirmation', async () => {
    const form = await mount()
    const pending = form.locate()
    expect(form.locating).toBe(true)
    await form.locate(); await form.submit()
    expect(getCurrentPosition).toHaveBeenCalledOnce(); expect(fixture.sendLocation).not.toHaveBeenCalled()
    gps(); await pending
    expect(form.lat).toBe('-23.5'); expect(form.lon).toBe('-46.6'); expect(form.accuracy).toBe(13)
    expect(form.locating).toBe(false); expect(form.valid).toBe(true)
    expect(fixture.sendLocation).not.toHaveBeenCalled()
    await form.submit()
    expect(fixture.sendLocation).toHaveBeenCalledExactlyOnceWith({ lat: -23.5, lon: -46.6, name: '', address: '', accuracy_m: 13 })
    expect(closed).toHaveBeenCalledOnce()
  })
  it('drops GPS accuracy after manual coordinate edits and sends legitimate zero coordinates only on confirmation', async () => {
    const form = await mount(); const pending = form.locate(); gps(); await pending
    form.lat = '0'; form.lon = '0'; form.editedCoordinates()
    expect(form.accuracy).toBe(0); expect(fixture.sendLocation).not.toHaveBeenCalled()
    await form.submit()
    expect(fixture.sendLocation.mock.calls[0]![0]).toMatchObject({ lat: 0, lon: 0, accuracy_m: undefined })
  })
  it.each(['close', 'unmount'])('ignores a GPS callback arriving after %s', async how => {
    const form = await mount(); form.lat = '1'; form.lon = '2'
    const pending = form.locate()
    if (how === 'close') form.close()
    else { unmount?.(); unmount = undefined }
    gps(); await pending
    expect(form.lat).toBe('1'); expect(form.lon).toBe('2'); expect(form.accuracy).toBe(0)
    expect(form.error).toBe(''); expect(fixture.sendLocation).not.toHaveBeenCalled()
    await form.submit(); expect(fixture.sendLocation).not.toHaveBeenCalled()
  })
  it.each(['deviceID', 'openChatKey', 'tenantID', 'view', 'connected', 'connection', 'token'])('closes and ignores late GPS when %s changes', async key => {
    const form = await mount(); const pending = form.locate()
    if (key === 'connection') fixture.runtime.conn = {}
    else if (key === 'token') fixture.runtime.token = 'token-b'
    else fixture.state[key] = key === 'connected' ? false : 'different'
    expect(closed).toHaveBeenCalledOnce()
    gps(); await pending
    expect(form.lat).toBe(''); expect(form.lon).toBe(''); expect(form.error).toBe('')
    expect(fixture.sendLocation).not.toHaveBeenCalled()
  })
  it('allows manual entry after permission denial without requesting GPS again', async () => {
    const form = await mount(); const pending = form.locate()
    positionError({ code: 1 } as GeolocationPositionError); await pending
    expect(form.error).toMatch(/Permissão/); expect(form.locating).toBe(false)
    form.lat = '−23,5'; form.lon = '−46,6'; form.editedCoordinates()
    await form.submit()
    expect(getCurrentPosition).toHaveBeenCalledOnce(); expect(fixture.sendLocation).toHaveBeenCalledOnce()
  })
  it('rechecks permission before confirmation even after valid GPS coordinates were acquired', async () => {
    const form = await mount(); const pending = form.locate(); gps(); await pending
    fixture.runtime.allowed = false
    await form.submit()
    expect(form.allowed).toBe(false); expect(fixture.sendLocation).not.toHaveBeenCalled()
  })
  it('prevents duplicate confirmations while awaiting the server', async () => {
    const form = await mount(); form.lat = '1'; form.lon = '2'
    const wait = deferred<{ ok: boolean }>(); fixture.sendLocation.mockReturnValue(wait.promise)
    const pending = form.submit(); await form.submit(); await form.locate()
    expect(form.busy).toBe(true); expect(fixture.sendLocation).toHaveBeenCalledOnce(); expect(getCurrentPosition).not.toHaveBeenCalled()
    wait.resolve({ ok: true }); await pending
    expect(closed).toHaveBeenCalledOnce()
  })
  it.each(['uncertain', 'throws'])('does not repeat an %s send and allows closing to check the conversation', async outcome => {
    const form = await mount(); form.lat = '1'; form.lon = '2'
    if (outcome === 'throws') fixture.sendLocation.mockRejectedValue(new Error('transport failed'))
    else fixture.sendLocation.mockResolvedValue({ ok: false, uncertain: true, error: 'Unknown send outcome' })
    await form.submit()
    expect(form.uncertain).toBe(true); expect(form.locked).toBe(true)
    await form.submit(); await form.locate()
    expect(fixture.sendLocation).toHaveBeenCalledOnce(); expect(getCurrentPosition).not.toHaveBeenCalled()
    form.close(); expect(closed).toHaveBeenCalledOnce()
  })
  it('does not surface a late send result in the next workspace', async () => {
    const form = await mount(); form.lat = '1'; form.lon = '2'
    const wait = deferred<{ ok: boolean; uncertain: boolean; error: string }>(); fixture.sendLocation.mockReturnValue(wait.promise)
    const pending = form.submit(); fixture.state.tenantID = 'space-b'
    expect(closed).toHaveBeenCalledOnce()
    wait.resolve({ ok: false, uncertain: true, error: 'Old workspace error' }); await pending
    expect(form.uncertain).toBe(false); expect(form.error).toBe(''); expect(closed).toHaveBeenCalledOnce()
  })
})
