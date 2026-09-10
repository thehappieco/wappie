import { createRenderer, defineComponent, nextTick, reactive, ssrContextKey } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from '../src/state/session'

const mocks = vi.hoisted(() => ({
  state: {} as Record<string, unknown>, start: vi.fn(), stop: vi.fn(), restore: vi.fn(),
  opened: undefined as ((session: Session) => void) | undefined,
  cleared: undefined as ((change: { id: string; kind: 'cleared' }) => void) | undefined,
}))
vi.mock('../src/ui/i18n', () => ({ t: (value: string) => value }))
vi.mock('../src/ui/preferences', () => ({ applyPrivacyAppearance() {} }))
vi.mock('../src/ui/mobileNavigation', () => ({ installMobileNavigation: () => ({ sync() {}, dispose() {} }) }))
vi.mock('../src/state/archive', () => ({ state: mocks.state, start: mocks.start, stop: mocks.stop }))
vi.mock('../src/state/session', () => ({ restoreAccountSession: mocks.restore }))
vi.mock('../src/state/sessionBridge', () => ({ browserSessionWasCleared: () => false,
  observeBrowserSession: (listener: typeof mocks.cleared) => { mocks.cleared = listener; return () => {} } }))
vi.mock('../src/components/SignInView.vue', () => ({ default: defineComponent({
  emits: ['opened'], setup(_props, { emit }) { mocks.opened = session => emit('opened', session); return () => null },
}) }))
vi.mock('../src/components/AdminView.vue', () => ({ default: { render: () => null } }))
vi.mock('../src/components/ChatList.vue', () => ({ default: { render: () => null } }))
vi.mock('../src/components/ConversationView.vue', () => ({ default: { render: () => null } }))
vi.mock('../src/components/ForensicPanel.vue', () => ({ default: { render: () => null } }))
vi.mock('../src/components/GroupPanel.vue', () => ({ default: { render: () => null } }))

interface Node { parent: Node | null; children: Node[] }
const node = (): Node => ({ parent: null, children: [] })
const renderer = createRenderer<Node, Node>({
  createElement: node, createText: node, createComment: node, patchProp() {},
  setText() {}, setElementText() {}, parentNode: value => value.parent, nextSibling: () => null,
  insert(value, parent) { value.parent = parent; parent.children.push(value) },
  remove(value) { if (value.parent) value.parent.children = value.parent.children.filter(child => child !== value) },
})
let unmount: (() => void) | undefined

beforeEach(() => {
  vi.resetModules()
  vi.clearAllMocks()
  mocks.state = reactive({ phase: 'locked', view: 'archive', selectedUID: '', openChatKey: '', groupPanel: false, quiet: false })
  mocks.start.mockImplementation(async () => { mocks.state.phase = 'ready' })
  mocks.stop.mockImplementation(() => { mocks.state.phase = 'locked' })
  mocks.restore.mockResolvedValue(null)
  const window = Object.assign(new EventTarget(), { matchMedia: () => Object.assign(new EventTarget(), { matches: false }),
    innerHeight: 800, visualViewport: undefined })
  vi.stubGlobal('window', window)
  vi.stubGlobal('location', new URL('https://app.wappie.thehappie.co/'))
  vi.stubGlobal('document', { documentElement: { dataset: {}, style: { setProperty() {}, removeProperty() {} } } })
})
afterEach(() => { unmount?.(); unmount = undefined; vi.unstubAllGlobals() })

async function settle() { await Promise.resolve(); await nextTick(); await Promise.resolve(); await nextTick() }
function session(id: string, remember = async () => {}): Session {
  return { label: id, serverURL: '', credential: { kind: 'session', token: 'synthetic' }, readable: [],
    archiveFor: () => undefined, close: async () => {}, dispose: vi.fn(), persistenceID: id, remember }
}
async function mount() {
  const App = (await import('../src/App.vue')).default
  // Vitest's Node transform emits the SSR template; mount the real setup and
  // lifecycle with a no-op renderer. The fence lives in App, not its children.
  const app = renderer.createApp({ ...App, render: () => null })
  app.provide(ssrContextKey, {})
  const instance = app.mount(node()) as unknown as { $: { setupState: { opened: (session: Session) => void } } }
  mocks.opened = instance.$.setupState.opened
  unmount = () => app.unmount()
  await settle()
}

describe('application login lifetime', () => {
  it('does not discard a new login when the previous login finishes clearing late', async () => {
    await mount()
    const old = session(crypto.randomUUID())
    mocks.opened!(old)
    await settle()
    expect(mocks.start).toHaveBeenCalledWith(old)
    // Explicit logout locks synchronously; persistent clearing completes later.
    mocks.stop()
    await settle()
    let release!: () => void
    const fresh = session(crypto.randomUUID(), () => new Promise<void>(resolve => { release = resolve }))
    mocks.opened!(fresh)
    mocks.cleared!({ id: old.persistenceID!, kind: 'cleared' })
    release()
    await settle()
    expect(mocks.start).toHaveBeenCalledWith(fresh)
    expect(fresh.dispose).not.toHaveBeenCalled()
  })

  it('still discards a new login if that same pending login is cleared', async () => {
    await mount()
    let release!: () => void
    const fresh = session(crypto.randomUUID(), () => new Promise<void>(resolve => { release = resolve }))
    mocks.opened!(fresh)
    mocks.cleared!({ id: fresh.persistenceID!, kind: 'cleared' })
    release()
    await settle()
    expect(mocks.start).not.toHaveBeenCalled()
    expect(fresh.dispose).toHaveBeenCalledOnce()
  })
})
