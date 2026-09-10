import { createRenderer, nextTick, ssrContextKey } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({ open: vi.fn(), state: { deviceID: 'device', openChatKey: 'chat', tenantID: 'work' }, conn: {} }))
vi.mock('../src/state/archive', () => ({ state: mocks.state, connection: () => mocks.conn }))
vi.mock('../src/media/videoCapture', () => ({ openVideoCamera: mocks.open, videoRecordingAvailable: () => true }))
vi.mock('../src/ui/i18n', () => ({ t: (text: string) => text }))
interface Node { parent: Node | null; children: Node[] }
const node = (): Node => ({ parent: null, children: [] })
const renderer = createRenderer<Node, Node>({ createElement: node, createText: node, createComment: node, patchProp() {}, setText() {}, setElementText() {}, parentNode: n => n.parent, nextSibling: () => null, insert(n, p) { n.parent = p; p.children.push(n) }, remove() {} })
interface Form { openNative(): void; nativeCancelled(): void; nativePicked(event: Event): void; visibility(): void; preview?: HTMLVideoElement; showReviewFrame(): void; toggleReview(): Promise<void>; phase: string; shape: 'square' | 'original'; quality: 'standard' | 'hd'; previewURL: string; actualHD: boolean; choice: string; openCamera(): Promise<void>; start(): void; useVideo(): void; close(): void }
const native = vi.fn(), recorded = vi.fn(), closed = vi.fn(), revoked = vi.fn()
let unmount: (() => void) | undefined
beforeEach(() => {
  vi.clearAllMocks()
  Object.assign(mocks.state, { deviceID: 'device', openChatKey: 'chat', tenantID: 'work' }); mocks.conn = {}
  vi.stubGlobal('document', { addEventListener: vi.fn(), removeEventListener: vi.fn() })
  vi.stubGlobal('URL', { createObjectURL: () => 'blob:video', revokeObjectURL: revoked })
})
afterEach(() => { unmount?.(); unmount = undefined; vi.unstubAllGlobals() })
async function mount(): Promise<Form> {
  const Dialog = (await import('../src/components/VideoRecorderDialog.vue')).default
  const app = renderer.createApp({ ...Dialog, render: () => null }, { onRecorded: recorded, onClose: closed, onNative: native }); app.provide(ssrContextKey, {})
  const instance = app.mount(node()) as unknown as { $: { setupState: Form } }; unmount = () => app.unmount(); return instance.$.setupState
}
function capture(width = 480, height = 480) {
  let finish!: (result: unknown) => void
  const done = new Promise(resolve => { finish = resolve })
  const camera = { width, height, stream: {}, dispose: vi.fn(), start: vi.fn(() => ({ done, stop: () => done, cancel: vi.fn() })) }
  return { camera, finish }
}
describe('video recorder review and cleanup', () => {
  it('disposes a camera granted after the dialog was closed', async () => {
    const form = await mount(); let opened!: (value: unknown) => void
    mocks.open.mockImplementation(() => new Promise(resolve => { opened = resolve }))
    const pending = form.openCamera(); const signal = mocks.open.mock.calls[0]![0].signal as AbortSignal
    form.close(); expect(signal.aborted).toBe(true)
    const { camera } = capture(); opened(camera); await pending
    expect(camera.dispose).toHaveBeenCalledOnce(); expect(recorded).not.toHaveBeenCalled()
  })
  it('does not emit a file until review is accepted, then releases its temporary preview', async () => {
    const form = await mount(), { camera, finish } = capture()
    mocks.open.mockResolvedValue(camera); await form.openCamera(); form.start()
    const file = new File(['mp4'], 'video.mp4', { type: 'video/mp4' })
    finish({ file, width: 480, height: 480, seconds: 2 }); await nextTick(); await nextTick()
    expect(form.phase).toBe('review'); expect(recorded).not.toHaveBeenCalled(); expect(camera.dispose).toHaveBeenCalled()
    form.useVideo(); expect(recorded).toHaveBeenCalledWith(file, 'ptv', 2); expect(revoked).toHaveBeenCalledWith('blob:video')
  })
  it('uses normal quality honestly when the requested HD camera is lower resolution', async () => {
    const form = await mount(); form.quality = 'hd'; form.shape = 'original'
    const { camera, finish } = capture(640, 360); mocks.open.mockResolvedValue(camera)
    await form.openCamera(); form.start(); const file = new File(['mp4'], 'video.mp4')
    finish({ file, width: 640, height: 360, seconds: 1 }); await nextTick(); await nextTick()
    expect(form.actualHD).toBe(false); form.useVideo(); expect(recorded).toHaveBeenCalledWith(file, 'video', 1)
  })
  it('drops a completed recording after the dialog closes and never creates a preview', async () => {
    const form = await mount(); const { camera, finish } = capture(); mocks.open.mockResolvedValue(camera)
    await form.openCamera(); form.start(); form.close()
    finish({ file: new File(['mp4'], 'video.mp4'), width: 480, height: 480, seconds: 1 }); await nextTick()
    expect(form.previewURL).toBe(''); expect(recorded).not.toHaveBeenCalled()
  })
  it('paints a decoded review frame without autoplay and toggles playback only on request', async () => {
    const form = await mount(), { camera, finish } = capture(); mocks.open.mockResolvedValue(camera)
    await form.openCamera(); form.start(); finish({ file: new File(['mp4'], 'video.mp4'), width: 480, height: 480, seconds: 2 })
    await nextTick(); await nextTick()
    const play = vi.fn().mockResolvedValue(undefined), pause = vi.fn()
    const video = { duration: 2, currentTime: 0, paused: true, play, pause } as unknown as HTMLVideoElement
    form.preview = video; form.showReviewFrame()
    expect(video.currentTime).toBe(.05); expect(play).not.toHaveBeenCalled()
    await form.toggleReview(); expect(play).toHaveBeenCalledOnce()
    Object.defineProperty(video, 'paused', { value: false, configurable: true }); await form.toggleReview(); expect(pause).toHaveBeenCalledOnce()
    expect(recorded).not.toHaveBeenCalled()
  })

  it('keeps a native camera picker alive while hidden and resets its exception after cancel', async () => {
    const form = await mount(); form.openNative()
    Object.defineProperty(document, 'hidden', { value: true, configurable: true })
    form.visibility(); expect(closed).not.toHaveBeenCalled(); expect(mocks.open).not.toHaveBeenCalled()
    form.nativeCancelled(); form.visibility(); expect(closed).toHaveBeenCalledOnce()
  })
  it('accepts a native camera file without opening a stream and rejects late files from another workspace', async () => {
    const form = await mount(); const file = new File(['mp4'], 'native.mp4'); form.openNative()
    const input = { files: [file], value: 'selected' }
    form.nativePicked({ target: input } as unknown as Event)
    expect(native).toHaveBeenCalledWith(file); expect(input.value).toBe(''); expect(mocks.open).not.toHaveBeenCalled()
    native.mockClear(); form.openNative(); mocks.state.tenantID = 'other'
    form.nativePicked({ target: { files: [file], value: 'selected' } } as unknown as Event)
    expect(native).not.toHaveBeenCalled()
  })
  it('rejects a native picker callback after unmount', async () => {
    const form = await mount(); form.openNative(); unmount?.(); unmount = undefined
    form.nativePicked({ target: { files: [new File(['mp4'], 'late.mp4')], value: 'selected' } } as unknown as Event)
    expect(native).not.toHaveBeenCalled()
  })

})
