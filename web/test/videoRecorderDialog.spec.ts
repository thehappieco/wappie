import { createRenderer, nextTick, ssrContextKey } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({ open: vi.fn(), state: { deviceID: 'device', openChatKey: 'chat', tenantID: 'work', connected: true }, conn: {} as object | null }))
vi.mock('../src/state/archive', async () => {
  const { reactive } = await import('vue')
  mocks.state = reactive(mocks.state)
  return { state: mocks.state, connection: () => mocks.conn }
})
vi.mock('../src/media/videoCapture', () => ({ openVideoCamera: mocks.open, videoRecordingAvailable: () => true }))
vi.mock('../src/ui/i18n', () => ({ t: (text: string) => text }))
interface Node { parent: Node | null; children: Node[] }
const node = (): Node => ({ parent: null, children: [] })
const renderer = createRenderer<Node, Node>({ createElement: node, createText: node, createComment: node, patchProp() {}, setText() {}, setElementText() {}, parentNode: n => n.parent, nextSibling: () => null, insert(n, p) { n.parent = p; p.children.push(n) }, remove() {} })
interface Form { openNative(): void; nativeCancelled(): void; nativePicked(event: Event): void; visibility(): void; preview?: HTMLVideoElement; showReviewFrame(): void; syncReview(): void; seekReview(event: Event): void; toggleReview(): Promise<void>; reviewCurrentTime: number; reviewDuration: number; previewPlaying: boolean; error: string; phase: string; shape: 'square' | 'original'; quality: 'standard' | 'hd'; previewURL: string; actualHD: boolean; choice: string; openCamera(): Promise<void>; start(): void; useVideo(): void; close(): void }
const native = vi.fn(), recorded = vi.fn(), closed = vi.fn(), revoked = vi.fn()
let unmount: (() => void) | undefined
beforeEach(() => {
  vi.clearAllMocks()
  Object.assign(mocks.state, { deviceID: 'device', openChatKey: 'chat', tenantID: 'work', connected: true }); mocks.conn = {}
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
async function review(form: Form, seconds = 2) {
  const { camera, finish } = capture()
  mocks.open.mockResolvedValue(camera); await form.openCamera(); form.start()
  finish({ file: new File(['mp4'], 'video.mp4'), width: 480, height: 480, seconds })
  await nextTick(); await nextTick()
  const video = {
    duration: seconds, currentTime: 0, paused: true, ended: false, srcObject: null,
    load: vi.fn(), play: vi.fn(async () => { video.paused = false }), pause: vi.fn(() => { video.paused = true }),
  }
  form.preview = video as unknown as HTMLVideoElement
  return video
}
function seek(form: Form, value: string) { form.seekReview({ target: { value } } as unknown as Event) }
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

  it('seeks through circular review without playing or accepting it and clamps to the available duration', async () => {
    const form = await mount(), video = await review(form, 8)
    seek(form, '3.5')
    expect(video.currentTime).toBe(3.5); expect(form.reviewCurrentTime).toBe(3.5)
    form.showReviewFrame(); expect(video.currentTime).toBe(3.5)
    seek(form, '-4'); expect(video.currentTime).toBe(0)
    seek(form, '20'); expect(video.currentTime).toBe(8)
    seek(form, 'NaN'); expect(video.currentTime).toBe(8)
    expect(form.reviewDuration).toBe(8)
    expect(video.play).not.toHaveBeenCalled(); expect(recorded).not.toHaveBeenCalled()
  })

  it('uses the recording duration before finite media metadata and tracks playback progress', async () => {
    const form = await mount(), video = await review(form, 8)
    video.duration = Infinity; form.syncReview(); expect(form.reviewDuration).toBe(8)
    seek(form, '4'); expect(video.currentTime).toBe(4)
    video.duration = 7.4; video.currentTime = 5.2; video.paused = false; form.syncReview()
    expect(form.reviewDuration).toBe(7.4); expect(form.reviewCurrentTime).toBe(5.2); expect(form.previewPlaying).toBe(true)
    seek(form, '8'); expect(video.currentTime).toBe(7.4)
    expect(video.play).not.toHaveBeenCalled()
    video.ended = true; video.paused = true; form.syncReview(); expect(form.previewPlaying).toBe(false)
    await form.toggleReview(); expect(video.currentTime).toBe(0); expect(video.play).toHaveBeenCalledOnce()
  })

  it.each(['close', 'rerecord', 'unmount', 'chat', 'device', 'workspace', 'connection'])('stops review playback and releases its timeline on %s', async (action) => {
    const form = await mount(), video = await review(form, 8)
    seek(form, '3'); await form.toggleReview(); expect(form.previewPlaying).toBe(true)
    if (action === 'close') form.close()
    else if (action === 'rerecord') { mocks.open.mockResolvedValue(capture().camera); await form.openCamera() }
    else if (action === 'unmount') { unmount?.(); unmount = undefined }
    else if (action === 'chat') mocks.state.openChatKey = 'another-chat'
    else if (action === 'device') mocks.state.deviceID = 'another-device'
    else if (action === 'workspace') mocks.state.tenantID = 'another-workspace'
    else { mocks.conn = null; mocks.state.connected = false }
    expect(video.pause).toHaveBeenCalled(); expect(revoked).toHaveBeenCalledWith('blob:video')
    expect(form.previewURL).toBe(''); expect(form.reviewCurrentTime).toBe(0); expect(form.reviewDuration).toBe(0)
    expect(form.previewPlaying).toBe(false); expect(recorded).not.toHaveBeenCalled()
  })

  it('does not restart playback or publish an error when a play request finishes after closing', async () => {
    const form = await mount(), video = await review(form)
    let finish!: () => void
    video.play.mockImplementation(() => new Promise<void>(resolve => { finish = resolve }))
    const playing = form.toggleReview(); form.close(); video.pause.mockClear()
    finish(); await playing
    expect(video.pause).toHaveBeenCalledOnce(); expect(form.previewPlaying).toBe(false); expect(form.error).toBe('')
    expect(recorded).not.toHaveBeenCalled()
  })

  it('preserves HD circular delivery after seeking and reviewing', async () => {
    const form = await mount(); form.quality = 'hd'
    const { camera, finish } = capture(720, 720); mocks.open.mockResolvedValue(camera)
    await form.openCamera(); form.start(); const file = new File(['mp4'], 'video.mp4')
    finish({ file, width: 720, height: 720, seconds: 4 }); await nextTick(); await nextTick()
    form.preview = { duration: 4, currentTime: 0, paused: true, pause: vi.fn() } as unknown as HTMLVideoElement
    seek(form, '2'); expect(recorded).not.toHaveBeenCalled()
    form.useVideo(); expect(recorded).toHaveBeenCalledWith(file, 'ptv_hd', 4)
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
