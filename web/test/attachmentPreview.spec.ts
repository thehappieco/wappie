import { createRenderer, ssrContextKey } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
vi.mock('../src/ui/i18n', () => ({ t: (value: string) => value }))
interface Node { parent: Node | null; children: Node[] }
const node = (): Node => ({ parent: null, children: [] })
const renderer = createRenderer<Node, Node>({ createElement: node, createText: node, createComment: node, patchProp() {}, setText() {}, setElementText() {}, parentNode: n => n.parent, nextSibling: () => null,
  insert(n, parent) { n.parent = parent; parent.children.push(n) }, remove() {} })
interface Form { media?: HTMLMediaElement; error: string; playing: boolean; position: number; duration: number; toggle(): Promise<void>; seek(event: Event): void; update(): void; stop(): void }
let unmount: (() => void) | undefined
async function mount(): Promise<Form> {
  const Preview = (await import('../src/components/AttachmentPreview.vue')).default
  const app = renderer.createApp({ ...Preview, render: () => null }, { url: 'blob:preview', kind: 'video', circular: true, seconds: 5 })
  app.provide(ssrContextKey, {})
  const value = app.mount(node()) as unknown as { $: { setupState: Form } }; unmount = () => app.unmount()
  return value.$.setupState
}
function player() {
  return { paused: true, ended: false, duration: 5, currentTime: 0, play: vi.fn().mockResolvedValue(undefined), pause: vi.fn(), removeAttribute: vi.fn(), load: vi.fn() }
}
afterEach(() => { unmount?.(); unmount = undefined; vi.restoreAllMocks() })

describe('local attachment playback', () => {
  it('plays only on request and seeks without starting playback', async () => {
    const form = await mount(), media = player(); form.media = media as unknown as HTMLMediaElement
    expect(media.play).not.toHaveBeenCalled()
    form.seek({ target: { value: '2.5' } } as unknown as Event)
    expect(media.currentTime).toBe(2.5); expect(media.play).not.toHaveBeenCalled()
    await form.toggle(); expect(media.play).toHaveBeenCalledOnce()
    media.paused = false; await form.toggle(); expect(media.pause).toHaveBeenCalledOnce()
  })
  it('clamps seeks to the real duration and handles unknown recorder duration', async () => {
    const form = await mount(), media = player(); media.duration = Infinity; form.media = media as unknown as HTMLMediaElement
    form.update(); expect(form.duration).toBe(5)
    form.seek({ target: { value: '30' } } as unknown as Event); expect(media.currentTime).toBe(5)
    media.duration = 4; form.update(); expect(form.duration).toBe(4)
    form.seek({ target: { value: '-2' } } as unknown as Event); expect(media.currentTime).toBe(0)
    form.seek({ target: { value: 'invalid' } } as unknown as Event); expect(media.currentTime).toBe(0)
  })
  it('stops decoding on removal without revoking the URL transferred to the outbox', async () => {
    const form = await mount(), media = player(); form.media = media as unknown as HTMLMediaElement
    const revoke = vi.spyOn(URL, 'revokeObjectURL')
    unmount?.(); unmount = undefined
    expect(media.pause).toHaveBeenCalledOnce(); expect(media.removeAttribute).toHaveBeenCalledWith('src'); expect(media.load).toHaveBeenCalledOnce()
    expect(revoke).not.toHaveBeenCalled()
  })
  it('ignores a late play rejection after discard', async () => {
    const form = await mount(), media = player(); form.media = media as unknown as HTMLMediaElement
    let reject!: (reason: unknown) => void; media.play.mockReturnValue(new Promise((_resolve, fail) => { reject = fail }))
    const playing = form.toggle(); form.stop(); reject(new DOMException('Interrupted', 'AbortError')); await playing
    expect(form.error).toBe('')
  })
})
