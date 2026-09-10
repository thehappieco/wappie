import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { openVideoCamera, preferredVideoMime, videoRecordingAvailable, type VideoCamera } from '../src/media/videoCapture'

vi.mock('../src/ui/i18n', () => ({ t: (text: string) => text }))

class Track extends EventTarget {
  readyState = 'live'
  constructor(readonly kind: 'video' | 'audio') { super() }
  stop = vi.fn(() => { this.readyState = 'ended' })
  end() { this.readyState = 'ended'; this.dispatchEvent(new Event('ended')) }
}
class Stream {
  constructor(readonly tracks: Track[]) {}
  getTracks() { return this.tracks }
  getVideoTracks() { return this.tracks.filter(track => track.kind === 'video') }
  getAudioTracks() { return this.tracks.filter(track => track.kind === 'audio') }
  addTrack(track: Track) { this.tracks.push(track) }
}

let sourceWidth = 1920
let sourceHeight = 1080
let play: () => Promise<void>
let recordedMime = ''
let startFailure: Error | undefined
let stopCompletes = true
const videos: Video[] = []
class Video extends EventTarget {
  muted = false; playsInline = false; autoplay = false; srcObject: unknown = null
  videoWidth = sourceWidth; videoHeight = sourceHeight; readyState = 4
  pause = vi.fn()
  play = vi.fn(() => play())
  constructor() { super(); videos.push(this) }
}
const canvases: Canvas[] = []
class Canvas {
  width = 0; height = 0
  draw = vi.fn()
  context: { drawImage: ReturnType<typeof vi.fn> } | null = { drawImage: this.draw }
  stream = new Stream([new Track('video')])
  getContext = vi.fn(() => this.context)
  captureStream = vi.fn((_rate: number) => this.stream)
  constructor() { canvases.push(this) }
}
// Availability checks the browser prototype, not a test-only instance field.
Canvas.prototype.captureStream = function (this: Canvas, _rate: number) { return this.stream } as typeof Canvas.prototype.captureStream

const recorders: Recorder[] = []
class Recorder {
  static isTypeSupported = vi.fn((mime: string) => mime.includes('avc1') && mime.includes('mp4a.40.2'))
  state = 'inactive'
  mimeType: string
  ondataavailable: ((event: { data: Blob }) => void) | null = null
  onstop: (() => void) | null = null
  onerror: (() => void) | null = null
  constructor(readonly stream: Stream, readonly options: MediaRecorderOptions) {
    this.mimeType = recordedMime || options.mimeType || ''
    recorders.push(this)
  }
  start = vi.fn((_slice?: number) => {
    if (startFailure) throw startFailure
    this.state = 'recording'
  })
  stop = vi.fn(() => {
    this.state = 'inactive'
    if (stopCompletes) queueMicrotask(() => this.complete())
  })
  data(blob = new Blob(['native-mp4'], { type: 'video/mp4' })) { this.ondataavailable?.({ data: blob }) }
  complete() { this.data(); this.onstop?.() }
}

const getUserMedia = vi.fn()
let inputStream: Stream
let documentStub: EventTarget & { visibilityState: string; createElement: ReturnType<typeof vi.fn> }
let nextFrame = 0
const frames = new Map<number, FrameRequestCallback>()
const cameras: VideoCamera[] = []

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] })
  sourceWidth = 1920; sourceHeight = 1080; play = async () => {}
  recordedMime = ''; startFailure = undefined; stopCompletes = true
  recorders.length = 0; videos.length = 0; canvases.length = 0; frames.clear()
  Recorder.isTypeSupported.mockReset().mockImplementation(mime => mime.includes('avc1') && mime.includes('mp4a.40.2'))
  inputStream = new Stream([new Track('video'), new Track('audio')])
  getUserMedia.mockReset().mockResolvedValue(inputStream)
  documentStub = Object.assign(new EventTarget(), { visibilityState: 'visible', createElement: vi.fn((tag: string) => tag === 'video' ? new Video() : new Canvas()) })
  vi.stubGlobal('document', documentStub)
  vi.stubGlobal('navigator', { mediaDevices: { getUserMedia } })
  vi.stubGlobal('MediaRecorder', Recorder)
  vi.stubGlobal('HTMLCanvasElement', Canvas)
  vi.stubGlobal('requestAnimationFrame', vi.fn((callback: FrameRequestCallback) => { const id = ++nextFrame; frames.set(id, callback); return id }))
  vi.stubGlobal('cancelAnimationFrame', vi.fn((id: number) => { frames.delete(id) }))
})
afterEach(() => {
  for (const camera of cameras.splice(0)) camera.dispose()
  vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks()
})

async function open(options: Partial<Parameters<typeof openVideoCamera>[0]> = {}) {
  const camera = await openVideoCamera({ quality: 'standard', facingMode: 'user', ...options })
  cameras.push(camera)
  return camera
}
function expectReleased() {
  for (const track of inputStream.getTracks()) expect(track.stop).toHaveBeenCalledOnce()
  for (const canvas of canvases) {
    if (canvas.captureStream.mock.calls.length) for (const track of canvas.stream.getVideoTracks()) expect(track.stop).toHaveBeenCalledOnce()
    expect(canvas.width).toBe(0); expect(canvas.height).toBe(0)
  }
  expect(frames.size).toBe(0)
  if (videos.length) { expect(videos[0]!.srcObject).toBeNull(); expect(videos[0]!.pause).toHaveBeenCalledOnce() }
}

describe('native MP4 video capture', () => {
  it('requires explicit AVC and AAC support and never falls back to WebM or unspecified MP4', () => {
    expect(preferredVideoMime()).toBe('video/mp4;codecs=avc1.42E01F,mp4a.40.2')
    expect(videoRecordingAvailable()).toBe(true)
    Recorder.isTypeSupported.mockImplementation(mime => mime === 'video/mp4' || mime.startsWith('video/webm'))
    expect(preferredVideoMime()).toBe('')
    expect(videoRecordingAvailable()).toBe(false)
  })

  it('tries another explicit AVC profile when a browser rejects a codec syntax', () => {
    Recorder.isTypeSupported.mockImplementation(mime => { if (mime.includes('42E01F')) throw new TypeError('syntax'); return mime.includes('avc1,') })
    expect(preferredVideoMime()).toBe('video/mp4;codecs=avc1,mp4a.40.2')
  })

  it('leaves the camera untouched when the browser must use input-capture fallback', async () => {
    vi.stubGlobal('HTMLCanvasElement', class {})
    expect(videoRecordingAvailable()).toBe(false)
    await expect(open()).rejects.toThrow('formato necessário')
    expect(getUserMedia).not.toHaveBeenCalled()
  })

  it.each([
    ['standard', 1920, 1080, 'square', 480, 480],
    ['hd', 1280, 720, 'square', 720, 720],
    ['hd', 640, 480, 'square', 480, 480],
    ['hd', 641, 479, 'square', 478, 478],
    ['standard', 1920, 1080, 'original', 852, 480],
    ['hd', 1920, 1080, 'original', 1280, 720],
    ['hd', 640, 360, 'original', 640, 360],
    ['standard', 1080, 1920, 'original', 480, 852],
  ] as const)('uses %s at actual %ix%i with %s shape: %ix%i without enlargement', async (quality, width, height, shape, expectedWidth, expectedHeight) => {
    sourceWidth = width; sourceHeight = height
    const camera = await open({ quality, shape })
    expect([camera.width, camera.height]).toEqual([expectedWidth, expectedHeight])
    expect(camera.width).toBeLessThanOrEqual(width)
    expect(camera.height).toBeLessThanOrEqual(height)
    expect(recorders).toHaveLength(0)
    expect(frames.size).toBe(0)
    const recording = camera.start()
    const crop = Math.min(width, height)
    expect(canvases[0]!.draw).toHaveBeenCalledWith(videos[0], shape === 'square' ? (width - crop) / 2 : 0, shape === 'square' ? (height - crop) / 2 : 0,
      shape === 'square' ? crop : width, shape === 'square' ? crop : height, 0, 0, expectedWidth, expectedHeight)
    recording.cancel()
    expect(await recording.done).toBeNull()
    expectReleased()
  })

  it('opens a muted preview first, then records original audio and the square canvas at 30 FPS', async () => {
    const camera = await open({ facingMode: 'environment' })
    expect(camera.stream).toBe(inputStream)
    expect(getUserMedia).toHaveBeenCalledWith(expect.objectContaining({ video: expect.objectContaining({ facingMode: { ideal: 'environment' } }), audio: expect.any(Object) }))
    expect(videos[0]).toMatchObject({ muted: true, playsInline: true, autoplay: true, srcObject: inputStream })
    expect(recorders).toHaveLength(0)
    const recording = camera.start()
    expect(camera.start()).toBe(recording)
    expect(recorders).toHaveLength(1)
    expect(canvases[0]!.captureStream).toHaveBeenCalledWith(30)
    expect(recorders[0]!.stream.getAudioTracks()[0]).toBe(inputStream.getAudioTracks()[0])
    expect(recorders[0]!.stream.getVideoTracks()[0]).not.toBe(inputStream.getVideoTracks()[0])
    expect(recorders[0]!.start).toHaveBeenCalledWith()
    recording.cancel()
  })

  it('rejects an oversized terminal blob even when no periodic chunks were requested', async () => {
    const recording = (await open()).start(), recorder = recorders[0]!
    recorder.stop.mockImplementation(() => {
      recorder.state = 'inactive'
      queueMicrotask(() => { recorder.data({ size: 64 * 1024 * 1024 + 1, type: 'video/mp4' } as Blob); recorder.onstop?.() })
    })
    await expect(recording.stop()).rejects.toThrow('64 MB')
    expect(inputStream.getTracks().every(track => track.readyState === 'ended')).toBe(true)
  })

  it('returns a single MP4 file and the same promise when stop is pressed twice', async () => {
    const camera = await open()
    const recording = camera.start()
    await vi.advanceTimersByTimeAsync(2100)
    const result = recording.stop()
    expect(recording.stop()).toBe(result)
    expect(result).toBe(recording.done)
    const video = await result
    expect(video).toMatchObject({ width: 480, height: 480, seconds: 3 })
    expect(video!.file.name).toBe('gravacao.mp4')
    expect(video!.file.type).toBe('video/mp4')
    expect(await video!.file.text()).toBe('native-mp4')
    expect(recorders[0]!.stop).toHaveBeenCalledOnce()
    camera.dispose()
    expectReleased()
  })

  it('aborts the permission prompt immediately and stops tracks from a late grant', async () => {
    let grant!: (stream: Stream) => void
    getUserMedia.mockImplementation(() => new Promise(resolve => { grant = resolve }))
    const signal = new AbortController()
    const pending = open({ signal: signal.signal })
    const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    signal.abort()
    await rejected
    grant(inputStream)
    await Promise.resolve()
    expectReleased()
    expect(videos).toHaveLength(0)
  })

  it('does not request permission with an already aborted signal', async () => {
    const signal = new AbortController(); signal.abort()
    await expect(open({ signal: signal.signal })).rejects.toMatchObject({ name: 'AbortError' })
    expect(getUserMedia).not.toHaveBeenCalled()
  })

  it('releases an opened preview without ever starting a recorder', async () => {
    const camera = await open()
    camera.dispose(); camera.dispose()
    expect(() => camera.start()).toThrow('encerrada')
    expect(recorders).toHaveLength(0)
    expectReleased()
  })

  it('releases the microphone if the video track ends while only previewing', async () => {
    const camera = await open()
    inputStream.getVideoTracks()[0]!.end()
    expect(() => camera.start()).toThrow('encerrada')
    expectReleased()
  })

  it('rejects promptly if a source disappears while camera playback is pending', async () => {
    play = () => new Promise(() => {})
    const pending = open()
    const rejected = expect(pending).rejects.toThrow('desconectado')
    await Promise.resolve(); await Promise.resolve()
    inputStream.getVideoTracks()[0]!.end()
    await rejected
    expectReleased()
  })

  it('times out a preview that never becomes ready and cleans up every source track', async () => {
    play = () => new Promise(() => {})
    const pending = open()
    const rejected = expect(pending).rejects.toThrow('não ficou pronta')
    await vi.advanceTimersByTimeAsync(10_000)
    await rejected
    expectReleased()
  })

  it('aborts a preview while playback is pending', async () => {
    play = () => new Promise(() => {})
    const controller = new AbortController()
    const pending = open({ signal: controller.signal })
    const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    await Promise.resolve(); await Promise.resolve()
    controller.abort()
    await rejected
    expectReleased()
  })

  it.each(['cancel', 'dispose', 'abort'] as const)('discards all chunks and cleans up when the recording is ended by %s', async method => {
    const controller = new AbortController()
    const camera = await open({ signal: controller.signal })
    const recording = camera.start()
    recorders[0]!.data()
    if (method === 'cancel') recording.cancel()
    else if (method === 'dispose') camera.dispose()
    else controller.abort()
    expect(await recording.done).toBeNull()
    expect(await recording.stop()).toBeNull()
    recording.cancel(); camera.dispose()
    expect(recorders[0]!.stop).toHaveBeenCalledOnce()
    expectReleased()
  })

  it('automatically stops at 59.8 seconds and completes done without a later user action', async () => {
    const recording = (await open()).start()
    await vi.advanceTimersByTimeAsync(59_799)
    expect(recorders[0]!.stop).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect((await recording.done)?.seconds).toBe(60)
    expectReleased()
  })

  it('rejects a recording that exceeds the byte limit, including the final stop chunk', async () => {
    const recording = (await open()).start()
    stopCompletes = false
    const stopped = recording.stop()
    const rejected = expect(stopped).rejects.toThrow('64 MB')
    recorders[0]!.data({ size: 64 * 1024 * 1024 + 1, type: 'video/mp4' } as Blob)
    await rejected
    expectReleased()
  })

  it.each(['video/webm;codecs=vp9,opus', 'video/mp4;codecs=hev1.1.6.L93.B0,mp4a.40.2'])('does not relabel incompatible recorder output %s as MP4', async mime => {
    recordedMime = mime
    const camera = await open()
    expect(() => camera.start()).toThrow('MP4 compatível')
    expectReleased()
  })

  it('rejects WebM data even when the recorder claimed to accept the requested MIME', async () => {
    const recording = (await open()).start()
    const rejected = expect(recording.done).rejects.toThrow('MP4 compatível')
    recorders[0]!.data(new Blob(['webm'], { type: 'video/webm' }))
    await rejected
    expectReleased()
  })

  it.each(['recorder', 'track', 'canvas'] as const)('rejects and releases resources on a %s failure', async failure => {
    const recording = (await open()).start()
    const rejected = expect(recording.done).rejects.toBeInstanceOf(Error)
    if (failure === 'recorder') recorders[0]!.onerror?.()
    else if (failure === 'track') inputStream.getAudioTracks()[0]!.end()
    else {
      canvases[0]!.draw.mockImplementation(() => { throw new Error('canvas failed') })
      const [id, callback] = [...frames][0]!
      frames.delete(id); callback(1)
    }
    await rejected
    expectReleased()
  })

  it('releases the preview and canvas when MediaRecorder.start throws', async () => {
    const camera = await open()
    startFailure = new Error('encoder unavailable')
    expect(() => camera.start()).toThrow('encoder unavailable')
    expectReleased()
  })

  it('bounds a browser failure to deliver the final stop event', async () => {
    stopCompletes = false
    const recording = (await open()).start()
    const rejected = expect(recording.stop()).rejects.toThrow('não foi finalizada')
    await vi.advanceTimersByTimeAsync(5_000)
    await rejected
    expectReleased()
  })

  it('stops when the tab is hidden instead of recording behind a throttled timer', async () => {
    const recording = (await open()).start()
    documentStub.visibilityState = 'hidden'
    documentStub.dispatchEvent(new Event('visibilitychange'))
    expect(await recording.done).not.toBeNull()
    expectReleased()
  })

  it('rejects a resolution drop during recording instead of enlarging the smaller source', async () => {
    const recording = (await open({ quality: 'hd' })).start()
    const rejected = expect(recording.done).rejects.toThrow('resolução')
    videos[0]!.videoHeight = 360
    const [id, callback] = [...frames][0]!
    frames.delete(id); callback(1)
    await rejected
    expectReleased()
  })
})
