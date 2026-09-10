import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { compatibleMP4, prepareVideo, videoDimensions } from '../src/media/videoPrepare'
import { offer, planFor, refuse } from '../src/media/plan'

vi.mock('../src/media/videoCapture', () => ({ preferredVideoMime: () => 'video/mp4;codecs=avc1.42E01F,mp4a.40.2' }))

function box(name: string, ...body: Uint8Array[]): Uint8Array {
  const size = 8 + body.reduce((n, b) => n + b.length, 0), bytes = new Uint8Array(size)
  new DataView(bytes.buffer).setUint32(0, size); bytes.set(new TextEncoder().encode(name), 4)
  let offset = 8; for (const b of body) { bytes.set(b, offset); offset += b.length }
  return bytes
}
function mp4(...codecs: string[]): Blob {
  const entries = codecs.map(codec => {
    const body = new Uint8Array(codec === 'mp4a' ? 28 : 8)
    if (codec === 'mp4a') new DataView(body.buffer).setUint16(16, 2)
    return box(codec, body)
  })
  const full = new Uint8Array(8); new DataView(full.buffer).setUint32(4, entries.length)
  return new Blob([box('ftyp', new Uint8Array(8)) as BlobPart, box('moov', box('trak', box('mdia', box('minf', box('stbl', box('stsd', full, ...entries)))))) as BlobPart], { type: 'video/mp4' })
}
describe('video format and quality', () => {
  it('preserves landscape and portrait framing and never upscales', () => {
    expect(videoDimensions(1920, 1080, 480)).toEqual({ width: 852, height: 480 })
    expect(videoDimensions(1080, 1920, 720)).toEqual({ width: 720, height: 1280 })
    expect(videoDimensions(320, 240, 720)).toEqual({ width: 320, height: 240 })
    expect(videoDimensions(1920, 1080, 480, true)).toEqual({ width: 480, height: 480 })
    expect(videoDimensions(240, 320, 720, true)).toEqual({ width: 240, height: 240 })
  })
  it('accepts declared H264 with AAC or no audio', async () => {
    expect(await compatibleMP4(mp4('avc1', 'mp4a'))).toBe(true)
    expect(await compatibleMP4(mp4('avc3'))).toBe(true)
  })
  it('rejects HEVC, unsupported audio, empty tracks and a mislabeled file', async () => {
    expect(await compatibleMP4(mp4('hvc1', 'mp4a'))).toBe(false)
    expect(await compatibleMP4(mp4('avc1', 'ac-3'))).toBe(false)
    expect(await compatibleMP4(mp4('mp4a'))).toBe(false)
    expect(await compatibleMP4(new Blob(['not mp4'], { type: 'video/mp4' }))).toBe(false)
  })
  it('rejects truncated or impossible box sizes', async () => {
    const valid = mp4('avc1')
    expect(await compatibleMP4(valid.slice(0, valid.size - 2))).toBe(false)
    const invalid = new Uint8Array(16); new DataView(invalid.buffer).setUint32(0, 4)
    expect(await compatibleMP4(new Blob([invalid]))).toBe(false)
  })
  it('offers honest video formats while keeping the circular HKDF kind and caption restriction', () => {
    expect(offer({ name: 'a.mp4', type: 'video/mp4' })).toEqual(['video', 'video_hd', 'ptv', 'ptv_hd', 'gif', 'file'])
    expect(planFor('video_hd').kind).toBe('video')
    for (const choice of ['ptv', 'ptv_hd'] as const) {
      expect(planFor(choice).kind).toBe('ptv')
      expect(planFor(choice).captionAllowed).toBe(false)
      expect(refuse(planFor(choice), { name: 'a.mp4', size: 100 }, 'caption')).not.toBe('')
    }
  })
})

describe('conversion playback and recorder synchronization', () => {
  class Track { stop = vi.fn() }
  const videoTrack = new Track(), audioTrack = new Track()
  let playImplementation: () => Promise<void>
  let startError = false
  let videoDuration = 2
  let resumeStalls = false
  let decodeImplementation: () => Promise<{ length: number; numberOfChannels: number }>
  let video: Video
  let recorder: Recorder | undefined
  let audio: Audio | undefined
  let source: BufferSource | undefined
  let clock: { offset: { value: number }; connect: ReturnType<typeof vi.fn>; start: ReturnType<typeof vi.fn>; stop: ReturnType<typeof vi.fn>; disconnect: ReturnType<typeof vi.fn> } | undefined
  class Video extends EventTarget {
    muted = false; playsInline = false; preload = ''; duration = videoDuration; videoWidth = 1280; videoHeight = 720; readyState = 4; currentTime = 0
    set src(_url: string) { queueMicrotask(() => this.dispatchEvent(new Event('loadedmetadata'))) }
    play = vi.fn(() => playImplementation())
    pause = vi.fn(); removeAttribute = vi.fn(); load = vi.fn()
  }
  class Canvas {
    width = 0; height = 0
    getContext = () => ({ drawImage: vi.fn() })
    captureStream() {
      const tracks = [videoTrack]
      return { getTracks: () => tracks, addTrack: (track: Track) => tracks.push(track) }
    }
  }
  class BufferSource {
    buffer: unknown
    onended: (() => void) | null = null
    start = vi.fn(); stop = vi.fn(); connect = vi.fn(); disconnect = vi.fn()
  }
  class Audio {
    state = 'suspended'
    resume = vi.fn(async () => { if (resumeStalls) await new Promise<void>(() => {}); this.state = 'running' })
    close = vi.fn(async () => { this.state = 'closed' })
    decodeAudioData = vi.fn(() => decodeImplementation())
    createBufferSource = () => (source = new BufferSource())
    createConstantSource = () => (clock = { offset: { value: 0 }, connect: vi.fn(), start: vi.fn(), stop: vi.fn(), disconnect: vi.fn() })
    createMediaStreamDestination = () => ({ stream: { getAudioTracks: () => [audioTrack] } })
    constructor() { audio = this }
  }
  class Recorder {
    state = 'inactive'
    ondataavailable: ((event: { data: Blob }) => void) | null = null
    onstop: (() => void) | null = null
    onerror: (() => void) | null = null
    constructor() { recorder = this }
    start = vi.fn(() => { if (startError) throw new Error('encoder failed'); this.state = 'recording' })
    stop = vi.fn(() => {
      this.state = 'inactive'
      queueMicrotask(() => { this.ondataavailable?.({ data: mp4('avc1', 'mp4a') }); this.onstop?.() })
    })
  }

  beforeEach(() => {
    vi.useFakeTimers()
    videoTrack.stop.mockClear(); audioTrack.stop.mockClear(); recorder = undefined; audio = undefined; source = undefined; clock = undefined; startError = false; videoDuration = 2; resumeStalls = false
    decodeImplementation = async () => ({ length: 96_000, numberOfChannels: 2 })
    playImplementation = async () => {}
    vi.stubGlobal('document', Object.assign(new EventTarget(), { visibilityState: 'visible', createElement: (tag: string) => tag === 'video' ? (video = new Video()) : new Canvas() }))
    vi.stubGlobal('HTMLCanvasElement', Canvas)
    vi.stubGlobal('MediaRecorder', Recorder)
    vi.stubGlobal('AudioContext', Audio)
    vi.stubGlobal('requestAnimationFrame', vi.fn(() => 17))
    vi.stubGlobal('cancelAnimationFrame', vi.fn())
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:synthetic-video')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
  })
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks() })

  function convert(signal?: AbortSignal) {
    return prepareVideo(new File([mp4('avc1', 'mp4a')], 'source.mp4', { type: 'video/mp4' }), 'ptv', { signal })
  }
  async function ready() { await vi.waitFor(() => expect(video.play).toHaveBeenCalledOnce()) }
  function cleaned() {
    expect(videoTrack.stop).toHaveBeenCalledOnce(); expect(audioTrack.stop).toHaveBeenCalledOnce()
    expect(audio!.close).toHaveBeenCalledOnce(); expect(video.pause).toHaveBeenCalledOnce()
    expect(source!.disconnect).toHaveBeenCalledOnce(); expect(source!.buffer).toBeNull()
    expect(clock!.stop).toHaveBeenCalledOnce(); expect(clock!.disconnect).toHaveBeenCalledOnce()
    expect(URL.revokeObjectURL).toHaveBeenCalledExactlyOnceWith('blob:synthetic-video')
    expect(cancelAnimationFrame).toHaveBeenCalledWith(17)
  }
  async function ended() { video.dispatchEvent(new Event('ended')); source?.onended?.(); await vi.advanceTimersByTimeAsync(80) }

  it('does not encode a silent lead-in while WebKit is still starting playback', async () => {
    const pending = convert()
    await ready()
    await vi.advanceTimersByTimeAsync(1600)
    expect(recorder!.start).not.toHaveBeenCalled()
    expect(video.muted).toBe(true)
    video.dispatchEvent(new Event('playing'))
    expect(recorder!.start).toHaveBeenCalledExactlyOnceWith()
    expect(source!.start).toHaveBeenCalledOnce()
    video.dispatchEvent(new Event('playing'))
    expect(recorder!.start).toHaveBeenCalledOnce()
    video.currentTime = 2
    await ended()
    expect(await pending).toMatchObject({ width: 480, height: 480, seconds: 2 })
    cleaned()
  })

  it('arms playing before calling play so an immediate first frame is not missed', async () => {
    playImplementation = async () => { video.dispatchEvent(new Event('playing')) }
    const pending = convert()
    await ready()
    expect(recorder!.start).toHaveBeenCalledOnce()
    await ended()
    await pending
    cleaned()
  })

  it('cancels startup without recording when a delayed playing event arrives later', async () => {
    const controller = new AbortController()
    const pending = convert(controller.signal)
    const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    await ready()
    controller.abort()
    await rejected
    video.dispatchEvent(new Event('playing'))
    expect(recorder!.start).not.toHaveBeenCalled()
    expect(recorder!.stop).not.toHaveBeenCalled()
    cleaned()
  })

  it.each(['rejected', 'thrown'] as const)('settles a %s play failure and releases resources', async kind => {
    playImplementation = kind === 'rejected' ? () => Promise.reject(new Error('denied')) : () => { throw new Error('denied') }
    await expect(convert()).rejects.toThrow()
    expect(recorder!.start).not.toHaveBeenCalled()
    cleaned()
  })

  it('settles an encoder start failure in playing without orphaning the conversion promise', async () => {
    startError = true
    const pending = convert()
    const rejected = expect(pending).rejects.toThrow()
    await ready()
    video.dispatchEvent(new Event('playing'))
    await rejected
    cleaned()
  })

  it('stops an active recorder when conversion is cancelled', async () => {
    const controller = new AbortController()
    const pending = convert(controller.signal)
    const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    await ready()
    video.dispatchEvent(new Event('playing'))
    controller.abort()
    await rejected
    expect(recorder!.stop).toHaveBeenCalledOnce()
    cleaned()
  })

  it('bounds a browser that never starts playback', async () => {
    const pending = convert()
    const rejected = expect(pending).rejects.toThrow()
    await ready()
    await vi.advanceTimersByTimeAsync(34_000)
    await rejected
    expect(recorder!.start).not.toHaveBeenCalled()
    cleaned()
  })

  it('waits for the first advancing frame rather than an early WebKit playing event', async () => {
    const pending = convert()
    await ready()
    let frame: VideoFrameRequestCallback | undefined
    const callbacks = vi.fn((callback: VideoFrameRequestCallback) => { frame = callback; return 19 })
    Object.assign(video, { requestVideoFrameCallback: callbacks, cancelVideoFrameCallback: vi.fn() })
    video.dispatchEvent(new Event('playing'))
    frame!(0, { mediaTime: 0 } as VideoFrameCallbackMetadata)
    expect(recorder!.start).not.toHaveBeenCalled()
    frame!(1000, { mediaTime: 1 / 24 } as VideoFrameCallbackMetadata)
    expect(recorder!.start).toHaveBeenCalledExactlyOnceWith()
    expect(source!.start).toHaveBeenCalledOnce()
    await ended(); await pending; cleaned()
  })

  it('keeps the full decoded soundtrack after video ended and drains the last AAC frames', async () => {
    const pending = convert()
    await ready(); video.dispatchEvent(new Event('playing'))
    video.dispatchEvent(new Event('ended'))
    expect(recorder!.stop).not.toHaveBeenCalled()
    source!.onended!()
    await vi.advanceTimersByTimeAsync(79)
    expect(recorder!.stop).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    await pending
    expect(recorder!.stop).toHaveBeenCalledOnce(); cleaned()
  })

  it('also waits for video when the soundtrack ends first', async () => {
    const pending = convert()
    await ready(); video.dispatchEvent(new Event('playing'))
    source!.onended!(); await vi.advanceTimersByTimeAsync(80)
    expect(recorder!.stop).not.toHaveBeenCalled()
    video.dispatchEvent(new Event('ended'))
    await pending; cleaned()
  })

  it('preserves a video without audio without attempting to decode or add an audio track', async () => {
    const pending = prepareVideo(new File([mp4('avc1')], 'silent.mp4'), 'ptv')
    await ready()
    expect(audio).toBeUndefined()
    video.dispatchEvent(new Event('playing')); video.dispatchEvent(new Event('ended'))
    await pending
    expect(videoTrack.stop).toHaveBeenCalledOnce(); expect(audioTrack.stop).not.toHaveBeenCalled()
  })

  it('rejects a soundtrack that cannot be decoded instead of silently dropping it', async () => {
    decodeImplementation = () => Promise.reject(new Error('unsupported'))
    await expect(convert()).rejects.toThrow('preservar o áudio')
    expect(recorder).toBeUndefined(); expect(videoTrack.stop).toHaveBeenCalledOnce(); expect(audio!.close).toHaveBeenCalledOnce()
  })

  it('bounds estimated PCM before allocating the decoder while keeping long HD passthrough', async () => {
    videoDuration = 400
    const file = new File([mp4('avc1', 'mp4a')], 'long.mp4')
    await expect(prepareVideo(file, 'video')).rejects.toThrow('áudio deste vídeo é muito grande')
    expect(audio).toBeUndefined(); expect(recorder).toBeUndefined()
    const original = await prepareVideo(file, 'video_hd')
    expect(original.seconds).toBe(400); expect(original.blob.size).toBe(file.size)
    expect(audio).toBeUndefined()
  })

  it('checks actual PCM size as well as the source channel estimate', async () => {
    decodeImplementation = async () => ({ length: 16 * 1024 * 1024, numberOfChannels: 2 })
    await expect(convert()).rejects.toThrow('áudio deste vídeo é muito grande')
    expect(source).toBeUndefined(); expect(recorder).toBeUndefined(); expect(audio!.close).toHaveBeenCalledOnce()
  })

  it('cancels a pending decode promptly and never creates a late audio source', async () => {
    let release: ((buffer: { length: number; numberOfChannels: number }) => void) | undefined
    decodeImplementation = () => new Promise(resolve => { release = resolve })
    const controller = new AbortController()
    const pending = convert(controller.signal)
    const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    await vi.waitFor(() => expect(audio!.decodeAudioData).toHaveBeenCalledOnce())
    controller.abort(); await rejected
    expect(audio!.close).toHaveBeenCalledOnce(); expect(videoTrack.stop).toHaveBeenCalledOnce()
    release!({ length: 96_000, numberOfChannels: 2 }); await vi.advanceTimersByTimeAsync(0)
    expect(source).toBeUndefined(); expect(recorder).toBeUndefined()
  })

  it('cancels a queued first-frame callback without allowing a late encoder start', async () => {
    const controller = new AbortController()
    const pending = convert(controller.signal)
    const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    await ready()
    let frame: VideoFrameRequestCallback | undefined
    const cancelFrame = vi.fn()
    Object.assign(video, { requestVideoFrameCallback: (callback: VideoFrameRequestCallback) => { frame = callback; return 29 }, cancelVideoFrameCallback: cancelFrame })
    video.dispatchEvent(new Event('playing')); controller.abort(); await rejected
    expect(cancelFrame).toHaveBeenCalledWith(29)
    frame!(1000, { mediaTime: 1 / 24 } as VideoFrameCallbackMetadata)
    expect(recorder!.start).not.toHaveBeenCalled(); cleaned()
  })

  it('aborts conversion when the tab is hidden instead of keeping audio over frozen frames', async () => {
    const pending = convert()
    const rejected = expect(pending).rejects.toThrow('aba visível')
    await ready(); video.dispatchEvent(new Event('playing'))
    Object.assign(document, { visibilityState: 'hidden' }); document.dispatchEvent(new Event('visibilitychange'))
    await rejected
    expect(recorder!.stop).toHaveBeenCalledOnce(); cleaned()
  })

  it('cancels while AudioContext permission is still pending', async () => {
    resumeStalls = true
    const controller = new AbortController()
    const pending = convert(controller.signal)
    const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    await vi.waitFor(() => expect(audio!.resume).toHaveBeenCalledOnce())
    controller.abort(); await rejected
    expect(recorder).toBeUndefined(); cleaned()
  })

  it('does not assume an unfamiliar MP4 audio sample description is a silent video', async () => {
    decodeImplementation = () => Promise.reject(new Error('unsupported AMR'))
    await expect(prepareVideo(new File([mp4('avc1', 'samr')], 'mobile.3gp'), 'ptv')).rejects.toThrow('preservar o áudio')
    expect(audio!.decodeAudioData).toHaveBeenCalledOnce(); expect(recorder).toBeUndefined()
  })

  it('continues cleanup when the recorder throws while stopping', async () => {
    const pending = convert()
    const rejected = expect(pending).rejects.toThrow('preparar o vídeo')
    await ready(); video.dispatchEvent(new Event('playing'))
    recorder!.stop.mockImplementation(() => { throw new Error('stop failed') })
    await ended(); await rejected
    cleaned()
  })
})
