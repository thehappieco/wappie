import { t } from '../ui/i18n'

export type VideoQuality = 'standard' | 'hd'
export interface RecordedVideo { file: File; seconds: number; width: number; height: number }
export interface VideoRecording {
  stop(): Promise<RecordedVideo | null>
  cancel(): void
  done: Promise<RecordedVideo | null>
}
export interface VideoCamera {
  /** Original camera stream for a muted, circular preview. */
  stream: MediaStream
  /** Encoded dimensions, which may be below the requested quality. */
  width: number
  height: number
  mimeType: string
  /** One recording per camera; repeated calls return that same recording. */
  start(): VideoRecording
  dispose(): void
}

const MAX_DURATION_MS = 59_800
const MAX_BYTES = 64 * 1024 * 1024
const OPEN_TIMEOUT_MS = 10_000
const STOP_TIMEOUT_MS = 5_000
const MIME_TYPES = [
  'video/mp4;codecs=avc1.42E01F,mp4a.40.2',
  'video/mp4;codecs=avc1.424028,mp4a.40.2',
  'video/mp4;codecs=avc1,mp4a.40.2',
]

/** Never rely on a generic MP4 default, which may choose HEVC or other audio. */
export function preferredVideoMime(): string {
  if (typeof MediaRecorder !== 'function' || typeof MediaRecorder.isTypeSupported !== 'function') return ''
  for (const mime of MIME_TYPES) {
    try { if (MediaRecorder.isTypeSupported(mime)) return mime } catch { /* Unsupported codec syntax. */ }
  }
  return ''
}

export function videoRecordingAvailable(): boolean {
  return typeof navigator !== 'undefined' && typeof navigator.mediaDevices?.getUserMedia === 'function'
    && typeof document !== 'undefined' && typeof HTMLCanvasElement !== 'undefined'
    && typeof HTMLCanvasElement.prototype.captureStream === 'function'
    && typeof requestAnimationFrame === 'function' && typeof cancelAnimationFrame === 'function'
    && Boolean(preferredVideoMime())
}

function abortError(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException('Aborted', 'AbortError')
}

/** getUserMedia cannot be aborted. A late permission grant still belongs to us. */
function requestCamera(constraints: MediaStreamConstraints, signal?: AbortSignal): Promise<MediaStream> {
  return new Promise((resolve, reject) => {
    let finished = false
    const cleanup = () => signal?.removeEventListener('abort', aborted)
    function aborted() {
      if (finished) return
      finished = true; cleanup(); reject(abortError(signal!))
    }
    if (signal?.aborted) { aborted(); return }
    signal?.addEventListener('abort', aborted, { once: true })
    let permission: Promise<MediaStream>
    try { permission = navigator.mediaDevices.getUserMedia(constraints) }
    catch (error) { finished = true; cleanup(); reject(error); return }
    permission.then(stream => {
      if (finished) { for (const track of stream.getTracks()) track.stop(); return }
      finished = true; cleanup(); resolve(stream)
    }, error => {
      if (finished) return
      finished = true; cleanup(); reject(error)
    })
  })
}

function playCamera(video: HTMLVideoElement, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    let finished = false
    const timeout = setTimeout(() => finish(new Error(t('A câmera não ficou pronta. Tente abrir novamente.'))), OPEN_TIMEOUT_MS)
    const abort = () => finish(abortError(signal!))
    const failed = () => finish(new Error(t('Não foi possível abrir a imagem da câmera.')))
    function ready() { if (video.readyState >= 2 && video.videoWidth > 0 && video.videoHeight > 0) finish() }
    function finish(error?: unknown) {
      if (finished) return
      finished = true
      clearTimeout(timeout)
      signal?.removeEventListener('abort', abort)
      video.removeEventListener('loadeddata', ready)
      video.removeEventListener('resize', ready)
      video.removeEventListener('error', failed)
      if (error !== undefined) reject(error)
      else resolve()
    }
    if (signal?.aborted) { abort(); return }
    signal?.addEventListener('abort', abort, { once: true })
    video.addEventListener('loadeddata', ready)
    video.addEventListener('resize', ready)
    video.addEventListener('error', failed)
    try { void video.play().then(ready, finish) } catch (error) { finish(error) }
  })
}

/** A recorder may omit codecs in emitted chunks; explicit contradictory types are rejected. */
function compatibleOutput(mime: string): boolean {
  const normalized = mime.toLowerCase().replace(/\s|"/g, '')
  const parts = normalized.split(';')
  if (parts[0] !== 'video/mp4') return false
  const codecs = parts.find(part => part.startsWith('codecs='))?.slice(7).split(',')
  return !codecs || codecs.length === 2 && codecs.some(codec => /^avc1(?:\.[0-9a-f]{6})?$/.test(codec)) && codecs.includes('mp4a.40.2')
}

export async function openVideoCamera(options: {
  quality: VideoQuality
  facingMode: 'user' | 'environment'
  shape?: 'square' | 'original'
  signal?: AbortSignal
}): Promise<VideoCamera> {
  const { signal } = options
  signal?.throwIfAborted()
  if (!videoRecordingAvailable()) throw new Error(t('Este navegador não grava vídeo no formato necessário. Use a câmera do celular para anexar um vídeo.'))
  const mimeType = preferredVideoMime()
  const target = options.quality === 'hd' ? 720 : 480
  const square = options.shape !== 'original'
  const stream = await requestCamera({
    video: { facingMode: { ideal: options.facingMode }, width: { ideal: square ? target : Math.round(target * 16 / 9) }, height: { ideal: target }, frameRate: { ideal: 30, max: 30 } },
    audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
  }, signal)

  let video: HTMLVideoElement | undefined
  let canvas: HTMLCanvasElement | undefined
  let captured: MediaStream | undefined
  let animation: number | undefined
  let disposed = false
  let recording: VideoRecording | undefined
  let recordingInterrupted: (() => void) | undefined
  const previewAbort = new AbortController()
  const ownedTracks = new Set(stream.getTracks())

  function release() {
    if (disposed) return
    disposed = true
    previewAbort.abort(signal?.reason ?? new DOMException('Aborted', 'AbortError'))
    signal?.removeEventListener('abort', dispose)
    if (animation !== undefined) cancelAnimationFrame(animation)
    animation = undefined
    for (const track of ownedTracks) {
      track.removeEventListener('ended', sourceEnded)
      track.stop()
    }
    if (video) { video.pause(); video.srcObject = null }
    if (canvas) { canvas.width = 0; canvas.height = 0 }
  }
  function dispose() {
    if (recording) recording.cancel()
    else release()
  }
  function sourceEnded() {
    if (recordingInterrupted) recordingInterrupted()
    else {
      previewAbort.abort(new Error(t('A câmera ou o microfone foi desconectado.')))
      release()
    }
  }
  for (const track of ownedTracks) track.addEventListener('ended', sourceEnded)
  signal?.addEventListener('abort', dispose, { once: true })

  try {
    signal?.throwIfAborted()
    if (!stream.getVideoTracks().length || !stream.getAudioTracks().length || [...ownedTracks].some(track => track.readyState === 'ended')) {
      throw new Error(t('A câmera ou o microfone não está disponível.'))
    }
    video = document.createElement('video')
    video.muted = true
    video.playsInline = true
    video.autoplay = true
    video.srcObject = stream
    await playCamera(video, previewAbort.signal)
    signal?.throwIfAborted()
    previewAbort.signal.throwIfAborted()
    const sourceWidth = video.videoWidth
    const sourceHeight = video.videoHeight
    const scale = Math.min(1, target / Math.min(sourceWidth, sourceHeight))
    const width = Math.floor((square ? Math.min(sourceWidth, sourceHeight) : sourceWidth) * scale / 2) * 2
    const height = Math.floor((square ? Math.min(sourceWidth, sourceHeight) : sourceHeight) * scale / 2) * 2
    if (Math.min(width, height) < 2) throw new Error(t('Não foi possível identificar o tamanho da câmera.'))
    canvas = document.createElement('canvas')
    canvas.width = width; canvas.height = height
    const context = canvas.getContext('2d', { alpha: false })
    if (!context) throw new Error(t('Este navegador não conseguiu preparar a gravação de vídeo.'))

    function draw() {
      if (!video || video.readyState < 2) return
      const crop = Math.min(video.videoWidth, video.videoHeight)
      if (square) {
        if (crop < width) throw new Error(t('A resolução da câmera mudou. Grave o vídeo novamente.'))
        context!.drawImage(video, (video.videoWidth - crop) / 2, (video.videoHeight - crop) / 2, crop, crop, 0, 0, width, height)
      } else {
        if (video.videoWidth < width || video.videoHeight < height || Math.abs(video.videoWidth / video.videoHeight - sourceWidth / sourceHeight) > .001) {
          throw new Error(t('A resolução da câmera mudou. Grave o vídeo novamente.'))
        }
        context!.drawImage(video, 0, 0, video.videoWidth, video.videoHeight, 0, 0, width, height)
      }
    }

    function start(): VideoRecording {
      if (recording) return recording
      if (disposed || signal?.aborted || [...ownedTracks].some(track => track.readyState === 'ended')) {
        release()
        throw new Error(t('A câmera foi encerrada. Abra novamente para gravar.'))
      }
      let recorder: MediaRecorder
      try {
        draw()
        captured = canvas!.captureStream(30)
        for (const track of captured.getTracks()) { ownedTracks.add(track); track.addEventListener('ended', sourceEnded) }
        if (!captured.getVideoTracks().length) throw new Error(t('Este navegador não conseguiu preparar a gravação de vídeo.'))
        for (const track of stream.getAudioTracks()) captured.addTrack(track)
        recorder = new MediaRecorder(captured, { mimeType, videoBitsPerSecond: Math.min(width, height) >= 720 ? 4_000_000 : 2_000_000, audioBitsPerSecond: 128_000 })
        if (recorder.mimeType && !compatibleOutput(recorder.mimeType)) throw new Error(t('O navegador não produziu um vídeo MP4 compatível.'))
      } catch (error) { release(); throw error }

      const chunks: Blob[] = []
      let byteCount = 0
      let settled = false
      let stopping = false
      const startedAt = performance.now()
      let stoppedAt: number | undefined
      let ceiling: ReturnType<typeof setTimeout> | undefined
      let stopTimeout: ReturnType<typeof setTimeout> | undefined
      let resolve!: (value: RecordedVideo | null) => void
      let reject!: (error: unknown) => void
      const done = new Promise<RecordedVideo | null>((yes, no) => { resolve = yes; reject = no })
      // Auto-stop/errors can settle before the UI awaits done; keep the promise
      // observable without an unhandled-rejection event during that interval.
      void done.catch(() => {})

      function finish(value: RecordedVideo | null, error?: unknown) {
        if (settled) return
        settled = true
        clearTimeout(ceiling); clearTimeout(stopTimeout)
        document.removeEventListener('visibilitychange', backgrounded)
        recorder.ondataavailable = null; recorder.onstop = null; recorder.onerror = null
        if (!stopping && recorder.state !== 'inactive') {
          stopping = true
          try { recorder.stop() } catch { /* Resources are released below. */ }
        }
        release()
        chunks.length = 0
        if (error !== undefined) reject(error)
        else resolve(value)
      }
      function failed(error: unknown) { finish(null, error) }
      function stop(): Promise<RecordedVideo | null> {
        if (!stopping && !settled) {
          stopping = true; stoppedAt = performance.now()
          clearTimeout(ceiling)
          stopTimeout = setTimeout(() => failed(new Error(t('A gravação não foi finalizada. Tente novamente.'))), STOP_TIMEOUT_MS)
          try { if (recorder.state !== 'inactive') recorder.stop() }
          catch (error) { failed(error) }
          release()
        }
        return done
      }
      function backgrounded() { if (document.visibilityState === 'hidden') void stop() }
      recorder.ondataavailable = event => {
        if (settled || event.data.size === 0) return
        if (event.data.type && !compatibleOutput(event.data.type)) { failed(new Error(t('O navegador não produziu um vídeo MP4 compatível.'))); return }
        if (event.data.size > MAX_BYTES - byteCount) { failed(new Error(t('A gravação ultrapassou 64 MB. Grave um vídeo mais curto.'))); return }
        chunks.push(event.data); byteCount += event.data.size
        if (!stopping && performance.now() - startedAt >= MAX_DURATION_MS) void stop()
      }
      recorder.onstop = () => {
        if (settled) return
        stoppedAt ??= performance.now()
        if (!byteCount) { finish(null); return }
        try {
          const file = new File(chunks, 'gravacao.mp4', { type: 'video/mp4' })
          finish({ file, width, height, seconds: Math.max(1, Math.min(60, Math.ceil((stoppedAt - startedAt) / 1000))) })
        } catch (error) { failed(error) }
      }
      recorder.onerror = () => failed(new Error(t('Não foi possível gravar o vídeo. Tente novamente.')))
      recordingInterrupted = () => { if (!stopping) failed(new Error(t('A câmera ou o microfone foi desconectado.'))) }
      recording = { stop, cancel: () => finish(null), done }
      let lastFrame = -Infinity
      function frame(now: number) {
        if (disposed || settled || stopping) return
        if (performance.now() - startedAt >= MAX_DURATION_MS) { void stop(); return }
        try {
          if (now - lastFrame >= 1000 / 30) { draw(); lastFrame = now }
          animation = requestAnimationFrame(frame)
        } catch (error) { failed(error) }
      }
      try {
        // WebKit can lose the last AAC fragment when stop meets a timeslice
        // boundary. The duration/bitrate bound keeps this single final blob
        // modest; ondataavailable still enforces the absolute size ceiling.
        recorder.start()
        if (!settled) {
          ceiling = setTimeout(() => { void stop() }, MAX_DURATION_MS)
          document.addEventListener('visibilitychange', backgrounded)
          animation = requestAnimationFrame(frame)
        }
      } catch (error) { failed(error); throw error }
      return recording
    }

    return { stream, width, height, mimeType, start, dispose }
  } catch (error) { release(); throw error }
}
