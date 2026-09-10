import { t } from '../ui/i18n'
import { MAX_BYTES, type Choice } from './plan'
import { preferredVideoMime } from './videoCapture'

export interface VideoProgress { fraction: number; converting: boolean }
export interface VideoPreparation { knownSeconds?: number; signal?: AbortSignal; onProgress?: (progress: VideoProgress) => void }
export interface PreparedVideo { blob: Blob; width: number; height: number; seconds: number; hd: boolean }

export function videoDimensions(width: number, height: number, side: number, square = false) {
  if (!(width > 0 && height > 0)) throw new Error(t('Não foi possível ler este vídeo.'))
  const scale = Math.min(1, side / Math.min(width, height))
  const even = (value: number) => Math.max(2, Math.floor(value / 2) * 2)
  return square
    ? { width: even(Math.min(side, width, height)), height: even(Math.min(side, width, height)) }
    : { width: even(width * scale), height: even(height * scale) }
}
export function isVideoChoice(choice: Choice): boolean { return ['video', 'video_hd', 'ptv', 'ptv_hd', 'gif'].includes(choice) }
function aborted(signal?: AbortSignal) { if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError') }

// Inspect sample descriptions rather than trusting a .mp4 extension: an MP4
// container can carry HEVC or another codec WhatsApp does not accept here.
interface MP4Description { codecs: string[]; audioChannels: number }
async function describeMP4(blob: Blob): Promise<MP4Description | null> {
  let offset = 0
  while (offset + 8 <= blob.size) {
    const header = new DataView(await blob.slice(offset, offset + 16).arrayBuffer())
    let size = header.getUint32(0), head = 8
    const type = String.fromCharCode(...new Uint8Array(header.buffer, 4, 4))
    if (size === 1) { if (header.byteLength < 16) return null; size = Number(header.getBigUint64(8)); head = 16 }
    if (size === 0) size = blob.size - offset
    if (!Number.isSafeInteger(size) || size < head || offset + size > blob.size) return null
    if (type === 'moov') {
      if (size > 16 * 1024 * 1024) return null
      const bytes = new Uint8Array(await blob.slice(offset + head, offset + size).arrayBuffer())
      const codecs: string[] = []
      let audioChannels = 0
      let valid = true
      const walk = (start: number, end: number, depth: number) => {
        if (depth > 8) { valid = false; return }
        for (let pos = start; pos + 8 <= end;) {
          const view = new DataView(bytes.buffer, bytes.byteOffset + pos, end - pos)
          const length = view.getUint32(0)
          if (length < 8 || pos + length > end) { valid = false; return }
          const name = String.fromCharCode(...bytes.subarray(pos + 4, pos + 8))
          if (['trak', 'mdia', 'minf', 'stbl'].includes(name)) walk(pos + 8, pos + length, depth + 1)
          if (name === 'stsd') {
            if (length < 16) { valid = false; return }
            const count = view.getUint32(12)
            let entry = pos + 16
            for (let n = 0; n < count; n++) {
              if (entry + 8 > pos + length) { valid = false; return }
              const size = new DataView(bytes.buffer, bytes.byteOffset + entry, 4).getUint32(0)
              if (size < 8 || entry + size > pos + length) { valid = false; return }
              const codec = String.fromCharCode(...bytes.subarray(entry + 4, entry + 8))
              codecs.push(codec)
              if (['mp4a', 'ac-3', 'ec-3', 'alac', 'Opus', 'fLaC', 'lpcm', 'sowt', 'twos', 'enca'].includes(codec)) {
                const channels = size >= 36 ? new DataView(bytes.buffer, bytes.byteOffset + entry + 24, 2).getUint16(0) : 0
                audioChannels = Math.max(audioChannels, channels >= 1 && channels <= 8 ? channels : 8)
              }
              entry += size
            }
          }
          pos += length
        }
      }
      walk(0, bytes.length, 0)
      return valid ? { codecs, audioChannels } : null
    }
    offset += size
  }
  return null
}
function compatibleDescription(description: MP4Description | null): boolean {
  return !!description && description.codecs.some(codec => ['avc1', 'avc3'].includes(codec)) && description.codecs.every(codec => ['avc1', 'avc3', 'mp4a'].includes(codec))
}
export async function compatibleMP4(blob: Blob): Promise<boolean> { return compatibleDescription(await describeMP4(blob)) }

const MAX_AUDIO_PCM_BYTES = 96 * 1024 * 1024
const AUDIO_SAMPLE_RATE = 48_000
const AUDIO_DRAIN_MS = 80
function cancellable<T>(task: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return task
  return new Promise((resolve, reject) => {
    const cancel = () => reject(new DOMException('Cancelled', 'AbortError'))
    signal.addEventListener('abort', cancel, { once: true })
    task.then(value => { signal.removeEventListener('abort', cancel); resolve(value) }, error => { signal.removeEventListener('abort', cancel); reject(error) })
    if (signal.aborted) cancel()
  })
}
function hasVideoAudio(video: HTMLVideoElement, description: MP4Description | null): boolean {
  if (description) return description.audioChannels > 0 || description.codecs.some(codec => !['avc1', 'avc3', 'hvc1', 'hev1', 'vp08', 'vp09', 'av01', 'mp4v', 'encv'].includes(codec))
  const media = video as HTMLVideoElement & { audioTracks?: { length: number }; captureStream?: () => MediaStream }
  if (media.audioTracks) return media.audioTracks.length > 0
  // Chromium exposes track membership through captureStream; Safari exposes
  // audioTracks. Only inspect the tracks after loadeddata and stop this probe.
  if (media.captureStream) {
    const probe = media.captureStream()
    try { return probe.getAudioTracks().length > 0 } finally { probe.getTracks().forEach(track => track.stop()) }
  }
  // An unknown source must decode successfully: never silently omit its sound.
  return true
}

function waitFor(video: HTMLVideoElement, event: string, signal?: AbortSignal, timeout = 15_000): Promise<void> {
  return new Promise((resolve, reject) => {
    const finish = (error?: Error) => {
      clearTimeout(timer); video.removeEventListener(event, success); video.removeEventListener('error', fail); signal?.removeEventListener('abort', cancel)
      error ? reject(error) : resolve()
    }
    const success = () => finish(), fail = () => finish(new Error(t('Não foi possível ler este vídeo.')))
    const cancel = () => finish(new DOMException('Cancelled', 'AbortError'))
    const timer = setTimeout(fail, timeout)
    video.addEventListener(event, success, { once: true }); video.addEventListener('error', fail, { once: true }); signal?.addEventListener('abort', cancel, { once: true })
    if (signal?.aborted) cancel()
  })
}

/** All conversion stays local; the usual encrypted upload receives its output. */
export async function prepareVideo(file: File, choice: Choice, options: VideoPreparation = {}): Promise<PreparedVideo> {
  const { signal, onProgress } = options
  aborted(signal)
  const video = document.createElement('video')
  const url = URL.createObjectURL(file)
  video.muted = true; video.playsInline = true; video.preload = 'auto'
  let stream: MediaStream | undefined, audio: AudioContext | undefined, recorder: MediaRecorder | undefined
  let audioSource: AudioBufferSourceNode | undefined
  let audioClock: ConstantSourceNode | undefined
  let animation = 0, progressTimer: ReturnType<typeof setInterval> | undefined
  try {
    const loaded = waitFor(video, 'loadedmetadata', signal)
    video.src = url
    await loaded
    const duration = Number.isFinite(video.duration) ? video.duration : options.knownSeconds || 0
    if (!Number.isFinite(duration) || duration <= 0 || !video.videoWidth || !video.videoHeight) throw new Error(t('Não foi possível ler este vídeo.'))
    const square = choice === 'ptv' || choice === 'ptv_hd'
    if (square && duration > 60.15) throw new Error(t('O vídeo circular pode ter no máximo 60 segundos.'))
    const hd = choice === 'video_hd' || choice === 'ptv_hd'
    if (hd && Math.min(video.videoWidth, video.videoHeight) < 720) throw new Error(t('Este vídeo tem resolução inferior a HD. Escolha a qualidade normal.'))
    const size = videoDimensions(video.videoWidth, video.videoHeight, hd && !square ? Math.min(video.videoWidth, video.videoHeight) : hd ? 720 : 480, square)
    const seconds = square ? Math.min(60, Math.ceil(duration)) : Math.ceil(duration)
    onProgress?.({ fraction: 0, converting: false })
    const description = await describeMP4(file)
    const compatible = compatibleDescription(description)
    aborted(signal)
    if (compatible && (choice !== 'gif' || !description?.audioChannels) && video.videoWidth === size.width && video.videoHeight === size.height) {
      onProgress?.({ fraction: 1, converting: false })
      return { blob: new Blob([file], { type: 'video/mp4' }), ...size, seconds, hd }
    }
    const mimeType = preferredVideoMime()
    if (!mimeType || typeof HTMLCanvasElement.prototype.captureStream !== 'function') throw new Error(t('Este navegador não consegue converter o vídeo para MP4. Use outro navegador ou envie como documento.'))
    const canvas = document.createElement('canvas'); canvas.width = size.width; canvas.height = size.height
    const context = canvas.getContext('2d', { alpha: false })
    if (!context) throw new Error(t('Não foi possível preparar o vídeo.'))
    if (video.readyState < 2) await waitFor(video, 'loadeddata', signal)
    const draw = () => {
      const side = Math.min(video.videoWidth, video.videoHeight)
      if (square) context.drawImage(video, (video.videoWidth - side) / 2, (video.videoHeight - side) / 2, side, side, 0, 0, size.width, size.height)
      else context.drawImage(video, 0, 0, size.width, size.height)
      animation = requestAnimationFrame(draw)
    }
    draw()
    stream = canvas.captureStream(30)
    const videoBitsPerSecond = hd ? 5_000_000 : 1_500_000
    if (duration * (videoBitsPerSecond + 128_000) / 8 * 1.2 > MAX_BYTES) throw new Error(t('O vídeo preparado ultrapassou o limite de tamanho.'))
    // WebKit's media-element audio source can start late and discard the tail.
    // Decode locally, then start the complete soundtrack with the encoder. The
    // channel estimate bounds PCM before decode; verify the actual buffer too.
    if (choice !== 'gif' && hasVideoAudio(video, description)) {
      if (duration * AUDIO_SAMPLE_RATE * (description?.audioChannels || 8) * 4 > MAX_AUDIO_PCM_BYTES) throw new Error(t('O áudio deste vídeo é muito grande para converter neste dispositivo. Envie o original em HD ou como documento.'))
      audio = new AudioContext({ sampleRate: AUDIO_SAMPLE_RATE })
      let buffer: AudioBuffer
      try { buffer = await cancellable(audio.decodeAudioData(await cancellable(file.arrayBuffer(), signal)), signal) }
      catch (error) { aborted(signal); throw new Error(t('Não foi possível preservar o áudio deste vídeo. Envie o original em HD ou como documento.')) }
      if (buffer.length * buffer.numberOfChannels * 4 > MAX_AUDIO_PCM_BYTES) throw new Error(t('O áudio deste vídeo é muito grande para converter neste dispositivo. Envie o original em HD ou como documento.'))
      const source = audio.createBufferSource(), destination = audio.createMediaStreamDestination()
      source.buffer = buffer
      source.connect(destination)
      audioSource = source
      // Keep the destination clock alive while the final AAC samples drain.
      // Exact zero lets WebKit suspend the track and corrupt MP4 timestamps;
      // this inaudible DC value (-160 dB) encodes as silence, without speakers.
      audioClock = audio.createConstantSource()
      audioClock.offset.value = 1e-8
      audioClock.connect(destination)
      audioClock.start()
      for (const track of destination.stream.getAudioTracks()) stream.addTrack(track)
      await cancellable(audio.resume(), signal)
      if (audio.state !== 'running') throw new Error(t('O navegador não liberou o áudio para converter este vídeo. Tente novamente.'))
    }
    aborted(signal)
    recorder = new MediaRecorder(stream, { mimeType, videoBitsPerSecond, audioBitsPerSecond: 128_000 })
    const current = recorder
    const chunks: Blob[] = []
    let total = 0
    onProgress?.({ fraction: 0, converting: true })
    const encoded = new Promise<Blob>((resolve, reject) => {
      let settled = false
      let started = false
      let waitingForFrame = false
      let videoEnded = false
      let audioEnded = !audioSource
      let firstFrame: number | undefined
      let audioDrain: ReturnType<typeof setTimeout> | undefined
      const finish = (error?: Error) => {
        if (settled) return
        settled = true
        signal?.removeEventListener('abort', cancel); document.removeEventListener('visibilitychange', visibility); video.removeEventListener('playing', playing); video.removeEventListener('ended', end); video.removeEventListener('error', failed)
        clearTimeout(deadline)
        clearTimeout(audioDrain)
        if (audioSource) audioSource.onended = null
        if (firstFrame !== undefined) video.cancelVideoFrameCallback?.(firstFrame)
        current.ondataavailable = null; current.onstop = null; current.onerror = null
        if (error) {
          try { if (current.state !== 'inactive') current.stop() } catch { /* Preserve the original failure and release the tracks below. */ }
          reject(error)
        }
        else resolve(new Blob(chunks, { type: 'video/mp4' }))
        chunks.length = 0
      }
      const cancel = () => finish(new DOMException('Cancelled', 'AbortError'))
      const failed = () => finish(new Error(t('Não foi possível preparar o vídeo.')))
      const visibility = () => { if (document.visibilityState === 'hidden') finish(new Error(t('Mantenha esta aba visível até terminar a preparação do vídeo.'))) }
      const stop = () => { if (!settled && videoEnded && audioEnded && current.state !== 'inactive') { try { current.stop() } catch { failed() } } }
      const end = () => { if (!started) failed(); else { videoEnded = true; stop() } }
      // Give the stream destination three AAC frames to drain after Web Audio's
      // render thread reports ended; Chromium reports it ahead of capture.
      if (audioSource) audioSource.onended = () => { audioDrain = setTimeout(() => { audioEnded = true; stop() }, AUDIO_DRAIN_MS) }
      const start = () => {
        if (settled || started) return
        if (signal?.aborted) { cancel(); return }
        started = true
        // Safari can drop the final MP4 fragment when a timeslice is supplied.
        // This bounded conversion emits a single complete file at stop.
        try { current.start(); audioSource?.start() } catch { failed() }
      }
      const playing = () => {
        if (settled || started || waitingForFrame) return
        if (typeof video.requestVideoFrameCallback !== 'function') { start(); return }
        waitingForFrame = true
        const ready: VideoFrameRequestCallback = (_now, metadata) => {
          firstFrame = undefined
          if (settled || started) return
          if (metadata.mediaTime > 0) start()
          else firstFrame = video.requestVideoFrameCallback(ready)
        }
        firstFrame = video.requestVideoFrameCallback(ready)
      }
      const deadline = setTimeout(failed, (duration * 2 + 30) * 1000)
      current.ondataavailable = event => { if (event.data.size) { total += event.data.size; chunks.push(event.data); if (total > MAX_BYTES) finish(new Error(t('O vídeo preparado ultrapassou o limite de tamanho.'))) } }
      current.onerror = failed
      current.onstop = () => finish(total ? undefined : new Error(t('Não foi possível preparar o vídeo.')))
      // A WebKit playing event can precede usable frames. Wait for the first
      // advancing frame, preserving the initial frame to within one frame.
      video.addEventListener('playing', playing)
      video.addEventListener('ended', end, { once: true }); video.addEventListener('error', failed, { once: true }); signal?.addEventListener('abort', cancel, { once: true })
      document.addEventListener('visibilitychange', visibility)
      // Both synchronous and asynchronous playback failures settle this same
      // promise; cancellation before playing never starts the encoder later.
      visibility()
      if (!settled) { try { void video.play().catch(failed) } catch { failed() } }
      if (signal?.aborted) cancel()
    })
    progressTimer = setInterval(() => onProgress?.({ fraction: Math.min(.99, video.currentTime / duration), converting: true }), 200)
    const blob = await encoded
    if (!await compatibleMP4(blob)) throw new Error(t('O navegador não produziu um vídeo MP4 compatível.'))
    aborted(signal)
    onProgress?.({ fraction: 1, converting: true })
    return { blob, ...size, seconds, hd }
  } finally {
    clearInterval(progressTimer); cancelAnimationFrame(animation)
    try { if (recorder?.state !== undefined && recorder.state !== 'inactive') recorder.stop() } catch { /* Cleanup must continue after an encoder failure. */ }
    stream?.getTracks().forEach(track => track.stop())
    if (audioSource) { audioSource.onended = null; try { audioSource.stop() } catch { /* Already ended or never started. */ } audioSource.disconnect(); audioSource.buffer = null }
    if (audioClock) { try { audioClock.stop() } catch { /* Already stopped. */ } audioClock.disconnect() }
    if (audio && audio.state !== 'closed') await audio.close().catch(() => {})
    video.pause(); video.removeAttribute('src'); video.load(); URL.revokeObjectURL(url)
  }
}
