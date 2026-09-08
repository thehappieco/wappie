// Recording a voice note.
//
// A voice note is not an audio file with a different label: WhatsApp draws a
// waveform for it, plays it with one tap, and reports it as "ouvida" rather
// than "lida". What it wants is Opus in an Ogg container, which is what its own
// clients record.
//
// Browsers do not agree about how to hand that over. Chrome records Opus inside
// a WebM container, Firefox will write Ogg when asked, and Safari records AAC
// in MP4 and cannot be talked out of it. The first two are the same encoder's
// output, so the first case is repackaged rather than converted — see
// oggopus.ts. The third is reported honestly instead of being sent as a voice
// note that some phones will not play.

import { webmToOggOpus } from './oggopus'

/** Taken is what came out of the microphone, and whether it can be a voice note. */
export interface Taken {
  file: File
  /**
   * Whether this is Opus in an Ogg container.
   *
   * False means the browser recorded something else. The recording is still
   * perfectly good audio and can be sent as an audio file; it is only the
   * voice-note rendering that depends on the format.
   */
  asVoiceNote: boolean
  seconds: number
}

export interface Recording {
  /** Stops, releases the microphone, and returns what was recorded. */
  stop(): Promise<Taken | null>
  /** Stops and throws it away. The microphone is released either way. */
  cancel(): void
}

/**
 * LONGEST caps a recording that was started and forgotten.
 *
 * Ten minutes of Opus is a couple of megabytes, so this is not about size — it
 * is about a tab that is quietly holding somebody's microphone open.
 */
const LONGEST_MS = 10 * 60 * 1000

/** available reports whether this browser can record at all. */
export function available(): boolean {
  return (
    typeof MediaRecorder === 'function' &&
    typeof navigator !== 'undefined' &&
    typeof navigator.mediaDevices?.getUserMedia === 'function'
  )
}

/**
 * begin opens the microphone and starts recording.
 *
 * Throws if permission is refused, which is the caller's to report: a silent
 * failure here looks like a broken button rather than a decision the person
 * made.
 */
export async function begin(): Promise<Recording> {
  if (!available()) throw new Error('este navegador não grava áudio')

  const stream = await navigator.mediaDevices.getUserMedia({
    // What a voice note is for. Left to the browser's own processing rather
    // than done afterwards, because it is the only side that still has the
    // signal before it was compressed.
    audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
  })

  // Released on every path out of here, including the ones that throw. A
  // MediaStream left live keeps the browser's microphone indicator on, and the
  // person has no way to turn it off but closing the tab.
  const release = () => {
    for (const track of stream.getTracks()) track.stop()
  }

  const mime = preferredMime()
  let recorder: MediaRecorder
  try {
    recorder = new MediaRecorder(stream, mime ? { mimeType: mime } : undefined)
  } catch (err) {
    release()
    throw err
  }

  const chunks: Blob[] = []
  recorder.ondataavailable = (event) => {
    if (event.data.size > 0) chunks.push(event.data)
  }

  const startedAt = Date.now()
  const ended = new Promise<void>((resolve) => {
    // Released here rather than only in stop(), so the ceiling below and any
    // failure inside the recorder release it too.
    recorder.onstop = () => {
      release()
      resolve()
    }
    recorder.onerror = () => {
      release()
      resolve()
    }
  })

  try {
    recorder.start()
  } catch (err) {
    release()
    throw err
  }
  const ceiling = setTimeout(() => {
    if (recorder.state === 'recording') recorder.stop()
  }, LONGEST_MS)

  return {
    async stop(): Promise<Taken | null> {
      clearTimeout(ceiling)
      if (recorder.state !== 'inactive') recorder.stop()
      await ended
      release()
      const seconds = Math.round((Date.now() - startedAt) / 1000)
      if (chunks.length === 0) return null
      return shape(new Blob(chunks, { type: recorder.mimeType || mime }), seconds)
    },
    cancel(): void {
      clearTimeout(ceiling)
      if (recorder.state !== 'inactive') recorder.stop()
      release()
      chunks.length = 0
    },
  }
}

/**
 * preferredMime picks the container to record into.
 *
 * Ogg first, so the browsers that can produce a voice note directly do. WebM
 * second, because its Opus data is the same and can be repackaged. Anything
 * else is left to the browser's own default, and reported for what it is.
 */
export function preferredMime(): string {
  const wanted = ['audio/ogg;codecs=opus', 'audio/webm;codecs=opus', 'audio/webm']
  if (typeof MediaRecorder !== 'function') return ''
  return wanted.find((type) => MediaRecorder.isTypeSupported(type)) ?? ''
}

/** shape turns the recorded blob into a file WhatsApp will render as intended. */
async function shape(blob: Blob, seconds: number): Promise<Taken> {
  const type = (blob.type || '').toLowerCase()

  if (type.startsWith('audio/ogg')) {
    return { file: named(blob, 'ogg', 'audio/ogg; codecs=opus'), asVoiceNote: true, seconds }
  }

  if (type.startsWith('audio/webm')) {
    const ogg = webmToOggOpus(new Uint8Array(await blob.arrayBuffer()))
    if (ogg) {
      const packaged = new Blob([ogg as BlobPart], { type: 'audio/ogg; codecs=opus' })
      return { file: named(packaged, 'ogg', 'audio/ogg; codecs=opus'), asVoiceNote: true, seconds }
    }
    // WebM that is not Opus, or laced in a way the repackager refuses to guess
    // at. Sending it as a voice note would be a file some phones will not play.
    return { file: named(blob, 'webm', blob.type), asVoiceNote: false, seconds }
  }

  // Safari, recording AAC in MP4. Perfectly good audio, and not a voice note.
  return { file: named(blob, extensionFor(type), blob.type), asVoiceNote: false, seconds }
}

function named(blob: Blob, extension: string, type: string): File {
  return new File([blob], `gravacao.${extension}`, { type })
}

function extensionFor(type: string): string {
  if (type.startsWith('audio/mp4') || type.startsWith('audio/aac')) return 'm4a'
  if (type.startsWith('audio/mpeg')) return 'mp3'
  if (type.startsWith('audio/wav')) return 'wav'
  return 'bin'
}
