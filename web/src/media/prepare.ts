import { t } from '../ui/i18n'
// Turning a file somebody picked into an attachment WhatsApp will render.
//
// One rule runs through all of it: the kind is decided once and used
// everywhere. The `?type=` on the upload picks the HKDF label the media key is
// derived from; the `type` on the send frame picks the protobuf field; and the
// media_type stored in the archive is what this client later derives its own
// decryption keys from. All three come from `plan.kind` below, because two of
// them disagreeing produces a file that opens for nobody — not the recipient,
// not us — with a 200 at every step and no error anywhere.

import { toBase64, type Bytes } from '../crypto/bytes'
import {
  animatedWebP,
  mimeFor,
  nameFor,
  planFor,
  sourceMime,
  type Choice,
  type Kind,
  type Plan,
} from './plan'
import { fitted, moving, sound, thumbnail } from './probe'
import { isVideoChoice, prepareVideo, type VideoPreparation } from './videoPrepare'

/** Prepared is an attachment with everything measured, ready to upload. */
export interface Prepared {
  plan: Plan
  kind: Kind
  /** The bytes to upload. The original file unless the plan re-encoded it. */
  blob: Blob
  mimetype: string
  fileName: string
  width: number
  height: number
  seconds: number
  /** Base64, 64 bars. Audio only; every other type ignores the field. */
  waveform?: string
  /** Base64 JPEG. Read for image, video, round video note and document. */
  thumbnail?: string
  isGIF: boolean
  isAnimated: boolean
  /** A local object URL for the bubble to draw while this uploads. */
  previewURL: string
  /** What that preview is, so the bubble knows which element to use. */
  previewKind: 'image' | 'video' | 'audio' | 'none'
  /**
   * What could not be measured, in words.
   *
   * Shown rather than swallowed. A video whose duration the browser refused to
   * read still sends; the recipient's player just shows nothing until it has
   * buffered, and that is worth knowing before rather than after.
   */
  missing: string[]
}

/**
 * prepare measures a file and produces everything the send needs.
 *
 * `knownSeconds` is for a recording made here: the browser held the microphone
 * open and knows how long for, which is worth more than nothing when decoding
 * the result to time it does not work. Absent for a file somebody chose, where
 * there is nothing to know it from.
 */
export async function prepare(file: File, choice: Choice, knownSeconds = 0, options: VideoPreparation = {}): Promise<Prepared> {
  const plan = planFor(choice)
  const missing: string[] = []

  let blob: Blob = file
  let mimetype = mimeFor(plan, file)
  let fileName = nameFor(plan, file.name)
  let width = 0
  let height = 0
  let seconds = 0
  let waveform: string | undefined
  let thumb: Bytes | null = null
  let isAnimated = false

  if (isVideoChoice(choice)) {
    const video = await prepareVideo(file, choice, { ...options, knownSeconds })
    blob = video.blob; mimetype = 'video/mp4'
    fileName = file.name.replace(/\.[^.]+$/, '') + '.mp4'
    width = video.width; height = video.height; seconds = video.seconds
  }

  if (plan.encodeTo) {
    const keep = plan.choice === 'sticker' && (await passThroughSticker(file, plan))
    if (keep) {
      // Already a WebP inside the bound. Re-encoding it through a canvas would
      // cost quality and, if it moves, would throw away every frame but one.
      blob = file
      mimetype = 'image/webp'
      fileName = file.name
      width = keep.width
      height = keep.height
      isAnimated = keep.animated
    } else {
      const picture = await fitted(
        file,
        plan.maxLongSide,
        plan.quality,
        plan.encodeTo,
        plan.strictFormat,
      )
      if (picture) {
        blob = picture.blob
        width = picture.width
        height = picture.height
        // The mime follows the bytes: `fitted` returns the original blob
        // untouched when it was already small enough, and calling a PNG a JPEG
        // is a file some readers will refuse to open. Read from the file
        // itself rather than from the plan, because a file that declares no
        // type at all would otherwise inherit the format it was going to
        // become and never did.
        mimetype = picture.blob === file ? sourceMime(file) : plan.encodeTo
        fileName = picture.blob === file ? file.name : nameFor(plan, file.name)
      } else {
        // The browser could not decode it. Sending the original bytes under
        // their own type is honest; claiming they are a JPEG would not be.
        mimetype = file.type || 'application/octet-stream'
        fileName = file.name
        missing.push(t('não foi possível redimensionar; vai como está'))
      }
    }
  }

  if (plan.wantsDuration) {
    if (plan.kind === 'video' || plan.kind === 'ptv') {
      const video = await moving(blob)
      if (video) {
        seconds = seconds || video.seconds
        width = width || video.width
        height = height || video.height
        if (video.poster) thumb = video.poster
      } else {
        if (!seconds || !width) missing.push(t('duração e dimensões'))
      }
    } else {
      const audio = await sound(blob)
      if (audio) {
        seconds = audio.seconds
        if (plan.wantsWaveform && audio.waveform.some((bar) => bar > 0)) {
          waveform = toBase64(new Uint8Array(audio.waveform) as Bytes)
        }
      } else if (knownSeconds > 0) {
        // Timed by the clock instead of by decoding it. Less exact and far
        // better than nothing: without a duration the recipient's player shows
        // no length at all until the whole file has arrived.
        seconds = knownSeconds
        if (plan.wantsWaveform) missing.push(t('onda sonora'))
      } else {
        missing.push(plan.wantsWaveform ? t('duração e onda sonora') : t('duração'))
      }
    }
  }

  // After the video probe, not before it. A moving picture reports its own
  // shape, and asking a still-image decoder about one first would fail and
  // report "dimensões" as unreadable for a file whose dimensions were read a
  // few lines later.
  if (plan.wantsDimensions && !width) {
    const picture = await fitted(blob, 0, plan.quality, mimetype)
    if (picture) {
      width = picture.width
      height = picture.height
    } else {
      missing.push(t('dimensões'))
    }
  }

  if (plan.wantsThumbnail && !thumb) {
    // Only pictures have one to make. A document is usually a PDF or a
    // spreadsheet, and nothing here can render those — but "foto como arquivo"
    // is a document too, and that one deserves its preview.
    if (blob.type.startsWith('image/')) thumb = await thumbnail(blob)
  }

  if (options.signal?.aborted) throw new DOMException('Cancelled', 'AbortError')
  return {
    plan,
    kind: plan.kind,
    blob,
    mimetype,
    fileName,
    width,
    height,
    seconds,
    waveform,
    thumbnail: thumb ? toBase64(thumb) : undefined,
    isGIF: plan.isGIF,
    isAnimated,
    previewURL: previewFor(blob),
    previewKind: previewKindFor(plan.kind, mimetype),
    missing,
  }
}

/** discard releases the local preview. Every prepare() needs one of these. */
export function discard(prepared: Pick<Prepared, 'previewURL'>): void {
  if (prepared.previewURL) URL.revokeObjectURL(prepared.previewURL)
}

async function passThroughSticker(
  file: File,
  plan: Plan,
): Promise<{ width: number; height: number; animated: boolean } | null> {
  if ((file.type || '').toLowerCase() !== 'image/webp') return null
  const bytes = new Uint8Array(await file.arrayBuffer())
  const animated = animatedWebP(bytes)
  const picture = await fitted(file, 0, plan.quality, 'image/webp')
  if (!picture) {
    // Undecodable but still a WebP by its own account. An animated one is
    // exactly the case a canvas would ruin, so it is passed through blind
    // rather than flattened.
    return animated ? { width: 0, height: 0, animated } : null
  }
  if (Math.max(picture.width, picture.height) > plan.maxLongSide && !animated) return null
  return { width: picture.width, height: picture.height, animated }
}

function previewFor(blob: Blob): string {
  if (typeof URL.createObjectURL !== 'function') return ''
  return URL.createObjectURL(blob)
}

function previewKindFor(kind: Kind, mimetype: string): Prepared['previewKind'] {
  if (kind === 'image' || kind === 'sticker') return 'image'
  if (kind === 'video' || kind === 'ptv') return 'video'
  if (kind === 'audio' || kind === 'ptt') return 'audio'
  // Sending the original bytes as a document still allows a local preview.
  // MIME also covers files whose browser File.type was empty.
  if (mimetype.startsWith('image/')) return 'image'
  if (mimetype.startsWith('audio/')) return 'audio'
  if (mimetype.startsWith('video/')) return 'video'
  return 'none'
}
