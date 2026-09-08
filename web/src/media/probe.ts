// Measuring and re-encoding an attachment, in the browser that is sending it.
//
// All of this could in principle be done on a server. None of it is done on
// this one, and the reason is the same reason the archive is sealed: the server
// would have to decode the picture to size it, decode the audio to sketch its
// waveform, and hold the frames of a video to pick a poster. The machine that
// already decoded the file is the one somebody chose it on.
//
// Everything here is guarded. Canvas, createImageBitmap and AudioContext are
// browser APIs that the type checker believes in and the test environment does
// not have, so each entry point answers "could not" rather than throwing, and
// the pipeline treats a missing measurement as a missing measurement — the
// attachment still goes, with the recipient's player showing less.

import type { Bytes } from '../crypto/bytes'

/** Picture is a decoded still, with the size it decoded to. */
export interface Picture {
  width: number
  height: number
  /** The re-encoded bytes, or the original when nothing needed changing. */
  blob: Blob
}

/** THUMB_SIDE is the inline preview WhatsApp carries inside the message. */
const THUMB_SIDE = 100
const THUMB_QUALITY = 0.5

/** WAVEFORM_BARS is fixed by the format: the field is a 64-byte sketch. */
export const WAVEFORM_BARS = 64

/**
 * bucket reduces a waveform to a fixed number of bars, 0..100.
 *
 * The arithmetic is separated from the decoding because it is the half that can
 * be checked: the count has to be exactly 64 whether the recording is one
 * second or ten minutes, the values have to land in the range the renderer
 * divides by four, and silence has to come out flat rather than as a full bar.
 *
 * Peak rather than mean, deliberately. Averaging a bucket of a few thousand
 * samples flattens speech into a featureless ribbon; the peak is what makes a
 * voice note look like speech.
 */
export function bucket(samples: ArrayLike<number>, bars = WAVEFORM_BARS): number[] {
  const out = new Array<number>(bars).fill(0)
  if (samples.length === 0) return out

  const width = samples.length / bars
  let loudest = 0
  for (let i = 0; i < bars; i++) {
    const from = Math.floor(i * width)
    const to = Math.max(from + 1, Math.floor((i + 1) * width))
    let peak = 0
    for (let s = from; s < to && s < samples.length; s++) {
      const amp = Math.abs(samples[s])
      if (amp > peak) peak = amp
    }
    out[i] = peak
    if (peak > loudest) loudest = peak
  }

  // Normalised against the recording's own loudest moment. A quiet recording
  // drawn against an absolute scale is a flat line, which reads as a broken
  // file rather than as somebody speaking softly.
  if (loudest <= 0) return out.fill(0)
  return out.map((peak) => Math.round((peak / loudest) * 100))
}

/**
 * fitted decodes a picture and re-encodes it to a bound.
 *
 * A picture already inside the bound is returned untouched rather than
 * re-encoded: recompressing something that needs no resizing only loses detail,
 * and for a screenshot or an already-small photograph it can make the file
 * larger.
 */
export async function fitted(
  blob: Blob,
  maxLongSide: number,
  quality: number,
  mime: string,
  strict = false,
): Promise<Picture | null> {
  const source = await decode(blob)
  if (!source) return null
  try {
    const { width, height } = source
    const longest = Math.max(width, height)
    const within = !maxLongSide || longest <= maxLongSide
    // `strict` is what a sticker needs: WhatsApp's sticker message is WebP, so
    // a small PNG has to be converted even though nothing about its size needs
    // changing. A photograph has no such requirement and is passed through.
    if (within && (!strict || blob.type === mime)) {
      // Still worth reporting the dimensions: the recipient's client reserves
      // the bubble from them, and without them it jumps when the image loads.
      return { width, height, blob }
    }
    const scale = within ? 1 : maxLongSide / longest
    const to = { width: Math.max(1, Math.round(width * scale)), height: Math.max(1, Math.round(height * scale)) }
    const encoded = await draw(source, to.width, to.height, mime, quality)
    if (!encoded) return { width, height, blob }
    return { width: to.width, height: to.height, blob: encoded }
  } finally {
    release(source)
  }
}

/** thumbnail renders the small JPEG that travels inside the message itself. */
export async function thumbnail(blob: Blob): Promise<Bytes | null> {
  const source = await decode(blob)
  if (!source) return null
  try {
    const longest = Math.max(source.width, source.height)
    const scale = longest > THUMB_SIDE ? THUMB_SIDE / longest : 1
    const encoded = await draw(
      source,
      Math.max(1, Math.round(source.width * scale)),
      Math.max(1, Math.round(source.height * scale)),
      'image/jpeg',
      THUMB_QUALITY,
    )
    if (!encoded) return null
    return new Uint8Array(await encoded.arrayBuffer()) as Bytes
  } finally {
    release(source)
  }
}

/** Moving is what a video says about itself before it is sent. */
export interface Moving {
  width: number
  height: number
  seconds: number
  /** A frame from near the start, as JPEG bytes. */
  poster?: Bytes
}

/**
 * moving reads a video's shape, duration and first usable frame.
 *
 * Seeked a little past zero rather than to it, because the first frame of a
 * recording is very often black — a poster nobody can recognise is worse than
 * the two hundred milliseconds this costs.
 */
export async function moving(blob: Blob): Promise<Moving | null> {
  if (typeof document === 'undefined' || typeof URL.createObjectURL !== 'function') return null
  const url = URL.createObjectURL(blob)
  const video = document.createElement('video')
  video.preload = 'metadata'
  video.muted = true
  // Required by Safari before it will decode anything without a gesture.
  video.playsInline = true
  try {
    await once(video, 'loadedmetadata', () => {
      video.src = url
    })
    const out: Moving = {
      width: video.videoWidth,
      height: video.videoHeight,
      seconds: Number.isFinite(video.duration) ? Math.round(video.duration) : 0,
    }
    const at = Math.min(0.2, (video.duration || 0) / 2)
    // A shorter ceiling than the metadata read, because a seek that will not
    // happen usually does not fail: setting currentTime to where the video
    // already is fires nothing at all, and a zero-length file is exactly that
    // case. Ten seconds of waiting for a poster frame is worse than no poster.
    const seeked = await once(
      video,
      'seeked',
      () => {
        video.currentTime = at
      },
      3000,
    ).then(
      () => true,
      () => false,
    )
    // No frame unless the seek actually landed. A video sitting at
    // HAVE_METADATA draws a solid black rectangle, and a black poster reported
    // as a success is worse than no poster: nothing downstream can tell the
    // difference, and the recipient sees a black square where a preview goes.
    if (seeked) {
      const frame = await draw(
        video,
        video.videoWidth,
        video.videoHeight,
        'image/jpeg',
        THUMB_QUALITY,
        THUMB_SIDE,
      )
      if (frame) out.poster = new Uint8Array(await frame.arrayBuffer()) as Bytes
    }
    return out
  } catch {
    return null
  } finally {
    video.removeAttribute('src')
    video.load()
    URL.revokeObjectURL(url)
  }
}

/** Sound is a recording's duration and the sketch drawn behind it. */
export interface Sound {
  seconds: number
  waveform: number[]
}

/** sound decodes audio far enough to time it and sketch it. */
export async function sound(blob: Blob): Promise<Sound | null> {
  const Ctor =
    typeof globalThis.AudioContext === 'function'
      ? globalThis.AudioContext
      : (globalThis as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext
  if (typeof Ctor !== 'function') return null

  // Inside the try, because a browser that has reached its limit of live
  // contexts throws here — and this module promises its callers "could not"
  // rather than an exception.
  let context: AudioContext
  try {
    context = new Ctor()
  } catch {
    return null
  }

  try {
    const decoded = await context.decodeAudioData(await blob.arrayBuffer())
    // The first channel is enough. Mixing every channel to sketch an envelope
    // costs a full pass over a stereo recording for a shape 64 bars wide.
    return { seconds: Math.round(decoded.duration), waveform: bucket(decoded.getChannelData(0)) }
  } catch {
    return null
  } finally {
    // Closing matters: browsers cap the number of live audio contexts, and a
    // session that attaches a dozen recordings would stop being able to open
    // one at all.
    await context.close().catch(() => undefined)
  }
}

// ---------------------------------------------------------------------------
// The guarded half: everything below touches an API the test environment lacks
// ---------------------------------------------------------------------------

type Source = ImageBitmap | HTMLImageElement

async function decode(blob: Blob): Promise<Source | null> {
  if (typeof createImageBitmap === 'function') {
    try {
      // from-image so a photograph taken sideways is not sent sideways. The
      // EXIF rotation is otherwise ignored, and the canvas has no idea.
      return await createImageBitmap(blob, { imageOrientation: 'from-image' })
    } catch {
      try {
        return await createImageBitmap(blob)
      } catch {
        return null
      }
    }
  }
  if (typeof Image !== 'function' || typeof URL.createObjectURL !== 'function') return null
  const url = URL.createObjectURL(blob)
  const image = new Image()
  try {
    await once(image, 'load', () => {
      image.src = url
    })
    return image
  } catch {
    return null
  } finally {
    URL.revokeObjectURL(url)
  }
}

function release(source: Source): void {
  if ('close' in source && typeof source.close === 'function') source.close()
}

/** draw paints a source onto a canvas and encodes it, or answers null. */
async function draw(
  source: CanvasImageSource,
  width: number,
  height: number,
  mime: string,
  quality: number,
  bound = 0,
): Promise<Blob | null> {
  if (width <= 0 || height <= 0) return null
  let to = { width, height }
  if (bound) {
    const longest = Math.max(width, height)
    if (longest > bound) {
      const scale = bound / longest
      to = { width: Math.max(1, Math.round(width * scale)), height: Math.max(1, Math.round(height * scale)) }
    }
  }

  if (typeof OffscreenCanvas === 'function') {
    const canvas = new OffscreenCanvas(to.width, to.height)
    const ctx = canvas.getContext('2d')
    if (!ctx) return null
    ctx.drawImage(source, 0, 0, to.width, to.height)
    try {
      return await canvas.convertToBlob({ type: mime, quality })
    } catch {
      // Safari has OffscreenCanvas but has refused WebP here in the past.
      return await canvas.convertToBlob({ type: 'image/jpeg', quality }).catch(() => null)
    }
  }

  if (typeof document === 'undefined') return null
  const canvas = document.createElement('canvas')
  canvas.width = to.width
  canvas.height = to.height
  const ctx = canvas.getContext('2d')
  if (!ctx) return null
  ctx.drawImage(source, 0, 0, to.width, to.height)
  return await new Promise<Blob | null>((resolve) => {
    canvas.toBlob((out) => resolve(out), mime, quality)
  })
}

/**
 * once waits for one event, with a ceiling.
 *
 * The ceiling is the point. A codec the browser cannot decode fires neither the
 * event nor an error — the element simply sits there — and without a timeout
 * the composer would wait for it forever with a file somebody is trying to
 * send.
 */
function once(target: HTMLElement, event: string, begin: () => void, ms = 10_000): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const done = (err?: Error) => {
      clearTimeout(timer)
      target.removeEventListener(event, ok)
      target.removeEventListener('error', bad)
      if (err) reject(err)
      else resolve()
    }
    const ok = () => done()
    const bad = () => done(new Error(`o navegador não conseguiu abrir este arquivo`))
    const timer = setTimeout(() => done(new Error('o navegador demorou demais para abrir este arquivo')), ms)
    target.addEventListener(event, ok, { once: true })
    target.addEventListener('error', bad, { once: true })
    begin()
  })
}
