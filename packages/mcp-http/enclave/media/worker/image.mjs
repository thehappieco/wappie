// The image worker (docs/mcp-enclave.md §16.11): photos, stickers and video
// previews re-encoded by sharp, jailed by media-jail under
//   node --max-old-space-size=128 --disallow-code-generation-from-strings image.mjs
//
// One input, one IMAGE frame (page 0): only the libvips loader of the
// header's `format` is unblocked, the first frame only is read, and nothing
// of the source's metadata is written back (no EXIF, XMP, IPTC or ICC), so a
// photo's location and camera data never leave. HEADER says whether the
// source had more frames than the one shown.

import { silenceConsole, run, strict, refuse, isInt, isObject, WorkerError, HEADER } from './lib/frames.mjs'
import { IMAGE_MAX_PIXELS, IMAGE_LONG_EDGE, IMAGE_MAX_BYTES, STICKER_LONG_EDGE, STICKER_MAX_BYTES } from './lib/limits.mjs'
import { LOADERS, loadSharp, photoLadder, stickerLadder, sharpError } from './lib/encode.mjs'

silenceConsole()

const PNG_SIGNATURE = Buffer.from('89504e470d0a1a0a', 'hex')
const MAGIC = {
  jpeg: (b) => b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  png: (b) => b.length >= 8 && b.subarray(0, 8).equals(PNG_SIGNATURE),
  gif: (b) => /^GIF8[79]a$/.test(b.toString('latin1', 0, 6)),
  webp: (b) => b.length >= 12 && b.toString('latin1', 0, 4) === 'RIFF' && b.toString('latin1', 8, 12) === 'WEBP',
}

// Per op: the ceilings of long_edge and image_bytes.
const OPS = {
  photo: [IMAGE_LONG_EDGE, IMAGE_MAX_BYTES],
  thumb: [IMAGE_LONG_EDGE, IMAGE_MAX_BYTES],
  sticker: [STICKER_LONG_EDGE, STICKER_MAX_BYTES],
}

function parseJob(header) {
  const job = strict(header, {
    v: (v) => v === 1,
    op: (v) => typeof v === 'string' && Object.hasOwn(OPS, v),
    format: (v) => typeof v === 'string' && Object.hasOwn(LOADERS, v),
    limits: isObject,
  })
  const [edge, bytes] = OPS[job.op]
  strict(job.limits, {
    pixels: (v) => isInt(v, 1, IMAGE_MAX_PIXELS),
    long_edge: (v) => isInt(v, 1, edge),
    image_bytes: (v) => isInt(v, 1, bytes),
  })
  return job
}

run(async ({ header, input }, frames) => {
  const job = parseJob(header)
  if (!MAGIC[job.format](input)) throw refuse('unsupported')
  const sharp = await loadSharp(LOADERS[job.format])
  const options = { limitInputPixels: job.limits.pixels, failOn: 'error' }
  try {
    const meta = await sharp(input, options).metadata()
    if (meta.format !== job.format) throw refuse('unsupported')
    // The first frame's size, checked before anything is decoded.
    if (!meta.width || !meta.height) throw refuse('damaged')
    if (meta.width * (meta.pageHeight ?? meta.height) > job.limits.pixels) throw refuse('too_large', 'pixels')
    await frames.json(HEADER, { animated: (meta.pages ?? 1) > 1 })

    const limits = { longEdge: job.limits.long_edge, maxBytes: job.limits.image_bytes }
    const out =
      job.op === 'sticker'
        ? await stickerLadder(sharp, () => sharp(input, options).rotate(), limits)
        : await photoLadder(sharp, () => sharp(input, options).rotate().flatten({ background: '#ffffff' }), limits)
    await frames.image(0, out.data)
  } catch (e) {
    throw e instanceof WorkerError ? e : sharpError(e)
  }
})
