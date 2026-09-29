// sharp, configured for a jail, and the two output ladders of §16.11: the
// photo ladder (JPEG, used by the image worker's photo and thumb ops and by
// the PDF worker's page images) and the sticker ladder (PNG with alpha).
// Imported only by image.mjs and pdf.mjs: the office worker runs with
// --no-addons and never loads sharp.

import { refuse } from './frames.mjs'
import { JPEG_QUALITIES, IMAGE_FALLBACK_EDGE, STICKER_EDGES } from './limits.mjs'

// The one libvips loader each input format may use (§16.11 image worker).
export const LOADERS = Object.freeze({
  jpeg: 'VipsForeignLoadJpegBuffer',
  png: 'VipsForeignLoadPngBuffer',
  webp: 'VipsForeignLoadWebpBuffer',
  gif: 'VipsForeignLoadNsgifBuffer',
})

/**
 * Import sharp with libvips set for one job: one thread, no operation cache,
 * every loader blocked except `loader` (none for raw pixels, which need no
 * loader). VIPS_BLOCK_UNTRUSTED is set before libvips starts, so its
 * untrusted-marked operations stay blocked whatever the block list says; the
 * jail passes no VIPS_* variable (§16.6), so this is where it is set.
 */
export async function loadSharp(loader) {
  process.env.VIPS_BLOCK_UNTRUSTED = '1'
  const { default: sharp } = await import('sharp')
  sharp.concurrency(1)
  sharp.cache(false)
  sharp.block({ operation: ['VipsForeignLoad'] })
  if (loader) sharp.unblock({ operation: [loader] })
  return sharp
}

/**
 * The photo ladder: fit inside `longEdge` without enlarging, JPEG at each of
 * JPEG_QUALITIES until the file is at most `maxBytes`, then at
 * IMAGE_FALLBACK_EDGE and 60; past that, ERROR too_large/pixels. `prepare`
 * returns a fresh sharp pipeline for the (oriented, flattened) source, which
 * is decoded and scaled once to raw pixels; every attempt encodes from those.
 * Returns { data, width, height } or throws.
 */
export async function photoLadder(sharp, prepare, { longEdge, maxBytes }) {
  const first = await scaled(prepare(), longEdge)
  try {
    for (const quality of JPEG_QUALITIES) {
      const data = await jpeg(sharp, first, quality)
      if (data.length <= maxBytes) return { data, width: first.info.width, height: first.info.height }
    }
    const small = await scaled(fromRaw(sharp, first), Math.min(longEdge, IMAGE_FALLBACK_EDGE))
    try {
      const data = await jpeg(sharp, small, JPEG_QUALITIES.at(-1))
      if (data.length > maxBytes) throw refuse('too_large', 'pixels')
      return { data, width: small.info.width, height: small.info.height }
    } finally {
      small.data.fill(0)
    }
  } finally {
    first.data.fill(0)
  }
}

/**
 * The sticker ladder: PNG with alpha at each of STICKER_EDGES not above
 * `longEdge`, full colour first and then as a palette PNG, until the file is
 * at most `maxBytes`; past that, ERROR too_large/pixels.
 */
export async function stickerLadder(sharp, prepare, { longEdge, maxBytes }) {
  const edges = STICKER_EDGES.filter((e) => e <= longEdge)
  if (!edges.length) edges.push(longEdge)
  const source = await scaled(prepare().ensureAlpha(), edges[0])
  try {
    for (const edge of edges) {
      const at = edge === edges[0] ? source : await scaled(fromRaw(sharp, source), edge)
      try {
        for (const palette of [false, true]) {
          const data = await fromRaw(sharp, at).png({ compressionLevel: 9, palette }).toBuffer()
          if (data.length <= maxBytes) return { data, width: at.info.width, height: at.info.height }
        }
      } finally {
        if (at !== source) at.data.fill(0)
      }
    }
  } finally {
    source.data.fill(0)
  }
  throw refuse('too_large', 'pixels')
}

async function scaled(pipeline, edge) {
  return pipeline
    .resize({ width: edge, height: edge, fit: 'inside', withoutEnlargement: true })
    .raw()
    .toBuffer({ resolveWithObject: true })
}

function fromRaw(sharp, { data, info }) {
  return sharp(data, { raw: { width: info.width, height: info.height, channels: info.channels } })
}

function jpeg(sharp, raw, quality) {
  // No metadata is kept (sharp's default): no EXIF, XMP, IPTC or ICC.
  return fromRaw(sharp, raw).jpeg({ quality, chromaSubsampling: '4:2:0' }).toBuffer()
}

/** What a sharp failure means for the reader (§16.11 ERROR codes). */
export function sharpError(e) {
  const message = String(e?.message ?? e)
  if (/pixel limit/i.test(message)) return refuse('too_large', 'pixels')
  if (/unsupported image format|is blocked|operation .* not permitted/i.test(message)) return refuse('unsupported')
  return refuse('damaged')
}
