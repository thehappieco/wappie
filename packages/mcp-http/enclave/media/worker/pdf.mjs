// The PDF worker (docs/mcp-enclave.md §16.11): text by page and page images,
// through the pdfjs-dist legacy build, jailed by media-jail under
//   node --max-old-space-size=256 --disallow-code-generation-from-strings pdf.mjs
//
// pdf.js runs in this thread (no worker thread: Node has no Worker global, so
// it uses its in-process "fake" worker), from `data` only, with its fonts,
// CMaps, ICC profiles and wasm decoders read from its own package directory.
// No canvas module is loaded (the image has none: @napi-rs is pruned), so a
// page image is the largest raster image the page paints, as pdf.js decodes
// it, re-encoded like a photo; a page drawn only with vectors has none.
// pdfjs-dist 6.x generates no code from strings at all (isEvalSupported is
// passed for older builds and ignored), and the flag above backs that up.

import { fileURLToPath } from 'node:url'
import { silenceConsole, run, strict, refuse, isInt, isObject, WorkerError, HEADER, SECTION, TextSink } from './lib/frames.mjs'
import { IMAGE_LONG_EDGE, IMAGE_MAX_BYTES, IMAGES_PER_RESULT, JOB_TEXT_MAX_BYTES, PDF_MAX_PAGES, PDF_PAGES_PER_JOB, PDF_MAX_IMAGE_PIXELS } from './lib/limits.mjs'

// pdf.js warns through console.log at import time (no @napi-rs/canvas, no
// DOMMatrix), which would land in the frames: silence first, import after.
silenceConsole()

const dir = (path) => fileURLToPath(new URL(`./node_modules/pdfjs-dist/${path}/`, import.meta.url))

function parseJob(header) {
  if (header?.op === 'images') {
    const job = strict(header, {
      v: (v) => v === 1,
      op: () => true,
      pages: (v) =>
        Array.isArray(v) &&
        v.length >= 1 &&
        v.length <= IMAGES_PER_RESULT &&
        v.every((p, i) => isInt(p, 1, PDF_MAX_PAGES) && (i === 0 || p > v[i - 1])),
      limits: isObject,
    })
    strict(job.limits, {
      long_edge: (v) => isInt(v, 1, IMAGE_LONG_EDGE),
      image_bytes: (v) => isInt(v, 1, IMAGE_MAX_BYTES),
      image_pixels: (v) => isInt(v, 1, PDF_MAX_IMAGE_PIXELS),
    })
    return job
  }
  const job = strict(header, {
    v: (v) => v === 1,
    op: (v) => v === 'text',
    from: (v) => isInt(v, 1, PDF_MAX_PAGES),
    count: (v) => isInt(v, 1, PDF_PAGES_PER_JOB),
    limits: isObject,
  })
  if (job.from + job.count - 1 > PDF_MAX_PAGES) throw refuse('bad_input')
  strict(job.limits, {
    text_bytes: (v) => isInt(v, 1, JOB_TEXT_MAX_BYTES),
    image_pixels: (v) => isInt(v, 1, PDF_MAX_IMAGE_PIXELS),
  })
  return job
}

async function open(input, imagePixels) {
  const pdfjs = await import('pdfjs-dist/legacy/build/pdf.mjs')
  const task = pdfjs.getDocument({
    data: new Uint8Array(input.buffer, input.byteOffset, input.length),
    isEvalSupported: false,
    disableFontFace: true,
    useSystemFonts: false,
    maxImageSize: imagePixels,
    verbosity: 0,
    standardFontDataUrl: dir('standard_fonts'),
    cMapUrl: dir('cmaps'),
    cMapPacked: true,
    iccUrl: dir('iccs'),
    wasmUrl: dir('wasm'),
  })
  try {
    return { pdfjs, doc: await task.promise }
  } catch (e) {
    if (e?.name === 'PasswordException') throw refuse('encrypted')
    throw refuse('damaged')
  }
}

// A page's text: its items joined, an item's end of line as "\n", spaces at
// the end of each line removed.
function pageText(items) {
  let s = ''
  for (const item of items) {
    if (typeof item.str !== 'string') continue
    s += item.str
    if (item.hasEOL) s += '\n'
  }
  return s
    .split('\n')
    .map((line) => line.replace(/[ \t]+$/, ''))
    .join('\n')
    .replace(/\n+$/, '')
}

async function text(doc, job, frames) {
  const total = doc.numPages
  const sink = new TextSink(frames, job.limits.text_bytes)
  for (let p = job.from; p <= Math.min(job.from + job.count - 1, total); p++) {
    await sink.flush()
    await frames.json(SECTION, { page: p })
    let content
    try {
      const page = await doc.getPage(p)
      content = await page.getTextContent()
      page.cleanup()
    } catch (e) {
      if (e?.name === 'PasswordException') throw refuse('encrypted')
      // One unreadable page leaves its block empty; the others still read.
      continue
    }
    await sink.write(pageText(content.items))
  }
  await sink.flush()
}

// The largest raster image a page paints: image XObjects and inline images
// (image masks are stencils, not pictures, and are left out).
async function largestImage(pdfjs, page) {
  const { OPS } = pdfjs
  const list = await page.getOperatorList()
  let best = null
  for (let i = 0; i < list.fnArray.length; i++) {
    const fn = list.fnArray[i]
    const args = list.argsArray[i]
    let candidate = null
    if (fn === OPS.paintImageXObject || fn === OPS.paintImageXObjectRepeat) {
      candidate = { id: args[0], width: args[1], height: args[2] }
    } else if (fn === OPS.paintInlineImageXObject) {
      candidate = { data: args[0], width: args[0]?.width, height: args[0]?.height }
    }
    if (candidate?.width > 0 && candidate.height > 0 && (!best || candidate.width * candidate.height > best.width * best.height)) {
      best = candidate
    }
  }
  if (!best) return null
  if (best.data) return best.data
  const objs = typeof best.id === 'string' && best.id.startsWith('g_') ? page.commonObjs : page.objs
  return new Promise((resolve) => objs.get(best.id, resolve))
}

// pdf.js's decoded image as raw pixels sharp takes: 1-bit rows unpacked to
// grey (a set bit is white), RGB and RGBA as they are.
function raw(image) {
  const { width, height, kind, data } = image ?? {}
  if (!data || !(width > 0) || !(height > 0)) return null
  if (kind === 1) {
    const stride = (width + 7) >> 3
    if (data.length < stride * height) return null
    const out = Buffer.alloc(width * height)
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) out[y * width + x] = data[y * stride + (x >> 3)] & (0x80 >> (x & 7)) ? 255 : 0
    }
    return { data: out, width, height, channels: 1 }
  }
  const channels = kind === 2 ? 3 : kind === 3 ? 4 : 0
  if (!channels || data.length < width * height * channels) return null
  return { data: Buffer.from(data.buffer, data.byteOffset, width * height * channels), width, height, channels }
}

async function images(pdfjs, doc, job, frames) {
  const { loadSharp, photoLadder } = await import('./lib/encode.mjs')
  // Raw pixels need no libvips loader: every loader stays blocked.
  const sharp = await loadSharp(null)
  for (const p of job.pages) {
    if (p > doc.numPages) break
    let pixels
    try {
      const page = await doc.getPage(p)
      pixels = raw(await largestImage(pdfjs, page))
      page.cleanup()
    } catch (e) {
      if (e?.name === 'PasswordException') throw refuse('encrypted')
      continue
    }
    if (!pixels) continue
    let out
    try {
      const prepare = () =>
        sharp(pixels.data, { raw: { width: pixels.width, height: pixels.height, channels: pixels.channels } }).flatten({
          background: '#ffffff',
        })
      out = await photoLadder(sharp, prepare, { longEdge: job.limits.long_edge, maxBytes: job.limits.image_bytes })
    } catch (e) {
      // A page image that cannot be made small enough is left out, like a
      // page without one; the other pages still get theirs.
      if (e instanceof WorkerError) continue
      throw e
    } finally {
      pixels.data.fill(0)
    }
    await frames.image(p, out.data)
  }
}

run(async ({ header, input }, frames) => {
  const job = parseJob(header)
  const { pdfjs, doc } = await open(input, job.limits.image_pixels)
  const total = doc.numPages
  if (!isInt(total, 1, 1_000_000)) throw refuse('damaged')
  await frames.json(HEADER, { pages: total })
  if (job.op === 'text') await text(doc, job, frames)
  else await images(pdfjs, doc, job, frames)
})
