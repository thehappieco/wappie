// A jailed worker's stdout, read as untrusted (docs/mcp-enclave.md §16.11,
// "What MAIN checks"). Frames are `u32 len ‖ u8 type ‖ payload`; every check
// below runs as the bytes arrive, so a violation stops the job before the
// rest is read, and nothing of a job that broke a rule is ever used.
import { cleanText } from './sniff.mjs'
import { FRAME_MAX, IMAGES_TOTAL_BYTES, JOB_TEXT_MAX_BYTES } from './policy.mjs'

export const FRAME = Object.freeze({ HEADER: 1, TEXT: 2, SECTION: 3, IMAGE: 4, ERROR: 8, DONE: 9 })
/** The most a job may write to stdout in all. */
export const STDOUT_MAX = JOB_TEXT_MAX_BYTES + 4 * (FRAME_MAX[4] + 5) + 65_536
export const ERROR_CODES = Object.freeze(['bad_input', 'unsupported', 'encrypted', 'too_large', 'kind_off', 'damaged'])
const TOO_LARGE_WHAT = ['pixels', 'entries', 'inflated']
const OFFICE_SNIFFED = { docx: null, odt: null, xlsx: 'sheets', xls: 'sheets', ods: 'sheets', pptx: 'slides', zip: 'entries' }
const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
const PNG_METADATA = new Set(['eXIf', 'tEXt', 'iTXt', 'zTXt', 'tIME'])

/** A worker broke the protocol: the job is killed and its output discarded (`bad_output`). */
export class OutputError extends Error {
  constructor(rule) { super(rule); this.name = 'OutputError'; this.code = 'bad_output'; this.rule = rule }
}
const violation = rule => { throw new OutputError(rule) }

const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const count = (value, max) => Number.isSafeInteger(value) && value >= 0 && value <= max
/** Strict JSON: exactly the keys allowed, each passing its test; `required` must all be there. */
function strict(payload, tests, required = Object.keys(tests)) {
  let value
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload)) } catch { return null }
  if (!isRecord(value)) return null
  const keys = Object.keys(value)
  if (keys.some(key => !Object.hasOwn(tests, key) || !tests[key](value[key])) || required.some(key => !keys.includes(key))) return null
  return value
}

/**
 * Width and height of a JPEG from its first SOF0 to SOF3 marker, or null.
 * The segments before the scan must carry no APP1 to APP15 and no COM: an
 * EXIF, XMP or IPTC block there is how location and camera data travel.
 */
export function jpegInfo(file) {
  if (file.length < 4 || file[0] !== 0xff || file[1] !== 0xd8 || file[2] !== 0xff) return null
  let at = 2, size = null
  while (at < file.length) {
    if (file[at] !== 0xff) return null
    while (at < file.length && file[at] === 0xff) at++
    if (at >= file.length) return null
    const marker = file[at++]
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue
    if (marker === 0xd8 || marker === 0xd9 || at + 2 > file.length) return null
    const length = file.readUInt16BE(at)
    if (length < 2 || at + length > file.length) return null
    if ((marker >= 0xe1 && marker <= 0xef) || marker === 0xfe) return null
    if (marker >= 0xc0 && marker <= 0xc3 && !size) {
      if (length < 7) return null
      size = { height: file.readUInt16BE(at + 3), width: file.readUInt16BE(at + 5) }
    }
    if (marker === 0xda) return size
    at += length
  }
  return null
}

/** Width and height of a PNG from IHDR, or null; no eXIf, tEXt, iTXt, zTXt or tIME chunk anywhere. */
export function pngInfo(file) {
  if (file.length < PNG.length + 25 || !file.subarray(0, PNG.length).equals(PNG)) return null
  let at = PNG.length, size = null
  while (at + 12 <= file.length) {
    const length = file.readUInt32BE(at)
    const type = file.subarray(at + 4, at + 8).toString('latin1')
    if (!/^[A-Za-z]{4}$/.test(type) || at + 12 + length > file.length) return null
    if (!size) {
      if (type !== 'IHDR' || length !== 13) return null
      size = { width: file.readUInt32BE(at + 8), height: file.readUInt32BE(at + 12) }
    }
    if (PNG_METADATA.has(type)) return null
    if (type === 'IEND') return size
    at += 12 + length
  }
  return null
}

/**
 * The reader for one job's stdout. `push(chunk)` validates frames as they
 * complete and throws OutputError on the first violation; `finish(exit)`
 * applies the last rule (DONE with exit 0, ERROR with exit 2, then EOF) and
 * returns the output. `job` is the §16.11 job header MAIN sent.
 */
export function createOutputReader({ worker, job }) {
  const pdfText = worker === 'pdf' && job.op === 'text'
  const pdfImages = worker === 'pdf' && job.op === 'images'
  const texts = pdfText || worker === 'office'
  const limits = job.limits ?? {}
  const decoder = new TextDecoder('utf-8', { fatal: true })
  const out = { header: null, sections: [], images: [], cut: false, error: null, last: null }
  let pending = [], pendingBytes = 0, total = 0, frames = 0, textBytes = 0, imageBytes = 0
  let expectedPage = pdfText ? job.from : null, lastSlide = 0, sheets = 0, lastImagePage = 0

  function header(payload) {
    if (out.header || frames !== 1) violation('header_not_first')
    if (worker === 'image') out.header = strict(payload, { animated: value => typeof value === 'boolean' })
    else if (worker === 'pdf') out.header = strict(payload, { pages: value => Number.isSafeInteger(value) && value >= 1 && value <= 1_000_000 })
    else {
      const parsed = strict(payload, { sniffed: value => Object.hasOwn(OFFICE_SNIFFED, value), sheets: value => count(value, 1_000_000), slides: value => count(value, 1_000_000), entries: value => count(value, 1_000_000) }, ['sniffed'])
      const total = parsed && OFFICE_SNIFFED[parsed.sniffed]
      // Only its own total, and only a kind the job allowed.
      if (!parsed || Object.keys(parsed).length !== (total ? 2 : 1) || (total && !Object.hasOwn(parsed, total)) ||
        !job.allow.includes(parsed.sniffed === 'zip' ? 'zip' : 'office')) violation('header_invalid')
      out.header = parsed
    }
    if (!out.header) violation('header_invalid')
  }
  function section(payload) {
    if (!texts || !out.header) violation('section_unexpected')
    const cleaned = name => typeof name === 'string' && name.length >= 1 && name.length <= 100
    let value
    if (pdfText) {
      value = strict(payload, { page: value => Number.isSafeInteger(value) && value >= 1 })
      if (!value || value.page !== expectedPage || value.page > job.from + job.count - 1 || value.page > out.header.pages) violation('section_order')
      expectedPage++
    } else if (out.header.slides !== undefined) {
      value = strict(payload, { slide: value => Number.isSafeInteger(value) && value >= 1 })
      if (!value || value.slide <= lastSlide || value.slide > out.header.slides) violation('section_order')
      lastSlide = value.slide
    } else if (out.header.sheets !== undefined) {
      value = strict(payload, { sheet: cleaned, rows: value => count(value, limits.sheet_rows), total_rows: value => Number.isSafeInteger(value) && value >= 0 })
      if (!value || value.rows > value.total_rows || ++sheets > Math.min(out.header.sheets, limits.sheets)) violation('section_order')
      value.sheet = cleanText(value.sheet)
    } else violation('section_unexpected')
    out.sections.push({ section: value, text: '' })
  }
  function text(payload) {
    if (!texts || !out.header || payload.length < 1) violation('text_unexpected')
    // A section-less office text (docx, odt, zip) has one leading part; the others need their section first.
    const sectioned = pdfText || out.header.slides !== undefined || out.header.sheets !== undefined
    if (sectioned && !out.sections.length) violation('text_outside_section')
    textBytes += payload.length
    if (textBytes > limits.text_bytes) violation('text_over_limit')
    let decoded
    try { decoded = decoder.decode(payload) } catch { violation('text_not_utf8') }
    if (!out.sections.length) out.sections.push({ section: null, text: '' })
    out.sections.at(-1).text += cleanText(decoded)
  }
  function image(payload) {
    if (!(worker === 'image' || pdfImages) || !out.header || payload.length < 3) violation('image_unexpected')
    const page = payload.readUInt16BE(0)
    const file = Buffer.from(payload.subarray(2))
    if (worker === 'image' ? page !== 0 || out.images.length >= 1 : !job.pages.includes(page) || page <= lastImagePage) violation('image_page')
    lastImagePage = page
    const png = worker === 'image' && job.op === 'sticker'
    const size = png ? pngInfo(file) : jpegInfo(file)
    if (!size || size.width < 1 || size.height < 1 || Math.max(size.width, size.height) > limits.long_edge) violation('image_invalid')
    imageBytes += file.length
    if (file.length > limits.image_bytes || imageBytes > IMAGES_TOTAL_BYTES) violation('image_too_large')
    out.images.push({ page, mimeType: png ? 'image/png' : 'image/jpeg', data: file, ...size })
  }
  function error(payload) {
    const value = strict(payload, { code: value => ERROR_CODES.includes(value), what: value => TOO_LARGE_WHAT.includes(value) }, ['code'])
    if (!value || (value.code === 'too_large') !== (value.what !== undefined) || (value.code === 'kind_off' && worker !== 'office')) violation('error_invalid')
    out.error = value
  }
  function done(payload) {
    if (!out.header) violation('done_without_header')
    if (payload.length) {
      if (!texts || !strict(payload, { cut: value => value === true })) violation('done_invalid')
      out.cut = true
    }
    if (worker === 'image' && out.images.length !== 1) violation('image_missing')
  }
  function frame(type, payload) {
    frames++
    if (out.last !== null) violation('frame_after_end')
    switch (type) {
      case FRAME.HEADER: return header(payload)
      case FRAME.TEXT: return text(payload)
      case FRAME.SECTION: return section(payload)
      case FRAME.IMAGE: return image(payload)
      case FRAME.ERROR: out.last = FRAME.ERROR; return error(payload)
      case FRAME.DONE: out.last = FRAME.DONE; return done(payload)
    }
  }
  function take(size) {
    const head = pending.length === 1 ? pending[0] : Buffer.concat(pending, pendingBytes)
    pending = head.length > size ? [head.subarray(size)] : []
    pendingBytes -= size
    return head.subarray(0, size)
  }
  return {
    push(chunk) {
      total += chunk.length
      if (total > STDOUT_MAX) violation('stdout_over_limit')
      pending.push(chunk)
      pendingBytes += chunk.length
      while (pendingBytes >= 5) {
        const prefix = pending[0].length >= 5 ? pending[0] : Buffer.concat(pending, pendingBytes)
        const length = prefix.readUInt32BE(0), type = prefix[4]
        // The prefix is checked before a byte of the payload is waited for.
        if (!Object.hasOwn(FRAME_MAX, type) || length > FRAME_MAX[type]) violation('frame_prefix')
        if (pendingBytes < 5 + length) break
        take(5)
        frame(type, length ? take(length) : Buffer.alloc(0))
      }
    },
    finish(exit) {
      if (pendingBytes) violation('frame_truncated')
      if (out.last === FRAME.DONE ? exit !== 0 : out.last === FRAME.ERROR ? exit !== 2 : true) violation('end_invalid')
      return { header: out.header, sections: out.sections, images: out.images, cut: out.cut, error: out.error }
    },
  }
}
