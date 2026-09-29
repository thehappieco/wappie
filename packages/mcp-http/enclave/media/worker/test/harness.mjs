// Runs a worker the way media-jail would (the §16.6 table's Node flags) but
// without the jail, feeds it a job, and reads its frames back. `validate`
// applies the six checks the reader's Node makes on every job (§16.11 "What
// MAIN checks"), written from the contract alone, so a worker that passes
// here passes the reader. The jail run (jail-corpus.mjs) uses the same
// checker on media-jail's output.

import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

export const WORKER_DIR = fileURLToPath(new URL('..', import.meta.url))

// §16.6 table, the argv after the node binary.
export const ARGV = {
  image: ['--max-old-space-size=128', '--disallow-code-generation-from-strings', 'image.mjs'],
  pdf: ['--max-old-space-size=256', '--disallow-code-generation-from-strings', 'pdf.mjs'],
  office: ['--max-old-space-size=256', '--disallow-code-generation-from-strings', '--no-addons', 'office.mjs'],
}

// §16.8 values the checks use.
export const LIMITS = {
  IMAGE_MAX_PIXELS: 40_000_000,
  IMAGE_LONG_EDGE: 1_568,
  IMAGE_MAX_BYTES: 307_200,
  STICKER_LONG_EDGE: 512,
  STICKER_MAX_BYTES: 102_400,
  IMAGES_TOTAL_BYTES: 921_600,
  JOB_TEXT_MAX_BYTES: 4_194_304,
  PDF_MAX_IMAGE_PIXELS: 16_000_000,
  ZIP_MAX_ENTRIES: 2_000,
  ZIP_MAX_INFLATED: 104_857_600,
  ZIP_MAX_RATIO: 100,
  ZIP_LISTED: 200,
  SHEETS_MAX: 50,
  SHEET_ROWS: 2_000,
}
export const FRAME_MAX = { 1: 16_384, 2: 65_536, 3: 512, 4: 2 + 307_200, 8: 256, 9: 64 }

/** The stdin of a job: u32 H ‖ header ‖ u32 N ‖ input. */
export function stdinOf(header, input) {
  const h = Buffer.from(JSON.stringify(header))
  const lengths = Buffer.alloc(8)
  lengths.writeUInt32BE(h.length, 0)
  lengths.writeUInt32BE(input.length, 4)
  return Buffer.concat([lengths.subarray(0, 4), h, lengths.subarray(4), input])
}

/** Split stdout into frames; a malformed tail is reported, not thrown. */
export function parseFrames(out) {
  const frames = []
  let at = 0
  while (at + 5 <= out.length) {
    const len = out.readUInt32BE(at)
    const type = out[at + 4]
    if (at + 5 + len > out.length) return { frames, trailing: out.length - at }
    frames.push({ type, payload: out.subarray(at + 5, at + 5 + len) })
    at += 5 + len
  }
  return { frames, trailing: out.length - at }
}

/** Run `argv` (a command) with `stdin`, collecting stdout, exit code and signal. */
export function runProcess(command, args, stdin, { timeoutMs = 60_000, env = {}, cwd } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd, env, stdio: ['pipe', 'pipe', 'ignore'] })
    const chunks = []
    let timer = setTimeout(() => {
      timer = null
      child.kill('SIGKILL')
    }, timeoutMs)
    child.stdout.on('data', (c) => chunks.push(c))
    child.stdin.on('error', () => {})
    child.stdin.end(stdin)
    child.on('close', (code, signal) => {
      if (timer) clearTimeout(timer)
      resolve({ code, signal, timedOut: timer === null, stdout: Buffer.concat(chunks) })
    })
  })
}

/** A worker run directly under the table's Node flags. */
export async function runWorker(worker, header, input, options = {}) {
  const r = await runProcess(process.execPath, ARGV[worker], stdinOf(header, input), {
    cwd: WORKER_DIR,
    env: { UV_USE_IO_URING: '0', PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', TMPDIR: '/tmp', OPENSSL_armcap: '0' },
    ...options,
  })
  return { ...r, ...validate(worker, header, r.stdout, r.code) }
}

const strictKeys = (v, keys, optional = []) =>
  v !== null &&
  typeof v === 'object' &&
  !Array.isArray(v) &&
  keys.every((k) => Object.hasOwn(v, k)) &&
  Object.keys(v).every((k) => keys.includes(k) || optional.includes(k))
const int = (v, lo, hi) => Number.isSafeInteger(v) && v >= lo && v <= hi
const json = (payload) => {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload))
  } catch {
    return undefined
  }
}
const ERROR_CODES = ['bad_input', 'unsupported', 'encrypted', 'too_large', 'kind_off', 'damaged']
const OFFICE_KINDS = ['docx', 'odt', 'xlsx', 'xls', 'ods', 'pptx', 'zip']
const OFFICE_TOTAL = { xlsx: 'sheets', xls: 'sheets', ods: 'sheets', pptx: 'slides', zip: 'entries' }

/** The image's pixel size, read by hand: JPEG SOF0-SOF3 or PNG IHDR. */
export function imageFacts(file) {
  if (file.length > 8 && file.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'))) {
    const chunks = []
    for (let at = 8; at + 8 <= file.length; ) {
      const len = file.readUInt32BE(at)
      chunks.push(file.toString('latin1', at + 4, at + 8))
      at += 12 + len
    }
    if (chunks[0] !== 'IHDR') return null
    return { type: 'png', width: file.readUInt32BE(16), height: file.readUInt32BE(20), chunks }
  }
  if (file.length > 3 && file[0] === 0xff && file[1] === 0xd8 && file[2] === 0xff) {
    const segments = []
    for (let at = 2; at + 4 <= file.length; ) {
      if (file[at] !== 0xff) return null
      const marker = file[at + 1]
      if (marker === 0xda) break
      const len = file.readUInt16BE(at + 2)
      segments.push(marker)
      if (marker >= 0xc0 && marker <= 0xc3) {
        return { type: 'jpeg', height: file.readUInt16BE(at + 5), width: file.readUInt16BE(at + 7), segments }
      }
      at += 2 + len
    }
    return null
  }
  return null
}

/**
 * The reader's checks (§16.11 1-6) on one job's stdout and exit code.
 * Returns { valid, why, header, sections, text, images, error, cut }.
 */
export function validate(worker, job, stdout, exit) {
  const fail = (why) => ({ valid: false, why })
  const { frames, trailing } = parseFrames(stdout)
  if (trailing) return fail(`${trailing} bytes of a partial frame`)
  const maxOut = LIMITS.JOB_TEXT_MAX_BYTES + 4 * (FRAME_MAX[4] + 5) + 65_536
  if (stdout.length > maxOut) return fail('stdout over its bound')
  let header = null
  const sections = []
  const texts = []
  const images = []
  let textBytes = 0
  let imageBytes = 0
  let error = null
  let done = null
  const textJob = worker === 'office' || (worker === 'pdf' && job.op === 'text')
  for (const [i, f] of frames.entries()) {
    if (!(f.type in FRAME_MAX)) return fail(`frame type ${f.type}`)
    if (f.payload.length > FRAME_MAX[f.type]) return fail(`frame ${f.type} of ${f.payload.length} bytes`)
    if (done || error) return fail('a frame after the last one')
    if (f.type === 8) {
      const e = json(f.payload)
      const ok =
        e?.code === 'too_large'
          ? strictKeys(e, ['code', 'what']) && ['pixels', 'entries', 'inflated'].includes(e.what)
          : strictKeys(e, ['code']) && ERROR_CODES.includes(e.code)
      if (!ok) return fail(`bad ERROR ${f.payload}`)
      error = e
      continue
    }
    if (i === 0 && f.type !== 1) return fail('first frame is not HEADER')
    if (f.type === 1) {
      if (header) return fail('second HEADER')
      const h = json(f.payload)
      if (worker === 'image' && !(strictKeys(h, ['animated']) && typeof h.animated === 'boolean')) return fail(`image HEADER ${f.payload}`)
      if (worker === 'pdf' && !(strictKeys(h, ['pages']) && int(h.pages, 1, 1e6))) return fail(`pdf HEADER ${f.payload}`)
      if (worker === 'office') {
        const own = OFFICE_TOTAL[h?.sniffed]
        if (!OFFICE_KINDS.includes(h?.sniffed) || !strictKeys(h, own ? ['sniffed', own] : ['sniffed']) || (own && !int(h[own], 0, 1e6))) {
          return fail(`office HEADER ${f.payload}`)
        }
      }
      header = h
      continue
    }
    if (f.type === 9) {
      if (f.payload.length) {
        const d = json(f.payload)
        if (!(strictKeys(d, ['cut']) && d.cut === true)) return fail(`DONE ${f.payload}`)
        done = d
      } else {
        done = {}
      }
      continue
    }
    if (f.type === 2) {
      if (!textJob) return fail('TEXT from a job without text')
      if (!f.payload.length) return fail('empty TEXT')
      try {
        texts.push(new TextDecoder('utf-8', { fatal: true }).decode(f.payload))
      } catch {
        return fail('TEXT is not UTF-8')
      }
      textBytes += f.payload.length
      if (textBytes > job.limits.text_bytes) return fail('TEXT over text_bytes')
      if (sections.length) sections.at(-1).text += texts.at(-1)
      continue
    }
    if (f.type === 3) {
      if (!textJob) return fail('SECTION from a job without text')
      const s = json(f.payload)
      const prev = sections.at(-1)?.value
      if (worker === 'pdf') {
        const want = prev ? prev.page + 1 : job.from
        if (!(strictKeys(s, ['page']) && s.page === want && s.page <= header.pages && s.page <= job.from + job.count - 1)) {
          return fail(`SECTION ${f.payload}`)
        }
      } else if (header.sniffed === 'pptx') {
        if (!(strictKeys(s, ['slide']) && s.slide === (prev ? prev.slide + 1 : 1) && s.slide <= header.slides)) return fail(`SECTION ${f.payload}`)
      } else if (OFFICE_TOTAL[header.sniffed] === 'sheets') {
        const ok =
          strictKeys(s, ['sheet', 'rows', 'total_rows']) &&
          typeof s.sheet === 'string' &&
          s.sheet.length >= 1 &&
          s.sheet.length <= 100 &&
          int(s.rows, 0, job.limits.sheet_rows) &&
          Number.isSafeInteger(s.total_rows) &&
          s.rows <= s.total_rows &&
          sections.length < Math.min(header.sheets, job.limits.sheets)
        if (!ok) return fail(`SECTION ${f.payload}`)
      } else {
        return fail('SECTION where none belongs')
      }
      sections.push({ value: s, text: '' })
      continue
    }
    if (f.type === 4) {
      const pdfImages = worker === 'pdf' && job.op === 'images'
      if (worker !== 'image' && !pdfImages) return fail('IMAGE from a job without images')
      const page = f.payload.readUInt16BE(0)
      const file = f.payload.subarray(2)
      if (worker === 'image' && (page !== 0 || images.length)) return fail('image job IMAGE page or count')
      if (pdfImages && (!job.pages.includes(page) || (images.length && page <= images.at(-1).page))) return fail(`IMAGE page ${page}`)
      const facts = imageFacts(file)
      const wantPng = worker === 'image' && job.op === 'sticker'
      if (!facts || facts.type !== (wantPng ? 'png' : 'jpeg')) return fail('IMAGE magic')
      if (!(facts.width > 0 && facts.height > 0) || Math.max(facts.width, facts.height) > job.limits.long_edge) return fail('IMAGE size')
      if (facts.type === 'jpeg' && facts.segments.some((m) => (m >= 0xe1 && m <= 0xef) || m === 0xfe)) return fail('JPEG APPn or COM')
      if (facts.type === 'png' && facts.chunks.some((c) => ['eXIf', 'tEXt', 'iTXt', 'zTXt', 'tIME'].includes(c))) return fail('PNG metadata chunk')
      if (file.length > job.limits.image_bytes) return fail('IMAGE over image_bytes')
      imageBytes += file.length
      if (imageBytes > LIMITS.IMAGES_TOTAL_BYTES) return fail('IMAGEs over their total')
      images.push({ page, file, ...facts })
      continue
    }
  }
  if (error) {
    if (exit !== 2) return fail(`ERROR with exit ${exit}`)
    if (header === null && frames.length !== 1) return fail('ERROR without HEADER is not alone')
  } else if (done) {
    if (exit !== 0) return fail(`DONE with exit ${exit}`)
    if (!header) return fail('DONE without HEADER')
    if (worker === 'image' && images.length !== 1) return fail('image job without its IMAGE')
  } else {
    return fail(`no DONE or ERROR (exit ${exit})`)
  }
  return { valid: true, header, sections, text: texts.join(''), images, error, cut: done?.cut === true }
}
