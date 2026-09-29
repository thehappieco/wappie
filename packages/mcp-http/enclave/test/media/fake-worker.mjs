// A stand-in for the jailed workers (docs/mcp-enclave.md §16.11), for the
// reader's tests: it reads the protocol's stdin and answers with valid frames
// built from a scenario the test put in the plaintext after the magic bytes
// (media-fixtures.mjs withScenario). It parses no real file. A scenario may
// also make it misbehave: `raw` (base64 stdout) with `exit`, `error`,
// `exit_code` with no frames, or `sleep_ms` before answering (`images_sleep_ms`
// before a PDF images job only).
import { Buffer } from 'node:buffer'

const worker = process.argv[2]
const chunks = []
for await (const chunk of process.stdin) chunks.push(chunk)
const stdin = Buffer.concat(chunks)

function frame(type, payload = Buffer.alloc(0)) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload))
  const head = Buffer.alloc(5); head.writeUInt32BE(body.length, 0); head[4] = type
  return Buffer.concat([head, body])
}
const out = []
const end = async code => { await new Promise(resolve => process.stdout.write(Buffer.concat(out), resolve)); process.exit(code) }
const refuse = (code, what) => { out.push(frame(8, { code, ...(what ? { what } : {}) })); return end(2) }

const H = stdin.length >= 4 ? stdin.readUInt32BE(0) : -1
let job, input
try {
  job = JSON.parse(stdin.subarray(4, 4 + H).toString('utf8'))
  const N = stdin.readUInt32BE(4 + H)
  input = stdin.subarray(8 + H)
  if (input.length !== N || N < 1) throw new Error('length')
} catch { await refuse('bad_input') }
const marker = input.indexOf('@@SCENARIO@@')
const scenario = marker >= 0 ? JSON.parse(input.subarray(marker + 12).toString('utf8')) : {}
if (scenario.sleep_ms) await new Promise(resolve => setTimeout(resolve, scenario.sleep_ms))
if (scenario.images_sleep_ms && job.op === 'images') await new Promise(resolve => setTimeout(resolve, scenario.images_sleep_ms))
if (scenario.raw !== undefined) { out.push(Buffer.from(scenario.raw, 'base64')); await end(scenario.exit ?? 0) }
if (scenario.exit_code !== undefined) process.exit(scenario.exit_code)

function jpeg(width, height, size = 0) {
  const segment = (marker, body) => { const head = Buffer.from([0xff, marker, 0, 0]); head.writeUInt16BE(body.length + 2, 2); return Buffer.concat([head, body]) }
  const sof = Buffer.from([8, 0, 0, 0, 0, 3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1])
  sof.writeUInt16BE(height, 1); sof.writeUInt16BE(width, 3)
  const head = Buffer.concat([Buffer.from([0xff, 0xd8]), segment(0xdb, Buffer.alloc(65, 1)), segment(0xc0, sof), segment(0xda, Buffer.from([3, 1, 0, 2, 0x11, 3, 0x11, 0, 0x3f, 0]))])
  return Buffer.concat([head, Buffer.alloc(Math.max(16, size - head.length - 2), 0x55), Buffer.from([0xff, 0xd9])])
}
function png(width, height) {
  const chunk = (type, data) => { const head = Buffer.alloc(8); head.writeUInt32BE(data.length, 0); head.write(type, 4, 'latin1'); return Buffer.concat([head, data, Buffer.alloc(4)]) }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4); ihdr[8] = 8; ihdr[9] = 6
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', Buffer.alloc(32, 0x78)), chunk('IEND', Buffer.alloc(0))])
}
const image = (page, file) => { const head = Buffer.alloc(2); head.writeUInt16BE(page); return frame(4, Buffer.concat([head, file])) }
/** TEXT frames of at most 64 KiB, never splitting a character; false once the job's text limit would be passed. */
let textBytes = 0
function text(value) {
  let bytes = Buffer.from(value)
  if (textBytes + bytes.length > job.limits.text_bytes) return false
  textBytes += bytes.length
  while (bytes.length) {
    let size = Math.min(65_536, bytes.length)
    while (size < bytes.length && (bytes[size] & 0xc0) === 0x80) size--
    out.push(frame(2, bytes.subarray(0, size)))
    bytes = bytes.subarray(size)
  }
  return true
}

if (scenario.error && !scenario.error_after_header) await refuse(scenario.error.code, scenario.error.what)
if (worker === 'image') {
  out.push(frame(1, { animated: scenario.animated === true }))
  if (scenario.error) await refuse(scenario.error.code, scenario.error.what)
  const edge = job.limits.long_edge
  const width = Math.min(scenario.width ?? 64, edge), height = Math.min(scenario.height ?? 48, edge)
  out.push(image(0, job.op === 'sticker' ? png(width, height) : jpeg(width, height, scenario.image_size)))
  out.push(frame(9))
  await end(0)
}
if (worker === 'pdf') {
  const pages = scenario.pages ?? ['hello']
  const total = scenario.total ?? pages.length
  out.push(frame(1, { pages: total }))
  if (scenario.error) await refuse(scenario.error.code, scenario.error.what)
  if (job.op === 'text') {
    let cut = false
    for (let page = job.from; page <= Math.min(job.from + job.count - 1, total); page++) {
      out.push(frame(3, { page }))
      const value = pages[page - 1] ?? ''
      if (value && !text(value)) { cut = true; break }
    }
    out.push(frame(9, cut ? { cut: true } : Buffer.alloc(0)))
  } else {
    const raster = scenario.raster ?? pages.flatMap((value, index) => (value.trim().length < 50 ? [index + 1] : []))
    for (const page of job.pages) if (page <= total && raster.includes(page)) out.push(image(page, jpeg(200, 300, scenario.image_size)))
    out.push(frame(9))
  }
  await end(0)
}
if (worker === 'office') {
  const office = scenario.office ?? { sniffed: 'docx', text: 'Hello from a document.\n' }
  if (!job.allow.includes(office.sniffed === 'zip' ? 'zip' : 'office')) await refuse('kind_off')
  const header = { sniffed: office.sniffed }
  if (office.sheets) header.sheets = office.total_sheets ?? office.sheets.length
  if (office.slides) header.slides = office.slides.length
  if (office.sniffed === 'zip') header.entries = office.entries ?? office.names.length
  out.push(frame(1, header))
  if (scenario.error) await refuse(scenario.error.code, scenario.error.what)
  let cut = false
  if (office.sheets) {
    for (const sheet of office.sheets.slice(0, job.limits.sheets)) {
      out.push(frame(3, { sheet: sheet.name, rows: sheet.rows, total_rows: sheet.total_rows }))
      if (sheet.csv && !text(sheet.csv)) { cut = true; break }
    }
  } else if (office.slides) {
    for (const [index, value] of office.slides.entries()) {
      out.push(frame(3, { slide: index + 1 }))
      if (value && !text(value)) { cut = true; break }
    }
  } else if (office.sniffed === 'zip') {
    const names = office.names.slice(0, job.limits.listed)
    cut = !text(`entries (${names.length} of ${header.entries} listed):\n${names.map(name => `${name}\n`).join('')}`)
  } else cut = !text(office.text)
  out.push(frame(9, cut ? { cut: true } : Buffer.alloc(0)))
  await end(0)
}
await refuse('unsupported')
