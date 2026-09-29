// The office worker (docs/mcp-enclave.md §16.11): office documents and zip
// archives as text, jailed by media-jail under
//   node --max-old-space-size=256 --disallow-code-generation-from-strings --no-addons office.mjs
//
// It classifies first, from a zip's central directory (with the bomb checks
// of lib/zip.mjs) or a CFB directory (lib/cfb.mjs), and refuses a kind the job
// does not allow (kind_off) before any parser of that kind runs:
//
//   word/document.xml      docx   own XML reader (lib/flow.mjs)
//   xl/workbook.xml        xlsx   SheetJS, on a stored copy of the counted entries
//   ppt/presentation.xml   pptx   own XML reader, slides in presentation order
//   mimetype …text         odt    own XML reader
//   mimetype …spreadsheet  ods    own XML reader (lib/ods.mjs)
//   CFB with Workbook/Book xls    SheetJS
//   CFB with EncryptionInfo       ERROR encrypted
//   any other CFB                 ERROR unsupported
//   any other zip          zip    entry names only
//
// Macros and scripts are never run, formulas never evaluated, external links
// never followed: nothing here reads a part the table above does not name.

import { silenceConsole, run, strict, refuse, isInt, isObject, HEADER, SECTION, TextSink } from './lib/frames.mjs'
import { JOB_TEXT_MAX_BYTES, ZIP_MAX_ENTRIES, ZIP_MAX_INFLATED, ZIP_MAX_RATIO, ZIP_LISTED, SHEETS_MAX, SHEET_ROWS } from './lib/limits.mjs'
import { readZip, storedZip } from './lib/zip.mjs'
import { classifyCfb } from './lib/cfb.mjs'
import { Package } from './lib/package.mjs'
import { parseXml } from './lib/xml.mjs'
import { renderFlow, DOCX, SLIDE, ODT } from './lib/flow.mjs'
import { readOds } from './lib/ods.mjs'
import { Out, STOP } from './lib/out.mjs'

silenceConsole()

const CFB_MAGIC = Buffer.from('d0cf11e0a1b11ae1', 'hex')
const isZip = (b) => b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && ((b[2] === 3 && b[3] === 4) || (b[2] === 5 && b[3] === 6))
const ODF = {
  'application/vnd.oasis.opendocument.text': 'odt',
  'application/vnd.oasis.opendocument.spreadsheet': 'ods',
}
const KINDS = ['office', 'zip']
const NAME_MAX = 255
// Parts that make SheetJS read a package as another format (ODS, UOC,
// Numbers), matched as it matches them: any case, either slash.
const NOT_XLSX = new Set(['meta-inf/manifest.xml', 'objectdata.xml', 'index/document.iwa'])
const partName = (name) => name.toLowerCase().replace(/\\/g, '/').replace(/^\/+/, '')

function parseJob(header) {
  const job = strict(header, {
    v: (v) => v === 1,
    op: (v) => v === 'text',
    allow: (v) =>
      Array.isArray(v) && v.length > 0 && v.every((k) => KINDS.includes(k)) && new Set(v).size === v.length,
    limits: isObject,
  })
  strict(job.limits, {
    text_bytes: (v) => isInt(v, 1, JOB_TEXT_MAX_BYTES),
    entries: (v) => isInt(v, 1, ZIP_MAX_ENTRIES),
    inflated: (v) => isInt(v, 1, ZIP_MAX_INFLATED),
    ratio: (v) => isInt(v, 1, ZIP_MAX_RATIO),
    listed: (v) => isInt(v, 1, ZIP_LISTED),
    sheets: (v) => isInt(v, 1, SHEETS_MAX),
    sheet_rows: (v) => isInt(v, 1, SHEET_ROWS),
  })
  return job
}

/** What a zip holds, from its names and, for ODF, its first entry. */
function classifyZip(entries, pkg) {
  if (pkg.has('word/document.xml')) return 'docx'
  if (pkg.has('xl/workbook.xml')) return 'xlsx'
  if (pkg.has('ppt/presentation.xml')) return 'pptx'
  const first = entries[0]
  if (first?.name === 'mimetype' && !first.encrypted && first.size <= 256) {
    const type = pkg.bytes('mimetype').toString('latin1').trim()
    if (Object.hasOwn(ODF, type)) return ODF[type]
  }
  return 'zip'
}

async function openCfb(input, job, out) {
  const kind = classifyCfb(input, job.limits.entries)
  if (!kind) throw refuse('unsupported')
  // A classification, like `unsupported`: no parser of any kind has run.
  if (kind === 'encrypted') throw refuse('encrypted')
  if (!job.allow.includes('office')) throw refuse('kind_off')
  const { readWorkbook } = await import('./lib/workbook.mjs')
  const book = readWorkbook(input, out, job.limits)
  return { header: { sniffed: 'xls', sheets: book.sheets }, render: book.render }
}

async function openZip(input, job, out) {
  const { entries } = readZip(input, job.limits)
  const pkg = new Package(input, entries, job.limits)
  const sniffed = classifyZip(entries, pkg)
  if (!job.allow.includes(sniffed === 'zip' ? 'zip' : 'office')) throw refuse('kind_off')
  switch (sniffed) {
    case 'docx':
      return { header: { sniffed }, render: () => renderFlow(pkg.xml('word/document.xml'), out, DOCX) }
    case 'odt':
      return { header: { sniffed }, render: () => renderFlow(pkg.xml('content.xml') ?? '', out, ODT) }
    case 'pptx':
      return slides(pkg, out)
    case 'ods': {
      const book = readOds(pkg.xml('content.xml') ?? '', out, job.limits)
      return { header: { sniffed, sheets: book.sheets }, render: book.render }
    }
    case 'xlsx': {
      // Only what SheetJS reads as an xlsx: without [Content_Types].xml it
      // would open a nested Index.zip and inflate it with no limits, and the
      // parts above send it to another format's parser.
      if (!pkg.has('[Content_Types].xml') || entries.some((e) => NOT_XLSX.has(partName(e.name)))) throw refuse('unsupported')
      // SheetJS gets the entries again as a stored zip, each inflated here,
      // counted and checked against its declared size and CRC: it reads the
      // central directory lib/zip.mjs checked and inflates nothing itself.
      const stored = storedZip(entries, pkg.inflater)
      const { readWorkbook } = await import('./lib/workbook.mjs')
      const book = readWorkbook(stored, out, job.limits)
      return { header: { sniffed, sheets: book.sheets }, render: book.render }
    }
    default:
      return listing(entries, job.limits, out)
  }
}

function slides(pkg, out) {
  const presentation = 'ppt/presentation.xml'
  const ids = []
  parseXml(pkg.xml(presentation), {
    open(name, attrs) {
      if (name === 'p:sldId' && attrs['r:id']) ids.push(attrs['r:id'])
    },
    text() {},
    close() {},
  })
  const targets = pkg.relationships(presentation)
  return {
    header: { sniffed: 'pptx', slides: ids.length },
    render() {
      ids.forEach((id, i) => {
        out.section({ slide: i + 1 })
        const part = targets.get(id)
        if (part && pkg.has(part)) renderFlow(pkg.xml(part), out, SLIDE)
      })
    },
  }
}

function listing(entries, limits, out) {
  const shown = entries.slice(0, limits.listed)
  return {
    header: { sniffed: 'zip', entries: entries.length },
    render() {
      out.text(`entries (${shown.length} of ${entries.length} listed):\n`)
      for (const e of shown) out.text(`${entryName(e.name)}\n`)
    },
  }
}

function entryName(name) {
  let s = name.replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
  if (s.length > NAME_MAX) s = s.slice(0, /[\ud800-\udbff]/.test(s[NAME_MAX - 1]) ? NAME_MAX - 1 : NAME_MAX)
  return s
}

run(async ({ header, input }, frames) => {
  const job = parseJob(header)
  const out = new Out(job.limits.text_bytes)
  let opened
  if (input.length >= 8 && input.subarray(0, 8).equals(CFB_MAGIC)) opened = await openCfb(input, job, out)
  else if (isZip(input)) opened = await openZip(input, job, out)
  else throw refuse('unsupported')
  try {
    opened.render()
  } catch (e) {
    if (e !== STOP) throw e
  }
  await frames.json(HEADER, opened.header)
  const sink = new TextSink(frames, job.limits.text_bytes)
  for (const item of out.items) {
    if (item.section) {
      await sink.flush()
      await frames.json(SECTION, item.section)
    } else {
      await sink.write(item.text)
    }
  }
  await sink.flush()
})
