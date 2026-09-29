// The §16.13 corpus, generated from nothing (no external files): ordinary
// files of every kind the workers open, and the hostile ones, each ending in
// a bounded refusal or result. Used twice: directly by the worker tests
// (test/corpus.test.mjs, no jail) and under media-jail by
// deploy/enclave/check-image.sh --jail (test/jail-corpus.mjs), where a
// job the memcg or the wall ends is also bounded.
//
// A case is { name, worker, header, input, expect, jailOnly?, check? }.
// `expect` lists the outcomes that count as bounded (see outcome() below);
// `check(result)` asserts the content of a finished job. `jailOnly` marks a
// case whose bound is the memcg: run without the jail it would take the
// host's memory instead.

import { createDeflate, deflateRawSync, deflateSync, crc32 } from 'node:zlib'
import { createHash } from 'node:crypto'
import sharp from 'sharp'
import * as XLSX from 'xlsx'

// ---- job headers (§16.11), at the §16.8 values unless a case lowers one ----

export const H = {
  image: (op, format, limits = {}) => ({
    v: 1,
    op,
    format,
    limits: {
      pixels: 40_000_000,
      long_edge: op === 'sticker' ? 512 : 1_568,
      image_bytes: op === 'sticker' ? 102_400 : 307_200,
      ...limits,
    },
  }),
  pdfText: (from = 1, count = 300, limits = {}) => ({
    v: 1,
    op: 'text',
    from,
    count,
    limits: { text_bytes: 4_194_304, image_pixels: 16_000_000, ...limits },
  }),
  pdfImages: (pages, limits = {}) => ({
    v: 1,
    op: 'images',
    pages,
    limits: { long_edge: 1_568, image_bytes: Math.min(307_200, Math.floor(921_600 / pages.length)), image_pixels: 16_000_000, ...limits },
  }),
  office: (allow = ['office', 'zip'], limits = {}) => ({
    v: 1,
    op: 'text',
    allow,
    limits: {
      text_bytes: 4_194_304,
      entries: 2_000,
      inflated: 104_857_600,
      ratio: 100,
      listed: 200,
      sheets: 50,
      sheet_rows: 2_000,
      ...limits,
    },
  }),
}

/**
 * One word for how a job ended: done, done:cut, error:<code>[/<what>] for a
 * valid output; oom (137), wall (124), term (143), seccomp (159), jail (3,
 * 125, 127) and abort (134, V8's heap limit) for media-jail's exits; signal:X
 * for a direct run killed by a signal; invalid:<why> for output the reader
 * would refuse.
 */
export function outcome(r) {
  if (r.valid) {
    if (r.error) return `error:${r.error.code}${r.error.what ? `/${r.error.what}` : ''}`
    return r.cut ? 'done:cut' : 'done'
  }
  const named = { 124: 'wall', 134: 'abort', 137: 'oom', 143: 'term', 159: 'seccomp', 3: 'jail', 125: 'jail', 127: 'jail' }
  if (r.code != null && named[r.code]) return named[r.code]
  if (r.signal) return `signal:${r.signal}`
  return `invalid:${r.why}`
}

// Outcomes that bound a hostile job without a result.
const KILLED = ['oom', 'wall', 'abort', 'signal:SIGABRT']

// ---- small builders --------------------------------------------------------

export function zip(files) {
  const locals = []
  const centrals = []
  let offset = 0
  for (const f of files) {
    const name = Buffer.from(f.name, f.cp437 ? 'latin1' : 'utf8')
    const raw = typeof f.data === 'string' ? Buffer.from(f.data, 'utf8') : f.data ?? Buffer.alloc(0)
    const method = f.method ?? (raw.length ? 8 : 0)
    const body = f.compressed ?? (method === 8 ? deflateRawSync(raw) : raw)
    const flags = (f.cp437 ? 0 : 0x800) | (f.flags ?? 0)
    const crc = f.crc ?? crc32(raw)
    const size = f.declaredSize ?? raw.length
    const fixed = (sig) => {
      const b = Buffer.alloc(sig === 0x04034b50 ? 30 : 46)
      b.writeUInt32LE(sig, 0)
      return b
    }
    const local = fixed(0x04034b50)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(flags, 6)
    local.writeUInt16LE(method, 8)
    local.writeUInt16LE(0x21, 12)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(body.length, 18)
    local.writeUInt32LE(size, 22)
    local.writeUInt16LE(name.length, 26)
    const central = fixed(0x02014b50)
    central.writeUInt16LE(20, 4)
    central.writeUInt16LE(20, 6)
    central.writeUInt16LE(flags, 8)
    central.writeUInt16LE(method, 10)
    central.writeUInt16LE(0x21, 14)
    central.writeUInt32LE(crc, 16)
    central.writeUInt32LE(body.length, 20)
    central.writeUInt32LE(size, 24)
    central.writeUInt16LE(name.length, 28)
    central.writeUInt32LE(offset, 42)
    locals.push(local, name, body)
    centrals.push(central, name)
    offset += local.length + name.length + body.length
  }
  const cd = Buffer.concat(centrals)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(files.length, 8)
  end.writeUInt16LE(files.length, 10)
  end.writeUInt32LE(cd.length, 12)
  end.writeUInt32LE(offset, 16)
  return Buffer.concat([...locals, cd, end])
}

/** Deflate `total` zero bytes without holding them. */
function deflateZeros(total, raw = true) {
  return new Promise((resolve, reject) => {
    const z = createDeflate({ level: 9 })
    const out = []
    z.on('data', (c) => out.push(c))
    z.on('end', () => {
      const all = Buffer.concat(out)
      // createDeflate writes a zlib stream; the raw deflate body sits inside.
      resolve(raw ? all.subarray(2, all.length - 4) : all)
    })
    z.on('error', reject)
    const chunk = Buffer.alloc(1 << 20)
    let left = total
    const pump = () => {
      while (left > 0) {
        const n = Math.min(left, chunk.length)
        left -= n
        if (!z.write(n === chunk.length ? chunk : chunk.subarray(0, n))) return z.once('drain', pump)
      }
      z.end()
    }
    pump()
  })
}

class Pdf {
  constructor() {
    this.objects = []
  }
  add(body) {
    this.objects.push(typeof body === 'string' ? Buffer.from(body, 'latin1') : body)
    return this.objects.length
  }
  stream(dict, data) {
    return this.add(Buffer.concat([Buffer.from(`<< ${dict} /Length ${data.length} >>\nstream\n`, 'latin1'), data, Buffer.from('\nendstream', 'latin1')]))
  }
  build(root, trailer = '') {
    const parts = [Buffer.from('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n', 'latin1')]
    let length = parts[0].length
    const offsets = []
    this.objects.forEach((body, i) => {
      offsets.push(length)
      const b = Buffer.concat([Buffer.from(`${i + 1} 0 obj\n`, 'latin1'), body, Buffer.from('\nendobj\n', 'latin1')])
      parts.push(b)
      length += b.length
    })
    let xref = `xref\n0 ${this.objects.length + 1}\n0000000000 65535 f \n`
    for (const o of offsets) xref += `${String(o).padStart(10, '0')} 00000 n \n`
    xref += `trailer\n<< /Size ${this.objects.length + 1} /Root ${root} 0 R ${trailer}>>\nstartxref\n${length}\n%%EOF\n`
    parts.push(Buffer.from(xref, 'latin1'))
    return Buffer.concat(parts)
  }
}

const escapePdf = (s) => s.replace(/[()\\]/g, (c) => `\\${c}`)

/**
 * A PDF of `pages`, each { lines: [...] } of text and optionally images:
 * [{ name, width, height, filter, data, bpc, colorSpace, mask, w, h }] drawn
 * at w×h points, or { inline } for an inline image operator. `pdf.catalog`
 * extras go into the trailer (the Encrypt dictionary).
 */
export function makePdf(pages, { trailer = '', encrypt } = {}) {
  const pdf = new Pdf()
  const catalog = pdf.add('<< /Type /Catalog /Pages 2 0 R >>')
  const pagesObj = pdf.add('PAGES')
  const font = pdf.add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>')
  const kids = []
  for (const page of pages) {
    const xobjects = []
    let ops = ''
    for (const img of page.images ?? []) {
      if (img.inline) {
        ops += `q ${img.w} 0 0 ${img.h} 36 36 cm\n`
        continue
      }
      const dict = [
        '/Type /XObject /Subtype /Image',
        `/Width ${img.width} /Height ${img.height}`,
        img.mask ? '/ImageMask true' : `/ColorSpace ${img.colorSpace ?? '/DeviceRGB'}`,
        `/BitsPerComponent ${img.bpc ?? 8}`,
        img.filter ? `/Filter ${img.filter}` : '',
      ].join(' ')
      const ref = pdf.stream(dict, img.data)
      xobjects.push(`/${img.name} ${ref} 0 R`)
      ops += `q ${img.w} 0 0 ${img.h} ${img.x ?? 0} ${img.y ?? 0} cm /${img.name} Do Q\n`
    }
    let content = Buffer.from(ops, 'latin1')
    if (page.lines?.length) {
      let text = 'BT /F1 12 Tf 14 TL 72 740 Td\n'
      for (const line of page.lines) text += `(${escapePdf(line)}) Tj T*\n`
      text += 'ET\n'
      content = Buffer.concat([content, Buffer.from(text, 'latin1')])
    }
    const inline = (page.images ?? []).find((i) => i.inline)
    if (inline) {
      content = Buffer.concat([
        content,
        Buffer.from(`BI /W ${inline.width} /H ${inline.height} /CS /RGB /BPC 8 ID `, 'latin1'),
        inline.data,
        Buffer.from('\nEI Q\n', 'latin1'),
      ])
    }
    const contents = page.rawContent ? pdf.stream(page.rawContent.dict, page.rawContent.data) : pdf.stream('', content)
    kids.push(
      pdf.add(
        `<< /Type /Page /Parent ${pagesObj} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${font} 0 R >> /XObject << ${xobjects.join(' ')} >> >> /Contents ${contents} 0 R >>`,
      ),
    )
  }
  pdf.objects[pagesObj - 1] = Buffer.from(`<< /Type /Pages /Kids [${kids.map((k) => `${k} 0 R`).join(' ')}] /Count ${kids.length} >>`, 'latin1')
  if (encrypt) {
    const ref = pdf.add(encrypt.dict)
    trailer += `/Encrypt ${ref} 0 R /ID [<${encrypt.id}> <${encrypt.id}>] `
  }
  return pdf.build(catalog, trailer)
}

// RC4, for the standard security handler (OpenSSL 3 keeps it in the legacy provider).
function rc4(key, data) {
  const s = Array.from({ length: 256 }, (_, i) => i)
  for (let i = 0, j = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key.length]) & 255
    ;[s[i], s[j]] = [s[j], s[i]]
  }
  const out = Buffer.alloc(data.length)
  for (let k = 0, i = 0, j = 0; k < data.length; k++) {
    i = (i + 1) & 255
    j = (j + s[i]) & 255
    ;[s[i], s[j]] = [s[j], s[i]]
    out[k] = data[k] ^ s[(s[i] + s[j]) & 255]
  }
  return out
}

/** A revision-2 standard security handler with a user password (PDF 1.4 §3.5). */
function pdfEncryption(user, owner) {
  const pad = Buffer.from('28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a', 'hex')
  const padded = (p) => Buffer.concat([Buffer.from(p, 'latin1'), pad]).subarray(0, 32)
  const md5 = (...b) => createHash('md5').update(Buffer.concat(b)).digest()
  const id = Buffer.from('0123456789abcdef0123456789abcdef', 'hex')
  const o = rc4(md5(padded(owner)).subarray(0, 5), padded(user))
  const p = Buffer.alloc(4)
  p.writeInt32LE(-44)
  const key = md5(padded(user), o, p, id).subarray(0, 5)
  const u = rc4(key, pad)
  return { dict: `<< /Filter /Standard /V 1 /R 2 /O <${o.toString('hex')}> /U <${u.toString('hex')}> /P -44 >>`, id: id.toString('hex') }
}

function png(width, height, { color = 2, idat = null } = {}) {
  const chunk = (type, data) => {
    const b = Buffer.alloc(12 + data.length)
    b.writeUInt32BE(data.length, 0)
    b.write(type, 4, 'latin1')
    data.copy(b, 8)
    b.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type, 'latin1'), data])), 8 + data.length)
    return b
  }
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(width, 0)
  ihdr.writeUInt32BE(height, 4)
  ihdr[8] = 8
  ihdr[9] = color
  return Buffer.concat([
    Buffer.from('89504e470d0a1a0a', 'hex'),
    chunk('IHDR', ihdr),
    chunk('IDAT', idat ?? deflateSync(Buffer.alloc(64))),
    chunk('IEND', Buffer.alloc(0)),
  ])
}

/**
 * A lossless WebP in the shape of CVE-2023-4863: the largest colour cache (11
 * bits, so the green alphabet has 2,328 symbols) and a prefix code whose code
 * lengths oversubscribe the tree, the input the vulnerable BuildHuffmanTable
 * overflowed on. A patched libwebp refuses it.
 */
function webpHuffmanShape() {
  const bits = []
  const put = (value, n) => {
    for (let i = 0; i < n; i++) bits.push((value >> i) & 1)
  }
  put(0x2f, 8) // VP8L signature
  put(255, 14) // width - 1
  put(255, 14) // height - 1
  put(0, 1) // alpha unused
  put(0, 3) // version
  put(0, 1) // no transform
  put(1, 1) // colour cache present
  put(11, 4) // 11 bits: 2,048 entries
  put(0, 1) // no meta prefix codes
  // The green prefix code, "normal": 19 code-length-code lengths, all 1,
  // which no complete tree has.
  put(0, 1)
  put(15, 4) // 4 + 15 = 19 code length codes
  for (let i = 0; i < 19; i++) put(1, 3)
  for (let i = 0; i < 4096; i++) put(i & 1, 1)
  const bytes = Buffer.alloc(Math.ceil(bits.length / 8))
  bits.forEach((b, i) => {
    if (b) bytes[i >> 3] |= 1 << (i & 7)
  })
  const chunk = Buffer.alloc(8)
  chunk.write('VP8L', 0, 'latin1')
  chunk.writeUInt32LE(bytes.length, 4)
  const body = Buffer.concat([Buffer.from('WEBP', 'latin1'), chunk, bytes, bytes.length % 2 ? Buffer.alloc(1) : Buffer.alloc(0)])
  const riff = Buffer.alloc(8)
  riff.write('RIFF', 0, 'latin1')
  riff.writeUInt32LE(body.length, 4)
  return Buffer.concat([riff, body])
}

/** Insert an APP13 (IPTC) and a COM segment right after the SOI of a JPEG. */
function withSegments(jpeg) {
  const segment = (marker, data) => {
    const b = Buffer.alloc(4)
    b[0] = 0xff
    b[1] = marker
    b.writeUInt16BE(data.length + 2, 2)
    return Buffer.concat([b, data])
  }
  return Buffer.concat([
    jpeg.subarray(0, 2),
    segment(0xed, Buffer.from('Photoshop 3.0\0 8BIM\x04\x04 IPTC city: Lisboa', 'latin1')),
    segment(0xfe, Buffer.from('comment: shot at 38.72,-9.14', 'latin1')),
    jpeg.subarray(2),
  ])
}

const noise = (width, height, sigma = 30) =>
  sharp({ create: { width, height, channels: 3, noise: { type: 'gaussian', mean: 128, sigma } } })
const gradient = (width, height) => {
  const data = Buffer.alloc(width * height * 3)
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const at = (y * width + x) * 3
      data[at] = (x * 255) / width
      data[at + 1] = (y * 255) / height
      data[at + 2] = ((x ^ y) & 0xff)
    }
  }
  return { data, width, height }
}

// ---- OOXML and ODF -----------------------------------------------------------

const W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
const R_NS = 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
const MC = 'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"'
const REL = 'http://schemas.openxmlformats.org/package/2006/relationships'

const para = (text, extra = '') => `<w:p>${extra}<w:r><w:t xml:space="preserve">${text}</w:t></w:r></w:p>`

export function makeDocx({ body, externalLink = false, stored = false } = {}) {
  const content =
    body ??
    [
      para('Invoice 2026-091 for Maria &amp; Filhos'),
      `<w:p><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr><w:tabs><w:tab w:val="left" w:pos="720"/></w:tabs></w:pPr><w:r><w:t>First item</w:t></w:r></w:p>`,
      `<w:p><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr></w:pPr><w:r><w:t>Second</w:t><w:tab/><w:t>item</w:t></w:r></w:p>`,
      `<w:p><w:r><w:t xml:space="preserve">Kept </w:t></w:r><w:ins w:id="1" w:author="a"><w:r><w:t>inserted</w:t></w:r></w:ins><w:del w:id="2" w:author="a"><w:r><w:delText>DELETED-SENTINEL</w:delText></w:r></w:del></w:p>`,
      `<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText>HYPERLINK "http://instr.example/"</w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>field result</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>`,
      `<w:p><w:r><mc:AlternateContent><mc:Choice Requires="wps"><w:drawing><w:txbxContent><w:p><w:r><w:t>Text box once</w:t></w:r></w:p></w:txbxContent></w:drawing></mc:Choice><mc:Fallback><w:pict><w:txbxContent><w:p><w:r><w:t>Text box once</w:t></w:r></w:p></w:txbxContent></w:pict></mc:Fallback></mc:AlternateContent></w:r></w:p>`,
      `<w:tbl><w:tr><w:tc><w:p><w:r><w:t>Total</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>R$ 1.234,56</w:t></w:r></w:p></w:tc></w:tr><w:tr><w:tc><w:p><w:r><w:t>Due</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>2026-10-15 | net</w:t></w:r></w:p></w:tc></w:tr></w:tbl>`,
      `<w:p><w:r><w:t>See note</w:t></w:r><w:r><w:footnoteReference w:id="1"/></w:r><w:r><w:commentReference w:id="0"/></w:r></w:p>`,
      externalLink
        ? `<w:p><w:r><w:drawing><a:blip xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" r:link="rId9"/></w:drawing><w:t>after image</w:t></w:r></w:p>`
        : '',
    ].join('')
  const rels = [
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footnotes" Target="footnotes.xml"/>',
    externalLink
      ? '<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="file:///etc/passwd" TargetMode="External"/>' +
        '<Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="http://169.254.169.254/latest/meta-data/" TargetMode="External"/>'
      : '',
  ].join('')
  return zip([
    { name: '[Content_Types].xml', data: '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>' },
    { name: '_rels/.rels', data: `<Relationships xmlns="${REL}"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>` },
    { name: 'word/document.xml', data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document ${W} ${R_NS} ${MC}><w:body>${content}<w:sectPr/></w:body></w:document>`, method: stored ? 0 : undefined },
    { name: 'word/_rels/document.xml.rels', data: `<Relationships xmlns="${REL}">${rels}</Relationships>` },
    { name: 'word/footnotes.xml', data: `<w:footnotes ${W}><w:footnote w:id="1"><w:p><w:r><w:t>FOOTNOTE-SENTINEL</w:t></w:r></w:p></w:footnote></w:footnotes>` },
    { name: 'word/header1.xml', data: `<w:hdr ${W}><w:p><w:r><w:t>HEADER-SENTINEL</w:t></w:r></w:p></w:hdr>` },
    { name: 'word/comments.xml', data: `<w:comments ${W}><w:comment w:id="0"><w:p><w:r><w:t>COMMENT-SENTINEL</w:t></w:r></w:p></w:comment></w:comments>` },
  ])
}

export function makePptx() {
  const P = 'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
  const slide = (body) => `<p:sld ${P}><p:cSld><p:spTree>${body}</p:spTree></p:cSld></p:sld>`
  const shape = (lines) =>
    `<p:sp><p:txBody><a:bodyPr/>${lines.map((l) => `<a:p><a:pPr><a:buChar char="•"/></a:pPr><a:r><a:rPr lang="pt-BR"/><a:t>${l}</a:t></a:r></a:p>`).join('')}</p:txBody></p:sp>`
  const table = `<p:graphicFrame><a:graphic><a:graphicData><a:tbl><a:tr><a:tc><a:txBody><a:p><a:r><a:t>Q3</a:t></a:r></a:p></a:txBody></a:tc><a:tc><a:txBody><a:p><a:r><a:t>12%</a:t></a:r></a:p></a:txBody></a:tc></a:tr></a:tbl></a:graphicData></a:graphic></p:graphicFrame>`
  return zip([
    { name: '[Content_Types].xml', data: '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>' },
    { name: 'ppt/presentation.xml', data: `<p:presentation ${P} ${R_NS}><p:sldIdLst><p:sldId id="256" r:id="rId3"/><p:sldId id="257" r:id="rId2"/></p:sldIdLst></p:presentation>` },
    {
      name: 'ppt/_rels/presentation.xml.rels',
      data: `<Relationships xmlns="${REL}"><Relationship Id="rId2" Type="x/slide" Target="slides/slide1.xml"/><Relationship Id="rId3" Type="x/slide" Target="/ppt/slides/slide2.xml"/></Relationships>`,
    },
    { name: 'ppt/slides/slide1.xml', data: slide(shape(['Results', 'Revenue up']) + table) },
    { name: 'ppt/slides/slide2.xml', data: slide(shape(['Agenda first'])) },
    { name: 'ppt/notesSlides/notesSlide1.xml', data: slide(shape(['NOTES-SENTINEL'])) },
  ])
}

const ODF_NS =
  'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"'

function odf(type, body) {
  return zip([
    { name: 'mimetype', data: `application/vnd.oasis.opendocument.${type}`, method: 0 },
    { name: 'META-INF/manifest.xml', data: '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>' },
    { name: 'content.xml', data: `<?xml version="1.0" encoding="UTF-8"?><office:document-content ${ODF_NS}><office:body>${body}</office:body></office:document-content>` },
    { name: 'styles.xml', data: `<office:document-styles ${ODF_NS}><office:master-styles><text:p>STYLES-SENTINEL</text:p></office:master-styles></office:document-styles>` },
  ])
}

export function makeOdt() {
  return odf(
    'text',
    `<office:text><text:sequence-decls><text:sequence-decl text:name="Figure"/></text:sequence-decls>` +
      `<text:tracked-changes><text:changed-region><text:deletion><text:p>DELETED-SENTINEL</text:p></text:deletion></text:changed-region></text:tracked-changes>` +
      `<text:h text:outline-level="1">Contrato de locação</text:h>` +
      `<text:p>Valor:<text:s text:c="3"/>R$ 2.000<text:tab/>mensal<text:note><text:note-citation>1</text:note-citation><text:note-body><text:p>NOTE-SENTINEL</text:p></text:note-body></text:note></text:p>` +
      `<text:p>Com <text:span>espaços</text:span>   colapsados<office:annotation><text:p>ANNOTATION-SENTINEL</text:p></office:annotation></text:p>` +
      `<text:list><text:list-item><text:p>Cláusula um</text:p></text:list-item><text:list-item><text:p>Cláusula dois</text:p></text:list-item></text:list>` +
      `<table:table table:name="T"><table:table-row><table:table-cell><text:p>Mês</text:p></table:table-cell><table:table-cell><text:p>Valor</text:p></table:table-cell></table:table-row></table:table>` +
      `<text:p><draw:frame><svg:title>ALT-SENTINEL</svg:title><draw:text-box><text:p>Caixa de texto</text:p></draw:text-box></draw:frame></text:p>` +
      `</office:text>`,
  )
}

export function makeOds() {
  const cell = (v, extra = '') => `<table:table-cell office:value-type="string"${extra}><text:p>${v}</text:p></table:table-cell>`
  const empty = (n) => `<table:table-cell table:number-columns-repeated="${n}"/>`
  return odf(
    'spreadsheet',
    `<office:spreadsheet>` +
      `<table:table table:name="Vendas &quot;2026&quot;"><table:table-column table:number-columns-repeated="3"/>` +
      `<table:table-row>${cell('mês')}${cell('total')}${cell('nota, com vírgula')}</table:table-row>` +
      `<table:table-row>${cell('set')}${cell('1.500')}${empty(2)}</table:table-row>` +
      `<table:table-row table:number-rows-repeated="3">${empty(1024)}</table:table-row>` +
      `<table:table-row>${cell('out')}${empty(2)}${cell('long "quoted"')}<table:table-cell><text:p>linha 1</text:p><text:p>linha 2</text:p><office:annotation><text:p>ANNOTATION-SENTINEL</text:p></office:annotation></table:table-cell></table:table-row>` +
      `<table:table-row table:number-rows-repeated="1048570">${empty(16384)}</table:table-row>` +
      `</table:table>` +
      `<table:table table:name="Repetida"><table:table-row table:number-rows-repeated="5000">${cell('x', ' table:number-columns-repeated="3"')}</table:table-row></table:table>` +
      `<table:table table:name="Vazia"><table:table-row table:number-rows-repeated="1048576"><table:table-cell table:number-columns-repeated="16384"/></table:table-row></table:table>` +
      `</office:spreadsheet>`,
  )
}

function workbook() {
  const wb = XLSX.utils.book_new()
  const big = [['id', 'valor', 'nota']]
  for (let r = 1; r < 3_000; r++) big.push([r, r * 2.5, r % 7 ? '' : `linha ${r}`])
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(big), 'Grande')
  const small = XLSX.utils.aoa_to_sheet([['produto', 'preço'], ['café, moído', 12.5], ['total', null]])
  small.B3 = { t: 'n', v: 12.5, f: 'SUM(B2:B2)' }
  XLSX.utils.book_append_sheet(wb, small, 'Resumo')
  return wb
}

/** An xlsx whose one sheet declares a million rows, written by hand. */
function millionRows() {
  const rows = []
  for (let r = 1; r <= 1_000_000; r++) rows.push(`<row r="${r}"><c r="A${r}"><v>${r}</v></c></row>`)
  const sheet = `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="A1:A1000000"/><sheetData>${rows.join('')}</sheetData></worksheet>`
  const S = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
  return zip([
    { name: '[Content_Types].xml', data: '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>' },
    { name: '_rels/.rels', data: `<Relationships xmlns="${REL}"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>` },
    { name: 'xl/workbook.xml', data: `<workbook xmlns="${S}" ${R_NS}><sheets><sheet name="Milhão" sheetId="1" r:id="rId1"/></sheets></workbook>` },
    { name: 'xl/_rels/workbook.xml.rels', data: `<Relationships xmlns="${REL}"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>` },
    { name: 'xl/worksheets/sheet1.xml', data: sheet },
  ])
}

function cfb(streams) {
  const c = XLSX.CFB.utils.cfb_new()
  for (const [name, data] of Object.entries(streams)) XLSX.CFB.utils.cfb_add(c, name, data)
  return XLSX.CFB.write(c, { type: 'buffer' })
}

const truncate = (b) => b.subarray(0, Math.floor(b.length / 2))

// ---- the cases ----------------------------------------------------------------

const has = (s) => (r) => r.text.includes(s)
const lacks = (s) => (r) => !r.text.includes(s)
const all = (...fs) => (r) => fs.every((f) => f(r))

export async function corpus() {
  const photo = await noise(1200, 900, 20)
    .withExif({ IFD0: { Make: 'CameraCo', Model: 'X1' }, IFD3: { GPSLatitudeRef: 'N', GPSLatitude: '38/1 43/1 0/1', GPSLongitudeRef: 'W', GPSLongitude: '9/1 8/1 0/1' } })
    .withMetadata({ orientation: 6 })
    .jpeg({ quality: 90 })
    .toBuffer()
  const gpsPhoto = withSegments(photo)
  const big = await noise(4000, 3000, 28).jpeg({ quality: 92 }).toBuffer()
  const alphaPng = await sharp({ create: { width: 300, height: 200, channels: 4, background: { r: 0, g: 0, b: 255, alpha: 0 } } }).png().toBuffer()
  const frame = (c) => sharp({ create: { width: 64, height: 48, channels: 4, background: c } }).png().toBuffer()
  const animatedGif = await sharp([await frame('#ff0000'), await frame('#00ff00')], { join: { animated: true } }).gif().toBuffer()
  const sticker = await sharp({ create: { width: 512, height: 512, channels: 4, background: { r: 250, g: 120, b: 0, alpha: 0.6 } } }).webp({ quality: 80 }).toBuffer()
  const animatedSticker = await sharp([await frame('#ff00ff'), await frame('#00ffff')], { join: { animated: true } }).webp().toBuffer()
  const noiseSticker = await noise(512, 512, 90).webp({ lossless: true }).toBuffer()
  const preview = await sharp({ create: { width: 100, height: 56, channels: 3, background: '#336699' } }).jpeg().toBuffer()
  const webpPhoto = await noise(800, 600, 10).webp().toBuffer()
  const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80"><rect width="80" height="80"/></svg>')
  const heic = Buffer.concat([Buffer.from('000000186674797068656963000000006d69663168656963', 'hex'), Buffer.alloc(64)])

  const scanJpeg = await sharp(gradient(1200, 1600).data, { raw: { width: 1200, height: 1600, channels: 3 } }).jpeg({ quality: 85 }).toBuffer()
  const smallJpeg = await sharp({ create: { width: 60, height: 60, channels: 3, background: '#aa0000' } }).jpeg().toBuffer()
  const rgb = gradient(640, 480)
  const inline = gradient(16, 16)
  const bilevel = Buffer.alloc(((200 + 7) >> 3) * 100, 0xaa)
  const textPages = Array.from({ length: 50 }, (_, i) => ({ lines: [`Page ${i + 1} of 50`, 'The quick brown fox jumps over the lazy dog 0123456789', `Total R$ ${i},00   `] }))
  const textPdf = makePdf(textPages)
  const scanned = makePdf([
    { lines: ['Cover page with enough text to not count as scanned by the reader, clearly.'] },
    { images: [{ name: 'Im1', width: 1200, height: 1600, filter: '/DCTDecode', data: scanJpeg, w: 612, h: 792 }, { name: 'Im2', width: 60, height: 60, filter: '/DCTDecode', data: smallJpeg, w: 30, h: 30 }] },
    { images: [{ name: 'Im3', width: 640, height: 480, filter: '/FlateDecode', data: deflateSync(rgb.data), w: 612, h: 459 }] },
    { images: [{ inline: true, width: 16, height: 16, data: inline.data, w: 100, h: 100 }] },
    { images: [{ name: 'Im4', width: 200, height: 100, colorSpace: '/DeviceGray', bpc: 1, data: bilevel, w: 400, h: 200 }] },
    { images: [{ name: 'Mask', width: 200, height: 100, mask: true, bpc: 1, data: bilevel, w: 400, h: 200 }], lines: ['vector only'] },
  ])
  const encryptedPdf = makePdf([{ lines: ['secret'] }], { encrypt: pdfEncryption('user-pass', 'owner-pass') })
  const bomb = await deflateZeros(1 << 30, false)
  const pdfBomb = makePdf([{ rawContent: { dict: '/Filter /FlateDecode', data: bomb } }])
  const deepPdf = makePdf([{ rawContent: { dict: '', data: Buffer.from(`${'['.repeat(100_000)}${']'.repeat(100_000)} BT /F1 12 Tf 72 700 Td (after) Tj ET`, 'latin1') } }, { lines: ['second page reads'] }])

  const docx = makeDocx({ externalLink: true })
  const renamed = makeDocx({
    body: '<x:p xmlns:x="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><x:r><x:t>Other prefix</x:t></x:r></x:p><p xmlns="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><r><t>Default namespace</t></r></p>',
  })
  // Stored, not deflated: deflated it would be refused by ZIP_MAX_RATIO before
  // the XML reader's depth ceiling is reached.
  const deepDocx = makeDocx({ body: `${'<w:sdt><w:sdtContent>'.repeat(5_000)}${para('deep')}${'</w:sdtContent></w:sdt>'.repeat(5_000)}`, stored: true })
  const doctypeDocx = zip([
    { name: 'word/document.xml', data: `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]><w:document ${W}><w:body><w:p><w:r><w:t>&lol2;</w:t></w:r></w:p></w:body></w:document>` },
  ])
  const lyingDocx = zip([
    { name: 'word/document.xml', data: `<w:document ${W}><w:body>${para('x'.repeat(20_000_000))}</w:body></w:document>`, declaredSize: 10_000 },
  ])
  const pptx = makePptx()
  const odt = makeOdt()
  const ods = makeOds()
  const wb = workbook()
  const xlsx = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' })
  const xls = XLSX.write(wb, { type: 'buffer', bookType: 'biff8' })
  const odsBySheetJS = XLSX.write(wb, { type: 'buffer', bookType: 'ods' })
  const million = millionRows()
  const listed = zip([
    { name: 'docs/', data: '' },
    { name: 'docs/relatório.pdf', data: 'pdf' },
    { name: Buffer.from([0x72, 0x82, 0x73, 0x75, 0x6d, 0x65, 0x2e, 0x74, 0x78, 0x74]).toString('latin1'), data: 'cp437', cp437: true },
    { name: 'inner.zip', data: zip([{ name: 'deeper.txt', data: 'hidden' }]), method: 0 },
    ...Array.from({ length: 246 }, (_, i) => ({ name: `f/${String(i).padStart(3, '0')}.txt`, data: `${i}` })),
  ])
  const zipBomb = zip([{ name: 'zeros.bin', data: Buffer.alloc(0), compressed: await deflateZeros(50 << 20), declaredSize: 50 << 20, crc: 0, method: 8 }])
  const manyEntries = zip(Array.from({ length: 2_001 }, (_, i) => ({ name: `e${i}`, data: '' })))
  const encryptedOoxml = cfb({ EncryptionInfo: Buffer.alloc(200, 1), EncryptedPackage: Buffer.alloc(200, 2) })
  const wordCfb = cfb({ WordDocument: Buffer.alloc(600, 3) })

  const cases = [
    // images
    {
      name: 'photo-gps',
      worker: 'image',
      header: H.image('photo', 'jpeg'),
      input: gpsPhoto,
      expect: ['done'],
      check: (r) => r.images[0].width === 900 && r.images[0].height === 1200 && r.header.animated === false,
    },
    { name: 'photo-12mp-ladder', worker: 'image', header: H.image('photo', 'jpeg'), input: big, expect: ['done', 'error:too_large/pixels'] },
    { name: 'photo-png-alpha', worker: 'image', header: H.image('photo', 'png'), input: alphaPng, expect: ['done'] },
    { name: 'photo-webp', worker: 'image', header: H.image('photo', 'webp'), input: webpPhoto, expect: ['done'] },
    { name: 'photo-gif-animated', worker: 'image', header: H.image('photo', 'gif'), input: animatedGif, expect: ['done'], check: (r) => r.header.animated === true },
    { name: 'sticker', worker: 'image', header: H.image('sticker', 'webp'), input: sticker, expect: ['done'], check: (r) => r.images[0].type === 'png' },
    { name: 'sticker-animated', worker: 'image', header: H.image('sticker', 'webp'), input: animatedSticker, expect: ['done'], check: (r) => r.header.animated },
    { name: 'sticker-noise-ladder', worker: 'image', header: H.image('sticker', 'webp'), input: noiseSticker, expect: ['done', 'error:too_large/pixels'] },
    { name: 'thumb', worker: 'image', header: H.image('thumb', 'jpeg'), input: preview, expect: ['done'], check: (r) => r.images[0].width === 100 },
    { name: 'png-50k', worker: 'image', header: H.image('photo', 'png'), input: png(50_000, 50_000), expect: ['error:too_large/pixels'] },
    { name: 'webp-cve-2023-4863', worker: 'image', header: H.image('photo', 'webp'), input: webpHuffmanShape(), expect: ['error:damaged', 'error:unsupported'] },
    { name: 'svg-as-png', worker: 'image', header: H.image('photo', 'png'), input: svg, expect: ['error:unsupported'] },
    { name: 'heic-as-jpeg', worker: 'image', header: H.image('photo', 'jpeg'), input: heic, expect: ['error:unsupported'] },
    { name: 'jpeg-as-png', worker: 'image', header: H.image('photo', 'png'), input: preview, expect: ['error:unsupported'] },
    { name: 'jpeg-truncated', worker: 'image', header: H.image('photo', 'jpeg'), input: truncate(photo), expect: ['error:damaged', 'done'] },
    { name: 'png-truncated', worker: 'image', header: H.image('photo', 'png'), input: truncate(alphaPng), expect: ['error:damaged', 'done'] },
    { name: 'webp-truncated', worker: 'image', header: H.image('photo', 'webp'), input: truncate(webpPhoto), expect: ['error:damaged', 'done'] },
    { name: 'gif-truncated', worker: 'image', header: H.image('photo', 'gif'), input: truncate(animatedGif), expect: ['error:damaged', 'done'] },
    { name: 'image-bad-header', worker: 'image', header: { ...H.image('photo', 'jpeg'), extra: 1 }, input: preview, expect: ['error:bad_input'] },
    { name: 'image-over-ceiling', worker: 'image', header: H.image('photo', 'jpeg', { image_bytes: 307_201 }), input: preview, expect: ['error:bad_input'] },

    // pdf
    {
      name: 'pdf-text',
      worker: 'pdf',
      header: H.pdfText(1, 300),
      input: textPdf,
      expect: ['done'],
      check: (r) => r.header.pages === 50 && r.sections.length === 50 && r.sections[2].text === 'Page 3 of 50\nThe quick brown fox jumps over the lazy dog 0123456789\nTotal R$ 2,00',
    },
    { name: 'pdf-text-window', worker: 'pdf', header: H.pdfText(49, 10), input: textPdf, expect: ['done'], check: (r) => r.sections.map((s) => s.value.page).join() === '49,50' },
    { name: 'pdf-text-past-end', worker: 'pdf', header: H.pdfText(51, 1), input: textPdf, expect: ['done'], check: (r) => r.sections.length === 0 && r.header.pages === 50 },
    { name: 'pdf-text-cut', worker: 'pdf', header: H.pdfText(1, 300, { text_bytes: 1_000 }), input: textPdf, expect: ['done:cut'], check: (r) => Buffer.byteLength(r.text) === 1_000 },
    { name: 'pdf-scanned-text', worker: 'pdf', header: H.pdfText(1, 6), input: scanned, expect: ['done'], check: (r) => r.sections.length === 6 && r.sections[1].text === '' },
    {
      name: 'pdf-scanned-images',
      worker: 'pdf',
      header: H.pdfImages([2, 3, 4, 5]),
      input: scanned,
      expect: ['done'],
      check: (r) => r.images.map((i) => i.page).join() === '2,3,4,5' && r.images[0].height === 1568 && r.images[1].width === 640,
    },
    { name: 'pdf-images-none', worker: 'pdf', header: H.pdfImages([1, 6]), input: scanned, expect: ['done'], check: (r) => r.images.length === 0 },
    { name: 'pdf-encrypted', worker: 'pdf', header: H.pdfText(), input: encryptedPdf, expect: ['error:encrypted'] },
    { name: 'pdf-not-a-pdf', worker: 'pdf', header: H.pdfText(), input: Buffer.from('%PDF-1.4 but nothing else'), expect: ['error:damaged'] },
    { name: 'pdf-truncated', worker: 'pdf', header: H.pdfText(), input: truncate(textPdf), expect: ['done', 'error:damaged'] },
    { name: 'pdf-deep-nesting', worker: 'pdf', header: H.pdfText(), input: deepPdf, expect: ['done', 'error:damaged'], check: has('second page reads') },
    { name: 'pdf-1gb-stream', worker: 'pdf', header: H.pdfText(), input: pdfBomb, expect: ['done', 'error:damaged', ...KILLED], jailOnly: true },
    { name: 'pdf-bad-window', worker: 'pdf', header: H.pdfText(1_990, 20), input: textPdf, expect: ['error:bad_input'] },

    // office
    {
      name: 'docx',
      worker: 'office',
      header: H.office(),
      input: docx,
      expect: ['done'],
      check: all(
        has('Invoice 2026-091 for Maria & Filhos\n- First item\n- Second\titem\nKept inserted\nfield result\nText box once\n'),
        has('| Total | R$ 1.234,56 |\n| Due | 2026-10-15 \\| net |\n'),
        (r) => r.text.split('Text box once').length === 2,
        lacks('DELETED-SENTINEL'),
        lacks('instr.example'),
        lacks('FOOTNOTE-SENTINEL'),
        lacks('HEADER-SENTINEL'),
        lacks('COMMENT-SENTINEL'),
        lacks('root:'),
        has('after image'),
        (r) => r.header.sniffed === 'docx',
      ),
    },
    { name: 'docx-prefixes', worker: 'office', header: H.office(), input: renamed, expect: ['done'], check: has('Other prefix\nDefault namespace\n') },
    { name: 'docx-kind-off', worker: 'office', header: H.office(['zip']), input: docx, expect: ['error:kind_off'] },
    { name: 'docx-deep-nesting', worker: 'office', header: H.office(), input: deepDocx, expect: ['error:damaged'] },
    { name: 'docx-doctype', worker: 'office', header: H.office(), input: doctypeDocx, expect: ['error:damaged'] },
    { name: 'docx-lying-size', worker: 'office', header: H.office(), input: lyingDocx, expect: ['error:too_large/inflated'] },
    { name: 'docx-truncated', worker: 'office', header: H.office(), input: truncate(docx), expect: ['error:damaged'] },
    { name: 'docx-cut', worker: 'office', header: H.office(undefined, { text_bytes: 20 }), input: docx, expect: ['done:cut'], check: (r) => Buffer.byteLength(r.text) === 20 },
    {
      name: 'pptx',
      worker: 'office',
      header: H.office(),
      input: pptx,
      expect: ['done'],
      check: all(
        (r) => r.header.slides === 2 && r.sections.map((s) => s.text).join('|') === 'Agenda first\n|Results\nRevenue up\n| Q3 | 12% |\n',
        lacks('NOTES-SENTINEL'),
      ),
    },
    {
      name: 'odt',
      worker: 'office',
      header: H.office(),
      input: odt,
      expect: ['done'],
      check: all(
        has('Contrato de locação\nValor:   R$ 2.000\tmensal\nCom espaços colapsados\n- Cláusula um\n- Cláusula dois\n| Mês | Valor |\n'),
        has('Caixa de texto'),
        lacks('SENTINEL'),
        (r) => r.header.sniffed === 'odt',
      ),
    },
    {
      name: 'ods',
      worker: 'office',
      header: H.office(),
      input: ods,
      expect: ['done'],
      check: all(
        (r) => r.header.sheets === 3,
        (r) => JSON.stringify(r.sections.map((s) => s.value)) === JSON.stringify([
          { sheet: 'Vendas "2026"', rows: 6, total_rows: 6 },
          { sheet: 'Repetida', rows: 2000, total_rows: 5000 },
          { sheet: 'Vazia', rows: 0, total_rows: 0 },
        ]),
        (r) => r.sections[0].text === 'mês,total,"nota, com vírgula"\nset,1.500\n\n\n\nout,,,"long ""quoted""","linha 1\nlinha 2"\n',
        lacks('ANNOTATION-SENTINEL'),
      ),
    },
    {
      name: 'xlsx',
      worker: 'office',
      header: H.office(),
      input: xlsx,
      expect: ['done'],
      check: all(
        (r) => r.header.sheets === 2 && r.sections[0].value.rows === 2000 && r.sections[0].value.total_rows === 3000,
        (r) => r.sections[1].text === 'produto,preço\n"café, moído",12.5\ntotal,12.5\n',
        lacks('SUM('),
      ),
    },
    { name: 'xls', worker: 'office', header: H.office(), input: xls, expect: ['done'], check: (r) => r.header.sniffed === 'xls' && r.sections[1].text.includes('"café, moído",12.5') },
    // SheetJS writes an ods whose mimetype is not the first entry, which ODF
    // requires and §16.11 classifies by: it is listed as a plain zip.
    { name: 'ods-mimetype-not-first', worker: 'office', header: H.office(), input: odsBySheetJS, expect: ['done'], check: (r) => r.header.sniffed === 'zip' && r.text.includes('\nmimetype\n') },
    { name: 'xls-kind-off', worker: 'office', header: H.office(['zip']), input: xls, expect: ['error:kind_off'] },
    { name: 'xlsx-million-rows', worker: 'office', header: H.office(), input: million, expect: ['done', ...KILLED], check: (r) => r.sections[0].value.rows === 2000 && r.sections[0].value.total_rows === 1_000_000 },
    { name: 'xlsx-truncated', worker: 'office', header: H.office(), input: truncate(xlsx), expect: ['error:damaged'] },
    { name: 'xls-truncated', worker: 'office', header: H.office(), input: truncate(xls), expect: ['error:damaged', 'done'] },
    { name: 'ooxml-encrypted', worker: 'office', header: H.office(), input: encryptedOoxml, expect: ['error:encrypted'] },
    { name: 'cfb-word97', worker: 'office', header: H.office(), input: wordCfb, expect: ['error:unsupported'] },
    {
      name: 'zip-listing',
      worker: 'office',
      header: H.office(),
      input: listed,
      expect: ['done'],
      check: all(
        (r) => r.header.entries === 250,
        has('entries (200 of 250 listed):\ndocs/\ndocs/relatório.pdf\nrésume.txt\ninner.zip\nf/000.txt\n'),
        lacks('deeper.txt'),
      ),
    },
    { name: 'zip-kind-off', worker: 'office', header: H.office(['office']), input: listed, expect: ['error:kind_off'] },
    { name: 'zip-bomb', worker: 'office', header: H.office(), input: zipBomb, expect: ['error:too_large/inflated'] },
    { name: 'zip-entries', worker: 'office', header: H.office(), input: manyEntries, expect: ['error:too_large/entries'] },
    { name: 'zip-total', worker: 'office', header: H.office(undefined, { inflated: 1_000 }), input: docx, expect: ['error:too_large/inflated'] },
    { name: 'zip-truncated', worker: 'office', header: H.office(), input: truncate(listed), expect: ['error:damaged'] },
    { name: 'office-not-office', worker: 'office', header: H.office(), input: Buffer.from('plain text is not for this worker'), expect: ['error:unsupported'] },
    { name: 'office-bad-allow', worker: 'office', header: H.office([]), input: docx, expect: ['error:bad_input'] },
  ]
  return cases
}
