// The probe enclave's stand-in for the production reader (deploy/enclave/probe,
// docs/mcp-enclave.md §16.13 GATE and JAIL). The probe image copies this file
// next to the reader's own tests, as
// /opt/e2e/packages/mcp-http/enclave/test/probe-bench.mjs, and probe-report.mjs
// runs it as a child after the jail check:
//
//   node --expose-gc probe-bench.mjs
//
// It boots the reader the way enclave/test/world.mjs does: main.mjs's
// startEnclave in this one Node, with the fake Go, KMS, NSM and ACME on
// loopback, and every job through the image's /usr/local/bin/media-jail and
// /opt/media/worker under the reader's own boot check and runWorker. Two media
// connections are consented as the console and Go would. Then, printing one
// line per result the moment it has it,
//
//   BENCH {"phase":"<name>", ...}
//
// 1. boot: how long the boot took, and whether the jail passed its check;
// 2. idle: MemAvailable and this process's own figures with the reader idle;
// 3. heavy: the corpus files whose jobs reach furthest into their memcg
//    (§16.13 CORPUS), each opened end to end while MemAvailable is sampled
//    every 50 ms, then the reader's own health line (mem_avail_min_mb);
// 4. documents: a scanned PDF and a docx of 16 MiB and of 32 MiB
//    (CAP_BYTES.document), each opened end to end with its ciphertext served
//    by the parent over vsock: the reader asks the fake Go, which asks the
//    archive, whose /v1/media for these objects reads the parent's
//    vsock-serve.py through the socat bridge the runner starts on
//    127.0.0.1:PROBE_BRIDGE_PORT, as production's own bridges carry Go's
//    answers. PROBE_OBJECTS=loopback (a local smoke run, no parent) serves
//    them from this process instead, and says so.
//
// Everything that builds inputs (the corpus, sharp, the documents) runs in a
// short-lived child of this file (`inputs`, `document`) writing to /tmp, so
// this process holds the reader, its fakes and one input at a time, and its
// RSS and MemAvailable are the reader's, not the generators'.
//
// The timings are from the first tools/call to the answer the model gets,
// following `pending` with the same arguments (claude.ai's 40 s inline
// wait); fits_chatgpt compares them with ChatGPT's 25 s (§16.7). Each job
// adds its worker, op, time, exit and media-jail's own memory figures, which
// the reader itself never reads (§16.10).
import { execFileSync, spawn as spawnProcess } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdirSync, readFileSync, rmSync, writeFileSync, writeSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { createRequire } from 'node:module'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { contentFixture } from '@whatserver2/mcp/test/content-fixture'
import { checkJail, runWorker } from '../media/jail.mjs'
import { CAP_BYTES } from '../media/policy.mjs'
import { encryptMedia, LABELS, sha256 } from './media-fixtures.mjs'
import { connectMedia, openAttachment, world } from './world.mjs'

const MIB = 1_048_576
const MODE = process.env.PROBE_OBJECTS === 'loopback' ? 'loopback' : 'vsock'
const BRIDGE = `http://127.0.0.1:${Number(process.env.PROBE_BRIDGE_PORT || 9101)}`
const IDLE_MS = Number(process.env.PROBE_IDLE_MS || 10_000)
const INPUTS = '/tmp/probe-inputs'
const OPEN_LIMIT_MS = 300_000
const CHATGPT_WAIT_MS = 25_000
const WORKER_DIR = new URL('../media/worker/', import.meta.url)

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
const now = () => performance.now()
/** One result line, written synchronously so a crash after it cannot lose it. */
const out = (phase, data) => writeSync(1, `BENCH ${JSON.stringify({ phase, ...data })}\n`)

function meminfo() {
  const text = readFileSync('/proc/meminfo', 'utf8')
  const kb = key => Number((new RegExp(`^${key}:\\s+(\\d+) kB$`, 'm').exec(text) ?? [])[1])
  return { mem_total_mb: Math.floor(kb('MemTotal') / 1024), mem_available_mb: Math.floor(kb('MemAvailable') / 1024) }
}
const rssMb = () => Math.round(process.memoryUsage.rss() / MIB)

/** MemAvailable's minimum and this process's largest RSS while `fn` runs. */
async function sampled(fn) {
  let min = Infinity, rss = 0
  const tick = () => { min = Math.min(min, meminfo().mem_available_mb); rss = Math.max(rss, rssMb()) }
  tick()
  const timer = setInterval(tick, 50)
  try { return { value: await fn(), mem_avail_min_mb: min, rss_max_mb: rss } } finally { clearInterval(timer); tick() }
}

// ---- the jail, as the reader runs it, timed per job ------------------------

/** Every job's worker, op, time and exit, and media-jail's own status line. */
let jobs = []
function timedRunWorker(args) {
  let stderr = ''
  // The reader ignores media-jail's stderr; here it is read for the memory figures only.
  const spawn = (bin, argv, options) => {
    const child = spawnProcess(bin, argv, { ...options, stdio: ['pipe', 'pipe', 'pipe'] })
    child.stderr.on('data', chunk => { stderr += chunk })
    return child
  }
  const started = now()
  return runWorker({ ...args, spawn }).then(output => {
    let status = null
    for (const line of stderr.split('\n')) { try { const value = JSON.parse(line); if (value?.tool === 'media-jail') status = value } catch { /* not the status line */ } }
    jobs.push({
      worker: args.worker, op: args.job.op, ms: Math.round(now() - started), exit: output.exit, killed: output.killed, error: output.error?.code ?? null,
      peak_mb: status?.memory_peak_bytes ? Math.round(status.memory_peak_bytes / MIB) : null,
      current_max_mb: status?.memory_current_max_bytes ? Math.round(status.memory_current_max_bytes / MIB) : null,
      jail_wall_ms: status?.wall_ms ?? null,
    })
    return output
  })
}

// ---- the archive, with /v1/media of the probe's objects read from the parent

/**
 * The synthetic archive behind a front that serves /v1/media/{uid} for the
 * uids in `remote`: from `local` when the object is held here (the corpus
 * files, and every object in loopback mode), else from the parent over
 * vsock. Everything else goes to the fixture.
 */
async function archiveWithFront(token) {
  const f = await contentFixture({ token, rows: 2, contacts: 1 })
  const remote = new Map(), local = new Map()
  const front = createServer((req, res) => {
    const uid = req.url.startsWith('/v1/media/') ? req.url.slice('/v1/media/'.length) : null
    const name = uid && remote.get(uid)
    if (name) {
      if (req.headers.authorization !== `Bearer ${token}`) { res.writeHead(403); res.end(); return }
      const object = local.get(name)
      if (object) {
        res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(object.length) })
        res.end(object)
        return
      }
      const up = httpRequest(`${BRIDGE}/objects/${name}`, response => {
        res.writeHead(response.statusCode, { 'content-type': 'application/octet-stream', ...(response.headers['content-length'] ? { 'content-length': response.headers['content-length'] } : {}) })
        response.pipe(res)
      })
      up.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end() })
      up.end()
      return
    }
    const pass = httpRequest(new URL(req.url, f.server), { method: req.method, headers: req.headers }, response => { res.writeHead(response.statusCode, response.headers); response.pipe(res) })
    pass.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end() })
    req.pipe(pass)
  })
  await new Promise(resolve => front.listen(0, '127.0.0.1', resolve))
  return {
    ...f, remote, local, server: `http://127.0.0.1:${front.address().port}`,
    async close() { await new Promise(resolve => front.close(resolve)); await f.close() },
  }
}

let parentDown = null
/** Puts `object` where the front will find it: at the parent, over vsock, or here. */
async function place(archive, name, object) {
  if (MODE === 'loopback') { archive.local.set(name, object); return { transport: 'loopback', ms: 0 } }
  if (parentDown) throw new Error(`the parent did not take an earlier object: ${parentDown}`)
  const started = now()
  let last
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      const response = await fetch(`${BRIDGE}/objects/${name}`, { method: 'PUT', body: object, headers: { 'content-type': 'application/octet-stream' } })
      if (response.status === 201) return { transport: 'vsock', ms: Math.round(now() - started) }
      last = `status ${response.status}`
    } catch (error) {
      last = String(error?.cause?.code ?? error?.message ?? error)
    }
    await sleep(1_000)
  }
  parentDown = last
  throw new Error(`the parent did not take the object: ${last}`)
}
async function unplace(archive, name) {
  archive.local.delete(name)
  if (MODE === 'vsock') await fetch(`${BRIDGE}/objects/${name}`, { method: 'DELETE' }).catch(() => {})
}

/** An attachment of the synthetic archive whose ciphertext the front serves. */
async function attach(archive, plaintext, { media_type, mimetype, filename }) {
  const key = randomBytes(32), object = encryptMedia(plaintext, key, LABELS[media_type])
  const name = randomBytes(8).toString('hex')
  const row = await archive.addMedia({ key, filename, media: { media_type, mimetype, file_length: plaintext.length, file_enc_sha256: sha256(object).toString('base64') } })
  archive.remote.set(row.uid, name)
  return { row, name, object }
}

// ---- one open, end to end ----------------------------------------------------

const headerOf = value => { try { return JSON.parse(value.content[0].text.split('\n')[0]) } catch { return null } }
const codeOf = value => (/^Could not open the attachment \(([a-z_]+)\)/.exec(value.content?.[0]?.text ?? '') ?? [])[1] ?? 'unknown'

/**
 * open_attachment until it answers something other than `pending`: each new
 * call with the same arguments joins the running open (§16.9). A budget
 * refusal waits its retry_after_s, which is reported, not timed.
 */
async function openUntilDone(w, done, args) {
  jobs = []
  let calls = 0, pendings = 0, waitedMs = 0
  const started = now()
  for (;;) {
    calls++
    const { response, value } = await openAttachment(w, done, args)
    const header = value.isError ? null : headerOf(value)
    if (header?.status === 'pending' && now() - started < OPEN_LIMIT_MS) { pendings++; continue }
    if (value.isError && ['rate_limited', 'media_busy'].includes(codeOf(value)) && now() - started < OPEN_LIMIT_MS) {
      const retry = (JSON.parse(value.content[0].text.split('\n')[1] ?? '{}').retry_after_s ?? 5) * 1000
      waitedMs += retry
      await sleep(retry)
      continue
    }
    return {
      ms: Math.round(now() - started - waitedMs), calls, pendings, budget_wait_ms: waitedMs, response_bytes: Buffer.byteLength(response.body),
      outcome: value.isError ? `error:${codeOf(value)}` : header?.status ?? 'unreadable',
      header: header && Object.fromEntries(['sniffed', 'pages', 'sheets', 'entries', 'part', 'scanned_pages', 'image_pages', 'next_cursor', 'truncated', 'images', 'images_withheld']
        .filter(key => header[key] !== undefined).map(key => [key, header[key]])),
      body_chars: value.isError ? 0 : value.content[0].text.length,
      image_kib: value.content.filter(block => block.type === 'image').map(block => Math.round(Buffer.from(block.data, 'base64').length / 1024)),
      jobs,
    }
  }
}

// ---- inputs, built in a child: the heavy corpus files and the documents ---

const HEAVY = [
  // The largest memcg peaks of the jail check: the 1 GB Flate stream reaches
  // pdf's 384 MiB ceiling, the million-row sheet about 230 MiB, a 35 MP PNG
  // and a 12 MP JPEG the image worker's largest, the scanned PDF two jobs.
  { name: 'pdf-1gb-stream', media_type: 'document', mimetype: 'application/pdf' },
  { name: 'xlsx-million-rows', media_type: 'document', mimetype: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
  { name: 'photo-png-35mp', media_type: 'image', mimetype: 'image/png' },
  { name: 'photo-12mp-ladder', media_type: 'image', mimetype: 'image/jpeg' },
  { name: 'pdf-scanned-images', media_type: 'document', mimetype: 'application/pdf' },
]
const PAGE = { width: 1700, height: 2200 }

/** Runs this file as a child that builds inputs, and returns what it printed. */
function child(...args) {
  const started = now()
  const printed = execFileSync(process.execPath, [fileURLToPath(import.meta.url), ...args], { encoding: 'utf8', maxBuffer: 1 << 20, timeout: 300_000 })
  return { ...JSON.parse(printed.trim().split('\n').at(-1)), build_ms: Math.round(now() - started) }
}

async function sharpOf() {
  return (await import(pathToFileURL(createRequire(new URL('package.json', WORKER_DIR)).resolve('sharp')).href)).default
}

/** A deterministic word stream, so the text deflates like prose (about 3:1), not like a pattern. */
function prose(chars, seed = 1) {
  const words = ['contrato', 'valor', 'cliente', 'prazo', 'pagamento', 'entrega', 'fatura', 'imposto', 'serviço', 'garantia', 'cláusula', 'parte',
    'invoice', 'total', 'due', 'amount', 'delivery', 'terms', 'warranty', 'notice', 'schedule', 'annex', 'section', 'party', 'renewal']
  let x = seed, text = ''
  while (text.length < chars) {
    x = (x * 1_103_515_245 + 12_345) % 2_147_483_648
    text += words[x % words.length] + (x % 11 === 0 ? `, R$ ${x % 100_000},${String(x % 100).padStart(2, '0')}. ` : ' ')
  }
  return text.slice(0, chars)
}

/**
 * A PDF of exactly `size` bytes: a cover page with text, then scanned pages,
 * each one `jpeg` drawn full page (no text layer), and one unreferenced
 * stream that fills the rest.
 */
function scannedPdf(size, jpeg) {
  const pages = Math.max(1, Math.floor((size - 64 * 1024) / (jpeg.length + 400)))
  const build = filler => {
    const objects = ['<< /Type /Catalog /Pages 2 0 R >>', 'PAGES', '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    const kids = []
    const stream = (dict, data) => { objects.push(Buffer.concat([Buffer.from(`<< ${dict} /Length ${data.length} >>\nstream\n`, 'latin1'), data, Buffer.from('\nendstream', 'latin1')])); return objects.length }
    const cover = stream('', Buffer.from(`BT /F1 12 Tf 14 TL 72 740 Td (Probe document: a cover page and ${pages} scanned pages.) Tj T* (${prose(90)}) Tj ET\n`, 'latin1'))
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${cover} 0 R >>`)
    kids.push(objects.length)
    for (let p = 0; p < pages; p++) {
      const image = stream(`/Type /XObject /Subtype /Image /Width ${PAGE.width} /Height ${PAGE.height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode`, jpeg)
      const content = stream('', Buffer.from('q 612 0 0 792 0 0 cm /Im0 Do Q\n', 'latin1'))
      objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /Im0 ${image} 0 R >> >> /Contents ${content} 0 R >>`)
      kids.push(objects.length)
    }
    objects[1] = `<< /Type /Pages /Kids [${kids.map(k => `${k} 0 R`).join(' ')}] /Count ${kids.length} >>`
    stream('', Buffer.alloc(filler, 0x20))
    const parts = [Buffer.from('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n', 'latin1')]
    let length = parts[0].length
    const offsets = []
    objects.forEach((body, i) => {
      offsets.push(length)
      const b = Buffer.concat([Buffer.from(`${i + 1} 0 obj\n`, 'latin1'), Buffer.isBuffer(body) ? body : Buffer.from(body, 'latin1'), Buffer.from('\nendobj\n', 'latin1')])
      parts.push(b)
      length += b.length
    })
    let xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
    for (const o of offsets) xref += `${String(o).padStart(10, '0')} 00000 n \n`
    xref += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${length}\n%%EOF\n`
    parts.push(Buffer.from(xref, 'latin1'))
    return Buffer.concat(parts)
  }
  let filler = 0
  for (let pass = 0; pass < 4; pass++) {
    const pdf = build(filler)
    if (pdf.length === size) return { file: pdf, file_pages: pages + 1 }
    filler += size - pdf.length
  }
  throw new Error('the PDF did not reach its size')
}

/**
 * A docx of exactly `size` bytes: document.xml with about 1.5 MB of prose in
 * paragraphs, images in word/media (deflated, as Word writes them), and one
 * stored entry that fills the rest.
 */
function bigDocx(size, jpeg, zip) {
  const W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
  const text = prose(1_500_000, 7)
  const paragraphs = []
  for (let at = 0; at < text.length; at += 600) paragraphs.push(`<w:p><w:r><w:t xml:space="preserve">${text.slice(at, at + 600)}</w:t></w:r></w:p>`)
  const base = [
    { name: '[Content_Types].xml', data: '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>' },
    { name: '_rels/.rels', data: '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>' },
    { name: 'word/document.xml', data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document ${W}><w:body>${paragraphs.join('')}<w:sectPr/></w:body></w:document>` },
  ]
  const head = zip(base).length
  const images = Math.max(0, Math.floor((size - head - 64 * 1024) / (jpeg.length + 200)))
  const files = [...base, ...Array.from({ length: images }, (_, i) => ({ name: `word/media/image${i + 1}.jpeg`, data: jpeg }))]
  const without = zip(files).length
  const name = 'word/media/filler.bin'
  const fill = size - without - (30 + 46 + 2 * Buffer.byteLength(name))
  if (fill < 0) throw new Error('the docx is past its size before the filler')
  const docx = zip([...files, { name, data: randomBytes(fill), method: 0 }])
  if (docx.length !== size) throw new Error(`the docx is ${docx.length} bytes, not ${size}`)
  return { file: docx, file_images: images }
}

/** `inputs <dir>`: the heavy corpus files, one file each. */
async function buildInputs(dir) {
  const { corpus } = await import(new URL('test/corpus.mjs', WORKER_DIR))
  mkdirSync(dir, { recursive: true })
  const sizes = {}
  for (const c of await corpus()) {
    if (!HEAVY.some(item => item.name === c.name)) continue
    writeFileSync(`${dir}/${c.name}`, c.input)
    sizes[c.name] = c.input.length
  }
  process.stdout.write(`${JSON.stringify({ sizes })}\n`)
}

/** `document <pdf|docx> <bytes> <file>`: one document of exactly that size. */
async function buildDocument(kind, size, file) {
  const sharp = await sharpOf()
  const jpeg = await sharp({ create: { ...PAGE, channels: 3, noise: { type: 'gaussian', mean: 200, sigma: 25 } } }).jpeg({ quality: 60 }).toBuffer()
  const { zip } = await import(new URL('test/corpus.mjs', WORKER_DIR))
  const built = kind === 'pdf' ? scannedPdf(size, jpeg) : bigDocx(size, jpeg, zip)
  writeFileSync(file, built.file)
  process.stdout.write(`${JSON.stringify({ file_pages: built.file_pages, file_images: built.file_images, page_jpeg_bytes: jpeg.length })}\n`)
}

// ---- the run -----------------------------------------------------------------

async function bench() {
  const cleanups = []
  const t = { after: fn => cleanups.push(fn) }
  out('begin', { mode: MODE, bridge: MODE === 'vsock' ? BRIDGE : null, pid: process.pid, ...meminfo(), rss_mb: rssMb() })
  try {
    const inputs = child('inputs', INPUTS)
    out('inputs', { ...inputs, ...meminfo() })

    // 1. boot
    let archive
    const booted = now()
    const w = await world(t, { archive: async token => (archive = await archiveWithFront(token)) })
    w.jail = { checkJail: () => checkJail(), runWorker: timedRunWorker }
    const e = await w.start()
    const heavyConnection = await connectMedia(w)
    const documentConnection = await connectMedia(w)
    const ready = e.facts.content.media.ready()
    const unavailable = w.lines.map(line => JSON.parse(line)).filter(entry => entry.event === 'media_jail_unavailable').map(entry => entry.code)
    out('boot', { ms: Math.round(now() - booted), media_jail: ready, media_jail_unavailable: unavailable, rss_mb: rssMb(), ...meminfo() })

    // 2. idle: the reader up, two media connections held, nothing running.
    globalThis.gc?.()
    const idle = await sampled(() => sleep(IDLE_MS))
    const idleHealth = await e.health.tick()
    out('idle', { ms: IDLE_MS, ...meminfo(), mem_avail_min_mb: idle.mem_avail_min_mb, rss_max_mb: idle.rss_max_mb,
      heap_mb: Math.round(process.memoryUsage().heapUsed / MIB), health: { rss_mb: idleHealth.rss_mb, heap_mb: idleHealth.heap_mb, mem_avail_min_mb: idleHealth.mem_avail_min_mb } })

    // 3. heavy: the corpus files that reach furthest into their memcg, one at a time.
    let heavyMin = Infinity
    for (const item of HEAVY) {
      const input = readFileSync(`${INPUTS}/${item.name}`)
      rmSync(`${INPUTS}/${item.name}`)
      const { row, name, object } = await attach(archive, input, { ...item, filename: `probe-${item.name}` })
      archive.local.set(name, object)
      const run = await sampled(() => openUntilDone(w, heavyConnection, { uid: row.uid }))
      archive.local.delete(name)
      heavyMin = Math.min(heavyMin, run.mem_avail_min_mb)
      out('heavy', { name: item.name, file_mb: +(input.length / MIB).toFixed(2), mem_avail_min_mb: run.mem_avail_min_mb, rss_max_mb: run.rss_max_mb, ...run.value })
    }
    const heavyHealth = await e.health.tick()
    const total = meminfo().mem_total_mb
    out('heavy_summary', { mem_total_mb: total, mem_avail_min_mb: heavyMin, quarter_of_total_mb: Math.floor(total / 4), meets_quarter: heavyMin >= total / 4,
      health: { rss_mb: heavyHealth.rss_mb, heap_mb: heavyHealth.heap_mb, mem_avail_min_mb: heavyHealth.mem_avail_min_mb, media_opens: heavyHealth.media_opens, media_killed: heavyHealth.media_killed } })

    // 4. documents through vsock.
    const documents = [{ kind: 'pdf', size: 16 * MIB }, { kind: 'pdf', size: CAP_BYTES.document }, { kind: 'docx', size: 16 * MIB }, { kind: 'docx', size: CAP_BYTES.document }]
    for (const doc of documents) {
      const label = `${doc.kind}-${Math.round(doc.size / MIB)}mib`
      const file = `${INPUTS}/${label}.${doc.kind}`
      try {
        const built = child('document', doc.kind, String(doc.size), file)
        const plaintext = readFileSync(file)
        rmSync(file)
        const mimetype = doc.kind === 'pdf' ? 'application/pdf' : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        const attached = await attach(archive, plaintext, { media_type: 'document', mimetype, filename: `probe-${label}.${doc.kind}` })
        const placed = await place(archive, attached.name, attached.object)
        const ciphertextBytes = attached.object.length
        attached.object = null
        globalThis.gc?.()
        const run = await sampled(() => openUntilDone(w, documentConnection, { uid: attached.row.uid }))
        // The repeat ChatGPT makes: the result cache answers it, with no fetch and no job.
        const repeat = await openUntilDone(w, documentConnection, { uid: attached.row.uid })
        await unplace(archive, attached.name)
        out('document', { name: label, bytes: plaintext.length, ciphertext_bytes: ciphertextBytes, ...built, transport: placed.transport, upload_ms: placed.ms,
          fits_chatgpt: run.value.ms <= CHATGPT_WAIT_MS, mem_avail_min_mb: run.mem_avail_min_mb, rss_max_mb: run.rss_max_mb, ...run.value,
          repeat: { ms: repeat.ms, outcome: repeat.outcome, jobs: repeat.jobs.length } })
      } catch (error) {
        rmSync(file, { force: true })
        out('document', { name: label, error: String(error?.stack ?? error).slice(0, 1_000) })
      }
    }
    out('end', { ...meminfo(), rss_mb: rssMb() })
  } finally {
    rmSync(INPUTS, { recursive: true, force: true })
    for (const fn of cleanups.reverse()) await fn().catch(() => {})
  }
}

const [mode, ...args] = process.argv.slice(2)
const main = mode === 'inputs' ? () => buildInputs(...args) : mode === 'document' ? () => buildDocument(args[0], Number(args[1]), args[2]) : bench
main().then(() => process.exit(0), error => {
  if (mode) { process.stderr.write(`${error?.stack ?? error}\n`); process.exit(1) }
  out('fatal', { error: String(error?.stack ?? error).slice(0, 2_000) })
  process.exit(1)
})
