// The media service end to end inside one process (docs/mcp-enclave.md §16.5
// to §16.10): calls through `provider.media.open` with a fake archive (the two
// reads reader.mjs hands it), a fake ciphertext server and the fake media-jail
// running fake workers. Every refusal is asserted to open no key and ask for
// no ciphertext where §16.5 says so; results, paging, caches, pending, wiping
// and the log lines are checked against the contract's words.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createLog } from '../../log.mjs'
import { lineAllowed } from '../logsink.mjs'
import { runWorker } from '../media/jail.mjs'
import { BYTES_PER_HOUR, CAP_BYTES, HOST_WAIT_MS, OPENS_PER_MINUTE, OPENS_QUEUE_MAX, PART_MAX_CHARS, QUEUE, RESULT_TTL_MS, TEXT_TTL_MS, THUMB_MAX_BYTES } from '../media/policy.mjs'
import { createMediaService } from '../media/service.mjs'
import { encryptMedia, fakeJailSpawn, JPEG_MAGIC, LABELS, newMediaKey, PDF_MAGIC, sha256, WEBP_MAGIC, withScenario, ZIP_MAGIC } from './media-fixtures.mjs'

const ARCHIVE = 'https://api.wappie.thehappie.co'
const device = '018f3a2b-2222-7000-8000-00000000dddd'
const tenant = '018f3a2b-1111-7000-8000-00000000aaaa'
/** The console link of a message of `device` (§16.7's contract), as the console reads it. */
const linkTo = (uid, number = device) => `https://app.wappie.thehappie.co/console?workspace=${tenant}&open_device=${number}&open_message=${uid}`
const sentinel = { filename: 'SENTINEL-filename-7c1f.pdf', caption: 'SENTINEL caption 7c1f' }
const tick = () => new Promise(resolve => setImmediate(resolve))

/**
 * A media service with everything around it faked. `status` is what Go's
 * status says (mutable); `clock` drives budgets and TTLs. The inline wait's
 * timer (`waits` records the ms asked for) lasts until the open settles, or
 * with `pending` ends at once, so a slow open answers `pending`, or ends after
 * `waitMs` real milliseconds: the host's wait running out mid-job.
 */
async function harness(t, { host = 'claude.ai', jailEnv = {}, ready = true, pending = false, waitMs } = {}) {
  const h = { lines: [], fetches: [], rows: 0, opens: [], objects: new Map(), status: { answer: 'serve', media: true, media_off: [] }, clock: Date.now(), waits: [], jobs: [] }
  const log = createLog(line => h.lines.push(line), () => h.clock)
  const fetch = async (url, init) => {
    h.fetches.push({ url: String(url), init })
    const uid = new URL(url).pathname.split('/').pop()
    const entry = h.objects.get(uid)
    if (!entry) return new Response('{"code":"not_found"}', { status: 404 })
    if (entry.fetch) return entry.fetch(init)
    const object = entry.object
    const body = new ReadableStream({ start(controller) { for (let at = 0; at < object.length; at += 4096) controller.enqueue(new Uint8Array(object.subarray(at, at + 4096))); controller.close() } })
    return new Response(body, { status: 200, headers: { 'content-length': String(object.length), 'content-type': 'application/octet-stream' } })
  }
  h.service = createMediaService({
    log, now: () => h.clock, archive: ARCHIVE, fetch,
    checkActive: { mediaStatus: async () => ({ ...h.status, media_off: [...h.status.media_off] }) },
    jail: { checkJail: async () => (ready ? { ok: true, cpuset: false } : { ok: false, code: 'no_controllers' }), runWorker, spawn: fakeJailSpawn(jailEnv, h.jobs) },
    delay: (ms, signal) => {
      h.waits.push(ms)
      if (pending) return Promise.resolve()
      return new Promise(resolve => {
        const timer = waitMs === undefined ? null : setTimeout(resolve, waitMs)
        signal.addEventListener('abort', () => { clearTimeout(timer); resolve() })
      })
    },
  })
  await h.service.start()
  h.record = { connection_id: randomUUID(), tenant_id: tenant, api_key: `a1b2c3d4.${'k'.repeat(43)}`, media: true, redirect_host: host }
  h.media = h.service.forConnection(h.record)
  /** An attachment the fake archive serves: its row, and the access reader.mjs would build for it. */
  h.attachment = ({ type = 'image', plaintext, mimetype, media = {}, view_once, thumbnail, opened = sentinel, object } = {}) => {
    const key = newMediaKey()
    const uid = randomUUID()
    const encrypted = plaintext ? encryptMedia(plaintext, key, LABELS[type] ?? LABELS.document) : Buffer.alloc(0)
    const row = { uid, device_id: device, ...(view_once ? { view_once: true } : {}), media: {
      media_type: type, ...(mimetype ? { mimetype } : {}), file_length: plaintext?.length ?? 10, file_enc_sha256: sha256(encrypted).toString('base64'),
      media_key_sealed: 'sealed-key', download_status: 'done', ...(thumbnail ? { thumb_sealed: 'sealed-thumb' } : {}), ...media,
    } }
    for (const [name, value] of Object.entries(row.media)) if (value === undefined) delete row.media[name]
    h.objects.set(uid, { object: encrypted, ...object })
    const access = {
      async row() { h.rows++; return row },
      async open(value, what) {
        h.opens.push(what)
        assert.equal(value, row)
        return { ...(what === 'key' ? { key: new Uint8Array(key) } : { thumbnail: thumbnail ? new Uint8Array(thumbnail) : undefined }), filename: opened.filename ?? null, caption: opened.caption ?? null }
      },
    }
    return { uid, row, key, access, open: (request = {}) => h.media.open({ device_id: device, uid, images: true, ...request }, access) }
  }
  /** Calls again until the open is no longer pending (joined calls: nothing new starts). */
  h.finish = async (item, request) => {
    for (;;) {
      const result = await item.open(request)
      if (result.header.status !== 'pending') return result
      await new Promise(resolve => setTimeout(resolve, 20))
    }
  }
  h.events = () => h.lines.map(line => JSON.parse(line)).filter(entry => entry.event)
  /** The worker of each job started so far. */
  h.workers = () => h.jobs.map(call => call.args[call.args.indexOf('--worker') + 1])
  /** Makes `item`'s row read take `ms`, as the archive's round trip does. */
  h.slowRow = (item, ms = 30) => {
    const read = item.access.row.bind(item.access)
    item.access.row = async () => { await new Promise(resolve => setTimeout(resolve, ms)); return read() }
    return item
  }
  h.quiet = () => { const counts = { fetches: h.fetches.length, opens: h.opens.length, rows: h.rows }; return () => ({ fetches: h.fetches.length - counts.fetches, opens: h.opens.length - counts.opens, rows: h.rows - counts.rows }) }
  t.after(() => h.service.close())
  return h
}

const refusedWith = (code, check = () => true) => error => { assert.equal(error.code, code, error.stack); return check(error) !== false }

test('a photo: the key, the ciphertext with the connection\'s key and identity encoding, the checks, the image job; the header in order; identical calls fetch once', async t => {
  const h = await harness(t)
  const photo = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { width: 1200, height: 800 }), mimetype: 'image/jpeg' })
  const result = await photo.open()
  assert.deepEqual(Object.keys(result.header), ['uid', 'media_type', 'sniffed', 'file_length', 'filename', 'caption', 'status', 'images', 'open_url'])
  assert.deepEqual(result.header, { uid: photo.uid, media_type: 'image', sniffed: 'jpeg', file_length: photo.row.media.file_length, filename: sentinel.filename, caption: sentinel.caption, status: 'complete', images: 1, open_url: linkTo(photo.uid) })
  assert.equal(h.media.openURL(photo.row), linkTo(photo.uid), 'get_message\'s link is the same')
  assert.equal(result.body, '')
  assert.equal(result.images[0].mimeType, 'image/jpeg')
  assert.deepEqual([...result.images[0].data.subarray(0, 3)], [0xff, 0xd8, 0xff])
  const [request] = h.fetches
  assert.equal(request.url, `${ARCHIVE}/v1/media/${photo.uid}`)
  assert.equal(request.init.headers.authorization, `Bearer ${h.record.api_key}`)
  assert.equal(request.init.headers['accept-encoding'], 'identity')
  assert.equal(request.init.redirect, 'error')
  assert.deepEqual(h.opens, ['key'])
  // ChatGPT repeats identical calls: the result cache answers them.
  const since = h.quiet()
  const again = await photo.open()
  assert.deepEqual(again.header, result.header)
  assert.deepEqual(again.images[0].data, result.images[0].data)
  assert.deepEqual(since(), { fetches: 0, opens: 0, rows: 0 })
  // The answer handed out is a copy: zeroing it leaves the cache whole.
  result.images[0].data.fill(0)
  assert.notEqual((await photo.open()).images[0].data[0], 0)
  // Another number of the same connection is never answered from what this one opened: its call reads the row.
  const otherNumber = '018f3a2b-2222-7000-8000-00000000eeee'
  const rows = h.rows
  await h.media.open({ device_id: otherNumber, uid: photo.uid, images: true }, photo.access)
  assert.equal(h.rows, rows + 1)
  h.clock += RESULT_TTL_MS
  await photo.open()
  assert.equal(h.fetches.length, 3, 'fetched again once the answer expired')
  // What the log says: only the events, the connection and codes.
  assert.deepEqual(h.events().map(entry => entry.event), ['media_opened', 'media_opened', 'media_opened'])
  for (const line of h.lines) {
    assert.equal(lineAllowed(line), true, line)
    for (const secret of [photo.uid, sentinel.filename, sentinel.caption, h.record.api_key, linkTo(photo.uid)]) assert.equal(line.includes(secret), false, line)
    // The size as a value of its own: a substring check would match the timestamp or the fingerprint by chance.
    const { ts: _ts, ...entry } = JSON.parse(line)
    assert.equal(Object.values(entry).some(value => String(value) === String(photo.row.media.file_length)), false, line)
  }
})

test('every call refusal comes before a key is opened or ciphertext asked for (§16.5 steps 3 to 17)', async t => {
  const h = await harness(t)
  const hash31 = Buffer.alloc(31, 1).toString('base64')
  const cases = [
    ['invalid_cursor', {}, { cursor: 'p2', pages: '2' }],
    ['invalid_cursor', {}, { pages: '5-1' }],
    ['invalid_cursor', {}, { pages: '1-5' }],
    ['view_once_excluded', { view_once: true }],
    ['attachment_unsupported', { type: 'contact' }],
    ['transcription_unavailable', { type: 'audio', media: { download_status: 'gone' } }],
    ['transcription_unavailable', { type: 'ptt' }],
    ['invalid_cursor', { type: 'image' }, { cursor: 'c0' }],
    ['invalid_cursor', { type: 'sticker' }, { pages: '1' }],
    ['invalid_cursor', { type: 'video', thumbnail: Buffer.from(JPEG_MAGIC) }, { cursor: 'p1' }],
    ['attachment_pending', { type: 'document', media: { download_status: 'pending' } }],
    ['attachment_pending', { type: 'document', media: { download_status: 'downloading' } }],
    ['attachment_pending', { type: 'document', media: { download_status: 'failed' } }],
    ['attachment_expired', { type: 'document', media: { download_status: 'gone' } }],
    ['read_failed', { type: 'document', media: { download_status: 'strange' } }],
    ['attachment_unverifiable', { media: { media_key_sealed: undefined } }],
    ['attachment_unverifiable', { media: { file_enc_sha256: undefined } }],
    ['attachment_unverifiable', { media: { file_enc_sha256: hash31 } }],
    ['attachment_too_large', { media: { file_length: CAP_BYTES.image + 1 } }, {}, error => error.facts.size === CAP_BYTES.image + 1 && error.facts.cap === CAP_BYTES.image && error.facts.family === 'image'],
    ['attachment_too_large', { type: 'document', media: { file_length: CAP_BYTES.document + 1 } }],
  ]
  for (const [code, options, request = {}, check] of cases) {
    const item = h.attachment({ plaintext: Buffer.from(JPEG_MAGIC), ...options })
    const since = h.quiet()
    await assert.rejects(item.open(request), refusedWith(code, check), `${code} ${JSON.stringify(options)} ${JSON.stringify(request)}`)
    const quiet = since()
    assert.deepEqual([quiet.fetches, quiet.opens], [0, 0], code)
  }
  // A refusal after the row carries what the model could already see; one before it does not.
  const late = h.attachment({ plaintext: Buffer.from(JPEG_MAGIC), view_once: true, mimetype: 'image/jpeg' })
  await assert.rejects(late.open(), error => assert.deepEqual(error.facts, { media_type: 'image', mimetype: 'image/jpeg', file_length: 4, open_url: linkTo(late.uid) }) ?? true)
  await assert.rejects(late.open({ cursor: 'p1', pages: '1' }), error => error.facts === undefined)
  // Every refusal that names the message carries its console link: the person can see or hear the original there.
  for (const [code, options] of [['transcription_unavailable', { type: 'ptt' }], ['attachment_expired', { type: 'document', media: { download_status: 'gone' } }], ['attachment_too_large', { media: { file_length: CAP_BYTES.image + 1 } }]]) {
    const item = h.attachment({ plaintext: Buffer.from(JPEG_MAGIC), ...options })
    await assert.rejects(item.open(), refusedWith(code, error => error.facts.open_url === linkTo(item.uid)), code)
  }
  // The row itself: another number, no attachment and a 404 are reader.mjs's attachment_not_found, passed through.
  const missing = { row: async () => { throw Object.assign(new Error('x'), { code: 'attachment_not_found' }) }, open: async () => assert.fail('no key') }
  await assert.rejects(h.media.open({ device_id: device, uid: randomUUID(), images: true }, missing), refusedWith('attachment_not_found'))
  // Kinds off, before the fetch.
  const photo = h.attachment({ plaintext: Buffer.from(JPEG_MAGIC) })
  h.status.media_off = ['image']
  await assert.rejects(photo.open(), refusedWith('media_not_allowed'))
  const video = h.attachment({ type: 'video', thumbnail: Buffer.from(JPEG_MAGIC) })
  await assert.rejects(video.open(), refusedWith('media_not_allowed'))
  const document = h.attachment({ type: 'document', plaintext: PDF_MAGIC })
  h.status.media_off = ['pdf', 'office', 'text', 'zip', 'image']
  await assert.rejects(document.open(), refusedWith('media_not_allowed'))
  h.status.media_off = []
  // The gate: media off in Go, a status that no longer serves, a reseal, and this boot's jail.
  for (const [status, code] of [[{ answer: 'serve', media: false }, 'media_not_allowed'], [{ answer: false, media: false }, 'media_not_allowed'], [{ answer: 'reseal', media: false }, 'reconsent_required']]) {
    Object.assign(h.status, status)
    const since = h.quiet()
    await assert.rejects(photo.open(), refusedWith(code), code)
    assert.deepEqual(since(), { fetches: 0, opens: 0, rows: 0 })
  }
  Object.assign(h.status, { answer: 'serve', media: true })
  await assert.rejects(h.service.forConnection({ ...h.record, media: false }).open({ device_id: device, uid: photo.uid, images: true }, photo.access), refusedWith('media_not_allowed'))
  const off = await harness(t, { ready: false })
  const blocked = off.attachment({ plaintext: Buffer.from(JPEG_MAGIC) })
  await assert.rejects(blocked.open(), refusedWith('media_unavailable'))
  assert.deepEqual([off.rows, off.opens.length, off.fetches.length], [0, 0, 0])
  assert.deepEqual(off.events().map(entry => [entry.event, entry.code]), [['media_jail_unavailable', 'no_controllers'], ['media_refused', 'media_unavailable']])
  // Each refusal was logged with its code and the connection only.
  const refused = h.events().filter(entry => entry.event === 'media_refused')
  assert.ok(refused.length > cases.length)
  assert.ok(refused.every(entry => Object.keys(entry).sort().join() === 'code,conn,event,ts'))
})

test('budgets: a queue of OPENS_QUEUE_MAX behind the connection\'s open, OPENS_PER_MINUTE a minute, BYTES_PER_HOUR an hour', async t => {
  const h = await harness(t, { pending: true })
  // A slow open holds the connection's place in the slot; another key waits behind it, the same key joins.
  const slow = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 400 }) })
  const first = await slow.open()
  assert.deepEqual([first.header.status, first.header.retry_after_s], ['pending', 5])
  const other = h.attachment({ plaintext: Buffer.from(JPEG_MAGIC) })
  const queued = await other.open()
  assert.deepEqual([queued.header.status, queued.header.retry_after_s, queued.header.open_url], ['pending', 10, linkTo(other.uid)], 'next after the running open')
  assert.deepEqual(h.opens, ['key'], 'nothing of the queued attachment is opened before its turn')
  const joined = await slow.open()
  assert.equal(joined.header.status, 'pending')
  assert.equal(h.fetches.length, 1, 'a joined call starts nothing')
  assert.equal((await h.finish(slow)).header.status, 'complete')
  assert.equal((await h.finish(other)).header.status, 'complete')
  assert.equal(h.fetches.length, 2)
  // OPENS_PER_MINUTE: every admitted open counts, queued ones too; the eleventh waits for the oldest to age out.
  for (let n = 2; n < OPENS_PER_MINUTE; n++) {
    const item = h.attachment({ plaintext: Buffer.from(JPEG_MAGIC), mimetype: 'image/jpeg' })
    h.objects.get(item.uid).fetch = () => new Response('', { status: 404 })
    await assert.rejects(h.finish(item), refusedWith('attachment_not_found'))
    h.clock += 1000
  }
  const late = h.attachment({ plaintext: Buffer.from(JPEG_MAGIC) })
  await assert.rejects(late.open(), refusedWith('rate_limited', error => error.retry_after_s === 60 && error.facts === undefined))
  h.clock += 60_000 - (OPENS_PER_MINUTE - 2) * 1000 - 21_000
  await assert.rejects(late.open(), refusedWith('rate_limited', error => error.retry_after_s === 40))
  h.clock += 40_000
  // BYTES_PER_HOUR: the claimed size is checked before any key; the declared length is charged at the fetch.
  const huge = h.attachment({ type: 'document', plaintext: PDF_MAGIC, media: { file_length: CAP_BYTES.document } })
  for (let n = 0; n < BYTES_PER_HOUR / CAP_BYTES.document - 1; n++) {
    const filler = h.attachment({ type: 'document', plaintext: PDF_MAGIC, media: { file_length: 10 } })
    h.objects.get(filler.uid).fetch = () => new Response(new Uint8Array(0), { status: 200, headers: { 'content-length': String(CAP_BYTES.document + 10) } })
    await assert.rejects(h.finish(filler), refusedWith('attachment_tampered'), 'the declared length is charged even when the body is short')
    h.clock += 7_000
  }
  const since = h.quiet()
  await assert.rejects(huge.open(), refusedWith('rate_limited', error => error.retry_after_s === 60 && error.facts.media_type === 'document'))
  assert.deepEqual([since().opens, since().fetches], [0, 0])
})

test('queue overflow: one open running and OPENS_QUEUE_MAX waiting; the next is rate_limited before its row is read, and room comes back as the line moves', async t => {
  const h = await harness(t, { pending: true })
  const items = Array.from({ length: 1 + OPENS_QUEUE_MAX }, () => h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 300 }) }))
  const answers = []
  for (const item of items) answers.push((await item.open()).header)
  assert.deepEqual(answers.map(header => [header.status, header.retry_after_s]), [['pending', 5], ['pending', 10], ['pending', 20], ['pending', 20], ['pending', 20]])
  assert.equal(h.service.counts().queue, OPENS_QUEUE_MAX, 'the line counts as waiting in the health line')
  const extra = h.attachment({ plaintext: Buffer.from(JPEG_MAGIC) })
  const since = h.quiet()
  await assert.rejects(extra.open(), refusedWith('rate_limited', error => error.retry_after_s === 10 && error.facts === undefined))
  assert.deepEqual(since(), { fetches: 0, opens: 0, rows: 0 })
  assert.equal(h.events().filter(entry => entry.event === 'media_refused').map(entry => entry.code).join(), 'rate_limited')
  // The line moves in arrival order, one job at a time, and the refused call fits once it has.
  for (const item of items) assert.equal((await h.finish(item)).header.status, 'complete')
  assert.deepEqual(h.fetches.map(item => item.url), items.map(item => `${ARCHIVE}/v1/media/${item.uid}`))
  assert.equal((await h.finish(extra)).header.status, 'complete')
  assert.deepEqual(h.service.counts(), { opens: 6, queue: 0, killed: 0 })
})

test('parallel calls of one connection: two, then five, all answered inline, one after another in arrival order; an identical call joins even a queued open', async t => {
  const h = await harness(t)
  const photo = h.slowRow(h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 200 }) }))
  const pair = await Promise.all([photo.open(), photo.open()])
  assert.deepEqual(pair.map(result => result.header.status), ['complete', 'complete'])
  assert.deepEqual([h.fetches.length, h.opens.length], [1, 1], 'the second call joined the first open')
  // Two photos at once, as claude.ai asks for them: the second waits for the first and runs next, within the same wait.
  const one = h.slowRow(h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 200 }) }))
  const two = h.slowRow(h.attachment({ plaintext: withScenario(JPEG_MAGIC, {}) }))
  const both = await Promise.all([one.open(), two.open()])
  assert.deepEqual(both.map(result => [result.header.status, result.images.length]), [['complete', 1], ['complete', 1]])
  assert.deepEqual(both.map(result => result.header.uid), [one.uid, two.uid])
  assert.deepEqual([h.fetches.length, h.opens.length], [3, 3])
  // Five at once, with a repeat of a queued one among them: every call is answered, the repeat by the open it joined.
  const five = Array.from({ length: 5 }, (_, n) => h.slowRow(h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 100 + 20 * n }) }), 10))
  let running = 0, most = 0
  for (const item of five) {
    const open = item.access.open.bind(item.access)
    item.access.open = async (...args) => { running++; most = Math.max(most, running); try { return await open(...args) } finally { running-- } }
  }
  const mark = h.fetches.length
  const results = await Promise.all([...five.map(item => item.open()), five[3].open()])
  assert.deepEqual(results.map(result => result.header.status), Array(6).fill('complete'))
  assert.deepEqual(results.map(result => result.header.uid), [...five.map(item => item.uid), five[3].uid])
  assert.deepEqual(h.fetches.slice(mark).map(item => item.url), five.map(item => `${ARCHIVE}/v1/media/${item.uid}`), 'one fetch each, in arrival order')
  assert.equal(most, 1, 'one key opened at a time')
  assert.equal(h.events().filter(entry => entry.event === 'media_refused').length, 0)
  // A wipe while the row is read ends the call before anything opens.
  const late = h.slowRow(h.attachment({ plaintext: withScenario(JPEG_MAGIC, {}) }), 100)
  const call = late.open()
  await new Promise(resolve => setTimeout(resolve, 20))
  h.service.wipe(h.record.connection_id)
  await assert.rejects(call, refusedWith('media_not_allowed'))
  assert.equal(h.fetches.length, mark + 5)
})

test('the slot\'s queue keeps its last place for a connection with no open there: five connections that keep their lines fed never shut a sixth out, and the lines go in turn', { timeout: 60_000 }, async t => {
  const h = await harness(t, { pending: true })
  const until = async condition => { while (!condition()) await new Promise(resolve => setTimeout(resolve, 5)) }
  // The order media keys are opened in, by connection.
  const order = []
  const connection = name => {
    const media = h.service.forConnection({ ...h.record, connection_id: randomUUID() })
    return () => {
      const item = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 120 }) })
      const open = item.access.open.bind(item.access)
      item.access.open = async (...args) => { order.push(name); return open(...args) }
      return () => media.open({ device_id: device, uid: item.uid, images: true }, item.access)
    }
  }
  // Five connections ask for three photos each: one open of each in the slot or its queue, two in its line.
  const lines = Array.from({ length: 5 }, (_, n) => { const next = connection(`C${n}`); return [next(), next(), next()] })
  for (const line of lines) for (const call of line) assert.equal((await call()).header.status, 'pending')
  const sixth = connection('F')()
  await assert.rejects(sixth(), refusedWith('media_busy', error => error.retry_after_s === 20), 'four connections wait in the queue: it is full')
  // The first photo done: its connection's line waits, so the place it freed stays free.
  await until(() => order.length === 2)
  assert.equal(h.service.scheduler.queued(), QUEUE - 1)
  assert.equal((await sixth()).header.status, 'pending', 'the sixth connection takes it')
  await until(() => order.length === 16 && h.service.scheduler.running() === 0)
  assert.deepEqual(order, ['C0', 'C1', 'C2', 'C3', 'C4', 'F', 'C0', 'C1', 'C2', 'C3', 'C4', 'C0', 'C1', 'C2', 'C3', 'C4'], 'the sixth within the first round, then the lines in turn')
  // A connection alone still has every place: its line goes in as soon as its open leaves.
  const alone = connection('A')
  for (const call of [alone(), alone(), alone()]) await call()
  await until(() => order.length === 19 && h.service.scheduler.running() === 0)
  assert.deepEqual(h.service.counts().queue, 0)
})

test('an open\'s turn looks again at the text cache and the hour\'s bytes: what the connection\'s earlier opens read or fetched counts before its key is opened', async t => {
  // The first part and page 3 of one PDF, text only: asked together, as asked one after the other, one key and one fetch;
  // page 3's turn comes after the first part's text is in the text cache.
  for (const together of [false, true]) {
    const h = await harness(t)
    const pages = ['Page one says hello to the reader in more than fifty characters of text.', 'Page two says hello to the reader in more than fifty characters of text.', 'Page three says hello to the reader in more than fifty characters of text.']
    const pdf = h.attachment({ type: 'document', mimetype: 'application/pdf', plaintext: withScenario(PDF_MAGIC, { pages }) })
    const [first, third] = together
      ? await Promise.all([pdf.open({ images: false }), pdf.open({ pages: '3', images: false })])
      : [await pdf.open({ images: false }), await pdf.open({ pages: '3', images: false })]
    assert.deepEqual([first.header.part, third.header.part], [{ unit: 'page', from: 1, to: 3 }, { unit: 'page', from: 3, to: 3 }])
    assert.ok(third.body.startsWith('--- page 3 ---\nPage three') && first.body.endsWith(third.body))
    assert.deepEqual([h.opens, h.fetches.length, h.workers()], [['key'], 1, ['pdf']], together ? 'together' : 'one after the other')
  }
  // Seven documents of 32 MiB fetched this hour (each refused as short once its length was charged), then three of
  // 15 MiB asked together: each fits the hour when its call checks it, but only two fit together.
  const h = await harness(t)
  const declared = length => () => new Response(new ReadableStream({ start(controller) { controller.close() } }), { status: 200, headers: { 'content-length': String(length) } })
  for (let n = 0; n < 7; n++) {
    const filler = h.attachment({ type: 'document', plaintext: PDF_MAGIC, media: { file_length: 10 } })
    h.objects.get(filler.uid).fetch = declared(CAP_BYTES.document + 26)
    await assert.rejects(filler.open(), refusedWith('attachment_tampered'))
    h.clock += 10_000
  }
  const claimed = 15 * 1_048_576
  const keys = []
  const documents = Array.from({ length: 3 }, () => {
    const item = h.attachment({ type: 'document', plaintext: PDF_MAGIC, media: { file_length: claimed } })
    h.objects.get(item.uid).fetch = declared(claimed + 26)
    const open = item.access.open.bind(item.access)
    item.access.open = async (...args) => { keys.push(item.uid); return open(...args) }
    return item
  })
  const settled = await Promise.allSettled(documents.map(item => item.open()))
  assert.deepEqual(settled.map(outcome => outcome.reason?.code), ['attachment_tampered', 'attachment_tampered', 'rate_limited'])
  const [, , late] = documents
  refusedWith('rate_limited', error => error.retry_after_s === 60 && error.facts.media_type === 'document' && error.facts.open_url === linkTo(late.uid))(settled[2].reason)
  assert.deepEqual(keys, documents.slice(0, 2).map(item => item.uid), 'the third\'s key was never opened')
  assert.equal(h.fetches.some(request => request.url.endsWith(late.uid)), false, 'nor its ciphertext asked for')
})

test('the host\'s wait holds for a queued open too: 40 s on claude.ai, 25 s on ChatGPT; a turn that does not come in time is pending, like a slow job', async t => {
  for (const [host, wait] of [['claude.ai', 40_000], ['chatgpt.com', 25_000]]) {
    // The host's wait runs out (after 60 real ms here) while the first job still runs.
    const h = await harness(t, { host, waitMs: 60 })
    const first = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 600 }) })
    const second = h.attachment({ plaintext: withScenario(JPEG_MAGIC, {}) })
    const [a, b] = await Promise.all([first.open(), second.open()])
    assert.deepEqual(h.waits, [wait, wait], host)
    assert.deepEqual([a.header.status, a.header.retry_after_s], ['pending', 5], host)
    assert.deepEqual([b.header.status, b.header.retry_after_s, b.header.open_url], ['pending', 10, linkTo(second.uid)], host)
    assert.deepEqual([b.body, b.images], ['', []])
    // Called again as the note says, the queued one is answered once its turn has come; nothing was refused.
    assert.equal((await h.finish(second)).header.status, 'complete', host)
    assert.equal((await h.finish(first)).header.status, 'complete', host)
    assert.equal(h.fetches.length, 2, host)
    assert.equal(h.events().filter(entry => entry.event === 'media_refused').length, 0, host)
  }
  // Within the wait, a queued call is answered with its result.
  const h = await harness(t, { host: 'chatgpt.com' })
  const first = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 200 }) })
  const second = h.attachment({ plaintext: withScenario(JPEG_MAGIC, {}) })
  const answered = await Promise.all([first.open(), second.open()])
  assert.deepEqual(answered.map(result => result.header.status), ['complete', 'complete'])
  assert.deepEqual(h.waits, [25_000, 25_000])
})

test('revocation and media off with a queue: the running job dies, the queued opens are dropped unopened, and every waiting call answers media_not_allowed', async t => {
  const h = await harness(t)
  const id = h.record.connection_id
  const until = async condition => { while (!condition()) await new Promise(resolve => setTimeout(resolve, 20)) }
  const killed = () => h.events().filter(entry => entry.event === 'media_job_killed').map(entry => entry.code)
  for (const reason of ['revoked', 'media_off']) {
    const running = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 5000 }) })
    const queued = [h.attachment({ plaintext: withScenario(JPEG_MAGIC, {}) }), h.attachment({ type: 'document', plaintext: withScenario(ZIP_MAGIC, { office: { sniffed: 'docx', text: 'never' } }) })]
    const calls = [running.open(), ...queued.map(item => item.open()), queued[0].open()]
    await until(() => h.jobs.length > 0 && h.service.counts().queue === 2 && h.service.scheduler.running() === 1)
    await new Promise(resolve => setTimeout(resolve, 200))
    const since = h.quiet()
    const started = Date.now()
    h.service.wipe(id, reason)
    for (const settled of await Promise.allSettled(calls)) refusedWith('media_not_allowed')(settled.reason)
    await until(() => !h.service.scheduler.running())
    assert.ok(Date.now() - started < 4000, `${reason}: the job died on SIGTERM`)
    assert.deepEqual(since(), { fetches: 0, opens: 0, rows: 0 }, `${reason}: nothing of the queued attachments was opened`)
    assert.equal(killed().at(-1), reason)
    assert.equal(h.service.counts().queue, 0)
    assert.equal(h.service.caches.bytes(id), 0)
  }
  // A kind switched off drops that kind's opens, running or queued; the rest of the line goes on in order.
  const photo = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 5000 }) })
  const sticker = h.attachment({ type: 'sticker', plaintext: withScenario(WEBP_MAGIC, {}) })
  const docx = h.attachment({ type: 'document', plaintext: withScenario(ZIP_MAGIC, { office: { sniffed: 'docx', text: 'kept' } }) })
  const [a, b, c] = [photo.open(), sticker.open(), docx.open()]
  await until(() => h.service.scheduler.running() === 1 && h.service.counts().queue === 2)
  await new Promise(resolve => setTimeout(resolve, 200))
  h.service.narrow(id, ['image'])
  await assert.rejects(a, refusedWith('media_not_allowed'))
  await assert.rejects(b, refusedWith('media_not_allowed'))
  assert.equal((await c).body, 'kept', 'the document ran once the killed job had left the slot')
})

test('the queue: one slot enclave-wide, four waiting in order; pending says 5, 10 and 20; a fifth waiting is media_busy', async t => {
  const h = await harness(t, { pending: true })
  const opens = []
  for (let n = 0; n < 5; n++) {
    const media = h.service.forConnection({ ...h.record, connection_id: randomUUID() })
    const item = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 1500 }) })
    opens.push({ media, item, open: () => media.open({ device_id: device, uid: item.uid, images: true }, item.access) })
  }
  const answers = []
  for (const entry of opens) answers.push((await entry.open()).header)
  await tick()
  assert.deepEqual(answers.map(header => [header.status, header.retry_after_s]), [['pending', 5], ['pending', 10], ['pending', 20], ['pending', 20], ['pending', 20]])
  const sixth = h.service.forConnection({ ...h.record, connection_id: randomUUID() })
  const late = h.attachment({ plaintext: Buffer.from(JPEG_MAGIC) })
  await assert.rejects(sixth.open({ device_id: device, uid: late.uid, images: true }, late.access), refusedWith('media_busy', error => error.retry_after_s === 20 && error.facts.media_type === 'image'))
  assert.equal(h.service.counts().queue, 4)
})

test('the inline wait is the host\'s: 40 s on claude.ai, 25 s on ChatGPT and elsewhere; a finished open is answered, then cached', async t => {
  for (const [host, wait] of [['claude.ai', 40_000], ['chatgpt.com', 25_000], ['example.com', 25_000]]) {
    const h = await harness(t, { host, pending: true })
    assert.equal(h.media.host, host === 'example.com' ? 'default' : host)
    const item = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 300 }) })
    const pending = await item.open()
    assert.equal(h.waits[0], wait, host)
    assert.equal(wait, HOST_WAIT_MS[host] ?? HOST_WAIT_MS.default)
    assert.deepEqual(Object.keys(pending.header), ['uid', 'media_type', 'status', 'retry_after_s', 'open_url'])
    assert.equal(pending.header.open_url, linkTo(item.uid))
    assert.deepEqual([pending.body, pending.images], ['', []])
  }
  // Within the wait the call answers the finished open itself, and the same call again comes from the cache.
  const h = await harness(t)
  const item = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 200 }) })
  const result = await item.open()
  assert.equal(result.header.status, 'complete')
  const since = h.quiet()
  assert.equal((await item.open()).header.status, 'complete')
  assert.deepEqual(since(), { fetches: 0, opens: 0, rows: 0 })
})

test('pending, then the same call again, then the result from the cache: one fetch for the three calls', async t => {
  const h = await harness(t, { pending: true })
  const item = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 300 }) })
  assert.equal((await item.open()).header.status, 'pending')
  assert.equal((await item.open()).header.status, 'pending')
  let result
  while ((result = await item.open()).header.status === 'pending') await new Promise(resolve => setTimeout(resolve, 50))
  assert.equal(result.header.status, 'complete')
  assert.equal(h.fetches.length, 1)
  assert.deepEqual(h.opens, ['key'])
})

test('the ciphertext request: status codes, encodings, lengths and streams, each refused before a job', async t => {
  const h = await harness(t)
  const cases = [
    ['attachment_not_found', () => new Response('{}', { status: 404 })],
    ['attachment_pending', () => new Response('{}', { status: 409 })],
    ['unauthorized', () => new Response('{}', { status: 401 })],
    ['read_failed', () => new Response('{}', { status: 500 })],
    ['read_failed', () => new Response('{}', { status: 302, headers: { location: 'https://elsewhere.example' } })],
    ['read_failed', () => { throw new TypeError('network') }],
    ['read_failed', object => new Response(object, { status: 200, headers: { 'content-encoding': 'gzip', 'content-length': String(object.length) } })],
    ['read_failed', object => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(object)); c.close() } }), { status: 200 })],
    ['attachment_tampered', object => new Response(object, { status: 200, headers: { 'content-length': String(object.length - 1) } })],
    ['attachment_tampered', () => new Response(new Uint8Array(25), { status: 200, headers: { 'content-length': '25' } })],
    ['attachment_too_large', () => new Response(new Uint8Array(0), { status: 200, headers: { 'content-length': String(CAP_BYTES.image + 26 + 16) } })],
    ['attachment_tampered', object => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(object)); c.enqueue(new Uint8Array(16)); c.close() } }), { status: 200, headers: { 'content-length': String(object.length) } })],
    ['attachment_tampered', object => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(object.subarray(0, 16))); c.close() } }), { status: 200, headers: { 'content-length': String(object.length) } })],
  ]
  for (const [code, respond] of cases) {
    const item = h.attachment({ plaintext: Buffer.from(JPEG_MAGIC) })
    const object = h.objects.get(item.uid).object
    h.objects.get(item.uid).fetch = () => respond(object)
    await assert.rejects(item.open(), refusedWith(code), code)
    h.clock += 7_000
  }
  assert.equal(h.events().some(entry => entry.event === 'media_job_killed' || entry.event === 'media_opened'), false, 'no job ran')
})

test('integrity: a bad MAC, a bad hash and a 31-byte key are attachment_tampered, the plaintext never reaches a worker, and the refusal is kept', async t => {
  const h = await harness(t)
  const flip = h.attachment({ plaintext: withScenario(JPEG_MAGIC, {}) })
  h.objects.get(flip.uid).object[3] ^= 1
  flip.row.media.file_enc_sha256 = sha256(h.objects.get(flip.uid).object).toString('base64')
  await assert.rejects(flip.open(), refusedWith('attachment_tampered', error => error.facts.media_type === 'image'))
  const hash = h.attachment({ plaintext: withScenario(JPEG_MAGIC, {}), media: { file_enc_sha256: sha256(Buffer.from('another')).toString('base64') } })
  await assert.rejects(hash.open(), refusedWith('attachment_tampered'))
  const short = h.attachment({ plaintext: withScenario(JPEG_MAGIC, {}) })
  const access = { ...short.access, open: async () => ({ key: new Uint8Array(31), filename: null, caption: null }) }
  await assert.rejects(h.media.open({ device_id: device, uid: short.uid, images: true }, access), refusedWith('attachment_tampered'))
  assert.equal(h.events().filter(entry => entry.event === 'media_opened' || entry.event === 'media_job_killed').length, 0)
  const since = h.quiet()
  await assert.rejects(flip.open(), refusedWith('attachment_tampered'))
  assert.deepEqual(since(), { fetches: 0, opens: 0, rows: 0 }, 'a tampered attachment is not fetched again for RESULT_TTL_MS')
})

test('images: stickers as PNG, animated first frames, images:false withheld without a job, and what does not sniff as an image', async t => {
  const h = await harness(t)
  const sticker = h.attachment({ type: 'sticker', plaintext: withScenario(WEBP_MAGIC, { animated: true }) })
  const result = await sticker.open()
  assert.deepEqual([result.header.sniffed, result.header.animated, result.images[0].mimeType], ['webp', true, 'image/png'])
  const text = h.attachment({ plaintext: withScenario(JPEG_MAGIC, {}) })
  const withheld = await text.open({ images: false })
  assert.deepEqual([withheld.header.images, withheld.header.images_withheld, withheld.header.status], [0, 'request', 'complete'])
  assert.equal(h.events().filter(entry => entry.event === 'media_opened').length, 2)
  const svg = h.attachment({ plaintext: Buffer.from('<svg/>'), mimetype: 'image/svg+xml' })
  await assert.rejects(svg.open(), refusedWith('attachment_unsupported'))
  const pdfAsImage = h.attachment({ plaintext: PDF_MAGIC })
  await assert.rejects(pdfAsImage.open(), refusedWith('attachment_unsupported'))
  const asDocument = h.attachment({ type: 'document', plaintext: withScenario(JPEG_MAGIC, {}), mimetype: 'application/octet-stream' })
  assert.deepEqual([(await asDocument.open()).header.sniffed, (await asDocument.open()).header.images], ['jpeg', 1])
  await assert.rejects(asDocument.open({ cursor: 'c0' }), refusedWith('invalid_cursor'), 'a cursor on an image sent as a document')
  const worker = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { error: { code: 'too_large', what: 'pixels' } }) })
  await assert.rejects(worker.open(), refusedWith('attachment_too_large', error => error.facts.what === 'pixels' && error.facts.media_type === 'image'))
})

test('video: the sealed preview only, never a fetch; no preview answers at once; the claimed length', async t => {
  const h = await harness(t)
  const video = h.attachment({ type: 'video', thumbnail: withScenario(JPEG_MAGIC, {}), media: { seconds: 42, download_status: 'gone', media_key_sealed: undefined, file_length: 10 ** 9 } })
  const result = await video.open()
  assert.deepEqual(result.header, { uid: video.uid, media_type: 'video', sniffed: 'thumbnail', file_length: 10 ** 9, filename: sentinel.filename, caption: sentinel.caption, seconds_claimed: 42, status: 'complete', images: 1, open_url: linkTo(video.uid) })
  assert.deepEqual(h.opens, ['thumbnail'])
  assert.equal(h.fetches.length, 0)
  const none = h.attachment({ type: 'ptv', media: { seconds: 7 } })
  const since = h.quiet()
  const bare = await none.open()
  assert.deepEqual(bare.header, { uid: none.uid, media_type: 'ptv', sniffed: 'thumbnail', file_length: 10, seconds_claimed: 7, status: 'complete', images: 0, open_url: linkTo(none.uid) })
  assert.deepEqual(since(), { fetches: 0, opens: 0, rows: 1 })
  const quietVideo = h.attachment({ type: 'video', thumbnail: withScenario(JPEG_MAGIC, {}) })
  assert.deepEqual([(await quietVideo.open({ images: false })).header.images_withheld], ['request'])
  const big = h.attachment({ type: 'video', thumbnail: Buffer.concat([Buffer.from(JPEG_MAGIC), Buffer.alloc(THUMB_MAX_BYTES)]) })
  await assert.rejects(big.open(), refusedWith('attachment_too_large', error => error.facts.size === THUMB_MAX_BYTES + 4 && error.facts.cap === THUMB_MAX_BYTES && error.facts.family === 'image'))
  const odd = h.attachment({ type: 'video', thumbnail: Buffer.from('not an image') })
  await assert.rejects(odd.open(), refusedWith('attachment_unsupported'))
})

test('PDF: text by page in whole blocks, scanned pages and their images, page cursors, pages ranges, and the text cache', async t => {
  const h = await harness(t)
  const long = 'Invoice line. '.repeat(1500)
  const pages = ['Page one says hello to the reader in more than fifty characters of text.', '', long, long, long, 'x', '', '', '', '', 'The end, in words enough to count as text, more than fifty of them.']
  // Page 6 has a little text and no raster image; the other short pages are scans.
  const pdf = h.attachment({ type: 'document', mimetype: 'application/pdf', plaintext: withScenario(PDF_MAGIC, { pages, raster: [2, 7, 8, 9, 10] }) })
  const first = await pdf.open()
  assert.deepEqual(Object.keys(first.header), ['uid', 'media_type', 'sniffed', 'file_length', 'filename', 'caption', 'pages', 'part', 'scanned_pages', 'image_pages', 'next_cursor', 'status', 'images', 'open_url'])
  assert.deepEqual([first.header.pages, first.header.part, first.header.scanned_pages, first.header.image_pages, first.header.next_cursor, first.header.status, first.header.images],
    [11, { unit: 'page', from: 1, to: 4 }, [2], [2], 'p5', 'partial', 1])
  assert.match(first.body, /^--- page 1 ---\nPage one says hello.*\n\n--- page 2 \(scanned\) ---\n\n\n--- page 3 ---\n/s)
  assert.ok(first.body.length <= PART_MAX_CHARS)
  assert.equal(h.fetches.length, 1)
  // The next cursor: its text is in the window already read, but its scanned pages need their images, and so the plaintext.
  const second = await pdf.open({ cursor: 'p5' })
  assert.deepEqual([second.header.part, second.header.scanned_pages, second.header.image_pages, second.header.next_cursor], [{ unit: 'page', from: 5, to: 11 }, [6, 7, 8, 9, 10], [7, 8, 9], null])
  assert.equal(second.suggest_pages, '10-11', 'the scanned pages after the first four, within the window')
  assert.equal(second.header.status, 'complete')
  // Page 6 ('x') is scanned without a raster: its text stays, it gets no frame.
  assert.equal(h.fetches.length, 2, 'page images need the plaintext again')
  const since = h.quiet()
  const textOnly = await pdf.open({ cursor: 'p5', images: false })
  assert.deepEqual([textOnly.header.images, textOnly.header.images_withheld, textOnly.header.image_pages], [0, 'request', undefined])
  assert.deepEqual(since(), { fetches: 0, opens: 0, rows: 0 }, 'text from the cache: no row, no key, no fetch')
  const range = await pdf.open({ pages: '1-2', images: false })
  assert.deepEqual([range.header.part, range.header.next_cursor, range.header.images_withheld], [{ unit: 'page', from: 1, to: 2 }, null, 'request'])
  assert.deepEqual(since(), { fetches: 0, opens: 0, rows: 0 })
  const asked = await pdf.open({ pages: '6-8' })
  assert.deepEqual([asked.header.part, asked.header.image_pages, asked.images.length], [{ unit: 'page', from: 6, to: 8 }, [7, 8], 2])
  for (const request of [{ cursor: 'p12' }, { pages: '11-12' }, { cursor: 'c0' }]) await assert.rejects(pdf.open(request), refusedWith('invalid_cursor'), JSON.stringify(request))
  // A first open at a page no PDF may have is refused before any job.
  const fresh = h.attachment({ type: 'document', mimetype: 'application/pdf', plaintext: withScenario(PDF_MAGIC, { pages: ['x'] }) })
  const killed = h.events().length
  for (const request of [{ cursor: 'p2001' }, { pages: '2001-2002' }]) await assert.rejects(fresh.open(request), refusedWith('invalid_cursor'), JSON.stringify(request))
  assert.equal(h.events().slice(killed).some(entry => entry.event === 'media_opened' || entry.event === 'media_job_killed'), false)
  // A PDF past PDF_MAX_PAGES: page_cap, and no cursor beyond it.
  const huge = h.attachment({ type: 'document', mimetype: 'application/pdf', plaintext: withScenario(PDF_MAGIC, { pages: ['long enough text for page one, well over fifty characters in all.'], total: 5000 }) })
  const capped = await huge.open({ images: false })
  assert.deepEqual([capped.header.pages, capped.header.truncated, capped.header.status], [5000, ['page_cap'], 'partial'])
  await assert.rejects(huge.open({ cursor: 'p2001' }), refusedWith('invalid_cursor'))
  // TEXT_TTL_MS later the window is gone and a cursor fetches again.
  h.clock += TEXT_TTL_MS
  const mark = h.fetches.length
  await pdf.open({ cursor: 'p3', images: false })
  assert.equal(h.fetches.length, mark + 1)
  const encrypted = h.attachment({ type: 'document', plaintext: withScenario(PDF_MAGIC, { error: { code: 'encrypted' } }) })
  await assert.rejects(encrypted.open(), refusedWith('attachment_encrypted'))
})

test('PDF: a pages range whose text passes PART_MAX_CHARS ends at its last whole page, with a cursor for the rest and images for its own pages', async t => {
  const h = await harness(t)
  const page = 'Twenty thousand characters of text. '.repeat(560)
  const pdf = h.attachment({ type: 'document', mimetype: 'application/pdf', plaintext: withScenario(PDF_MAGIC, { pages: [page, page, page, page, page], raster: [1, 2, 3, 4] }) })
  const range = await pdf.open({ pages: '1-4' })
  assert.deepEqual([range.header.part, range.header.next_cursor, range.header.status, range.header.image_pages, range.images.length], [{ unit: 'page', from: 1, to: 2 }, 'p3', 'partial', [1, 2], 2])
  assert.ok(range.body.length <= PART_MAX_CHARS)
  const rest = await pdf.open({ cursor: 'p3', images: false })
  assert.deepEqual([rest.header.part, rest.header.next_cursor], [{ unit: 'page', from: 3, to: 4 }, 'p5'])
})

test('PDF: a pages read keeps the wider text window it overlaps, so later cursors in it fetch nothing', async t => {
  const h = await harness(t)
  const pages = Array.from({ length: 320 }, (_, index) => `Page ${index + 1} has a text layer of more than fifty characters in it.`)
  const pdf = h.attachment({ type: 'document', mimetype: 'application/pdf', plaintext: withScenario(PDF_MAGIC, { pages }) })
  await pdf.open()
  const asked = await pdf.open({ pages: '299-302' })
  assert.deepEqual([asked.header.part, h.fetches.length], [{ unit: 'page', from: 299, to: 302 }, 2])
  const since = h.quiet()
  assert.deepEqual((await pdf.open({ cursor: 'p50' })).header.part.from, 50)
  assert.deepEqual((await pdf.open({ pages: '300-301', images: false })).header.part, { unit: 'page', from: 300, to: 301 }, 'its text from both windows')
  assert.deepEqual(since(), { fetches: 0, opens: 0, rows: 0 })
})

test('PDF page images follow kind image (sharp re-encodes them): withheld while it is off, with the text; switching it off ends an images job', async t => {
  const h = await harness(t)
  const id = h.record.connection_id
  const pages = ['Words enough to count as a text layer on this first page, surely.', '']
  const pdf = h.attachment({ type: 'document', mimetype: 'application/pdf', plaintext: withScenario(PDF_MAGIC, { pages, raster: [2] }) })
  h.status.media_off = ['image']
  const off = await pdf.open()
  assert.deepEqual([off.header.scanned_pages, off.header.image_pages, off.header.images, off.header.images_withheld, off.header.status], [[2], undefined, 0, 'kind_off', 'complete'])
  assert.deepEqual(h.workers(), ['pdf'], 'the text job only')
  const since = h.quiet()
  const asked = await pdf.open({ pages: '2' })
  assert.deepEqual([asked.header.images, asked.header.images_withheld], [0, 'kind_off'])
  assert.deepEqual(since(), { fetches: 0, opens: 0, rows: 0 }, 'from the text cache')
  // Back on, the same call is not answered from a kept result: it gets its image.
  h.status.media_off = []
  const on = await pdf.open()
  assert.deepEqual([on.header.image_pages, on.images.length, on.header.images_withheld], [[2], 1, undefined])
  assert.deepEqual(h.workers(), ['pdf', 'pdf'], 'the images job of an open whose text was cached')
  // Turned off while the images job runs: the job is killed and the call answers media_not_allowed.
  const slow = h.attachment({ type: 'document', mimetype: 'application/pdf', plaintext: withScenario(PDF_MAGIC, { pages, raster: [2], images_sleep_ms: 5000 }) })
  const waiting = slow.open()
  while (h.jobs.length < 4) await new Promise(resolve => setTimeout(resolve, 20))
  await new Promise(resolve => setTimeout(resolve, 200))
  h.service.narrow(id, ['image'])
  await assert.rejects(waiting, refusedWith('media_not_allowed'))
  while (h.service.scheduler.running()) await new Promise(resolve => setTimeout(resolve, 20))
  assert.deepEqual(h.events().filter(entry => entry.event === 'media_job_killed').map(entry => entry.code), ['media_off'])
})

test('office, zip and plain text: rendered text, char cursors from the cache, kinds decided by the worker, and the caps', async t => {
  const h = await harness(t)
  const sheet = h.attachment({ type: 'document', plaintext: withScenario(ZIP_MAGIC, { office: { sniffed: 'xlsx', total_sheets: 60, sheets: [{ name: 'Q"1\u0001', rows: 2, total_rows: 9000, csv: 'a,b\n1,2\n' }, { name: 'Empty', rows: 0, total_rows: 0 }] } }) })
  const workbook = await sheet.open()
  assert.equal(workbook.body, '--- sheet "Q1" (rows 1-2 of 9000) ---\na,b\n1,2\n\n--- sheet "Empty" (empty) ---\n\n')
  assert.deepEqual([workbook.header.sniffed, workbook.header.sheets, workbook.header.truncated, workbook.header.next_cursor, workbook.header.part], ['xlsx', 60, ['sheet_cap', 'row_cap'], null, { unit: 'char', from: 0, to: workbook.body.length }])
  const slides = h.attachment({ type: 'document', plaintext: withScenario(ZIP_MAGIC, { office: { sniffed: 'pptx', slides: ['First', 'Second'] } }) })
  assert.equal((await slides.open()).body, '--- slide 1 ---\nFirst\n--- slide 2 ---\nSecond\n')
  const names = Array.from({ length: 250 }, (_, n) => `folder/file-${n}.txt`)
  const zip = h.attachment({ type: 'document', plaintext: withScenario(ZIP_MAGIC, { office: { sniffed: 'zip', names } }) })
  const listing = await zip.open()
  assert.match(listing.body, /^entries \(200 of 250 listed\):\nfolder\/file-0\.txt\n/)
  assert.deepEqual([listing.header.entries, listing.header.truncated], [250, ['entry_cap']])
  // A long docx: parts of PART_MAX_CHARS, the next one from the text cache.
  const long = 'Clause. '.repeat(20_000)
  const docx = h.attachment({ type: 'document', plaintext: withScenario(ZIP_MAGIC, { office: { sniffed: 'docx', text: long } }) })
  const part = await docx.open()
  assert.deepEqual([part.header.part, part.header.next_cursor, part.body.length], [{ unit: 'char', from: 0, to: PART_MAX_CHARS }, `c${PART_MAX_CHARS}`, PART_MAX_CHARS])
  const since = h.quiet()
  const next = await docx.open({ cursor: `c${PART_MAX_CHARS}` })
  assert.equal(next.body, long.slice(PART_MAX_CHARS, 2 * PART_MAX_CHARS))
  assert.deepEqual(since(), { fetches: 0, opens: 0, rows: 0 })
  await h.media.open({ device_id: '018f3a2b-2222-7000-8000-00000000eeee', uid: docx.uid, cursor: `c${PART_MAX_CHARS}`, images: true }, docx.access)
  assert.equal(since().rows, 1, 'the text cache is the number\'s too')
  h.clock += 60_000
  for (const request of [{ cursor: 'p1' }, { pages: '1' }, { cursor: `c${long.length}` }]) await assert.rejects(docx.open(request), refusedWith('invalid_cursor'), JSON.stringify(request))
  // Plain text never reaches a worker.
  const killedBefore = h.events().length
  const csv = h.attachment({ type: 'document', mimetype: 'text/csv', plaintext: Buffer.from('﻿name,total\r\nAna,3\r\n') })
  const plain = await csv.open()
  assert.deepEqual([plain.body, plain.header.sniffed], ['name,total\nAna,3\n', 'text'])
  assert.deepEqual(h.events().slice(killedBefore).map(entry => entry.event), ['media_opened'])
  const binary = h.attachment({ type: 'document', mimetype: 'application/octet-stream', plaintext: Buffer.from('just bytes') })
  await assert.rejects(binary.open(), refusedWith('attachment_unsupported'))
  // Kinds: zip off lets office through and refuses a plain zip in the worker (kind_off); text off refuses text after the sniff.
  h.status.media_off = ['zip']
  const another = h.attachment({ type: 'document', plaintext: withScenario(ZIP_MAGIC, { office: { sniffed: 'zip', names: ['a'] } }) })
  await assert.rejects(another.open(), refusedWith('media_not_allowed'))
  const word = h.attachment({ type: 'document', plaintext: withScenario(ZIP_MAGIC, { office: { sniffed: 'docx', text: 'ok' } }) })
  assert.equal((await word.open()).body, 'ok')
  h.status.media_off = ['text']
  const note = h.attachment({ type: 'document', mimetype: 'text/plain', plaintext: Buffer.from('hello') })
  await assert.rejects(note.open(), refusedWith('media_not_allowed'))
  h.status.media_off = []
  const damaged = h.attachment({ type: 'document', plaintext: withScenario(ZIP_MAGIC, { error: { code: 'damaged' } }) })
  await assert.rejects(damaged.open(), refusedWith('parser_failed'))
})

test('a worker that breaks the protocol, runs out of time or crashes is parser_failed, logged by its kill code only', async t => {
  const h = await harness(t, { jailEnv: { FAKE_WALL_MS: '300' } })
  const bad = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { raw: Buffer.from([0, 0, 0, 1, 7, 0]).toString('base64'), exit: 0 }) })
  await assert.rejects(bad.open(), refusedWith('parser_failed'))
  const slow = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 5000 }) })
  await assert.rejects(slow.open(), refusedWith('parser_failed'))
  const crash = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { exit_code: 137 }) })
  await assert.rejects(crash.open(), refusedWith('parser_failed'))
  assert.deepEqual(h.events().filter(entry => entry.event === 'media_job_killed').map(entry => entry.code), ['bad_output', 'wall', 'oom'])
  assert.deepEqual(h.service.counts(), { opens: 0, queue: 0, killed: 3 })
  assert.deepEqual(h.service.counts(), { opens: 0, queue: 0, killed: 0 }, 'counts are since the last call')
})

test('wiping: a revocation kills the fetch or the job in flight and empties the caches; media off and a kind off do it for media only', async t => {
  // A call waits for its open (no host timeout here), so a wipe reaches a call still waiting.
  const h = await harness(t, { delay: (ms, signal) => new Promise(resolve => signal.addEventListener('abort', resolve)) })
  const id = h.record.connection_id
  const until = async condition => { while (!condition()) await new Promise(resolve => setTimeout(resolve, 20)) }
  const killed = () => h.events().filter(entry => entry.event === 'media_job_killed').map(entry => entry.code)
  // Caches first: a result and a text entry.
  const photo = h.attachment({ plaintext: withScenario(JPEG_MAGIC, {}) })
  await photo.open()
  const docx = h.attachment({ type: 'document', plaintext: withScenario(ZIP_MAGIC, { office: { sniffed: 'docx', text: 'kept' } }) })
  await docx.open()
  assert.ok(h.service.caches.bytes(id) > 0)
  // During a job: the waiting call answers media_not_allowed, the job dies on SIGTERM, nothing is cached.
  const slow = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 5000 }) })
  const waiting = slow.open()
  await new Promise(resolve => setTimeout(resolve, 400))
  const started = Date.now()
  h.service.wipe(id)
  await assert.rejects(waiting, refusedWith('media_not_allowed'))
  assert.equal(h.service.caches.bytes(id), 0)
  await until(() => !h.service.scheduler.running())
  assert.ok(Date.now() - started < 4000, 'the job died on SIGTERM')
  assert.deepEqual(killed(), ['revoked'])
  // During a fetch: the body stalls until the wipe aborts it.
  const stalled = h.attachment({ plaintext: withScenario(JPEG_MAGIC, {}) })
  let aborted = false
  h.objects.get(stalled.uid).fetch = init => new Response(new ReadableStream({ start(controller) {
    controller.enqueue(new Uint8Array(16))
    init.signal.addEventListener('abort', () => { aborted = true; controller.error(new Error('aborted')) })
  } }), { status: 200, headers: { 'content-length': String(h.objects.get(stalled.uid).object.length) } })
  const fetching = stalled.open()
  await until(() => h.fetches.some(item => item.url.endsWith(stalled.uid)))
  h.service.wipe(id)
  await assert.rejects(fetching, refusedWith('media_not_allowed'))
  await until(() => aborted)
  await until(() => !h.service.scheduler.running())
  // A kind switched off kills that kind's open, with its own code, and drops its cache entries; the others stay.
  const again = h.attachment({ plaintext: withScenario(JPEG_MAGIC, { sleep_ms: 5000 }) })
  const imaging = again.open()
  await new Promise(resolve => setTimeout(resolve, 400))
  h.service.narrow(id, ['image'])
  await assert.rejects(imaging, refusedWith('media_not_allowed'))
  await until(() => !h.service.scheduler.running())
  assert.deepEqual(killed(), ['revoked', 'media_off'])
  h.service.narrow(id, [])
  const kept = h.attachment({ type: 'document', plaintext: withScenario(ZIP_MAGIC, { office: { sniffed: 'docx', text: 'stays' } }) })
  await kept.open()
  const pdf = h.attachment({ type: 'document', plaintext: withScenario(PDF_MAGIC, { pages: ['words words words words words words words words words words.'] }) })
  await pdf.open()
  h.service.narrow(id, ['pdf'])
  assert.ok(h.service.caches.text.get(id, `${device}|${kept.uid}`), 'the office text stays')
  assert.equal(h.service.caches.text.get(id, `${device}|${pdf.uid}`), undefined, 'the pdf text goes')
  assert.equal(h.media.why(pdf.row), null, 'a document\'s kind is known only after the sniff')
  assert.equal(h.media.why(photo.row), null)
  h.service.narrow(id, ['image'])
  assert.equal(h.media.why(photo.row), 'kind_off')
  // media: false in a status answer: media only, and nothing left.
  h.service.wipe(id, 'media_off')
  assert.equal(h.service.caches.bytes(id), 0)
})
