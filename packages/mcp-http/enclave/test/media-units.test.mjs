// Attachments stage A1, the reader's own parts (docs/mcp-enclave.md §16.5 to
// §16.10): streamed decryption against Go's vectors and every tampering, the
// sniff and the plain-text decoder, the hand-read image headers, the gate's
// order, the caches' bounds, the budgets, padding and media-jail's boot check.
// No worker runs here (media-worker.test.mjs, media-service.test.mjs).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createStatusCheck, STATUS_TTL_MS } from '../../verifier.mjs'
import { CONSOLE_URL, READER_CAPABILITIES, READER_VERSION } from '../constants.mjs'
import { createMemSampler } from '../health.mjs'
import { createCaches, sizeOf } from '../media/cache.mjs'
import { checkRow, hostOf, knownKinds, parseRequest, whyNot } from '../media/gate.mjs'
import { checkJail, CONTROLLERS_FILE, jailArgs, jobHeader } from '../media/jail.mjs'
import { createBudgets, createScheduler, retryAfter } from '../media/jobs.mjs'
import { paddedLength, padResponse } from '../media/pad.mjs'
import * as policy from '../media/policy.mjs'
import { charPart, factsOf, finish, pageBlocks, pdfPart, pdfWindow, pending } from '../media/result.mjs'
import { messageURL } from '../provider.mjs'
import { JOBS } from '../media/service.mjs'
import { cleanText, decodeText, sniff } from '../media/sniff.mjs'
import { jpegInfo, pngInfo } from '../media/validate-output.mjs'
import { createMediaStream, objectLength } from '../media/wamedia-stream.mjs'
import { encryptMedia, fakeJailSpawn, goVectors, jpeg, LABELS, newMediaKey, png, sha256 } from './media-fixtures.mjs'

const b64 = value => Buffer.from(value, 'base64')
/** Decrypts `object` in chunks of `size`; the plaintext as a copy, or the thrown error. */
function decrypt(object, mediaKey, label, { size = 7, hash = sha256(object), length = object.length } = {}) {
  const stream = createMediaStream({ mediaKey: new Uint8Array(mediaKey), label, length })
  // Buffers and plain Uint8Arrays (what a web stream yields) alike.
  for (let offset = 0; offset < object.length; offset += size) stream.update((offset / size) % 2 ? new Uint8Array(object.subarray(offset, offset + size)) : Buffer.from(object.subarray(offset, offset + size)))
  try { return Buffer.from(stream.finish(new Uint8Array(hash))) } finally { stream.wipe() }
}
const tampered = { code: 'attachment_tampered' }

test('decryption: every Go vector, for every label, in any chunking; the encryptor the tests use matches Go', () => {
  const labels = new Set()
  for (const vector of goVectors) {
    const key = b64(vector.media_key), enc = b64(vector.enc), plain = b64(vector.plaintext)
    labels.add(vector.type)
    for (const size of [1, 7, 16, 4096, enc.length]) assert.deepEqual(decrypt(enc, key, LABELS[vector.type], { size }), plain, `${vector.type} ${vector.note ?? ''} in ${size}-byte chunks`)
    assert.deepEqual(encryptMedia(plain, key, LABELS[vector.type]), enc, `${vector.type}: encryptMedia is Go's scheme`)
  }
  assert.deepEqual([...labels].sort(), ['audio', 'document', 'image', 'ptt', 'ptv', 'sticker', 'video'])
  assert.deepEqual(Object.fromEntries(Object.entries(policy.MEDIA_TYPES).map(([type, entry]) => [type, entry.label])), LABELS)
})

test('decryption refuses a bad MAC, a bad hash, every truncation, the wrong label, a bad length, bad padding and a 31-byte key, and zeroes the buffer', () => {
  const key = newMediaKey(), plain = Buffer.from('an attachment whose bytes matter, twice over.'), label = LABELS.document
  const object = encryptMedia(plain, key, label)
  assert.deepEqual(decrypt(object, key, label), plain)
  const flipped = (at, bytes = object) => { const copy = Buffer.from(bytes); copy[at] ^= 1; return copy }
  // The MAC's own bytes, and the ciphertext under it (the hash is recomputed so only the MAC can catch it).
  for (const at of [object.length - 1, object.length - 10, 0, 17]) assert.throws(() => decrypt(flipped(at), key, label, { hash: sha256(flipped(at)) }), tampered, `byte ${at}`)
  assert.throws(() => decrypt(object, key, label, { hash: sha256(Buffer.from('other')) }), tampered, 'the row\'s hash')
  assert.throws(() => decrypt(object, key, label, { hash: sha256(object).subarray(0, 31) }), tampered, 'a 31-byte hash')
  assert.throws(() => decrypt(object, key, LABELS.image), tampered, 'the wrong label')
  // Truncated at every boundary: declared at the full length, the stream ends short.
  for (let cut = 0; cut < object.length; cut++) {
    assert.throws(() => decrypt(object.subarray(0, cut), key, label, { length: object.length, hash: sha256(object) }), tampered, `cut at ${cut}`)
  }
  // A length no object has, and one longer than declared.
  for (const length of [0, 25, 27, object.length - 1, object.length + 1]) assert.equal(objectLength(length), length === 26)
  assert.throws(() => createMediaStream({ mediaKey: new Uint8Array(key), label, length: object.length - 1 }), tampered)
  assert.throws(() => decrypt(Buffer.concat([object, Buffer.alloc(1)]), key, label, { length: object.length }), tampered, 'a byte past the length')
  // Padding that is wrong while the MAC and hash are right.
  for (const padding of [Buffer.alloc(3, 0), Buffer.alloc(3, 17), Buffer.from([2, 3, 3])]) {
    const bad = encryptMedia(Buffer.from('thirteen byte'), key, label, { padding })
    assert.throws(() => decrypt(bad, key, label), tampered, `padding ${padding.toString('hex')}`)
  }
  assert.throws(() => createMediaStream({ mediaKey: new Uint8Array(31), label, length: object.length }), tampered, 'a 31-byte media key')
  // The plaintext buffer is zeroed on a failure, and by wipe() after a success.
  const stream = createMediaStream({ mediaKey: new Uint8Array(key), label, length: object.length })
  stream.update(Buffer.from(object))
  const view = stream.finish(new Uint8Array(sha256(object)))
  assert.deepEqual(Buffer.from(view), plain)
  stream.wipe()
  assert.equal(view.every(byte => byte === 0), true)
  const failing = createMediaStream({ mediaKey: new Uint8Array(key), label, length: object.length })
  const chunk = flipped(object.length - 1)
  failing.update(chunk)
  assert.equal(chunk.every(byte => byte === 0), true, 'each chunk is zeroed after use')
  assert.throws(() => failing.finish(new Uint8Array(sha256(object))), tampered)
})

test('sniff: magic bytes decide, never the mimetype, except the plain-text rule', () => {
  const cases = [
    [[0xff, 0xd8, 0xff, 0xe0], 'jpeg', 'image'], [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0], 'png', 'image'],
    [Buffer.from('GIF89a..'), 'gif', 'image'], [Buffer.from('GIF87a..'), 'gif', 'image'], [Buffer.from('RIFF\u0000\u0000\u0000\u0000WEBPVP8 '), 'webp', 'image'],
    [Buffer.from('%PDF-1.4'), 'pdf', 'pdf'], [Buffer.concat([Buffer.alloc(1000, 0x20), Buffer.from('%PDF-1.7')]), 'pdf', 'pdf'],
    [[0x50, 0x4b, 0x03, 0x04], 'zip', 'office'], [[0x50, 0x4b, 0x05, 0x06], 'zip', 'office'], [[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], 'cfb', 'office'],
  ]
  for (const [bytes, sniffed, kind] of cases) assert.deepEqual(sniff(Buffer.from(bytes), 'text/plain'), { sniffed, kind }, sniffed)
  assert.equal(sniff(Buffer.concat([Buffer.alloc(1020, 0x20), Buffer.from('%PDF-1.7')]), 'application/pdf'), null, '%PDF- past the first 1,024 bytes')
  assert.deepEqual(sniff(Buffer.from('a,b\n1,2\n'), 'text/csv; charset=utf-8'), { sniffed: 'text', kind: 'text' })
  assert.deepEqual(sniff(Buffer.from('{"a":1}'), 'Application/JSON'), { sniffed: 'text', kind: 'text' })
  assert.equal(sniff(Buffer.from('plain words'), 'application/octet-stream'), null)
  assert.equal(sniff(Buffer.from('plain\u0000words'), 'text/plain'), null, 'a NUL in the first 8 KiB')
  assert.deepEqual(sniff(Buffer.concat([Buffer.alloc(8192, 0x41), Buffer.from([0])]), 'text/plain'), { sniffed: 'text', kind: 'text' }, 'a NUL past them')
  assert.equal(sniff(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>'), 'image/svg+xml'), null)
  assert.equal(sniff(Buffer.from('\u0000\u0000\u0000\u0018ftypheic'), 'image/heic'), null)
  assert.deepEqual(sniff(new Uint8Array([0xff, 0xd8, 0xff, 0xdb]), null), { sniffed: 'jpeg', kind: 'image' }, 'a Uint8Array preview')
})

test('plain text: BOMs, UTF-16 both ways, windows-1252 fallback, the byte cap on a character boundary, and control characters', () => {
  assert.deepEqual(decodeText(Buffer.from('﻿olá\r\nmundo\rfim', 'utf8')), { text: 'olá\nmundo\nfim', cut: false })
  const le = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('ação 😀', 'utf16le')])
  assert.deepEqual(decodeText(le), { text: 'ação 😀', cut: false })
  const beBody = Buffer.from('ação', 'utf16le'); for (let i = 0; i < beBody.length; i += 2) [beBody[i], beBody[i + 1]] = [beBody[i + 1], beBody[i]]
  assert.deepEqual(decodeText(Buffer.concat([Buffer.from([0xfe, 0xff]), beBody])), { text: 'ação', cut: false })
  assert.deepEqual(decodeText(Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x20, 0x80, 0x20, 0x81, 0x9d])), { text: 'café € ', cut: false }, 'windows-1252, its undefined bytes dropped as C1')
  assert.deepEqual(decodeText(Buffer.from('tab\tbell\u0007del\u007fc1\u0085end')), { text: 'tab\tbelldelc1end', cut: false })
  // The cap: never half a character.
  assert.deepEqual(decodeText(Buffer.from('aé', 'utf8'), 2), { text: 'a', cut: true })
  assert.deepEqual(decodeText(Buffer.from('ab😀', 'utf8'), 5), { text: 'ab', cut: true })
  assert.deepEqual(decodeText(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('a😀', 'utf16le')]), 4), { text: 'a', cut: true })
  assert.deepEqual(decodeText(Buffer.from('abc'), 3), { text: 'abc', cut: false })
  assert.equal(cleanText('a\r\nb\rc\u0000d\u009fe f'), 'a\nb\ncd' + 'e f')
})

test('image headers read by hand: sizes, and no EXIF, XMP, IPTC, COM or PNG text chunks', () => {
  assert.deepEqual(jpegInfo(jpeg({ width: 1568, height: 900 })), { height: 900, width: 1568 })
  assert.deepEqual(jpegInfo(jpeg({ width: 10, height: 20, sof: 0xc2 })), { height: 20, width: 10 }, 'progressive')
  assert.equal(jpegInfo(jpeg({ app1: true })), null, 'APP1')
  assert.equal(jpegInfo(jpeg({ com: true })), null, 'COM')
  assert.equal(jpegInfo(jpeg({ sof: 0xc5 })), null, 'no SOF0 to SOF3 before the scan')
  assert.equal(jpegInfo(jpeg().subarray(0, 40)), null, 'truncated before the scan')
  assert.equal(jpegInfo(png()), null)
  assert.deepEqual(pngInfo(png({ width: 512, height: 300 })), { width: 512, height: 300 })
  for (const type of ['eXIf', 'tEXt', 'iTXt', 'zTXt', 'tIME']) assert.equal(pngInfo(png({ chunks: [[type, 'x']] })), null, type)
  assert.deepEqual(pngInfo(png({ chunks: [['PLTE', Buffer.alloc(6)]] })), { width: 64, height: 64 }, 'a palette PNG')
  assert.equal(pngInfo(jpeg()), null)
  assert.equal(pngInfo(png().subarray(0, 40)), null)
})

test('gate: the request shape, then the row checks in §16.5\'s order, and get_message\'s why in §16.7\'s', () => {
  assert.deepEqual(parseRequest({ uid: 'u', pages: '3-6' }).pages, { from: 3, to: 6 })
  assert.deepEqual(parseRequest({ uid: 'u', pages: '7' }).pages, { from: 7, to: 7 })
  assert.deepEqual(parseRequest({ uid: 'u', cursor: 'p12' }).cursor, { unit: 'page', at: 12 })
  assert.deepEqual(parseRequest({ uid: 'u', cursor: 'c0' }).cursor, { unit: 'char', at: 0 })
  for (const bad of [{ cursor: 'p2', pages: '2' }, { pages: '6-3' }, { pages: '1-5' }, { cursor: 't3' }]) assert.throws(() => parseRequest({ uid: 'u', ...bad }), { code: 'invalid_cursor' }, JSON.stringify(bad))
  const hash = Buffer.alloc(32, 1).toString('base64')
  const row = (media, extra = {}) => ({ uid: 'u', ...extra, media: { media_type: 'document', mimetype: 'application/pdf', download_status: 'done', media_key_sealed: 'sealed', file_enc_sha256: hash, file_length: 1000, ...media } })
  const request = parseRequest({ uid: 'u' })
  const refused = (value, code, off = [], req = request) => assert.throws(() => checkRow(value, req, off), error => error.code === code && error.facts?.media_type === value.media.media_type, code)
  refused(row({}, { view_once: true }), 'view_once_excluded')
  refused(row({ media_type: 'contact' }), 'attachment_unsupported')
  refused(row({ media_type: 'audio' }), 'transcription_unavailable')
  refused(row({ media_type: 'ptt', download_status: 'gone' }), 'transcription_unavailable')
  refused(row({ media_type: 'image' }), 'invalid_cursor', [], parseRequest({ uid: 'u', cursor: 'c0' }))
  refused(row({ media_type: 'ptv' }), 'invalid_cursor', [], parseRequest({ uid: 'u', pages: '1' }))
  refused(row({ media_type: 'sticker' }), 'media_not_allowed', ['image'])
  refused(row({ media_type: 'video' }), 'media_not_allowed', ['image'])
  refused(row({}), 'media_not_allowed', ['pdf', 'office', 'text', 'zip', 'image'])
  assert.equal(checkRow(row({}), request, ['pdf', 'office', 'text', 'zip']).family, 'document', 'a document is checked after the sniff unless every kind is off')
  for (const status of ['pending', 'downloading', 'failed']) refused(row({ download_status: status }), 'attachment_pending')
  refused(row({ download_status: 'gone' }), 'attachment_expired')
  refused(row({ download_status: 'odd' }), 'read_failed')
  refused(row({ media_key_sealed: undefined }), 'attachment_unverifiable')
  refused(row({ file_enc_sha256: undefined }), 'attachment_unverifiable')
  refused(row({ file_enc_sha256: Buffer.alloc(31).toString('base64') }), 'attachment_unverifiable')
  refused(row({ file_enc_sha256: Buffer.alloc(32).toString('base64url') + 'A' }), 'attachment_unverifiable')
  assert.throws(() => checkRow(row({ file_length: policy.CAP_BYTES.document + 1 }), request, []), error => error.code === 'attachment_too_large' &&
    error.facts.size === policy.CAP_BYTES.document + 1 && error.facts.cap === policy.CAP_BYTES.document && error.facts.family === 'document')
  assert.throws(() => checkRow(row({ media_type: 'image', file_length: policy.CAP_BYTES.image + 1 }), request, []), error => error.facts.family === 'image')
  const plan = checkRow(row({}), request, [])
  assert.deepEqual([plan.family, plan.label, plan.preview, plan.encSHA256.length], ['document', 'WhatsApp Document Keys', false, 32])
  // A video never fetches: its preview, whatever its download state, hash or size.
  const video = checkRow(row({ media_type: 'video', download_status: 'gone', media_key_sealed: undefined, file_length: 10 ** 10, thumb_sealed: 'x' }), request, [])
  assert.deepEqual([video.preview, video.hasPreview, video.kind], [true, true, 'image'])
  assert.equal(checkRow(row({ media_type: 'ptv' }), request, []).hasPreview, false)

  assert.equal(whyNot(row({}), []), null)
  assert.equal(whyNot(row({ media_type: 'audio' }, { view_once: true }), []), 'view_once')
  assert.equal(whyNot(row({ media_type: 'poll' }), []), 'unsupported')
  assert.equal(whyNot(row({ media_type: 'ptt' }), []), 'not_transcribed')
  assert.equal(whyNot(row({ download_status: 'gone', media_key_sealed: undefined }), []), 'expired')
  assert.equal(whyNot(row({ download_status: 'pending', media_key_sealed: undefined }), []), 'pending')
  assert.equal(whyNot(row({ media_key_sealed: undefined, file_length: 10 ** 10 }), []), 'unverifiable')
  assert.equal(whyNot(row({ file_length: 10 ** 10 }), ['pdf']), 'too_large')
  assert.equal(whyNot(row({ media_type: 'image' }), ['image']), 'kind_off')
  assert.equal(whyNot(row({ media_type: 'video', download_status: 'gone' }), []), null)
  assert.equal(whyNot(row({ media_type: 'video' }), ['image']), 'kind_off')
  assert.equal(whyNot({ uid: 'u' }, []), null)

  assert.deepEqual(knownKinds(['zip', 'heic', 'pdf', 'zip', 3]), ['pdf', 'zip'])
  assert.deepEqual(knownKinds(null), [])
  assert.deepEqual(['chatgpt.com', 'claude.ai', 'example.com', undefined].map(hostOf), ['chatgpt.com', 'claude.ai', 'default', 'default'])
})

test('caches: 2 bytes a code unit plus Buffers, per-connection and enclave bounds, the connection\'s own entries first, TTLs, and zeroing', () => {
  let clock = 0
  const caches = createCaches({ now: () => clock, connectionBytes: 1000, enclaveBytes: 1500 })
  assert.equal(sizeOf('abcd'), 8)
  assert.equal(sizeOf({ a: Buffer.alloc(10) }), 12)
  const text = (chars, kind = 'office') => ({ kind, facts: {}, text: 'x'.repeat(chars) })
  assert.equal(caches.text.set('A', 'u1', text(200)), true)
  assert.equal(caches.text.set('A', 'u2', text(200)), true)
  assert.equal(caches.bytes('A') > 800, true)
  caches.text.get('A', 'u1')
  // A's own bound: u2 (least recently used) goes, u1 stays.
  caches.text.set('A', 'u3', text(200))
  assert.equal(caches.text.get('A', 'u2'), undefined)
  assert.ok(caches.text.get('A', 'u1') && caches.text.get('A', 'u3'))
  // The enclave's bound: B's entry evicts B's own first, then A's least recently used.
  caches.text.set('B', 'v1', text(200))
  caches.text.set('B', 'v2', text(200))
  assert.ok(caches.bytes() <= 1500)
  assert.equal(caches.text.get('B', 'v2') !== undefined, true)
  assert.equal(caches.text.set('A', 'huge', text(600)), false, 'an entry over the connection bound is not kept')
  // TTLs from the write.
  clock += policy.TEXT_TTL_MS
  assert.equal(caches.text.get('B', 'v2'), undefined)
  const image = { mimeType: 'image/jpeg', data: Buffer.alloc(100, 7) }
  caches.result.set('C', 'k', { outcome: { result: { header: {}, body: '', images: [image] } }, kinds: ['image'] })
  assert.ok(caches.result.get('C', 'k'))
  clock += policy.RESULT_TTL_MS - 1
  assert.ok(caches.result.get('C', 'k'))
  clock += 1
  assert.equal(caches.result.get('C', 'k'), undefined)
  assert.equal(image.data.every(byte => byte === 0), true, 'an image Buffer is zeroed when its entry leaves')
  // Kinds and connections.
  caches.text.set('D', 'pdf', text(10, 'pdf')); caches.text.set('D', 'zip', text(10, 'zip')); caches.text.set('E', 'pdf', text(10, 'pdf'))
  caches.dropKinds('D', ['pdf'])
  assert.deepEqual([caches.text.get('D', 'pdf'), Boolean(caches.text.get('D', 'zip')), Boolean(caches.text.get('E', 'pdf'))], [undefined, true, true])
  caches.drop('D')
  assert.equal(caches.bytes('D'), 0)
})

test('budgets, slot and queue: retry_after_s values, opens a minute, bytes an hour, FIFO with a bounded queue', async () => {
  assert.deepEqual([0, 1, 4_001, 5_000, 5_001, 19_000, 39_500, 61_000, 3_600_000].map(retryAfter), [5, 5, 5, 5, 10, 20, 40, 60, 60])
  let clock = 0
  const budgets = createBudgets({ now: () => clock })
  for (let n = 0; n < policy.OPENS_PER_MINUTE; n++) { assert.equal(budgets.opensWait('c'), 0); budgets.admit('c'); clock += 1000 }
  assert.equal(budgets.opensWait('c'), 50_000)
  assert.equal(budgets.opensWait('other'), 0)
  clock += 50_000
  assert.equal(budgets.opensWait('c'), 0)
  budgets.charge('c', policy.BYTES_PER_HOUR - 100)
  assert.equal(budgets.bytesWait('c', 100), 0)
  assert.equal(budgets.bytesWait('c', 101), 3_600_000)
  clock += 3_600_000
  assert.equal(budgets.bytesWait('c', 101), 0)
  budgets.forget('c')

  const scheduler = createScheduler()
  const gates = [], order = []
  const entry = n => ({ n })
  const task = n => () => new Promise(resolve => { order.push(n); gates[n] = resolve })
  const entries = Array.from({ length: 6 }, (_, n) => entry(n))
  assert.equal(scheduler.room(), policy.SLOTS + policy.QUEUE)
  assert.deepEqual(entries.map((item, n) => [scheduler.admit(item, task(n)), scheduler.room()]), [[true, 4], [true, 3], [true, 2], [true, 1], [true, 0], [false, 0]], 'one runs, four wait, the sixth is refused')
  await new Promise(resolve => setImmediate(resolve))
  assert.deepEqual([scheduler.position(entries[0]), scheduler.position(entries[1]), scheduler.position(entries[4]), scheduler.position(entries[5])], ['running', 0, 3, null])
  assert.equal(scheduler.remove(entries[2]), true)
  gates[0]()
  await new Promise(resolve => setImmediate(resolve))
  assert.deepEqual(order, [0, 1])
  assert.equal(scheduler.queued(), 2)

  // `left` is told once the entry's place is free, after the next one started: a connection's next open takes the place it held.
  const handed = createScheduler({ slots: 1, queue: 1 })
  const told = [], release = []
  const hold = n => () => new Promise(resolve => { release[n] = resolve })
  const [a, b, c] = [{}, {}, {}]
  assert.equal(handed.admit(a, hold(0), () => told.push(['a', handed.running(), handed.queued(), handed.admit(c, hold(2))])), true)
  assert.equal(handed.admit(b, hold(1), () => { throw new Error('a left that throws is contained') }), true)
  await new Promise(resolve => setImmediate(resolve))
  release[0]()
  await new Promise(resolve => setImmediate(resolve))
  assert.deepEqual(told, [['a', 1, 0, true]], 'b runs, the queue is empty, and c gets the place a held')
  assert.equal(handed.position(c), 0)
  release[1]()
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(handed.position(c), 'running')
})

test('the console link (§16.7): the contract\'s three parameters, UUIDs only, in lower case; every answer about the message carries it', () => {
  const tenant = '018F3A2B-1111-7000-8000-00000000AAAA', device = '018f3a2b-2222-7000-8000-00000000dddd', uid = '018f3a2b-3333-7000-8000-00000000cccc'
  const link = messageURL(CONSOLE_URL, tenant, device, uid)
  assert.equal(link, `https://app.wappie.thehappie.co/console?workspace=${tenant.toLowerCase()}&open_device=${device}&open_message=${uid}`)
  const url = new URL(link)
  assert.deepEqual([url.origin + url.pathname, [...url.searchParams.keys()]], [CONSOLE_URL, ['workspace', 'open_device', 'open_message']])
  for (const [a, b, c] of [[undefined, device, uid], [tenant, 'x', uid], [tenant, device, `${uid}&mcp_renew=1`], [tenant, device, 42]]) assert.equal(messageURL(CONSOLE_URL, a, b, c), null)
  const row = { uid, media: { media_type: 'ptt', file_length: 9 } }
  assert.throws(() => checkRow(row, parseRequest({ uid }), [], link), error => error.code === 'transcription_unavailable' && error.facts.open_url === link)
  assert.equal(finish(factsOf(row, null, { sniffed: 'jpeg' }, link)).header.open_url, link)
  assert.deepEqual(Object.keys(finish(factsOf(row, null, { sniffed: 'jpeg' }, link)).header).at(-1), 'open_url', 'last of the reader\'s fields')
  assert.deepEqual(pending(uid, 'image', 10, link).header, { uid, media_type: 'image', status: 'pending', retry_after_s: 10, open_url: link })
  assert.equal(factsOf(row, null, {}).open_url, undefined)
})

test('paging: char parts never split a surrogate pair; page parts are whole blocks within the window', () => {
  const text = 'a'.repeat(policy.PART_MAX_CHARS - 1) + '😀' + 'b'
  const first = charPart(text, undefined)
  assert.equal(first.body.length, policy.PART_MAX_CHARS - 1)
  assert.equal(first.next, `c${policy.PART_MAX_CHARS - 1}`)
  const second = charPart(text, { unit: 'char', at: policy.PART_MAX_CHARS - 1 })
  assert.equal(second.body, '😀b')
  assert.equal(second.next, null)
  assert.deepEqual(charPart('', undefined), { body: '', part: { unit: 'char', from: 0, to: 0 }, next: null })
  for (const cursor of [{ unit: 'char', at: text.length }, { unit: 'page', at: 1 }]) assert.throws(() => charPart(text, cursor), { code: 'invalid_cursor' })
  assert.throws(() => charPart('', { unit: 'char', at: 1 }), { code: 'invalid_cursor' })

  const texts = ['x'.repeat(30_000), '', 'y'.repeat(29_990), 'z'.repeat(70_000)]
  const blocks = pageBlocks(1, 4, page => texts[page - 1])
  assert.deepEqual([blocks.from, blocks.to, blocks.tooLong], [1, 2, false])
  assert.match(blocks.body, /^--- page 1 ---\nx+\n\n--- page 2 \(scanned\) ---\n\n$/)
  const long = pageBlocks(4, 4, page => texts[page - 1])
  assert.deepEqual([long.to, long.tooLong, long.body.length], [4, true, policy.PART_MAX_CHARS])
  const window = pdfWindow({ sections: texts.map((value, index) => ({ section: { page: index + 1 }, text: value })), cut: false }, 1, 0)
  const part = pdfPart(window, 2, 2500, true)
  assert.deepEqual([part.part, part.next, part.scannedPages, part.wanted], [{ unit: 'page', from: 2, to: 3 }, 'p4', [2], [2]])
  assert.equal(pdfPart(window, 4, 4, false).next, null)
  assert.deepEqual(pdfWindow({ sections: [{ section: { page: 5 }, text: 'a' }, { section: { page: 6 }, text: 'b' }], cut: true }, 5, 0).to, 5, 'a cut window ends at its last complete page')
  const scannedMany = pdfWindow({ sections: Array.from({ length: 8 }, (_, index) => ({ section: { page: index + 1 }, text: '' })), cut: false }, 1, 0)
  const many = pdfPart(scannedMany, 1, 8, true)
  assert.deepEqual([many.wanted, many.suggest], [[1, 2, 3, 4], '5-8'])
})

test('padding: every bucket, beyond the last in steps of 512 KiB, Content-Length set, event streams with a comment line, bodiless ones untouched', async () => {
  for (const [length, padded] of [[0, 16_384], [1, 16_384], [16_384, 16_384], [16_385, 32_768], [600_000, 1_048_576], [1_048_577, 1_572_864], [2_097_152, 2_097_152], [2_097_153, 2_621_440]]) {
    assert.equal(paddedLength(length), padded, String(length))
  }
  for (const bucket of policy.PAD_BUCKETS) assert.equal(paddedLength(bucket - 1), bucket)
  const response = await padResponse(Response.json({ jsonrpc: '2.0', id: 1, result: { content: [] } }, { status: 200, headers: { 'x-kept': 'yes' } }))
  const body = Buffer.from(await response.arrayBuffer())
  assert.equal(body.length, 16_384)
  assert.equal(response.headers.get('content-length'), '16384')
  assert.equal(response.headers.get('x-kept'), 'yes')
  assert.deepEqual(JSON.parse(body.toString('utf8')), { jsonrpc: '2.0', id: 1, result: { content: [] } }, 'trailing spaces are still JSON')
  const empty = new Response(null, { status: 202 })
  assert.equal(await padResponse(empty), empty)
  // An event stream ends in a comment line, so its events read the same.
  const event = 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n'
  const stream = await padResponse(new Response(event, { headers: { 'content-type': 'text/event-stream' } }))
  const text = await stream.text()
  assert.equal(Buffer.byteLength(text), 16_384)
  assert.equal(text.startsWith(event + ':'), true)
  assert.equal(text.endsWith(' \n'), true)
  assert.deepEqual(text.split('\n').filter(line => line && !line.startsWith(':')), ['event: message', 'data: {"jsonrpc":"2.0","id":1,"result":{}}'])
  const tight = await (await padResponse(new Response('x'.repeat(16_383), { headers: { 'content-type': 'text/event-stream' } }))).text()
  assert.equal(tight.at(-1), '\n', 'one byte short: an empty line')
})

test('job headers and media-jail\'s command line are §16.11\'s, byte for byte', () => {
  // The worked example: a sticker job's 104-byte header.
  const sticker = jobHeader(JOBS.imageJob('sticker', 'webp'))
  assert.equal(sticker.readUInt32BE(0), 104)
  assert.equal(sticker.subarray(4).toString(), '{"v":1,"op":"sticker","format":"webp","limits":{"pixels":40000000,"long_edge":512,"image_bytes":102400}}')
  assert.deepEqual(JOBS.imageJob('photo', 'jpeg').limits, { pixels: 40_000_000, long_edge: 1568, image_bytes: 307_200 })
  assert.deepEqual(JOBS.pdfTextJob(301, 300), { v: 1, op: 'text', from: 301, count: 300, limits: { text_bytes: 4_194_304, image_pixels: 16_000_000 } })
  assert.equal(JOBS.pdfImagesJob([1, 2, 3, 4]).limits.image_bytes, 230_400)
  assert.equal(JOBS.pdfImagesJob([2]).limits.image_bytes, 307_200)
  assert.deepEqual(JOBS.officeJob(['office', 'zip']).limits, { text_bytes: 4_194_304, entries: 2000, inflated: 104_857_600, ratio: 100, listed: 200, sheets: 50, sheet_rows: 2000 })
  assert.deepEqual(jailArgs('pdf', '0123456789abcdef'), ['--worker', 'pdf', '--slot', 'light', '--id', '0123456789abcdef', '--mem-mb', '384', '--pids', '64', '--cpus', '0', '--wall-s', '20', '--tmp-mb', '16'])
  assert.match(jailArgs('image')[5], /^[0-9a-f]{16}$/)
  assert.deepEqual(policy.WORKERS, { image: { mem_mb: 256, wall_s: 10, pids: 64, tmp_mb: 16 }, pdf: { mem_mb: 384, wall_s: 20, pids: 64, tmp_mb: 16 }, office: { mem_mb: 384, wall_s: 15, pids: 64, tmp_mb: 16 } })
  assert.equal(Object.isFrozen(policy.WORKERS.pdf) && Object.isFrozen(policy.HOST_WAIT_MS) && Object.isFrozen(policy.MEDIA_TYPES.image), true)
})

test('the jail\'s boot check: controllers, then --self-check, then --table equal to WORKERS', async () => {
  const readFile = text => async path => { assert.equal(path, CONTROLLERS_FILE); if (text === null) throw new Error('ENOENT'); return text }
  const calls = []
  assert.deepEqual(await checkJail({ spawn: fakeJailSpawn({}, calls), readFile: readFile('memory pids cpuset\n') }), { ok: true, cpuset: true })
  assert.deepEqual(calls.map(call => call.args), [['--self-check'], ['--table']])
  assert.deepEqual(calls.map(call => call.bin), [policy.JAIL_BIN, policy.JAIL_BIN])
  assert.deepEqual(await checkJail({ spawn: fakeJailSpawn(), readFile: readFile('memory pids\n') }), { ok: true, cpuset: false }, 'cpuset is never required (4.14)')
  for (const text of [null, '', 'cpuset memory\n', 'pids\n']) {
    assert.deepEqual(await checkJail({ spawn: fakeJailSpawn(), readFile: readFile(text) }), { ok: false, code: 'no_controllers' }, String(text))
  }
  assert.deepEqual(await checkJail({ spawn: fakeJailSpawn({ FAKE_SELF_CHECK: '1' }), readFile: readFile('memory pids') }), { ok: false, code: 'self_check_failed' })
  assert.deepEqual(await checkJail({ spawn: () => { throw new Error('ENOENT') }, readFile: readFile('memory pids') }), { ok: false, code: 'self_check_failed' }, 'no binary')
  for (const table of ['mismatch', 'extra', 'garbage']) {
    assert.deepEqual(await checkJail({ spawn: fakeJailSpawn({ FAKE_TABLE: table }), readFile: readFile('memory pids') }), { ok: false, code: 'table_mismatch' }, table)
  }
})

test('mediaStatus: the serve answer\'s media fields for 60 s, a fresh check past them or while a renewal waits, and false and [] unless serve', async () => {
  const id = '0199b3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b'
  let clock = 0, calls = 0, waiting = false, decision = 'serve'
  let reply = { status: 'active', expires_at: '2099-01-01T00:00:00Z', kind: 'content', service_user_id: 'x', media: true, media_off: ['pdf'] }
  const state = { connections: new Map([[id, { connection_id: id, kind: 'content', expires_at: '2099-01-01T00:00:00Z' }]]), wipeConnection: () => false, save: async () => {} }
  const check = createStatusCheck({ state, relay: { status: async () => { calls++; return reply } }, now: () => clock, content: { decide: async () => decision, pending: () => waiting } })
  assert.deepEqual(await check.mediaStatus(id), { answer: 'serve', media: true, media_off: ['pdf'] })
  assert.equal(calls, 1, 'no cached answer: a check')
  clock += STATUS_TTL_MS - 1
  reply = { ...reply, media: false, media_off: [] }
  assert.deepEqual(await check.mediaStatus(id), { answer: 'serve', media: true, media_off: ['pdf'] }, 'the cached answer serves for 60 s')
  assert.equal(calls, 1)
  clock += 1
  assert.deepEqual(await check.mediaStatus(id), { answer: 'serve', media: false, media_off: [] }, 'older than 60 s: asked again')
  assert.equal(calls, 2)
  waiting = true
  await check.mediaStatus(id)
  assert.equal(calls, 3, 'a staged renewal forces a check')
  waiting = false
  const { media: _media, media_off: _off, ...bare } = reply
  reply = bare
  clock += STATUS_TTL_MS
  assert.deepEqual(await check.mediaStatus(id), { answer: 'serve', media: false, media_off: [] }, 'missing fields are false and []')
  decision = 'reseal'
  reply = { ...bare, media: true, media_off: ['zip'] }
  clock += STATUS_TTL_MS
  assert.deepEqual(await check.mediaStatus(id), { answer: 'reseal', media: false, media_off: [] })
  assert.equal(await check(id), 'reseal', 'nothing but serve is cached')
})

test('the health line\'s memory minimum: sampled, the lowest of the window, rounded down to 64 MiB, then a new window', async () => {
  const values = [1_400_000, 900_123, 1_200_000]
  let index = 0
  const sampler = createMemSampler({ readFile: async path => { assert.equal(path, '/proc/meminfo'); return `MemTotal:  1572864 kB\nMemAvailable:  ${values[index++]} kB\n` } })
  for (let n = 0; n < 3; n++) await sampler.sample()
  assert.equal(sampler.take(), 832, '900,123 kB is 879 MiB, 832 after rounding down to 64')
  assert.equal(sampler.take(), undefined, 'a new window has no sample yet')
  const off = createMemSampler({ readFile: async () => { throw new Error('ENOENT') } })
  await off.sample()
  assert.equal(off.take(), undefined)
})

test('the release: reader 0.4.2 declares consent version 2 and media, as 0.4.0 and 0.4.1 did', () => {
  assert.equal(READER_VERSION, '0.4.2')
  assert.deepEqual(READER_CAPABILITIES, ['consent_v2', 'media'])
  assert.equal(Object.isFrozen(READER_CAPABILITIES), true)
})
