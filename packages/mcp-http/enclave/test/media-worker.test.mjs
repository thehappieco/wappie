// runWorker against scripted workers, no jail (docs/mcp-enclave.md §16.11):
// the stdin it writes, every output it accepts, every rule of "What MAIN
// checks" refusing its violation (the job is killed and nothing of it used),
// and every exit code mapped as the "Exit and outcome" table says.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { outcomeOf, runWorker } from '../media/jail.mjs'
import { FRAME_MAX, IMAGES_TOTAL_BYTES, JAIL_BIN } from '../media/policy.mjs'
import { JOBS } from '../media/service.mjs'
import { STDOUT_MAX } from '../media/validate-output.mjs'
import { frame, imageFrame, jpeg, png, scriptedSpawn } from './media-fixtures.mjs'

const HEADER = 1, TEXT = 2, SECTION = 3, ERROR = 8, DONE = 9
const input = Buffer.from('plaintext')
const jobs = {
  photo: JOBS.imageJob('photo', 'jpeg'), sticker: JOBS.imageJob('sticker', 'webp'), thumb: JOBS.imageJob('thumb', 'jpeg'),
  pdfText: JOBS.pdfTextJob(1, 3), pdfImages: JOBS.pdfImagesJob([2, 4]), office: JOBS.officeJob(['office', 'zip']), officeOnly: JOBS.officeJob(['office']),
}
const run = (worker, job, stdout, exit = 0, options = {}) => runWorker({ worker, job, input, spawn: scriptedSpawn({ stdout: Buffer.concat(stdout), exit, ...options }), ...options.run })
const done = frame(DONE)

test('stdin is u32 H, the job header, u32 N and the input, then EOF; media-jail gets §16.11\'s command line, an empty environment and no stderr', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wappie-worker-'))
  try {
    const calls = [], stdinFile = join(directory, 'stdin')
    const output = await runWorker({ worker: 'image', job: jobs.sticker, input, spawn: scriptedSpawn({ stdout: Buffer.concat([frame(HEADER, { animated: true }), imageFrame(0, png()), done]), stdinFile, calls }) })
    assert.equal(output.killed, null)
    assert.equal(output.exit, 0)
    assert.equal(output.header.animated, true)
    assert.equal(output.images[0].mimeType, 'image/png')
    const stdin = await readFile(stdinFile)
    const H = stdin.readUInt32BE(0)
    assert.deepEqual(JSON.parse(stdin.subarray(4, 4 + H).toString()), jobs.sticker)
    assert.equal(stdin.readUInt32BE(4 + H), input.length)
    assert.deepEqual(stdin.subarray(8 + H), input)
    assert.equal(calls[0].bin, JAIL_BIN)
    assert.deepEqual(calls[0].args.filter((_, index) => index !== 5), ['--worker', 'image', '--slot', 'light', '--id', '--mem-mb', '256', '--pids', '64', '--cpus', '0', '--wall-s', '10', '--tmp-mb', '16'])
    assert.deepEqual(calls[0].options.env, {})
    assert.deepEqual(calls[0].options.stdio, ['pipe', 'pipe', 'ignore'])
  } finally { await rm(directory, { recursive: true, force: true }) }
})

test('valid output of every worker and op is taken, text cleaned of controls', async () => {
  const photo = await run('image', jobs.photo, [frame(HEADER, { animated: false }), imageFrame(0, jpeg({ width: 1568, height: 1000 })), done])
  assert.deepEqual([photo.killed, photo.images.length, photo.images[0].width, photo.images[0].mimeType], [null, 1, 1568, 'image/jpeg'])
  const pdf = await run('pdf', jobs.pdfText, [frame(HEADER, { pages: 3 }), frame(SECTION, { page: 1 }), frame(TEXT, 'one\r\nline\u0007'), frame(SECTION, { page: 2 }), frame(SECTION, { page: 3 }), frame(TEXT, 'thr'), frame(TEXT, 'ee'), frame(DONE, { cut: true })])
  assert.equal(pdf.killed, null)
  assert.deepEqual(pdf.sections, [{ section: { page: 1 }, text: 'one\nline' }, { section: { page: 2 }, text: '' }, { section: { page: 3 }, text: 'three' }])
  assert.equal(pdf.cut, true)
  const images = await run('pdf', jobs.pdfImages, [frame(HEADER, { pages: 9 }), imageFrame(2, jpeg()), imageFrame(4, jpeg()), done])
  assert.deepEqual(images.images.map(image => image.page), [2, 4])
  const sheets = await run('office', jobs.office, [frame(HEADER, { sniffed: 'xlsx', sheets: 2 }), frame(SECTION, { sheet: 'Q\u00011', rows: 2, total_rows: 5000 }), frame(TEXT, 'a,b\n1,2\n'), frame(SECTION, { sheet: 'Empty', rows: 0, total_rows: 0 }), done])
  assert.deepEqual(sheets.sections.map(item => item.section.sheet), ['Q1', 'Empty'])
  const slides = await run('office', jobs.office, [frame(HEADER, { sniffed: 'pptx', slides: 3 }), frame(SECTION, { slide: 1 }), frame(TEXT, 'x'), frame(SECTION, { slide: 3 }), done])
  assert.equal(slides.killed, null)
  const docx = await run('office', jobs.office, [frame(HEADER, { sniffed: 'docx' }), frame(TEXT, 'para\n'), frame(TEXT, '| a | b |\n'), done])
  assert.deepEqual(docx.sections, [{ section: null, text: 'para\n| a | b |\n' }])
  const zip = await run('office', jobs.office, [frame(HEADER, { sniffed: 'zip', entries: 0 }), frame(TEXT, 'entries (0 of 0 listed):\n'), done])
  assert.equal(zip.killed, null)
  const refused = await run('office', jobs.office, [frame(ERROR, { code: 'encrypted' })], 2)
  assert.deepEqual([refused.killed, refused.error], [null, { code: 'encrypted' }])
  const late = await run('pdf', jobs.pdfText, [frame(HEADER, { pages: 1 }), frame(ERROR, { code: 'too_large', what: 'pixels' })], 2)
  assert.deepEqual(late.error, { code: 'too_large', what: 'pixels' })
})

test('every §16.11 check refuses its violation: the job is killed as bad_output and none of its output is kept', async () => {
  const big = n => 'x'.repeat(n)
  const header = { image: frame(HEADER, { animated: false }), pdf: frame(HEADER, { pages: 3 }) }
  const oversized = Buffer.alloc(5); oversized.writeUInt32BE(FRAME_MAX[TEXT] + 1); oversized[4] = TEXT
  const cases = [
    ['oversized frame prefix, before its payload', 'pdf', jobs.pdfText, [header.pdf, oversized]],
    ['unknown frame type', 'pdf', jobs.pdfText, [header.pdf, frame(5, 'x'), done]],
    ['a frame before HEADER', 'pdf', jobs.pdfText, [frame(SECTION, { page: 1 }), done]],
    ['a second HEADER', 'pdf', jobs.pdfText, [header.pdf, header.pdf, done]],
    ['HEADER with an unknown key', 'image', jobs.photo, [frame(HEADER, { animated: false, exif: 1 }), imageFrame(0, jpeg()), done]],
    ['HEADER not JSON', 'pdf', jobs.pdfText, [frame(HEADER, '{pages:1'), done]],
    ['pdf pages out of range', 'pdf', jobs.pdfText, [frame(HEADER, { pages: 0 }), done]],
    ['office kind not allowed', 'office', jobs.officeOnly, [frame(HEADER, { sniffed: 'zip', entries: 1 }), done]],
    ['office total of another kind', 'office', jobs.office, [frame(HEADER, { sniffed: 'docx', sheets: 1 }), done]],
    ['office total missing', 'office', jobs.office, [frame(HEADER, { sniffed: 'xlsx' }), done]],
    ['bad UTF-8', 'pdf', jobs.pdfText, [header.pdf, frame(SECTION, { page: 1 }), frame(TEXT, Buffer.from([0xc3, 0x28])), done]],
    ['a code point split across frames', 'pdf', jobs.pdfText, [header.pdf, frame(SECTION, { page: 1 }), frame(TEXT, Buffer.from([0xc3])), frame(TEXT, Buffer.from([0xa9])), done]],
    ['an empty TEXT', 'pdf', jobs.pdfText, [header.pdf, frame(SECTION, { page: 1 }), frame(TEXT, ''), done]],
    ['TEXT from the image worker', 'image', jobs.photo, [header.image, frame(TEXT, 'x'), done]],
    ['TEXT from a pdf images job', 'pdf', jobs.pdfImages, [header.pdf, frame(TEXT, 'x'), done]],
    ['TEXT before any page', 'pdf', jobs.pdfText, [header.pdf, frame(TEXT, 'x'), done]],
    ['TEXT over the job\'s text limit', 'pdf', { ...jobs.pdfText, limits: { ...jobs.pdfText.limits, text_bytes: 10 } }, [header.pdf, frame(SECTION, { page: 1 }), frame(TEXT, big(11)), done]],
    ['SECTION out of order', 'pdf', jobs.pdfText, [header.pdf, frame(SECTION, { page: 2 }), done]],
    ['SECTION repeated', 'pdf', jobs.pdfText, [header.pdf, frame(SECTION, { page: 1 }), frame(SECTION, { page: 1 }), done]],
    ['SECTION past the total', 'pdf', JOBS.pdfTextJob(1, 5), [frame(HEADER, { pages: 1 }), frame(SECTION, { page: 1 }), frame(SECTION, { page: 2 }), done]],
    ['SECTION past the window', 'pdf', JOBS.pdfTextJob(1, 1), [header.pdf, frame(SECTION, { page: 1 }), frame(SECTION, { page: 2 }), done]],
    ['a slide not ascending', 'office', jobs.office, [frame(HEADER, { sniffed: 'pptx', slides: 3 }), frame(SECTION, { slide: 2 }), frame(SECTION, { slide: 2 }), done]],
    ['a slide past the total', 'office', jobs.office, [frame(HEADER, { sniffed: 'pptx', slides: 1 }), frame(SECTION, { slide: 2 }), done]],
    ['more rows than the limit', 'office', jobs.office, [frame(HEADER, { sniffed: 'xlsx', sheets: 1 }), frame(SECTION, { sheet: 'A', rows: 2001, total_rows: 3000 }), done]],
    ['rows above the total', 'office', jobs.office, [frame(HEADER, { sniffed: 'xlsx', sheets: 1 }), frame(SECTION, { sheet: 'A', rows: 5, total_rows: 4 }), done]],
    ['more sheets than declared', 'office', jobs.office, [frame(HEADER, { sniffed: 'xlsx', sheets: 1 }), frame(SECTION, { sheet: 'A', rows: 0, total_rows: 0 }), frame(SECTION, { sheet: 'B', rows: 0, total_rows: 0 }), done]],
    ['a sheet name over 100 characters', 'office', jobs.office, [frame(HEADER, { sniffed: 'xlsx', sheets: 1 }), frame(SECTION, { sheet: big(101), rows: 0, total_rows: 0 }), done]],
    ['a section in a docx', 'office', jobs.office, [frame(HEADER, { sniffed: 'docx' }), frame(SECTION, { slide: 1 }), done]],
    ['a PNG where a photo is JPEG', 'image', jobs.photo, [header.image, imageFrame(0, png()), done]],
    ['a JPEG where a sticker is PNG', 'image', jobs.sticker, [header.image, imageFrame(0, jpeg()), done]],
    ['not an image at all', 'image', jobs.photo, [header.image, imageFrame(0, Buffer.from('GIF89a......')), done]],
    ['an EXIF segment', 'image', jobs.photo, [header.image, imageFrame(0, jpeg({ app1: true })), done]],
    ['a COM segment', 'image', jobs.photo, [header.image, imageFrame(0, jpeg({ com: true })), done]],
    ['a PNG tEXt chunk', 'image', jobs.sticker, [header.image, imageFrame(0, png({ chunks: [['tEXt', 'Comment\u0000hi']] })), done]],
    ['a long edge over the limit', 'image', jobs.photo, [header.image, imageFrame(0, jpeg({ width: 1569, height: 10 })), done]],
    ['a sticker over its edge', 'image', jobs.sticker, [header.image, imageFrame(0, png({ width: 513, height: 10 })), done]],
    ['a zero side', 'image', jobs.photo, [header.image, imageFrame(0, jpeg({ width: 0, height: 10 })), done]],
    ['an image over its byte limit', 'image', jobs.photo, [header.image, imageFrame(0, jpeg({ size: 307_201 })), done]],
    ['two images from the image worker', 'image', jobs.photo, [header.image, imageFrame(0, jpeg()), imageFrame(0, jpeg()), done]],
    ['no image from the image worker', 'image', jobs.photo, [header.image, done]],
    ['an image page other than 0', 'image', jobs.photo, [header.image, imageFrame(1, jpeg()), done]],
    ['a page image not asked for', 'pdf', jobs.pdfImages, [header.pdf, imageFrame(3, jpeg()), done]],
    ['page images not ascending', 'pdf', jobs.pdfImages, [header.pdf, imageFrame(4, jpeg()), imageFrame(2, jpeg()), done]],
    // Each image within its own limit, together past IMAGES_TOTAL_BYTES.
    ['page images over their total', 'pdf', { ...JOBS.pdfImagesJob([1, 2, 3, 4]), limits: { ...JOBS.pdfImagesJob([1]).limits } }, [header.pdf, ...[1, 2, 3, 4].map(page => imageFrame(page, jpeg({ size: Math.ceil(IMAGES_TOTAL_BYTES / 3.9) }))), done]],
    ['an image from a pdf text job', 'pdf', jobs.pdfText, [header.pdf, imageFrame(1, jpeg()), done]],
    ['bytes after DONE', 'pdf', jobs.pdfText, [header.pdf, done, frame(TEXT, 'x')]],
    ['a frame after ERROR', 'pdf', jobs.pdfText, [header.pdf, frame(ERROR, { code: 'damaged' }), done], 2],
    ['DONE with exit 2', 'pdf', jobs.pdfText, [header.pdf, done], 2],
    ['ERROR with exit 0', 'pdf', jobs.pdfText, [frame(ERROR, { code: 'damaged' })], 0],
    ['EOF without DONE or ERROR', 'pdf', jobs.pdfText, [header.pdf], 0],
    ['a frame cut short at EOF', 'pdf', jobs.pdfText, [header.pdf, frame(TEXT, 'abc').subarray(0, 6)], 0],
    ['DONE without HEADER', 'pdf', jobs.pdfText, [done]],
    ['DONE with a payload other than cut', 'pdf', jobs.pdfText, [header.pdf, frame(DONE, { cut: false })]],
    ['cut from the image worker', 'image', jobs.photo, [header.image, imageFrame(0, jpeg()), frame(DONE, { cut: true })]],
    ['an unknown ERROR code', 'pdf', jobs.pdfText, [frame(ERROR, { code: 'oops' })], 2],
    ['too_large without what', 'pdf', jobs.pdfText, [frame(ERROR, { code: 'too_large' })], 2],
    ['what without too_large', 'pdf', jobs.pdfText, [frame(ERROR, { code: 'damaged', what: 'pixels' })], 2],
    ['kind_off from the pdf worker', 'pdf', jobs.pdfText, [frame(ERROR, { code: 'kind_off' })], 2],
  ]
  for (const [label, worker, job, stdout, exit = 0] of cases) {
    const output = await run(worker, job, stdout, exit)
    assert.equal(output.killed, 'bad_output', label)
    assert.deepEqual([output.header, output.sections, output.images, output.error], [null, [], [], null], `${label}: nothing kept`)
    assert.deepEqual(outcomeOf(output), { code: 'parser_failed', log: 'bad_output' }, label)
  }
})

test('the whole stdout is bounded, and a worker that keeps writing is stopped', async () => {
  const text = Array.from({ length: Math.ceil(STDOUT_MAX / 65_541) + 1 }, () => frame(TEXT, 'x'.repeat(65_536)))
  const output = await run('pdf', { ...jobs.pdfText, limits: { ...jobs.pdfText.limits, text_bytes: 10 ** 9 } }, [frame(HEADER, { pages: 1 }), frame(SECTION, { page: 1 }), ...text, done])
  assert.equal(output.killed, 'bad_output')
})

test('exit codes map as §16.11\'s table says, and an abort ends the job at once', async () => {
  const header = frame(HEADER, { pages: 1 })
  for (const [code, facts] of [['unsupported', 'attachment_unsupported'], ['encrypted', 'attachment_encrypted'], ['kind_off', 'media_not_allowed'], ['damaged', 'parser_failed']]) {
    const worker = code === 'kind_off' ? 'office' : 'pdf', job = worker === 'office' ? jobs.office : jobs.pdfText
    assert.deepEqual(outcomeOf(await run(worker, job, [frame(ERROR, { code })], 2)), { code: facts, log: null }, code)
  }
  assert.deepEqual(outcomeOf(await run('office', jobs.office, [frame(ERROR, { code: 'too_large', what: 'entries' })], 2)), { code: 'attachment_too_large', facts: { what: 'entries' }, log: null })
  assert.deepEqual(outcomeOf(await run('pdf', jobs.pdfText, [frame(ERROR, { code: 'bad_input' })], 2)), { code: 'parser_failed', log: 'parser_exit' })
  for (const [exit, log] of [[124, 'wall'], [137, 'oom'], [3, 'jail_error'], [125, 'jail_error'], [127, 'jail_error'], [1, 'parser_exit'], [134, 'parser_exit'], [159, 'parser_exit'], [143, 'parser_exit']]) {
    const output = await run('pdf', jobs.pdfText, [header], exit)
    assert.deepEqual([output.exit, output.killed], [exit, null], String(exit))
    assert.deepEqual(outcomeOf(output), { code: 'parser_failed', log }, String(exit))
  }
  const ok = await run('pdf', jobs.pdfText, [header, frame(SECTION, { page: 1 }), done], 0)
  assert.deepEqual(outcomeOf(ok).output.sections.length, 1)
  assert.deepEqual(outcomeOf({ killed: 'watchdog' }), { code: 'parser_failed', log: 'watchdog' })
  // An abort (a wipe): SIGTERM now, whatever the worker was about to write.
  const controller = new AbortController()
  const started = Date.now()
  const pending = run('pdf', jobs.pdfText, [header, frame(SECTION, { page: 1 }), done], 0, { delayMs: 10_000, run: { signal: controller.signal } })
  setTimeout(() => controller.abort(), 200)
  const aborted = await pending
  assert.ok(Date.now() - started < 5_000, 'ended by SIGTERM, not by its own end')
  assert.equal(aborted.killed, 'aborted')
  assert.deepEqual(outcomeOf(aborted, 'media_off'), { code: 'media_not_allowed', log: 'media_off' })
  assert.deepEqual(outcomeOf(aborted), { code: 'media_not_allowed', log: 'revoked' })
  const already = new AbortController(); already.abort()
  assert.equal((await run('pdf', jobs.pdfText, [header, done], 0, { delayMs: 10_000, run: { signal: already.signal } })).killed, 'aborted')
  // A media-jail that cannot be started is a jail error.
  assert.deepEqual(outcomeOf(await runWorker({ worker: 'pdf', job: jobs.pdfText, input, spawn: () => { throw new Error('ENOENT') } })), { code: 'parser_failed', log: 'jail_error' })
})
