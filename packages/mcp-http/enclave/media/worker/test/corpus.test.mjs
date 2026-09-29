// Every §16.13 corpus file through its worker, run directly (no jail): each
// ends in the bounded outcome its case names, with output the reader's
// checks accept. The cases whose bound is the memcg run only under the jail
// (deploy/enclave/jailcheck/jail-check.mjs, from check-image.sh --jail).

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { runWorker } from './harness.mjs'
import { corpus, outcome } from './corpus.mjs'

const cases = await corpus()

for (const c of cases) {
  test(`${c.worker}: ${c.name}`, { skip: c.jailOnly && 'bounded by the memcg: runs under media-jail only' }, async () => {
    const r = await runWorker(c.worker, c.header, c.input, { timeoutMs: 120_000 })
    const got = outcome(r)
    assert.ok(c.expect.includes(got), `${c.name}: ${got}, expected one of ${c.expect.join(', ')}`)
    if (got.startsWith('done') && c.check) assert.ok(c.check(r), `${c.name}: content check failed:\n${JSON.stringify(r.text).slice(0, 2_000)}`)
  })
}

test('a GPS-tagged photo comes out without APP1 or APP13, and nothing of its EXIF', async () => {
  const c = cases.find((x) => x.name === 'photo-gps')
  assert.ok(c.input.includes('CameraCo') && c.input.includes('Lisboa'))
  const r = await runWorker(c.worker, c.header, c.input)
  const file = r.images[0].file
  assert.deepEqual(r.images[0].segments.filter((m) => m >= 0xe0), [])
  for (const s of ['CameraCo', 'Exif', 'Lisboa', '38.72', 'Photoshop']) assert.equal(file.includes(s), false, s)
})

test('the photo ladder falls back to IMAGE_FALLBACK_EDGE before refusing', async () => {
  const c = cases.find((x) => x.name === 'photo-gps')
  const r = await runWorker(c.worker, { ...c.header, limits: { ...c.header.limits, image_bytes: 40_000 } }, c.input)
  if (r.error) {
    assert.deepEqual(r.error, { code: 'too_large', what: 'pixels' })
  } else {
    assert.ok(Math.max(r.images[0].width, r.images[0].height) <= 1_024)
    assert.ok(r.images[0].file.length <= 40_000)
  }
})

test('a sticker steps down its edges until it fits', async () => {
  const c = cases.find((x) => x.name === 'sticker-noise-ladder')
  const r = await runWorker(c.worker, c.header, c.input)
  if (!r.error) assert.ok([512, 384, 256].includes(Math.max(r.images[0].width, r.images[0].height)))
})

test('page images keep to their share of IMAGES_TOTAL_BYTES', async () => {
  const c = cases.find((x) => x.name === 'pdf-scanned-images')
  const r = await runWorker(c.worker, c.header, c.input)
  for (const img of r.images) assert.ok(img.file.length <= 230_400)
})
