// The worker's copies of §16.8 against the contract's values (the harness
// holds them as §16.8 writes them) and, once MAIN's enclave/media/policy.mjs
// sits beside this package, against the reader's own constants: a worker
// ceiling may never be above what the reader sends.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import * as worker from '../lib/limits.mjs'
import { LIMITS, FRAME_MAX } from './harness.mjs'

test('the worker limits are the contract values', () => {
  for (const [name, value] of Object.entries(LIMITS)) {
    if (name in worker) assert.equal(worker[name], value, name)
  }
  assert.deepEqual({ ...worker.FRAME_MAX }, FRAME_MAX)
  assert.equal(worker.STDIN_HEADER_MAX, 4_096)
  assert.equal(worker.INPUT_MAX, 33_554_432)
  assert.deepEqual([...worker.JPEG_QUALITIES], [80, 70, 60])
  assert.equal(worker.IMAGE_FALLBACK_EDGE, 1_024)
  assert.deepEqual([...worker.STICKER_EDGES], [512, 384, 256])
  assert.equal(worker.STICKER_EDGES[0], worker.STICKER_LONG_EDGE)
})

const policyPath = fileURLToPath(new URL('../../policy.mjs', import.meta.url))

test('the worker limits equal the reader policy.mjs', { skip: !existsSync(policyPath) && 'enclave/media/policy.mjs (MAIN) is not in this tree yet' }, async () => {
  const policy = await import(policyPath)
  const same = [
    'STDIN_HEADER_MAX',
    'IMAGE_MAX_PIXELS',
    'IMAGE_LONG_EDGE',
    'IMAGE_MAX_BYTES',
    'STICKER_LONG_EDGE',
    'STICKER_MAX_BYTES',
    'JOB_TEXT_MAX_BYTES',
    'PDF_MAX_PAGES',
    'PDF_PAGES_PER_JOB',
    'PDF_MAX_IMAGE_PIXELS',
    'IMAGES_PER_RESULT',
    'ZIP_MAX_ENTRIES',
    'ZIP_MAX_INFLATED',
    'ZIP_MAX_RATIO',
    'ZIP_LISTED',
    'SHEETS_MAX',
    'SHEET_ROWS',
    'IMAGE_FALLBACK_EDGE',
  ]
  for (const name of same) assert.equal(worker[name], policy[name], name)
  assert.deepEqual([...worker.JPEG_QUALITIES], [...policy.JPEG_QUALITIES])
  assert.deepEqual([...worker.STICKER_EDGES], [...policy.STICKER_EDGES])
  assert.deepEqual({ ...worker.FRAME_MAX }, { ...policy.FRAME_MAX })
  assert.equal(worker.INPUT_MAX, policy.CAP_BYTES.document)
})
