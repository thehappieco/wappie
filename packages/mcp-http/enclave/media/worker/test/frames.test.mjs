// The worker side of §16.11's framing, and the rules every worker keeps.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Readable, Writable } from 'node:stream'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { readJob, run, TextSink, Frames, boundary, refuse, CUT } from '../lib/frames.mjs'
import { stdinOf, parseFrames, runWorker, WORKER_DIR } from './harness.mjs'
import { H } from './corpus.mjs'

const chunked = (buf, size) => Readable.from(Array.from({ length: Math.ceil(buf.length / size) }, (_, i) => buf.subarray(i * size, (i + 1) * size)))

class Sink extends Writable {
  constructor() {
    super()
    this.chunks = []
  }
  _write(chunk, _enc, cb) {
    this.chunks.push(chunk)
    cb()
  }
  get bytes() {
    return Buffer.concat(this.chunks)
  }
}

test('readJob takes the header and input whatever the chunking', async () => {
  const stdin = stdinOf({ v: 1, op: 'x' }, Buffer.from('hello'))
  for (const size of [1, 3, 7, stdin.length]) {
    const { header, input } = await readJob(chunked(stdin, size))
    assert.deepEqual(header, { v: 1, op: 'x' })
    assert.equal(input.toString(), 'hello')
  }
})

test('readJob refuses every framing fault as bad_input', async () => {
  const good = stdinOf({ v: 1 }, Buffer.from('abc'))
  const bad = {
    short: good.subarray(0, good.length - 1),
    extra: Buffer.concat([good, Buffer.from('!')]),
    empty: Buffer.alloc(0),
    headerTooShort: Buffer.from([0, 0, 0, 1, 0x7b]),
    headerTooLong: Buffer.from([0, 0, 0x10, 0x01]),
    notJson: stdinOf({}, Buffer.from('a')).fill(0x20, 4, 6),
    array: Buffer.concat([Buffer.from([0, 0, 0, 2]), Buffer.from('[]'), Buffer.from([0, 0, 0, 1, 0x61])]),
    bom: Buffer.concat([Buffer.from([0, 0, 0, 5]), Buffer.from('﻿{}'), Buffer.from([0, 0, 0, 1, 0x61])]),
    noInput: Buffer.concat([Buffer.from([0, 0, 0, 2]), Buffer.from('{}'), Buffer.from([0, 0, 0, 0])]),
    inputTooLong: Buffer.concat([Buffer.from([0, 0, 0, 2]), Buffer.from('{}'), Buffer.from([0x02, 0, 0, 1])]),
  }
  for (const [name, stdin] of Object.entries(bad)) {
    await assert.rejects(readJob(chunked(stdin, 4)), (e) => e.code === 'bad_input', name)
  }
})

test('TextSink never splits a code point and cuts at the byte', async () => {
  const out = new Sink()
  const sink = new TextSink(new Frames(out), 70_000)
  const text = 'ação🙂'.repeat(20_000)
  await assert.rejects(sink.write(text), (e) => e === CUT)
  const { frames } = parseFrames(out.bytes)
  let total = 0
  for (const f of frames) {
    assert.equal(f.type, 2)
    assert.ok(f.payload.length <= 65_536 && f.payload.length > 0)
    new TextDecoder('utf-8', { fatal: true }).decode(f.payload)
    total += f.payload.length
  }
  assert.ok(total <= 70_000 && total > 70_000 - 4)
})

test('boundary steps back to the start of a code point', () => {
  const b = Buffer.from('a🙂b')
  assert.equal(boundary(b, 1), 1)
  assert.equal(boundary(b, 2), 1)
  assert.equal(boundary(b, 4), 1)
  assert.equal(boundary(b, 5), 5)
  assert.equal(boundary(b, 99), 6)
})

test('run ends with DONE and exit 0, ERROR and exit 2, damaged for a crash', async () => {
  const cases = [
    [async (_job, f) => f.json(1, { ok: true }), 0, [1, 9]],
    [async () => {
      throw refuse('too_large', 'pixels')
    }, 2, [8]],
    [async () => {
      throw new TypeError('bug')
    }, 2, [8]],
  ]
  for (const [handler, want, types] of cases) {
    const out = new Sink()
    let code
    await run(handler, { stdin: Readable.from([stdinOf({ v: 1 }, Buffer.from('x'))]), stdout: out, exit: (c) => (code = c) })
    assert.equal(code, want)
    const { frames } = parseFrames(out.bytes)
    assert.deepEqual(frames.map((f) => f.type), types)
  }
})

test('a worker answers a malformed stdin with one ERROR bad_input frame', async () => {
  for (const worker of ['image', 'pdf', 'office']) {
    const r = await runWorker(worker, { v: 2 }, Buffer.from('x'))
    assert.equal(r.code, 2)
    assert.equal(r.valid, true, r.why)
    assert.deepEqual(r.error, { code: 'bad_input' })
  }
  const r = await runWorker('office', H.office(), Buffer.from('x'))
  assert.deepEqual(r.error, { code: 'unsupported' })
})

test('workers import only node: built-ins, their own files and their own packages', () => {
  const allowed = new Set(['sharp', 'pdfjs-dist/legacy/build/pdf.mjs', 'xlsx', 'xlsx/dist/cpexcel.full.mjs'])
  const forbidden = /\b(child_process|worker_threads|net|http|https|http2|dgram|dns|tls|cluster|inspector|vm)\b/
  const files = ['image.mjs', 'pdf.mjs', 'office.mjs', ...readdirSync(join(WORKER_DIR, 'lib')).map((f) => `lib/${f}`)]
  for (const file of files) {
    const source = readFileSync(join(WORKER_DIR, file), 'utf8')
    const specs = [...source.matchAll(/^import\s[^;]*?from\s*'([^']+)'/gms), ...source.matchAll(/\bimport\(\s*'([^']+)'\s*\)/g)]
    if (!file.startsWith('lib/')) assert.ok(specs.length > 0, `${file}: the import scan found nothing`)
    for (const [, spec] of specs) {
      if (spec.startsWith('node:')) assert.doesNotMatch(spec, forbidden, `${file} imports ${spec}`)
      else if (!spec.startsWith('./') && !spec.startsWith('../')) assert.ok(allowed.has(spec), `${file} imports ${spec}`)
    }
    assert.doesNotMatch(source, /process\.stdout\.write|console\.log\(/, `${file} writes to stdout outside the frames`)
  }
})

test('the office worker never loads sharp (its table row has --no-addons)', () => {
  const office = readFileSync(join(WORKER_DIR, 'office.mjs'), 'utf8')
  assert.doesNotMatch(office, /encode\.mjs|sharp/)
  for (const f of readdirSync(join(WORKER_DIR, 'lib'))) {
    const src = readFileSync(join(WORKER_DIR, 'lib', f), 'utf8')
    if (/from 'sharp'|import\('sharp'\)/.test(src)) assert.equal(f, 'encode.mjs')
  }
})
