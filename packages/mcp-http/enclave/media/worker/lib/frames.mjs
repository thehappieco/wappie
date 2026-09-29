// The worker side of the protocol between the reader's Node and a jailed
// worker (docs/mcp-enclave.md §16.11): the job on stdin, frames on stdout.
// Every worker (image.mjs, pdf.mjs, office.mjs) runs through run() below, so
// the rules every worker shares live here once:
//
//   stdin   u32 H ‖ H bytes of strict JSON ‖ u32 N ‖ N bytes of input ‖ EOF,
//           read whole before anything is written;
//   stdout  frames u32 len ‖ u8 type ‖ payload, nothing else, with
//           backpressure honoured; exit 0 after DONE, 2 after ERROR.
//
// A worker's own code never writes to fd 1: console is silenced before any
// parser is imported (pdf.js warns through console.log at import time), and
// fd 2 is /dev/null in the jail anyway.

import { STDIN_HEADER_MAX, INPUT_MAX, FRAME_MAX } from './limits.mjs'

export const HEADER = 1
export const TEXT = 2
export const SECTION = 3
export const IMAGE = 4
export const ERROR = 8
export const DONE = 9

/** A refusal the worker answers with one ERROR frame and exit 2. */
export class WorkerError extends Error {
  constructor(code, what) {
    super(code)
    this.code = code
    this.what = what
  }
}

export const refuse = (code, what) => new WorkerError(code, what)

/** Silence every console method, so no library can write into the frames. */
export function silenceConsole() {
  for (const name of ['log', 'info', 'warn', 'error', 'debug', 'trace', 'dir', 'dirxml', 'table', 'group', 'groupCollapsed']) {
    console[name] = () => {}
  }
}

/**
 * Read the whole job from `stream`: the strict JSON header (parsed, not yet
 * validated against a worker's schema) and the input Buffer. Any framing fault
 * is bad_input; so is a byte after the input. The input Buffer is allocated
 * once at its declared size.
 */
export async function readJob(stream) {
  let prefix = Buffer.alloc(0)
  let header = null
  let input = null
  let filled = 0
  let need = 4
  let stage = 'H'
  for await (const chunk of stream) {
    let at = 0
    while (at < chunk.length) {
      if (stage === 'done') throw refuse('bad_input')
      if (stage === 'input') {
        const take = Math.min(chunk.length - at, input.length - filled)
        chunk.copy(input, filled, at, at + take)
        filled += take
        at += take
        if (filled === input.length) stage = 'done'
        continue
      }
      const take = Math.min(chunk.length - at, need - prefix.length)
      prefix = Buffer.concat([prefix, chunk.subarray(at, at + take)])
      at += take
      if (prefix.length < need) continue
      if (stage === 'H') {
        const h = prefix.readUInt32BE(0)
        if (h < 2 || h > STDIN_HEADER_MAX) throw refuse('bad_input')
        stage = 'header'
        need = h
      } else if (stage === 'header') {
        header = parseJSON(prefix)
        stage = 'N'
        need = 4
      } else {
        const n = prefix.readUInt32BE(0)
        if (n < 1 || n > INPUT_MAX) throw refuse('bad_input')
        input = Buffer.alloc(n)
        stage = 'input'
      }
      prefix = Buffer.alloc(0)
    }
  }
  if (stage !== 'done') throw refuse('bad_input')
  return { header, input }
}

function parseJSON(bytes) {
  // Strict: one object, UTF-8, no BOM.
  if (bytes[0] !== 0x7b) throw refuse('bad_input')
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)
    const value = JSON.parse(text)
    if (!isObject(value)) throw new Error('not an object')
    return value
  } catch {
    throw refuse('bad_input')
  }
}

export const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
export const isInt = (v, lo, hi) => Number.isSafeInteger(v) && v >= lo && v <= hi

/**
 * Check a parsed header against a schema of exactly these keys:
 * { key: (value) => boolean }. Unknown, missing or ill-typed keys are
 * bad_input.
 */
export function strict(value, schema) {
  if (!isObject(value)) throw refuse('bad_input')
  const keys = Object.keys(value)
  const want = Object.keys(schema)
  if (keys.length !== want.length || !want.every((k) => Object.hasOwn(value, k))) throw refuse('bad_input')
  for (const k of want) if (!schema[k](value[k])) throw refuse('bad_input')
  return value
}

const EMPTY = Buffer.alloc(0)

/** The frame writer: one frame per call, each awaited, so backpressure holds. */
export class Frames {
  constructor(stream) {
    this.stream = stream
  }

  async frame(type, payload = EMPTY) {
    if (payload.length > FRAME_MAX[type]) throw new Error(`frame ${type} over its limit`)
    const prefix = Buffer.alloc(5)
    prefix.writeUInt32BE(payload.length, 0)
    prefix.writeUInt8(type, 4)
    await this.#write(payload.length ? Buffer.concat([prefix, payload]) : prefix)
  }

  #write(bytes) {
    return new Promise((resolve, reject) => {
      this.stream.write(bytes, (err) => (err ? reject(err) : resolve()))
    })
  }

  /** A JSON frame; no value sends an empty payload (a plain DONE). */
  json(type, value) {
    return this.frame(type, value === undefined ? undefined : Buffer.from(JSON.stringify(value), 'utf8'))
  }

  /** An IMAGE frame: u16 page ‖ one complete JPEG or PNG. */
  image(page, file) {
    const payload = Buffer.alloc(2 + file.length)
    payload.writeUInt16BE(page, 0)
    file.copy(payload, 2)
    return this.frame(IMAGE, payload)
  }
}

/**
 * Text out of a worker, as TEXT frames of at most FRAME_MAX[TEXT] bytes that
 * never split a code point, within `limit` bytes in all. When the next byte
 * would pass the limit the sink is `cut`, emits what fits (to a code point
 * boundary) and throws CUT, which run() turns into DONE {"cut": true}.
 */
export const CUT = Symbol('cut')

export class TextSink {
  constructor(frames, limit) {
    this.frames = frames
    this.limit = limit
    this.used = 0
    this.pending = []
    this.pendingBytes = 0
    this.cut = false
  }

  /** Queue text; frames go out as 64 KiB fill up. */
  async write(text) {
    if (!text) return
    let bytes = Buffer.from(text, 'utf8')
    const room = this.limit - this.used - this.pendingBytes
    let over = false
    if (bytes.length > room) {
      bytes = bytes.subarray(0, boundary(bytes, room))
      over = true
    }
    this.pending.push(bytes)
    this.pendingBytes += bytes.length
    while (this.pendingBytes >= FRAME_MAX[TEXT]) await this.#emit(FRAME_MAX[TEXT])
    if (over) {
      await this.flush()
      this.cut = true
      throw CUT
    }
  }

  async flush() {
    while (this.pendingBytes > 0) await this.#emit(FRAME_MAX[TEXT])
  }

  async #emit(max) {
    const all = Buffer.concat(this.pending)
    const n = all.length <= max ? all.length : boundary(all, max)
    const head = all.subarray(0, n)
    const rest = all.subarray(n)
    this.pending = rest.length ? [rest] : []
    this.pendingBytes = rest.length
    this.used += head.length
    if (head.length) await this.frames.frame(TEXT, head)
  }
}

/** The largest n ≤ max such that bytes[0, n) ends on a UTF-8 code point boundary. */
export function boundary(bytes, max) {
  let n = Math.min(max, bytes.length)
  // Step back over continuation bytes (10xxxxxx) to the start of a code point.
  while (n > 0 && n < bytes.length && (bytes[n] & 0xc0) === 0x80) n--
  return n
}

/**
 * The whole life of a worker once its console is silenced: read the job, run
 * `handler(job, frames)` and end with DONE (exit 0) or ERROR (exit 2).
 * `handler` resolves when its output is complete; a TextSink that reached its
 * limit throws CUT, which ends the job with DONE {"cut": true}. A WorkerError
 * is a refusal; any other exception is the parser failing: ERROR damaged.
 */
export async function run(handler, { stdin = process.stdin, stdout = process.stdout, exit = process.exit } = {}) {
  const frames = new Frames(stdout)
  let code = 0
  try {
    const job = await readJob(stdin)
    let cut = false
    try {
      await handler(job, frames)
    } catch (e) {
      if (e !== CUT) throw e
      cut = true
    }
    await frames.json(DONE, cut ? { cut: true } : undefined)
  } catch (e) {
    code = 2
    const error = e instanceof WorkerError ? e : refuse('damaged')
    try {
      await frames.json(ERROR, error.what ? { code: error.code, what: error.what } : { code: error.code })
    } catch {
      // stdout is gone: the reader already stopped listening.
    }
  }
  exit(code)
}
