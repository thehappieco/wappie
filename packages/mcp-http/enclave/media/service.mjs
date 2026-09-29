// Attachments in the attested reader (docs/mcp-enclave.md §16.5 to §16.10):
// the one object content.mjs builds, which gives each media connection its
// `provider.media` and runs every open.
//
// A call runs §16.5's cheap checks in order (nothing opens a key or asks for
// ciphertext before the last of them), then joins or starts an open and waits
// for it at most HOST_WAIT_MS for its host. A connection has one open in the
// slot or its queue at a time; the opens its parallel calls start wait behind
// it in the connection's own line (OPENS_QUEUE_MAX) and go in, in order, as it
// leaves. An open runs in the slot, from its keys to its last job: the media
// key, the ciphertext, the checks, the sniff and one or two jailed jobs. The
// reader's Node itself never parses anything: it checks magic bytes, decodes
// plain text and reads worker frames.
import { ArchiveError } from '@whatserver2/client'
import { LocalConfigError } from '@whatserver2/mcp/config'
import { fingerprint } from '../../log.mjs'
import { CONSOLE_URL } from '../constants.mjs'
import { messageURL } from '../provider.mjs'
import { createCaches } from './cache.mjs'
import { fetchCiphertext } from './fetch.mjs'
import { checkRow, hostOf, knownKinds, parseRequest, refusal, rowFacts, waitFor, whyNot } from './gate.mjs'
import { checkJail, outcomeOf, runWorker } from './jail.mjs'
import { createBudgets, createScheduler, retryAfter } from './jobs.mjs'
import { charPart, factsOf, finish, lastPage, pagesPart, pdfPart, pdfWindow, pending, renderOffice } from './result.mjs'
import { decodeText, sniff } from './sniff.mjs'
import { createMediaStream } from './wamedia-stream.mjs'
import {
  CAP_BYTES, IMAGE_LONG_EDGE, IMAGE_MAX_BYTES, IMAGE_MAX_PIXELS, IMAGES_TOTAL_BYTES, JOB_TEXT_MAX_BYTES, OPENS_QUEUE_MAX, PDF_MAX_IMAGE_PIXELS,
  PDF_MAX_PAGES, PDF_PAGES_PER_JOB, RESULT_MAX_BYTES, SHEET_ROWS, SHEETS_MAX, STICKER_LONG_EDGE, STICKER_MAX_BYTES, TEXT_TTL_MS, THUMB_MAX_BYTES,
  ZIP_LISTED, ZIP_MAX_ENTRIES, ZIP_MAX_INFLATED, ZIP_MAX_RATIO,
} from './policy.mjs'

/**
 * Outcomes answered once and forgotten rather than kept for RESULT_TTL_MS:
 * the §16.9 list, plus the three whose truth changes with a budget, a switch
 * or the queue rather than with the attachment (a kept `rate_limited` or
 * `media_busy` would outlive its own `retry_after_s`, a kept
 * `media_not_allowed` a kind switched back on). A result whose page images
 * were withheld because `image` is off is not kept either, for the same
 * reason; its text is in the text cache.
 */
const FORGOTTEN = new Set(['attachment_pending', 'read_failed', 'reconsent_required', 'stale_grant', 'unauthorized', 'rate_limited', 'media_busy', 'media_not_allowed'])
const safeCode = error => ((error instanceof ArchiveError || error instanceof LocalConfigError) && /^[a-z][a-z0-9_]{0,47}$/.test(error.code) ? error.code : 'read_failed')
const keeps = outcome => (outcome.result ? outcome.result.header.images_withheld !== 'kind_off' : !FORGOTTEN.has(safeCode(outcome.error)))

/**
 * The per-connection key of an open (§16.9): identical calls share it. The
 * caches and the running opens are also keyed by the call's number, so what
 * one number's call opened never answers a call naming another, whose row
 * check would have refused it.
 */
export const openKey = ({ uid, cursor, pages, images = true }) => `${uid}|${cursor ?? ''}|${pages ?? ''}|${images === false ? 0 : 1}`
const numbered = (device, key) => `${device}|${key}`

const defaultDelay = (ms, signal) => new Promise(resolve => {
  const timer = setTimeout(resolve, ms)
  signal?.addEventListener('abort', () => { clearTimeout(timer); resolve() }, { once: true })
})

/** Image job headers (§16.11). */
const imageJob = (op, format) => ({ v: 1, op, format, limits: op === 'sticker'
  ? { pixels: IMAGE_MAX_PIXELS, long_edge: STICKER_LONG_EDGE, image_bytes: STICKER_MAX_BYTES }
  : { pixels: IMAGE_MAX_PIXELS, long_edge: IMAGE_LONG_EDGE, image_bytes: IMAGE_MAX_BYTES } })
const pdfTextJob = (from, count) => ({ v: 1, op: 'text', from, count, limits: { text_bytes: JOB_TEXT_MAX_BYTES, image_pixels: PDF_MAX_IMAGE_PIXELS } })
const pdfImagesJob = pages => ({ v: 1, op: 'images', pages, limits: { long_edge: IMAGE_LONG_EDGE, image_bytes: Math.min(IMAGE_MAX_BYTES, Math.floor(IMAGES_TOTAL_BYTES / pages.length)), image_pixels: PDF_MAX_IMAGE_PIXELS } })
const officeJob = allow => ({ v: 1, op: 'text', allow, limits: { text_bytes: JOB_TEXT_MAX_BYTES, entries: ZIP_MAX_ENTRIES, inflated: ZIP_MAX_INFLATED, ratio: ZIP_MAX_RATIO, listed: ZIP_LISTED, sheets: SHEETS_MAX, sheet_rows: SHEET_ROWS } })
export const JOBS = Object.freeze({ imageJob, pdfTextJob, pdfImagesJob, officeJob })

/**
 * `checkActive.mediaStatus(id)` is verifier.mjs's; `archive` is the ARCHIVE
 * origin; `consoleURL` is CONSOLE_URL, where a result's `open_url` points;
 * `jail` is {checkJail, runWorker} (tests replace it, and may pass `spawn`
 * for runWorker); `delay(ms, signal)` is the inline wait's timer.
 */
export function createMediaService({ log, now = Date.now, checkActive, archive, consoleURL = CONSOLE_URL, fetch = globalThis.fetch, jail = { checkJail, runWorker }, delay = defaultDelay }) {
  const caches = createCaches({ now })
  const scheduler = createScheduler()
  const budgets = createBudgets({ now })
  // connection id -> { opens: Map(open key -> open), active: its open in the
  // slot or the slot's queue, line: its opens waiting behind that one, first in
  // first out, mediaOff: the last media_off seen }
  const connections = new Map()
  const counters = { opens: 0, killed: 0 }
  let jailState = null, closed = false
  const conn = id => ({ conn: fingerprint(id) })
  const stateOf = id => {
    let state = connections.get(id)
    if (!state) connections.set(id, state = { opens: new Map(), active: null, line: [], mediaOff: [] })
    return state
  }
  /** The console link of a row's message on this connection (§16.7), or null. */
  const linkOf = (record, row) => messageURL(consoleURL, record.tenant_id, row?.device_id, row?.uid)
  const ready = () => jailState?.ok === true && !closed

  /** Copies of a result's image Buffers: the cached ones are zeroed when their entry leaves. */
  const copy = result => ({ ...result, images: result.images.map(image => ({ mimeType: image.mimeType, data: Buffer.from(image.data) })) })

  function settle(open, outcome) {
    if (open.done) return
    open.done = true
    const state = connections.get(open.id)
    if (state?.opens.get(open.key) === open) state.opens.delete(open.key)
    const index = state ? state.line.indexOf(open) : -1
    if (index >= 0) state.line.splice(index, 1)
    if (open.controller.signal.aborted) outcome = { error: refusal('media_not_allowed', { facts: open.facts }) }
    else if (keeps(outcome)) caches.result.set(open.id, open.key, { outcome, kinds: open.kinds })
    if (outcome.result) { counters.opens++; log.event('media_opened', conn(open.id)) }
    open.outcome = outcome
    open.resolve()
  }
  /**
   * Ends an open for `reason` ('revoked' or 'media_off'): its callers answer
   * now, its job dies on SIGTERM. One waiting in the slot's queue leaves it at
   * once and hands its connection's place to the next of its line; one
   * running hands it over when its job has died (`leave`).
   */
  function abort(open, reason) {
    if (open.done) return
    open.reason = reason
    open.controller.abort()
    if (scheduler.remove(open)) leave(open)
    settle(open)
  }
  /**
   * `open` left the slot or its queue: the connection's next open, first in
   * its line, goes to the slot. The place it takes was freed just now, so the
   * scheduler admits it; `media_busy` is only the answer should it not.
   */
  function leave(open) {
    const state = connections.get(open.id)
    if (state?.active !== open) return
    state.active = null
    while (state.line.length) {
      const next = state.line.shift()
      if (scheduler.admit(next, next.start, () => leave(next))) { state.active = next; return }
      settle(next, { error: refusal('media_busy', { retry_after_s: 20, facts: next.facts }) })
    }
  }

  /** One jailed job of the open; its output, or the refusal its end means. */
  async function job(open, worker, header, input) {
    const output = await jail.runWorker({ worker, job: header, input, signal: open.controller.signal, ...(jail.spawn ? { spawn: jail.spawn } : {}) })
    const outcome = outcomeOf(output, open.reason ?? 'revoked')
    if (outcome.log) { counters.killed++; log.event('media_job_killed', { ...conn(open.id), code: outcome.log }) }
    if (outcome.output) return outcome.output
    throw refusal(outcome.code, { facts: { ...open.facts, ...outcome.facts } })
  }
  const live = open => { if (open.controller.signal.aborted) throw refusal('media_not_allowed') }

  /** The text cache's windows of a PDF that still live. */
  const windowsOf = entry => (entry?.windows ?? []).filter(window => window.expires > now())
  function pageTexts(windows, from, to) {
    const texts = []
    for (let page = from; page <= to; page++) {
      const window = windows.find(item => item.from <= page && page <= item.to)
      if (!window) return null
      texts.push(window.texts[page - window.from])
    }
    return texts
  }
  /** Adds `window` to the PDF's text; a window it overlaps stays unless it lies wholly inside it. */
  function storePdf(id, textKey, facts, window) {
    const entry = caches.text.get(id, textKey)
    const windows = windowsOf(entry).filter(item => item.from < window.from || item.to > window.to)
    caches.text.set(id, textKey, { kind: 'pdf', facts, windows: [...windows, window].sort((a, b) => a.from - b.from) })
  }

  /** A PDF part, from the text cache (under `textKey`) where it can be; `plaintext` null means no job may run. */
  async function pdfResult(open, id, textKey, facts, request, plaintext) {
    let windows = windowsOf(caches.text.get(id, textKey)), total = facts.pages
    const read = async (from, count) => {
      if (!plaintext) return null
      const output = await job(open, 'pdf', pdfTextJob(from, count), plaintext)
      live(open)
      total = output.header.pages
      facts.pages = total
      if (total > PDF_MAX_PAGES && !facts.truncated.includes('page_cap')) facts.truncated = [...facts.truncated, 'page_cap']
      if (from > lastPage(total)) throw refusal('invalid_cursor')
      const window = pdfWindow(output, from, now() + TEXT_TTL_MS)
      if (!window) throw refusal('parser_failed')
      storePdf(id, textKey, facts, window)
      windows = [window]
      return window
    }
    if (request.cursor?.unit === 'char') throw refusal('invalid_cursor')
    // Page images are re-encoded by sharp, the image kind's parser: with
    // `image` off they are withheld and the part is text only (§16.3).
    const withImages = request.images && !stateOf(id).mediaOff.includes('image')
    let part, wanted = []
    if (request.pages) {
      const { from, to } = request.pages
      if (to > lastPage(total ?? PDF_MAX_PAGES)) throw refusal('invalid_cursor')
      if (!pageTexts(windows, from, to) && !(await read(from, to - from + 1))) return null
      if (to > lastPage(total)) throw refusal('invalid_cursor')
      const window = windows.find(item => item.from <= from && from <= item.to)
      const end = Math.min(to, pageTexts(windows, from, to) ? to : window.to)
      const texts = pageTexts(windows, from, end)
      part = pagesPart({ from, to: end }, page => texts[page - from])
      // Pages whose text did not fit follow by cursor, and so do their images.
      if (part.part.to < to) part.next = `p${part.part.to + 1}`
      if (withImages) wanted = Array.from({ length: part.part.to - from + 1 }, (_, index) => from + index)
      else part.withheld = request.images ? 'kind_off' : 'request'
    } else {
      const at = request.cursor?.at ?? 1
      if (at > lastPage(total ?? PDF_MAX_PAGES)) throw refusal('invalid_cursor')
      const window = windows.find(item => item.from <= at && at <= item.to) ?? await read(at, Math.min(PDF_PAGES_PER_JOB, PDF_MAX_PAGES - at + 1))
      if (!window) return null
      part = pdfPart(window, at, total, withImages)
      if (part.withheld && request.images) part.withheld = 'kind_off'
      wanted = part.wanted
    }
    if (wanted.length && !plaintext) return null
    let images = []
    if (wanted.length) {
      // Its pixels go through sharp: `image` switched off now ends this job too.
      open.kinds = ['pdf', 'image']
      images = (await job(open, 'pdf', pdfImagesJob(wanted), plaintext)).images
      live(open)
    }
    const extra = { scanned_pages: part.scannedPages.length ? part.scannedPages : undefined, image_pages: images.length ? images.map(image => image.page) : undefined }
    return finish(facts, { body: part.body, part: part.part, next: part.next, images, withheld: part.withheld, tooLong: part.tooLong, extra, suggest: part.suggest })
  }

  /** Step 6: a part the text cache already holds, or null. */
  function fromText(id, textKey, request) {
    const entry = caches.text.get(id, textKey)
    const state = connections.get(id)
    if (!entry || state?.mediaOff.includes(entry.kind)) return null
    const facts = { ...entry.facts, truncated: [...entry.facts.truncated] }
    if (entry.kind === 'pdf') return pdfResult(null, id, textKey, facts, request, null)
    if (request.pages || request.cursor?.unit === 'page') throw refusal('invalid_cursor')
    const part = charPart(entry.text, request.cursor)
    return finish(facts, { body: part.body, part: part.part, next: part.next })
  }

  /** The open itself (§16.5 "An open"), in the slot. */
  async function perform(open, record, row, request, plan, access) {
    const id = record.connection_id
    const media = row.media
    const signal = open.controller.signal
    let opened, stream
    try {
      if (plan.preview) {
        opened = await access.open(row, 'thumbnail')
        live(open)
        const seconds = typeof media.seconds === 'number' && Number.isFinite(media.seconds) && media.seconds >= 0 ? media.seconds : undefined
        const facts = factsOf(row, opened, { sniffed: 'thumbnail', seconds_claimed: seconds }, open.link)
        const thumbnail = opened.thumbnail
        if (!thumbnail?.length) return finish(facts)
        if (thumbnail.length > THUMB_MAX_BYTES) throw refusal('attachment_too_large', { facts: { ...open.facts, size: thumbnail.length, cap: THUMB_MAX_BYTES, family: 'image' } })
        const found = sniff(thumbnail, null)
        if (!found || found.kind !== 'image') throw refusal('attachment_unsupported')
        if (stateOf(id).mediaOff.includes('image')) throw refusal('media_not_allowed')
        if (!request.images) return finish(facts, { withheld: 'request' })
        const output = await job(open, 'image', imageJob('thumb', found.sniffed), Buffer.from(thumbnail.buffer, thumbnail.byteOffset, thumbnail.byteLength))
        live(open)
        return finish(facts, { images: output.images, extra: { animated: output.header.animated || undefined } })
      }
      opened = await access.open(row, 'key')
      live(open)
      if (!(opened.key instanceof Uint8Array) || opened.key.length !== 32) throw refusal('attachment_tampered')
      const cap = CAP_BYTES[plan.family]
      await fetchCiphertext({
        fetch, archive, uid: row.uid, apiKey: record.api_key, cap, family: plan.family, signal,
        charge: bytes => {
          const wait = budgets.bytesWait(id, bytes)
          if (wait > 0) throw refusal('rate_limited', { retry_after_s: retryAfter(wait) })
          budgets.charge(id, bytes)
        },
        begin: length => (stream = createMediaStream({ mediaKey: opened.key, label: plan.label, length })),
      })
      live(open)
      opened.key.fill(0)
      const plaintext = stream.finish(plan.encSHA256)
      const sniffed = sniff(plaintext, media.mimetype)
      if (!sniffed || (plan.family === 'image' && sniffed.kind !== 'image')) throw refusal('attachment_unsupported')
      const off = stateOf(id).mediaOff
      if (sniffed.kind === 'office') {
        open.kinds = ['office', 'zip'].filter(kind => !off.includes(kind))
        if (!open.kinds.length) throw refusal('media_not_allowed')
      } else {
        if (off.includes(sniffed.kind)) throw refusal('media_not_allowed')
        open.kinds = [sniffed.kind]
      }
      if ((sniffed.kind !== 'pdf' && request.pages) || (sniffed.kind === 'image' && request.cursor)) throw refusal('invalid_cursor')
      if (sniffed.kind === 'image') {
        const facts = factsOf(row, opened, { sniffed: sniffed.sniffed }, open.link)
        if (!request.images) return finish(facts, { withheld: 'request' })
        const op = media.media_type === 'sticker' ? 'sticker' : 'photo'
        const output = await job(open, 'image', imageJob(op, sniffed.sniffed), plaintext)
        live(open)
        return finish(facts, { images: output.images, extra: { animated: output.header.animated || undefined } })
      }
      if (sniffed.kind === 'pdf') {
        const entry = caches.text.get(id, open.textKey)
        const facts = entry?.kind === 'pdf' ? { ...entry.facts, truncated: [...entry.facts.truncated] } : factsOf(row, opened, { sniffed: 'pdf' }, open.link)
        return await pdfResult(open, id, open.textKey, facts, request, plaintext)
      }
      if (request.cursor?.unit === 'page') throw refusal('invalid_cursor')
      // Plain text is decoded here; an office file or a zip is the office worker's.
      let text, found
      if (sniffed.kind === 'text') {
        const decoded = decodeText(plaintext)
        text = decoded.text
        found = { sniffed: 'text', truncated: decoded.cut ? ['text_cap'] : [] }
      } else {
        const output = await job(open, 'office', officeJob(open.kinds), plaintext)
        live(open)
        ;({ text, found } = renderOffice(output))
        open.kinds = [output.header.sniffed === 'zip' ? 'zip' : 'office']
      }
      const facts = factsOf(row, opened, found, open.link)
      caches.text.set(id, open.textKey, { kind: open.kinds[0], facts, text })
      const part = charPart(text, request.cursor)
      return finish(facts, { body: part.body, part: part.part, next: part.next })
    } finally {
      opened?.key?.fill(0)
      opened?.thumbnail?.fill(0)
      stream?.wipe()
    }
  }

  async function run(open, record, row, request, plan, access) {
    let outcome
    try { outcome = { result: await perform(open, record, row, request, plan, access) } } catch (error) {
      if (error instanceof ArchiveError || error instanceof LocalConfigError) error.facts = { ...open.facts, ...error.facts }
      outcome = { error }
    }
    settle(open, outcome)
  }

  /** Step 5: this key's kept outcome, answered (a kept refusal is thrown), or its running open to join; else null. */
  function known(state, id, key) {
    const kept = caches.result.get(id, key)
    if (kept) {
      if (kept.outcome.error) throw kept.outcome.error
      return { result: copy(kept.outcome.result) }
    }
    const open = state.opens.get(key)
    return open ? { open } : null
  }
  /** Step 7: room for one more open of this connection (its line not full, OPENS_PER_MINUTE), else `rate_limited`. */
  function budget(state, id, facts) {
    if (state.active && state.line.length >= OPENS_QUEUE_MAX) throw refusal('rate_limited', { retry_after_s: 10, facts })
    const opensWait = budgets.opensWait(id)
    if (opensWait > 0) throw refusal('rate_limited', { retry_after_s: retryAfter(opensWait), facts })
  }

  /**
   * A waiting call's `retry_after_s` (§16.9): 5 while its open runs, 10 when
   * it runs next (first in the slot's queue, or first in its connection's
   * line behind a running open with no queue), 20 behind that.
   */
  function retryOf(open) {
    const state = connections.get(open.id)
    const index = state ? state.line.indexOf(open) : -1
    if (index < 0) {
      const position = scheduler.position(open)
      return position === 'running' || position === null ? 5 : position === 0 ? 10 : 20
    }
    return index === 0 && scheduler.position(state.active) === 'running' && scheduler.queued() === 0 ? 10 : 20
  }

  /** Step 18: the open's answer, or `pending` once the host's wait is over, whether it runs or waits its turn. */
  async function wait(open, started, host) {
    const remaining = started + waitFor(host) - now()
    if (!open.done && remaining > 0) {
      const stop = new AbortController()
      await Promise.race([open.settled, delay(remaining, stop.signal)])
      stop.abort()
    }
    if (open.done) {
      if (open.outcome.error) throw open.outcome.error
      return copy(open.outcome.result)
    }
    return pending(open.uid, open.facts.media_type, retryOf(open), open.link)
  }

  /** One open_attachment call (§16.5 "A call"), steps 3 to 18. */
  async function call(record, input, access, host) {
    const id = record.connection_id
    const started = now()
    try {
      const request = parseRequest(input)
      if (record.media !== true) throw refusal('media_not_allowed')
      if (!ready()) throw refusal('media_unavailable')
      const status = await checkActive.mediaStatus(id)
      if (status.answer === 'reseal') throw new LocalConfigError('reconsent_required')
      if (status.answer !== 'serve' || status.media !== true) throw refusal('media_not_allowed')
      const state = stateOf(id)
      state.mediaOff = knownKinds(status.media_off)
      const key = numbered(input.device_id, openKey(input)), textKey = numbered(input.device_id, input.uid)
      let found = known(state, id, key)
      if (!found) {
        const cached = await fromText(id, textKey, request)
        if (cached) return copy(cached)
        budget(state, id)
        const row = await access.row()
        // From here every answer names this message: it carries the console link (§16.7).
        const link = linkOf(record, row)
        const facts = rowFacts(row, link)
        const plan = checkRow(row, request, state.mediaOff, link)
        if (plan.preview && !plan.hasPreview) {
          const seconds = typeof row.media.seconds === 'number' && Number.isFinite(row.media.seconds) && row.media.seconds >= 0 ? row.media.seconds : undefined
          return finish(factsOf(row, null, { sniffed: 'thumbnail', seconds_claimed: seconds }, link))
        }
        if (!plan.preview) {
          const bytesWait = budgets.bytesWait(id, Number.isSafeInteger(row.media.file_length) ? row.media.file_length : CAP_BYTES[plan.family])
          if (bytesWait > 0) throw refusal('rate_limited', { retry_after_s: retryAfter(bytesWait), facts })
        }
        // Steps 5 and 7 again, with nothing awaited from here to the queue:
        // while the text cache and the row were read, a parallel call of this
        // connection may have started or finished this key's open, or started
        // another, and a wipe may have ended the connection's media.
        if (connections.get(id) !== state) throw refusal('media_not_allowed', { facts })
        found = known(state, id, key)
        if (!found) {
          budget(state, id, facts)
          const open = { id, key, textKey, uid: row.uid, facts, link, kinds: plan.kind ? [plan.kind] : [], controller: new AbortController(), done: false, outcome: null, reason: null }
          open.settled = new Promise(resolve => { open.resolve = resolve })
          open.start = () => run(open, record, row, request, plan, access)
          // Step 17: the slot or its queue when this connection has nothing
          // there, else behind its own open, in its line.
          if (state.active) state.line.push(open)
          else if (scheduler.admit(open, open.start, () => leave(open))) state.active = open
          else throw refusal('media_busy', { retry_after_s: 20, facts })
          budgets.admit(id)
          state.opens.set(key, open)
          found = { open }
        }
      }
      return found.result ?? await wait(found.open, started, host)
    } catch (error) {
      log.event('media_refused', { ...conn(id), code: safeCode(error) })
      throw error
    }
  }

  return {
    /** The boot check (§16.6), once; a failure keeps attachments off for this boot and is logged once. */
    async start() {
      if (jailState) return jailState
      try { jailState = await jail.checkJail() } catch { jailState = { ok: false, code: 'self_check_failed' } }
      if (!jailState.ok) log.event('media_jail_unavailable', { code: jailState.code })
      return jailState
    },
    ready,
    /** `provider.media` for a record whose sealed consent carries `media: true`. */
    forConnection(record) {
      const host = hostOf(record.redirect_host)
      return {
        host,
        why: row => whyNot(row, connections.get(record.connection_id)?.mediaOff ?? []),
        /** The console link of the row's message, or null (§16.7). */
        openURL: row => linkOf(record, row),
        open: (request, access) => call(record, request, access, host),
        /** The serialized result's cap, which server.mjs enforces by dropping images (§16.7). */
        resultMaxBytes: RESULT_MAX_BYTES,
      }
    },
    /** Ends everything of a connection's media: its open, its queue entries, both caches (§16.9). */
    wipe(id, reason = 'revoked') {
      const state = connections.get(id)
      // Its line first, so that the open leaving the slot's queue hands nothing in.
      for (const open of state?.line.splice(0) ?? []) abort(open, reason)
      for (const open of [...(state?.opens.values() ?? [])]) abort(open, reason)
      caches.drop(id)
      if (reason === 'revoked') { connections.delete(id); budgets.forget(id) }
      else if (state) state.opens.clear()
    },
    /** A status answer's `media_off`: the open and the cache entries of a kind now off go. */
    narrow(id, mediaOff) {
      const off = knownKinds(mediaOff)
      const state = stateOf(id)
      state.mediaOff = off
      if (!off.length) return
      for (const open of [...state.opens.values()]) if (open.kinds.some(kind => off.includes(kind))) abort(open, 'media_off')
      caches.dropKinds(id, off)
    },
    /** Opens finished and jobs killed since the last call, and opens waiting now (the slot's queue and every connection's line). */
    counts() {
      let queue = scheduler.queued()
      for (const state of connections.values()) queue += state.line.length
      const counts = { opens: counters.opens, queue, killed: counters.killed }
      counters.opens = 0
      counters.killed = 0
      return counts
    },
    close() {
      closed = true
      for (const [id] of [...connections]) this.wipe(id)
      caches.clear()
    },
    /** For tests: the caches and the slot. */
    get caches() { return caches },
    get scheduler() { return scheduler },
  }
}

