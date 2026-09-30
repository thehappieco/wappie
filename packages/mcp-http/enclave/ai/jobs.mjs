// AI jobs (docs/mcp-enclave.md §18.10): one function run for one message
// under one AI authorization, keyed `${authorization}|${device}|${uid}|${feature}`
// so that an identical request, a redo too, joins the job in flight.
//
// The queue: AI_CALLS_IN_FLIGHT jobs run at once enclave-wide, at most one
// per authorization; up to AI_LINE_MAX more of one authorization wait in its
// line and up to AI_QUEUE_MAX in all, first in first out, connector jobs
// ahead of console jobs; past either, `ai_busy`. A finished job's state is
// kept AI_JOB_TTL_MS. Wiping an authorization aborts its jobs (the fetch, the
// provider call and a jailed job through their signals); nothing of an
// aborted job is stored, and only a provider call it had already sent is
// charged, at its bound (§18.9).
//
// A job, in order: the gate; the budget; a stored record (without redo);
// the row and its media, opened with the authorization's own grants (I2);
// the configuration tag again with the DSK that opened them (I3a); the
// fetch and its verification; reuse by dedupe tag (§18.8); the jailed
// preparation of an image or a document; the provider call (§18.9), each
// attempt checked against the budget and counted as it leaves; the record
// sealed and stored; the usage counted; every caller answered.
import { createHash, randomBytes } from 'node:crypto'
import { ArchiveError } from '@whatserver2/client'
import { derivedBytes, derivedKey, openDerivedWith } from '@whatserver2/mcp/reader'
import { fingerprint } from '../../log.mjs'
import { fetchCiphertext } from '../media/fetch.mjs'
import { refusal } from '../media/gate.mjs'
import { MEDIA_TYPES, PDF_MAX_PAGES, PDF_PAGES_PER_JOB, JOB_TEXT_MAX_BYTES, IMAGES_PER_RESULT } from '../media/policy.mjs'
import { cut, renderOffice, scanned } from '../media/result.mjs'
import { cleanText, decodeText, sniff } from '../media/sniff.mjs'
import { createMediaStream } from '../media/wamedia-stream.mjs'
import { costOf, measure, reported } from './budget.mjs'
import { dedupeTag, reusable } from './dedupe.mjs'
import { makeRecord, sealDerivedWith } from './derived.mjs'
import { classify, EgressError, errorFacts } from './egress.mjs'
import { PROVIDERS } from './install.mjs'
import {
  AI_CALLS_IN_FLIGHT, AI_CAP_BYTES, AI_ERROR_EFFECTS, AI_GOOGLE_REQUEST_MAX_BYTES, AI_JOB_TTL_MS, AI_LINE_MAX, AI_MAX_SECONDS,
  AI_OPENAI_AUDIO_MAX_BYTES, AI_QUEUE_MAX, AI_RETRIES, AI_TEXT_MAX_CHARS, promptVersion,
} from './policy.mjs'
import { recordTagHolds } from './tags.mjs'

/**
 * A job's refusal: an ArchiveError with its code (and `retry_after_s` where
 * it has one; `limit`, `month` or `day`, for `ai_budget_reached`).
 */
export function aiRefusal(code, extra) {
  const error = refusal(code, extra)
  if (extra?.limit === 'month' || extra?.limit === 'day') error.limit = extra.limit
  return error
}

// ---- The queue -------------------------------------------------------------------

/**
 * The queue of every authorization's jobs. `submit(spec, run)` joins the job
 * in flight under `spec.key`, or creates one and queues it (throwing
 * `ai_busy` past AI_LINE_MAX or AI_QUEUE_MAX); `run(job)` does its work once
 * it is picked, under `job.controller.signal`, and resolves to its outcome.
 */
export function createQueue({ now = Date.now, callsInFlight = AI_CALLS_IN_FLIGHT, lineMax = AI_LINE_MAX, queueMax = AI_QUEUE_MAX, ttlMs = AI_JOB_TTL_MS } = {}) {
  const jobs = new Map() // id -> job
  const inFlight = new Map() // key -> job not finished
  const running = new Set()
  const waiting = []
  const counters = { jobs: 0, failed: 0 }
  const busyFor = authorization => [...running].some(job => job.authorization_id === authorization)
  /** The next waiting job: connector jobs first, each authorization one at a time. */
  function next() {
    for (const origin of ['connector', 'console']) {
      const index = waiting.findIndex(job => job.origin === origin && !busyFor(job.authorization_id))
      if (index >= 0) return waiting.splice(index, 1)[0]
    }
    return null
  }
  function pump() {
    while (running.size < callsInFlight) {
      const job = next()
      if (!job) return
      start(job)
    }
  }
  function start(job) {
    running.add(job)
    job.state = 'running'
    job.started_at = now()
    Promise.resolve().then(() => job.run(job)).then(outcome => finish(job, outcome), error => finish(job, { error }))
  }
  function finish(job, outcome) {
    if (job.state === 'done' || job.state === 'failed') return
    running.delete(job)
    if (inFlight.get(job.key) === job) inFlight.delete(job.key)
    const index = waiting.indexOf(job)
    if (index >= 0) waiting.splice(index, 1)
    job.outcome = job.controller.signal.aborted ? { error: job.abortError ?? aiRefusal('ai_paused') } : outcome
    job.state = job.outcome.error ? 'failed' : 'done'
    job.finished_at = now()
    counters.jobs++
    if (job.outcome.error) counters.failed++
    job.resolve(job.outcome)
    sweep()
    pump()
  }
  function sweep() {
    for (const [id, job] of jobs) if (job.finished_at !== undefined && now() - job.finished_at > ttlMs) jobs.delete(id)
  }
  return {
    submit(spec, run) {
      const joined = inFlight.get(spec.key)
      if (joined) { joined.requesters.add(spec.requester_id); return joined }
      const line = waiting.filter(job => job.authorization_id === spec.authorization_id).length
      if (line >= lineMax || waiting.length >= queueMax) throw aiRefusal('ai_busy', { retry_after_s: 20 })
      const job = { ...spec, id: randomBytes(16).toString('base64url'), requesters: new Set([spec.requester_id]), controller: new AbortController(),
        state: 'queued', created_at: now(), run, outcome: null }
      job.settled = new Promise(resolve => { job.resolve = resolve })
      jobs.set(job.id, job)
      inFlight.set(job.key, job)
      waiting.push(job)
      pump()
      return job
    },
    get(id) { sweep(); return jobs.get(id) },
    /** A waiting caller's `retry_after_s` (§18.12): 5 while its job runs, 10 when it runs next, 20 behind that. */
    retryOf(job) {
      if (job.state === 'running' || !waiting.includes(job)) return 5
      const order = [...waiting.filter(other => other.origin === 'connector'), ...waiting.filter(other => other.origin !== 'connector')]
      return order.find(other => !busyFor(other.authorization_id)) === job ? 10 : 20
    },
    /** Aborts every job of an authorization: `error` is what their callers answer. */
    abort(authorization, error) {
      for (const job of [...waiting, ...running]) {
        if (job.authorization_id !== authorization) continue
        job.abortError = error
        job.controller.abort()
        if (waiting.includes(job)) finish(job, { error })
      }
    },
    /** Aborts the jobs of one function or provider of an authorization (a narrowing). */
    abortWhere(authorization, test, error) {
      for (const job of [...waiting, ...running]) {
        if (job.authorization_id !== authorization || !test(job)) continue
        job.abortError = error
        job.controller.abort()
        if (waiting.includes(job)) finish(job, { error })
      }
    },
    counts() {
      const counts = { jobs: counters.jobs, failed: counters.failed, queue: waiting.length, in_flight: running.size }
      counters.jobs = 0
      counters.failed = 0
      return counts
    },
    clear() { for (const job of [...waiting, ...running]) { job.controller.abort(); finish(job, { error: aiRefusal('ai_paused') }) } jobs.clear() },
  }
}

// ---- One job ---------------------------------------------------------------------

/** Which messages a function takes (§18.3). `gif` is a video with `is_gif`, an image's. */
export function functionOf(row) {
  const type = row?.media?.media_type
  if (type === 'audio' || type === 'ptt') return 'audio'
  if (type === 'video' || type === 'ptv') return row.media.is_gif === true ? 'image' : 'video'
  if (type === 'image' || type === 'sticker') return 'image'
  if (type === 'document') return 'document'
  return null
}

const hash32 = value => {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null
  const decoded = Buffer.from(value, 'base64')
  return decoded.length === 32 && decoded.toString('base64') === value ? decoded : null
}
const claimedSeconds = row => (typeof row.media.seconds === 'number' && Number.isFinite(row.media.seconds) && row.media.seconds >= 0 ? row.media.seconds : undefined)

/**
 * Step 4 on the row alone: the message fits the function, is not view-once,
 * and (but a GIF's preview) is downloaded, verifiable, within
 * AI_CAP_BYTES[feature] and, for audio and video, within the claimed
 * AI_MAX_SECONDS. The sender's claims only spare a call the provider would
 * refuse; the charge never rests on them.
 */
export function checkAIRow(row, feature) {
  const media = row.media
  if (functionOf(row) !== feature) throw aiRefusal('ai_unsupported')
  if (row.view_once === true) throw aiRefusal('view_once_excluded')
  const type = MEDIA_TYPES[media.media_type]
  if (feature === 'image' && type.family === 'video') {
    if (typeof media.thumb_sealed !== 'string' || !media.thumb_sealed) throw aiRefusal('ai_unsupported')
    return { preview: true, label: type.label, family: type.family }
  }
  if (media.download_status !== 'done') {
    if (['pending', 'downloading', 'failed'].includes(media.download_status)) throw aiRefusal('attachment_pending')
    if (media.download_status === 'gone') throw aiRefusal('attachment_expired')
    throw aiRefusal('read_failed')
  }
  const encSHA256 = hash32(media.file_enc_sha256)
  if (typeof media.media_key_sealed !== 'string' || !media.media_key_sealed || !encSHA256) throw aiRefusal('attachment_unverifiable')
  if (media.file_length !== undefined && (!Number.isSafeInteger(media.file_length) || media.file_length > AI_CAP_BYTES[feature])) throw aiRefusal('ai_too_large')
  const seconds = claimedSeconds(row)
  if ((feature === 'audio' || feature === 'video') && seconds !== undefined && seconds > AI_MAX_SECONDS[feature]) throw aiRefusal('ai_too_large')
  return { preview: false, label: type.label, family: type.family, encSHA256 }
}

const ascii = (bytes, at, text) => bytes.length >= at + text.length && [...text].every((char, index) => bytes[at + index] === char.charCodeAt(0))
/**
 * The container of an audio or video plaintext, by its first bytes (the
 * filename and `mimetype` are never trusted): `{container, mimeType}`, or
 * null. Video in B1 is an mp4.
 */
export function mediaContainer(bytes, feature) {
  if (ascii(bytes, 4, 'ftyp')) {
    const brand = bytes.subarray(8, 12).toString('latin1')
    if (feature === 'video') return { container: 'mp4', mimeType: 'video/mp4' }
    return brand === 'M4A ' || brand === 'M4B ' ? { container: 'm4a', mimeType: 'audio/mp4' } : { container: 'mp4', mimeType: 'audio/mp4' }
  }
  if (feature !== 'audio') return null
  if (ascii(bytes, 0, 'OggS')) return { container: 'ogg', mimeType: 'audio/ogg' }
  if (bytes.length >= 4 && bytes[0] === 0x1a && bytes[1] === 0x45 && bytes[2] === 0xdf && bytes[3] === 0xa3) return { container: 'webm', mimeType: 'audio/webm' }
  if (ascii(bytes, 0, 'RIFF') && ascii(bytes, 8, 'WAVE')) return { container: 'wav', mimeType: 'audio/wav' }
  if (ascii(bytes, 0, 'ID3') || (bytes.length >= 2 && bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0)) return { container: 'mp3', mimeType: 'audio/mpeg' }
  return null
}

/**
 * A 200 answer as §18.9's "Answers" read it, in order: a safety stop is a
 * `refused` record with no text; any other Google finish reason but STOP and
 * MAX_TOKENS is `ai_provider_failed`; an empty text is `no_speech` for
 * OpenAI's transcription and otherwise `ai_output_limit` (stopped at the
 * limit) or `ai_provider_failed`; a stop at the limit with text flags
 * `partial`. Control characters are removed as §16.11 says, white space
 * trimmed, and the text cut at AI_TEXT_MAX_CHARS (`cut`).
 */
export function interpret(provider, route, json) {
  const read = PROVIDERS[provider].answer(json, route)
  let text = cleanText(read.text).trim()
  const flags = []
  if (text.length > AI_TEXT_MAX_CHARS) { text = cut(text, AI_TEXT_MAX_CHARS); flags.push('cut') }
  if (read.stop === 'refusal') return { text: '', flags: ['refused'], usage: read.usage }
  if (read.stop === 'failed') return { code: 'ai_provider_failed', usage: read.usage }
  if (!text) {
    if (provider === 'openai' && route === 'transcriptions') return { text: '', flags: ['no_speech'], usage: read.usage }
    return { code: read.stop === 'max_tokens' ? 'ai_output_limit' : 'ai_provider_failed', usage: read.usage }
  }
  if (read.stop === 'max_tokens') flags.push('partial')
  return { text, flags, usage: read.usage }
}

const delay = (ms, signal) => new Promise(resolve => {
  const timer = setTimeout(resolve, ms)
  signal?.addEventListener('abort', () => { clearTimeout(timer); resolve() }, { once: true })
})

/**
 * The provider call (§18.9) with its retries: a 429 that is not a spent
 * quota, a 5xx, a timeout or a network error is tried again after each of
 * AI_RETRIES, then `ai_provider_failed`. Resolves to `{status: 200, json,
 * bytesOut}` or `{code}`.
 *
 * Each attempt is a call of its own (§18.10): `attempt()` runs before it
 * leaves, to check the budget again (it throws to stop) and count the day's
 * item; `failed({answered, sent, bytesOut})` after each attempt that did not
 * end in a 200, where `answered` is a non-200 answer (never charged) and
 * `sent` a request the transport had when it failed unanswered (a timeout,
 * a dropped connection, an abort, an answer too large), which the caller
 * charges at its bound: the provider may have it whole and bill it.
 */
export async function callProvider(egress, provider, key, request, { signal, attempt = () => {}, failed = () => {} }) {
  for (let n = 0; n <= AI_RETRIES.length; n++) {
    if (n > 0) { await delay(AI_RETRIES[n - 1], signal); if (signal.aborted) throw new EgressError('aborted') }
    attempt()
    let response
    try { response = await egress.request(provider, key, { ...request, signal }) } catch (error) {
      failed({ answered: false, sent: error?.sent === true, bytesOut: error?.bytesOut ?? 0 })
      if (error?.code === 'aborted' || signal.aborted) throw new EgressError('aborted')
      if (error?.code === 'timeout' || error?.code === 'network') continue
      return { code: 'ai_provider_failed' }
    }
    if (response.status === 200) return { status: 200, json: response.json, bytesOut: response.bytesOut, route: response.route }
    failed({ answered: true, sent: true, bytesOut: response.bytesOut })
    const verdict = classify(provider, response.route, response.status, errorFacts(provider, response.json))
    if (verdict !== 'retry') return { code: verdict }
  }
  return { code: 'ai_provider_failed' }
}

/**
 * Runs one job's steps 3 to 12 for `job` under `record` (step 1 and 2, the
 * gate and the budget, ran as it was picked; the budget runs again before
 * each attempt at the call). `ctx` is the AI service's: `{log, now, relay,
 * egress, budgets, reader, keys(record), status, media, archive, fetch,
 * pause(record, code, where), usage(record, job, counts), readStored(record,
 * device, uid, feature, keys), storedOf(…same)}`. Resolves to `{record}` (the
 * derived record, opened), with `stored`, `reused` or `unstored` saying how.
 */
export async function runJob(ctx, record, job) {
  const signal = job.controller.signal
  const { device_id, uid, feature } = job
  const entry = record.functions[feature]
  const lang = record.features[device_id]?.[feature]?.lang
  const version = promptVersion(feature)
  const conn = { conn: fingerprint(record.connection_id) }
  const live = () => { if (signal.aborted) throw job.abortError ?? aiRefusal('ai_paused') }
  return ctx.reader.aiJob({ device_id, uid }, async ({ row: readRow, open, keys }) => {
    live()
    // I3a first: nothing is fetched, tagged or sent under a DSK the stored tag does not hold.
    if (!recordTagHolds(record, device_id, keys)) { ctx.log.event('ai_tag_mismatch', conn); throw aiRefusal('grant_mismatch') }
    const scope = { namespace: keys.namespace, device_id, epoch: keys.epoch }
    // 3. A stored record, unless this is a redo.
    if (!job.redo) {
      const stored = await ctx.readStored(record, device_id, uid, feature, keys)
      if (stored) return { record: stored, stored: true }
    }
    // 4. The row and its media.
    const row = await readRow()
    live()
    const plan = checkAIRow(row, feature)
    const off = ctx.status(record)?.media_off ?? []
    if ((feature === 'audio' || feature === 'video') && off.includes(feature)) throw aiRefusal('media_not_allowed')
    // 5. Fetch and verify (the preview for a GIF), with this record's key.
    let opened, stream, plaintext
    try {
      if (plan.preview) {
        opened = await open(row, 'thumbnail')
        live()
        if (!opened.thumbnail?.length) throw aiRefusal('ai_unsupported')
        plaintext = Buffer.from(opened.thumbnail.buffer, opened.thumbnail.byteOffset, opened.thumbnail.byteLength)
      } else {
        opened = await open(row, 'key')
        live()
        if (!(opened.key instanceof Uint8Array) || opened.key.length !== 32) throw aiRefusal('attachment_tampered')
        try {
          await fetchCiphertext({
            fetch: ctx.fetch, archive: ctx.archive, uid: row.uid, apiKey: record.api_key, cap: AI_CAP_BYTES[feature], family: plan.family, signal,
            charge: () => {}, begin: length => (stream = createMediaStream({ mediaKey: opened.key, label: plan.label, length })),
          })
        } catch (error) {
          if (error?.code === 'attachment_too_large') throw aiRefusal('ai_too_large')
          throw error
        }
        live()
        opened.key.fill(0)
        plaintext = stream.finish(plan.encSHA256)
      }
      const source_sha256 = createHash('sha256').update(plaintext).digest('hex')
      const tagInput = { source_sha256, feature, provider: entry.provider, model: entry.model, prompt_version: version, lang }
      // 6. Reuse: a record of this file, function, provider, model, prompt version and language, on any number of the authorization.
      if (!job.redo) {
        const reused = await findReusable(ctx, record, job, keys, tagInput)
        live()
        if (reused) {
          const copy = makeRecord({ ...reused, feature })
          const outcome = await store(ctx, record, job, row, keys, scope, copy, tagInput)
          ctx.usage(record, job, { reused: 1 })
          ctx.log.event('ai_reused', conn)
          return { ...outcome, reused: true }
        }
      }
      // 7. Prepare what the provider receives.
      const prepared = await prepare(ctx, record, job, row, plaintext, off, signal)
      live()
      // 9. The call (the tag held at step 8, above).
      const module = PROVIDERS[entry.provider]
      const request = module.build(feature, { model: entry.model, lang, ...prepared })
      if (!request) throw aiRefusal('ai_unsupported')
      if (entry.provider === 'openai' && feature === 'audio' && plaintext.length > AI_OPENAI_AUDIO_MAX_BYTES) throw aiRefusal('ai_too_large')
      if (entry.provider === 'google' && Buffer.byteLength(JSON.stringify(request.body)) > AI_GOOGLE_REQUEST_MAX_BYTES) throw aiRefusal('ai_too_large')
      const rate = record.budget.rates[`${entry.provider}:${entry.model}`]
      const claimed = claimedSeconds(row)
      /** Charges `usage` (a 200's, or `{}` for a call sent and never answered) and posts it: the cost by `measure`'s bounds, the counts as reported. */
      const charge = (usage, bytesOut, counted) => {
        const bounds = measure(feature, usage, { bodyBytes: bytesOut, plaintextBytes: plaintext.length, claimedSeconds: claimed })
        const cost = costOf(rate, bounds)
        const counts = reported(feature, usage, bounds, rate, claimed)
        ctx.budgets.charge(record.connection_id, cost)
        ctx.usage(record, job, { ...counted, ...counts, cost_microcents: cost })
        return counts
      }
      let answer
      try {
        answer = await callProvider(ctx.egress, entry.provider, ctx.keys(record)?.[entry.provider], request, {
          signal,
          // Every attempt is a call (§18.10): the budget again before it leaves, and the day's item counted.
          attempt: () => {
            const limit = ctx.budgets.limit(record, ctx.status(record))
            if (limit) { ctx.log.event('ai_budget_reached', conn); throw aiRefusal('ai_budget_reached', { limit }) }
            ctx.budgets.item(record.connection_id)
          },
          // A failed attempt is counted; one sent and never answered is charged at its bound (§18.9).
          failed: ({ answered, sent, bytesOut }) => {
            if (!answered && sent) charge({}, bytesOut, { failures: 1 })
            else ctx.usage(record, job, { failures: 1 })
          },
        })
      } catch (error) {
        if (error?.code === 'aborted') throw job.abortError ?? aiRefusal('ai_paused')
        throw error
      }
      if (answer.code) {
        if (AI_ERROR_EFFECTS[answer.code]) ctx.pause(record, answer.code, { provider: entry.provider, feature })
        throw aiRefusal(answer.code)
      }
      // 11. Every 200 answer is charged by its usage, a record or not (the counts go to Go).
      const read = interpret(entry.provider, answer.route, answer.json)
      const counts = charge(read.usage, answer.bytesOut, { items: 1 })
      if (read.code) throw aiRefusal(read.code)
      // 10. The record, sealed and stored, with the counts its usage row reports.
      const made = makeRecord({
        feature, text: read.text, lang, provider: entry.provider, model: entry.model, prompt_version: version, created_at: new Date(ctx.now()).toISOString(),
        source_sha256, usage: { input_tokens: counts.input_tokens, output_tokens: counts.output_tokens, ...(feature === 'audio' || feature === 'video' ? { seconds: counts.seconds } : {}) },
        flags: [...read.flags, ...(job.redo ? ['redo'] : [])],
      })
      return await store(ctx, record, job, row, keys, scope, made, tagInput)
    } finally {
      opened?.key?.fill(0)
      opened?.thumbnail?.fill(0)
      stream?.wipe()
      if (plan.preview) plaintext?.fill(0)
    }
  })
}

/**
 * Step 6: tags for every number of the authorization (§18.8), each from its
 * own DSK (a number whose stored configuration tag its DSK does not hold is
 * left out, as I3a would), one lookup at Go, and the first hit that opens
 * with its number's key and matches the job, or null.
 */
async function findReusable(ctx, record, job, keys, tagInput) {
  const numbers = new Map()
  const add = (device, k) => numbers.set(device, { tag: dedupeTag(k.dsk, { namespace: k.namespace, device_id: device, epoch: k.epoch }, tagInput), key: derivedKey(k.dsk, { namespace: k.namespace, device_id: device, epoch: k.epoch }), namespace: k.namespace, epoch: k.epoch })
  try {
    add(job.device_id, keys)
    const others = record.device_ids.filter(device => device !== job.device_id)
    if (others.length) {
      await ctx.reader.aiKeys(others, (device, k) => {
        if (!recordTagHolds(record, device, k)) { ctx.log.event('ai_tag_mismatch', { conn: fingerprint(record.connection_id) }); return }
        add(device, k)
      })
    }
    const tags = [...numbers].map(([device, value]) => `${device}.${value.tag.toString('base64url')}`).join(',')
    let answer
    try { answer = await ctx.relay.ai(record.connection_id, record.api_key, 'GET', 'ai/derived', { query: { feature: tagInput.feature, tags } }) } catch { return null }
    if (answer.status !== 200 || !Array.isArray(answer.data?.items)) return null
    for (const item of answer.data.items) {
      const number = numbers.get(item?.device_id)
      const sealed = derivedBytes(item?.sealed)
      if (!number || !sealed || item.epoch !== number.epoch || item.feature !== tagInput.feature || typeof item.message_uid !== 'string') continue
      try {
        const found = openDerivedWith(number.key, { namespace: number.namespace, device_id: item.device_id, message_uid: item.message_uid, feature: tagInput.feature, epoch: item.epoch }, sealed)
        if (reusable(found, tagInput)) return found
      } catch { /* a record this key does not open */ } finally { sealed.fill(0) }
    }
    return null
  } finally { for (const value of numbers.values()) value.key.fill(0) }
}

/**
 * Step 10: the record sealed for this message under the job's number's key
 * and PUT to Go with its dedupe tag. A 409 `derived_exists` (another
 * authorization stored one first) answers with that record instead; when
 * what is stored opens under no key this number's grant holds now (a record
 * of an older epoch, §18.8, which no current grant reads), it is replaced
 * (`redo: true`). A 409 `storage_paused`, or any other failure, answers the
 * caller unstored and logs `ai_store_failed`.
 */
async function store(ctx, record, job, row, keys, scope, made, tagInput) {
  const key = derivedKey(keys.dsk, scope)
  try {
    const sealed = sealDerivedWith(key, { ...scope, message_uid: row.uid, feature: job.feature }, made)
    const tag = dedupeTag(keys.dsk, scope, tagInput)
    const put = async redo => {
      try {
        return await ctx.relay.ai(record.connection_id, record.api_key, 'PUT', `ai/derived/${encodeURIComponent(row.uid)}/${job.feature}`, {
          body: { device_id: job.device_id, epoch: keys.epoch, sealed: sealed.toString('base64url'), dedupe_tag: tag.toString('base64url'), redo },
        })
      } catch { return null }
    }
    let answer = await put(job.redo === true)
    if (answer?.status === 204) return { record: made, stored: true }
    if (answer?.status === 409 && answer.data?.code === 'derived_exists') {
      const stored = await ctx.storedOf(record, job.device_id, row.uid, job.feature, keys)
      if (stored.record) return { record: stored.record, stored: true }
      if (stored.read) {
        answer = await put(true)
        if (answer?.status === 204) return { record: made, stored: true }
      }
    }
    ctx.log.event('ai_store_failed', { conn: fingerprint(record.connection_id) })
    return { record: made, unstored: answer?.data?.code === 'storage_paused' ? 'storage_paused' : 'read_failed' }
  } finally { key.fill(0) }
}

/**
 * Step 7: audio and video as they are (their container sniffed); an image
 * re-encoded, and a document's text and up to 4 page images of a PDF's
 * scanned pages, through §16.5's jailed jobs in the media slot, which is
 * released before the provider call. A kind in `media_off` is
 * `media_not_allowed`; a kind the function does not take, `ai_unsupported`.
 */
async function prepare(ctx, record, job, row, plaintext, off, signal) {
  const { feature } = job
  if (feature === 'audio' || feature === 'video') {
    const found = mediaContainer(plaintext, feature)
    if (!found) throw aiRefusal('ai_unsupported')
    const item = { mimeType: found.mimeType, data: plaintext }
    return { audio: { ...found, data: plaintext }, media: [item] }
  }
  const isPreview = row.media.media_type === 'video' || row.media.media_type === 'ptv'
  const sniffed = sniff(plaintext, row.media.mimetype)
  if (feature === 'image') {
    if (!sniffed || sniffed.kind !== 'image') throw aiRefusal('ai_unsupported')
    if (off.includes('image')) throw aiRefusal('media_not_allowed')
    const op = isPreview ? 'thumb' : row.media.media_type === 'sticker' ? 'sticker' : 'photo'
    const images = await ctx.media.inSlot(signal, async run => (await run('image', ctx.media.JOBS.imageJob(op, sniffed.sniffed), plaintext)).images)
    if (!images?.length) throw aiRefusal('ai_unsupported')
    return { images: images.slice(0, 1), media: images.slice(0, 1) }
  }
  // A document: its rendered text, never the file (§18.3).
  if (!sniffed || !['pdf', 'office', 'text'].includes(sniffed.kind)) throw aiRefusal('ai_unsupported')
  if (sniffed.kind === 'text') {
    if (off.includes('text')) throw aiRefusal('media_not_allowed')
    return { documentText: decodeText(plaintext).text, images: [], media: [] }
  }
  if (off.includes(sniffed.kind)) throw aiRefusal('media_not_allowed')
  return ctx.media.inSlot(signal, async run => {
    if (sniffed.kind === 'office') {
      let output
      // A zip that is no office file: its entry names are no document's text.
      try { output = await run('office', ctx.media.JOBS.officeJob(['office']), plaintext) } catch (error) {
        if (error?.code === 'media_not_allowed') throw aiRefusal('ai_unsupported')
        throw error
      }
      if (!['docx', 'odt', 'xlsx', 'xls', 'ods', 'pptx'].includes(output.header.sniffed)) throw aiRefusal('ai_unsupported')
      return { documentText: renderOffice(output).text, images: [], media: [] }
    }
    const blocks = [], scannedPages = []
    let bytes = 0, from = 1, total = PDF_MAX_PAGES, full = false
    while (!full && from <= Math.min(total, PDF_MAX_PAGES)) {
      const output = await run('pdf', ctx.media.JOBS.pdfTextJob(from, Math.min(PDF_PAGES_PER_JOB, PDF_MAX_PAGES - from + 1)), plaintext)
      total = output.header.pages
      let last = from - 1
      for (const { section, text } of output.sections) {
        const block = `--- page ${section.page}${scanned(text) ? ' (scanned)' : ''} ---\n${text}\n`
        const size = Buffer.byteLength(block)
        if (bytes + size > JOB_TEXT_MAX_BYTES) { full = true; break }
        blocks.push(block)
        bytes += size
        if (scanned(text)) scannedPages.push(section.page)
        last = section.page
      }
      if (output.cut || last < from) break
      from = last + 1
    }
    let images = []
    if (scannedPages.length && !off.includes('image')) images = (await run('pdf', ctx.media.JOBS.pdfImagesJob(scannedPages.slice(0, IMAGES_PER_RESULT)), plaintext)).images
    return { documentText: blocks.join('\n'), images, media: images }
  })
}

/**
 * The authorization's own grant or key no longer serving (its key gone, its
 * grant's epoch or service changed, its API key refused): the authorization
 * waits for its creator, which its callers hear as `ai_paused`, never as
 * their own connection's code.
 */
const PAUSED = new Set(['reconsent_required', 'stale_grant', 'account_mismatch', 'not_authorized', 'unauthorized', 'invalid_grant'])
/** The code a job answers with: an ArchiveError's, `ai_paused` for PAUSED, else `read_failed`. */
export function jobCode(error) {
  if (PAUSED.has(error?.code)) return 'ai_paused'
  return error instanceof ArchiveError && /^[a-z][a-z0-9_]{0,47}$/.test(error.code) ? error.code : 'read_failed'
}
