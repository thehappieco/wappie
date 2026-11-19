// The reader's clock (reader 0.6.1). The enclave has no clock of its own
// worth trusting: chronyd steers it to NSM time, fed by nsm-timefeed, which
// writes what it sees to /run/wappie-clock/state.json every cycle. This file
// decides, from that file and from two independent cross-checks, whether the
// clock can be trusted right now (`ok()`), and waits for that at boot
// (`ready()`).
//
// The cross-checks are ranges for θ = local − true, in ms:
// - KMS: the Date header of every KMS answer (our own TLS, so the parent can
//   delay an answer but not forge it). Date has 1 s resolution, so one
//   sample is [sent − (D + 1000), received − D].
// - NSM, seen by Node: the timestamp in every attestation document that
//   nsm-attest makes for us, the same way with 1 ms resolution. It reads the
//   same NSM as the helper, so it checks our own pipeline (sign, units,
//   staleness), not NSM itself.
//
// A range is only ever widened by the parent (by delaying traffic), never
// moved, so a range that lies wholly beyond a threshold proves the clock is
// off. Such a proof is sticky: missing or wide samples never set one and
// never clear one; only two narrow samples inside the threshold clear it.
//
// Each range keeps the anchor Date.now() − performance.now() of its sample.
// A step of the system clock moves the anchor by the step, so an old range is
// moved by the change in anchor (it then describes the clock as it is now)
// and widened by DRIFT_PPM of its age, which covers slewing and drift since.

import { readFile } from 'node:fs/promises'

export const STATE_FILE = '/run/wappie-clock/state.json'
export const READ_EVERY_MS = 5000
/** state.json older than this (on CLOCK_MONOTONIC) means the helper is gone. */
export const STATE_FRESH_MS = 60_000
/** No good NSM sample for this long: the helper's own STALE. */
export const NSM_STALE_MS = 120_000
/** The gate closes above this uncertainty, and reopens only below UNC_OPEN_MS. */
export const UNC_CLOSE_MS = 5000
export const UNC_OPEN_MS = 1000
/** How fast an old reading loses value: chrony's caps (about 110 ppm) with margin. */
export const DRIFT_PPM = 200
/** Boot: the helper's last skew must be within this. */
export const BOOT_SKEW_MS = 500
export const READY_TIMEOUT_MS = 180_000
export const PROBE_EVERY_MS = 5000
/** A KMS range wholly beyond ±5 s proves the clock off; an NSM range beyond ±2 s. */
export const KMS_PROOF_MS = 5000
export const NSM_PROOF_MS = 2000
/** Positive agreement: a range no wider than this, inside the threshold. */
export const AGREE_WIDTH_MS = 2500
/** Boot agreement: each range inside ±2.5 s. */
export const BOOT_AGREE_MS = 2500
export const AGREE_SAMPLES = 2
export const PROOF_SAMPLES = 2
export const WINDOW_MS = 600_000
/** Wall and monotonic durations of one sample that differ by more than this: the clock stepped mid-sample. */
export const STEP_TOLERANCE_MS = 5
/** Date header resolution. */
export const DATE_RESOLUTION_MS = 1000
/** NSM timestamp resolution: whole ms, truncated (settled by P0). */
export const NSM_RESOLUTION_MS = 1

const HELPER_STATES = new Set(['ok', 'starting', 'boot_refused', 'cap_exceeded', 'chronyd_gone', 'nsm_stale', 'nsm_error'])

function bracket({ sent, received, sentMono, receivedMono }, at, resolution) {
  if (![sent, received, sentMono, receivedMono, at].every(Number.isFinite)) return null
  if (received < sent || receivedMono < sentMono) return null
  if (Math.abs((received - sent) - (receivedMono - sentMono)) > STEP_TOLERANCE_MS) return null
  return { lo: sent - (at + resolution), hi: received - at, anchor: received - receivedMono, mono: receivedMono }
}

/**
 * One KMS answer as a range for θ = local − true (ms), or null. `sent` and
 * `received` are Date.now() around the exchange, `sentMono` and
 * `receivedMono` performance.now(), `date` the Date header as received.
 * Null when the Date is unparseable, `received < sent`, or the wall and
 * monotonic durations differ by more than 5 ms (the clock stepped meanwhile).
 */
export function kmsRange({ sent, received, sentMono, receivedMono, date }) {
  const at = typeof date === 'string' ? Date.parse(date) : NaN
  return bracket({ sent, received, sentMono, receivedMono }, at, DATE_RESOLUTION_MS)
}

/** One attestation document's NSM timestamp (ms since the epoch) as a range, as kmsRange. */
export function nsmRange({ sent, received, sentMono, receivedMono, timestamp }) {
  const at = typeof timestamp === 'number' && Number.isSafeInteger(timestamp) ? timestamp : NaN
  return bracket({ sent, received, sentMono, receivedMono }, at, NSM_RESOLUTION_MS)
}

/**
 * The proof logic shared by the KMS and NSM checks. `add(range)` takes a
 * kmsRange or nsmRange (null is ignored). `proven()` is 'fast', 'slow' or
 * null. `agree({since})` is the boot rule. `interval()` is the intersection
 * of the window's ranges as they stand now, or null with no samples.
 */
function createProofCheck({ proofMs, windowMs = WINDOW_MS, wall = Date.now, mono = () => performance.now(), log, inconsistentEvent }) {
  let samples = [], proof = null, agreeing = 0, inconsistent = false
  const rebase = (range, anchor, at) => {
    const widen = Math.max(0, at - range.mono) * DRIFT_PPM * 1e-6
    const shift = anchor - range.anchor
    return { lo: range.lo + shift - widen, hi: range.hi + shift + widen, mono: range.mono }
  }
  const now = () => { const at = mono(); return { anchor: wall() - at, at } }
  const current = () => { const { anchor, at } = now(); samples = samples.filter(s => at - s.mono <= windowMs); return samples.map(s => rebase(s, anchor, at)) }
  const proves = (range, direction) => (direction === 'fast' ? range.lo > proofMs : range.hi < -proofMs)
  return {
    add(range) {
      if (!range || ![range.lo, range.hi, range.anchor, range.mono].every(Number.isFinite) || range.hi < range.lo) return
      samples.push({ lo: range.lo, hi: range.hi, anchor: range.anchor, mono: range.mono })
      const ranges = current()
      const latest = ranges[ranges.length - 1]
      const direction = latest.lo > proofMs ? 'fast' : latest.hi < -proofMs ? 'slow' : null
      if (direction) {
        agreeing = 0
        if (ranges.filter(r => proves(r, direction)).length >= PROOF_SAMPLES) proof = direction
        return
      }
      // Positive agreement clears a proof; a wide range says nothing either way.
      if (!proof || latest.hi - latest.lo > AGREE_WIDTH_MS) return
      if (latest.lo >= -proofMs && latest.hi <= proofMs) { if (++agreeing >= AGREE_SAMPLES) { proof = null; agreeing = 0 } } else agreeing = 0
    },
    proven: () => proof,
    /** At least 2 ranges taken at or after `since` (performance.now()), each no wider than 2.5 s and inside ±2.5 s. */
    agree({ since = -Infinity, widthMs = AGREE_WIDTH_MS, boundMs = BOOT_AGREE_MS } = {}) {
      return current().filter(r => r.mono >= since && r.hi - r.lo <= widthMs && r.lo >= -boundMs && r.hi <= boundMs).length >= AGREE_SAMPLES
    },
    interval() {
      const ranges = current()
      if (!ranges.length) return null
      const lo = Math.max(...ranges.map(r => r.lo)), hi = Math.min(...ranges.map(r => r.hi))
      if (lo <= hi) { inconsistent = false; return { lo, hi } }
      if (!inconsistent && inconsistentEvent) log?.event(inconsistentEvent)
      inconsistent = true
      const latest = ranges[ranges.length - 1]
      return { lo: latest.lo, hi: latest.hi }
    },
    size: () => current().length,
  }
}

/** KMS Date ranges: a proof at 5 s (S1, S4, S5). */
export const createKmsCheck = (options = {}) => createProofCheck({ proofMs: KMS_PROOF_MS, inconsistentEvent: 'clock_kms_inconsistent', ...options })

/** NSM timestamps seen by Node (nsm_node_proof): a proof at 2 s (S10). */
export const createNsmCheck = (options = {}) => createProofCheck({ proofMs: NSM_PROOF_MS, ...options })

/** state.json as the helper writes it, or null when it is not that shape. */
export function parseState(text) {
  let s
  try { s = JSON.parse(typeof text === 'string' ? text : Buffer.from(text).toString('utf8')) } catch { return null }
  const numberOrNull = value => value === null || Number.isFinite(value)
  if (!s || typeof s !== 'object' || s.v !== 1 || !Number.isFinite(s.mono_ns) || !HELPER_STATES.has(s.state) || typeof s.synced !== 'boolean') return null
  for (const key of ['last_good_mono_ns', 'nsm_skew_ms', 'rtt_us', 'corr_hour_ms', 'corr_day_ms', 'freq_ppm']) if (!numberOrNull(s[key] ?? null)) return null
  if (!Number.isFinite(s.steps ?? 0)) return null
  return s
}

const round = value => (Number.isFinite(value) ? Math.round(value) : undefined)

/** At most this many of Go's timestamps are kept for go_skew_ms; the oldest go first. */
export const GO_SKEW_MAX = 256

/**
 * Go's clock as its signatures show it: `note(seconds, at)` takes the signed
 * timestamp of a request whose signature checked out (hmac.mjs onVerified)
 * and our Date.now() when it arrived; `median()` is the median of
 * at − seconds·1000 (ms) over the last WINDOW_MS on performance.now(), or
 * null with none. The timestamp is whole seconds, so this has 1 s
 * resolution. It is reported (go_skew_ms) and never decides anything: Go's
 * host clock is not a source of time for the reader.
 */
export function createGoSkew({ windowMs = WINDOW_MS, max = GO_SKEW_MAX, mono = () => performance.now() } = {}) {
  let samples = []
  const current = () => { const at = mono(); samples = samples.filter(s => at - s.mono <= windowMs); return samples }
  return {
    note(seconds, at) {
      if (!Number.isFinite(seconds) || !Number.isFinite(at)) return
      samples.push({ skew: at - seconds * 1000, mono: mono() })
      if (samples.length > max) samples.splice(0, samples.length - max)
    },
    median() {
      const values = current().map(s => s.skew).sort((a, b) => a - b)
      if (!values.length) return null
      const middle = values.length >> 1
      return Math.round(values.length % 2 ? values[middle] : (values[middle - 1] + values[middle]) / 2)
    },
  }
}

/**
 * `readState()` returns state.json's text; `kms` and `nsm` are the checks
 * above; `go` is createGoSkew (Go's signed timestamps, go_skew_ms);
 * `probe()` takes one KMS Date sample (it feeds `kms` itself);
 * `monoNs()` is CLOCK_MONOTONIC in ns (the helper's mono_ns), `perf()`
 * performance.now() (the checks' timebase). `ok()` is the runtime rule,
 * `ready()` the boot rule, `fields()` the health line's clock fields.
 */
export function createClock({
  readState = () => readFile(STATE_FILE, 'utf8'), kms = createKmsCheck(), nsm = null, probe = async () => {}, log,
  monoNs = () => Number(process.hrtime.bigint()), perf = () => performance.now(), go = createGoSkew({ mono: perf }),
  wait = ms => new Promise(resolve => setTimeout(resolve, ms)), everyMs = READ_EVERY_MS,
} = {}) {
  let snapshot = null, open = false, code = null, syncedSince = null, refused = 0, timer = null
  let latest = { code: 'helper_stale', unc: null }

  async function refresh() {
    let text
    try { text = await readState() } catch { text = null }
    snapshot = text === null ? null : parseState(text)
    const fresh = snapshot && (monoNs() - snapshot.mono_ns) / 1e6 <= STATE_FRESH_MS
    if (fresh && snapshot.state === 'ok' && snapshot.synced) syncedSince ??= perf()
    else syncedSince = null
    ok()
    return snapshot
  }

  function uncertainty(s, nowNs) {
    if (!Number.isFinite(s.nsm_skew_ms) || !Number.isFinite(s.last_good_mono_ns)) return null
    const age = Math.max(0, nowNs - s.last_good_mono_ns) / 1e6
    return Math.abs(s.nsm_skew_ms) + Math.ceil((s.rtt_us ?? 0) / 2000) + 1 + age * DRIFT_PPM * 1e-6
  }

  /** The reason the clock is not trusted, or 'ok'; `unc` is clock_unc_ms. */
  function assess() {
    const s = snapshot, nowNs = monoNs()
    if (!s) return { code: 'helper_stale', unc: null }
    const age = (nowNs - s.mono_ns) / 1e6
    if (age > STATE_FRESH_MS || age < -1000) return { code: 'helper_stale', unc: null }
    const unc = uncertainty(s, nowNs)
    if (s.state !== 'ok') return { code: s.state, unc }
    if (unc === null || (nowNs - s.last_good_mono_ns) / 1e6 > NSM_STALE_MS) return { code: 'nsm_stale', unc }
    if (kms?.proven()) return { code: 'kms_proof', unc }
    if (nsm?.proven()) return { code: 'nsm_node_proof', unc }
    if (open ? unc > UNC_CLOSE_MS : unc >= UNC_OPEN_MS) return { code: 'unc_high', unc }
    return { code: 'ok', unc }
  }

  function ok() {
    latest = assess()
    open = latest.code === 'ok'
    if (latest.code !== code) {
      code = latest.code
      log?.event('clock_state', { code, ...(latest.unc === null ? {} : { clock_unc_ms: Math.ceil(latest.unc) }) })
      // A proof while the helper says ok: the sources disagree (an alert).
      if (code === 'kms_proof' || code === 'nsm_node_proof') log?.event('clock_sources_disagree', { code })
    }
    return open
  }

  async function ready({ timeoutMs = READY_TIMEOUT_MS } = {}) {
    const deadline = perf() + timeoutMs
    for (;;) {
      await refresh()
      await Promise.resolve(probe()).catch(() => {})
      const s = snapshot
      if (syncedSince !== null && Math.abs(s.nsm_skew_ms ?? Infinity) <= BOOT_SKEW_MS && kms.agree({ since: syncedSince }) && ok()) return
      const left = deadline - perf()
      if (left <= 0) { const error = new Error('clock_unknown'); error.code = 'clock_unknown'; throw error }
      await wait(Math.min(PROBE_EVERY_MS, left))
    }
  }

  return {
    ok,
    ready,
    refresh,
    /** The current reason ('ok' or a reason code). */
    code: () => { ok(); return code },
    /** clock_unc_ms now, or null. */
    uncertainty: () => { ok(); return latest.unc },
    /** A send refused because of the clock, reported as clock_refused on the next line. */
    noteRefused() { refused++ },
    /** Go's signed timestamp (seconds) of a verified request, and Date.now() when it came (hmac.mjs onVerified). */
    noteGo(seconds, at) { go?.note(seconds, at) },
    /** go_skew_ms now, or null with no verified request in the window. */
    goSkew: () => go?.median() ?? null,
    /** One KMS answer's range (kms.mjs dateRangeMiddleware, health.mjs clockSkew). */
    onKms(range) { kms?.add(range) },
    /** One attestation run as attest.mjs's onSample gives it. */
    onNsm(sample) { nsm?.add(nsmRange(sample)) },
    /**
     * What /internal/healthz reports (main.mjs health()): the same values as
     * the health line's, null when unknown, and nothing counted is reset.
     */
    summary() {
      const clockOk = ok(), s = snapshot, skew = go?.median() ?? null
      return {
        clock_ok: clockOk,
        clock_unc_ms: latest.unc === null ? null : Math.ceil(latest.unc),
        nsm_skew_ms: round(s?.nsm_skew_ms) ?? null,
        go_skew_ms: skew,
      }
    },
    fields() {
      const clockOk = ok(), s = snapshot, interval = kms?.interval() ?? null
      const taken = refused
      refused = 0
      return {
        clock_ok: clockOk,
        clock_unc_ms: latest.unc === null ? undefined : Math.ceil(latest.unc),
        nsm_skew_ms: round(s?.nsm_skew_ms),
        go_skew_ms: go?.median() ?? undefined,
        kms_skew_lo_ms: interval ? Math.floor(interval.lo) : undefined,
        kms_skew_hi_ms: interval ? Math.ceil(interval.hi) : undefined,
        clock_corr_hour_ms: round(s?.corr_hour_ms),
        clock_corr_day_ms: round(s?.corr_day_ms),
        clock_freq_ppm: Number.isFinite(s?.freq_ppm) ? Math.round(s.freq_ppm * 100) / 100 : undefined,
        clock_steps: Number.isFinite(s?.steps) ? s.steps : undefined,
        clock_refused: taken,
      }
    },
    start() {
      if (timer) return
      timer = setInterval(() => { void refresh() }, everyMs)
      timer.unref?.()
    },
    stop() { if (timer) clearInterval(timer); timer = null },
  }
}
