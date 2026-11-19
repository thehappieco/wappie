// clock.mjs: KMS and NSM ranges, the proof rules, and the runtime and boot
// rules over the helper's state.json. Every clock here is a fake one the test
// moves by hand.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  BOOT_SKEW_MS, createClock, createCountFile, createGoSkew, createKmsCheck, createNsmCheck, GO_SKEW_MAX, kmsRange, nsmRange, parseState, READY_TIMEOUT_MS, STATE_FRESH_MS, WINDOW_MS,
} from '../clock.mjs'

const EPOCH = Date.UTC(2026, 10, 19, 12, 0, 0)

/** A fake time: `perf` (performance.now), `wall` (Date.now) and `monoNs` (CLOCK_MONOTONIC) move together; `step(ms)` moves wall alone. */
function fakeTime() {
  const time = { at: 1000, stepped: 0 }
  time.perf = () => time.at
  time.wall = () => EPOCH + time.at + time.stepped
  time.monoNs = () => 7e12 + time.at * 1e6
  time.advance = ms => { time.at += ms }
  time.step = ms => { time.stepped += ms }
  return time
}

function fakeLog() {
  const events = []
  return { events, event: (event, fields = {}) => events.push({ event, ...fields }), named: name => events.filter(e => e.event === name) }
}

/** A range taken now, for a clock that is `lo..hi` ms off (as kmsRange would compute it). */
const rangeNow = (time, lo, hi) => ({ lo, hi, anchor: time.wall() - time.perf(), mono: time.perf() })

test('kmsRange: the Date floor on the low side, the round trip on both, steps and bad input give null', () => {
  const date = new Date(EPOCH).toUTCString()
  const range = kmsRange({ sent: EPOCH + 500, received: EPOCH + 700, sentMono: 100, receivedMono: 300, date })
  assert.deepEqual(range, { lo: 500 - 1000, hi: 700, anchor: EPOCH + 700 - 300, mono: 300 })
  // A longer round trip widens the range on both sides.
  const slow = kmsRange({ sent: EPOCH + 100, received: EPOCH + 1900, sentMono: 100, receivedMono: 1900, date })
  assert.equal(slow.lo, 100 - 1000)
  assert.equal(slow.hi, 1900)
  // A clock that is 10 s fast: the range lies wholly above zero.
  const fast = kmsRange({ sent: EPOCH + 10_200, received: EPOCH + 10_300, sentMono: 0, receivedMono: 100, date })
  assert.ok(fast.lo > 9000 && fast.hi <= 10_300)
  // The clock stepped mid-sample (wall and monotonic durations differ by more than 5 ms).
  assert.equal(kmsRange({ sent: EPOCH, received: EPOCH + 206, sentMono: 0, receivedMono: 200, date }), null)
  assert.ok(kmsRange({ sent: EPOCH, received: EPOCH + 205, sentMono: 0, receivedMono: 200, date }))
  assert.equal(kmsRange({ sent: EPOCH, received: EPOCH + 100, sentMono: 0, receivedMono: 100, date: 'yesterday' }), null)
  assert.equal(kmsRange({ sent: EPOCH, received: EPOCH + 100, sentMono: 0, receivedMono: 100, date: undefined }), null)
  assert.equal(kmsRange({ sent: EPOCH, received: EPOCH + 100, sentMono: 0, receivedMono: 100, date: EPOCH }), null)
  assert.equal(kmsRange({ sent: EPOCH + 100, received: EPOCH, sentMono: 0, receivedMono: 100, date }), null)
  assert.equal(kmsRange({ sent: EPOCH, received: EPOCH + 100, sentMono: NaN, receivedMono: 100, date }), null)
})

test('nsmRange: a whole-ms timestamp gives a range 1 ms wider than the round trip', () => {
  const range = nsmRange({ sent: EPOCH + 40, received: EPOCH + 60, sentMono: 5, receivedMono: 25, timestamp: EPOCH + 50 })
  assert.deepEqual(range, { lo: -11, hi: 10, anchor: EPOCH + 60 - 25, mono: 25 })
  assert.equal(nsmRange({ sent: EPOCH, received: EPOCH + 1, sentMono: 0, receivedMono: 1, timestamp: '1' }), null)
  assert.equal(nsmRange({ sent: EPOCH, received: EPOCH + 1, sentMono: 0, receivedMono: 1, timestamp: 1.5 }), null)
  assert.equal(nsmRange({ sent: EPOCH, received: EPOCH + 50, sentMono: 0, receivedMono: 10, timestamp: EPOCH }), null)
})

test('KMS check: two ranges beyond 5 s prove the clock fast or slow; one, a straddling range, or none never does', () => {
  const time = fakeTime()
  const fast = createKmsCheck({ wall: time.wall, mono: time.perf })
  assert.equal(fast.proven(), null)
  // 10 ms beyond the threshold: an old range is widened by 200 ppm of its age (1 ms after 5 s).
  fast.add(rangeNow(time, 5010, 6010))
  assert.equal(fast.proven(), null, 'one range alone does not prove')
  time.advance(5000)
  fast.add(rangeNow(time, 5010, 6010))
  assert.equal(fast.proven(), 'fast')

  const slow = createKmsCheck({ wall: time.wall, mono: time.perf })
  slow.add(rangeNow(time, -6001, -5001)); slow.add(rangeNow(time, -6001, -5001))
  assert.equal(slow.proven(), 'slow')

  const wide = createKmsCheck({ wall: time.wall, mono: time.perf })
  for (let i = 0; i < 10; i++) wide.add(rangeNow(time, -5000, 40_000))
  assert.equal(wide.proven(), null, 'a range that contains a 5 s offset proves nothing')
  const edge = createKmsCheck({ wall: time.wall, mono: time.perf })
  edge.add(rangeNow(time, 5000, 6000)); edge.add(rangeNow(time, 5000, 6000))
  assert.equal(edge.proven(), null, 'exactly 5 s is not beyond 5 s')
})

test('KMS check: missing data never sets or clears a proof; the proof outlives its samples', () => {
  const time = fakeTime()
  const check = createKmsCheck({ wall: time.wall, mono: time.perf })
  for (const bad of [null, undefined, { lo: NaN, hi: 1, anchor: 0, mono: 0 }, { lo: 2, hi: 1, anchor: 0, mono: 0 }]) check.add(bad)
  assert.equal(check.size(), 0)
  assert.equal(check.proven(), null)
  assert.equal(check.interval(), null)
  check.add(rangeNow(time, 8000, 9000)); check.add(rangeNow(time, 8000, 9000))
  assert.equal(check.proven(), 'fast')
  // KMS goes quiet (the parent blocks it): the samples expire, the proof stays.
  time.advance(30 * 60_000)
  for (const bad of [null, undefined]) check.add(bad)
  assert.equal(check.size(), 0)
  assert.equal(check.proven(), 'fast')
  // Wide answers (the parent delays them) say nothing either way.
  for (let i = 0; i < 5; i++) check.add(rangeNow(time, -3000, 3000))
  assert.equal(check.proven(), 'fast')
})

test('KMS check: only two narrow ranges inside ±5 s in a row clear a proof', () => {
  const time = fakeTime()
  const check = createKmsCheck({ wall: time.wall, mono: time.perf })
  check.add(rangeNow(time, 8000, 9000)); check.add(rangeNow(time, 8000, 9000))
  check.add(rangeNow(time, -500, 1000))
  assert.equal(check.proven(), 'fast', 'one narrow agreeing range is not enough')
  check.add(rangeNow(time, 4000, 6000)) // narrow, not inside, not proving: starts the count again
  check.add(rangeNow(time, -500, 1000))
  assert.equal(check.proven(), 'fast')
  check.add(rangeNow(time, -3000, 3000)) // wide: ignored, the count goes on
  check.add(rangeNow(time, -400, 900))
  assert.equal(check.proven(), null)
  // A new proof after clearing needs two proving ranges again, counting those still in the window.
  check.add(rangeNow(time, 8000, 9000))
  assert.equal(check.proven(), 'fast', 'the earlier proving ranges are still in the window')
})

test('KMS check: a range is rebased across a step of the clock and widened with age', () => {
  const time = fakeTime()
  const log = fakeLog()
  const check = createKmsCheck({ wall: time.wall, mono: time.perf, log })
  // Taken while the clock was 10 s fast; the clock is then stepped back by 10 s.
  check.add(rangeNow(time, 9500, 10_500))
  time.advance(1000)
  time.step(-10_000)
  const rebased = check.interval()
  assert.ok(Math.abs(rebased.lo - -500) < 1 && Math.abs(rebased.hi - 500) < 1, JSON.stringify(rebased))
  // A sample after the step agrees with it: no inconsistency.
  check.add(rangeNow(time, -400, 600))
  const both = check.interval()
  assert.ok(both.lo > -401 && both.hi < 501, JSON.stringify(both))
  assert.equal(log.named('clock_kms_inconsistent').length, 0)
  // The same proving pair does not prove once the clock has been stepped back into line.
  const proof = createKmsCheck({ wall: time.wall, mono: time.perf })
  proof.add(rangeNow(time, 9500, 10_500))
  time.step(-10_000)
  proof.add(rangeNow(time, 9500, 10_500))
  assert.equal(proof.proven(), null, 'the first range, rebased, no longer proves')
  // Age widens a range by 200 ppm.
  const aging = createKmsCheck({ wall: time.wall, mono: time.perf })
  aging.add(rangeNow(time, 0, 1000))
  time.advance(500_000)
  const old = aging.interval()
  assert.ok(Math.abs(old.lo - -100) < 1e-6 && Math.abs(old.hi - 1100) < 1e-6, JSON.stringify(old))
  time.advance(100_001)
  assert.equal(aging.interval(), null, 'gone after 10 minutes')
})

test('KMS check: an empty intersection is logged once and reports the latest range', () => {
  const time = fakeTime()
  const log = fakeLog()
  const check = createKmsCheck({ wall: time.wall, mono: time.perf, log })
  check.add(rangeNow(time, 0, 1000))
  check.add(rangeNow(time, 2000, 3000))
  assert.deepEqual(check.interval(), { lo: 2000, hi: 3000 })
  check.interval()
  assert.equal(log.named('clock_kms_inconsistent').length, 1)
})

test('KMS check: agree() needs two narrow ranges inside ±2.5 s taken since the given time', () => {
  const time = fakeTime()
  const check = createKmsCheck({ wall: time.wall, mono: time.perf })
  check.add(rangeNow(time, -1000, 1000))
  time.advance(10)
  const since = time.perf()
  assert.equal(check.agree({ since }), false)
  check.add(rangeNow(time, -1000, 1000))
  assert.equal(check.agree({ since }), false, 'the first range came before `since`')
  check.add(rangeNow(time, -2600, 0))
  assert.equal(check.agree({ since }), false, 'outside ±2.5 s')
  check.add(rangeNow(time, -1500, 1500))
  assert.equal(check.agree({ since }), false, 'wider than 2.5 s')
  check.add(rangeNow(time, -1200, 1200))
  assert.equal(check.agree({ since }), true)
})

test('NSM check: a proof at 2 s, cleared by two narrow ranges inside ±2 s', () => {
  const time = fakeTime()
  const check = createNsmCheck({ wall: time.wall, mono: time.perf })
  check.add(rangeNow(time, 1990, 2010)); check.add(rangeNow(time, 1990, 2010))
  assert.equal(check.proven(), null)
  check.add(rangeNow(time, 2001, 2020)); check.add(rangeNow(time, 2001, 2020))
  assert.equal(check.proven(), 'fast')
  check.add(rangeNow(time, -10, 10)); check.add(rangeNow(time, -10, 10))
  assert.equal(check.proven(), null)
})

/** A controllable state.json. */
function fakeHelper(time, fields = {}) {
  const helper = { text: null, fail: false }
  helper.set = (more = {}) => {
    const now = time.monoNs()
    helper.text = JSON.stringify({
      v: 1, mono_ns: now, last_good_mono_ns: now, state: 'ok', synced: true, nsm_skew_ms: 2.5, rtt_us: 400, good: 10, bad: 0,
      corr_hour_ms: 12, corr_day_ms: 340, freq_ppm: -17.126, steps: 1, ...fields, ...more,
    })
  }
  helper.read = async () => { if (helper.fail || helper.text === null) throw Object.assign(new Error('missing'), { code: 'ENOENT' }); return helper.text }
  helper.set()
  return helper
}

function world(fields = {}, options = {}) {
  const time = fakeTime(), log = fakeLog()
  const helper = fakeHelper(time, fields)
  const kms = createKmsCheck({ wall: time.wall, mono: time.perf, log })
  const nsm = createNsmCheck({ wall: time.wall, mono: time.perf })
  const clock = createClock({ readState: helper.read, kms, nsm, log, monoNs: time.monoNs, perf: time.perf, wall: time.wall, wait: async ms => time.advance(ms), ...options })
  return { time, log, helper, kms, nsm, clock }
}

test('state.json: fresh, stale, missing and malformed files', async () => {
  const { time, helper, clock, log } = world()
  await clock.refresh()
  assert.equal(clock.ok(), true)
  assert.equal(clock.code(), 'ok')
  // The helper stops writing: stale after 60 s on CLOCK_MONOTONIC, even without a new read.
  time.advance(STATE_FRESH_MS)
  assert.equal(clock.ok(), true)
  time.advance(1)
  assert.equal(clock.ok(), false)
  assert.equal(clock.code(), 'helper_stale')
  helper.set()
  await clock.refresh()
  assert.equal(clock.ok(), true)
  helper.fail = true
  await clock.refresh()
  assert.equal(clock.code(), 'helper_stale', 'missing file')
  helper.fail = false
  for (const text of ['{', '[]', 'null', JSON.stringify({ v: 2 })]) {
    helper.text = text
    await clock.refresh()
    assert.equal(clock.code(), 'helper_stale', text)
  }
  for (const more of [{ v: 2 }, { mono_ns: '1' }, { state: 'fine' }, { synced: 'yes' }, { nsm_skew_ms: '3' }, { rtt_us: 'x' }]) {
    helper.set(more)
    await clock.refresh()
    assert.equal(clock.code(), 'helper_stale', JSON.stringify(more))
  }
  assert.equal(parseState(Buffer.from(JSON.stringify({ v: 1, mono_ns: 1, state: 'ok', synced: false }))).state, 'ok')
  // One clock_state line per transition, not per call.
  assert.deepEqual(log.named('clock_state').map(e => e.code), ['ok', 'helper_stale', 'ok', 'helper_stale'])
})

test('each helper state is its own reason; nsm_stale also when the last good sample is over 120 s old', async () => {
  const { time, helper, clock } = world()
  for (const state of ['starting', 'boot_refused', 'cap_exceeded', 'chronyd_gone', 'nsm_stale', 'nsm_error']) {
    helper.set({ state })
    await clock.refresh()
    assert.equal(clock.ok(), false)
    assert.equal(clock.code(), state)
    assert.equal(clock.summary().clock_code, state, 'healthz names the helper state, starting included')
  }
  helper.set({ last_good_mono_ns: time.monoNs() - 120_001e6 })
  await clock.refresh()
  assert.equal(clock.code(), 'nsm_stale')
  helper.set({ last_good_mono_ns: null, nsm_skew_ms: null, rtt_us: null })
  await clock.refresh()
  assert.equal(clock.code(), 'nsm_stale')
  helper.set()
  await clock.refresh()
  assert.equal(clock.code(), 'ok')
})

test('clock_unc_ms = |nsm_skew| + ceil(rtt/2) + 1 + 200 ppm of the age of the last good sample', async () => {
  const { time, helper, clock } = world()
  helper.set({ nsm_skew_ms: -300, rtt_us: 3001, last_good_mono_ns: time.monoNs() - 100_000e6 })
  await clock.refresh()
  assert.ok(Math.abs(clock.uncertainty() - (300 + 2 + 1 + 20)) < 1e-6, String(clock.uncertainty()))
  assert.equal(clock.fields().clock_unc_ms, 323)
  // The age term keeps growing between reads.
  time.advance(10_000)
  assert.ok(Math.abs(clock.uncertainty() - 325) < 1e-6)
})

test('hysteresis: the gate closes above 5 s and reopens only below 1 s', async () => {
  const { helper, clock, log } = world()
  const at = async nsm_skew_ms => { helper.set({ nsm_skew_ms, rtt_us: 0 }); await clock.refresh(); return clock.ok() }
  assert.equal(await at(1200), false, 'closed at boot until below 1 s')
  assert.equal(await at(998), true) // 998 + 0 + 1 = 999
  assert.equal(await at(4999), true) // 5000: still open
  assert.equal(await at(5000), false) // 5001: closes
  assert.equal(clock.code(), 'unc_high')
  assert.equal(await at(2000), false)
  assert.equal(await at(999), false) // 1000 is not below 1000
  assert.equal(await at(998), true)
  assert.deepEqual(log.named('clock_state').map(e => e.code), ['unc_high', 'ok', 'unc_high', 'ok'])
})

test('a KMS or NSM proof closes the gate, logs clock_sources_disagree, and the gate reopens only once it clears', async () => {
  const { time, clock, kms, nsm, log, helper } = world()
  await clock.refresh()
  assert.equal(clock.ok(), true)
  kms.add(rangeNow(time, 89_000, 91_000)); kms.add(rangeNow(time, 89_000, 91_000))
  assert.equal(clock.ok(), false)
  assert.equal(clock.code(), 'kms_proof')
  assert.deepEqual(log.named('clock_sources_disagree'), [{ event: 'clock_sources_disagree', code: 'kms_proof' }])
  kms.add(rangeNow(time, -900, 900)); kms.add(rangeNow(time, -900, 900))
  assert.equal(clock.ok(), true)
  nsm.add(rangeNow(time, -3000, -2500)); nsm.add(rangeNow(time, -3000, -2500))
  assert.equal(clock.code(), 'nsm_node_proof')
  assert.equal(log.named('clock_sources_disagree').length, 2)
  // A helper fault comes first: no disagreement to report.
  helper.set({ state: 'cap_exceeded' })
  await clock.refresh()
  assert.equal(clock.code(), 'cap_exceeded')
  assert.equal(log.named('clock_sources_disagree').length, 2)
})

test('a boot 90 s off: KMS proves it, the helper agrees, so no clock_sources_disagree; ready() resolves after the step', async () => {
  // The clock starts 90 s slow. KMS probes every 5 s from the start; chronyd
  // steps at 37 s, between two reads; the helper's sample lags its cycle, so
  // the read after the step still carries the old -90 s.
  const { time, helper, kms, log } = world({ state: 'starting', synced: false, nsm_skew_ms: null, last_good_mono_ns: null, rtt_us: null })
  time.step(-90_000)
  const stepAt = 37_000
  let reads = 0
  const clock = createClock({
    readState: helper.read, kms, log, monoNs: time.monoNs, perf: time.perf, wall: time.wall,
    probe: async () => { const theta = time.stepped; kms.add(rangeNow(time, theta - 900, theta + 300)) },
    wait: async ms => {
      const before = time.perf()
      time.advance(ms)
      if (before < stepAt && time.perf() >= stepAt) time.step(90_000)
      reads++
      if (reads < 3) return
      const sinceStep = time.perf() - stepAt, sample = { state: 'ok', rtt_us: 400, last_good_mono_ns: time.monoNs() - 1000e6 }
      if (sinceStep < 0) helper.set({ ...sample, synced: false, nsm_skew_ms: -90_000 })
      else if (sinceStep < 5000) helper.set({ ...sample, synced: false, nsm_skew_ms: -90_000, last_good_mono_ns: time.monoNs() - (sinceStep + 500) * 1e6 })
      else helper.set({ ...sample, synced: sinceStep >= 10_000, nsm_skew_ms: 3 })
    },
  })
  await clock.ready({ timeoutMs: 120_000 })
  assert.equal(clock.ok(), true)
  const codes = log.named('clock_state').map(e => e.code)
  assert.ok(codes.includes('kms_proof'), codes.join(','))
  assert.deepEqual(log.named('clock_sources_disagree'), [])
  assert.equal(clock.summary().clock_disagree_kms, 0, 'a proof the helper agrees with is not counted')
})

test('clock_sources_disagree: only from a helper sample taken after the last step Node saw, and once per proof', async () => {
  const { time, clock, kms, log, helper } = world({ nsm_skew_ms: 0 })
  await clock.refresh()
  assert.equal(clock.ok(), true)
  // The clock steps 90 s ahead; KMS proves it before the helper's next sample.
  time.advance(1000)
  time.step(90_000)
  kms.add(rangeNow(time, 89_500, 90_700)); kms.add(rangeNow(time, 89_500, 90_700))
  assert.equal(clock.code(), 'kms_proof')
  assert.deepEqual(log.named('clock_sources_disagree'), [], 'the helper sample is from before the step')
  // The helper sees it too: they agree.
  time.advance(4000)
  helper.set({ nsm_skew_ms: 90_000 })
  await clock.refresh()
  assert.equal(clock.code(), 'kms_proof')
  assert.deepEqual(log.named('clock_sources_disagree'), [])
  // The helper says the clock is right while KMS still proves it 90 s fast.
  time.advance(4000)
  kms.add(rangeNow(time, 89_500, 90_700))
  helper.set({ nsm_skew_ms: 0 })
  await clock.refresh()
  assert.deepEqual(log.named('clock_sources_disagree'), [{ event: 'clock_sources_disagree', code: 'kms_proof' }])
  await clock.refresh()
  clock.ok()
  assert.equal(log.named('clock_sources_disagree').length, 1, 'once per proof')
})

test('ready(): waits for synced, |nsm_skew| <= 500 ms and two KMS ranges taken after synced', async () => {
  const { time, helper, kms } = world({ synced: false })
  let probes = 0
  const probing = createClock({
    readState: helper.read, kms, log: fakeLog(), monoNs: time.monoNs, perf: time.perf,
    wait: async ms => { time.advance(ms); helper.set({ synced: probes >= 3, nsm_skew_ms: probes >= 3 ? 40 : 2000 }) },
    probe: async () => { probes++; kms.add(rangeNow(time, -900, 400)) },
  })
  const started = time.perf()
  await probing.ready({ timeoutMs: 60_000 })
  assert.equal(probing.ok(), true)
  // Synced on the 4th read; the ranges from before it do not count, so two more probes.
  assert.equal(probes, 5)
  assert.equal(time.perf() - started, 4 * 5000)
})

test('ready(): times out with clock_unknown when the skew is too big, KMS ranges are wide, or nothing is synced', async () => {
  for (const [fields, range] of [[{ nsm_skew_ms: BOOT_SKEW_MS + 1 }, [-900, 400]], [{}, [-1500, 1500]], [{ synced: false }, [-900, 400]], [{}, null]]) {
    const { time, helper, kms } = world(fields)
    const clock = createClock({
      readState: helper.read, kms, log: fakeLog(), monoNs: time.monoNs, perf: time.perf,
      wait: async ms => { time.advance(ms); helper.set() },
      probe: async () => { if (range) kms.add(rangeNow(time, ...range)) },
    })
    const started = time.perf()
    await assert.rejects(clock.ready(), { code: 'clock_unknown', message: 'clock_unknown' }, JSON.stringify(fields))
    assert.ok(time.perf() - started >= READY_TIMEOUT_MS)
  }
})

test('ready(): a failing probe is not fatal before the deadline', async () => {
  const { time, helper, kms } = world()
  let calls = 0
  const clock = createClock({
    readState: helper.read, kms, monoNs: time.monoNs, perf: time.perf,
    wait: async ms => { time.advance(ms); helper.set() },
    probe: async () => { if (++calls <= 2) throw new Error('no route'); kms.add(rangeNow(time, -900, 400)) },
  })
  await clock.ready({ timeoutMs: 60_000 })
  assert.equal(calls, 4)
})

test('fields(): the health line clock fields, numbers and booleans only, omitted when unknown', async () => {
  const { time, helper, clock, kms } = world()
  const empty = createClock({ readState: async () => { throw new Error('missing') }, monoNs: time.monoNs, perf: time.perf })
  await empty.refresh()
  const none = Object.fromEntries(Object.entries(empty.fields()).filter(([, v]) => v !== undefined))
  assert.deepEqual(none, { clock_ok: false, clock_refused: 0 })
  helper.set({ nsm_skew_ms: -12.345 })
  await clock.refresh()
  kms.add(rangeNow(time, -800.2, 450.7))
  clock.noteRefused(); clock.noteRefused()
  // Go signed 4 s before the request arrived here.
  clock.noteGo(1_790_000_000, 1_790_000_004_000)
  const fields = clock.fields()
  assert.deepEqual(fields, {
    clock_ok: true, clock_unc_ms: 15, nsm_skew_ms: -12, go_skew_ms: 4000, kms_skew_lo_ms: -801, kms_skew_hi_ms: 451,
    clock_corr_hour_ms: 12, clock_corr_day_ms: 340, clock_freq_ppm: -17.13, clock_steps: 1, clock_refused: 2,
  })
  for (const [key, value] of Object.entries(fields)) assert.ok(/^[a-z][a-z0-9_]{0,31}$/.test(key) && (typeof value === 'boolean' || Number.isFinite(value)), key)
  assert.equal(clock.fields().clock_refused, 0, 'counted since the last line')
})

test('summary(): the healthz clock fields, null when unknown, with the reason; clock_refused is neither there nor reset', async () => {
  const { time, helper, clock, kms, log } = world()
  const empty = createClock({ readState: async () => { throw new Error('missing') }, monoNs: time.monoNs, perf: time.perf })
  await empty.refresh()
  assert.deepEqual(empty.summary(), {
    clock_ok: false, clock_unc_ms: null, nsm_skew_ms: null, go_skew_ms: null, clock_code: 'helper_stale', clock_disagree_kms: 0,
    kms_skew_lo_ms: null, kms_skew_hi_ms: null, clock_corr_hour_ms: null, clock_corr_day_ms: null,
  })
  helper.set({ nsm_skew_ms: -12.345 })
  await clock.refresh()
  kms.add(rangeNow(time, -800.2, 450.7))
  clock.noteRefused(); clock.noteRefused()
  clock.noteGo(1_790_000_000, 1_790_000_004_000)
  const summary = clock.summary()
  assert.deepEqual(summary, {
    clock_ok: true, clock_unc_ms: 15, nsm_skew_ms: -12, go_skew_ms: 4000, clock_code: 'ok', clock_disagree_kms: 0,
    kms_skew_lo_ms: -801, kms_skew_hi_ms: 451, clock_corr_hour_ms: 12, clock_corr_day_ms: 340,
  })
  // The same numbers as the health line's.
  const fields = clock.fields()
  for (const key of ['clock_ok', 'clock_unc_ms', 'nsm_skew_ms', 'go_skew_ms', 'kms_skew_lo_ms', 'kms_skew_hi_ms', 'clock_corr_hour_ms', 'clock_corr_day_ms']) assert.equal(summary[key], fields[key], key)
  assert.equal(fields.clock_refused, 2, 'summary() reset nothing')
  clock.noteRefused()
  clock.summary(); clock.summary()
  assert.equal(clock.fields().clock_refused, 1, 'nor does it now')
  // A helper fault: its own code, and the numbers it still reports.
  helper.set({ state: 'cap_exceeded', corr_hour_ms: 3600.4, corr_day_ms: 86_399.6 })
  await clock.refresh()
  assert.deepEqual(Object.fromEntries(Object.entries(clock.summary()).filter(([key]) => ['clock_ok', 'clock_code', 'clock_corr_hour_ms', 'clock_corr_day_ms'].includes(key))),
    { clock_ok: false, clock_code: 'cap_exceeded', clock_corr_hour_ms: 3600, clock_corr_day_ms: 86_400 })
  // Only clock_state transitions are logged, nothing new for a summary.
  const logged = log.events.length
  clock.summary()
  assert.equal(log.events.length, logged)
  // No KMS check: no KMS range.
  const { clock: bare } = world({}, { kms: null })
  await bare.refresh()
  assert.deepEqual([bare.summary().kms_skew_lo_ms, bare.summary().kms_skew_hi_ms], [null, null])
})

test('summary(): clock_disagree_kms counts clock_sources_disagree for a KMS proof only, once per proof', async () => {
  const { time, clock, kms, nsm, log } = world()
  await clock.refresh()
  assert.equal(clock.summary().clock_disagree_kms, 0)
  kms.add(rangeNow(time, 89_000, 91_000)); kms.add(rangeNow(time, 89_000, 91_000))
  assert.equal(clock.summary().clock_code, 'kms_proof')
  assert.equal(clock.summary().clock_disagree_kms, 1)
  clock.ok(); clock.summary()
  assert.equal(clock.summary().clock_disagree_kms, 1, 'once per proof')
  // Cleared, then an NSM proof: disagreement logged, not counted.
  kms.add(rangeNow(time, -900, 900)); kms.add(rangeNow(time, -900, 900))
  assert.equal(clock.summary().clock_code, 'ok')
  nsm.add(rangeNow(time, -3000, -2500)); nsm.add(rangeNow(time, -3000, -2500))
  assert.equal(clock.summary().clock_code, 'nsm_node_proof')
  assert.equal(log.named('clock_sources_disagree').length, 2)
  assert.equal(clock.summary().clock_disagree_kms, 1)
  nsm.add(rangeNow(time, -10, 10)); nsm.add(rangeNow(time, -10, 10))
  // A second KMS proof counts again.
  time.advance(5000)
  kms.add(rangeNow(time, 89_000, 91_000)); kms.add(rangeNow(time, 89_000, 91_000))
  assert.equal(clock.summary().clock_code, 'kms_proof')
  assert.equal(clock.summary().clock_disagree_kms, 2)
  assert.deepEqual(log.named('clock_sources_disagree').map(e => e.code), ['kms_proof', 'nsm_node_proof', 'kms_proof'])
})

test('clock_disagree_kms goes on across a Node restart in the same enclave boot (disagreeStore)', async () => {
  const saved = []
  const store = { value: 0, load: () => store.value, save: async n => { saved.push(n); store.value = n } }
  const first = world({}, { disagreeStore: store })
  await first.clock.refresh()
  first.kms.add(rangeNow(first.time, 89_000, 91_000)); first.kms.add(rangeNow(first.time, 89_000, 91_000))
  assert.equal(first.clock.summary().clock_disagree_kms, 1)
  first.clock.summary()
  assert.deepEqual(saved, [1], 'saved once per proof')
  // Node restarts: a new clock against the same store starts from 1, not 0,
  // so a proof right after the restart is 2 and Go sees it go up.
  const second = world({}, { disagreeStore: store })
  await second.clock.refresh()
  assert.equal(second.clock.summary().clock_disagree_kms, 1)
  assert.equal(second.clock.summary().clock_code, 'ok')
  second.kms.add(rangeNow(second.time, 89_000, 91_000)); second.kms.add(rangeNow(second.time, 89_000, 91_000))
  assert.equal(second.clock.summary().clock_disagree_kms, 2)
  assert.deepEqual(saved, [1, 2])
  // Without a store the count is this process's alone.
  const alone = world()
  await alone.clock.refresh()
  assert.equal(alone.clock.summary().clock_disagree_kms, 0)
})

test('createCountFile: 0 when missing or malformed, writes in call order at 0600, a failed write never throws', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'wappie-clock-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const path = join(dir, 'clock_disagree_kms')
  const file = createCountFile(path)
  assert.equal(file.load(), 0)
  file.save(1)
  await file.save(2)
  assert.equal(await readFile(path, 'utf8'), '2\n')
  assert.equal((await stat(path)).mode & 0o777, 0o600)
  assert.equal(createCountFile(path).load(), 2, 'a new process reads it back')
  for (const text of ['', 'x', '-1\n', '1.5\n', '1e3\n', '9'.repeat(16)]) {
    await writeFile(path, text)
    assert.equal(createCountFile(path).load(), 0, JSON.stringify(text))
  }
  const failing = createCountFile(join(dir, 'missing', 'count'))
  await failing.save(3)
  assert.equal(failing.load(), 0)
})

test('start(): reads state.json on a timer, stop() ends it', async () => {
  let reads = 0
  const clock = createClock({ readState: async () => { reads++; throw new Error('missing') }, everyMs: 5 })
  clock.start()
  // Polled rather than a fixed sleep: the suite's files run side by side.
  for (const end = Date.now() + 5000; reads < 2 && Date.now() < end;) await new Promise(resolve => setTimeout(resolve, 5))
  clock.stop()
  const seen = reads
  assert.ok(seen >= 2, String(seen))
  await new Promise(resolve => setTimeout(resolve, 20))
  assert.equal(reads, seen)
})

test('go_skew_ms: the median of verified Go timestamps against our clock, over the window, at most GO_SKEW_MAX kept', () => {
  const time = fakeTime()
  const go = createGoSkew({ mono: time.perf })
  assert.equal(go.median(), null)
  const sec = 1_790_000_000
  go.note(sec, sec * 1000 + 2000)
  assert.equal(go.median(), 2000)
  go.note(sec, sec * 1000 + 61_000)
  go.note(sec, sec * 1000 + 3000)
  assert.equal(go.median(), 3000, 'one far sample does not move the median')
  go.note(sec, sec * 1000 + 4000)
  assert.equal(go.median(), 3500, 'an even count takes the middle two')
  go.note(Number.NaN, 1)
  go.note(sec, Number.POSITIVE_INFINITY)
  assert.equal(go.median(), 3500, 'non-numbers are ignored')
  time.advance(WINDOW_MS + 1)
  assert.equal(go.median(), null, 'samples leave the window on the monotonic clock')
  for (let i = 0; i < GO_SKEW_MAX + 10; i++) go.note(sec, sec * 1000 + (i < 10 ? 999_000 : -1000))
  assert.equal(go.median(), -1000, 'the oldest samples are dropped past the cap')
  // A clock without one reports none.
  const { clock } = world({}, { go: null })
  assert.equal(clock.goSkew(), null)
  clock.noteGo(sec, sec * 1000)
  assert.equal(clock.fields().go_skew_ms, undefined)
})
