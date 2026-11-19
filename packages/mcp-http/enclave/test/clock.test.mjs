// clock.mjs: KMS and NSM ranges, the proof rules, and the runtime and boot
// rules over the helper's state.json. Every clock here is a fake one the test
// moves by hand.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  BOOT_SKEW_MS, createClock, createKmsCheck, createNsmCheck, kmsRange, nsmRange, parseState, READY_TIMEOUT_MS, STATE_FRESH_MS,
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
  const clock = createClock({ readState: helper.read, kms, nsm, log, monoNs: time.monoNs, perf: time.perf, wait: async ms => time.advance(ms), ...options })
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
  const fields = clock.fields()
  assert.deepEqual(fields, {
    clock_ok: true, clock_unc_ms: 15, nsm_skew_ms: -12, kms_skew_lo_ms: -801, kms_skew_hi_ms: 451,
    clock_corr_hour_ms: 12, clock_corr_day_ms: 340, clock_freq_ppm: -17.13, clock_steps: 1, clock_refused: 2,
  })
  for (const [key, value] of Object.entries(fields)) assert.ok(/^[a-z][a-z0-9_]{0,31}$/.test(key) && (typeof value === 'boolean' || Number.isFinite(value)), key)
  assert.equal(clock.fields().clock_refused, 0, 'counted since the last line')
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
