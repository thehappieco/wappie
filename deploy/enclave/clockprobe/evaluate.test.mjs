// Tests for the clock probe's arithmetic (evaluate.mjs): node --test.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  capBit, check, chronyConf, corrSeries, cpuPercent, findSteps, maxRatePpm, meanRatePpm, nsmDrift, parseJsonl, parseStat,
  percentileAbs, verdict,
} from './evaluate.mjs'

const S = 1e9
// A watch file: one line a second, corr = real - raw following `corrAt(i)` in ns.
const watch = (seconds, corrAt) => Array.from({ length: seconds }, (_, i) => ({ raw_ns: 1000 * S + i * S, mono_ns: 2000 * S + i * S, real_ns: 1000 * S + i * S + corrAt(i) }))

test('parseJsonl skips cut and empty lines', () => {
  assert.deepEqual(parseJsonl('{"a":1}\n\n{"b":\n"text"\n{"c":3}\n'), [{ a: 1 }, { c: 3 }])
})

test('findSteps sees a step and nothing else', () => {
  const s = corrSeries(watch(100, i => (i >= 50 ? -90 * S : 0) + i * 20_000))
  const steps = findSteps(s)
  assert.equal(steps.length, 1)
  assert.ok(Math.abs(steps[0].delta_ms + 90_000) < 1)
  assert.equal(steps[0].mono_ns, 2050 * S)
})

test('maxRatePpm takes steps out and reports slewing', () => {
  // 60 ppm of slewing (60 us a second), and a +3 s step in the middle. The
  // second the step falls in is taken out whole, slewing included.
  const s = corrSeries(watch(1800, i => i * 60_000 + (i >= 900 ? 3 * S : 0)))
  assert.ok(Math.abs(maxRatePpm(s, 600) - 60) < 0.1)
  assert.ok(Math.abs(meanRatePpm(s) - 60) < 0.1)
  assert.equal(maxRatePpm(corrSeries(watch(100, () => 0)), 600), null)
})

test('maxRatePpm finds the worst window', () => {
  const s = corrSeries(watch(2400, i => (i < 1200 ? i * 10_000 : 1200 * 10_000 + (i - 1200) * 120_000)))
  assert.ok(maxRatePpm(s, 600) >= 119.9)
})

test('nsmDrift fits NSM time against MONOTONIC_RAW', () => {
  // NSM gains 17 ppm on the oscillator.
  const lines = Array.from({ length: 60 }, (_, i) => ({ nsm: { ts_ms: 1.8e12 + i * 60_000 * (1 + 17e-6), mid_raw_ns: i * 60 * S } }))
  const d = nsmDrift(lines)
  assert.equal(d.samples, 60)
  assert.ok(Math.abs(d.ppm - 17) < 0.05, String(d.ppm))
  assert.equal(nsmDrift([]).ppm, null)
})

test('verdict: any failure fails, nothing run is null', () => {
  assert.equal(verdict([check('a', true), check('b', null)]), true)
  assert.equal(verdict([check('a', true), check('b', false)]), false)
  assert.equal(verdict([check('a', null)]), null)
})

test('capBit reads CAP_SYS_TIME from a CapEff mask', () => {
  assert.equal(capBit('000001ffffffffff', 25), true)
  assert.equal(capBit('00000000a80425fb', 25), false)
  assert.equal(capBit('nonsense', 25), null)
})

test('parseStat and cpuPercent', () => {
  const stat = '123 (nsm-timefeed) S 1 1 1 0 -1 4194304 10 0 0 0 7 3 0 0 20 0 1 0 555 0 0'
  assert.deepEqual(parseStat(stat), { state: 'S', utime: 7, stime: 3, starttime: 555 })
  assert.equal(parseStat('garbage'), null)
  assert.equal(cpuPercent({ utime: 7, stime: 3 }, { utime: 17, stime: 8 }, 100, 100), 0.15)
})

test('chronyConf names the configuration', () => {
  assert.equal(chronyConf('chronyd\0-n\0-f\0/etc/chrony/run.conf\0-l\0/dev/null\0'), 'run.conf')
  assert.equal(chronyConf('chronyd\0-n\0'), null)
})

test('percentileAbs', () => {
  assert.equal(percentileAbs([-3, 1, 2], 1), 3)
  assert.equal(percentileAbs([], 0.5), null)
})
