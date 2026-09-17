import { test } from 'node:test'
import assert from 'node:assert/strict'
import { resolveRange, validTimezone } from '../time.mjs'

const now = new Date('2026-09-17T15:45:12.345Z')
const invalidRange = { message: 'invalid_time_range' }

test('default and all ranges freeze their upper bound to the supplied clock', () => {
  for (const input of [undefined, {}, { period: 'all' }]) {
    const result = resolveRange(input, 'UTC', now)
    assert.equal(result.from, '1970-01-01T00:00:00.000Z')
    assert.equal(result.until, '2026-09-17T15:45:12.345Z')
    assert.equal(result.now, result.until)
    assert.equal(result.timezone, 'UTC')
  }
  assert.equal(now.toISOString(), '2026-09-17T15:45:12.345Z')
})

test('relative periods use civil dates in the requested zone', () => {
  for (const [period, from, until] of [
    ['today', '2026-09-17T03:00:00.000Z', '2026-09-17T15:45:12.345Z'],
    ['yesterday', '2026-09-16T03:00:00.000Z', '2026-09-17T03:00:00.000Z'],
    ['yesterday_evening', '2026-09-16T21:00:00.000Z', '2026-09-17T03:00:00.000Z'],
    ['last_7_days', '2026-09-11T03:00:00.000Z', '2026-09-17T15:45:12.345Z'],
  ]) {
    const result = resolveRange({ period }, 'America/Sao_Paulo', now)
    assert.equal(result.from, from, period)
    assert.equal(result.until, until, period)
    assert.equal(result.timezone, 'America/Sao_Paulo')
    assert.equal(result.now, '2026-09-17T15:45:12.345Z')
    assert.equal(typeof result.definition, 'string')
  }
})

test('yesterday follows 23-hour and 25-hour New York days', () => {
  const spring = resolveRange({ period: 'yesterday' }, 'America/New_York', new Date('2024-03-11T12:00:00Z'))
  assert.equal(spring.from, '2024-03-10T05:00:00.000Z')
  assert.equal(spring.until, '2024-03-11T04:00:00.000Z')
  const autumn = resolveRange({ period: 'yesterday' }, 'America/New_York', new Date('2024-11-04T12:00:00Z'))
  assert.equal(autumn.from, '2024-11-03T04:00:00.000Z')
  assert.equal(autumn.until, '2024-11-04T05:00:00.000Z')
})

test('last seven days starts six civil dates ago even across DST', () => {
  const result = resolveRange({ period: 'last_7_days' }, 'America/New_York', new Date('2024-03-11T12:00:00Z'))
  assert.equal(result.from, '2024-03-05T05:00:00.000Z')
  assert.equal(result.until, '2024-03-11T12:00:00.000Z')
})

test('a skipped Sao Paulo midnight starts at the first real instant of that day', () => {
  const yesterday = resolveRange({ period: 'yesterday' }, 'America/Sao_Paulo', new Date('2018-11-05T12:00:00Z'))
  assert.equal(yesterday.from, '2018-11-04T03:00:00.000Z')
  assert.equal(yesterday.until, '2018-11-05T02:00:00.000Z')
  const today = resolveRange({ period: 'today' }, 'America/Sao_Paulo', new Date('2018-11-04T12:00:00Z'))
  assert.equal(today.from, '2018-11-04T03:00:00.000Z')
  const repeatedEvening = resolveRange({ period: 'yesterday_evening' }, 'America/Sao_Paulo', new Date('2019-02-17T12:00:00Z'))
  assert.equal(repeatedEvening.from, '2019-02-16T20:00:00.000Z')
  assert.equal(repeatedEvening.until, '2019-02-17T03:00:00.000Z')
})

test('non-hour offsets and leap-year month boundaries preserve local dates', () => {
  const kathmandu = resolveRange({ period: 'today' }, 'Asia/Kathmandu', new Date('2026-09-17T01:00:00Z'))
  assert.equal(kathmandu.from, '2026-09-16T18:15:00.000Z')
  const leap = resolveRange({ period: 'yesterday' }, 'UTC', new Date('2024-03-01T12:00:00Z'))
  assert.equal(leap.from, '2024-02-29T00:00:00.000Z')
  assert.equal(leap.until, '2024-03-01T00:00:00.000Z')
})

test('explicit RFC3339 bounds retain offsets and nanoseconds exactly', () => {
  const input = { from: '2026-09-17T11:00:00.123456788-03:00', until: '2026-09-17T14:00:00.123456789Z' }
  assert.deepEqual(resolveRange(input, 'Asia/Kathmandu', now), { ...input, timezone: 'Asia/Kathmandu', now: '2026-09-17T15:45:12.345Z' })
  assert.throws(() => resolveRange({ from: input.until, until: input.from }, 'UTC', now), invalidRange)
  assert.throws(() => resolveRange({ from: input.from, until: '2026-09-17T14:00:00.123456788Z' }, 'UTC', now), invalidRange)
})

test('invalid calendar dates, times and offset-free timestamps are rejected', () => {
  for (const from of [
    '2025-02-29T12:00:00Z', '2026-02-30T12:00:00Z', '2026-04-31T12:00:00Z',
    '2026-00-01T00:00:00Z', '2026-13-01T00:00:00Z', '2026-09-00T00:00:00Z',
    '2026-09-17', '2026-09-17T12:00:00', '2026-09-17T24:00:00Z',
    '2026-09-17T12:60:00Z', '2026-09-17T12:00:60Z',
    '2026-09-17T12:00:00+24:00', '2026-09-17T12:00:00+01:60',
    '2026-09-17T12:00:00Z trailing', '', null, 12,
  ]) assert.throws(() => resolveRange({ from, until: '2026-10-01T00:00:00Z' }, 'UTC', now), invalidRange, String(from))
})

test('mixed, incomplete, empty and reversed ranges fail without echoing inputs', () => {
  for (const input of [
    null, [], 'yesterday', { period: 'private-value' }, { period: null },
    { from: '2026-09-17T12:00:00Z' }, { until: '2026-09-17T12:00:00Z' },
    { period: 'today', from: '2026-09-17T12:00:00Z', until: '2026-09-18T12:00:00Z' },
    { from: '2026-09-17T12:00:00Z', until: '2026-09-17T12:00:00Z' },
    { from: '2026-09-18T12:00:00Z', until: '2026-09-17T12:00:00Z' },
  ]) assert.throws(() => resolveRange(input, 'UTC', now), invalidRange)
  assert.throws(() => resolveRange({ period: 'today' }, 'UTC', new Date('2026-09-17T00:00:00Z')), invalidRange)
  assert.throws(() => resolveRange({}, 'UTC', new Date(NaN)), invalidRange)
  assert.throws(() => resolveRange({}, 'UTC', '2026-09-17T12:00:00Z'), invalidRange)
})

test('timezone validation is explicit and never silently uses the host timezone', () => {
  for (const timezone of ['UTC', 'America/New_York', 'America/Sao_Paulo', 'Asia/Kathmandu']) assert.equal(validTimezone(timezone), true)
  for (const timezone of ['', 'America/Unknown', '../private-value', null, 1, {}, undefined]) {
    assert.equal(validTimezone(timezone), false)
    if (timezone !== undefined) assert.throws(() => resolveRange({}, timezone, now), { message: 'invalid_timezone' })
  }
})
