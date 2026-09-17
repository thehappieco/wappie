const hourMS = 3_600_000
const timestamp = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/
const definitions = {
  all: 'From the Unix epoch until now.',
  today: 'From the start of the current local day until now.',
  yesterday: 'The preceding local calendar day, from its start to the start of today.',
  yesterday_evening: 'The preceding local calendar day from 18:00 until the start of today.',
  last_7_days: 'From the start of the local calendar day six dates ago until now.',
}
const invalidRange = () => new Error('invalid_time_range')

export function validTimezone(value) {
  if (typeof value !== 'string' || value.length === 0) return false
  try { new Intl.DateTimeFormat('en', { timeZone: value }); return true }
  catch { return false }
}

function civilDate(year, month, day, hour = 0, minute = 0, second = 0) {
  // Date.UTC treats years 0–99 specially; setUTCFullYear does not.
  const date = new Date(0)
  date.setUTCFullYear(year, month - 1, day)
  date.setUTCHours(hour, minute, second, 0)
  return date
}

function nanoseconds(value) {
  if (typeof value !== 'string') throw invalidRange()
  const match = timestamp.exec(value)
  if (!match) throw invalidRange()
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number)
  const date = civilDate(year, month, day, hour, minute, second)
  if (date.getUTCFullYear() !== year || date.getUTCMonth() + 1 !== month ||
      date.getUTCDate() !== day || date.getUTCHours() !== hour ||
      date.getUTCMinutes() !== minute || date.getUTCSeconds() !== second) throw invalidRange()
  const offsetHour = Number(match[10] ?? 0), offsetMinute = Number(match[11] ?? 0)
  if (offsetHour > 23 || offsetMinute > 59) throw invalidRange()
  const offsetSeconds = (offsetHour * 3600 + offsetMinute * 60) * (match[9] === '-' ? -1 : 1)
  return BigInt(date.getTime() / 1000 - offsetSeconds) * 1_000_000_000n +
    BigInt((match[7] ?? '').padEnd(9, '0'))
}

function localClock(formatter, instant) {
  const parts = Object.fromEntries(formatter.formatToParts(instant).map(part => [part.type, part.value]))
  const year = parts.era === 'BC' ? 1 - Number(parts.year) : Number(parts.year)
  return civilDate(year, Number(parts.month), Number(parts.day), Number(parts.hour), Number(parts.minute), Number(parts.second))
}

function boundary(formatter, date, days = 0, hour = 0) {
  const target = civilDate(date.getUTCFullYear(), date.getUTCMonth() + 1, date.getUTCDate() + days, hour).getTime()
  const offsets = new Set()
  // Sample both sides of the civil date. Using the offset at `now` would shift
  // boundaries on a DST transition; these candidates also cover midnight folds.
  for (let hours = -48; hours <= 48; hours += 6) {
    const instant = target + hours * hourMS
    offsets.add(localClock(formatter, instant).getTime() - instant)
  }
  const candidates = [...offsets].map(offset => target - offset).sort((a, b) => a - b)
  for (const candidate of candidates) {
    if (localClock(formatter, candidate).getTime() === target) return candidate
  }
  // A civil boundary inside a clock gap does not exist. Find the transition's
  // first real instant after it (e.g. Sao Paulo's skipped midnight), rather
  // than carrying an old offset into the following day.
  for (let index = 1; index < candidates.length; index++) {
    let lower = candidates[index - 1], upper = candidates[index]
    if (localClock(formatter, lower).getTime() >= target || localClock(formatter, upper).getTime() < target) continue
    while (upper - lower > 1) {
      const middle = lower + Math.floor((upper - lower) / 2)
      if (localClock(formatter, middle).getTime() >= target) upper = middle
      else lower = middle
    }
    return upper
  }
  throw invalidRange()
}

/** Resolve a half-open archive interval. Explicit bounds keep their exact text. */
export function resolveRange(input = {}, timezone = 'UTC', now = new Date()) {
  if (!validTimezone(timezone)) throw new Error('invalid_timezone')
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      !(now instanceof Date) || !Number.isFinite(now.getTime())) throw invalidRange()
  const clock = now.toISOString()
  nanoseconds(clock)
  const hasFrom = input.from !== undefined, hasUntil = input.until !== undefined
  if (hasFrom || hasUntil) {
    if (!hasFrom || !hasUntil || input.period !== undefined || nanoseconds(input.from) >= nanoseconds(input.until)) throw invalidRange()
    return { from: input.from, until: input.until, timezone, now: clock }
  }
  const period = input.period === undefined ? 'all' : input.period
  if (typeof period !== 'string' || !Object.hasOwn(definitions, period)) throw invalidRange()
  let from = '1970-01-01T00:00:00.000Z', until = clock
  if (period !== 'all') {
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone, calendar: 'gregory', numberingSystem: 'latn', era: 'short',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
    })
    const today = localClock(formatter, now)
    const previous = period === 'yesterday' || period === 'yesterday_evening'
    from = new Date(boundary(formatter, today, previous ? -1 : period === 'last_7_days' ? -6 : 0,
      period === 'yesterday_evening' ? 18 : 0)).toISOString()
    if (previous) until = new Date(boundary(formatter, today)).toISOString()
  }
  if (nanoseconds(from) >= nanoseconds(until)) throw invalidRange()
  return { from, until, timezone, now: clock, definition: definitions[period] }
}
