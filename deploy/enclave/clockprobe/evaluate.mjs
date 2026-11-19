// The clock probe's arithmetic (deploy/enclave/clockprobe), kept apart from
// clockprobe-run.mjs so it can be tested off-Nitro (evaluate.test.mjs). Pure
// functions only: no clock, no process, no file.
//
// "corr" is CLOCK_REALTIME - CLOCK_MONOTONIC_RAW, the quantity nsm-timefeed's
// ledger watches: a step of the system clock moves it at once, slewing and
// frequency correction move it slowly. nsm-p0 watch writes the three clocks
// once a second; these functions read those lines.

/** A step: corr moving by more than this between two readings a second apart. */
export const STEP_MS = 100

/** The JSON lines of `text` that parse to objects; others are skipped. */
export function parseJsonl(text) {
  const out = []
  for (const line of String(text ?? '').split('\n')) {
    if (!line.trim()) continue
    try {
      const value = JSON.parse(line)
      if (value && typeof value === 'object') out.push(value)
    } catch { /* a line cut by a kill: skipped */ }
  }
  return out
}

/** nsm-p0 watch lines as {raw_ns, mono_ns, real_ns, corr_ns, nsm}. */
export function corrSeries(lines) {
  return lines
    .filter(l => Number.isFinite(l.real_ns) && Number.isFinite(l.raw_ns))
    .map(l => ({ raw_ns: l.raw_ns, mono_ns: l.mono_ns, real_ns: l.real_ns, corr_ns: l.real_ns - l.raw_ns, nsm: l.nsm ?? null }))
}

/** Every change of corr over `thresholdMs` between consecutive readings: {mono_ns, raw_ns, delta_ms}. */
export function findSteps(series, thresholdMs = STEP_MS) {
  const steps = []
  for (let i = 1; i < series.length; i++) {
    const delta = (series[i].corr_ns - series[i - 1].corr_ns) / 1e6
    if (Math.abs(delta) > thresholdMs) steps.push({ mono_ns: series[i].mono_ns, raw_ns: series[i].raw_ns, delta_ms: Math.round(delta * 1000) / 1000 })
  }
  return steps
}

/** corr with every step taken out: what slewing and frequency correction did. */
export function slewSeries(series, thresholdMs = STEP_MS) {
  let removed = 0
  return series.map((point, i) => {
    if (i > 0) {
      const delta = point.corr_ns - series[i - 1].corr_ns
      if (Math.abs(delta) > thresholdMs * 1e6) removed += delta
    }
    return { raw_ns: point.raw_ns, slew_ns: point.corr_ns - removed }
  })
}

/**
 * The largest |d(corr)/d(raw)| in ppm over any window of `windowS` seconds
 * (steps taken out), or null when the series is shorter than one window.
 * chronyd's caps (maxslewrate 60 + maxdrift 50) bound it at 110 ppm.
 */
export function maxRatePpm(series, windowS = 600, thresholdMs = STEP_MS) {
  const s = slewSeries(series, thresholdMs)
  const window = windowS * 1e9
  let best = null
  let j = 0
  for (let i = 0; i < s.length; i++) {
    while (j < s.length && s[j].raw_ns - s[i].raw_ns < window) j++
    if (j >= s.length) break
    const rate = Math.abs((s[j].slew_ns - s[i].slew_ns) / (s[j].raw_ns - s[i].raw_ns)) * 1e6
    if (best === null || rate > best) best = rate
  }
  return best === null ? null : Math.round(best * 100) / 100
}

/** The average d(corr)/d(raw) in ppm from the first to the last reading (steps taken out). */
export function meanRatePpm(series, thresholdMs = STEP_MS) {
  const s = slewSeries(series, thresholdMs)
  if (s.length < 2) return null
  const a = s[0], b = s[s.length - 1]
  if (b.raw_ns <= a.raw_ns) return null
  return Math.round(((b.slew_ns - a.slew_ns) / (b.raw_ns - a.raw_ns)) * 1e6 * 100) / 100
}

/**
 * The slope of y against x (least squares), or null. Used for the drift of
 * NSM time against MONOTONIC_RAW: x raw seconds, y (NSM - raw) ms, slope in
 * ms per s, which is 1000 ppm.
 */
export function slope(points) {
  const n = points.length
  if (n < 2) return null
  const mx = points.reduce((a, p) => a + p.x, 0) / n
  const my = points.reduce((a, p) => a + p.y, 0) / n
  let num = 0, den = 0
  for (const p of points) { num += (p.x - mx) * (p.y - my); den += (p.x - mx) ** 2 }
  return den === 0 ? null : num / den
}

/**
 * NSM time against MONOTONIC_RAW over a run, from nsm-p0 watch's NSM samples:
 * {samples, span_s, ppm}, where ppm > 0 means NSM time runs faster than the
 * enclave's oscillator (the oscillator loses).
 */
export function nsmDrift(lines) {
  const points = []
  for (const l of lines) {
    const n = l.nsm
    if (!n || !Number.isFinite(n.ts_ms) || !Number.isFinite(n.mid_raw_ns)) continue
    points.push({ x: n.mid_raw_ns / 1e9, y: n.ts_ms - n.mid_raw_ns / 1e6 })
  }
  const span = points.length > 1 ? points[points.length - 1].x - points[0].x : 0
  const k = slope(points)
  return { samples: points.length, span_s: Math.round(span), ppm: k === null ? null : Math.round(k * 1000 * 100) / 100 }
}

/** Nearest-rank percentile of |values| (null when empty). */
export function percentileAbs(values, p) {
  const v = values.filter(Number.isFinite).map(Math.abs).sort((a, b) => a - b)
  if (!v.length) return null
  return v[Math.min(v.length - 1, Math.max(0, Math.ceil(p * v.length) - 1))]
}

/** One machine-readable check. `pass` is true, false, or null (not run). */
export const check = (name, pass, value = null, want = null) => ({ name, pass: pass === null ? null : Boolean(pass), value, want })

/** A scenario's verdict: false if any check failed, true if every check that ran passed, null if none ran. */
export function verdict(checks) {
  const ran = checks.filter(c => c.pass !== null)
  if (!ran.length) return null
  return ran.every(c => c.pass)
}

/** Whether capability `bit` is set in a /proc status hex mask (CAP_SYS_TIME is 25). */
export function capBit(hex, bit) {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]+$/.test(hex)) return null
  return ((BigInt(`0x${hex}`) >> BigInt(bit)) & 1n) === 1n
}

/** CAP_SYS_TIME's bit in the capability masks. */
export const CAP_SYS_TIME = 25

/**
 * A process's CPU use between two /proc/<pid>/stat readings
 * ({utime, stime} in clock ticks), as a percentage of one CPU over `seconds`.
 */
export function cpuPercent(before, after, seconds, ticksPerSecond = 100) {
  if (!before || !after || !(seconds > 0)) return null
  const ticks = (after.utime + after.stime) - (before.utime + before.stime)
  return Math.round((ticks / ticksPerSecond / seconds) * 100 * 1000) / 1000
}

/** /proc/<pid>/stat's fields after the command name: state, utime, stime, starttime. */
export function parseStat(text) {
  const close = String(text).lastIndexOf(')')
  if (close < 0) return null
  const f = String(text).slice(close + 2).split(' ')
  // f[0] is field 3 (state); utime is field 14, stime 15, starttime 22.
  const utime = Number(f[11]), stime = Number(f[12]), starttime = Number(f[19])
  if (![utime, stime, starttime].every(Number.isFinite)) return null
  return { state: f[0], utime, stime, starttime }
}

/** The chrony configuration a chronyd command line names (boot.conf, run.conf, or null). */
export function chronyConf(cmdline) {
  const args = String(cmdline ?? '').split('\0')
  const i = args.indexOf('-f')
  if (i < 0 || i + 1 >= args.length) return null
  return args[i + 1].split('/').pop()
}
