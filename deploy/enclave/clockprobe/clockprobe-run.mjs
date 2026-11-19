// The clock probe's runner, inside the probe enclave (deploy/enclave/clockprobe).
// NEVER in the release image. entrypoint-clockprobe.sh starts it as a child.
//
// It runs the scenarios of the reader 0.6.1 plan (section 5) on the enclave's
// own kernel, with the release image's own clock: /usr/local/sbin/wappie-clock-start,
// chronyd, its configuration and nsm-timefeed, byte for byte, and the reader's
// clock.mjs through kms-sampler.mjs. Each scenario starts from a fresh clock:
// every chronyd, nsm-timefeed and sampler of the last one killed, /run/chrony
// and /run/wappie-clock removed, the kernel's frequency and tick put back to
// their boot values, and CLOCK_REALTIME set to NSM time (nsm-p0 align). Then
// it injects its fault and calls wappie-clock-start, as the release
// entrypoint does.
//
// Which run this boot is, and its settings, come from the parent's control
// server (control.py on vsock 9103; `hello`): main (P0, S1-S7 and the in-run
// part of S9), s8 (the parent's clock, S8) or s9boot (KMS blocked from boot,
// S9). The parent also blocks KMS and moves its own clock when asked.
//
// Output: one record per section on stdout, `CPR <seq> <bytes> <json>`, with
// json {section, t, data} (t is the enclave's uptime in s), and the same
// JSON in /run/clockprobe/report.jsonl, which the entrypoint prints again at
// the end. Progress lines start with `CP `. A scenario record is
// {section:"scenario", data:{id, pass, checks:[{name, pass, value, want}],
// observations}}; pass is true, false or null (not run).
//
// Environment (local smoke runs only): CLOCKPROBE_OUT, CLOCKPROBE_RUN,
// CLOCKPROBE_SCENARIOS (a comma list), CLOCKPROBE_PARENT_CID,
// CLOCKPROBE_CONTROL_PORT, CLOCKPROBE_NSM_P0, CLOCKPROBE_SAMPLER, CLOCKPROBE_S5_S,
// CLOCKPROBE_S6_S.
import { spawn } from 'node:child_process'
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, readlinkSync, rmSync, writeFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import {
  CAP_SYS_TIME, capBit, check, chronyConf, corrSeries, cpuPercent, findSteps, maxRatePpm, meanRatePpm,
  nsmDrift, parseJsonl, parseStat, percentileAbs, verdict,
} from './evaluate.mjs'

const OUT = process.env.CLOCKPROBE_OUT ?? '/run/clockprobe'
const P0 = process.env.CLOCKPROBE_NSM_P0 ?? '/opt/clockprobe/bin/nsm-p0'
const SAMPLER = process.env.CLOCKPROBE_SAMPLER ?? new URL('./kms-sampler.mjs', import.meta.url).pathname
const FAKE_DIR = '/opt/clockprobe/fake'
const CLOCK_START = '/usr/local/sbin/wappie-clock-start'
const STATE_FILE = '/run/wappie-clock/state.json'
const LEDGER_FILE = '/run/wappie-clock/ledger'
const BOOT_FILE = '/run/wappie-clock/boot'
const PIDFILE = '/run/chrony/chronyd.pid'
const PARENT_CID = process.env.CLOCKPROBE_PARENT_CID ?? '3'
const CONTROL_PORT = process.env.CLOCKPROBE_CONTROL_PORT ?? '9103'

// Plan values the checks compare against (reader 0.6.1 plan, sections 2, 3 and 5).
const READY_WAIT_S = 240          // clock.ready() gives up at 180 s; this is the probe's own bound
const SKEW_OK_MS = 50             // |nsm_skew_ms| once synced (S1/S2)
const RATE_CAP_PPM = 110          // maxslewrate 60 + maxdrift 50
const RATE_SLACK_PPM = 5          // the watch's own reading noise over a 10-minute window
const HOUR_CAP_MS = 5000          // nsm-timefeed HOUR_CAP
const CPU_BUDGET_PERCENT = 5      // nsm-timefeed + chronyd on the enclave's one vCPU
const RTT_HARD_CAP_MS = 500       // nsm-timefeed RTT_HARD_CAP_NS

mkdirSync(OUT, { recursive: true })
const REPORT = `${OUT}/report.jsonl`
const uptime = () => { try { return Number(readFileSync('/proc/uptime', 'utf8').split(' ')[0]) } catch { return null } }
const monoS = () => Number(process.hrtime.bigint()) / 1e9
const monoNs = () => Number(process.hrtime.bigint())
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
const say = text => process.stdout.write(`CP ${text}\n`)

let seq = 0
function emit(section, data) {
  const json = JSON.stringify({ section, t: uptime(), data })
  process.stdout.write(`CPR ${seq++} ${Buffer.byteLength(json)} ${json}\n`)
  try { appendFileSync(REPORT, `${json}\n`) } catch { /* stdout still has it */ }
}

process.on('uncaughtException', e => emit('fatal', { kind: 'uncaughtException', message: String(e?.stack ?? e) }))
process.on('unhandledRejection', e => emit('fatal', { kind: 'unhandledRejection', message: String(e?.stack ?? e) }))

// ---------------------------------------------------------------- processes

/** Runs a command to its end (or its timeout): {code, signal, stdout, stderr, ms}. */
function run(cmd, args = [], { timeoutMs = 60_000, input = null, env = process.env } = {}) {
  return new Promise(resolve => {
    const started = monoS()
    let child
    try { child = spawn(cmd, args, { env, stdio: [input === null ? 'ignore' : 'pipe', 'pipe', 'pipe'] }) } catch (e) {
      resolve({ code: null, signal: null, stdout: '', stderr: String(e), ms: 0 }); return
    }
    let stdout = '', stderr = ''
    child.stdout.on('data', d => { stdout += d })
    child.stderr.on('data', d => { stderr += d })
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs)
    child.on('error', e => { stderr += String(e) })
    child.on('close', (code, signal) => {
      clearTimeout(timer)
      resolve({ code, signal, stdout, stderr: stderr.slice(-2000), ms: Math.round((monoS() - started) * 1000) })
    })
    if (input !== null) { child.stdin.on('error', () => {}); child.stdin.end(input) }
  })
}

/** nsm-p0's JSON answer, or {ok:false, error, code}. */
async function p0(args, timeoutMs = 120_000) {
  const r = await run(P0, args, { timeoutMs })
  const last = r.stdout.trim().split('\n').pop()
  try { return { ...JSON.parse(last), code: r.code } } catch { return { ok: false, error: r.stderr.trim() || `exit ${r.code} signal ${r.signal}`, code: r.code } }
}

/** One request to the parent's control server, or null when it does not answer. */
async function control(request, timeoutMs = 120_000) {
  const r = await run('socat', ['-t', '5', '-T', String(Math.ceil(timeoutMs / 1000)), '-', `VSOCK-CONNECT:${PARENT_CID}:${CONTROL_PORT}`],
    { input: `${request}\n`, timeoutMs: timeoutMs + 5000 })
  try { return JSON.parse(r.stdout.trim().split('\n').pop()) } catch { return null }
}

// Process groups this runner started (wappie-clock-start's loops, samplers,
// watchers): each is killed whole at the next reset.
const groups = new Set()
function startGroup(cmd, args, env = process.env) {
  const child = spawn(cmd, args, { detached: true, stdio: 'ignore', env })
  child.on('error', () => {})
  groups.add(child.pid)
  const exit = new Promise(resolve => child.on('exit', (code, signal) => resolve({ code, signal, at: monoS() })))
  return { pid: child.pid, exit }
}
function killGroups() {
  for (const pgid of groups) { try { process.kill(-pgid, 'SIGKILL') } catch { /* gone */ } }
  groups.clear()
}

/** Live processes whose comm is `name`: [{pid, cmdline, exe, stat}]. Zombies are left out. */
function procs(name) {
  const found = []
  for (const entry of readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue
    try {
      if (readFileSync(`/proc/${entry}/comm`, 'utf8').trim() !== name) continue
      const stat = parseStat(readFileSync(`/proc/${entry}/stat`, 'utf8'))
      if (!stat || stat.state === 'Z') continue
      let exe = null
      try { exe = readlinkSync(`/proc/${entry}/exe`) } catch { /* a kernel thread or gone */ }
      found.push({ pid: Number(entry), cmdline: readFileSync(`/proc/${entry}/cmdline`, 'utf8'), exe, stat })
    } catch { /* it ended meanwhile */ }
  }
  return found
}

function capabilities(pid) {
  try {
    const status = readFileSync(`/proc/${pid}/status`, 'utf8')
    const get = key => (new RegExp(`^${key}:\\s+([0-9a-f]+)$`, 'm').exec(status) ?? [])[1] ?? null
    const eff = get('CapEff')
    return { pid, CapEff: eff, CapPrm: get('CapPrm'), CapBnd: get('CapBnd'), cap_sys_time: capBit(eff, CAP_SYS_TIME) }
  } catch (e) { return { pid, error: String(e.code ?? e) } }
}

const readText = path => { try { return readFileSync(path, 'utf8') } catch { return null } }
const readJson = path => { try { return JSON.parse(readFileSync(path, 'utf8')) } catch { return null } }
const readLines = path => parseJsonl(readText(path))

// ---------------------------------------------------------------- the clock

let bootTimex = null     // adjtimex at boot, before any chronyd: restored at each reset
const hasNsm = existsSync('/dev/nsm')

/** A fresh clock for the next scenario (see the top of this file). */
async function reset(id) {
  killGroups()
  await sleep(300)
  for (const name of ['chronyd', 'nsm-timefeed']) for (const p of procs(name)) { try { process.kill(p.pid, 'SIGKILL') } catch { /* gone */ } }
  await sleep(300)
  rmSync('/run/chrony', { recursive: true, force: true })
  rmSync('/run/wappie-clock', { recursive: true, force: true })
  const dir = `${OUT}/${id}`
  mkdirSync(dir, { recursive: true })
  const restored = bootTimex ? await p0(['restore', String(bootTimex.freq_raw), String(bootTimex.tick)]) : null
  const aligned = await p0(['align'])
  const watch = `${dir}/watch.jsonl`
  startGroup(P0, ['watch', watch, '30'])
  say(`${id}: reset (align ${aligned.ok ? `${aligned.offset_before_ns} ns` : aligned.error})`)
  return { dir, watch, aligned, restored }
}

function startClock({ fake = false } = {}) {
  const env = fake ? { ...process.env, PATH: `${FAKE_DIR}:${process.env.PATH}` } : process.env
  return startGroup(CLOCK_START, [], env)
}

function startSampler(dir, mode) {
  const file = `${dir}/kms.jsonl`
  const proc = startGroup(process.execPath, [SAMPLER, file, mode])
  return { file, ...proc, lines: () => readLines(file) }
}

/** One look at the clock: state.json, chronyd and nsm-timefeed. */
function look(t0) {
  const chronyd = procs('chronyd').map(p => ({ pid: p.pid, conf: chronyConf(p.cmdline), cpu: p.stat.utime + p.stat.stime }))
  const feed = procs('nsm-timefeed').map(p => ({ pid: p.pid, exe: p.exe, cpu: p.stat.utime + p.stat.stime }))
  return { t: Math.round((monoS() - t0) * 10) / 10, state: readJson(STATE_FILE), chronyd, feed }
}

/**
 * Looks every 2 s for up to `seconds`, until `until(look, looks)` holds.
 * Returns the looks.
 */
async function observe(seconds, t0, until = null, looks = []) {
  const end = monoS() + seconds
  while (monoS() < end) {
    const l = look(t0)
    looks.push(l)
    if (until && until(l, looks)) break
    await sleep(2000)
  }
  return looks
}

/** The looks thinned to one every `everyS` seconds, for the report. */
const thin = (looks, everyS = 20) => looks.filter((l, i) => i === 0 || i === looks.length - 1 || Math.floor(l.t / everyS) !== Math.floor(looks[i - 1].t / everyS))
  .map(l => ({ t: l.t, state: l.state?.state ?? null, synced: l.state?.synced ?? null, nsm_skew_ms: l.state?.nsm_skew_ms ?? null, rtt_us: l.state?.rtt_us ?? null, good: l.state?.good ?? null, bad: l.state?.bad ?? null, corr_hour_ms: l.state?.corr_hour_ms ?? null, corr_day_ms: l.state?.corr_day_ms ?? null, freq_ppm: l.state?.freq_ppm ?? null, steps: l.state?.steps ?? null, chronyd: l.chronyd.map(c => `${c.pid}:${c.conf}`).join(','), feed: l.feed.map(f => f.pid).join(',') }))

/** chronyd and nsm-timefeed processes seen over the looks: their pids, in order, and chronyd's configuration. */
function lifecycle(looks) {
  const chronyd = [], feed = []
  for (const l of looks) {
    for (const c of l.chronyd) if (!chronyd.some(x => x.pid === c.pid)) chronyd.push({ pid: c.pid, conf: c.conf, first_t: l.t })
    for (const f of l.feed) if (!feed.some(x => x.pid === f.pid)) feed.push({ pid: f.pid, first_t: l.t })
  }
  return { chronyd, feed }
}

/** Waits for the helper to say ok and synced, and for the sampler's ready() (when there is one). */
async function waitReady(t0, sampler, looks = []) {
  let ready = null
  await observe(READY_WAIT_S, t0, () => {
    ready = sampler?.lines().find(x => x.kind === 'ready') ?? null
    const s = looks[looks.length - 1]?.state
    return (sampler ? ready !== null : true) && s?.state === 'ok' && s?.synced === true
  }, looks)
  const syncedAt = looks.find(l => l.state?.state === 'ok' && l.state?.synced)?.t ?? null
  return { ready, syncedAt, looks }
}

const ticksAfter = (sampler, monoMs) => sampler.lines().filter(x => x.kind === 'tick' && x.mono_ms >= monoMs)
// The sampler's mono_ms is CLOCK_MONOTONIC in ms, as this is.
const samplerNow = () => Math.round(monoNs() / 1e6)
const skews = looks => looks.map(l => l.state?.nsm_skew_ms).filter(Number.isFinite)

function scenarioRecord(id, title, checks, observations) {
  const data = { id, title, pass: verdict(checks), checks, observations }
  emit('scenario', data)
  say(`${id}: ${data.pass === null ? 'not run' : data.pass ? 'PASS' : 'FAIL'}${checks.filter(c => c.pass === false).map(c => ` [${c.name}]`).join('')}`)
  return data
}

function notRun(id, title, why) {
  return scenarioRecord(id, title, [check('ran', null, why)], { why })
}

// ---------------------------------------------------------------- P0

async function scenarioP0() {
  const id = 'P0'
  const obs = {}
  obs.capabilities = { pid1: capabilities(1), entrypoint: capabilities(process.ppid), runner: capabilities(process.pid) }
  obs.clocksource = {
    current: readText('/sys/devices/system/clocksource/clocksource0/current_clocksource')?.trim() ?? null,
    available: readText('/sys/devices/system/clocksource/clocksource0/available_clocksource')?.trim() ?? null,
  }
  obs.kernel = await p0(['kernel'])
  if (obs.kernel.ok && obs.kernel.adjtimex_read?.freq_raw !== undefined) bootTimex = obs.kernel.adjtimex_read
  obs.boot_sample = readJson(`${OUT}/boot-sample.json`)
  obs.uname = readText('/proc/sys/kernel/osrelease')?.trim() ?? null
  obs.cpus = readText('/sys/devices/system/cpu/online')?.trim() ?? null
  const checks = [
    check('cap_sys_time_pid1', obs.capabilities.pid1.cap_sys_time === true, obs.capabilities.pid1.CapEff, 'bit 25 set'),
    check('cap_sys_time_entrypoint', obs.capabilities.entrypoint.cap_sys_time === true, obs.capabilities.entrypoint.CapEff, 'bit 25 set'),
    check('clock_settime_works', obs.kernel.clock_settime_now?.ok === true, obs.kernel.clock_settime_now ?? obs.kernel.error, 'ok'),
    check('adjtimex_write_works', obs.kernel.adjtimex_write_same_freq?.ok === true, obs.kernel.adjtimex_write_same_freq ?? obs.kernel.error, 'ok'),
  ]
  if (!hasNsm) {
    checks.push(check('dev_nsm', false, 'absent', 'present'))
    return scenarioRecord(id, 'P0 measurements', checks, obs)
  }

  say('P0: 1000 NSM requests alone')
  obs.latency_alone = await p0(['latency', '1000', 'alone'], 600_000)
  say('P0: 1000 NSM requests while nsm-attest runs 10 times a second')
  const load = { started: 0, exits: {} }
  const pending = []
  const loader = setInterval(() => {
    load.started++
    pending.push(run('/usr/local/bin/nsm-attest', ['-', randomBytes(32).toString('hex'), '-'], { timeoutMs: 10_000 })
      .then(r => { const k = r.signal ? `signal ${r.signal}` : `exit ${r.code}`; load.exits[k] = (load.exits[k] ?? 0) + 1 }))
  }, 100)
  obs.latency_load = await p0(['latency', '1000', 'nsm-attest-10-per-s'], 600_000)
  clearInterval(loader)
  await Promise.all(pending)
  obs.latency_load_generator = load
  say('P0: concurrent opens of /dev/nsm')
  obs.concurrent = await p0(['concurrent', '200'], 300_000)

  // The CPU of the real clock for 120 s from an aligned clock: nsm-timefeed's
  // best-of-3 cycle every 4 s and chronyd, and chronyd's capabilities.
  say('P0: the clock for 120 s, for its CPU use')
  const r = await reset('P0')
  startClock()
  const t0 = monoS()
  const looks = await observe(30, t0)
  const first = { tf: procs('nsm-timefeed')[0], cd: procs('chronyd')[0], at: monoS() }
  await observe(120, t0, null, looks)
  const last = { tf: procs('nsm-timefeed').find(p => p.pid === first.tf?.pid), cd: procs('chronyd').find(p => p.pid === first.cd?.pid), at: monoS() }
  const tick = 100 // USER_HZ on Linux arm64
  obs.cpu = {
    seconds: Math.round(last.at - first.at),
    nsm_timefeed_percent: cpuPercent(first.tf?.stat, last.tf?.stat, last.at - first.at, tick),
    chronyd_percent: cpuPercent(first.cd?.stat, last.cd?.stat, last.at - first.at, tick),
  }
  obs.capabilities.chronyd = first.cd ? capabilities(first.cd.pid) : null
  obs.capabilities.nsm_timefeed = first.tf ? capabilities(first.tf.pid) : null
  obs.clock_run = thin(looks, 30)
  obs.align = r.aligned

  const goodShare = l => (l?.n ? l.good / l.n : 0)
  const p99ms = l => (l?.good_rtt_ns?.p99 ?? Infinity) / 1e6
  const res = obs.latency_alone?.resolution
  const cpuTotal = (obs.cpu.nsm_timefeed_percent ?? Infinity) + (obs.cpu.chronyd_percent ?? Infinity)
  checks.push(
    check('cap_sys_time_chronyd', obs.capabilities.chronyd?.cap_sys_time === true, obs.capabilities.chronyd?.CapEff ?? null, 'bit 25 set'),
    check('nsm_good_alone', goodShare(obs.latency_alone) >= 0.99, obs.latency_alone?.good ?? obs.latency_alone?.error, '>= 99% of 1000'),
    check('nsm_good_under_load', goodShare(obs.latency_load) >= 0.99, obs.latency_load?.good ?? obs.latency_load?.error, '>= 99% of 1000'),
    check('rtt_p99_alone_ms', p99ms(obs.latency_alone) < RTT_HARD_CAP_MS / 2, p99ms(obs.latency_alone), `< ${RTT_HARD_CAP_MS / 2} (half of RTT_HARD_CAP)`),
    check('rtt_p99_load_ms', p99ms(obs.latency_load) < RTT_HARD_CAP_MS / 2, p99ms(obs.latency_load), `< ${RTT_HARD_CAP_MS / 2} (half of RTT_HARD_CAP)`),
    check('nsm_attest_under_load_ok', (load.exits['exit 0'] ?? 0) >= load.started * 0.99, load.exits, '>= 99% exit 0'),
    check('concurrent_opens', obs.concurrent?.second_open === true && obs.concurrent?.threads_opened === 2
      && obs.concurrent.alternating.good === obs.concurrent.alternating.n && obs.concurrent.threads.good === obs.concurrent.threads.n,
    obs.concurrent?.ok ? { second_open: obs.concurrent.second_open, threads_opened: obs.concurrent.threads_opened } : obs.concurrent?.error, 'two fds and two threads, every request good'),
    check('from_binary_decodes', (obs.latency_alone?.from_binary_decoded ?? 0) > 0, obs.latency_alone?.from_binary_decoded ?? null, '> 0'),
    check('timestamp_resolution_1ms', res?.min_step_ms === 1 && res?.on_1s < 0.05 && res?.backwards === 0, res ? { min_step_ms: res.min_step_ms, on_1s: res.on_1s, backwards: res.backwards } : null, 'min step 1 ms, not whole seconds, never backwards'),
    check('cpu_percent', cpuTotal <= CPU_BUDGET_PERCENT, obs.cpu, `nsm-timefeed + chronyd <= ${CPU_BUDGET_PERCENT}% of one vCPU`),
  )
  // What the "settled by P0" constants rest on (nsm-attest src/timefeed/mod.rs,
  // packages/mcp-http/enclave/clock.mjs NSM_RESOLUTION_MS).
  obs.constants = {
    CYCLE_NS_and_BEST_OF: { value: '4 s, best of 3', cpu_percent: Number.isFinite(cpuTotal) ? cpuTotal : null },
    RTT_HARD_CAP_NS: { value_ms: RTT_HARD_CAP_MS, p99_load_ms: p99ms(obs.latency_load), max_load_ms: (obs.latency_load?.good_rtt_ns?.max ?? null) / 1e6 },
    RTT_FACTOR_and_WINDOW: { value: '2x the minimum of 15 cycles', p50_load_over_min: obs.latency_load?.good_rtt_ns ? Math.round(obs.latency_load.good_rtt_ns.p50 / Math.max(1, obs.latency_load.good_rtt_ns.min) * 100) / 100 : null },
    TS_ROUNDING_NS: { value_ms: 0.5, min_step_ms: res?.min_step_ms ?? null, ts_minus_mid_ns: res?.ts_minus_mid_ns ?? null, note: 'truncation and rounding differ only by a constant 0.5 ms, which no in-enclave measurement can tell apart from the clock offset itself' },
    NSM_RESOLUTION_MS: { value: 1, min_step_ms: res?.min_step_ms ?? null },
  }
  obs.fallback_needed = obs.capabilities.pid1.cap_sys_time !== true || obs.capabilities.chronyd?.cap_sys_time !== true
    || obs.kernel.clock_settime_now?.ok !== true || obs.kernel.adjtimex_write_same_freq?.ok !== true
  return scenarioRecord(id, 'P0 measurements', checks, obs)
}

// ---------------------------------------------------------------- S1-S7

/** S1 and S2: a step of ±90 s before chronyd starts. */
async function scenarioBootStep(id, shiftS) {
  const title = `${shiftS > 0 ? '+' : ''}${shiftS} s before chronyd starts`
  const r = await reset(id)
  const shifted = await p0(['shift', String(shiftS * 1000)])
  const injectMono = monoNs()
  const t0 = monoS()
  startClock()
  const sampler = startSampler(r.dir, 'ready')
  const { ready, syncedAt, looks } = await waitReady(t0, sampler)
  const tReady = looks[looks.length - 1].t
  await observe(60, t0, null, looks)
  const steady = looks.filter(l => l.t >= tReady)
  // The injection itself is not counted: only what the clock did after it.
  const steps = findSteps(corrSeries(readLines(r.watch)).filter(p => p.mono_ns > injectMono))
  const last = looks[looks.length - 1].state
  const life = lifecycle(looks)
  const checks = [
    check('injected', shifted.ok === true, shifted.moved_ns ?? shifted.error, `${shiftS * 1000} ms`),
    check('one_step', steps.length === 1, steps, 'exactly one step'),
    check('step_size', steps.length >= 1 && Math.abs(steps[0].delta_ms + shiftS * 1000) < 2000, steps[0]?.delta_ms ?? null, `${-shiftS * 1000} ms ± 2000`),
    check('helper_ok_synced', syncedAt !== null, syncedAt, `state ok and synced within ${READY_WAIT_S} s`),
    check('synced_within_s', syncedAt !== null && syncedAt <= 180, syncedAt, '<= 180 (the plan expects about 90)'),
    check('nsm_skew_ms_steady', percentileAbs(skews(steady), 1) !== null && percentileAbs(skews(steady), 1) < SKEW_OK_MS, percentileAbs(skews(steady), 1), `< ${SKEW_OK_MS} over the 60 s after ready`),
    check('ready_passes', ready?.ok === true, ready, 'clock.ready() resolves (KMS agreement)'),
    check('helper_steps_field', last?.steps === 1, last?.steps ?? null, '1 (the boot step)'),
    check('no_cap_or_refusal', !looks.some(l => ['cap_exceeded', 'boot_refused'].includes(l.state?.state)), [...new Set(looks.map(l => l.state?.state))], 'never cap_exceeded or boot_refused'),
    check('chronyd_boot_conf_alive', life.chronyd.length === 1 && life.chronyd[0].conf === 'boot.conf' && looks[looks.length - 1].chronyd.length === 1, life.chronyd, 'one chronyd, boot.conf, still running'),
  ]
  return scenarioRecord(id, title, checks, { align: r.aligned, shifted, steps, synced_at_s: syncedAt, ready, chronyd: life.chronyd, feed: life.feed, looks: thin(looks) })
}

/** S3: +700 s before chronyd starts. */
async function scenarioS3() {
  const id = 'S3'
  const r = await reset(id)
  const shifted = await p0(['shift', '700000'])
  const injectMono = monoNs()
  const t0 = monoS()
  startClock()
  const sampler = startSampler(r.dir, 'watch')
  const looks = await observe(150, t0)
  const series = corrSeries(readLines(r.watch))
  const steps = findSteps(series.filter(p => p.mono_ns > injectMono))
  const ticks = sampler.lines().filter(x => x.kind === 'tick')
  const lastTick = ticks[ticks.length - 1]
  const lastState = looks[looks.length - 1].state
  const nsmOffsets = series.filter(p => p.mono_ns > injectMono && p.nsm && Number.isFinite(p.nsm.offset_ns)).map(p => -p.nsm.offset_ns / 1e6)
  const checks = [
    check('injected', shifted.ok === true, shifted.moved_ns ?? shifted.error, '700000 ms'),
    check('boot_refused', lastState?.state === 'boot_refused', lastState?.state ?? null, 'boot_refused'),
    check('refused_within_60_s', (looks.find(l => l.state?.state === 'boot_refused')?.t ?? Infinity) <= 60, looks.find(l => l.state?.state === 'boot_refused')?.t ?? null, '<= 60 s'),
    check('no_step', steps.length === 0, steps, 'no step after the injection'),
    check('clock_stays_ahead_ms', nsmOffsets.length > 0 && nsmOffsets.every(o => Math.abs(o - 700_000) < 2000), nsmOffsets.slice(-3), 'system - NSM stays 700000 ± 2000'),
    check('clock_mjs_not_ok', ticks.length > 0 && ticks.every(t => t.code !== 'ok') && lastTick?.code === 'boot_refused', lastTick?.code ?? null, 'boot_refused, never ok'),
    check('nothing_fed', !looks.some(l => l.state?.synced), null, 'never synced'),
  ]
  return scenarioRecord(id, '+700 s before chronyd starts', checks, { align: r.aligned, shifted, steps, kms_last: lastTick, chronyd: lifecycle(looks).chronyd, looks: thin(looks) })
}

const s9 = { parts: [] }

/** S4: +90 s after sync; then, with the KMS proof it sets, the S9 part that keeps a proof while KMS is held. */
async function scenarioS4(controlOk) {
  const id = 'S4'
  const r = await reset(id)
  const t0 = monoS()
  startClock()
  const sampler = startSampler(r.dir, 'ready')
  const { ready } = await waitReady(t0, sampler)
  const before = look(t0)
  const injectedAtMs = samplerNow()
  const injectMono = monoNs()
  const shifted = await p0(['shift', '90000'])
  const tInject = monoS() - t0
  const looks = await observe(300, t0)
  const after = looks
  const series = corrSeries(readLines(r.watch))
  const steps = findSteps(series)
  const stepBack = steps.filter(s => s.mono_ns > injectMono + 3e9 && s.delta_ms < -1000)
  const capAt = after.find(l => l.state?.state === 'cap_exceeded')?.t ?? null
  const ticks = ticksAfter(sampler, injectedAtMs)
  const provenAt = ticks.find(t => t.proven === 'fast')
  const lastCorr = series[series.length - 1]?.corr_ns
  const corrBefore = series.filter(p => p.mono_ns < injectMono).pop()?.corr_ns
  const life = lifecycle([before, ...after])
  const chronydExited = life.chronyd.length > 1 || after[after.length - 1].chronyd.length === 0
  const checks = [
    check('synced_before', before.state?.state === 'ok' && before.state?.synced === true, before.state?.state ?? null, 'ok and synced before the injection'),
    check('ready_before', ready?.ok === true, ready, 'clock.ready() passed before the injection'),
    check('injected', shifted.ok === true, shifted.moved_ns ?? shifted.error, '90000 ms'),
    check('cap_exceeded_within_60_s', capAt !== null && capAt - tInject <= 60, capAt === null ? null : Math.round(capAt - tInject), '<= 60 s after the injection'),
    check('cap_sticky', after.slice(after.findIndex(l => l.state?.state === 'cap_exceeded')).every(l => l.state?.state === 'cap_exceeded'), null, 'cap_exceeded to the end'),
    check('no_step_back', stepBack.length === 0 && Number.isFinite(lastCorr) && Number.isFinite(corrBefore) && (lastCorr - corrBefore) / 1e6 > 89_000, { step_back: stepBack, corr_moved_ms: Number.isFinite(lastCorr) && Number.isFinite(corrBefore) ? Math.round((lastCorr - corrBefore) / 1e6) : null }, 'the clock stays 90 s ahead'),
    check('clock_mjs_not_ok', ticks.length > 0 && ticks.slice(-3).every(t => t.code !== 'ok'), ticks.slice(-1)[0]?.code ?? null, 'not ok'),
    check('kms_proof_fast', provenAt !== undefined, provenAt ? { after_ms: provenAt.mono_ms - injectedAtMs, range: provenAt.range } : null, "proven 'fast' (about +90 s)"),
  ]
  const obs = {
    align: r.aligned, shifted, steps, chronyd: life.chronyd, chronyd_exited: chronydExited,
    note: 'The plan also lists chronyd_gone: nsm-timefeed checks the ledger before it feeds, so the cycle that sees the jump stops the feed and chronyd may never see the +90 s. Recorded, not required.',
    kms_last: ticks.slice(-1)[0] ?? null, looks: thin([before, ...after]),
  }
  const record = scenarioRecord(id, '+90 s after sync', checks, obs)

  // S9: a proof stays set while KMS is held (it never expires with silence).
  if (!controlOk) {
    s9.parts.push({ part: 'held_keeps_proof', checks: [check('held_keeps_proof', null, 'no parent control server')] })
  } else if (provenAt === undefined) {
    s9.parts.push({ part: 'held_keeps_proof', checks: [check('held_keeps_proof', null, 'S4 set no proof')] })
  } else {
    say('S9: KMS held for 11 minutes with the S4 proof set')
    const blocked = await control('kms block hold')
    const from = samplerNow()
    await observe(660, t0)
    const held = ticksAfter(sampler, from)
    const unblocked = await control('kms unblock')
    const from2 = samplerNow()
    await observe(40, t0)
    const resumed = ticksAfter(sampler, from2)
    s9.parts.push({
      part: 'held_keeps_proof',
      blocked, unblocked,
      checks: [
        check('parent_blocked', blocked?.ok === true, blocked, 'ok'),
        check('no_ranges_while_held', held.length > 0 && held.every(t => t.range === null), held.filter(t => t.range !== null).length, '0 ranges'),
        check('proof_kept_11_min', held.length > 0 && held.every(t => t.proven === 'fast'), [...new Set(held.map(t => t.proven))], "'fast' throughout, past the 10-minute window"),
        check('ranges_resume', resumed.some(t => t.range !== null), resumed.filter(t => t.range !== null).length, '>= 1 after unblock'),
      ],
    })
  }
  return record
}

/** S5: +3 s after sync. */
async function scenarioS5(seconds) {
  const id = 'S5'
  const r = await reset(id)
  const t0 = monoS()
  startClock()
  const sampler = startSampler(r.dir, 'ready')
  const { ready } = await waitReady(t0, sampler)
  const before = look(t0)
  const injectMono = monoNs()
  const shifted = await p0(['shift', '3000'])
  const injectedAtMs = samplerNow()
  const tInject = monoS() - t0
  const looks = await observe(seconds, t0)
  const series = corrSeries(readLines(r.watch))
  const afterSeries = series.filter(p => p.mono_ns > injectMono + 5e9)
  const steps = findSteps(afterSeries)
  const life = lifecycle([before, ...looks])
  const hourMax = Math.max(...looks.map(l => l.state?.corr_hour_ms ?? 0))
  const skewAfter = looks.filter(l => l.t > tInject + 10).map(l => l.state?.nsm_skew_ms).filter(Number.isFinite)
  const ticks = ticksAfter(sampler, injectedAtMs)
  const checks = [
    check('synced_before', before.state?.state === 'ok' && before.state?.synced === true, before.state?.state ?? null, 'ok and synced'),
    check('injected', shifted.ok === true, shifted.moved_ns ?? shifted.error, '3000 ms'),
    check('no_step', steps.length === 0, steps, 'no step after the injection'),
    check('chronyd_no_exit', life.chronyd.length === 1 && looks[looks.length - 1].chronyd.length === 1, life.chronyd, 'the same chronyd throughout'),
    check('no_cap_breach', !looks.some(l => l.state?.state === 'cap_exceeded'), [...new Set(looks.map(l => l.state?.state))], 'never cap_exceeded'),
    check('hour_bucket_records_3s', hourMax >= 2800 && hourMax < HOUR_CAP_MS, hourMax, `about 3000, < ${HOUR_CAP_MS}`),
    check('slew_rate_ppm', seconds < 600 ? null : (maxRatePpm(afterSeries) ?? Infinity) <= RATE_CAP_PPM + RATE_SLACK_PPM, maxRatePpm(afterSeries), `<= ${RATE_CAP_PPM} (+${RATE_SLACK_PPM}) over any 10 min`),
    check('slewing_back', skewAfter.length > 1 && skewAfter[0] - skewAfter[skewAfter.length - 1] > 0.5 * 50e-6 * Math.max(0, seconds - 60) * 1000, skewAfter.length ? { first: skewAfter[0], last: skewAfter[skewAfter.length - 1] } : null, 'nsm_skew_ms falls by at least half of 50 ppm of the run'),
  ]
  return scenarioRecord(id, '+3 s after sync', checks, {
    align: r.aligned, shifted, ready, steps, mean_rate_ppm: meanRatePpm(afterSeries), corr_hour_ms_max: hourMax,
    kms_codes: [...new Set(ticks.map(t => t.code))], looks: thin(looks, 120),
  })
}

/** S6: NSM time made to run 200 ppm fast (the fake-drift nsm-timefeed). */
async function scenarioS6(seconds) {
  const id = 'S6'
  if (!existsSync(`${FAKE_DIR}/nsm-timefeed`)) return notRun(id, '+200 ppm fake drift', 'no fake-drift nsm-timefeed in the image')
  const r = await reset(id)
  const t0 = monoS()
  startClock({ fake: true })
  const sampler = startSampler(r.dir, 'ready')
  const { ready, syncedAt } = await waitReady(t0, sampler)
  const tStart = monoS() - t0
  const startMono = monoNs()
  const looks = await observe(seconds, t0)
  const series = corrSeries(readLines(r.watch)).filter(p => p.mono_ns > startMono)
  const tail = looks.filter(l => l.t >= tStart + 900)
  const sk = tail.map(l => ({ t: l.t, s: l.state?.nsm_skew_ms })).filter(x => Number.isFinite(x.s))
  // NSM runs fast, so the system clock falls behind it: nsm_skew_ms (system - NSM) grows negative.
  const growthPpm = sk.length > 1 ? -((sk[sk.length - 1].s - sk[0].s) / ((sk[sk.length - 1].t - sk[0].t) * 1000)) * 1e6 : null
  const freqs = looks.map(l => l.state?.freq_ppm).filter(Number.isFinite)
  const lastSkew = sk[sk.length - 1]?.s ?? null
  const eta = growthPpm > 0 && Number.isFinite(lastSkew) ? Math.round((5000 - Math.abs(lastSkew)) / (growthPpm * 1e-6 * 1000)) : null
  const ticks = sampler.lines().filter(x => x.kind === 'tick')
  const closed = ticks.find(t => t.code === 'unc_high')
  const crossed = Number.isFinite(lastSkew) && Math.abs(lastSkew) > 5000
  const feedExe = looks.flatMap(l => l.feed).find(f => f.exe)?.exe ?? null
  const checks = [
    check('fake_feed_running', feedExe === `${FAKE_DIR}/nsm-timefeed`, feedExe, `${FAKE_DIR}/nsm-timefeed (first on PATH)`),
    check('synced_first', syncedAt !== null, syncedAt, 'ok and synced before the hour'),
    check('rate_ppm', seconds < 600 ? null : (maxRatePpm(series) ?? Infinity) <= RATE_CAP_PPM + RATE_SLACK_PPM, maxRatePpm(series), `<= ${RATE_CAP_PPM} (+${RATE_SLACK_PPM}) over any 10 min`),
    check('kernel_freq_bounded', freqs.length > 0 && Math.max(...freqs.map(Math.abs)) <= RATE_CAP_PPM + 1, freqs.length ? Math.max(...freqs.map(Math.abs)) : null, `|freq_ppm| <= ${RATE_CAP_PPM} (maxdrift 50 + maxslewrate 60)`),
    check('offset_grows', seconds < 1200 ? null : growthPpm !== null && growthPpm >= 50, growthPpm === null ? null : Math.round(growthPpm * 10) / 10, '>= 50 ppm (200 injected, at most 110 corrected, less the oscillator error)'),
    check('no_cap_breach', !looks.some(l => l.state?.state === 'cap_exceeded'), [...new Set(looks.map(l => l.state?.state))], 'never cap_exceeded within the hour'),
    check('gate_closes_past_5s', crossed ? closed !== undefined : null, crossed ? closed?.code ?? null : `not reached; at this rate in about ${eta} s`, "clock.mjs code unc_high once |skew| > 5000"),
  ]
  return scenarioRecord(id, '+200 ppm fake drift', checks, {
    align: r.aligned, ready, growth_ppm: growthPpm, mean_rate_ppm: meanRatePpm(series), last_skew_ms: lastSkew,
    gate_close_eta_s: eta, freq_ppm_last: freqs[freqs.length - 1] ?? null, looks: thin(looks, 120),
  })
}

/** S7: kill the helper; kill chronyd and leave a stale pidfile naming a live process. */
async function scenarioS7() {
  const id = 'S7'
  const r = await reset(id)
  const t0 = monoS()
  startClock()
  const { syncedAt, looks } = await waitReady(t0, null)
  const ledgerBefore = readText(LEDGER_FILE)
  const bootBefore = readText(BOOT_FILE)
  const baseBefore = /^base (.+)$/m.exec(ledgerBefore ?? '')?.[1] ?? null

  // The helper.
  const tf = procs('nsm-timefeed')[0]
  if (tf) process.kill(tf.pid, 'SIGKILL')
  const tKillTf = monoS() - t0
  await observe(90, t0, l => l.feed.some(f => f.pid !== tf?.pid) && l.state?.state === 'ok' && l.t > tKillTf + 10, looks)
  const newTf = looks[looks.length - 1].feed.find(f => f.pid !== tf?.pid)
  const ledgerAfter = readText(LEDGER_FILE)
  const baseAfter = /^base (.+)$/m.exec(ledgerAfter ?? '')?.[1] ?? null
  const tfBackAt = looks.find(l => l.t > tKillTf && l.feed.some(f => f.pid !== tf?.pid))?.t ?? null
  const okAfterTf = looks.filter(l => l.t > tKillTf).find(l => l.state?.state === 'ok' && l.state?.good > 0)?.t ?? null

  // chronyd, and a pidfile naming a live process (this runner) before the loop starts it again.
  const cd = procs('chronyd')[0]
  if (cd) process.kill(cd.pid, 'SIGKILL')
  const tKillCd = monoS() - t0
  await sleep(1000)
  let pidfileWritten = false
  try { writeFileSync(PIDFILE, `${process.pid}\n`); pidfileWritten = true } catch { /* /run/chrony is gone */ }
  await observe(150, t0, l => l.chronyd.some(c => c.pid !== cd?.pid) && l.state?.state === 'ok' && l.state?.synced && l.t > tKillCd + 40, looks)
  const restarted = looks[looks.length - 1].chronyd.find(c => c.pid !== cd?.pid) ?? null
  const cdBackAt = looks.find(l => l.t > tKillCd && l.chronyd.some(c => c.pid !== cd?.pid))?.t ?? null
  await observe(60, t0, null, looks)
  const steps = findSteps(corrSeries(readLines(r.watch)))
  const lastState = looks[looks.length - 1].state
  const checks = [
    check('synced_first', syncedAt !== null, syncedAt, 'ok and synced'),
    check('helper_restarts', newTf !== undefined && tfBackAt - tKillTf <= 15, tfBackAt === null ? null : Math.round(tfBackAt - tKillTf), 'a new nsm-timefeed within 15 s (the loop sleeps 5)'),
    check('ledger_survives', baseBefore !== null && baseBefore !== '-' && baseAfter === baseBefore, { before: baseBefore, after: baseAfter }, 'the same ledger baseline'),
    check('boot_file_kept', bootBefore !== null && readText(BOOT_FILE) === bootBefore, bootBefore?.trim() ?? null, 'unchanged'),
    check('helper_ok_again', okAfterTf !== null, okAfterTf === null ? null : Math.round(okAfterTf - tKillTf), 'state ok again'),
    check('stale_pidfile_written', pidfileWritten, PIDFILE, 'written with a live pid'),
    check('chronyd_restarts_run_conf', restarted?.conf === 'run.conf' && cdBackAt - tKillCd <= 45, restarted ? { conf: restarted.conf, after_s: Math.round(cdBackAt - tKillCd) } : null, 'run.conf within 45 s (the loop sleeps 30)'),
    check('recovers', lastState?.state === 'ok' && lastState?.synced === true && Math.abs(lastState?.nsm_skew_ms ?? Infinity) < SKEW_OK_MS, lastState ? { state: lastState.state, synced: lastState.synced, nsm_skew_ms: lastState.nsm_skew_ms } : null, `ok, synced, |skew| < ${SKEW_OK_MS} ms`),
    check('no_second_step', steps.length <= 1, steps, 'only the boot step (if any)'),
  ]
  return scenarioRecord(id, 'kill the helper; kill chronyd with a stale pidfile', checks, { align: r.aligned, killed_feed: tf?.pid ?? null, killed_chronyd: cd?.pid ?? null, lifecycle: lifecycle(looks), looks: thin(looks) })
}

/** S9 in the main run: KMS refused, then held, with the clock good and no proof. */
async function scenarioS9InRun(controlOk) {
  const id = 'S9'
  if (controlOk) {
    const r = await reset(`${id}-inrun`)
    const t0 = monoS()
    startClock()
    const sampler = startSampler(r.dir, 'ready')
    const { ready } = await waitReady(t0, sampler)
    for (const how of ['refuse', 'hold']) {
      say(`S9: KMS ${how} for 120 s with the clock good`)
      const blocked = await control(`kms block ${how}`)
      const from = samplerNow()
      await observe(120, t0)
      const ticks = ticksAfter(sampler, from)
      const unblocked = await control('kms unblock')
      const from2 = samplerNow()
      await observe(30, t0)
      const resumed = ticksAfter(sampler, from2)
      s9.parts.push({
        part: `${how}_no_proof`, blocked, unblocked, ready,
        checks: [
          check('ready_before', ready?.ok === true, ready, 'clock.ready() passed'),
          check('parent_blocked', blocked?.ok === true, blocked, 'ok'),
          check('no_ranges', ticks.length > 0 && ticks.every(t => t.range === null), ticks.filter(t => t.range !== null).length, '0 ranges while blocked'),
          check('no_proof_set', ticks.every(t => t.proven === null), [...new Set(ticks.map(t => t.proven))], 'proven null'),
          check('gate_stays_open', ticks.every(t => t.code === 'ok'), [...new Set(ticks.map(t => t.code))], 'ok (missing KMS never closes the gate)'),
          check('ranges_resume', resumed.some(t => t.range !== null), resumed.filter(t => t.range !== null).length, '>= 1 after unblock'),
        ],
      })
    }
  } else {
    s9.parts.push({ part: 'refuse_no_proof', checks: [check('refuse_no_proof', null, 'no parent control server')] })
  }
  const checks = s9.parts.flatMap(p => p.checks.map(c => ({ ...c, name: `${p.part}.${c.name}` })))
  return scenarioRecord(id, 'KMS blocked (vsock 8000) while running', checks, { parts: s9.parts.map(({ checks: _, ...rest }) => rest) })
}

// ---------------------------------------------------------------- the parent's runs

/** How the NSM's time compares with the parent's, taken now. */
async function compareWithParent() {
  const a = monoNs()
  const parent = await control('time')
  const b = monoNs()
  const s = await p0(['sample'])
  if (!parent?.ok || !s.ok) return { parent, sample: s }
  // The parent's clocks at the NSM sample's moment, assuming the control answer came at the middle of its exchange.
  const atNs = s.sample.mid_mono_ns - (a + (b - a) / 2)
  const nsmMs = s.sample.ts_ms + 0.5
  return {
    exchange_ms: Math.round((b - a) / 1e6),
    nsm_minus_parent_real_ms: Math.round(nsmMs - (parent.parent_real_ns + atNs) / 1e6),
    nsm_minus_parent_true_ms: Math.round(nsmMs - (parent.parent_true_ns + atNs) / 1e6),
    parent_shift_ms: Math.round(parent.shift_ns / 1e6),
    system_minus_nsm_ms: Math.round(-s.sample.offset_ns / 1e6),
  }
}

/** S8: the parent's clock +120 s (its chronyd stopped) at the enclave's launch and while it runs. */
async function scenarioS8(hello) {
  const id = 'S8'
  const boot = readJson(`${OUT}/boot-sample.json`)
  const bootOffsetMs = boot?.ok ? Math.round(-boot.sample.offset_ns / 1e6) : null
  const atLaunch = await compareWithParent()
  const r = await reset(id)
  const t0 = monoS()
  startClock()
  const sampler = startSampler(r.dir, 'ready')
  const { ready, syncedAt, looks } = await waitReady(t0, sampler)
  const phases = []
  for (const request of ['parent restore', 'parent shift 120', 'parent restore']) {
    const answer = await control(request)
    const from = looks.length
    const fromMono = monoNs()
    await observe(120, t0, null, looks)
    const part = looks.slice(from)
    phases.push({
      request, answer,
      steps: findSteps(corrSeries(readLines(r.watch)).filter(p => p.mono_ns > fromMono)),
      states: [...new Set(part.map(l => l.state?.state))],
      bad_added: (part[part.length - 1]?.state?.bad ?? 0) - (part[0]?.state?.bad ?? 0),
      max_abs_skew_ms: percentileAbs(skews(part), 1),
      compare: await compareWithParent(),
    })
  }
  const shiftedAtLaunch = Math.abs((atLaunch.parent_shift_ms ?? 0) - 120_000) < 2000
  const checks = [
    check('parent_shifted_at_launch', shiftedAtLaunch, atLaunch.parent_shift_ms ?? null, '120000 ± 2000 (control.py --shift-at-start 120)'),
    check('boot_time_unaffected', bootOffsetMs !== null && Math.abs(bootOffsetMs) < 60_000, bootOffsetMs, '|system - NSM| at the entrypoint < 60000 (not the parent\'s +120 s)'),
    check('nsm_follows_true_time', Math.abs(atLaunch.nsm_minus_parent_true_ms ?? Infinity) < 2000, atLaunch.nsm_minus_parent_true_ms ?? null, '|NSM - parent true time| < 2000'),
    check('nsm_ignores_parent_clock', Math.abs((atLaunch.nsm_minus_parent_real_ms ?? Infinity) + 120_000) < 2000, atLaunch.nsm_minus_parent_real_ms ?? null, 'NSM - parent clock = -120000 ± 2000'),
    check('ready_while_parent_off', ready?.ok === true && syncedAt !== null, ready, 'clock.ready() passes with the parent +120 s'),
    ...phases.map((p, i) => check(`run_phase_${i + 1}_${p.request.replace(/ /g, '_')}`,
      p.answer?.ok === true && p.steps.length === 0 && p.states.every(s => s === 'ok') && p.bad_added <= 2 && (p.max_abs_skew_ms ?? Infinity) < SKEW_OK_MS
        && Math.abs(p.compare.nsm_minus_parent_true_ms ?? Infinity) < 2000,
      { steps: p.steps.length, states: p.states, bad_added: p.bad_added, max_abs_skew_ms: p.max_abs_skew_ms, nsm_minus_parent_true_ms: p.compare.nsm_minus_parent_true_ms },
      'no step, helper ok, <= 2 bad cycles, |skew| < 50 ms, NSM = parent true time')),
  ]
  return scenarioRecord(id, 'the parent\'s clock +120 s, at launch and while running', checks, { hello, boot_sample: boot, at_launch: atLaunch, phases, looks: thin(looks) })
}

/** S9, from boot: KMS blocked before the enclave started. */
async function scenarioS9Boot(hello) {
  const id = 'S9-boot'
  const r = await reset(id)
  const t0 = monoS()
  startClock()
  const sampler = startSampler(r.dir, 'ready')
  const exited = await Promise.race([sampler.exit, sleep(260_000).then(() => null)])
  const looks = await observe(4, t0)
  const lines = sampler.lines()
  const readyLine = lines.find(x => x.kind === 'ready')
  const ticks = lines.filter(x => x.kind === 'tick')
  const last = looks[looks.length - 1].state
  const checks = [
    check('parent_blocked_from_boot', hello?.kms_blocked === true, hello?.kms_blocked ?? null, 'control.py --block-at-start'),
    check('ready_times_out', readyLine?.ok === false && readyLine?.code === 'clock_unknown', readyLine ?? null, 'clock_unknown'),
    check('waited_full_timeout', (readyLine?.ms ?? 0) >= 175_000, readyLine?.ms ?? null, '>= 175000 ms (READY_TIMEOUT_MS 180000)'),
    check('exits_78', exited?.code === 78, exited, 'exit 78, as main.mjs boot_failed'),
    check('no_proof_no_range', ticks.every(t => t.proven === null && t.range === null), ticks.length, 'no range, no proof'),
    check('helper_fine', last?.state === 'ok' && last?.synced === true, last ? { state: last.state, synced: last.synced } : null, 'the NSM side is fine: ok and synced'),
  ]
  return scenarioRecord(id, 'KMS blocked (vsock 8000) from boot', checks, { hello, ready: readyLine ?? null, exit: exited, looks: thin(looks) })
}

// ---------------------------------------------------------------- main

async function main() {
  emit('meta', {
    node: process.version, release: readText('/proc/sys/kernel/osrelease')?.trim() ?? null, dev_nsm: hasNsm,
    nsm_timefeed_release_marker: (readText('/usr/local/bin/nsm-timefeed') ?? '').includes('WAPPIE_FAKE_DRIFT'),
    nsm_timefeed_fake_marker: (readText(`${FAKE_DIR}/nsm-timefeed`) ?? '').includes('WAPPIE_FAKE_DRIFT'),
  })
  const hello = await control('hello', 15_000)
  const controlOk = hello?.ok === true
  const runName = hello?.run ?? process.env.CLOCKPROBE_RUN ?? 'main'
  const only = String(hello?.scenarios ?? process.env.CLOCKPROBE_SCENARIOS ?? '').split(',').map(s => s.trim()).filter(Boolean)
  const want = id => !only.length || only.includes(id)
  const s5s = Number(hello?.s5_s ?? process.env.CLOCKPROBE_S5_S ?? 1800), s6s = Number(hello?.s6_s ?? process.env.CLOCKPROBE_S6_S ?? 3600)
  emit('run', { run: runName, control: controlOk, hello, only, s5_s: s5s, s6_s: s6s })
  say(`run ${runName} (control ${controlOk ? 'up' : 'absent'})`)

  if (runName === 'main') {
    if (want('P0')) await scenarioP0()
    else bootTimex = (await p0(['kernel'])).adjtimex_read ?? null
    const steps = [
      ['S1', () => scenarioBootStep('S1', 90)],
      ['S2', () => scenarioBootStep('S2', -90)],
      ['S3', scenarioS3],
      ['S4', () => scenarioS4(controlOk)],
      ['S9', () => scenarioS9InRun(controlOk)],
      ['S7', scenarioS7],
      ['S5', () => scenarioS5(s5s)],
      ['S6', () => scenarioS6(s6s)],
    ]
    for (const [id, fn] of steps) {
      if (!want(id)) continue
      if (!hasNsm) { notRun(id, id, 'no /dev/nsm'); continue }
      say(`${id}: start`)
      try { await fn() } catch (e) { scenarioRecord(id, id, [check('ran', false, String(e?.stack ?? e))], {}) }
    }
  } else if (runName === 's8' || runName === 's9boot') {
    if (!hasNsm) notRun(runName === 's8' ? 'S8' : 'S9-boot', runName, 'no /dev/nsm')
    else {
      bootTimex = (await p0(['kernel'])).adjtimex_read ?? null
      try { await (runName === 's8' ? scenarioS8(hello) : scenarioS9Boot(hello)) } catch (e) { scenarioRecord(runName, runName, [check('ran', false, String(e?.stack ?? e))], {}) }
    }
  }

  // The enclave's oscillator against NSM time over the whole run (nsm-p0
  // watch's NSM samples, every 30 s): the true drift, in ppm.
  const drift = []
  for (const dir of readdirSync(OUT, { withFileTypes: true })) {
    if (dir.isDirectory()) drift.push({ scenario: dir.name, ...nsmDrift(readLines(`${OUT}/${dir.name}/watch.jsonl`)) })
  }
  killGroups()
  if (hasNsm) await p0(['align'])
  emit('drift', { per_scenario: drift, note: 'ppm > 0: NSM time runs faster than MONOTONIC_RAW (the oscillator loses). S6 uses the real NSM here, not the fake feed.' })
  await control('done', 10_000)
  emit('done', { run: runName })
}

await main()
process.exit(0)
