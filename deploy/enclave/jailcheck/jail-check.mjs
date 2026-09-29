// The jail checks of check-image.sh --jail (docs/mcp-enclave.md §16.13 JAIL
// and CORPUS), as root in a privileged container that run.sh prepared with
// the entrypoint's own cgroup block. Every job goes through the image's
// media-jail exactly as the reader spawns it (§16.11: the table's limits, an
// empty environment); media-jail's own stderr, which the reader ignores, is
// read here for the memory and time figures only. One line per check; any
// failure exits 1.
//
//   1. the kernel setup the entrypoint made, --self-check, --table = WORKERS;
//   2. bad invocations exit 3 and leave no cgroup behind;
//   3. the A0 probe's escape tests, run from a stand-in /opt/media (driver.mjs
//      execs jailtest as the worker), and the A1 ones: SIGTERM ends a job with
//      143, a reader that dies takes its job with it;
//   4. every corpus file (test/corpus.mjs) through its real worker, run by
//      the reader's own runWorker (enclave/media/jail.mjs, §16.11's checks and
//      its watchdog): a bounded outcome its case allows, and never a seccomp
//      kill.

import { spawn, execFileSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { isDeepStrictEqual } from 'node:util'
import { setTimeout as sleep } from 'node:timers/promises'
import { runWorker } from '/app/packages/mcp-http/enclave/media/jail.mjs'
import { stdinOf } from '/opt/media/worker/test/harness.mjs'
import { corpus, outcome } from '/opt/media/worker/test/corpus.mjs'

const MJ = '/usr/local/bin/media-jail'
const MEDIA = '/run/cg2/media'
const POLICY = '/app/packages/mcp-http/enclave/media/policy.mjs'
const ENOENT = 2
const ENOSYS = 38

const results = []
function record(name, pass, detail = {}) {
  results.push({ name, pass })
  console.log(`${pass ? 'PASS' : 'FAIL'} ${name} ${JSON.stringify(detail)}`)
}

// The reader spawns media-jail with an empty environment. The check-4.14
// target passes MEDIA_JAIL_EMULATE on, which only its test build reads.
const ENV = process.env.MEDIA_JAIL_EMULATE ? { MEDIA_JAIL_EMULATE: process.env.MEDIA_JAIL_EMULATE } : {}

const hex = () => randomBytes(8).toString('hex')
const leaves = () => readdirSync(MEDIA).filter((n) => n.startsWith('light-'))

function run(args, { input = '', timeoutMs = 10_000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(MJ, args, { env: ENV, stdio: ['pipe', 'pipe', 'pipe'] })
    const out = []
    const err = []
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs)
    child.stdout.on('data', (c) => out.push(c))
    child.stderr.on('data', (c) => err.push(c))
    child.stdin.on('error', () => {})
    child.stdin.end(input)
    child.on('close', (code, signal) => {
      clearTimeout(timer)
      resolve({ code, signal, stdout: Buffer.concat(out), stderr: Buffer.concat(err).toString() })
    })
  })
}

let TABLE

/**
 * One job of `worker` under media-jail, with the row's limits unless a check
 * lowers one. `after(child, id)` runs once it is spawned (to signal it). The
 * status line is media-jail's own report on stderr.
 */
function job(worker, input, { limits = {}, id = hex(), after } = {}) {
  const l = { ...TABLE[worker].max, ...limits }
  const args = ['--worker', worker, '--slot', 'light', '--id', id, '--mem-mb', `${l.mem_mb}`, '--pids', `${l.pids}`, '--cpus', '0', '--wall-s', `${l.wall_s}`, '--tmp-mb', `${l.tmp_mb}`]
  return new Promise((resolve) => {
    const started = Date.now()
    const child = spawn(MJ, args, { env: ENV, stdio: ['pipe', 'pipe', 'pipe'] })
    const out = []
    const err = []
    let hung = false
    // The reader's own watchdog: wall plus JAIL_WATCHDOG_MS.
    const watchdog = setTimeout(() => {
      hung = true
      child.kill('SIGKILL')
    }, (l.wall_s + 5) * 1_000)
    child.stdout.on('data', (c) => out.push(c))
    child.stderr.on('data', (c) => err.push(c))
    child.stdin.on('error', () => {})
    child.stdin.end(input)
    after?.(child, id)
    child.on('close', (code, signal) => {
      clearTimeout(watchdog)
      const stderr = Buffer.concat(err).toString()
      const status = stderr
        .split('\n')
        .map((line) => {
          try {
            return JSON.parse(line)
          } catch {
            return null
          }
        })
        .find((v) => v?.tool === 'media-jail')
      resolve({ code, signal, hung, id, stdout: Buffer.concat(out), stderr, status, ms: Date.now() - started })
    })
  })
}

// ---- 1. setup, self-check, table ----------------------------------------------

async function setup() {
  const subtree = readFileSync(`${MEDIA}/cgroup.subtree_control`, 'utf8').trim().split(/\s+/)
  record('cgroup2 media controllers', subtree.includes('memory') && subtree.includes('pids'), { subtree })
  const hidepid = readFileSync('/proc/self/mountinfo', 'utf8').split('\n').find((l) => / \/proc /.test(l) && /hidepid=(2|invisible)/.test(l))
  record('/proc hidepid=2', Boolean(hidepid))
  const oom = readFileSync('/proc/self/oom_score_adj', 'utf8').trim()
  record('node oom_score_adj -1000', oom === '-1000', { oom })

  const self = await run(['--self-check'])
  let report = null
  try {
    report = JSON.parse(self.stdout.toString())
  } catch {}
  record('media-jail --self-check', self.code === 0 && report?.seccomp?.compiles === true, {
    kernel: report?.kernel,
    emulated: report?.emulated,
    kill_action: report?.seccomp?.kill_action,
    media_files: report?.cgroup2?.media_files,
  })

  const table = await run(['--table'])
  TABLE = JSON.parse(table.stdout.toString()).workers
  const { WORKERS } = await import(POLICY)
  const max = Object.fromEntries(Object.entries(TABLE).map(([id, w]) => [id, w.max]))
  record('--table equals WORKERS (policy.mjs)', table.code === 0 && isDeepStrictEqual(max, JSON.parse(JSON.stringify(WORKERS))), { max })
}

// ---- 2. refusals ----------------------------------------------------------------

async function refusals() {
  const before = leaves().length
  const base = (worker, over = {}) => {
    const l = { ...TABLE[worker]?.max, ...over }
    return ['--worker', worker, '--slot', 'light', '--id', hex(), '--mem-mb', `${l.mem_mb ?? 64}`, '--pids', `${l.pids ?? 8}`, '--cpus', '0', '--wall-s', `${l.wall_s ?? 1}`, '--tmp-mb', `${l.tmp_mb ?? 1}`]
  }
  const bad = { 'unknown worker': base('ffmpeg'), 'heavy slot': base('image').map((a) => (a === 'light' ? 'heavy' : a)) }
  for (const [id, row] of Object.entries(TABLE)) {
    for (const k of ['mem_mb', 'wall_s', 'pids', 'tmp_mb']) bad[`${id} ${k} over its ceiling`] = base(id, { [k]: row.max[k] + 1 })
  }
  bad['a program after --'] = [...base('image'), '--', '/bin/sh']
  for (const [name, args] of Object.entries(bad)) {
    const r = await run(args)
    record(`refused: ${name}`, r.code === 3 && r.stdout.length === 0, { exit: r.code })
  }
  record('refusals leave no cgroup leaf', leaves().length === before)
}

// ---- 3. escape tests ----------------------------------------------------------------

function classify(r, name) {
  const stdout = r.stdout.toString()
  const line = (stdout.match(/^RESULT .*/m) || [])[0] || null
  const errno = line ? Number((line.match(/\berrno=(-?\d+)/) || [])[1]) : null
  const started = new RegExp(`^START ${name}$`, 'm').test(stdout)
  let verdict
  if (r.hung) verdict = 'hung'
  else if (line && /\bCLEARED\b/.test(line)) verdict = 'cleared'
  else if (line && /\bHELD\b/.test(line)) verdict = 'held'
  else if (line && /\bCOUNT\b/.test(line)) verdict = 'listed'
  else if (line && /\b(DENIED|NOT-VISIBLE)\b/.test(line)) verdict = 'denied-errno'
  else if (line && /\b(OPENED|SURVIVED|VISIBLE)\b/.test(line)) verdict = 'survived'
  else if (!started) verdict = `not-started(exit ${r.code})`
  else if (r.code === 159) verdict = 'denied-seccomp'
  else if (r.code === 137) verdict = 'killed-memcg'
  else if (r.code === 124) verdict = 'killed-wall'
  else verdict = `other(exit ${r.code})`
  return { verdict, errno, stdout, jail: r.status && { root_switch: r.status.root_switch, caps: r.status.caps, cpu_pin: r.status.cpu_pin, kill_method: r.status.kill_method } }
}

const FORBIDDEN_MOUNTS = /^\/(sys|run|etc|oldroot|dev\/nsm)(\/|$)/

async function escapes() {
  execFileSync('mount', ['--bind', '/opt/jailcheck/media', '/opt/media'])
  try {
    const one = async (name, args, expect, { errno = null, limits = {} } = {}) => {
      const r = await job('image', JSON.stringify(args), { limits: { wall_s: 3, mem_mb: 128, ...limits } })
      const c = classify(r, args[0])
      const pass = expect.includes(c.verdict) && (errno === null || c.verdict !== 'denied-errno' || c.errno === errno)
      record(`escape: ${name}`, pass, { verdict: c.verdict, errno: c.errno, jail: c.jail })
      return c
    }
    await one('nsm', ['nsm'], ['denied-errno'], { errno: ENOENT })
    await one('socket-vsock', ['socket-vsock'], ['denied-seccomp'])
    await one('socket-inet', ['socket-inet'], ['denied-seccomp'])
    await one('socket-unix', ['socket-unix'], ['survived'])
    await one('connect-unix', ['connect-unix'], ['denied-seccomp'])
    await one('io-uring', ['io-uring'], ['denied-errno'], { errno: ENOSYS })
    await one('userfaultfd', ['userfaultfd'], ['denied-seccomp'])
    await one('unshare-userns', ['unshare-userns'], ['denied-seccomp'])
    await one('clone-newns', ['clone-newns'], ['denied-seccomp'])
    await one('clone3', ['clone3'], ['denied-errno'], { errno: ENOSYS })
    await one('chroot', ['chroot'], ['denied-seccomp'])
    await one('paths', ['paths'], ['denied-errno'], { errno: ENOENT })
    await one('privs', ['privs'], ['cleared'])
    const mounts = await one('mountinfo', ['mountinfo'], ['listed'])
    const points = mounts.stdout.split('\n').filter((l) => l.startsWith('MOUNT ')).map((l) => l.split(' ')[5])
    record('escape: jail mount table', points.length > 0 && !points.some((p) => FORBIDDEN_MOUNTS.test(p)), { points })
    await one('memhog', ['memhog', '512'], ['killed-memcg'], { limits: { mem_mb: 64, wall_s: 10 } })
    // V8's heap limit ends a worker by abort(). The worker is its PID
    // namespace's init, which ignores its own SIGABRT, so musl's abort()
    // crashes instead: SIGSEGV, 139 (134 outside the jail), and never 159,
    // which would mean the profile lacks tkill.
    const heap = await job('image', JSON.stringify(['v8-heap']), { limits: { wall_s: 10 } })
    record('escape: v8 heap limit is a crash, not a seccomp kill (139)', heap.code === 139, { exit: heap.code, ms: heap.ms })
    await one('wall-timeout', ['spin'], ['killed-wall'], { limits: { wall_s: 2 } })

    // A concurrent job cannot see the other's /proc, and SIGTERM to
    // media-jail (how the reader stops a job) ends it with 143.
    const victimId = hex()
    let victimJail
    const victim = job('image', JSON.stringify(['spin']), { id: victimId, limits: { wall_s: 10 }, after: (child) => (victimJail = child) })
    await sleep(1_000)
    const victimPid = (readFileSync(`${MEDIA}/light-${victimId}/cgroup.procs`, 'utf8').trim().split('\n')[0] || '').trim()
    const peek = await job('image', JSON.stringify(['proc-peek', victimPid || '1']), { limits: { wall_s: 3 } })
    const p = classify(peek, 'proc-peek')
    const alive = existsSync(`/proc/${victimPid}/stat`)
    record('escape: proc-peek of a concurrent job', Boolean(victimPid) && alive && p.verdict === 'denied-errno' && p.errno === ENOENT, { verdict: p.verdict, errno: p.errno, victimPid, alive })
    const t0 = Date.now()
    victimJail.kill('SIGTERM')
    const v = await victim
    record('SIGTERM to media-jail ends the job, exit 143', v.code === 143 && !existsSync(`/proc/${victimPid}/stat`) && !existsSync(`${MEDIA}/light-${victimId}`) && Date.now() - t0 < 4_000, {
      exit: v.code,
      ms: Date.now() - t0,
      kill_method: v.status?.kill_method,
    })

    // The reader dies: media-jail gets SIGTERM (PR_SET_PDEATHSIG) and ends the
    // job; its child would get SIGKILL if media-jail itself died.
    const orphanId = hex()
    const reader = spawn(process.execPath, ['-e', `
      const { spawn } = require('node:child_process')
      const c = spawn(${JSON.stringify(MJ)}, ${JSON.stringify(['--worker', 'image', '--slot', 'light', '--id', orphanId, '--mem-mb', '64', '--pids', '64', '--cpus', '0', '--wall-s', '10', '--tmp-mb', '16'])}, { env: ${JSON.stringify(ENV)}, stdio: ['pipe', 'ignore', 'ignore'] })
      c.stdin.end(${JSON.stringify(JSON.stringify(['spin']))})
      setInterval(() => {}, 1000)`], { stdio: 'ignore' })
    let orphanPid = ''
    for (let i = 0; i < 50 && !orphanPid; i++) {
      await sleep(100)
      try {
        orphanPid = readFileSync(`${MEDIA}/light-${orphanId}/cgroup.procs`, 'utf8').trim().split('\n')[0]
      } catch {}
    }
    reader.kill('SIGKILL')
    const t1 = Date.now()
    while (Date.now() - t1 < 5_000 && (existsSync(`${MEDIA}/light-${orphanId}`) || (orphanPid && existsSync(`/proc/${orphanPid}/stat`)))) await sleep(100)
    record('a reader that dies takes its job with it', Boolean(orphanPid) && !existsSync(`${MEDIA}/light-${orphanId}`) && !existsSync(`/proc/${orphanPid}/stat`), { orphanPid, ms: Date.now() - t1 })
  } finally {
    execFileSync('umount', ['/opt/media'])
  }
  record('escape tests left no cgroup leaf', leaves().length === 0, { leaves: leaves() })
}

// ---- 4. the corpus ----------------------------------------------------------------

/**
 * One corpus job as the reader runs it: runWorker spawns media-jail with the
 * table's limits and an empty environment, and reads the frames. The spawn
 * here also keeps media-jail's status line, which the reader ignores, for the
 * memory figures. Returns the output in the shape the corpus checks read.
 */
async function readerJob(c) {
  let stderr = ''
  const spawnJail = (bin, args, options) => {
    const child = spawn(bin, args, { ...options, env: { ...options.env, ...ENV }, stdio: ['pipe', 'pipe', 'pipe'] })
    child.stderr.on('data', (chunk) => (stderr += chunk))
    return child
  }
  const started = Date.now()
  const o = await runWorker({ worker: c.worker, job: c.header, input: c.input, spawn: spawnJail })
  const status = stderr
    .split('\n')
    .map((line) => {
      try {
        return JSON.parse(line)
      } catch {
        return null
      }
    })
    .find((v) => v?.tool === 'media-jail')
  // A job the reader itself ended (bad output, its watchdog) is invalid:<why>,
  // whatever media-jail exited with after its SIGTERM.
  return {
    valid: o.killed === null && (o.exit === 0 || o.exit === 2),
    why: o.killed ?? `exit ${o.exit}`,
    code: o.killed ? null : o.exit,
    header: o.header,
    error: o.error,
    cut: o.cut,
    sections: o.sections.map((s) => ({ value: s.section, text: s.text })),
    text: o.sections.map((s) => s.text).join(''),
    images: o.images.map((i) => ({ page: i.page, width: i.width, height: i.height, type: i.mimeType === 'image/png' ? 'png' : 'jpeg', file: i.data })),
    status,
    stderr,
    ms: Date.now() - started,
  }
}

async function corpusRun() {
  const cases = await corpus()
  for (const c of cases) {
    const r = await readerJob(c)
    const got = outcome(r)
    let pass = c.expect.includes(got)
    if (pass && got.startsWith('done') && c.check) pass = Boolean(c.check(r))
    record(`corpus ${c.worker}: ${c.name}`, pass, {
      outcome: got,
      expect: c.expect,
      ms: r.ms,
      peak_mb: r.status?.memory_peak_bytes ? Math.round(r.status.memory_peak_bytes / 1_048_576) : null,
      current_max_mb: r.status?.memory_current_max_bytes ? Math.round(r.status.memory_current_max_bytes / 1_048_576) : null,
      ...(pass ? {} : { why: r.why, stderr: r.stderr.slice(-400) }),
    })
    if (got === 'seccomp') record(`no seccomp kill: ${c.name}`, false)
  }

  // SIGTERM in the middle of a real worker's job (the sticker ladder of a
  // noise image takes seconds).
  const slow = cases.find((c) => c.name === 'sticker-noise-ladder')
  const r = await job(slow.worker, stdinOf(slow.header, slow.input), { after: (child) => setTimeout(() => child.kill('SIGTERM'), 500) })
  record('SIGTERM during a worker job: 143, leaf gone', r.code === 143 && !existsSync(`${MEDIA}/light-${r.id}`), { exit: r.code, ms: r.ms })
  record('corpus left no cgroup leaf', leaves().length === 0, { leaves: leaves() })
}

try {
  await setup()
  await refusals()
  await escapes()
  await corpusRun()
} catch (e) {
  record('jail check crashed', false, { error: String(e?.stack ?? e) })
}
const failed = results.filter((r) => !r.pass)
console.log(`jail check: ${results.length - failed.length} passed, ${failed.length} failed${failed.length ? `: ${failed.map((f) => f.name).join('; ')}` : ''}`)
process.exit(failed.length ? 1 : 0)
