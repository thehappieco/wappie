// The A0 probe runner. It runs INSIDE the probe enclave at boot, as a child of
// entrypoint-probe.sh, and STREAMS its report to the enclave console: every
// section is printed the moment it is measured, as one line
//
//   A0R <seq> <bytes> {"section":"<name>","t":<uptime s>,"data":{...}}
//
// where <bytes> is the UTF-8 length of the JSON, so probe.sh
// (assemble-report.py) can tell a whole line from one a kernel message broke
// in two. The same lines are appended to /run/probe/report.jsonl, which the
// entrypoint prints again at the end. A crash mid-way therefore still leaves
// every finished section on the console; the first Nitro run (2026-09-28)
// printed its one JSON object only at the very end and left nothing.
//
// It answers the §4 JAIL go/no-go and §16 open points with raw evidence: kernel
// config and features, the cgroup layout and whether the v1→v2 switch worked,
// /dev/nsm, media-jail --self-check, a jailed test per escape, the memory
// headroom for the A1 sharp + pdfjs stack on a generated 12 MP JPEG and 50-page
// PDF, vsock throughput, the kernel's own reports about our processes (SIGILL,
// seccomp kills, OOM) matched to what the runner started, and what the 4.14
// blob kernel lacks for §16.6.
//
// Every process it starts is announced first (argv), then recorded with its
// pid, /proc/<pid>/comm and cmdline, and its exit code or signal, so a kernel
// line naming a pid can be traced to a command.
import { spawn } from 'node:child_process'
import {
  appendFileSync,
  closeSync,
  constants,
  existsSync,
  openSync,
  readFileSync,
  readSync,
  writeFileSync,
  writeSync,
} from 'node:fs'
import { release } from 'node:os'
import { gunzipSync } from 'node:zlib'

const MEDIA_JAIL = '/usr/local/bin/media-jail'
const NODE = process.execPath
const BIN = '/opt/probe/bin'
const WORKER = '/opt/probe/worker'
const CORPUS = '/opt/probe/corpus'
const VSOCK_PORT = 9100 // outside production's 5443-5445/7000-7002/8000-8002/9000
const PROBE = '/run/probe'
const REPORT = `${PROBE}/report.jsonl`
const CG_MEDIA = '/run/cg2/media'

const ENOENT = 2
const ENOSYS = 38

// PROBE_EMULATE_OLD_KERNEL=1 (local smoke test only): behave as on the 4.14
// blob on a newer kernel. The entrypoint leaves cpuset off cgroup2 and hidepid
// at 2; media-jail is told to treat the rest as missing; the runner's own kill
// path ignores cgroup.kill.
const EMULATE = process.env.PROBE_EMULATE_OLD_KERNEL === '1'
const JAIL_ENV = EMULATE
  ? { ...process.env, MEDIA_JAIL_EMULATE: 'no-cgroup-kill,no-oom-group,no-peak,no-pivot-root,kill-thread' }
  : process.env

// The page offset of OpenSSL's _armv8_sve_probe (`eor z0.d, z0.d, z0.d`) in
// the pinned node:22-alpine binary (Node 22.23.3, OpenSSL 3.5.8; nm: 0x213ee48).
// A pre-SVE kernel (4.14) traps it as "Bad EL0 synchronous exception ... code
// 0x66000000" (ESR class 0x19, SVE access) and sends SIGILL, which OpenSSL's
// arm_probe_for catches (sigsetjmp) to learn there is no SVE.
const SVE_PROBE_PAGE_OFFSET = 0xe48
const SVE_PROBE_OFFSET = 0x213ee48

const readText = (p) => {
  try {
    return readFileSync(p, 'utf8')
  } catch {
    return null
  }
}

const errText = (e) => String(e && e.stack ? e.stack : e)

const uptime = () => {
  const u = readText('/proc/uptime')
  return u ? Number(u.split(' ')[0]) : null
}

// --- the stream -------------------------------------------------------------

// Synchronous writes straight to fd 1, so a line is on the console before the
// next step runs, whatever happens after it.
function out(text) {
  const buf = Buffer.from(text)
  let off = 0
  let spins = 0
  while (off < buf.length) {
    try {
      off += writeSync(1, buf, off)
    } catch (e) {
      if (e.code !== 'EAGAIN' || ++spins > 100000) return
    }
  }
}

let seq = 0
let fatal = 0

function emit(section, data) {
  let json
  try {
    json = JSON.stringify({ section, t: uptime(), data })
  } catch (e) {
    json = JSON.stringify({ section, t: uptime(), data: { error: `unserializable: ${errText(e)}` } })
  }
  const line = `A0R ${++seq} ${Buffer.byteLength(json)} ${json}\n`
  out(line)
  try {
    appendFileSync(REPORT, line)
  } catch {
    /* the console copy is the one that counts */
  }
}

function progress(msg) {
  out(`A0 RUN t=${uptime()} ${msg}\n`)
}

process.on('uncaughtException', (e) => {
  fatal++
  emit('fatal', { kind: 'uncaughtException', error: errText(e) })
})
process.on('unhandledRejection', (e) => {
  fatal++
  emit('fatal', { kind: 'unhandledRejection', error: errText(e) })
})

// Measure one section and print it at once; a throw becomes that section's
// error and the run goes on.
async function section(name, fn) {
  progress(`section ${name}`)
  let data
  try {
    data = await fn()
  } catch (e) {
    data = { error: errText(e) }
  }
  emit(name, data)
  return data
}

// --- processes ----------------------------------------------------------------

const spawned = []
// Every jailed job's PID 1 as the host sees it (media-jail's child_pid), for
// matching kernel lines to jobs.
const jobs = []

const procComm = (pid) => (readText(`/proc/${pid}/comm`) || '').trim() || null
const procCmdline = (pid) => {
  const t = readText(`/proc/${pid}/cmdline`)
  return t == null ? null : t.split('\0').filter(Boolean)
}

// Start a process: its argv is printed BEFORE it starts, then its pid, comm and
// cmdline as the kernel sees them (spawn returns after the exec), and its end.
function start(argv, { env = process.env, stdio = ['ignore', 'pipe', 'pipe'] } = {}) {
  progress(`spawn ${JSON.stringify(argv)}`)
  const child = spawn(argv[0], argv.slice(1), { env, stdio })
  const pid = child.pid ?? null
  const rec = { pid, argv, comm: pid ? procComm(pid) : null, cmdline: pid ? procCmdline(pid) : null }
  spawned.push(rec)
  emit('spawn', rec)
  child.once('exit', (code, signal) => {
    rec.code = code
    rec.signal = signal
    emit('exit', { pid, argv0: argv[0], code, signal })
  })
  return child
}

// Run a process to completion, collecting its output, with a hard timeout.
function run(argv, { timeoutMs = 60000, env } = {}) {
  return new Promise((resolve) => {
    let child
    try {
      child = start(argv, { env })
    } catch (e) {
      resolve({ pid: null, code: null, signal: null, stdout: '', stderr: '', error: errText(e) })
      return
    }
    let stdout = ''
    let stderr = ''
    let done = false
    let timedOut = false
    child.stdout.on('data', (d) => (stdout += d))
    child.stderr.on('data', (d) => (stderr += d))
    const timer = setTimeout(() => {
      timedOut = true
      try {
        child.kill('SIGKILL')
      } catch {
        /* already gone */
      }
    }, timeoutMs)
    const finish = (extra) => {
      if (done) return
      done = true
      clearTimeout(timer)
      resolve({ pid: child.pid ?? null, stdout, stderr, timed_out: timedOut, ...extra })
    }
    child.on('error', (e) => finish({ code: null, signal: null, error: errText(e) }))
    child.on('close', (code, signal) => finish({ code, signal }))
  })
}

function meminfo(text) {
  if (!text) return null
  const out = {}
  for (const key of ['MemTotal', 'MemAvailable', 'MemFree']) {
    const m = text.match(new RegExp(`^${key}:\\s+(\\d+)`, 'm'))
    if (m) out[key + '_kb'] = Number(m[1])
  }
  return out
}

// media-jail's one-line status JSON, or null for any other stderr line. The
// jailed worker's stderr is /dev/null, so only media-jail writes these lines.
function statusLine(line) {
  try {
    const v = JSON.parse(line)
    return v && v.tool === 'media-jail' ? v : null
  } catch {
    return null
  }
}

// Parse media-jail's status line off the tail of its stderr.
function mjStatus(stderr) {
  const lines = (stderr || '').trim().split('\n').filter(Boolean)
  for (let i = lines.length - 1; i >= 0; i--) {
    const v = statusLine(lines[i])
    if (v) return v
  }
  return null
}

// media-jail's own diagnostics without the status line: a setup error in the
// parent or the child (a root switch, a cgroup file write, the /proc mount) is
// the first thing to read when a test fails on the real kernel. The last 2 KiB.
function stderrTail(stderr) {
  const text = (stderr || '')
    .split('\n')
    .filter((l) => l.trim() && !statusLine(l))
    .join('\n')
  return text.length > 2048 ? text.slice(-2048) : text
}

// The PID-namespace init among a leaf's processes: its NSpid ends in 1.
function nsInit(pids) {
  for (const p of pids) {
    const m = (readText(`/proc/${p}/status`) || '').match(/^NSpid:\s+(.*)$/m)
    const ids = m ? m[1].trim().split(/\s+/) : []
    if (ids.length > 1 && ids[ids.length - 1] === '1') return Number(p)
  }
  return null
}

// The main Node's kill path (§16.6): cgroup.kill where the kernel has it
// (5.14); otherwise SIGKILL the job's PID-namespace init, which takes every
// process in that namespace with it. Returns what it did.
function killJob(leaf) {
  if (!EMULATE && existsSync(`${leaf}/cgroup.kill`)) {
    writeFileSync(`${leaf}/cgroup.kill`, '1')
    return 'cgroup.kill'
  }
  const pids = (readText(`${leaf}/cgroup.procs`) || '').split('\n').filter(Boolean)
  const init = nsInit(pids)
  if (init) {
    process.kill(init, 'SIGKILL')
    return 'pidns-init'
  }
  for (const p of pids) {
    try {
      process.kill(Number(p), 'SIGKILL')
    } catch {
      /* gone */
    }
  }
  return `sigkill-each(${pids.length})`
}

// Run a program in the jail, sampling MemAvailable while it runs. A watchdog
// fires 10 s after the job's own wall: if a kernel primitive fails and
// media-jail hangs, it kills media-jail and the job and records `hung`, so one
// bad primitive cannot cost the whole report.
function jail(opts) {
  const { program, argv = [], slot = 'light', memMb, pids = 128, cpus = '0', wallS, id } = opts
  const args = [
    '--profile', 'node-worker', '--slot', slot, '--mem-mb', String(memMb),
    '--pids', String(pids), '--cpus', cpus, '--wall-s', String(wallS), '--id', id,
    '--', program, ...argv,
  ]
  return new Promise((resolve) => {
    let child
    try {
      child = start([MEDIA_JAIL, ...args], { env: JAIL_ENV })
    } catch (e) {
      resolve({ code: null, signal: null, stdout: '', status: null, stderr_tail: errText(e), min_mem_avail_kb: null, hung: false })
      return
    }
    let stdout = ''
    let stderr = ''
    let minAvail = Infinity
    let done = false
    child.stdout.on('data', (d) => (stdout += d))
    child.stderr.on('data', (d) => (stderr += d))
    const sampler = setInterval(() => {
      const mi = meminfo(readText('/proc/meminfo'))
      if (mi && mi.MemAvailable_kb < minAvail) minAvail = mi.MemAvailable_kb
    }, 100)
    const finish = (code, signal, extra = {}) => {
      if (done) return
      done = true
      clearInterval(sampler)
      clearTimeout(watchdog)
      const status = mjStatus(stderr)
      if (status) jobs.push({ id, program: [program, ...argv].join(' '), child_pid: status.child_pid })
      resolve({
        code,
        signal,
        stdout: stdout.trim(),
        status,
        stderr_tail: stderrTail(stderr),
        min_mem_avail_kb: Number.isFinite(minAvail) ? minAvail : null,
        hung: false,
        ...extra,
      })
    }
    const watchdog = setTimeout(() => {
      try {
        child.kill('SIGKILL')
      } catch {
        /* already gone */
      }
      let killed
      try {
        killed = killJob(`${CG_MEDIA}/${slot}-${id}`)
      } catch (e) {
        killed = String(e)
      }
      // A surviving job may still hold the pipes open; do not wait for them.
      child.stdout.destroy()
      child.stderr.destroy()
      finish(null, 'SIGKILL', { hung: true, watchdog_kill: killed })
    }, (wallS + 10) * 1000)
    child.on('close', (code, signal) => finish(code, signal))
    child.on('error', (e) => finish(null, null, { stderr_tail: String(e) }))
  })
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function safeJson(s) {
  try {
    return JSON.parse(s)
  } catch {
    return { raw: (s || '').slice(0, 500) }
  }
}

// What media-jail says about how it built the jail, for every jailed record.
function jailFacts(st) {
  if (!st) return null
  return {
    child_pid: st.child_pid ?? null,
    root_switch: st.root_switch ?? null,
    caps: st.caps ?? null,
    cpu_pin: st.cpu_pin ?? null,
    oom_group: st.oom_group ?? null,
    seccomp_kill: st.seccomp_kill ?? null,
    cgroup: st.cgroup ?? null,
    swap_max: st.swap_max ?? null,
    emulated: st.emulated ?? [],
  }
}

// --- sections -----------------------------------------------------------------

// AT_HWCAP / AT_HWCAP2 from /proc/self/auxv (u64 pairs, little-endian arm64).
function hwcaps() {
  let buf
  try {
    buf = readFileSync('/proc/self/auxv')
  } catch {
    return null
  }
  const out = {}
  for (let i = 0; i + 16 <= buf.length; i += 16) {
    const type = buf.readBigUInt64LE(i)
    const val = buf.readBigUInt64LE(i + 8)
    if (type === 16n) out.hwcap = val
    if (type === 26n) out.hwcap2 = val
  }
  return {
    hwcap: out.hwcap == null ? null : `0x${out.hwcap.toString(16)}`,
    hwcap2: out.hwcap2 == null ? null : `0x${out.hwcap2.toString(16)}`,
    // HWCAP_SVE is bit 22, HWCAP2_SVE2 bit 1: only a kernel that supports SVE
    // (4.15+) advertises them, whatever the CPU has.
    sve: out.hwcap == null ? null : ((out.hwcap >> 22n) & 1n) === 1n,
    sve2: out.hwcap2 == null ? null : ((out.hwcap2 >> 1n) & 1n) === 1n,
  }
}

// Where the node executable is mapped in this process (for turning the
// runner's own SIGILL pc into a file offset).
function nodeBase() {
  const maps = readText('/proc/self/maps') || ''
  for (const line of maps.split('\n')) {
    const f = line.trim().split(/\s+/)
    if (f.length >= 6 && f[5] === NODE && f[2] === '00000000') return BigInt(`0x${f[0].split('-')[0]}`)
  }
  return null
}

function meta() {
  const [maj, min] = process.versions.node.split('.').map(Number)
  return {
    schema: 'wappie-media-a0-probe/v2',
    pid: process.pid,
    node: process.version,
    node_ok: maj > 22 || (maj === 22 && min >= 13), // pdf.js needs >= 22.13
    arch: process.arch,
    os_release: release(),
    uname: (readText(`${PROBE}/uname`) || '').trim(),
    openssl: process.versions.openssl,
    v8: process.versions.v8,
    uv: process.versions.uv,
    exec_path: NODE,
    node_base: (() => {
      const b = nodeBase()
      return b == null ? null : `0x${b.toString(16)}`
    })(),
    hwcaps: hwcaps(),
    cpu_features: (readText(`${PROBE}/cpu-features`) || '').trim(),
    // 0xd40 is Neoverse V1 (Graviton3), which has SVE: there a false
    // hwcaps.sve means the kernel, not the CPU, lacks it.
    cpu_part: ((readText('/proc/cpuinfo') || '').match(/^CPU part\s*:\s*(\S+)/m) || [])[1] || null,
    cmdline: (readText(`${PROBE}/cmdline`) || '').trim(),
    entrypoint_processes: (readText(`${PROBE}/processes`) || '').trim().split('\n').filter(Boolean),
    emulate_old_kernel: EMULATE,
    boot_mem: meminfo(readText(`${PROBE}/boot-meminfo`)),
    after_node_mem: meminfo(readText('/proc/meminfo')),
  }
}

// --- kernel config from /proc/config.gz (probe.sh also records the blob's
//     Image.config on the parent, for when this is absent) ---
function kernelConfig() {
  const KEYS = [
    'CONFIG_IO_URING', 'CONFIG_USER_NS', 'CONFIG_SECCOMP_FILTER', 'CONFIG_CGROUPS',
    'CONFIG_MEMCG', 'CONFIG_CGROUP_PIDS', 'CONFIG_CPUSETS', 'CONFIG_PID_NS',
    'CONFIG_NET_NS', 'CONFIG_USERFAULTFD', 'CONFIG_SWAP', 'CONFIG_MEMCG_SWAP',
    'CONFIG_SECURITY_YAMA', 'CONFIG_ARM64_SVE',
  ]
  if (!existsSync('/proc/config.gz')) {
    return {
      source: null,
      note: '/proc/config.gz absent (CONFIG_IKCONFIG_PROC off); see kernel_unjailed and the blob Image.config probe.sh saved',
    }
  }
  const text = gunzipSync(readFileSync('/proc/config.gz')).toString('utf8')
  const facts = {}
  for (const k of KEYS) {
    const m = text.match(new RegExp(`^(${k})=(.*)$`, 'm'))
    const notset = text.match(new RegExp(`^# ${k} is not set$`, 'm'))
    facts[k] = m ? m[2] : notset ? 'not set' : 'absent'
  }
  return { source: '/proc/config.gz', facts }
}

// --- what the kernel itself supports, outside the jail (root, no seccomp).
//     Inside the jail these always fail by design, so they say nothing about
//     the kernel; here ENOSYS means not built in (§16.14: CONFIG_IO_URING) or
//     older than the call. ---
async function kernelUnjailed() {
  const meaning = (line, errno) => {
    if (line && /\b(OPENED|SURVIVED)\b/.test(line)) return 'supported'
    if (errno === ENOSYS) return 'absent (ENOSYS)'
    return errno == null ? 'unknown' : `refused (errno ${errno})`
  }
  const out = {}
  for (const t of ['io-uring', 'userfaultfd', 'unshare-userns', 'clone3', 'pidfd-open']) {
    const r = await run([`${BIN}/jailtest`, t], { timeoutMs: 5000 })
    const line = ((r.stdout || '').match(/^RESULT .*/m) || [])[0] || null
    const errno = line ? Number((line.match(/\berrno=(-?\d+)/) || [])[1]) : null
    out[t] = { result_line: line, meaning: meaning(line, errno), exit_code: r.code, signal: r.signal }
  }
  const sysctl = {}
  for (const p of [
    '/proc/sys/kernel/io_uring_disabled',
    '/proc/sys/vm/unprivileged_userfaultfd',
    '/proc/sys/user/max_user_namespaces',
    '/proc/sys/kernel/seccomp/actions_avail',
    '/proc/sys/kernel/cap_last_cap',
  ]) {
    const v = readText(p)
    sysctl[p] = v == null ? null : v.trim()
  }
  out.sysctl = sysctl
  return out
}

// --- cgroup layout, at boot (snapshot) and now ---
function cgroupReport() {
  const bootMountinfo = readText(`${PROBE}/boot-mountinfo`) || ''
  const setup = readText(`${PROBE}/cgroup-setup`) || ''
  const mediaCtl = (readText(`${CG_MEDIA}/cgroup.subtree_control`) || '').trim()
  const controllers = mediaCtl ? mediaCtl.split(/\s+/) : []
  // memory and pids are what media-jail needs; cpuset only where the kernel's
  // cgroup2 has it (5.0), else media-jail pins with sched_setaffinity.
  const v2Ok = ['memory', 'pids'].every((c) => controllers.includes(c))
  // Which interface files the media node has: cgroup.kill needs 5.14,
  // memory.peak 5.19, memory.oom.group 4.19, cpuset.cpus a cgroup2 cpuset (5.0).
  const files = {}
  for (const f of ['cgroup.kill', 'memory.peak', 'memory.current', 'memory.max', 'memory.swap.max', 'memory.oom.group', 'memory.events', 'pids.max', 'cpuset.cpus']) {
    files[f] = existsSync(`${CG_MEDIA}/${f}`)
  }
  return {
    path: 'cgroup2 at /run/cg2: memory + pids (+ cpuset where the kernel has it); media-jail detects each optional file',
    boot_cgroup_mountinfo: bootMountinfo.split('\n').filter((l) => l.includes('cgroup')),
    // The boot mount of / (mountinfo field 5): pivot_root needs the current
    // root to be a mount with a parent; this explains which root switch ran.
    boot_root_mount: bootMountinfo.split('\n').filter((l) => l.split(' ')[4] === '/'),
    boot_cgroups: readText(`${PROBE}/boot-cgroups`),
    setup_log: setup.split('\n').filter(Boolean),
    root_controllers: (readText('/run/cg2/cgroup.controllers') || '').trim(),
    run_cg2_media_controllers: controllers,
    v1_unmounted_v2_mounted_ok: v2Ok,
    media_files_present: files,
    hidepid: (readText(`${PROBE}/hidepid`) || '').trim(),
    swaps: readText('/proc/swaps'),
  }
}

async function selfCheck() {
  const r = await run([MEDIA_JAIL, '--self-check'], { env: JAIL_ENV, timeoutMs: 10000 })
  return { exit_code: r.code, signal: r.signal, report: safeJson(r.stdout), stderr: r.stderr.slice(0, 1000) }
}

// --- the jailed escape tests ---
// `started` is the jailtest sub-command whose START line must be on stdout
// before a kill counts: a SIGSYS during startup is a gap in the profile, not
// the denial under test. `errno`, when given, is the one a denied-errno must
// carry (ENOENT for a missing path, ENOSYS for the shim).
function classify(name, res, expect, { started = name, errno = null } = {}) {
  const st = res.status || {}
  const outcome = st.outcome
  const sig = st.term_signal
  const resultLine = (res.stdout.match(/^RESULT .*/m) || [])[0] || null
  const gotErrno = resultLine ? Number((resultLine.match(/\berrno=(-?\d+)/) || [])[1]) : null
  const didStart = new RegExp(`^START ${started}$`, 'm').test(res.stdout)
  let verdict
  // Denied patterns first: NOT-VISIBLE contains "VISIBLE", so it must be
  // matched before the survived patterns.
  if (res.hung) verdict = 'hung'
  else if (resultLine && /\bCLEARED\b/.test(resultLine)) verdict = 'cleared'
  else if (resultLine && /\bHELD\b/.test(resultLine)) verdict = 'held'
  else if (resultLine && /\bCOUNT\b/.test(resultLine)) verdict = 'listed'
  else if (resultLine && /\b(DENIED|NOT-VISIBLE)\b/.test(resultLine)) verdict = 'denied-errno'
  else if (resultLine && /\b(OPENED|SURVIVED|VISIBLE)\b/.test(resultLine)) verdict = 'survived'
  else if (!didStart) verdict = `not-started(${outcome},sig=${sig})`
  else if (outcome === 'signaled' && sig === 31) verdict = 'denied-seccomp'
  else if (outcome === 'oom') verdict = 'killed-memcg'
  else if (outcome === 'timeout') verdict = 'killed-wall'
  else verdict = `other(${outcome},sig=${sig})`
  let pass = expect.includes(verdict)
  if (pass && verdict === 'denied-errno' && errno != null) pass = gotErrno === errno
  // Anything the test printed besides START/RESULT (e.g. the PATH lines).
  const detail = res.stdout.split('\n').filter((l) => l && !/^(START|RESULT) /.test(l)).slice(0, 40)
  return {
    test: name,
    expected: expect,
    expected_errno: errno,
    verdict,
    pass,
    result_line: resultLine,
    errno: gotErrno,
    started: didStart,
    ...(detail.length ? { detail } : {}),
    outcome,
    term_signal: sig,
    exit_code: res.code,
    wall_ms: st.wall_ms ?? null,
    kill_method: st.kill_method ?? null,
    jail: jailFacts(res.status),
    hung: res.hung,
    ...(res.watchdog_kill ? { watchdog_kill: res.watchdog_kill } : {}),
    stderr_tail: res.stderr_tail,
  }
}

// Mount points a jail must never show (§16.6 step 3).
const FORBIDDEN_MOUNTS = /^\/(sys|run|etc|oldroot|dev\/nsm)(\/|$)/

async function jailTests() {
  const jt = `${BIN}/jailtest`
  const base = { program: jt, slot: 'light', memMb: 128, pids: 64, cpus: '0', wallS: 3 }
  const tests = []
  const record = (t) => {
    tests.push(t)
    emit('jail_test', t)
  }

  const run1 = async (name, argv, expect, { wallS = 3, memMb = 128, errno = null } = {}) =>
    classify(name, await jail({ ...base, argv, id: `t-${name}`, wallS, memMb }), expect, { started: argv[0], errno })

  record(await run1('nsm', ['nsm'], ['denied-errno'], { errno: ENOENT }))
  record(await run1('socket-vsock', ['socket-vsock'], ['denied-seccomp']))
  record(await run1('socket-inet', ['socket-inet'], ['denied-seccomp']))
  record(await run1('socket-unix', ['socket-unix'], ['survived'])) // AF_UNIX is allowed on purpose
  record(await run1('connect-unix', ['connect-unix'], ['denied-seccomp']))
  record(await run1('io-uring', ['io-uring'], ['denied-errno'], { errno: ENOSYS }))
  record(await run1('userfaultfd', ['userfaultfd'], ['denied-seccomp']))
  record(await run1('unshare-userns', ['unshare-userns'], ['denied-seccomp']))
  record(await run1('clone-newns', ['clone-newns'], ['denied-seccomp']))
  record(await run1('clone3', ['clone3'], ['denied-errno'], { errno: ENOSYS }))
  record(await run1('chroot', ['chroot'], ['denied-seccomp']))
  record(await run1('paths', ['paths'], ['denied-errno'], { errno: ENOENT }))
  // No capability left anywhere, NoNewPrivs and the filter on: what makes
  // either root switch final (the move+chroot one in particular).
  record(await run1('privs', ['privs'], ['cleared']))
  // The worker's whole view of the mount table: nothing host-only in it.
  const mounts = await run1('mountinfo', ['mountinfo'], ['listed'])
  const points = (mounts.detail || []).filter((l) => l.startsWith('MOUNT ')).map((l) => l.split(' ')[5])
  mounts.mount_points = points
  mounts.forbidden = points.filter((p) => FORBIDDEN_MOUNTS.test(p))
  mounts.pass = mounts.pass && points.length > 0 && mounts.forbidden.length === 0
  record(mounts)
  record(await run1('memhog', ['memhog', '512'], ['killed-memcg'], { wallS: 30, memMb: 64 }))

  // proc-peek needs a live concurrent job to look at. Start a spinner, read its
  // host pid from the leaf's cgroup.procs, then peek it from another jail. The
  // peek only counts if the victim existed (the runner, outside any jail, sees
  // it) and was still running when the peek finished.
  const victimId = 'victim'
  const victimLeaf = `${CG_MEDIA}/heavy-${victimId}`
  let victimDone = false
  const victim = jail({ program: jt, argv: ['spin'], slot: 'heavy', memMb: 64, pids: 64, cpus: '0', wallS: 20, id: victimId })
  victim.then(() => (victimDone = true))
  await sleep(800)
  const victimPid = (readText(`${victimLeaf}/cgroup.procs`) || '').trim().split('\n')[0] || null
  if (victimPid) {
    const seenBefore = existsSync(`/proc/${victimPid}/stat`)
    const peek = await run1('proc-peek', ['proc-peek', victimPid], ['denied-errno'], { errno: ENOENT })
    const aliveAfter = !victimDone && existsSync(`/proc/${victimPid}/stat`)
    peek.victim = { host_pid: victimPid, seen_by_runner: seenBefore, alive_after_peek: aliveAfter }
    if (!seenBefore || !aliveAfter) {
      peek.pass = false
      peek.verdict += seenBefore ? ' (victim exited before the peek finished)' : ' (victim pid not visible to the runner)'
    }
    record(peek)
  } else {
    record({ test: 'proc-peek', expected: ['denied-errno'], verdict: 'no-victim', pass: false, victim_procs: readText(`${victimLeaf}/cgroup.procs`) })
  }

  // The main Node's kill path from outside media-jail (§16.6): cgroup.kill, or
  // on a kernel without it (4.14) SIGKILL of the job's PID-namespace init. The
  // victim must die by SIGKILL well before its 20 s wall.
  let killPath
  try {
    killPath = killJob(victimLeaf)
  } catch (e) {
    killPath = `failed: ${String(e)}`
  }
  const vr = await victim
  const vs = vr.status || {}
  const vStarted = /^START spin$/m.test(vr.stdout)
  const vVerdict = vr.hung ? 'hung' : vs.outcome === 'signaled' ? `signaled-${vs.term_signal}` : `other(${vs.outcome},sig=${vs.term_signal})`
  record({
    test: 'external-kill',
    expected: ['signaled-9'],
    verdict: vVerdict,
    pass: !killPath.startsWith('failed') && vStarted && vVerdict === 'signaled-9' && vs.wall_ms != null && vs.wall_ms < 10000,
    kill_path: killPath,
    started: vStarted,
    outcome: vs.outcome ?? null,
    term_signal: vs.term_signal ?? null,
    wall_ms: vs.wall_ms ?? null,
    kill_method: vs.kill_method ?? null,
    jail: jailFacts(vr.status),
    hung: vr.hung,
    stderr_tail: vr.stderr_tail,
  })

  // The wall timeout is exercised by spin under a short wall; kill_method says
  // whether cgroup.kill alone did it or media-jail fell back to the job's PID 1.
  const spinRes = await jail({ program: jt, argv: ['spin'], slot: 'light', memMb: 128, pids: 64, cpus: '0', wallS: 2, id: 't-wall' })
  record(classify('wall-timeout', spinRes, ['killed-wall'], { started: 'spin' }))

  return {
    go: tests.every((t) => t.pass),
    passed: tests.filter((t) => t.pass).map((t) => t.test),
    failed: tests.filter((t) => !t.pass).map((t) => t.test),
    root_switch: [...new Set(tests.map((t) => t.jail && t.jail.root_switch).filter(Boolean))],
    kill_methods: [...new Set(tests.map((t) => t.kill_method).filter(Boolean))],
  }
}

// --- the A1 sharp/pdfjs stack on the generated corpus ---
const jobMem = (res) => ({
  parsed: safeJson(res.stdout),
  peak_bytes: res.status ? res.status.memory_peak_bytes : null,
  // Sampled every 50 ms by media-jail, for a kernel without memory.peak.
  current_max_bytes: res.status ? res.status.memory_current_max_bytes : null,
  ru_maxrss_kb: res.status ? res.status.ru_maxrss_kb : null,
  wall_ms: res.status ? res.status.wall_ms : null,
  min_mem_avail_kb: res.min_mem_avail_kb,
  outcome: res.status ? res.status.outcome : null,
  exit_code: res.code,
  jail: jailFacts(res.status),
  hung: res.hung,
  stderr_tail: res.stderr_tail,
})

async function corpus() {
  // Unjailed: the runner is Node with sharp available.
  const gen = await run([NODE, `${WORKER}/gen-corpus.mjs`, CORPUS], { timeoutMs: 120000 })
  const parsed = safeJson(gen.stdout)
  return { ...parsed, pid: gen.pid, exit_code: gen.code, signal: gen.signal, timed_out: gen.timed_out, stderr: gen.stderr.slice(0, 1000) }
}

// Image job (jailed): a 12 MP decode + re-encode. Generous cap so it does not
// OOM — the point is to read the true peak. The jail passes the worker no
// VIPS_* variables (§16.6 step 7); image-probe.mjs sets concurrency and the
// loader block itself.
async function imageJob() {
  return jobMem(await jail({
    program: NODE,
    argv: [`${WORKER}/image-probe.mjs`, `${CORPUS}/image.jpg`],
    slot: 'light', memMb: 768, pids: 256, cpus: '0', wallS: 30, id: 'img',
  }))
}

// PDF job (jailed): 50-page text extraction, proving pdf.js needs no canvas.
async function pdfJob() {
  return jobMem(await jail({
    program: NODE,
    argv: [`${WORKER}/pdf-probe.mjs`, `${CORPUS}/doc.pdf`],
    slot: 'light', memMb: 768, pids: 256, cpus: '0', wallS: 30, id: 'pdf',
  }))
}

// --- vsock throughput: start the sink, the parent (probe.sh) connects and
//     streams. Wait for the sink to write its results, or time out. ---
async function vsock() {
  const outFile = `${PROBE}/vsock.json`
  const sink = start([`${BIN}/vsock-sink`, String(VSOCK_PORT), outFile, '16MiB', '32MiB'], {
    stdio: ['ignore', 'ignore', 'ignore'],
  })
  // The wait is bounded; a local (non-Nitro) simulation shortens it because no
  // parent sender exists there.
  const waitMs = Number(process.env.PROBE_VSOCK_TIMEOUT_MS || 60000)
  const deadline = Date.now() + waitMs
  while (Date.now() < deadline) {
    if (existsSync(outFile)) {
      const parsed = safeJson(readText(outFile))
      if (Array.isArray(parsed) && parsed.length >= 2) {
        return { port: VSOCK_PORT, transfers: parsed }
      }
    }
    await sleep(500)
  }
  try {
    sink.kill('SIGKILL')
  } catch {
    /* best effort */
  }
  return { port: VSOCK_PORT, error: `no sender completed within ${Math.round(waitMs / 1000)}s (parent did not stream)` }
}

// --- the kernel's own reports about our processes, from /dev/kmsg ---
function readKmsg() {
  const fd = openSync('/dev/kmsg', constants.O_RDONLY | constants.O_NONBLOCK)
  const buf = Buffer.alloc(16384)
  const recs = []
  try {
    for (;;) {
      let n
      try {
        n = readSync(fd, buf, 0, buf.length, null)
      } catch (e) {
        if (e.code === 'EPIPE') continue // a record was overwritten; go on
        break // EAGAIN: no more records
      }
      if (n <= 0) break
      const text = buf.toString('utf8', 0, n)
      const semi = text.indexOf(';')
      const head = text.slice(0, semi).split(',')
      recs.push({ ts_us: Number(head[2]), msg: text.slice(semi + 1).split('\n')[0] })
    }
  } finally {
    closeSync(fd)
  }
  return recs
}

// Who a pid was: something the runner started, a jailed job's PID 1, one of
// the entrypoint's processes, or the runner itself.
function whoIs(pid) {
  if (pid === process.pid) return 'the runner (probe-report.mjs)'
  const s = spawned.find((r) => r.pid === pid)
  if (s) return `runner spawn: ${JSON.stringify(s.argv)} (comm ${s.comm})`
  const j = jobs.find((x) => x.child_pid === pid)
  if (j) return `jailed job ${j.id}: ${j.program}`
  const e = ((readText(`${PROBE}/processes`) || '').match(new RegExp(`^(\\S+) pid=${pid} `, 'm')) || [])[1]
  if (e) return `entrypoint: ${e}`
  return 'unknown'
}

// The entrypoint's mark in the kernel log; only what follows it is this run
// (a test kernel's log also holds other runs).
const KMSG_MARK = 'wappie-a0: probe entrypoint started'

function kernelLog() {
  const all = readKmsg()
  let from = 0
  all.forEach((r, i) => {
    if (r.msg.includes(KMSG_MARK)) from = i + 1
  })
  const recs = all.slice(from)
  const base = nodeBase()
  const sigill = []
  const seccomp = []
  const oom = []
  const other = []
  for (let i = 0; i < recs.length; i++) {
    const m = recs[i].msg
    const bad = m.match(/Bad EL0 synchronous exception detected on CPU\d+, code (0x[0-9a-f]+)/)
    if (bad) {
      const ev = { ts_s: recs[i].ts_us / 1e6, esr: bad[1], pid: null, comm: null, pc: null }
      // The register dump that follows belongs to this event, up to the next.
      for (let k = i + 1; k < Math.min(recs.length, i + 8); k++) {
        if (/Bad EL0 synchronous exception/.test(recs[k].msg)) break
        const who = recs[k].msg.match(/PID: (\d+) Comm: (\S+)/)
        if (who && ev.pid == null) {
          ev.pid = Number(who[1])
          ev.comm = who[2]
        }
        const pc = recs[k].msg.match(/^pc : (?:0x)?([0-9a-f]+)/)
        if (pc && ev.pc == null) ev.pc = `0x${pc[1]}`
      }
      if (ev.pc) {
        const pc = BigInt(ev.pc)
        ev.pc_page_offset = `0x${(pc & 0xfffn).toString(16)}`
        ev.openssl_sve_probe = Number(pc & 0xfffn) === SVE_PROBE_PAGE_OFFSET
        // The runner's own event maps to an exact offset in the node binary.
        if (ev.pid === process.pid && base != null) {
          ev.node_file_offset = `0x${(pc - base).toString(16)}`
          ev.openssl_sve_probe = pc - base === BigInt(SVE_PROBE_OFFSET)
        }
      }
      ev.source = ev.pid == null ? 'unknown' : whoIs(ev.pid)
      sigill.push(ev)
      continue
    }
    // Seccomp kills, as audit records (type 1326): which syscall, which job.
    if (/type=1326/.test(m)) {
      const f = (k) => ((m.match(new RegExp(`\\b${k}=("[^"]*"|\\S+)`)) || [])[1] || '').replace(/^"|"$/g, '') || null
      const pid = Number(f('pid'))
      seccomp.push({ ts_s: recs[i].ts_us / 1e6, pid, comm: f('comm'), sig: f('sig'), syscall: Number(f('syscall')), code: f('code'), source: whoIs(pid) })
      continue
    }
    if (/out of memory|Killed process|oom-kill|oom_reaper/i.test(m)) {
      oom.push({ ts_s: recs[i].ts_us / 1e6, msg: m })
      continue
    }
    if (/undefined instruction|unhandled|segfault|Unable to handle|panic|BUG:|WARNING:/i.test(m)) {
      other.push({ ts_s: recs[i].ts_us / 1e6, msg: m })
    }
  }
  const nodeSigills = sigill.filter((e) => e.comm === 'node')
  return {
    since_mark: from > 0,
    records_read: recs.length,
    sigill,
    node_sigill_count: nodeSigills.length,
    node_sigill_recurs: nodeSigills.length > 1,
    // true when every node SIGILL sits on OpenSSL's SVE probe (handled by
    // OpenSSL, so harmless); false points at something else executing SVE.
    all_node_sigills_are_openssl_sve_probe: nodeSigills.length > 0 && nodeSigills.every((e) => e.openssl_sve_probe),
    seccomp_kills: seccomp,
    oom: oom.slice(0, 40),
    other: other.slice(0, 40),
  }
}

// --- the facts for A1's decision: stay on the blob kernel or build our own ---
function a1Kernel(ctx) {
  const unj = ctx.unjailed || {}
  const files = (ctx.cgroup && ctx.cgroup.media_files_present) || {}
  const sc = (ctx.selfCheck && ctx.selfCheck.report) || {}
  const hp = (readText(`${PROBE}/hidepid`) || '').trim()
  const supported = (t) => (unj[t] ? unj[t].meaning === 'supported' : null)
  const feature = (name, since, present, onMissing) => ({ feature: name, since, present, on_missing: onMissing })
  const hw = (ctx.meta && ctx.meta.hwcaps) || {}
  const list = [
    feature('cgroup2 cpuset', '5.0', files['cpuset.cpus'] ?? null, 'sched_setaffinity in the child; sched_setaffinity is never allowlisted'),
    feature('cgroup.kill', '5.14', files['cgroup.kill'] ?? null, "SIGKILL of the job's PID-namespace init (kills the namespace)"),
    feature('memory.oom.group', '4.19', files['memory.oom.group'] ?? null, 'media-jail kills the namespace on the first oom_kill'),
    feature('memory.peak', '5.19', files['memory.peak'] ?? null, 'memory.current sampled every 50 ms + the worker ru_maxrss'),
    feature('hidepid on /proc', '3.3 (as 2; "invisible" is its 5.8 name)', hp ? hp.startsWith('hidepid=2') : null, 'none needed: hidepid=2 works on 4.14; jobs mount their own /proc anyway'),
    feature('io_uring', '5.1', supported('io-uring'), 'nothing to do; the ENOSYS shim stays for newer kernels'),
    feature('clone3', '5.3', supported('clone3'), 'nothing to do; the ENOSYS shim stays for newer kernels'),
    feature('pidfd_open', '5.3', supported('pidfd-open'), 'the main Node kills by pid; the PID namespace bounds the job'),
    feature('SECCOMP_RET_KILL_PROCESS', '4.14', sc.seccomp ? sc.seccomp.kill_action === 'kill_process' : null, 'KILL_THREAD (a multi-threaded worker then hangs until its wall)'),
    // Only meaningful on an SVE CPU (Graviton3, CPU part 0xd40).
    feature('SVE in the kernel (HWCAP_SVE)', '4.15', ctx.meta && ctx.meta.cpu_part === '0xd40' ? hw.sve ?? null : null, "Graviton3's SVE unused; OpenSSL's probe SIGILLs once per node start"),
    feature('close_range', '5.9', null, '/proc/self/fd walk in media-jail (not measured here)'),
  ]
  return {
    kernel: release(),
    missing: list.filter((f) => f.present === false).map((f) => f.feature),
    features: list,
    root_switch_used: ctx.jail ? ctx.jail.root_switch : null,
  }
}

async function main() {
  emit('begin', { schema: 'wappie-media-a0-probe/v2', pid: process.pid, emulate_old_kernel: EMULATE })
  const ctx = {}
  ctx.meta = await section('meta', meta)
  await section('kernel_config', kernelConfig)
  ctx.cgroup = await section('cgroup', cgroupReport)
  ctx.selfCheck = await section('media_jail_self_check', selfCheck)
  ctx.unjailed = await section('kernel_unjailed', kernelUnjailed)
  ctx.jail = await section('jail', jailTests)
  await section('corpus', corpus)
  await section('image_job', imageJob)
  await section('pdf_job', pdfJob)
  await section('vsock', vsock)
  await section('kernel_log', kernelLog)
  await section('a1_kernel', () => a1Kernel(ctx))
  emit('done', { records: seq + 1, fatal_errors: fatal, spawned: spawned.length, go: ctx.jail ? ctx.jail.go === true : false })
}

main().then(
  () => process.exit(fatal ? 1 : 0),
  (e) => {
    emit('fatal', { kind: 'main', error: errText(e) })
    process.exit(1)
  },
)
