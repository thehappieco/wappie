// The A1 probe runner. It runs INSIDE the probe enclave at boot, as a child of
// entrypoint-probe.sh, and STREAMS its report to the enclave console: every
// section is printed the moment it is measured, as one line
//
//   A1R <seq> <bytes> {"section":"<name>","t":<uptime s>,"data":{...}}
//
// where <bytes> is the UTF-8 length of the JSON, so probe.sh
// (assemble-report.py) can tell a whole line from one a kernel message broke
// in two. The same lines are appended to /run/probe/report.jsonl, which the
// entrypoint prints again at the end. A crash mid-way therefore still leaves
// every finished section on the console (the A0 lesson: the first Nitro run
// printed one JSON object at the very end and left nothing).
//
// The probe image is the A1 reader image with the jail check of
// check-image.sh --jail on top (Dockerfile.probe). On the enclave's own
// kernel this runs, in order:
//
//   - the A0 kernel facts: versions and CPU, /proc/config.gz, the cgroup
//     layout the production entrypoint's media jail block made, media-jail
//     --self-check, the syscalls the kernel has outside any jail, and the
//     vsock throughput from the parent (vsock 9100, vsock-send.py);
//   - the jail check check-image.sh --jail runs (jailcheck/jail-check.mjs):
//     the setup, the refusals, the A0 escape tests from /opt/media, signals
//     and parent death, and the whole §16.13 corpus through the reader's
//     runWorker, every worker under the image's media-jail and seccomp
//     profile. One `jail_result` record per check, as it passes or fails;
//   - the reader end to end (enclave/test/media-e2e.test.mjs, MEDIA_E2E=jail),
//     which needs loopback only;
//   - the reader stand-in (reader-bench.mjs): the production reader idle,
//     MemAvailable while the heaviest jobs run, and 16 and 32 MiB PDF and
//     docx files opened end to end with their ciphertext served by the parent
//     over vsock (vsock 9101, vsock-serve.py). One `bench` record per result;
//   - the kernel's own reports about all of it (SIGILL, seccomp kills, OOM)
//     and what the 4.14 blob kernel lacks for §16.6.
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
  writeSync,
} from 'node:fs'
import { release } from 'node:os'
import { dirname } from 'node:path'
import { gunzipSync } from 'node:zlib'

const MEDIA_JAIL = '/usr/local/bin/media-jail'
const NODE = process.execPath
const JAILTEST = '/opt/jailcheck/media/bin/jailtest'
const VSOCK_SINK = '/opt/probe/bin/vsock-sink'
const JAIL_CHECK = '/opt/jailcheck/jail-check.mjs'
const E2E = '/opt/e2e/packages/mcp-http/enclave/test/media-e2e.test.mjs'
const BENCH = '/opt/e2e/packages/mcp-http/enclave/test/probe-bench.mjs'
const CONSTANTS = '/app/packages/mcp-http/enclave/constants.mjs'
// vsock ports outside production's 5443-5445/7000-7002/8000-8002/9000: the
// parent streams to 9100 (A0's throughput) and serves objects on 9101.
const VSOCK_PORT = 9100
const OBJECTS_PORT = 9101
const BRIDGE_PORT = 9101 // the loopback end of the bridge to the parent's 9101
const PARENT_CID = Number(process.env.PROBE_PARENT_CID || 3)
const PROBE = '/run/probe'
const REPORT = `${PROBE}/report.jsonl`
const CG_MEDIA = '/run/cg2/media'
// Paths only the probe carries: the root filesystem lives in enclave memory,
// so the report says how much of it production would not hold.
const PROBE_ONLY = ['/opt/e2e', '/opt/jailcheck', '/opt/media/worker/test', '/opt/probe', '/probe']

const ENOSYS = 38

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
  const line = `A1R ${++seq} ${Buffer.byteLength(json)} ${json}\n`
  out(line)
  try {
    appendFileSync(REPORT, line)
  } catch {
    /* the console copy is the one that counts */
  }
}

function progress(msg) {
  out(`A1 RUN t=${uptime()} ${msg}\n`)
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

const procComm = (pid) => (readText(`/proc/${pid}/comm`) || '').trim() || null
const procCmdline = (pid) => {
  const t = readText(`/proc/${pid}/cmdline`)
  return t == null ? null : t.split('\0').filter(Boolean)
}

// Start a process: its argv is printed BEFORE it starts, then its pid, comm and
// cmdline as the kernel sees them (spawn returns after the exec), and its end.
function start(argv, { env = process.env, cwd, stdio = ['ignore', 'pipe', 'pipe'] } = {}) {
  progress(`spawn ${JSON.stringify(argv)}`)
  const child = spawn(argv[0], argv.slice(1), { env, cwd, stdio })
  const pid = child.pid ?? null
  const rec = { pid, argv, comm: pid ? procComm(pid) : null, cmdline: pid ? procCmdline(pid) : null }
  spawned.push(rec)
  emit('spawn', rec)
  child.once('exit', (code, signal) => {
    rec.code = code
    rec.signal = signal
    emit('exit', { pid, argv0: argv[0], code, signal })
  })
  // A spawn that fails (ENOENT) is reported by its 'error' event; the callers
  // listen for it, and this keeps it from becoming an uncaught exception.
  child.on('error', () => {})
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

// Run a long child, handing each stdout line to `onLine` as it arrives (so its
// results are streamed, not held), with a hard timeout. Lines `onLine` does
// not take, and stderr, are kept as tails for the section's record.
function streamChild(argv, { env = process.env, cwd, timeoutMs, onLine = () => false }) {
  return new Promise((resolve) => {
    const started = Date.now()
    const other = []
    let stderr = ''
    let pending = ''
    let done = false
    let timedOut = false
    const keep = (line) => {
      other.push(line)
      if (other.length > 60) other.shift()
    }
    const take = (line) => {
      try {
        if (!onLine(line)) keep(line)
      } catch (e) {
        keep(`${line} (not read: ${String(e)})`)
      }
    }
    let child
    try {
      child = start(argv, { env, cwd })
    } catch (e) {
      resolve({ code: null, signal: null, error: errText(e), ms: 0, output_tail: [], stderr_tail: '' })
      return
    }
    child.stdout.on('data', (d) => {
      pending += d
      let nl
      while ((nl = pending.indexOf('\n')) >= 0) {
        take(pending.slice(0, nl))
        pending = pending.slice(nl + 1)
      }
    })
    child.stderr.on('data', (d) => {
      stderr = (stderr + d).slice(-4000)
    })
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
      if (pending) take(pending)
      resolve({ pid: child.pid ?? null, ms: Date.now() - started, timed_out: timedOut, output_tail: other, stderr_tail: stderr, ...extra })
    }
    child.on('error', (e) => finish({ code: null, signal: null, error: errText(e) }))
    child.on('close', (code, signal) => finish({ code, signal }))
  })
}

function meminfo(text) {
  if (!text) return null
  const out = {}
  for (const key of ['MemTotal', 'MemAvailable', 'MemFree', 'Shmem', 'Cached']) {
    const m = text.match(new RegExp(`^${key}:\\s+(\\d+)`, 'm'))
    if (m) out[key + '_kb'] = Number(m[1])
  }
  return out
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function safeJson(s) {
  try {
    return JSON.parse(s)
  } catch {
    return { raw: (s || '').slice(0, 500) }
  }
}

// --- the A0 kernel facts --------------------------------------------------------

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

async function meta() {
  const [maj, min] = process.versions.node.split('.').map(Number)
  let reader = null
  try {
    const c = await import(CONSTANTS)
    reader = { version: c.READER_VERSION ?? null, capabilities: c.READER_CAPABILITIES ?? null }
  } catch (e) {
    reader = { error: errText(e) }
  }
  // The probe-only trees, in KiB (busybox du -sk).
  const du = await run(['du', '-sk', ...PROBE_ONLY.filter((p) => existsSync(p))], { timeoutMs: 60000 })
  const probeOnly = {}
  for (const line of (du.stdout || '').split('\n')) {
    const m = line.match(/^(\d+)\s+(\S+)$/)
    if (m) probeOnly[m[2]] = Number(m[1])
  }
  return {
    schema: 'wappie-media-a1-probe/v1',
    pid: process.pid,
    reader,
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
    cpus_online: (readText('/sys/devices/system/cpu/online') || '').trim(),
    cmdline: (readText(`${PROBE}/cmdline`) || '').trim(),
    entrypoint_processes: (readText(`${PROBE}/processes`) || '').trim().split('\n').filter(Boolean),
    boot_mem: meminfo(readText(`${PROBE}/boot-meminfo`)),
    after_node_mem: meminfo(readText('/proc/meminfo')),
    probe_only_kb: probeOnly,
    probe_only_total_kb: Object.values(probeOnly).reduce((a, b) => a + b, 0),
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
//     the kernel; here ENOSYS means not built in or older than the call. ---
async function kernelUnjailed() {
  const meaning = (line, errno) => {
    if (line && /\b(OPENED|SURVIVED)\b/.test(line)) return 'supported'
    if (errno === ENOSYS) return 'absent (ENOSYS)'
    return errno == null ? 'unknown' : `refused (errno ${errno})`
  }
  const out = {}
  for (const t of ['io-uring', 'userfaultfd', 'unshare-userns', 'clone3', 'pidfd-open']) {
    const r = await run([JAILTEST, t], { timeoutMs: 5000 })
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

// --- cgroup layout, at boot (snapshot) and after the production block ---
function cgroupReport() {
  const bootMountinfo = readText(`${PROBE}/boot-mountinfo`) || ''
  const setup = readText(`${PROBE}/cgroup-setup`) || ''
  const mediaCtl = (readText(`${CG_MEDIA}/cgroup.subtree_control`) || '').trim()
  const controllers = mediaCtl ? mediaCtl.split(/\s+/) : []
  // memory and pids are what the reader's boot check requires; cpuset only
  // where the kernel's cgroup2 has it (5.0), else media-jail pins with
  // sched_setaffinity.
  const v2Ok = ['memory', 'pids'].every((c) => controllers.includes(c))
  // Which interface files the media node has: cgroup.kill needs 5.14,
  // memory.peak 5.19, memory.oom.group 4.19, cpuset.cpus a cgroup2 cpuset (5.0).
  const files = {}
  for (const f of ['cgroup.kill', 'memory.peak', 'memory.current', 'memory.max', 'memory.swap.max', 'memory.oom.group', 'memory.events', 'pids.max', 'cpuset.cpus']) {
    files[f] = existsSync(`${CG_MEDIA}/${f}`)
  }
  return {
    path: "the production entrypoint's media jail block (deploy/enclave/entrypoint.sh), run as shipped",
    boot_cgroup_mountinfo: bootMountinfo.split('\n').filter((l) => l.includes('cgroup')),
    // The boot mount of / (mountinfo field 5): pivot_root needs the current
    // root to be a mount with a parent; this explains which root switch ran.
    boot_root_mount: bootMountinfo.split('\n').filter((l) => l.split(' ')[4] === '/'),
    boot_cgroups: readText(`${PROBE}/boot-cgroups`),
    setup_trace: setup.split('\n').filter(Boolean).slice(-120),
    root_controllers: (readText('/run/cg2/cgroup.controllers') || '').trim(),
    root_subtree_control: (readText('/run/cg2/cgroup.subtree_control') || '').trim(),
    run_cg2_media_controllers: controllers,
    memory_and_pids_ok: v2Ok,
    media_files_present: files,
    hidepid: (readText('/proc/mounts') || '').split('\n').filter((l) => / \/proc proc /.test(l)),
    oom_score_adj: (readText('/proc/self/oom_score_adj') || '').trim(),
    swaps: readText('/proc/swaps'),
  }
}

async function selfCheck() {
  const r = await run([MEDIA_JAIL, '--self-check'], { timeoutMs: 10000 })
  const table = await run([MEDIA_JAIL, '--table'], { timeoutMs: 10000 })
  return { exit_code: r.code, signal: r.signal, report: safeJson(r.stdout), stderr: r.stderr.slice(0, 1000), table: safeJson(table.stdout) }
}

// --- vsock throughput: start the sink, the parent (probe.sh) connects and
//     streams. Wait for the sink to write its results, or time out. ---
async function vsock() {
  const outFile = `${PROBE}/vsock.json`
  const sink = start([VSOCK_SINK, String(VSOCK_PORT), outFile, '16MiB', '32MiB'], {
    stdio: ['ignore', 'ignore', 'ignore'],
  })
  // The wait is bounded; a local (non-Nitro) run shortens it when no parent
  // sender exists there.
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

// --- the jail check, as check-image.sh --jail runs it --------------------------

// jail-check.mjs prints `PASS <name> <json>` or `FAIL <name> <json>` per check
// and a last summary line; each check becomes a `jail_result` record now.
async function jailCheck() {
  const results = []
  const rootSwitch = new Set()
  const killMethods = new Set()
  const peaks = []
  const r = await streamChild([NODE, JAIL_CHECK], {
    timeoutMs: 600000,
    onLine(line) {
      const m = line.match(/^(PASS|FAIL) (.*?)(?: (\{.*\}))?$/)
      if (!m) return false
      const detail = m[3] ? safeJson(m[3]) : {}
      const rec = { pass: m[1] === 'PASS', name: m[2], detail }
      results.push(rec)
      emit('jail_result', rec)
      if (detail.jail?.root_switch) rootSwitch.add(detail.jail.root_switch)
      if (detail.jail?.kill_method) killMethods.add(detail.jail.kill_method)
      if (detail.kill_method) killMethods.add(detail.kill_method)
      if (detail.peak_mb != null || detail.current_max_mb != null) peaks.push({ name: m[2], peak_mb: detail.peak_mb ?? null, current_max_mb: detail.current_max_mb ?? null, ms: detail.ms ?? null })
      return true
    },
  })
  const failed = results.filter((x) => !x.pass).map((x) => x.name)
  peaks.sort((a, b) => (b.peak_mb ?? b.current_max_mb ?? 0) - (a.peak_mb ?? a.current_max_mb ?? 0))
  return {
    go: r.code === 0 && results.length > 0 && failed.length === 0,
    exit_code: r.code,
    signal: r.signal,
    timed_out: r.timed_out,
    ms: r.ms,
    checks: results.length,
    passed: results.length - failed.length,
    failed,
    root_switch: [...rootSwitch],
    kill_methods: [...killMethods],
    largest_memory: peaks.slice(0, 8),
    summary: r.output_tail.filter((l) => l.startsWith('jail check:')),
    output_tail: r.output_tail.slice(-20),
    stderr_tail: r.stderr_tail,
  }
}

// --- the reader end to end, as check-image.sh --jail runs it -------------------
async function mediaE2e() {
  const tap = []
  const r = await streamChild([NODE, '--test', '--test-reporter=tap', E2E], {
    env: { ...process.env, MEDIA_E2E: 'jail' },
    timeoutMs: 300000,
    onLine(line) {
      tap.push(line)
      if (tap.length > 200) tap.shift()
      return true
    },
  })
  const count = (key) => Number((tap.join('\n').match(new RegExp(`^# ${key} (\\d+)$`, 'm')) || [])[1] ?? NaN)
  return {
    go: r.code === 0 && count('pass') >= 1 && count('fail') === 0,
    exit_code: r.code,
    signal: r.signal,
    timed_out: r.timed_out,
    ms: r.ms,
    pass: count('pass'),
    fail: count('fail'),
    skipped: count('skipped'),
    // A failure's diagnostics sit between its `not ok` line and the summary.
    tap_tail: tap.slice(-60),
    stderr_tail: r.stderr_tail,
  }
}

// --- the reader stand-in: idle memory, the heaviest jobs, documents over vsock
async function readerBench() {
  const loopback = process.env.PROBE_OBJECTS === 'loopback'
  // The parent's objects arrive the way production's archive answers do: a
  // socat bridge from loopback to the parent's vsock port.
  const bridge = loopback
    ? null
    : start(['socat', `TCP-LISTEN:${BRIDGE_PORT},bind=127.0.0.1,reuseaddr,fork`, `VSOCK-CONNECT:${PARENT_CID}:${OBJECTS_PORT}`], {
        stdio: ['ignore', 'ignore', 'ignore'],
      })
  const phases = {}
  const documents = []
  let fatalBench = null
  try {
    const r = await streamChild([NODE, '--expose-gc', BENCH], {
      cwd: dirname(BENCH),
      env: { ...process.env, PROBE_OBJECTS: loopback ? 'loopback' : 'vsock', PROBE_BRIDGE_PORT: String(BRIDGE_PORT) },
      timeoutMs: 900000,
      onLine(line) {
        if (!line.startsWith('BENCH ')) return false
        const rec = safeJson(line.slice(6))
        emit('bench', rec)
        phases[rec.phase] = (phases[rec.phase] ?? 0) + 1
        if (rec.phase === 'document') documents.push(rec)
        if (rec.phase === 'fatal') fatalBench = rec.error
        if (rec.phase === 'boot') phases.media_jail = rec.media_jail
        if (rec.phase === 'heavy_summary') phases.heavy = { mem_avail_min_mb: rec.mem_avail_min_mb, meets_quarter: rec.meets_quarter }
        return true
      },
    })
    // Each document must open: an OOM, a wall, a worker's seccomp kill or a
    // still-pending open after OPEN_LIMIT_MS ends as another outcome.
    const opened = (d) => !d.error && (d.outcome === 'complete' || d.outcome === 'partial')
    return {
      go: r.code === 0 && phases.end === 1 && phases.media_jail === true && documents.length === 4 && documents.every(opened),
      exit_code: r.code,
      signal: r.signal,
      timed_out: r.timed_out,
      ms: r.ms,
      objects: loopback ? 'loopback (no parent)' : `vsock ${PARENT_CID}:${OBJECTS_PORT} through 127.0.0.1:${BRIDGE_PORT}`,
      phases,
      heavy: phases.heavy ?? null,
      documents: documents.map((d) => ({ name: d.name, ms: d.ms ?? null, outcome: d.outcome ?? null, fits_chatgpt: d.fits_chatgpt ?? null, transport: d.transport ?? null, error: d.error ?? null })),
      fatal: fatalBench,
      runner_rss_mb: Math.round(process.memoryUsage.rss() / 1048576),
      output_tail: r.output_tail.slice(-20),
      stderr_tail: r.stderr_tail,
    }
  } finally {
    if (bridge) {
      try {
        bridge.kill('SIGTERM')
      } catch {
        /* gone */
      }
    }
  }
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

// Who a pid was: something the runner started, one of the entrypoint's
// processes, or the runner itself. A jailed job's PID 1 is a grandchild
// (jail-check.mjs or the reader stand-in started it), so it reads `unknown`,
// and its comm says what it ran.
function whoIs(pid) {
  if (pid === process.pid) return 'the runner (probe-report.mjs)'
  const s = spawned.find((r) => r.pid === pid)
  if (s) return `runner spawn: ${JSON.stringify(s.argv)} (comm ${s.comm})`
  const e = ((readText(`${PROBE}/processes`) || '').match(new RegExp(`^(\\S+) pid=${pid} `, 'm')) || [])[1]
  if (e) return `entrypoint: ${e}`
  return 'unknown'
}

// The entrypoint's mark in the kernel log; only what follows it is this run
// (a test kernel's log also holds other runs).
const KMSG_MARK = 'wappie-a1: probe entrypoint started'

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
    // On the real kernel this is where a gap in node-worker.txt shows.
    if (/type=1326/.test(m)) {
      const f = (k) => ((m.match(new RegExp(`\\b${k}=("[^"]*"|\\S+)`)) || [])[1] || '').replace(/^"|"$/g, '') || null
      const pid = Number(f('pid'))
      seccomp.push({ ts_s: recs[i].ts_us / 1e6, pid, comm: f('comm'), sig: f('sig'), syscall: Number(f('syscall')), code: f('code'), source: whoIs(pid) })
      continue
    }
    if (/out of memory|Killed process|oom-kill|oom_reaper|Memory cgroup/i.test(m)) {
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
    sigill: sigill.slice(0, 60),
    node_sigill_count: nodeSigills.length,
    // true when every node SIGILL sits on OpenSSL's SVE probe (handled by
    // OpenSSL, so harmless); false points at something else executing SVE.
    // Workers run with OPENSSL_armcap=0, so theirs should be none.
    all_node_sigills_are_openssl_sve_probe: nodeSigills.length > 0 && nodeSigills.every((e) => e.openssl_sve_probe),
    // The escape tests' denials are jailtest's; a kill of a worker (node) is a
    // gap in node-worker.txt on this kernel, and must be none.
    seccomp_kills_by_comm: seccomp.reduce((by, e) => ({ ...by, [e.comm]: (by[e.comm] ?? 0) + 1 }), {}),
    worker_seccomp_kills: seccomp.filter((e) => e.comm !== 'jailtest'),
    seccomp_kills: seccomp.slice(0, 60),
    oom: oom.slice(0, 60),
    other: other.slice(0, 40),
  }
}

// --- the facts for A1's decision: stay on the blob kernel or build our own ---
function a1Kernel(ctx) {
  const unj = ctx.unjailed || {}
  const files = (ctx.cgroup && ctx.cgroup.media_files_present) || {}
  const sc = (ctx.selfCheck && ctx.selfCheck.report) || {}
  const mounts = (ctx.cgroup && ctx.cgroup.hidepid) || []
  const supported = (t) => (unj[t] ? unj[t].meaning === 'supported' : null)
  const feature = (name, since, present, onMissing) => ({ feature: name, since, present, on_missing: onMissing })
  const hw = (ctx.meta && ctx.meta.hwcaps) || {}
  const list = [
    feature('cgroup2 cpuset', '5.0', files['cpuset.cpus'] ?? null, 'sched_setaffinity in the child; sched_setaffinity is never allowlisted'),
    feature('cgroup.kill', '5.14', files['cgroup.kill'] ?? null, "SIGKILL of the job's PID-namespace init (kills the namespace)"),
    feature('memory.oom.group', '4.19', files['memory.oom.group'] ?? null, 'media-jail kills the namespace on the first oom_kill'),
    feature('memory.peak', '5.19', files['memory.peak'] ?? null, 'memory.current sampled every 50 ms + the worker ru_maxrss'),
    feature('hidepid on /proc', '3.3 (as 2; "invisible" is its 5.8 name)', mounts.length ? mounts.some((l) => /hidepid=(2|invisible)/.test(l)) : null, 'none needed: hidepid=2 works on 4.14; jobs mount their own /proc anyway'),
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
    kill_methods_used: ctx.jail ? ctx.jail.kill_methods : null,
  }
}

async function main() {
  emit('begin', { schema: 'wappie-media-a1-probe/v1', pid: process.pid })
  const ctx = {}
  ctx.meta = await section('meta', meta)
  await section('kernel_config', kernelConfig)
  ctx.cgroup = await section('cgroup', cgroupReport)
  ctx.selfCheck = await section('media_jail_self_check', selfCheck)
  ctx.unjailed = await section('kernel_unjailed', kernelUnjailed)
  // Early, while the parent's sender still retries its connect.
  await section('vsock', vsock)
  ctx.jail = await section('jail_check', jailCheck)
  ctx.e2e = await section('media_e2e', mediaE2e)
  ctx.bench = await section('reader_bench', readerBench)
  const kernel = await section('kernel_log', kernelLog)
  await section('a1_kernel', () => a1Kernel(ctx))
  const go = {
    jail_check: ctx.jail?.go === true,
    media_e2e: ctx.e2e?.go === true,
    reader_bench: ctx.bench?.go === true,
    // The 32 MiB documents run only in the stand-in; a worker killed there shows only here.
    no_worker_seccomp_kills: Array.isArray(kernel?.worker_seccomp_kills) && kernel.worker_seccomp_kills.length === 0,
  }
  emit('done', { records: seq + 1, fatal_errors: fatal, spawned: spawned.length, go: Object.values(go).every(Boolean), parts: go })
}

main().then(
  () => process.exit(fatal ? 1 : 0),
  (e) => {
    emit('fatal', { kind: 'main', error: errText(e) })
    process.exit(1)
  },
)
