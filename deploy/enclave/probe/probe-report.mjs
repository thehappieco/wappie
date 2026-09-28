// The A0 probe runner. It runs INSIDE the probe enclave at boot (started by
// entrypoint-probe.sh) and prints ONE JSON report to the enclave console,
// bracketed by markers so probe.sh can extract it. It answers the §4 JAIL
// go/no-go and §16 open points with raw evidence: kernel config, the cgroup
// layout and whether the v1→v2 switch worked, /dev/nsm, media-jail --self-check,
// a jailed test per escape, the memory headroom for the A1 sharp + pdfjs stack
// on a generated 12 MP JPEG and 50-page PDF, and vsock throughput.
//
// It never fails hard: every section is wrapped so one failure still yields a
// report with that section's error, because a report is the whole point. Each
// run costs a production outage, so every record also carries what it needs to
// explain its own failure (media-jail's diagnostics, the kill path, hangs).
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { gunzipSync } from 'node:zlib'

const BEGIN = '===WAPPIE-A0-PROBE-BEGIN==='
const END = '===WAPPIE-A0-PROBE-END==='

const MEDIA_JAIL = '/usr/local/bin/media-jail'
const NODE = process.execPath
const BIN = '/opt/probe/bin'
const WORKER = '/opt/probe/worker'
const CORPUS = '/opt/probe/corpus'
const VSOCK_PORT = 9100 // outside production's 5443-5445/7000-7002/8000-8002/9000
const PROBE = '/run/probe'
const CG_MEDIA = '/run/cg2/media'

const ENOENT = 2
const ENOSYS = 38

const readText = (p) => {
  try {
    return readFileSync(p, 'utf8')
  } catch {
    return null
  }
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
// parent or the child (pivot_root, a cgroup file write, the /proc mount) is the
// first thing to read when a test fails on the real kernel. The last 2 KiB.
function stderrTail(stderr) {
  const text = (stderr || '')
    .split('\n')
    .filter((l) => l.trim() && !statusLine(l))
    .join('\n')
  return text.length > 2048 ? text.slice(-2048) : text
}

// Run a program in the jail, sampling MemAvailable while it runs. Async so the
// sampler fires (spawnSync would block the event loop). A watchdog fires 10 s
// after the job's own wall: if a kernel primitive fails and media-jail hangs,
// it kills media-jail and the leaf and records `hung`, so one bad primitive
// cannot cost the whole report.
function jail(opts) {
  const { program, argv = [], slot = 'light', memMb, pids = 128, cpus = '0', wallS, id } = opts
  const args = [
    '--profile', 'node-worker', '--slot', slot, '--mem-mb', String(memMb),
    '--pids', String(pids), '--cpus', cpus, '--wall-s', String(wallS), '--id', id,
    '--', program, ...argv,
  ]
  return new Promise((resolve) => {
    const child = spawn(MEDIA_JAIL, args)
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
      resolve({
        code,
        signal,
        stdout: stdout.trim(),
        status: mjStatus(stderr),
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
      try {
        writeFileSync(`${CG_MEDIA}/${slot}-${id}/cgroup.kill`, '1')
      } catch {
        /* no leaf, or no cgroup.kill on this kernel */
      }
      // A surviving job may still hold the pipes open; do not wait for them.
      child.stdout.destroy()
      child.stderr.destroy()
      finish(null, 'SIGKILL', { hung: true })
    }, (wallS + 10) * 1000)
    child.on('close', (code, signal) => finish(code, signal))
    child.on('error', (e) => finish(null, null, { stderr_tail: String(e) }))
  })
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function section(fn) {
  try {
    return fn()
  } catch (e) {
    return { error: String(e && e.stack ? e.stack : e) }
  }
}

async function sectionAsync(fn) {
  try {
    return await fn()
  } catch (e) {
    return { error: String(e && e.stack ? e.stack : e) }
  }
}

// --- kernel config from /proc/config.gz (probe.sh also records the blob's
//     Image.config on the parent, for when this is absent) ---
function kernelConfig() {
  const KEYS = [
    'CONFIG_IO_URING', 'CONFIG_USER_NS', 'CONFIG_SECCOMP_FILTER', 'CONFIG_CGROUPS',
    'CONFIG_MEMCG', 'CONFIG_CGROUP_PIDS', 'CONFIG_CPUSETS', 'CONFIG_PID_NS',
    'CONFIG_NET_NS', 'CONFIG_USERFAULTFD', 'CONFIG_SWAP', 'CONFIG_MEMCG_SWAP',
    'CONFIG_SECURITY_YAMA',
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
//     the kernel; here ENOSYS means not built in (§16.14: CONFIG_IO_URING). ---
function kernelUnjailed() {
  const meaning = (line, errno) => {
    if (line && /\b(OPENED|SURVIVED)\b/.test(line)) return 'supported'
    if (errno === ENOSYS) return 'not built in (ENOSYS)'
    return errno == null ? 'unknown' : `refused (errno ${errno})`
  }
  const out = {}
  for (const t of ['io-uring', 'userfaultfd', 'unshare-userns']) {
    const r = spawnSync(`${BIN}/jailtest`, [t], { encoding: 'utf8', timeout: 5000 })
    const line = ((r.stdout || '').match(/^RESULT .*/m) || [])[0] || null
    const errno = line ? Number((line.match(/\berrno=(-?\d+)/) || [])[1]) : null
    out[t] = { result_line: line, meaning: meaning(line, errno), exit_code: r.status, signal: r.signal }
  }
  const sysctl = {}
  for (const p of [
    '/proc/sys/kernel/io_uring_disabled',
    '/proc/sys/vm/unprivileged_userfaultfd',
    '/proc/sys/user/max_user_namespaces',
    '/proc/sys/kernel/seccomp/actions_avail',
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
  const cgroupLines = bootMountinfo
    .split('\n')
    .filter((l) => l.includes('cgroup') )
  const setup = readText(`${PROBE}/cgroup-setup`) || ''
  const mediaCtl = (readText('/run/cg2/media/cgroup.subtree_control') || '').trim()
  const controllers = mediaCtl ? mediaCtl.split(/\s+/) : []
  const need = ['memory', 'pids', 'cpuset']
  const v2Ok = need.every((c) => controllers.includes(c))
  // Which interface files the media node has: cgroup.kill needs 5.14,
  // memory.peak 5.19, memory.swap.max swap accounting.
  const files = {}
  for (const f of ['cgroup.kill', 'memory.peak', 'memory.current', 'memory.swap.max', 'memory.oom.group', 'memory.events', 'pids.max', 'cpuset.cpus']) {
    files[f] = existsSync(`${CG_MEDIA}/${f}`)
  }
  return {
    boot_cgroup_mountinfo: cgroupLines,
    boot_cgroups: readText('/proc/cgroups'),
    setup_log: setup.split('\n').filter(Boolean),
    run_cg2_media_controllers: controllers,
    v1_unmounted_v2_mounted_ok: v2Ok,
    cgroup_kill_present: files['cgroup.kill'],
    media_files_present: files,
    swaps: readText('/proc/swaps'),
  }
}

// The boot mount of / (mountinfo field 5): pivot_root needs the current root to
// be a mount with a parent, so this explains a pivot_root EINVAL in a tail.
function rootMount() {
  return (readText(`${PROBE}/boot-mountinfo`) || '')
    .split('\n')
    .filter((l) => l.split(' ')[4] === '/')
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
  const detail = res.stdout.split('\n').filter((l) => l && !/^(START|RESULT) /.test(l)).slice(0, 20)
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
    hung: res.hung,
    stderr_tail: res.stderr_tail,
  }
}

async function jailTests() {
  const jt = `${BIN}/jailtest`
  const base = { program: jt, slot: 'light', memMb: 128, pids: 64, cpus: '0', wallS: 3 }
  const tests = []

  const run1 = async (name, argv, expect, { wallS = 3, memMb = 128, errno = null } = {}) =>
    classify(name, await jail({ ...base, argv, id: `t-${name}`, wallS, memMb }), expect, { started: argv[0], errno })

  tests.push(await run1('nsm', ['nsm'], ['denied-errno'], { errno: ENOENT }))
  tests.push(await run1('socket-vsock', ['socket-vsock'], ['denied-seccomp']))
  tests.push(await run1('socket-inet', ['socket-inet'], ['denied-seccomp']))
  tests.push(await run1('socket-unix', ['socket-unix'], ['survived'])) // AF_UNIX is allowed on purpose
  tests.push(await run1('connect-unix', ['connect-unix'], ['denied-seccomp']))
  tests.push(await run1('io-uring', ['io-uring'], ['denied-errno'], { errno: ENOSYS }))
  tests.push(await run1('userfaultfd', ['userfaultfd'], ['denied-seccomp']))
  tests.push(await run1('unshare-userns', ['unshare-userns'], ['denied-seccomp']))
  tests.push(await run1('clone-newns', ['clone-newns'], ['denied-seccomp']))
  tests.push(await run1('clone3', ['clone3'], ['denied-errno'], { errno: ENOSYS }))
  tests.push(await run1('paths', ['paths'], ['denied-errno'], { errno: ENOENT }))
  tests.push(await run1('memhog', ['memhog', '512'], ['killed-memcg'], { wallS: 30, memMb: 64 }))

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
    tests.push(peek)
  } else {
    tests.push({ test: 'proc-peek', expected: ['denied-errno'], verdict: 'no-victim', pass: false, victim_procs: readText(`${victimLeaf}/cgroup.procs`) })
  }

  // cgroup.kill of a running job, from outside media-jail (the main Node's
  // kill path, §16.6): the victim must die by SIGKILL well before its 20 s wall.
  let killWrite = 'ok'
  try {
    writeFileSync(`${victimLeaf}/cgroup.kill`, '1')
  } catch (e) {
    killWrite = String(e)
  }
  const vr = await victim
  const vs = vr.status || {}
  const vStarted = /^START spin$/m.test(vr.stdout)
  const vVerdict = vr.hung ? 'hung' : vs.outcome === 'signaled' ? `signaled-${vs.term_signal}` : `other(${vs.outcome},sig=${vs.term_signal})`
  tests.push({
    test: 'cgroup-kill',
    expected: ['signaled-9'],
    verdict: vVerdict,
    pass: killWrite === 'ok' && vStarted && vVerdict === 'signaled-9' && vs.wall_ms != null && vs.wall_ms < 10000,
    cgroup_kill_write: killWrite,
    started: vStarted,
    outcome: vs.outcome ?? null,
    term_signal: vs.term_signal ?? null,
    wall_ms: vs.wall_ms ?? null,
    kill_method: vs.kill_method ?? null,
    hung: vr.hung,
    stderr_tail: vr.stderr_tail,
  })

  // The wall timeout is exercised by spin under a short wall; kill_method says
  // whether cgroup.kill alone did it or media-jail fell back to the job's PID 1.
  const spinRes = await jail({ program: jt, argv: ['spin'], slot: 'light', memMb: 128, pids: 64, cpus: '0', wallS: 2, id: 't-wall' })
  tests.push(classify('wall-timeout', spinRes, ['killed-wall'], { started: 'spin' }))

  return { tests, go: tests.every((t) => t.pass) }
}

// --- memory headroom + the A1 sharp/pdfjs stack on the generated corpus ---
async function memoryAndStack(bootMem, afterNodeMem) {
  // Generate the corpus (unjailed; the runner is Node with sharp available).
  const gen = spawnSync(NODE, [`${WORKER}/gen-corpus.mjs`, CORPUS], { encoding: 'utf8', maxBuffer: 1 << 24 })
  let corpus = null
  try {
    corpus = JSON.parse(gen.stdout)
  } catch {
    corpus = { ok: false, stdout: gen.stdout, stderr: gen.stderr }
  }

  // Image job (jailed): a 12 MP decode + re-encode. Generous cap so it does not
  // OOM — the point is to read the true peak. The jail passes the worker no
  // VIPS_* variables (§16.6 step 7); image-probe.mjs sets concurrency and the
  // loader block itself.
  const image = await jail({
    program: NODE,
    argv: [`${WORKER}/image-probe.mjs`, `${CORPUS}/image.jpg`],
    slot: 'light', memMb: 768, pids: 256, cpus: '0', wallS: 30, id: 'img',
  })
  // PDF job (jailed): 50-page text extraction, proving pdf.js needs no canvas.
  const pdf = await jail({
    program: NODE,
    argv: [`${WORKER}/pdf-probe.mjs`, `${CORPUS}/doc.pdf`],
    slot: 'light', memMb: 768, pids: 256, cpus: '0', wallS: 30, id: 'pdf',
  })

  const jobMem = (res) => ({
    parsed: safeJson(res.stdout),
    peak_bytes: res.status ? res.status.memory_peak_bytes : null,
    // Sampled every 50 ms by media-jail, for a kernel without memory.peak.
    current_max_bytes: res.status ? res.status.memory_current_max_bytes : null,
    wall_ms: res.status ? res.status.wall_ms : null,
    min_mem_avail_kb: res.min_mem_avail_kb,
    outcome: res.status ? res.status.outcome : null,
    exit_code: res.code,
    hung: res.hung,
    stderr_tail: res.stderr_tail,
  })

  return {
    boot: bootMem,
    after_node: afterNodeMem,
    corpus,
    image_job: jobMem(image),
    pdf_job: jobMem(pdf),
  }
}

function safeJson(s) {
  try {
    return JSON.parse(s)
  } catch {
    return { raw: (s || '').slice(0, 500) }
  }
}

// --- vsock throughput: start the sink, the parent (probe.sh) connects and
//     streams. Wait for the sink to write its results, or time out. ---
async function vsock() {
  const outFile = `${PROBE}/vsock.json`
  const sink = spawn(`${BIN}/vsock-sink`, [String(VSOCK_PORT), outFile, '16MiB', '32MiB'], {
    stdio: ['ignore', 'ignore', 'ignore'],
  })
  // The wait is bounded; a local (non-Nitro) simulation shortens it because no
  // parent sender exists there.
  const waitMs = Number(process.env.PROBE_VSOCK_TIMEOUT_MS || 60000)
  const deadline = Date.now() + waitMs
  while (Date.now() < deadline) {
    if (existsSync(outFile)) {
      const text = readText(outFile)
      const parsed = safeJson(text)
      if (Array.isArray(parsed) && parsed.length >= 2) {
        return { port: VSOCK_PORT, transfers: parsed }
      }
    }
    await new Promise((r) => setTimeout(r, 500))
  }
  try {
    sink.kill('SIGKILL')
  } catch {
    /* best effort */
  }
  return { port: VSOCK_PORT, error: `no sender completed within ${Math.round(waitMs / 1000)}s (parent did not stream)` }
}

async function main() {
  const nodeVer = process.versions.node
  const [maj, min] = nodeVer.split('.').map(Number)
  const nodeOk = maj > 22 || (maj === 22 && min >= 13)

  const bootMem = meminfo(readText(`${PROBE}/boot-meminfo`))
  const afterNodeMem = meminfo(readText('/proc/meminfo'))

  const selfCheck = section(() => {
    const r = spawnSync(MEDIA_JAIL, ['--self-check'], { encoding: 'utf8' })
    return { exit_code: r.status, report: safeJson(r.stdout) }
  })

  const unjailed = section(kernelUnjailed)
  const jt = await sectionAsync(jailTests)
  const mem = await sectionAsync(() => memoryAndStack(bootMem, afterNodeMem))
  const vs = await sectionAsync(vsock)

  const report = {
    schema: 'wappie-media-a0-probe/v1',
    when: new Date().toISOString(),
    node: nodeVer,
    node_ok: nodeOk,
    uname: (readText(`${PROBE}/uname`) || '').trim(),
    kernel_config: section(kernelConfig),
    kernel_unjailed: unjailed,
    root_mount: section(rootMount),
    cgroup: section(cgroupReport),
    dev_nsm: (readText(`${PROBE}/dev-nsm`) || '').trim(),
    media_jail_self_check: selfCheck,
    jail: jt,
    memory: mem,
    vsock: vs,
  }

  process.stdout.write('\n' + BEGIN + '\n')
  process.stdout.write(JSON.stringify(report, null, 2) + '\n')
  process.stdout.write(END + '\n')
}

main().then(
  () => {
    // Give the console a moment to flush, then keep PID 1 alive briefly so
    // probe.sh reliably captures the tail before the enclave is terminated.
    setTimeout(() => process.exit(0), 2000)
  },
  (e) => {
    process.stdout.write('\n' + BEGIN + '\n')
    process.stdout.write(JSON.stringify({ fatal: String(e && e.stack ? e.stack : e) }) + '\n')
    process.stdout.write(END + '\n')
    setTimeout(() => process.exit(1), 2000)
  },
)
