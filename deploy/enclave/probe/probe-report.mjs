// The A0 probe runner. It runs INSIDE the probe enclave at boot (started by
// entrypoint-probe.sh) and prints ONE JSON report to the enclave console,
// bracketed by markers so probe.sh can extract it. It answers the §4 JAIL
// go/no-go and §16 open points with raw evidence: kernel config, the cgroup
// layout and whether the v1→v2 switch worked, /dev/nsm, media-jail --self-check,
// a jailed test per escape, the memory headroom for the A1 sharp + pdfjs stack
// on a generated 12 MP JPEG and 50-page PDF, and vsock throughput.
//
// It never fails hard: every section is wrapped so one failure still yields a
// report with that section's error, because a report is the whole point.
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
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

// Parse media-jail's one-line status JSON off the tail of its stderr.
function mjStatus(stderr) {
  const lines = (stderr || '').trim().split('\n').filter(Boolean)
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const v = JSON.parse(lines[i])
      if (v && v.tool === 'media-jail') return v
    } catch {
      /* not the status line */
    }
  }
  return null
}

// Run a program in the jail, sampling MemAvailable while it runs. Async so the
// sampler fires (spawnSync would block the event loop).
function jail(opts) {
  const { program, argv = [], slot = 'light', memMb, pids = 128, cpus = '0', wallS, id, env = {} } = opts
  const args = [
    '--profile', 'node-worker', '--slot', slot, '--mem-mb', String(memMb),
    '--pids', String(pids), '--cpus', cpus, '--wall-s', String(wallS), '--id', id,
    '--', program, ...argv,
  ]
  return new Promise((resolve) => {
    const child = spawn(MEDIA_JAIL, args, { env: { ...process.env, ...env } })
    let stdout = ''
    let stderr = ''
    let minAvail = Infinity
    child.stdout.on('data', (d) => (stdout += d))
    child.stderr.on('data', (d) => (stderr += d))
    const sampler = setInterval(() => {
      const mi = meminfo(readText('/proc/meminfo'))
      if (mi && mi.MemAvailable_kb < minAvail) minAvail = mi.MemAvailable_kb
    }, 100)
    child.on('close', (code, signal) => {
      clearInterval(sampler)
      resolve({
        code,
        signal,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        status: mjStatus(stderr),
        min_mem_avail_kb: Number.isFinite(minAvail) ? minAvail : null,
      })
    })
    child.on('error', (e) => {
      clearInterval(sampler)
      resolve({ code: null, signal: null, stdout: '', stderr: String(e), status: null, min_mem_avail_kb: null })
    })
  })
}

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

// --- kernel config from /proc/config.gz ---
function kernelConfig() {
  const KEYS = [
    'CONFIG_IO_URING', 'CONFIG_USER_NS', 'CONFIG_SECCOMP_FILTER', 'CONFIG_CGROUPS',
    'CONFIG_MEMCG', 'CONFIG_CGROUP_PIDS', 'CONFIG_CPUSETS', 'CONFIG_PID_NS',
    'CONFIG_NET_NS', 'CONFIG_USERFAULTFD',
  ]
  if (!existsSync('/proc/config.gz')) {
    return { source: null, note: '/proc/config.gz absent (CONFIG_IKCONFIG_PROC off)' }
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
  return {
    boot_cgroup_mountinfo: cgroupLines,
    boot_cgroups: readText('/proc/cgroups'),
    setup_log: setup.split('\n').filter(Boolean),
    run_cg2_media_controllers: controllers,
    v1_unmounted_v2_mounted_ok: v2Ok,
  }
}

// --- the jailed escape tests ---
function classify(name, res, expect) {
  const st = res.status || {}
  const outcome = st.outcome
  const sig = st.term_signal
  const resultLine = (res.stdout.match(/^RESULT .*/m) || [])[0] || null
  let verdict
  // Denied patterns first: NOT-VISIBLE contains "VISIBLE", so it must be
  // matched before the survived patterns.
  if (resultLine && /\b(DENIED|NOT-VISIBLE)\b/.test(resultLine)) verdict = 'denied-errno'
  else if (resultLine && /\b(OPENED|SURVIVED|VISIBLE)\b/.test(resultLine)) verdict = 'survived'
  else if (outcome === 'signaled' && sig === 31) verdict = 'denied-seccomp'
  else if (outcome === 'oom') verdict = 'killed-memcg'
  else if (outcome === 'timeout') verdict = 'killed-wall'
  else verdict = `other(${outcome},sig=${sig})`
  return {
    test: name,
    expected: expect,
    verdict,
    pass: expect.includes(verdict),
    result_line: resultLine,
    outcome,
    term_signal: sig,
    exit_code: res.code,
  }
}

async function jailTests() {
  const jt = `${BIN}/jailtest`
  const base = { program: jt, slot: 'light', memMb: 128, pids: 64, cpus: '0', wallS: 3 }
  const tests = []

  const run1 = async (name, argv, expect, wallS = 3, memMb = 128) =>
    classify(name, await jail({ ...base, argv, id: `t-${name}`, wallS, memMb }), expect)

  tests.push(await run1('nsm', ['nsm'], ['denied-errno']))
  tests.push(await run1('socket-vsock', ['socket-vsock'], ['denied-seccomp']))
  tests.push(await run1('socket-inet', ['socket-inet'], ['denied-seccomp']))
  tests.push(await run1('socket-unix', ['socket-unix'], ['survived'])) // AF_UNIX is allowed on purpose
  tests.push(await run1('io-uring', ['io-uring'], ['denied-errno', 'denied-seccomp']))
  tests.push(await run1('userfaultfd', ['userfaultfd'], ['denied-seccomp']))
  tests.push(await run1('unshare-userns', ['unshare-userns'], ['denied-seccomp']))
  tests.push(await run1('memhog', ['memhog', '512'], ['killed-memcg'], 30, 64))

  // proc-peek needs a live concurrent job to look at. Start a spinner, read its
  // host pid from the leaf's cgroup.procs, then peek it from another jail.
  const victimId = 'victim'
  const victim = jail({ program: jt, argv: ['spin'], slot: 'heavy', memMb: 64, pids: 64, cpus: '0', wallS: 20, id: victimId })
  await new Promise((r) => setTimeout(r, 800))
  const procs = readText(`/run/cg2/media/heavy-${victimId}/cgroup.procs`)
  const victimPid = (procs || '').trim().split('\n')[0] || '99999'
  tests.push(await run1('proc-peek', ['proc-peek', victimPid], ['denied-errno']))
  // kill the victim's cgroup and reap
  try {
    spawnSync('sh', ['-c', `echo 1 > /run/cg2/media/heavy-${victimId}/cgroup.kill`])
  } catch {
    /* best effort */
  }
  await victim

  // The wall timeout is exercised by spin under a short wall.
  const spinRes = await jail({ program: jt, argv: ['spin'], slot: 'light', memMb: 128, pids: 64, cpus: '0', wallS: 2, id: 't-wall' })
  tests.push(classify('wall-timeout', spinRes, ['killed-wall']))

  return { tests, go: tests.every((t) => t.pass), victim_host_pid: victimPid }
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
  // OOM — the point is to read the true peak.
  const image = await jail({
    program: NODE,
    argv: [`${WORKER}/image-probe.mjs`, `${CORPUS}/image.jpg`],
    slot: 'light', memMb: 768, pids: 256, cpus: '0', wallS: 30, id: 'img',
    env: { VIPS_BLOCK_UNTRUSTED: '1', VIPS_CONCURRENCY: '1' },
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
    wall_ms: res.status ? res.status.wall_ms : null,
    min_mem_avail_kb: res.min_mem_avail_kb,
    outcome: res.status ? res.status.outcome : null,
    exit_code: res.code,
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
