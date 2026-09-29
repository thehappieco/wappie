// The reader's side of media-jail (docs/mcp-enclave.md §16.6 and §16.11):
// the boot check that decides whether attachments open at all this boot, and
// runWorker, which runs one job and reads its stdout as untrusted.
//
// The reader never touches cgroupfs: media-jail keeps itself out of the job's
// leaf and holds the wall timeout. What the reader does is send SIGTERM to
// media-jail (a wipe, a kind switched off, invalid output, its own watchdog)
// and SIGKILL if it is still there JAIL_TERM_GRACE_MS later; the job's
// PR_SET_PDEATHSIG then ends the worker. Nothing of a job's stderr, nor of
// media-jail's own status line, is read: no per-job number leaves the process.
import { spawn as spawnProcess } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { readFile as readFileAsync } from 'node:fs/promises'
import { constants as os } from 'node:os'
import { JAIL_BIN, JAIL_CPUS, JAIL_SLOT, JAIL_TERM_GRACE_MS, JAIL_WATCHDOG_MS, STDIN_HEADER_MAX, WORKERS } from './policy.mjs'
import { createOutputReader, OutputError } from './validate-output.mjs'

export const CONTROLLERS_FILE = '/run/cg2/media/cgroup.subtree_control'
export const BOOT_CHECK_MS = 5_000
const TABLE_MAX_BYTES = 65_536

/** Runs `bin args`, collecting at most `max` bytes of stdout; resolves {code, stdout} or null past `ms`. */
function run(spawn, args, { ms = BOOT_CHECK_MS, max = TABLE_MAX_BYTES } = {}) {
  return new Promise(resolve => {
    let child
    try { child = spawn(JAIL_BIN, args, { stdio: ['ignore', 'pipe', 'ignore'], env: {} }) } catch { resolve(null); return }
    const chunks = []
    let size = 0, settled = false
    const finish = value => { if (!settled) { settled = true; clearTimeout(timer); resolve(value) } }
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish(null) }, ms)
    child.stdout?.on('data', chunk => { size += chunk.length; if (size > max) { child.kill('SIGKILL'); finish(null) } else chunks.push(chunk) })
    child.once('error', () => finish(null))
    child.once('close', code => finish({ code, stdout: Buffer.concat(chunks) }))
  })
}

/** Whether `--table`'s JSON names exactly WORKERS, each with `max` equal to its entry. */
function tableMatches(stdout) {
  let table
  try { table = JSON.parse(stdout.toString('utf8')) } catch { return false }
  const workers = table?.workers
  if (!workers || typeof workers !== 'object' || Array.isArray(workers)) return false
  const names = Object.keys(workers).sort(), expected = Object.keys(WORKERS).sort()
  if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) return false
  return expected.every(name => {
    const max = workers[name]?.max, want = WORKERS[name]
    return max && typeof max === 'object' && Object.keys(max).length === Object.keys(want).length && Object.entries(want).every(([key, value]) => max[key] === value)
  })
}

/**
 * The boot check (§16.6), in order: the media leaf delegates memory and pids
 * (cpuset is used where listed, never required); `--self-check` exits 0;
 * `--table` equals WORKERS. Any failure turns attachments off for the boot.
 */
export async function checkJail({ spawn = spawnProcess, readFile = readFileAsync } = {}) {
  let controllers
  try { controllers = (await readFile(CONTROLLERS_FILE, 'utf8')).split(/\s+/) } catch { return { ok: false, code: 'no_controllers' } }
  if (!controllers.includes('memory') || !controllers.includes('pids')) return { ok: false, code: 'no_controllers' }
  const selfCheck = await run(spawn, ['--self-check'])
  if (selfCheck?.code !== 0) return { ok: false, code: 'self_check_failed' }
  const table = await run(spawn, ['--table'])
  if (table?.code !== 0 || !tableMatches(table.stdout)) return { ok: false, code: 'table_mismatch' }
  return { ok: true, cpuset: controllers.includes('cpuset') }
}

/** media-jail's command line for one job of `worker` (§16.11 "Spawn"). */
export function jailArgs(worker, id = randomBytes(8).toString('hex')) {
  const max = WORKERS[worker]
  return ['--worker', worker, '--slot', JAIL_SLOT, '--id', id, '--mem-mb', String(max.mem_mb), '--pids', String(max.pids),
    '--cpus', JAIL_CPUS, '--wall-s', String(max.wall_s), '--tmp-mb', String(max.tmp_mb)]
}

/** The stdin of a job: `u32 H ‖ header ‖ u32 N ‖ input`. */
export function jobHeader(job) {
  const header = Buffer.from(JSON.stringify(job))
  if (header.length < 2 || header.length > STDIN_HEADER_MAX) throw new Error('job header out of bounds')
  const prefix = Buffer.alloc(4)
  prefix.writeUInt32BE(header.length)
  return Buffer.concat([prefix, header])
}

const signalCode = signal => (signal && os.signals[signal] ? 128 + os.signals[signal] : 255)

/**
 * Runs one job under media-jail. `input` is a Buffer the caller zeroes
 * afterwards. Resolves a WorkerOutput whatever happened; `killed` says why
 * the reader ended it: 'bad_output' (§16.11's checks; the output is then
 * discarded), 'watchdog' (wall_s + JAIL_WATCHDOG_MS) or 'aborted' (`signal`).
 */
export function runWorker({ worker, job, input, signal, spawn = spawnProcess }) {
  const max = WORKERS[worker]
  if (!max) throw new Error('unknown worker')
  const reader = createOutputReader({ worker, job })
  return new Promise(resolve => {
    let child
    const empty = { exit: 3, header: null, sections: [], images: [], cut: false, error: null }
    try { child = spawn(JAIL_BIN, jailArgs(worker), { stdio: ['pipe', 'pipe', 'ignore'], env: {} }) } catch { resolve({ ...empty, killed: null }); return }
    let killed = null, broken = false, graceTimer = null
    const kill = reason => {
      if (killed || child.exitCode !== null || child.signalCode !== null) return
      killed = reason
      child.kill('SIGTERM')
      graceTimer = setTimeout(() => child.kill('SIGKILL'), JAIL_TERM_GRACE_MS)
    }
    const watchdog = setTimeout(() => kill('watchdog'), max.wall_s * 1000 + JAIL_WATCHDOG_MS)
    const onAbort = () => kill('aborted')
    if (signal?.aborted) queueMicrotask(onAbort)
    else signal?.addEventListener('abort', onAbort, { once: true })
    child.stdout.on('data', chunk => {
      if (broken) return
      try { reader.push(chunk) } catch (error) {
        if (!(error instanceof OutputError)) throw error
        broken = true
        kill('bad_output')
      }
    })
    child.once('error', () => {})
    child.once('close', (code, signalName) => {
      clearTimeout(watchdog)
      clearTimeout(graceTimer)
      signal?.removeEventListener('abort', onAbort)
      const exit = code ?? signalCode(signalName)
      // A wipe outranks what the job was doing when it came.
      if (killed === 'aborted' || (killed && !broken)) { resolve({ ...empty, exit, killed }); return }
      if (broken) { resolve({ ...empty, exit, killed: 'bad_output' }); return }
      // The last rule applies only to a job that ended by itself: any other
      // exit code is media-jail's word on what happened (§16.6).
      if (exit !== 0 && exit !== 2) { resolve({ ...empty, exit, killed: null }); return }
      try { resolve({ exit, ...reader.finish(exit), killed: null }) } catch (error) {
        if (!(error instanceof OutputError)) throw error
        resolve({ ...empty, exit, killed: 'bad_output' })
      }
    })
    // A worker that exits before reading everything closes the pipe: that is its answer, not an error here.
    child.stdin.on('error', () => {})
    const length = Buffer.alloc(4)
    length.writeUInt32BE(input.length)
    child.stdin.write(jobHeader(job))
    child.stdin.write(length)
    child.stdin.end(input)
  })
}

/**
 * What a job's end means for the call (§16.11 "Exit and outcome"): `{output}`
 * or `{code, facts?, log}`, where `log` is the `media_job_killed` code or null.
 * `reason` is why an 'aborted' job was ended: 'revoked' or 'media_off'.
 */
export function outcomeOf(output, reason = 'revoked') {
  if (output.killed === 'bad_output') return { code: 'parser_failed', log: 'bad_output' }
  if (output.killed === 'watchdog') return { code: 'parser_failed', log: 'watchdog' }
  if (output.killed === 'aborted') return { code: 'media_not_allowed', log: reason }
  if (output.exit === 0) return { output }
  if (output.exit === 2) {
    const code = output.error.code
    if (code === 'too_large') return { code: 'attachment_too_large', facts: { what: output.error.what }, log: null }
    if (code === 'bad_input') return { code: 'parser_failed', log: 'parser_exit' }
    return { code: { unsupported: 'attachment_unsupported', encrypted: 'attachment_encrypted', kind_off: 'media_not_allowed', damaged: 'parser_failed' }[code], log: null }
  }
  if (output.exit === 124) return { code: 'parser_failed', log: 'wall' }
  if (output.exit === 137) return { code: 'parser_failed', log: 'oom' }
  if ([3, 125, 127].includes(output.exit)) return { code: 'parser_failed', log: 'jail_error' }
  return { code: 'parser_failed', log: 'parser_exit' }
}
