// The syscalls the workers make inside the jail, for reviewing
// media-jail/profiles/node-worker.txt (docs/mcp-enclave.md §16.6): every
// corpus file runs through media-jail under `strace -ff`, and only what the
// job's processes do after the exec of node counts (media-jail's own setup
// and its child's before the exec are not the worker's). Run by
// deploy/enclave/jailcheck/trace-profile.sh; prints JSON:
//   { used: [...], allowed_unused: [...], used_not_listed: [...] }
// `used_not_listed` can only hold the calls seccomp.rs owns (socket, clone,
// ioctl, prctl, execve, the io_uring and clone3 shims): anything else would
// have been a seccomp kill.

import { spawnSync } from 'node:child_process'
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { stdinOf } from '/opt/media/worker/test/harness.mjs'
import { corpus } from '/opt/media/worker/test/corpus.mjs'

const table = JSON.parse(spawnSync('/usr/local/bin/media-jail', ['--table']).stdout).workers
const profile = readFileSync('/opt/jailcheck/node-worker.txt', 'utf8')
  .split('\n')
  .map((l) => l.replace(/#.*/, '').trim())
  .filter(Boolean)

const used = new Map()
for (const c of await corpus()) {
  const dir = mkdtempSync('/tmp/trace-')
  const input = join(dir, 'stdin')
  writeFileSync(input, stdinOf(c.header, c.input))
  const max = table[c.worker].max
  spawnSync('strace', ['-ff', '-qq', '-o', join(dir, 't'), '/usr/local/bin/media-jail', '--worker', c.worker, '--slot', 'light',
    '--id', randomBytes(8).toString('hex'), '--mem-mb', `${max.mem_mb}`, '--pids', `${max.pids}`, '--cpus', '0',
    '--wall-s', `${max.wall_s}`, '--tmp-mb', `${max.tmp_mb}`], { input: readFileSync(input), env: {}, maxBuffer: 1 << 28 })
  const files = readdirSync(dir).filter((f) => f.startsWith('t.'))
  const traces = files.map((f) => ({ pid: Number(f.slice(2)), lines: readFileSync(join(dir, f), 'utf8').split('\n') }))
  // The job's first process is the one that execs node; its threads and any
  // children have higher pids. media-jail itself, the lowest, is left out.
  const job = traces.find((t) => t.lines.some((l) => l.startsWith('execve("/usr/local/bin/node"')))
  if (!job) continue
  for (const t of traces) {
    if (t.pid < job.pid) continue
    let after = t !== job
    for (const line of t.lines) {
      if (!after) {
        after = line.startsWith('execve("/usr/local/bin/node"')
        if (!after) continue
      }
      const name = /^([a-z0-9_]+)\(/.exec(line)?.[1]
      if (name) used.set(name, (used.get(name) ?? new Set()).add(c.name))
    }
  }
}

const names = [...used.keys()].sort()
console.log(
  JSON.stringify(
    {
      used: names,
      allowed_unused: profile.filter((p) => !used.has(p)),
      used_not_listed: names.filter((n) => !profile.includes(n)).map((n) => ({ name: n, by: [...used.get(n)].slice(0, 5) })),
    },
    null,
    2,
  ),
)
