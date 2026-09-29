// A stand-in for media-jail (docs/mcp-enclave.md §16.6) on a machine without
// cgroup v2 or namespaces: the same command line, table, exit codes and
// signal handling, and no isolation at all. It runs fake-worker.mjs with
// media-jail's own stdin and stdout. FAKE_WALL_MS shortens the wall;
// FAKE_SELF_CHECK (an exit code) and FAKE_TABLE ('mismatch', 'extra',
// 'garbage') change what the boot check sees.
import { spawn } from 'node:child_process'
import { constants } from 'node:os'
import { fileURLToPath } from 'node:url'

const TABLE = {
  image: { mem_mb: 256, wall_s: 10, pids: 64, tmp_mb: 16, flags: ['--max-old-space-size=128', '--disallow-code-generation-from-strings'] },
  pdf: { mem_mb: 384, wall_s: 20, pids: 64, tmp_mb: 16, flags: ['--max-old-space-size=256', '--disallow-code-generation-from-strings'] },
  office: { mem_mb: 384, wall_s: 15, pids: 64, tmp_mb: 16, flags: ['--max-old-space-size=256', '--disallow-code-generation-from-strings', '--no-addons'] },
}
const args = process.argv.slice(2)
if (args[0] === '--self-check' && args.length === 1) {
  process.stdout.write('{"kernel":"fake"}\n')
  process.exit(Number(process.env.FAKE_SELF_CHECK ?? 0))
}
if (args[0] === '--table' && args.length === 1) {
  const workers = Object.fromEntries(Object.entries(TABLE).map(([id, row]) => [id, {
    argv: ['/usr/local/bin/node', ...row.flags, `/opt/media/worker/${id}.mjs`], profile: 'node-worker',
    max: { mem_mb: row.mem_mb, wall_s: row.wall_s, pids: row.pids, tmp_mb: row.tmp_mb },
  }]))
  if (process.env.FAKE_TABLE === 'mismatch') workers.pdf.max.mem_mb = 512
  if (process.env.FAKE_TABLE === 'extra') workers.audio = workers.image
  process.stdout.write(process.env.FAKE_TABLE === 'garbage' ? 'not json' : JSON.stringify({ workers }))
  process.exit(0)
}
// --worker <id> --slot light --id <16 hex> --mem-mb N --pids N --cpus LIST --wall-s N --tmp-mb N, nothing else, each once.
const flags = new Map()
for (let index = 0; index < args.length; index += 2) {
  if (!args[index].startsWith('--') || flags.has(args[index]) || args[index + 1] === undefined) process.exit(3)
  flags.set(args[index], args[index + 1])
}
const names = ['--worker', '--slot', '--id', '--mem-mb', '--pids', '--cpus', '--wall-s', '--tmp-mb']
const row = TABLE[flags.get('--worker')]
const within = (flag, max) => /^[1-9]\d{0,6}$/.test(flags.get(flag)) && Number(flags.get(flag)) <= max
if (flags.size !== names.length || names.some(name => !flags.has(name)) || !row || flags.get('--slot') !== 'light' || !/^[0-9a-f]{16}$/.test(flags.get('--id')) ||
  !within('--mem-mb', row.mem_mb) || !within('--pids', row.pids) || !within('--wall-s', row.wall_s) || !within('--tmp-mb', row.tmp_mb) || !/^\d+(?:[-,]\d+)*$/.test(flags.get('--cpus'))) process.exit(3)

const child = spawn(process.execPath, [fileURLToPath(new URL('./fake-worker.mjs', import.meta.url)), flags.get('--worker')], { stdio: ['inherit', 'inherit', 'ignore'] })
let forced = null
const stop = code => { if (forced === null) { forced = code; child.kill('SIGKILL') } }
const wall = setTimeout(() => stop(124), Number(process.env.FAKE_WALL_MS || Number(flags.get('--wall-s')) * 1000))
for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.on(signal, () => stop(143))
child.on('exit', (code, signal) => {
  clearTimeout(wall)
  process.exit(forced ?? (code ?? 128 + constants.signals[signal]))
})
