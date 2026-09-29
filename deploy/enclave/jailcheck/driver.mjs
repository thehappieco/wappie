// Stands in for a worker during the escape tests (jail-check.mjs): reads the
// jailtest sub-command and its arguments as a JSON array on stdin and execs
// /opt/media/bin/jailtest with them, so the test binary runs exactly where a
// worker would, as PID 1 of the job, under the worker's table row, uid,
// namespaces and seccomp filter.
// ["v8-heap"] instead fills the V8 heap past the row's --max-old-space-size,
// so V8 aborts (jail-check.mjs says how that ends).
import { readFileSync } from 'node:fs'

const args = JSON.parse(readFileSync(0, 'utf8'))
if (args[0] === 'v8-heap') {
  process.stdout.write('START v8-heap\n')
  const hold = []
  for (;;) hold.push(new Array(1 << 16).fill(hold.length))
}
process.execve('/opt/media/bin/jailtest', ['jailtest', ...args], {})
