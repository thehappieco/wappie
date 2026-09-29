// A worker that says exactly what it is told (runWorker's tests, no jail): it
// reads its whole stdin (written to STDIN_FILE when set), waits DELAY_MS,
// writes the bytes of SCRIPT_FILE to stdout and exits with EXIT.
import { readFileSync, writeFileSync } from 'node:fs'

const chunks = []
for await (const chunk of process.stdin) chunks.push(chunk)
if (process.env.STDIN_FILE) writeFileSync(process.env.STDIN_FILE, Buffer.concat(chunks))
await new Promise(resolve => setTimeout(resolve, Number(process.env.DELAY_MS || 0)))
const script = readFileSync(process.env.SCRIPT_FILE)
if (script.length) await new Promise(resolve => process.stdout.write(script, resolve))
process.exit(Number(process.env.EXIT || 0))
