// The clock probe's KMS Date sampler (deploy/enclave/clockprobe). NEVER in
// the release image.
//
// A probe enclave runs in debug mode, so its PCRs are zero and KMS refuses
// every call it makes. Node's main.mjs therefore never boots there. KMS still
// answers, and every answer, error or not, carries a Date header, so this
// does what the reader's clock does with those answers, with the reader's own
// code from the image: health.mjs clockSkew (the request, through the same
// /etc/hosts name and socat bridge to vsock 8000) and clock.mjs createClock
// and createKmsCheck (the ranges, the proofs, the boot rule and ok()).
//
//   node kms-sampler.mjs <out.jsonl> watch|ready
//
// watch: every 5 s one KMS sample and one look at state.json, written as a
// `tick` line. ready: first clock.ready() exactly as main.mjs step 2b calls
// it (a `ready` line), and exit 78 with code clock_unknown when it times out,
// as the reader's boot does; after a ready that passed, the ticks follow.
//
// Lines (JSON, one per line):
//   {kind:"tick", mono_ms, skew_ms, range:{lo,hi}|null, proven, interval,
//    agree, code, unc_ms, state, synced, nsm_skew_ms}
//   {kind:"ready", ok, ms, code?}
//   {kind:"event", name, ...fields}   (the clock's own log events)
// mono_ms is CLOCK_MONOTONIC in ms (process.hrtime), the same clock the
// runner reads, so the two can compare times; skew_ms is clockSkew's
// result (null when no Date came back); range is the KMS range for
// local - true time in ms, or null.
//
// CLOCKPROBE_APP (default /app/packages/mcp-http/enclave) is where the
// reader's modules are; CLOCKPROBE_CLOCK_URL overrides the KMS URL (local
// tests only); CLOCKPROBE_STATE the state file.
import { appendFileSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'

const [out, mode] = process.argv.slice(2)
if (!out || !['watch', 'ready'].includes(mode)) {
  process.stderr.write('usage: kms-sampler.mjs <out.jsonl> watch|ready\n')
  process.exit(3)
}

const app = process.env.CLOCKPROBE_APP ?? '/app/packages/mcp-http/enclave'
const { createClock, createKmsCheck, STATE_FILE, PROBE_EVERY_MS } = await import(pathToFileURL(`${app}/clock.mjs`).href)
const { clockSkew, CLOCK_URL } = await import(pathToFileURL(`${app}/health.mjs`).href)
const url = process.env.CLOCKPROBE_CLOCK_URL ?? CLOCK_URL
const stateFile = process.env.CLOCKPROBE_STATE ?? STATE_FILE

const monoMs = () => Number(process.hrtime.bigint() / 1_000_000n)
const write = record => {
  try { appendFileSync(out, `${JSON.stringify(record)}\n`) } catch { /* the run directory went away: nothing to do */ }
}
const log = { event: (name, fields = {}) => write({ kind: 'event', name, mono_ms: monoMs(), ...fields }) }

const kms = createKmsCheck({ log })
let lastRange = null, lastSkew = null
async function sample() {
  lastRange = null
  lastSkew = await clockSkew({ url, onRange: range => { lastRange = range; clock.onKms(range) } }).catch(() => null)
}
const clock = createClock({ readState: () => readFile(stateFile, 'utf8'), kms, probe: sample, log })

async function tick() {
  await sample()
  const s = await clock.refresh()
  const interval = kms.interval()
  write({
    kind: 'tick',
    mono_ms: monoMs(),
    skew_ms: lastSkew,
    range: lastRange ? { lo: Math.round(lastRange.lo), hi: Math.round(lastRange.hi) } : null,
    proven: kms.proven(),
    interval: interval ? { lo: Math.floor(interval.lo), hi: Math.ceil(interval.hi) } : null,
    agree: kms.agree(),
    code: clock.code(),
    unc_ms: clock.uncertainty() === null ? null : Math.ceil(clock.uncertainty()),
    state: s?.state ?? null,
    synced: s?.synced ?? null,
    nsm_skew_ms: s?.nsm_skew_ms ?? null,
  })
}

if (mode === 'ready') {
  const started = performance.now()
  try {
    await clock.ready()
    write({ kind: 'ready', ok: true, ms: Math.round(performance.now() - started) })
  } catch (error) {
    write({ kind: 'ready', ok: false, ms: Math.round(performance.now() - started), code: error?.code ?? String(error) })
    // main.mjs: boot_failed code=clock_unknown, exit 78.
    process.exit(78)
  }
}
for (;;) {
  await tick()
  await new Promise(resolve => setTimeout(resolve, PROBE_EVERY_MS))
}
