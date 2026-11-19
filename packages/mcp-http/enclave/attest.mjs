// Attestation documents come from the NSM (/dev/nsm) through the small Rust
// helper baked into the image (deploy/enclave/nsm-attest), whose contract is
//   nsm-attest <public_key_hex|-> <nonce_hex|-> <user_data_hex|->
//   0 document on stdout, 1 NSM error, 2 no /dev/nsm, 3 bad arguments.
// A document is never cached: every KMS call, every prepare and every
// /attestation request gets a fresh one.
//
// From reader 0.6.1 at most ATTEST_IN_FLIGHT helpers run at once in the whole
// process, and at most ATTEST_QUEUE requests wait for one; past that a
// request fails with attest_busy at once. The public /attestation route runs
// one for anyone on the internet, and nsm-timefeed, which keeps the clock,
// shares the same NSM and the single vCPU. Each run is also timed on both
// clocks, so the document's NSM timestamp can cross-check our clock
// (clock.mjs nsmRange, the nsm_node_proof).
import { execFile } from 'node:child_process'
import { decodeAttestationDocument } from '../attestation.mjs'
import { NSM_ATTEST } from './constants.mjs'

const MAX_DOCUMENT = 64 * 1024
// Field limits from aws-nitro-enclaves-nsm-api attestation_process.md (the
// CDDL allows 1024 for nonce and user_data; 512 is the stricter reading).
const LIMITS = { publicKey: 1024, nonce: 512, userData: 512 }
export const ATTEST_IN_FLIGHT = 2
export const ATTEST_QUEUE = 16

// nsm-attest takes hex, or '-' for a field that is not set.
function hexArg(value, max) {
  if (value === undefined || value === null) return '-'
  if (!(value instanceof Uint8Array) || value.length < 1 || value.length > max) throw new Error('attest_bad_input')
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('hex')
}

const EXIT_CODES = { 1: 'attest_nsm_error', 2: 'attest_no_nsm', 3: 'attest_bad_input' }

function failure(error) {
  if (error.code === 'ENOENT') return 'attest_unavailable'
  if (error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') return 'attest_too_large'
  if (error.killed) return 'attest_timeout'
  return EXIT_CODES[error.code] ?? 'attest_failed'
}

/**
 * A process-wide cap: `run(fn)` runs `fn` once fewer than `inFlight` runs
 * are going, in arrival order, and throws attest_busy when `queue` already
 * wait. `counts()` is {running, waiting}.
 */
export function createAttestLimit({ inFlight = ATTEST_IN_FLIGHT, queue = ATTEST_QUEUE } = {}) {
  let running = 0
  const waiting = []
  return {
    async run(fn) {
      if (running < inFlight) running++
      else {
        if (waiting.length >= queue) throw new Error('attest_busy')
        await new Promise(resolve => waiting.push(resolve)) // the finishing run hands its slot over
      }
      try { return await fn() } finally {
        const next = waiting.shift()
        if (next) next()
        else running--
      }
    },
    counts: () => ({ running, waiting: waiting.length }),
  }
}

const shared = createAttestLimit()

/**
 * Resolves to the raw COSE_Sign1 document (a Buffer) with `publicKey`,
 * `nonce` and `userData` embedded when given (null or undefined leaves a field
 * out). The KMS recipient passes its RSA SPKI; a consent request passes its
 * raw 32-byte X25519 key. `onSample({sent, received, sentMono, receivedMono,
 * timestamp})` receives the helper's run bracketed by Date.now() and
 * performance.now() (not counting the wait for a slot) and the document's
 * NSM timestamp; a document whose timestamp cannot be read gives none.
 * `bin`, `timeoutMs` and `limit` are only overridden by tests.
 */
export async function attest({ publicKey, nonce, userData } = {}, { bin = NSM_ATTEST, timeoutMs = 5000, limit = shared, onSample } = {}) {
  const args = [hexArg(publicKey, LIMITS.publicKey), hexArg(nonce, LIMITS.nonce), hexArg(userData, LIMITS.userData)]
  return limit.run(() => new Promise((resolve, reject) => {
    const sent = Date.now(), sentMono = performance.now()
    // Empty environment: the helper needs nothing from ours.
    execFile(bin, args, { encoding: 'buffer', maxBuffer: MAX_DOCUMENT, timeout: timeoutMs, env: {} }, (error, stdout) => {
      const received = Date.now(), receivedMono = performance.now()
      if (error) return reject(new Error(failure(error)))
      if (!stdout.length) return reject(new Error('attest_failed'))
      if (onSample) {
        try {
          const { timestamp } = decodeAttestationDocument(stdout)
          if (Number.isSafeInteger(timestamp)) onSample({ sent, received, sentMono, receivedMono, timestamp })
        } catch { /* the caller checks the document itself */ }
      }
      resolve(stdout)
    })
  }))
}
