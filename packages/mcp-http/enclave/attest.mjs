// Attestation documents come from the NSM (/dev/nsm) through the small Rust
// helper baked into the image (deploy/enclave/nsm-attest), whose contract is
//   nsm-attest <public_key_hex|-> <nonce_hex|-> <user_data_hex|->
//   0 document on stdout, 1 NSM error, 2 no /dev/nsm, 3 bad arguments.
// A document is never cached: every KMS call, every prepare and every
// /attestation request gets a fresh one.
import { execFile } from 'node:child_process'
import { NSM_ATTEST } from './constants.mjs'

const MAX_DOCUMENT = 64 * 1024
// Field limits from aws-nitro-enclaves-nsm-api attestation_process.md (the
// CDDL allows 1024 for nonce and user_data; 512 is the stricter reading).
const LIMITS = { publicKey: 1024, nonce: 512, userData: 512 }

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
 * Resolves to the raw COSE_Sign1 document (a Buffer) with `publicKey`,
 * `nonce` and `userData` embedded when given (null or undefined leaves a field
 * out). The KMS recipient passes its RSA SPKI; a consent request passes its
 * raw 32-byte X25519 key. `bin` and `timeoutMs` are only overridden by tests.
 */
export async function attest({ publicKey, nonce, userData } = {}, { bin = NSM_ATTEST, timeoutMs = 5000 } = {}) {
  const args = [hexArg(publicKey, LIMITS.publicKey), hexArg(nonce, LIMITS.nonce), hexArg(userData, LIMITS.userData)]
  return new Promise((resolve, reject) => {
    // Empty environment: the helper needs nothing from ours.
    execFile(bin, args, { encoding: 'buffer', maxBuffer: MAX_DOCUMENT, timeout: timeoutMs, env: {} }, (error, stdout) => {
      if (error) return reject(new Error(failure(error)))
      if (!stdout.length) return reject(new Error('attest_failed'))
      resolve(stdout)
    })
  })
}
