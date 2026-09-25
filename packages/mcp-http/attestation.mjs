// Attestation for a reader that runs in a Nitro Enclave (docs/mcp-enclave.md
// §6). The document itself comes from an injected `attest` (the NSM helper in
// the enclave, a stub in tests); this module decides what goes into it and
// wraps it in the object the console verifies. It never runs in the hosted
// reader: startReader only builds it when an `attest` is injected.
//
// What the document binds, and why each field is there:
// - public_key: the request's own X25519 key, the only key the console may seal to;
// - nonce: the browser's, so a document cannot be replayed into another page;
// - user_data: SHA-256 over the request, the resource, the SPKI of the TLS key
//   the assistant talks to, the hash of the KMS key policy and the version.
import { createHash } from 'node:crypto'

export const ATTEST_LABEL = 'wappie-mcp-attest/v1'
export const ATTESTATION_FORMAT = 'aws-nitro-v1'
export const MAX_DOCUMENT_BYTES = 16 * 1024
export const NONCE_MIN_BYTES = 16
export const NONCE_MAX_BYTES = 64
const hex64 = /^[0-9a-f]{64}$/
const versionShape = /^[0-9]+\.[0-9]+\.[0-9]+$/

/** A refusal with the status and code the routes answer (503 unless said otherwise). */
export class AttestationError extends Error {
  constructor(code, status = 503) { super(code); this.name = 'AttestationError'; this.code = code; this.status = status }
}

/** The six fields joined by 0x00, as UTF-8. None may contain 0x00 itself. */
export function userDataPreimage({ request_id, resource, tls_spki_sha256, policy_sha256, reader_version }) {
  const fields = [ATTEST_LABEL, request_id, resource, tls_spki_sha256, policy_sha256, reader_version]
  if (fields.some(field => typeof field !== 'string' || field.includes('\0'))) throw new AttestationError('attest_bad_input', 500)
  return Buffer.from(fields.join('\0'), 'utf8')
}

/** user_data: 32 bytes, SHA-256 of the preimage. */
export const attestationUserData = fields => createHash('sha256').update(userDataPreimage(fields)).digest()

/**
 * A browser nonce from its base64url form: canonical, 16 to 64 bytes decoded,
 * or null. Canonical means re-encoding gives the same text, so one nonce has
 * exactly one spelling.
 */
export function decodeNonce(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{22,86}$/.test(value)) return null
  const bytes = Buffer.from(value, 'base64url')
  if (bytes.length < NONCE_MIN_BYTES || bytes.length > NONCE_MAX_BYTES || bytes.toString('base64url') !== value) return null
  return bytes
}

// ---- Parse-only document decoding ---------------------------------------------
//
// The reader reads its own PCR0 back out of a fresh document to report it
// (Go stores it, the health line prints it). Nothing here verifies anything:
// the console is the verifier. CBOR subset as the NSM writes it (RFC 8949:
// definite-length strings, maps and arrays that may be indefinite, no floats).
const fail = () => { throw new AttestationError('attest_failed') }
function decodeCbor(bytes) {
  let at = 0
  const need = n => { if (at + n > bytes.length) fail() }
  function length(info) {
    if (info < 24) return info
    const size = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : fail()
    need(size)
    let value = 0
    for (let i = 0; i < size; i++) value = value * 256 + bytes[at++]
    if (!Number.isSafeInteger(value)) fail()
    return value
  }
  function item(depth) {
    if (depth > 6) fail()
    need(1)
    const head = bytes[at++], major = head >> 5, info = head & 31
    if (info === 31) {
      if (major === 4) { const out = []; while ((need(1), bytes[at]) !== 0xff) out.push(item(depth + 1)); at++; return out }
      if (major === 5) { const out = new Map(); while ((need(1), bytes[at]) !== 0xff) { const key = item(depth + 1); out.set(key, item(depth + 1)) } at++; return out }
      fail()
    }
    if (major === 7) return info === 20 ? false : info === 21 ? true : info === 22 ? null : fail()
    const n = length(info)
    switch (major) {
      case 0: return n
      case 1: return -1 - n
      case 2: need(n); return bytes.subarray(at, at += n)
      case 3: need(n); return Buffer.from(bytes.subarray(at, at += n)).toString('utf8')
      case 4: { const out = []; for (let i = 0; i < n; i++) out.push(item(depth + 1)); return out }
      case 5: { const out = new Map(); for (let i = 0; i < n; i++) { const key = item(depth + 1); out.set(key, item(depth + 1)) } return out }
      default: return { tag: n, value: item(depth + 1) }
    }
  }
  const value = item(0)
  if (at !== bytes.length) fail()
  return value
}

/**
 * The fields of a COSE_Sign1 attestation document, unverified:
 * `{pcrs, publicKey, nonce, userData, timestamp, moduleId}` with PCRs as hex.
 */
export function decodeAttestationDocument(document) {
  let outer = decodeCbor(new Uint8Array(document))
  if (outer && typeof outer === 'object' && 'tag' in outer) outer = outer.value // tag 18 is optional
  if (!Array.isArray(outer) || outer.length !== 4 || !(outer[2] instanceof Uint8Array)) fail()
  const payload = decodeCbor(outer[2])
  if (!(payload instanceof Map) || !(payload.get('pcrs') instanceof Map)) fail()
  const pcrs = {}
  for (const [index, value] of payload.get('pcrs')) if (Number.isInteger(index) && value instanceof Uint8Array) pcrs[index] = Buffer.from(value).toString('hex')
  const bytes = name => (payload.get(name) instanceof Uint8Array ? Buffer.from(payload.get(name)) : null)
  return { pcrs, publicKey: bytes('public_key'), nonce: bytes('nonce'), userData: bytes('user_data'), timestamp: payload.get('timestamp'), moduleId: payload.get('module_id') }
}

/**
 * Builds attestation objects (§6.3). `attest({publicKey, nonce, userData})`
 * returns a raw document; `spki()` and `policy()` return the current 64-hex
 * values or null (no certificate yet, no policy read in the last 20 minutes),
 * which refuses with tls_not_ready or policy_unknown before the NSM is asked.
 */
export function createAttestor({ attest, readerId, readerVersion, resource, spki, policy }) {
  if (!versionShape.test(readerVersion)) throw new AttestationError('reader_version_invalid', 500)
  return {
    /** `publicKey` is the request's raw 32-byte key, or null for the public /attestation route. */
    async attestation({ requestId, publicKey, nonce }) {
      const tls = spki(), policyHash = policy()
      if (!tls || !hex64.test(tls)) throw new AttestationError('tls_not_ready')
      if (!policyHash || !hex64.test(policyHash)) throw new AttestationError('policy_unknown')
      const fields = { request_id: requestId, resource, tls_spki_sha256: tls, policy_sha256: policyHash, reader_version: readerVersion }
      let document
      try { document = await attest({ publicKey: publicKey ?? null, nonce, userData: attestationUserData(fields) }) } catch { throw new AttestationError('attest_failed') }
      if (!Buffer.isBuffer(document) || document.length === 0 || document.length > MAX_DOCUMENT_BYTES) throw new AttestationError('attest_failed')
      const pcr0 = decodeAttestationDocument(document).pcrs[0]
      if (!/^[0-9a-f]{96}$/.test(pcr0 ?? '')) throw new AttestationError('attest_failed')
      return {
        format: ATTESTATION_FORMAT, document: document.toString('base64url'),
        request_id: requestId, resource, reader_id: readerId, reader_version: readerVersion,
        tls_spki_sha256: tls, policy_sha256: policyHash, pcr0,
      }
    },
  }
}
