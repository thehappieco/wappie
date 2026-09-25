// AWS Nitro Enclaves attestation, verified before anything is sealed to a reader.
//
// The console seals a connection only to a key that an attested enclave image
// holds, and this file is what decides "attested". It runs in the browser, so
// it is written against WebCrypto with no dependency, for the reason hpke.ts
// gives: a CBOR or X.509 package from npm would sit between the user's
// consent and the key it goes to, and it would be much harder to audit than a
// decoder for the one fixed shape the NSM produces. The reader-verify CLI and
// the enclave use the same file, so there is one verifier (plan 2a.16).
//
// What is accepted is narrow on purpose: a COSE_Sign1 signed with ES384 by a
// P-384 leaf, chained with ecdsa-with-SHA384 to the pinned AWS root, and an
// image whose PCR0, PCR1 and PCR2 match one released build. The document then
// has to carry this page's nonce and a user_data that commits to the request,
// the resource, the TLS key and the KMS key policy the enclave runs under.
//
// Every refusal is an AttestationError with one of a fixed set of codes; the
// console translates the codes, so the set is part of the contract
// (docs/mcp-enclave.md section 11).

import { type Bytes, encodeUTF8, equal, fromBase64, toHex } from './bytes.js'

export type AttestationCode =
  | 'attestation_format'
  | 'attestation_signature'
  | 'attestation_chain'
  | 'attestation_root'
  | 'attestation_validity'
  | 'attestation_clock'
  | 'attestation_debug'
  | 'attestation_measurement'
  | 'attestation_allowlist'
  | 'attestation_nonce'
  | 'attestation_user_data'
  | 'attestation_policy'
  | 'attestation_public_key'
  | 'attestation_version'
  | 'attestation_request'

export class AttestationError extends Error {
  readonly code: AttestationCode
  constructor(code: AttestationCode) {
    super(code)
    this.name = 'AttestationError'
    this.code = code
  }
}

/** The fields the enclave commits to in user_data (docs/mcp-enclave.md 6.2). */
export interface AttestationFields {
  request_id: string
  resource: string
  reader_version: string
  tls_spki_sha256: string
  policy_sha256: string
}

/** One released image: exactly PCR0, PCR1 and PCR2, as 96 lowercase hex characters each. */
export interface AllowEntry {
  version: string
  pcrs: { 0: string; 1: string; 2: string }
}

export interface VerifyOptions {
  /** The bytes this page sent as the nonce, 16 to 64 of them. */
  nonce: Uint8Array
  allow: readonly AllowEntry[]
  /** Accepted KMS key policy hashes, 64 lowercase hex characters each. */
  policies: readonly string[]
  /** The request this page is consenting to, or '' for the public /attestation route. */
  requestId: string
  resource: string
  /** True for a request document (the per-request X25519 key), false for /attestation. */
  requirePublicKey: boolean
  now?: number
  maxSkewMs?: number
  /** Replaces the pinned AWS root. Only tests have a reason to. */
  rootDer?: Uint8Array
}

export interface AttestationResult {
  publicKey: Uint8Array | null
  entry: AllowEntry
  pcrs: { 0: string; 1: string; 2: string }
  timestamp: number
  moduleId: string
  documentSha256: string
  fields: AttestationFields
}

// AWS_NitroEnclaves_Root-G1, from aws-nitro-enclaves.amazonaws.com. Pinned by
// value rather than fetched, so there is nothing to intercept. Its SHA-256
// fingerprint is 64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B,
// which test/attestation.spec.ts checks.
const AWS_NITRO_ROOT_G1 =
  'MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/Y='

/** The pinned AWS Nitro Enclaves root (G1), DER. */
export function awsNitroRoot(): Uint8Array {
  return fromBase64(AWS_NITRO_ROOT_G1)
}

export const DEFAULT_MAX_SKEW_MS = 600_000
/** The largest document the verifier reads. The NSM's are about 4.5 KiB. */
export const MAX_DOCUMENT_BYTES = 16 * 1024
const MAX_CERTIFICATE_BYTES = 1024
const MAX_CABUNDLE = 8
const MAX_NONCE_FIELD = 512
const MAX_USER_DATA = 512
const MAX_PUBLIC_KEY = 1024
const MIN_NONCE = 16
const MAX_NONCE = 64
const X25519_PUBLIC_KEY = 32
const USER_DATA_LABEL = 'wappie-mcp-attest/v1'

const PCR_HEX = /^[0-9a-f]{96}$/
const SHA256_HEX = /^[0-9a-f]{64}$/
const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+$/
const REQUEST_ID = /^[A-Za-z0-9_-]{22}$/

function fail(code: AttestationCode): never {
  throw new AttestationError(code)
}

// Runs a parser and reports anything it throws, including a TypeError from a
// fatal TextDecoder, as one code: the caller learns what was wrong, never how.
function guarded<T>(code: AttestationCode, parse: () => T): T {
  try {
    return parse()
  } catch (error) {
    if (error instanceof AttestationError) throw error
    return fail(code)
  }
}

async function sha256(data: Bytes): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data))
}

// ---------------------------------------------------------------------------
// CBOR (RFC 8949), the subset the NSM writes: definite and indefinite arrays
// and maps, definite strings, integers, true, false and null. No floats and no
// tags (COSE's tag 18 is handled by the caller, and only at the top). Depth is
// capped because the input is untrusted and recursion is how it is walked.
// ---------------------------------------------------------------------------

type CborValue = number | string | boolean | null | Bytes | CborValue[] | Map<number | string, CborValue>

const utf8 = new TextDecoder('utf-8', { fatal: true })
const MAX_CBOR_DEPTH = 6

function decodeCbor(bytes: Bytes): CborValue {
  let at = 0
  const need = (n: number) => {
    if (at + n > bytes.length) fail('attestation_format')
  }
  const argument = (info: number): number => {
    if (info < 24) return info
    const size = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : fail('attestation_format')
    need(size)
    let value = 0
    for (let i = 0; i < size; i++) value = value * 256 + bytes[at++]
    // The timestamp is a uint64 on the wire; beyond 2^53 a Number would round it.
    if (!Number.isSafeInteger(value)) fail('attestation_format')
    return value
  }
  const mapEntry = (out: Map<number | string, CborValue>, depth: number) => {
    const key = item(depth + 1)
    // A repeated key would let two readers of one document see different values.
    if ((typeof key !== 'string' && typeof key !== 'number') || out.has(key)) fail('attestation_format')
    out.set(key, item(depth + 1))
  }
  const item = (depth: number): CborValue => {
    if (depth > MAX_CBOR_DEPTH) fail('attestation_format')
    need(1)
    const head = bytes[at++]
    const major = head >> 5
    const info = head & 31
    if (info === 31) {
      // serde_cbor in the NSM writes the payload map with indefinite length
      // (0xbf ... 0xff), so arrays and maps may be indefinite; strings may not.
      const more = () => (need(1), bytes[at] !== 0xff)
      if (major === 4) {
        const out: CborValue[] = []
        while (more()) out.push(item(depth + 1))
        at++
        return out
      }
      if (major === 5) {
        const out = new Map<number | string, CborValue>()
        while (more()) mapEntry(out, depth)
        at++
        return out
      }
      return fail('attestation_format')
    }
    if (major === 7) {
      if (info === 20) return false
      if (info === 21) return true
      if (info === 22) return null
      return fail('attestation_format')
    }
    const n = argument(info)
    switch (major) {
      case 0:
        return n
      case 1:
        return -1 - n
      case 2:
        need(n)
        return bytes.subarray(at, (at += n))
      case 3:
        need(n)
        return utf8.decode(bytes.subarray(at, (at += n)))
      case 4: {
        const out: CborValue[] = []
        for (let i = 0; i < n; i++) out.push(item(depth + 1))
        return out
      }
      case 5: {
        const out = new Map<number | string, CborValue>()
        for (let i = 0; i < n; i++) mapEntry(out, depth)
        return out
      }
      default:
        return fail('attestation_format') // tags
    }
  }
  const value = guarded('attestation_format', () => item(0))
  // Trailing bytes would be unsigned data riding along with a signed document.
  if (at !== bytes.length) fail('attestation_format')
  return value
}

// ---------------------------------------------------------------------------
// COSE_Sign1 envelope and the attestation document's fields
// (aws-nitro-enclaves-nsm-api docs/attestation_process.md 3.2).
// ---------------------------------------------------------------------------

const COSE_SIGN1_TAG = 0xd2 // tag 18, in its one-byte form
const ES384 = -35

interface Envelope {
  protectedBytes: Bytes
  payload: Bytes
  signature: Bytes
  doc: Map<number | string, CborValue>
}

interface Document {
  moduleId: string
  timestamp: number
  pcrs: Map<number, Bytes>
  certificate: Bytes
  cabundle: Bytes[]
  publicKey: Bytes | null
  userData: Bytes | null
  nonce: Bytes | null
}

const isBytes = (v: unknown): v is Bytes => v instanceof Uint8Array

function openEnvelope(document: Bytes): Envelope {
  if (document.length < 1 || document.length > MAX_DOCUMENT_BYTES) fail('attestation_format')
  // AWS documents show the tagged form and the NSM writes the untagged one.
  // Both are accepted; any other tag is not.
  const cose = decodeCbor(document[0] === COSE_SIGN1_TAG ? document.subarray(1) : document)
  if (!Array.isArray(cose) || cose.length !== 4) fail('attestation_format')
  const [protectedBytes, unprotected, payload, signature] = cose
  if (!isBytes(protectedBytes) || !(unprotected instanceof Map) || !isBytes(payload) || !isBytes(signature)) {
    fail('attestation_format')
  }
  const doc = decodeCbor(payload)
  if (!(doc instanceof Map)) fail('attestation_format')
  return { protectedBytes, payload, signature, doc }
}

// The nsm-api AttestationDoc has plain Option fields, which serde writes as
// null, so null means "not set" even though attestation_process.md forbids it.
function optionalBytes(doc: Map<number | string, CborValue>, field: string, max: number): Bytes | null {
  const value = doc.get(field)
  if (value === undefined || value === null) return null
  if (!isBytes(value) || value.length > max) fail('attestation_format')
  return value
}

function readDocument(doc: Map<number | string, CborValue>): Document {
  const moduleId = doc.get('module_id')
  if (typeof moduleId !== 'string' || moduleId.length === 0) fail('attestation_format')
  if (doc.get('digest') !== 'SHA384') fail('attestation_format')
  const timestamp = doc.get('timestamp')
  if (typeof timestamp !== 'number' || !Number.isSafeInteger(timestamp) || timestamp <= 0) fail('attestation_format')
  const pcrs = doc.get('pcrs')
  if (!(pcrs instanceof Map) || pcrs.size < 1 || pcrs.size > 32) fail('attestation_format')
  const pcrMap = new Map<number, Bytes>()
  for (const [index, value] of pcrs) {
    if (typeof index !== 'number' || !Number.isInteger(index) || index < 0 || index > 31) fail('attestation_format')
    if (!isBytes(value) || ![32, 48, 64].includes(value.length)) fail('attestation_format')
    pcrMap.set(index, value)
  }
  const certificate = doc.get('certificate')
  if (!isBytes(certificate) || certificate.length < 1 || certificate.length > MAX_CERTIFICATE_BYTES) {
    fail('attestation_format')
  }
  const cabundle = doc.get('cabundle')
  if (!Array.isArray(cabundle) || cabundle.length < 1 || cabundle.length > MAX_CABUNDLE) fail('attestation_format')
  for (const der of cabundle) {
    if (!isBytes(der) || der.length < 1 || der.length > MAX_CERTIFICATE_BYTES) fail('attestation_format')
  }
  return {
    moduleId,
    timestamp,
    pcrs: pcrMap,
    certificate,
    cabundle: cabundle as Bytes[],
    publicKey: optionalBytes(doc, 'public_key', MAX_PUBLIC_KEY),
    userData: optionalBytes(doc, 'user_data', MAX_USER_DATA),
    nonce: optionalBytes(doc, 'nonce', MAX_NONCE_FIELD),
  }
}

// Copied once at the edge: the input could be a Node Buffer, a view over
// shared memory, or an array the caller keeps writing to while this awaits.
function ownBytes(value: unknown, code: AttestationCode): Bytes {
  if (!(value instanceof Uint8Array)) fail(code)
  return new Uint8Array(value)
}

/**
 * decodeAttestationDocument reads a document without trusting it: no
 * signature, chain, clock or measurement check. The enclave uses it to report
 * its own PCR0; nothing else should act on what it returns.
 */
export function decodeAttestationDocument(document: Uint8Array): {
  pcrs: Record<number, string>
  publicKey: Uint8Array | null
  nonce: Uint8Array | null
  userData: Uint8Array | null
  timestamp: number
  moduleId: string
} {
  const doc = readDocument(openEnvelope(ownBytes(document, 'attestation_format')).doc)
  const pcrs: Record<number, string> = {}
  for (const [index, value] of [...doc.pcrs].sort(([a], [b]) => a - b)) pcrs[index] = toHex(value)
  return {
    pcrs,
    publicKey: doc.publicKey && doc.publicKey.slice(),
    nonce: doc.nonce && doc.nonce.slice(),
    userData: doc.userData && doc.userData.slice(),
    timestamp: doc.timestamp,
    moduleId: doc.moduleId,
  }
}

// ---------------------------------------------------------------------------
// DER and X.509, for the fixed shape of the AWS chain: v3 certificates with
// EC P-384 keys, signed with ecdsa-with-SHA384. Anything else is refused
// rather than half-understood.
// ---------------------------------------------------------------------------

interface Node {
  tag: number
  start: number
  body: number
  end: number
}

function tlv(der: Bytes, at: number, end: number): Node {
  if (at + 2 > end) fail('attestation_chain')
  const tag = der[at]
  // High tag numbers never occur in a certificate; refusing them keeps the tag one byte.
  if ((tag & 0x1f) === 0x1f) fail('attestation_chain')
  let length = der[at + 1]
  let body = at + 2
  if (length & 0x80) {
    const n = length & 0x7f
    // n = 0 is BER's indefinite length, which DER forbids.
    if (n === 0 || n > 3 || body + n > end) fail('attestation_chain')
    if (der[body] === 0) fail('attestation_chain') // minimal length only
    length = 0
    for (let i = 0; i < n; i++) length = length * 256 + der[body++]
    if (length < 128) fail('attestation_chain')
  }
  if (body + length > end) fail('attestation_chain')
  return { tag, start: at, body, end: body + length }
}

function children(der: Bytes, node: Node): Node[] {
  const out: Node[] = []
  for (let at = node.body; at < node.end; ) {
    const child = tlv(der, at, node.end)
    out.push(child)
    at = child.end
  }
  return out
}

function expect(node: Node | undefined, tag: number): Node {
  if (!node || node.tag !== tag) fail('attestation_chain')
  return node
}

const whole = (der: Bytes, node: Node) => der.subarray(node.start, node.end)
const content = (der: Bytes, node: Node) => der.subarray(node.body, node.end)

function oid(der: Bytes, node: Node | undefined): string {
  const b = content(der, expect(node, 0x06))
  if (b.length === 0 || b[b.length - 1] & 0x80) fail('attestation_chain')
  const parts = [Math.floor(b[0] / 40), b[0] % 40]
  let value = 0
  for (let i = 1; i < b.length; i++) {
    value = value * 128 + (b[i] & 0x7f)
    if (!(b[i] & 0x80)) {
      parts.push(value)
      value = 0
    }
  }
  return parts.join('.')
}

// UTCTime or GeneralizedTime, both in the Z form DER requires. The components
// are round-tripped because Date.UTC quietly turns February 30 into March 2.
function time(der: Bytes, node: Node): number {
  const s = String.fromCharCode(...content(der, node))
  const m =
    node.tag === 0x17
      ? /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s)
      : node.tag === 0x18
        ? /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s)
        : null
  if (!m) return fail('attestation_chain')
  let year = Number(m[1])
  if (node.tag === 0x17) year += year < 50 ? 2000 : 1900
  const [month, day, hour, minute, second] = m.slice(2).map(Number)
  const ms = Date.UTC(year, month - 1, day, hour, minute, second)
  const d = new Date(ms)
  const same =
    d.getUTCFullYear() === year &&
    d.getUTCMonth() === month - 1 &&
    d.getUTCDate() === day &&
    d.getUTCHours() === hour &&
    d.getUTCMinutes() === minute &&
    d.getUTCSeconds() === second
  return same ? ms : fail('attestation_chain')
}

const ECDSA_SHA384 = '1.2.840.10045.4.3.3'
const EC_PUBLIC_KEY = '1.2.840.10045.2.1'
const P384 = '1.3.132.0.34'
const BASIC_CONSTRAINTS = '2.5.29.19'
const KEY_USAGE = '2.5.29.15'
// keyUsage bits in the first byte of the BIT STRING (RFC 5280 4.2.1.3).
const DIGITAL_SIGNATURE = 0x80
const KEY_CERT_SIGN = 0x04

interface Certificate {
  tbs: Bytes
  issuer: Bytes
  subject: Bytes
  spki: Bytes
  p384: boolean
  notBefore: number
  notAfter: number
  ca: boolean
  pathLen: number | undefined
  keyUsage: number | undefined
  signature: Bytes
}

// An AlgorithmIdentifier for ecdsa-with-SHA384, which has no parameters.
function isEcdsaSha384(der: Bytes, node: Node | undefined): boolean {
  const parts = children(der, expect(node, 0x30))
  return parts.length === 1 && oid(der, parts[0]) === ECDSA_SHA384
}

function parseCertificate(der: Bytes): Certificate {
  const top = tlv(der, 0, der.length)
  if (top.tag !== 0x30 || top.end !== der.length) fail('attestation_chain')
  const parts = children(der, top)
  if (parts.length !== 3) fail('attestation_chain')
  const [tbs, algorithm, signature] = parts
  expect(tbs, 0x30)
  expect(signature, 0x03)
  if (!isEcdsaSha384(der, algorithm)) fail('attestation_chain')

  const fields = children(der, tbs)
  // v3 only: the version is explicit, and extensions are what the checks below read.
  const version = content(der, expect(fields[0], 0xa0))
  if (version.length !== 3 || version[0] !== 0x02 || version[1] !== 0x01 || version[2] !== 0x02) {
    fail('attestation_chain')
  }
  const [serial, innerAlgorithm, issuer, validity, subject, spki, ...rest] = fields.slice(1)
  expect(serial, 0x02)
  // The signed copy of the algorithm has to agree with the unsigned one.
  if (!isEcdsaSha384(der, innerAlgorithm)) fail('attestation_chain')
  expect(issuer, 0x30)
  expect(subject, 0x30)

  const [notBefore, notAfter, ...extraTimes] = children(der, expect(validity, 0x30))
  if (!notBefore || !notAfter || extraTimes.length) fail('attestation_chain')

  const spkiParts = children(der, expect(spki, 0x30))
  if (spkiParts.length !== 2) fail('attestation_chain')
  expect(spkiParts[1], 0x03)
  const keyAlgorithm = children(der, expect(spkiParts[0], 0x30))
  const p384 = keyAlgorithm.length === 2 && oid(der, keyAlgorithm[0]) === EC_PUBLIC_KEY && keyAlgorithm[1].tag === 0x06 && oid(der, keyAlgorithm[1]) === P384

  const bits = content(der, signature)
  if (bits.length < 2 || bits[0] !== 0) fail('attestation_chain')

  const out: Certificate = {
    tbs: whole(der, tbs),
    issuer: whole(der, issuer),
    subject: whole(der, subject),
    spki: whole(der, spki),
    p384,
    notBefore: time(der, notBefore),
    notAfter: time(der, notAfter),
    ca: false,
    pathLen: undefined,
    keyUsage: undefined,
    signature: bits.subarray(1),
  }
  if (out.notBefore > out.notAfter) fail('attestation_chain')
  readExtensions(der, rest, out)
  return out
}

// After the key come the optional issuerUniqueID [1], subjectUniqueID [2] and
// extensions [3], in that order and at most once each.
function readExtensions(der: Bytes, rest: Node[], out: Certificate) {
  let last = 0
  let extensions: Node | undefined
  for (const node of rest) {
    const n = node.tag === 0x81 || node.tag === 0xa1 ? 1 : node.tag === 0x82 || node.tag === 0xa2 ? 2 : node.tag === 0xa3 ? 3 : 0
    if (n <= last) fail('attestation_chain')
    last = n
    if (n === 3) extensions = node
  }
  if (!extensions) return
  const list = children(der, extensions)
  if (list.length !== 1) fail('attestation_chain')
  const seen = new Set<string>()
  for (const extension of children(der, expect(list[0], 0x30))) {
    const parts = children(der, expect(extension, 0x30))
    if (parts.length < 2 || parts.length > 3) fail('attestation_chain')
    const id = oid(der, parts[0])
    const flag = parts.length === 3 ? content(der, expect(parts[1], 0x01)) : undefined
    if (flag && flag.length !== 1) fail('attestation_chain')
    const critical = flag !== undefined && flag[0] !== 0
    const value = expect(parts[parts.length - 1], 0x04)
    // Two basicConstraints could each be read by a different verifier.
    if (seen.has(id)) fail('attestation_chain')
    seen.add(id)
    if (id === BASIC_CONSTRAINTS) readBasicConstraints(der, value, out)
    else if (id === KEY_USAGE) out.keyUsage = readKeyUsage(der, value)
    // RFC 5280 4.2: a critical extension that is not understood must be refused.
    else if (critical) fail('attestation_chain')
  }
}

function readBasicConstraints(der: Bytes, value: Node, out: Certificate) {
  const inner = tlv(der, value.body, value.end)
  if (inner.tag !== 0x30 || inner.end !== value.end) fail('attestation_chain')
  // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
  const parts = children(der, inner)
  if (parts.length > 2) fail('attestation_chain')
  let next = 0
  if (parts[next]?.tag === 0x01) {
    const b = content(der, parts[next++])
    if (b.length !== 1) fail('attestation_chain')
    out.ca = b[0] !== 0
  }
  if (next < parts.length) {
    const b = content(der, expect(parts[next++], 0x02))
    if (b.length < 1 || b.length > 2 || b[0] & 0x80) fail('attestation_chain')
    out.pathLen = b.reduce((n, x) => n * 256 + x, 0)
  }
  if (next !== parts.length) fail('attestation_chain')
}

function readKeyUsage(der: Bytes, value: Node): number {
  const inner = tlv(der, value.body, value.end)
  if (inner.tag !== 0x03 || inner.end !== value.end) fail('attestation_chain')
  const b = content(der, inner)
  if (b.length < 1 || b[0] > 7) fail('attestation_chain')
  return b[1] ?? 0
}

// DER ECDSA-Sig-Value to the raw r||s form WebCrypto verifies.
function rawSignature(der: Bytes): Bytes {
  const size = 48
  const top = tlv(der, 0, der.length)
  if (top.tag !== 0x30 || top.end !== der.length) fail('attestation_chain')
  const parts = children(der, top)
  if (parts.length !== 2) fail('attestation_chain')
  const out = new Uint8Array(size * 2)
  parts.forEach((node, k) => {
    let v = content(der, expect(node, 0x02))
    while (v.length > size && v[0] === 0) v = v.subarray(1)
    if (v.length === 0 || v.length > size) fail('attestation_chain')
    out.set(v, k * size + size - v.length)
  })
  return out
}

async function verifyP384(spki: Bytes, signature: Bytes, data: Bytes, code: AttestationCode): Promise<void> {
  let key: CryptoKey
  try {
    key = await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify'])
  } catch {
    return fail(code)
  }
  let ok = false
  try {
    ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key, signature, data)
  } catch {
    ok = false
  }
  if (!ok) fail(code)
}

// ---------------------------------------------------------------------------
// COSE signature (RFC 9052 4.4)
// ---------------------------------------------------------------------------

function bstrHead(n: number): number[] {
  if (n < 24) return [0x40 | n]
  if (n < 256) return [0x58, n]
  if (n < 65536) return [0x59, n >> 8, n & 255]
  return [0x5a, n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]
}

// Sig_structure = ["Signature1", protected, external_aad = h'', payload],
// written out by hand: it is a fixed four-element array, and an encoder would
// be one more thing to trust.
function sigStructure(protectedBytes: Bytes, payload: Bytes): Bytes {
  const parts: ArrayLike<number>[] = [
    [0x84, 0x6a],
    encodeUTF8('Signature1'),
    bstrHead(protectedBytes.length),
    protectedBytes,
    [0x40],
    bstrHead(payload.length),
    payload,
  ]
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

// The leaf key signs the document. It is checked before any other field so
// that a changed payload fails as a bad signature whichever field it touched.
async function checkSignature(envelope: Envelope): Promise<void> {
  const header = decodeCbor(envelope.protectedBytes)
  if (!(header instanceof Map) || header.get(1) !== ES384) fail('attestation_signature')
  const certificate = envelope.doc.get('certificate')
  if (!isBytes(certificate) || certificate.length > MAX_CERTIFICATE_BYTES) fail('attestation_format')
  const leaf = guarded('attestation_chain', () => parseCertificate(certificate))
  if (!leaf.p384 || envelope.signature.length !== 96) fail('attestation_signature')
  await verifyP384(leaf.spki, envelope.signature, sigStructure(envelope.protectedBytes, envelope.payload), 'attestation_signature')
}

// ---------------------------------------------------------------------------
// Chain: cabundle is [ROOT, INTERM_1 ... INTERM_N] and the leaf hangs off
// INTERM_N. No revocation check: AWS says to disable CRLs, and the chain is
// short-lived (the zonal and instance certificates last hours to days).
// ---------------------------------------------------------------------------

async function checkChain(doc: Document, rootDer: Bytes, now: number): Promise<void> {
  if (!equal(doc.cabundle[0], rootDer)) fail('attestation_root')
  const chain = doc.cabundle.map(der => guarded('attestation_chain', () => parseCertificate(der)))
  const leaf = guarded('attestation_chain', () => parseCertificate(doc.certificate))
  chain.forEach((c, i) => {
    if (!c.p384 || !c.ca) fail('attestation_chain')
    if (c.keyUsage === undefined || !(c.keyUsage & KEY_CERT_SIGN)) fail('attestation_chain')
    // pathLenConstraint counts the CA certificates that may follow this one
    // (RFC 5280 4.2.1.9); the leaf is not one of them.
    if (c.pathLen !== undefined && c.pathLen < chain.length - 1 - i) fail('attestation_chain')
  })
  if (leaf.ca || leaf.pathLen !== undefined) fail('attestation_chain')
  if (leaf.keyUsage === undefined || !(leaf.keyUsage & DIGITAL_SIGNATURE)) fail('attestation_chain')
  for (let i = 1; i <= chain.length; i++) {
    const child = i < chain.length ? chain[i] : leaf
    const parent = chain[i - 1]
    if (!equal(child.issuer, parent.subject)) fail('attestation_chain')
    const signature = guarded('attestation_chain', () => rawSignature(child.signature))
    await verifyP384(parent.spki, signature, child.tbs, 'attestation_chain')
  }
  for (const c of [...chain, leaf]) if (now < c.notBefore || now > c.notAfter) fail('attestation_validity')
}

// ---------------------------------------------------------------------------
// Options and fields
// ---------------------------------------------------------------------------

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(v))

const hasExactKeys = (v: Record<string, unknown>, keys: string[]) => {
  const own = Object.keys(v)
  return own.length === keys.length && keys.every(k => own.includes(k))
}

// An entry's pcrs must name exactly PCR0, PCR1 and PCR2. The PoC compared
// whatever keys an entry had, so {} or {pcrs: {1: …}} matched every enclave.
// Other keys on the entry itself (the generated module's release_url, say) are
// ignored: they cannot widen what matches.
function checkAllowlist(allow: unknown): AllowEntry[] {
  if (!Array.isArray(allow)) fail('attestation_allowlist')
  return allow.map(entry => {
    if (!isPlainObject(entry)) fail('attestation_allowlist')
    const { version, pcrs } = entry
    if (typeof version !== 'string' || !VERSION.test(version)) fail('attestation_allowlist')
    if (!isPlainObject(pcrs) || !hasExactKeys(pcrs, ['0', '1', '2'])) fail('attestation_allowlist')
    for (const k of ['0', '1', '2']) if (typeof pcrs[k] !== 'string' || !PCR_HEX.test(pcrs[k] as string)) fail('attestation_allowlist')
    return { version, pcrs: { 0: pcrs['0'] as string, 1: pcrs['1'] as string, 2: pcrs['2'] as string } }
  })
}

interface Checked {
  nonce: Bytes
  allow: AllowEntry[]
  policies: string[]
  requestId: string
  resource: string
  requirePublicKey: boolean
  now: number
  maxSkewMs: number
  rootDer: Bytes
}

// Programmatic callers skip any parsing a CLI would do. A NaN clock makes every
// date comparison false and a non-array list is silently empty, so a bad option
// has to fail rather than switch a check off.
function checkOptions(options: VerifyOptions): Checked {
  if (options === null || typeof options !== 'object') fail('attestation_allowlist')
  const allow = checkAllowlist(options.allow)
  const policies = options.policies
  if (!Array.isArray(policies) || !policies.every(p => typeof p === 'string' && SHA256_HEX.test(p))) fail('attestation_policy')
  const nonce = ownBytes(options.nonce, 'attestation_nonce')
  if (nonce.length < MIN_NONCE || nonce.length > MAX_NONCE) fail('attestation_nonce')
  const { requestId, resource } = options
  if (typeof requestId !== 'string' || (requestId !== '' && !REQUEST_ID.test(requestId))) fail('attestation_request')
  if (typeof resource !== 'string' || resource === '' || resource.includes('\0')) fail('attestation_request')
  if (typeof options.requirePublicKey !== 'boolean') fail('attestation_public_key')
  const now = options.now ?? Date.now()
  const maxSkewMs = options.maxSkewMs ?? DEFAULT_MAX_SKEW_MS
  if (!Number.isSafeInteger(now) || now <= 0 || !Number.isSafeInteger(maxSkewMs) || maxSkewMs < 0) fail('attestation_clock')
  const rootDer = options.rootDer === undefined ? fromBase64(AWS_NITRO_ROOT_G1) : ownBytes(options.rootDer, 'attestation_root')
  return { nonce, allow, policies: [...policies], requestId, resource, requirePublicKey: options.requirePublicKey, now, maxSkewMs, rootDer }
}

const FIELD_NAMES = ['request_id', 'resource', 'tls_spki_sha256', 'policy_sha256', 'reader_version'] as const

// Picks the five committed fields, so a caller can pass the whole attestation
// object from the descriptor, and so later reads cannot see a changed value.
function pickFields(fields: unknown): AttestationFields {
  if (fields === null || typeof fields !== 'object') fail('attestation_user_data')
  const source = fields as Record<string, unknown>
  const out: Record<string, string> = {}
  for (const name of FIELD_NAMES) {
    const value = source[name]
    // 0x00 separates the fields in the preimage, so it may not appear in one.
    if (typeof value !== 'string' || value.includes('\0')) fail('attestation_user_data')
    out[name] = value
  }
  return out as unknown as AttestationFields
}

/**
 * attestationUserData is the 32 bytes the enclave puts in user_data:
 * SHA-256 of the six fields joined by 0x00 (docs/mcp-enclave.md 6.2).
 */
export async function attestationUserData(fields: AttestationFields): Promise<Uint8Array> {
  const f = pickFields(fields)
  if (!VERSION.test(f.reader_version)) fail('attestation_version')
  if (!SHA256_HEX.test(f.tls_spki_sha256) || !SHA256_HEX.test(f.policy_sha256)) fail('attestation_user_data')
  const preimage = [USER_DATA_LABEL, f.request_id, f.resource, f.tls_spki_sha256, f.policy_sha256, f.reader_version].join('\0')
  return sha256(encodeUTF8(preimage))
}

// ---------------------------------------------------------------------------
// PCRs
// ---------------------------------------------------------------------------

function imagePcrs(doc: Document): { 0: string; 1: string; 2: string } {
  const read = (index: number) => {
    const value = doc.pcrs.get(index)
    // PCR0 to 2 are SHA-384 measurements of the image, kernel and application.
    if (!value || value.length !== 48) return fail('attestation_format')
    // A debug-mode enclave reports all-zero PCRs: its document says nothing about the image.
    if (value.every(b => b === 0)) fail('attestation_debug')
    return toHex(value)
  }
  return { 0: read(0), 1: read(1), 2: read(2) }
}

function matchEntry(allow: AllowEntry[], pcrs: { 0: string; 1: string; 2: string }, version: string): AllowEntry {
  const matches = allow.filter(e => e.pcrs[0] === pcrs[0] && e.pcrs[1] === pcrs[1] && e.pcrs[2] === pcrs[2])
  if (matches.length === 0) fail('attestation_measurement')
  // The version is part of user_data, so the release it names must be the one measured.
  const entry = matches.find(e => e.version === version)
  if (!entry) fail('attestation_version')
  return { version: entry.version, pcrs: { ...entry.pcrs } }
}

// ---------------------------------------------------------------------------
// verifyAttestation
// ---------------------------------------------------------------------------

/**
 * verifyAttestation checks an NSM attestation document against a release
 * allowlist and the fields the reader says it committed to, and returns the
 * attested public key. It resolves only when every check passed; otherwise it
 * rejects with an AttestationError.
 *
 * The order matters for what a refusal reports, not for safety: the signature
 * comes first so tampering reads as tampering, then the chain, then what the
 * image is, then what this particular document says.
 */
export async function verifyAttestation(
  document: Uint8Array,
  fields: AttestationFields,
  options: VerifyOptions,
): Promise<AttestationResult> {
  const o = checkOptions(options)
  const f = pickFields(fields)
  const raw = ownBytes(document, 'attestation_format')

  const envelope = openEnvelope(raw)
  await checkSignature(envelope)
  const doc = readDocument(envelope.doc)
  // Both directions: an enclave clock can run a little ahead of the browser's.
  if (Math.abs(o.now - doc.timestamp) > o.maxSkewMs) fail('attestation_clock')
  await checkChain(doc, o.rootDer, o.now)

  const pcrs = imagePcrs(doc)
  if (!VERSION.test(f.reader_version)) fail('attestation_version')
  const entry = matchEntry(o.allow, pcrs, f.reader_version)
  if (f.request_id !== o.requestId || f.resource !== o.resource) fail('attestation_request')
  if (!o.policies.includes(f.policy_sha256)) fail('attestation_policy')
  // The nonce is what makes the document this page's and not a replay.
  if (!doc.nonce || !equal(doc.nonce, o.nonce)) fail('attestation_nonce')
  const userData = await attestationUserData(f)
  if (!doc.userData || !equal(doc.userData, userData as Bytes)) fail('attestation_user_data')
  // A request document carries the request's own X25519 key; the public route
  // carries none, so a key there could only be one the caller should not use.
  if (o.requirePublicKey ? doc.publicKey?.length !== X25519_PUBLIC_KEY : doc.publicKey !== null) fail('attestation_public_key')

  return {
    publicKey: doc.publicKey && doc.publicKey.slice(),
    entry,
    pcrs,
    timestamp: doc.timestamp,
    moduleId: doc.moduleId,
    documentSha256: toHex(await sha256(raw)),
    fields: f,
  }
}
