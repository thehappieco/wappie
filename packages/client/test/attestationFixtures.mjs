// Synthetic, Nitro-shaped PKI and attestation documents for the verifier tests:
// a P-384 root -> regional -> zonal -> leaf chain with real basicConstraints and
// keyUsage extensions, and COSE_Sign1 documents signed by the leaf.
//
// Built with node:crypto and a small DER and CBOR encoder written here, not with
// the verifier's own code, so a bug in the verifier's decoding cannot be
// mirrored by the fixtures. Plain JavaScript so tools/reader-verify's tests can
// use it too. Every key is generated in memory and thrown away.
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto'

export const NOW = Date.parse('2026-09-24T12:00:00Z')
export const HOUR = 3_600_000
export const DAY = 24 * HOUR

// keyUsage bits, first byte of the BIT STRING.
export const DIGITAL_SIGNATURE = 0x80
export const NON_REPUDIATION = 0x40
export const KEY_CERT_SIGN = 0x04
export const CRL_SIGN = 0x02

// ---- DER ----------------------------------------------------------------------

function derLength(n) {
  if (n < 128) return [n]
  const out = []
  for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v & 255)
  return [0x80 | out.length, ...out]
}
export const der = (tag, ...parts) => {
  const body = Buffer.concat(parts.map(p => Buffer.from(p)))
  return Buffer.concat([Buffer.from([tag, ...derLength(body.length)]), body])
}
const seq = (...parts) => der(0x30, ...parts)
const set = (...parts) => der(0x31, ...parts)
function oid(dotted) {
  const [a, b, ...rest] = dotted.split('.').map(Number)
  const out = [a * 40 + b]
  for (const n of rest) {
    const chunk = [n & 0x7f]
    for (let v = Math.floor(n / 128); v > 0; v = Math.floor(v / 128)) chunk.unshift(0x80 | (v & 0x7f))
    out.push(...chunk)
  }
  return der(0x06, out)
}
function integer(bytes) {
  let b = Buffer.from(bytes)
  while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1)
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b])
  return der(0x02, b)
}
const smallInt = n => integer(n === 0 ? [0] : n < 256 ? [n] : [n >> 8, n & 255])
const bool = v => der(0x01, [v ? 0xff : 0x00])
const octets = b => der(0x04, b)
function bitString(bytes) {
  const b = Buffer.from(bytes)
  let unused = 0
  if (b.length) for (let last = b[b.length - 1]; unused < 8 && !(last & (1 << unused)); ) unused++
  return der(0x03, [unused === 8 ? 0 : unused], b)
}
function utcTime(ms) {
  const d = new Date(ms)
  const two = n => String(n).padStart(2, '0')
  const text = `${two(d.getUTCFullYear() % 100)}${two(d.getUTCMonth() + 1)}${two(d.getUTCDate())}${two(d.getUTCHours())}${two(d.getUTCMinutes())}${two(d.getUTCSeconds())}Z`
  return der(0x17, Buffer.from(text, 'ascii'))
}
const name = cn => seq(set(seq(oid('2.5.4.3'), der(0x0c, Buffer.from(cn, 'utf8')))))

const ECDSA_SHA384 = seq(oid('1.2.840.10045.4.3.3'))
export const OID = {
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  subjectKeyIdentifier: '2.5.29.14',
  authorityKeyIdentifier: '2.5.29.35',
}
export const extension = (id, value, critical = false) => seq(oid(id), ...(critical ? [bool(true)] : []), octets(value))
const keyId = publicKey => createHash('sha1').update(publicKey.export({ type: 'spki', format: 'der' })).digest()

export const p384 = () => generateKeyPairSync('ec', { namedCurve: 'P-384' })
export const p256 = () => generateKeyPairSync('ec', { namedCurve: 'P-256' })

/**
 * One DER certificate signed with ecdsa-with-SHA384. Leaving ca or keyUsage
 * undefined omits that extension; extensions adds more, in order.
 */
export function makeCert({ subject, issuer = subject, publicKey, signingKey, issuerPublicKey = publicKey, ca, pathLen, keyUsage, notBefore, notAfter, extensions = [] }) {
  const ext = []
  if (ca !== undefined) {
    const fields = [...(ca ? [bool(true)] : []), ...(pathLen !== undefined ? [smallInt(pathLen)] : [])]
    ext.push(extension(OID.basicConstraints, seq(...fields), true))
  }
  if (keyUsage !== undefined) ext.push(extension(OID.keyUsage, bitString([keyUsage]), true))
  ext.push(extension(OID.subjectKeyIdentifier, octets(keyId(publicKey))))
  ext.push(extension(OID.authorityKeyIdentifier, seq(der(0x80, keyId(issuerPublicKey)))))
  ext.push(...extensions)
  const serial = randomBytes(12)
  serial[0] = (serial[0] & 0x7f) | 0x01
  const tbs = seq(
    der(0xa0, smallInt(2)),
    integer(serial),
    ECDSA_SHA384,
    name(issuer),
    seq(utcTime(notBefore), utcTime(notAfter)),
    name(subject),
    publicKey.export({ type: 'spki', format: 'der' }),
    der(0xa3, seq(...ext)),
  )
  const signature = sign('sha384', tbs, { key: signingKey, dsaEncoding: 'der' })
  return seq(tbs, ECDSA_SHA384, der(0x03, [0], signature))
}

const CA_DEFAULTS = { ca: true, keyUsage: KEY_CERT_SIGN | CRL_SIGN | DIGITAL_SIGNATURE, notBefore: NOW - 30 * DAY, notAfter: NOW + 365 * DAY }

/** root -> regional -> zonal -> leaf, like the real chain, with per-certificate overrides. */
export function buildPki(o = {}) {
  const keys = { root: p384(), int1: p384(), int2: p384(), leaf: o.leafKey ?? p384() }
  const root = makeCert({ ...CA_DEFAULTS, subject: 'Test Nitro Root', publicKey: keys.root.publicKey, signingKey: keys.root.privateKey, ...o.root })
  const int1 = makeCert({
    ...CA_DEFAULTS, pathLen: 1, subject: 'Test Regional', issuer: 'Test Nitro Root',
    publicKey: keys.int1.publicKey, signingKey: keys.root.privateKey, issuerPublicKey: keys.root.publicKey, ...o.int1,
  })
  const int2 = makeCert({
    ...CA_DEFAULTS, pathLen: 0, subject: 'Test Zonal', issuer: 'Test Regional',
    publicKey: keys.int2.publicKey, signingKey: keys.int1.privateKey, issuerPublicKey: keys.int1.publicKey, ...o.int2,
  })
  const leaf = makeCert({
    ca: false, keyUsage: DIGITAL_SIGNATURE | NON_REPUDIATION, notBefore: NOW - HOUR, notAfter: NOW + 3 * HOUR,
    subject: 'i-0123456789abcdef0-enc0123456789abcdef.eu-west-1.aws', issuer: 'Test Zonal',
    publicKey: keys.leaf.publicKey, signingKey: keys.int2.privateKey, issuerPublicKey: keys.int2.publicKey, ...o.leaf,
  })
  return { keys, root, int1, int2, leaf, cabundle: [root, int1, int2] }
}

// ---- CBOR ---------------------------------------------------------------------

/** A CBOR tag around a value. */
export class Tag {
  constructor(tag, value) { this.tag = tag; this.value = value }
}
/** A map written with indefinite length, the way serde_cbor in the NSM writes the payload. */
export class Indefinite {
  constructor(map) { this.map = map }
}
/** An unsigned integer forced into the 8-byte form, the way the NSM writes the timestamp. */
export class Uint64 {
  constructor(value) { this.value = BigInt(value) }
}
/** Raw bytes spliced into the encoding as they are. */
export class Raw {
  constructor(bytes) { this.bytes = Buffer.from(bytes) }
}

function head(major, n) {
  const m = major << 5
  if (n < 24) return Buffer.from([m | n])
  if (n < 256) return Buffer.from([m | 24, n])
  if (n < 65536) return Buffer.from([m | 25, n >> 8, n & 255])
  if (n < 2 ** 32) { const b = Buffer.alloc(5); b[0] = m | 26; b.writeUInt32BE(n, 1); return b }
  const b = Buffer.alloc(9); b[0] = m | 27; b.writeBigUInt64BE(BigInt(n), 1); return b
}

export function cbor(value) {
  if (value instanceof Raw) return value.bytes
  if (value === null) return Buffer.from([0xf6])
  if (value === true) return Buffer.from([0xf5])
  if (value === false) return Buffer.from([0xf4])
  if (value instanceof Uint64) { const b = Buffer.alloc(9); b[0] = 0x1b; b.writeBigUInt64BE(value.value, 1); return b }
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) { const b = Buffer.alloc(9); b[0] = 0xfb; b.writeDoubleBE(value, 1); return b }
    return value >= 0 ? head(0, value) : head(1, -1 - value)
  }
  if (typeof value === 'string') { const b = Buffer.from(value, 'utf8'); return Buffer.concat([head(3, b.length), b]) }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value])
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)])
  if (value instanceof Tag) return Buffer.concat([head(6, value.tag), cbor(value.value)])
  if (value instanceof Indefinite) {
    return Buffer.concat([Buffer.from([0xbf]), ...[...value.map].flatMap(([k, v]) => [cbor(k), cbor(v)]), Buffer.from([0xff])])
  }
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])])
  throw new Error('cbor: unsupported value')
}

// ---- documents ------------------------------------------------------------------

export const hex = bytes => Buffer.from(bytes).toString('hex')
export const NONCE = randomBytes(32)
export const READER_KEY = randomBytes(32) // stands in for the per-request X25519 public key
export const RESOURCE = 'https://mcp.wappie.thehappie.co/mcp'
export const REQUEST_ID = 'AAAAAAAAAAAAAAAAAAAAAA'
export const POLICY = 'b'.repeat(64)
export const FIELDS = { request_id: REQUEST_ID, resource: RESOURCE, reader_version: '0.2.0', tls_spki_sha256: 'a'.repeat(64), policy_sha256: POLICY }

/** SHA-256 of the user_data preimage (docs/mcp-enclave.md 6.2), computed apart from the verifier. */
export function userData(fields) {
  const preimage = ['wappie-mcp-attest/v1', fields.request_id, fields.resource, fields.tls_spki_sha256, fields.policy_sha256, fields.reader_version].join('\0')
  return createHash('sha256').update(preimage, 'utf8').digest()
}

// Like the NSM: 16 PCRs of 48 bytes, with 0-4 and 8 measured and the rest zero.
const MEASURED = [0, 1, 2, 3, 4, 8]
export const makePcrs = (zero = false) =>
  new Map(Array.from({ length: 16 }, (_, i) => [i, !zero && MEASURED.includes(i) ? randomBytes(48) : Buffer.alloc(48)]))

/** The allowlist entry that matches a document's PCRs. */
export const entryFor = (pcrs, version = '0.2.0') => ({ version, pcrs: { 0: hex(pcrs.get(0)), 1: hex(pcrs.get(1)), 2: hex(pcrs.get(2)) } })

/**
 * A signed document. set replaces payload fields, drop removes them, tag is 18
 * or null for the untagged form, header is the protected header, mangle edits
 * the COSE array after signing.
 */
export function buildDoc(pki, { set = {}, drop = [], tag = 18, header = new Map([[1, -35]]), signingKey = pki.keys.leaf.privateKey, pcrs = makePcrs(), fields = FIELDS, indefinite = true, mangle } = {}) {
  const doc = new Map([
    ['module_id', 'i-0123456789abcdef0-enc0123456789abcdef'],
    ['digest', 'SHA384'],
    ['timestamp', new Uint64(NOW)],
    ['pcrs', pcrs],
    ['certificate', pki.leaf],
    ['cabundle', pki.cabundle],
    ['public_key', READER_KEY],
    ['user_data', userData(fields)],
    ['nonce', NONCE],
  ])
  for (const [key, value] of Object.entries(set)) doc.set(key, value)
  for (const key of drop) doc.delete(key)
  const protectedBytes = cbor(header)
  const payload = cbor(indefinite ? new Indefinite(doc) : doc)
  const toBeSigned = cbor(['Signature1', protectedBytes, Buffer.alloc(0), payload])
  const cose = [protectedBytes, new Map(), payload, sign('sha384', toBeSigned, { key: signingKey, dsaEncoding: 'ieee-p1363' })]
  mangle?.(cose)
  return { raw: new Uint8Array(cbor(tag === null ? cose : new Tag(tag, cose))), pcrs }
}

/** verifyAttestation options that accept buildDoc(pki) as it is. */
export const optionsFor = (pki, pcrs, extra = {}) => ({
  nonce: NONCE,
  allow: [entryFor(pcrs)],
  policies: [POLICY],
  requestId: REQUEST_ID,
  resource: RESOURCE,
  requirePublicKey: true,
  now: NOW,
  rootDer: pki.root,
  ...extra,
})
