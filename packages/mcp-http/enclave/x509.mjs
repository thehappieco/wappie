// The few X.509 structures the enclave has to write itself, as plain DER:
// the PKCS#10 request for its certificate and the RFC 8737 self-signed
// certificate that answers a TLS-ALPN-01 challenge. Node signs (ECDSA P-256
// with SHA-256, DER signatures as X.509 wants them) and parses certificates
// (X509Certificate); only the encoding is here, so no ASN.1 library enters
// the image for it.
import { createHash, createPublicKey, randomBytes, sign as signData } from 'node:crypto'

// ---- DER --------------------------------------------------------------------
function length(n) {
  if (n < 0x80) return Buffer.from([n])
  const bytes = []
  for (let value = n; value > 0; value = Math.floor(value / 256)) bytes.unshift(value & 0xff)
  return Buffer.from([0x80 | bytes.length, ...bytes])
}
export const tlv = (tag, ...contents) => { const body = Buffer.concat(contents); return Buffer.concat([Buffer.from([tag]), length(body.length), body]) }
export const seq = (...items) => tlv(0x30, ...items)
export const set = (...items) => tlv(0x31, ...items)
export const octets = bytes => tlv(0x04, bytes)
export const utf8 = text => tlv(0x0c, Buffer.from(text, 'utf8'))
export const bool = value => tlv(0x01, Buffer.from([value ? 0xff : 0]))
export const bits = bytes => tlv(0x03, Buffer.from([0]), bytes)
export const explicit = (n, ...items) => tlv(0xa0 | n, ...items)
/** A non-negative INTEGER from big-endian bytes (a leading 0x00 keeps it positive). */
export function integer(bytes) {
  let value = Buffer.from(bytes)
  while (value.length > 1 && value[0] === 0 && value[1] < 0x80) value = value.subarray(1)
  if (value[0] >= 0x80) value = Buffer.concat([Buffer.from([0]), value])
  return tlv(0x02, value)
}
export function oid(text) {
  const parts = text.split('.').map(Number)
  const out = [parts[0] * 40 + parts[1]]
  for (const part of parts.slice(2)) {
    const chunk = []
    let value = part
    do { chunk.unshift(value & 0x7f); value = Math.floor(value / 128) } while (value > 0)
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] |= 0x80
    out.push(...chunk)
  }
  return tlv(0x06, Buffer.from(out))
}
function time(ms) {
  // UTCTime through 2049, GeneralizedTime after (RFC 5280 §4.1.2.5).
  const iso = new Date(ms).toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z'
  const year = new Date(ms).getUTCFullYear()
  return year < 2050 ? tlv(0x17, Buffer.from(iso.slice(2), 'ascii')) : tlv(0x18, Buffer.from(iso, 'ascii'))
}

export const OID = {
  ecdsaWithSHA256: '1.2.840.10045.4.3.2', commonName: '2.5.4.3', subjectAltName: '2.5.29.17',
  extensionRequest: '1.2.840.113549.1.9.14', acmeIdentifier: '1.3.6.1.5.5.7.1.31', basicConstraints: '2.5.29.19',
}
const signatureAlgorithm = () => seq(oid(OID.ecdsaWithSHA256))
const name = commonName => seq(set(seq(oid(OID.commonName), utf8(commonName))))
const dnsNames = names => seq(...names.map(value => tlv(0x82, Buffer.from(value, 'ascii'))))
const extension = (id, critical, value) => seq(oid(id), ...(critical ? [bool(true)] : []), octets(value))

/** DER SubjectPublicKeyInfo of a KeyObject (public or private). */
export const spkiOf = key => createPublicKey(key).export({ type: 'spki', format: 'der' })

/** lowercase hex SHA-256 of a DER SubjectPublicKeyInfo: tls_spki_sha256. */
export const spkiSha256 = der => createHash('sha256').update(der).digest('hex')

/** A PKCS#10 CertificationRequest for `names` (first is the CN), signed with `privateKey` (EC P-256). */
export function certificationRequest(names, privateKey) {
  const info = seq(
    integer([0]), name(names[0]), spkiOf(privateKey),
    explicit(0, seq(oid(OID.extensionRequest), set(seq(extension(OID.subjectAltName, false, dnsNames(names)))))),
  )
  return seq(info, signatureAlgorithm(), bits(signData('sha256', info, privateKey)))
}

/**
 * A self-signed certificate for the public half of `privateKey`. `names` go
 * in subjectAltName (the first is also the CN); `extensions` are DER
 * Extension SEQUENCEs; `ca` marks a test trust anchor.
 */
export function selfSigned({ names, privateKey, notBefore, notAfter, extensions = [], ca = false }) {
  const serial = randomBytes(16)
  serial[0] &= 0x7f
  const tbs = seq(
    explicit(0, integer([2])), integer(serial), signatureAlgorithm(), name(names[0]),
    seq(time(notBefore), time(notAfter)), name(names[0]), spkiOf(privateKey),
    explicit(3, seq(extension(OID.subjectAltName, false, dnsNames(names)), ...(ca ? [extension(OID.basicConstraints, true, seq(bool(true)))] : []), ...extensions)),
  )
  return seq(tbs, signatureAlgorithm(), bits(signData('sha256', tbs, privateKey)))
}

/**
 * The RFC 8737 challenge certificate for `domain`: its only name is the
 * domain, and the critical id-pe-acmeIdentifier extension carries the SHA-256
 * of the key authorization as an OCTET STRING.
 */
export function alpnChallengeCertificate({ domain, keyAuthorization, privateKey, now = Date.now() }) {
  const digest = createHash('sha256').update(keyAuthorization, 'utf8').digest()
  return selfSigned({ names: [domain], privateKey, notBefore: now - 3_600_000, notAfter: now + 7 * 86_400_000, extensions: [extension(OID.acmeIdentifier, true, octets(digest))] })
}

export const pem = (label, der) => `-----BEGIN ${label}-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`
