// Writes the two attestation-document fixtures nsm-timefeed's decoder is
// tested against, with a CBOR encoder written here rather than the Rust
// side's, so a decoding bug cannot be mirrored by the fixture:
//   attest-tag18.doc     COSE_Sign1 with tag 18 in front
//   attest-untagged.doc  the same array without the tag (what the NSM sends)
// The shape is a real NSM document's (the payload fields and types of
// aws-nitro-enclaves-nsm-api's AttestationDoc, sixteen 48-byte PCRs, an ES384
// protected header); the values are fixed so the files never change, and the
// signature and certificates are placeholders (nsm-timefeed does not check
// them). packages/mcp-http/test/vectors/attest-v2.json has no real document
// to copy (its documents are placeholders), hence this script.
//   node deploy/enclave/nsm-attest/tests/fixtures/make-fixtures.mjs
import { writeFileSync } from 'node:fs'

function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n])
  if (n < 256) return Buffer.from([(major << 5) | 24, n])
  if (n < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b }
  if (n < 2 ** 32) { const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b }
  const b = Buffer.alloc(9); b[0] = (major << 5) | 27; b.writeBigUInt64BE(BigInt(n), 1); return b
}
function cbor(value) {
  if (value === null) return Buffer.from([0xf6])
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value)
  if (typeof value === 'string') { const bytes = Buffer.from(value, 'utf8'); return Buffer.concat([head(3, bytes.length), bytes]) }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value])
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)])
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])])
  if (value && value.tag !== undefined) return Buffer.concat([head(6, value.tag), cbor(value.value)])
  throw new Error('cbor: unsupported')
}

// Kept in step with tests/cose.rs.
const TIMESTAMP = Date.parse('2026-11-19T12:00:00Z')
const NONCE = Buffer.from([...Array(32).keys()])
const pcrs = new Map([...Array(16).keys()].map(i => [i, Buffer.alloc(48, i === 0 ? 0xab : i < 4 ? i : 0)]))
const payload = new Map([
  ['module_id', 'i-0123456789abcdef0-enc0123456789abcdef'],
  ['digest', 'SHA384'],
  ['timestamp', TIMESTAMP],
  ['pcrs', pcrs],
  ['certificate', Buffer.alloc(16, 0xce)],
  ['cabundle', [Buffer.alloc(16, 0xca)]],
  ['public_key', null],
  ['user_data', null],
  ['nonce', NONCE],
])
const sign1 = [cbor(new Map([[1, -35]])), new Map(), cbor(payload), Buffer.alloc(96, 0x5e)]
const dir = new URL('./', import.meta.url)
writeFileSync(new URL('attest-untagged.doc', dir), cbor(sign1))
writeFileSync(new URL('attest-tag18.doc', dir), cbor({ tag: 18, value: sign1 }))
