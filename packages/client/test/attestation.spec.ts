// The attestation verifier against real Nitro documents from the spike (Day 3,
// testdata/attestation) and a synthetic chain built with node:crypto
// (attestationFixtures.mjs). Each negative changes exactly one thing, so the
// code it expects is the check that caught it.
import { describe, expect, it } from 'vitest'
import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import * as client from '../src/index.js'
import {
  AttestationError,
  attestationUserData,
  awsNitroRoot,
  decodeAttestationDocument,
  verifyAttestation,
  type AllowEntry,
  type AttestationCode,
  type AttestationFields,
  type VerifyOptions,
} from '../src/crypto/attestation.js'
import {
  DAY,
  DIGITAL_SIGNATURE,
  FIELDS,
  HOUR,
  KEY_CERT_SIGN,
  NONCE,
  NOW,
  OID,
  POLICY,
  READER_KEY,
  RESOURCE,
  Raw,
  buildDoc,
  buildPki,
  cbor,
  der,
  entryFor,
  extension,
  hex,
  makeCert,
  makePcrs,
  optionsFor,
  p256,
  p384,
  userData,
} from './attestationFixtures.mjs'

const dir = fileURLToPath(new URL('../testdata/attestation/', import.meta.url))
const b64file = (name: string) => new Uint8Array(Buffer.from(readFileSync(dir + name, 'utf8').trim(), 'base64'))
const hexfile = (name: string) => new Uint8Array(Buffer.from(readFileSync(dir + name, 'utf8').trim(), 'hex'))

async function codeOf(run: () => Promise<unknown>): Promise<AttestationCode | 'passed'> {
  try {
    await run()
    return 'passed'
  } catch (error) {
    if (error instanceof AttestationError) return error.code
    throw error
  }
}

// ---- real documents ------------------------------------------------------------

describe('real Nitro documents (spike Day 3)', () => {
  const doc = b64file('att.b64')
  const nonce = hexfile('att.nonce')
  const debugDoc = b64file('att-debug.b64')
  const debugNonce = hexfile('att-debug.nonce')
  const m = JSON.parse(readFileSync(dir + 'measurements.json', 'utf8')).Measurements
  const allow: AllowEntry[] = [{ version: '0.2.0', pcrs: { 0: m.PCR0, 1: m.PCR1, 2: m.PCR2 } }]
  const at = decodeAttestationDocument(doc).timestamp
  // The spike's documents predate user_data: every check before it runs on real
  // bytes, and user_data is where they stop. The synthetic chain covers the rest.
  const fields: AttestationFields = { ...FIELDS, request_id: '' }
  const options = (extra: Partial<VerifyOptions> = {}): VerifyOptions => ({
    nonce, allow, policies: [POLICY], requestId: '', resource: RESOURCE, requirePublicKey: false, now: at, ...extra,
  })

  it('pins the AWS root by its published fingerprint, and it heads the real chain', () => {
    const root = awsNitroRoot()
    expect(createHash('sha256').update(root).digest('hex')).toBe('641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b')
    expect(Buffer.from(doc).indexOf(Buffer.from(root))).toBeGreaterThan(0)
  })

  it('decodes without trusting: PCRs, nonce, key and timestamp', () => {
    const d = decodeAttestationDocument(doc)
    expect(d.pcrs[0]).toBe(m.PCR0)
    expect(d.pcrs[1]).toBe(m.PCR1)
    expect(d.pcrs[2]).toBe(m.PCR2)
    expect(Buffer.from(d.nonce!).equals(Buffer.from(nonce))).toBe(true)
    expect(d.userData).toBeNull()
    expect(d.publicKey?.length).toBe(294) // the spike's RSA SPKI (KMS recipient shape)
    expect(d.moduleId).toBe('i-05cdefb4833fdf39e-enc01a0d45160bb15e8')
    expect(d.timestamp).toBe(1790268502945)
  })

  it('passes signature, chain, root, clock, measurement and nonce, and stops at user_data', async () => {
    expect(doc[0]).toBe(0x84) // the NSM writes it untagged
    expect(await codeOf(() => verifyAttestation(doc, fields, options()))).toBe('attestation_user_data')
  })

  it('accepts the tagged form of the same document', async () => {
    const tagged = new Uint8Array([0xd2, ...doc])
    expect(await codeOf(() => verifyAttestation(tagged, fields, options()))).toBe('attestation_user_data')
  })

  it('refuses a flipped payload byte as a bad signature', async () => {
    const copy = doc.slice()
    const pcr0 = Buffer.from(m.PCR0, 'hex')
    const where = Buffer.from(copy).indexOf(pcr0) + 24
    copy[where] ^= 1
    expect(await codeOf(() => verifyAttestation(copy, fields, options()))).toBe('attestation_signature')
  })

  it('refuses another nonce', async () => {
    const other = nonce.slice()
    other[0] ^= 0xff
    expect(await codeOf(() => verifyAttestation(doc, fields, options({ nonce: other })))).toBe('attestation_nonce')
  })

  it('refuses a browser clock 11 minutes off, in either direction', async () => {
    expect(await codeOf(() => verifyAttestation(doc, fields, options({ now: at + 11 * 60_000 })))).toBe('attestation_clock')
    expect(await codeOf(() => verifyAttestation(doc, fields, options({ now: at - 11 * 60_000 })))).toBe('attestation_clock')
  })

  it('refuses once the leaf has expired', async () => {
    // The leaf lives three hours; the skew allowance is opened wide so only validity can refuse.
    const later = at + 4 * HOUR
    expect(await codeOf(() => verifyAttestation(doc, fields, options({ now: later, maxSkewMs: 5 * HOUR })))).toBe('attestation_validity')
  })

  it('refuses PCRs outside the allowlist, and an empty allowlist', async () => {
    const other = [{ version: '0.2.0', pcrs: { ...allow[0].pcrs, 2: 'ab'.repeat(48) } }]
    expect(await codeOf(() => verifyAttestation(doc, fields, options({ allow: other })))).toBe('attestation_measurement')
    expect(await codeOf(() => verifyAttestation(doc, fields, options({ allow: [] })))).toBe('attestation_measurement')
  })

  it('refuses another root', async () => {
    const root = awsNitroRoot().slice()
    root[root.length - 5] ^= 1
    expect(await codeOf(() => verifyAttestation(doc, fields, options({ rootDer: root })))).toBe('attestation_root')
  })

  it('refuses a debug-mode document (zero PCR0 to PCR2)', async () => {
    const d = decodeAttestationDocument(debugDoc)
    expect(d.pcrs[0]).toBe('0'.repeat(96))
    const run = () => verifyAttestation(debugDoc, fields, options({ nonce: debugNonce, now: d.timestamp }))
    expect(await codeOf(run)).toBe('attestation_debug')
  })

  it('refuses trailing bytes and a document over 16 KiB', async () => {
    expect(await codeOf(() => verifyAttestation(new Uint8Array([...doc, 0]), fields, options()))).toBe('attestation_format')
    const big = new Uint8Array(16 * 1024 + 1)
    big.set(doc)
    expect(await codeOf(() => verifyAttestation(big, fields, options()))).toBe('attestation_format')
  })
})

// ---- user_data -----------------------------------------------------------------

describe('attestationUserData', () => {
  it('matches the contract vector', async () => {
    const fields = { request_id: 'AAAAAAAAAAAAAAAAAAAAAA', resource: RESOURCE, tls_spki_sha256: 'a'.repeat(64), policy_sha256: 'b'.repeat(64), reader_version: '0.2.0' }
    expect(hex(await attestationUserData(fields))).toBe('a63c1d0bc8fd8789d35f08c48db83edc71e71ae751d624ff9159fa5c3d50aad8')
    expect(hex(await attestationUserData(fields))).toBe(hex(userData(fields)))
  })

  it('refuses a field with a NUL, a bad version or a bad hash', async () => {
    expect(await codeOf(() => attestationUserData({ ...FIELDS, resource: 'a\0b' }))).toBe('attestation_user_data')
    expect(await codeOf(() => attestationUserData({ ...FIELDS, reader_version: 'v0.2' }))).toBe('attestation_version')
    expect(await codeOf(() => attestationUserData({ ...FIELDS, tls_spki_sha256: 'A'.repeat(64) }))).toBe('attestation_user_data')
    expect(await codeOf(() => attestationUserData({ ...FIELDS, policy_sha256: 'b'.repeat(63) }))).toBe('attestation_user_data')
  })
})

// ---- synthetic chain -----------------------------------------------------------

const pki = buildPki()

async function verifySynthetic(change: Parameters<typeof buildDoc>[1] = {}, extra: Partial<VerifyOptions> = {}, fields: AttestationFields = FIELDS, from = pki) {
  const { raw, pcrs } = buildDoc(from, change)
  return verifyAttestation(raw, fields, optionsFor(from, pcrs, extra))
}
const refusal = (...args: Parameters<typeof verifySynthetic>) => codeOf(() => verifySynthetic(...args))

describe('genuine synthetic documents', () => {
  it('pass tagged and return the attested key, entry and fields', async () => {
    const { raw, pcrs } = buildDoc(pki)
    expect(raw[0]).toBe(0xd2)
    const result = await verifyAttestation(raw, { ...FIELDS, extra: 'ignored' } as AttestationFields, optionsFor(pki, pcrs))
    expect(Buffer.from(result.publicKey!).equals(READER_KEY)).toBe(true)
    expect(result.entry).toEqual(entryFor(pcrs))
    expect(result.pcrs).toEqual(entryFor(pcrs).pcrs)
    expect(result.timestamp).toBe(NOW)
    expect(result.moduleId).toBe('i-0123456789abcdef0-enc0123456789abcdef')
    expect(result.documentSha256).toBe(createHash('sha256').update(raw).digest('hex'))
    expect(result.fields).toEqual(FIELDS)
  })

  it('pass untagged, and with a definite-length payload map', async () => {
    expect(await refusal({ tag: null })).toBe('passed')
    expect(await refusal({ indefinite: false })).toBe('passed')
  })

  it('pass for the public route: no request id and no key', async () => {
    const fields = { ...FIELDS, request_id: '' }
    expect(await refusal({ drop: ['public_key'], fields }, { requestId: '', requirePublicKey: false }, fields)).toBe('passed')
    expect(await refusal({ set: { public_key: null }, fields }, { requestId: '', requirePublicKey: false }, fields)).toBe('passed')
  })

  it('pick the entry whose version is the attested one', async () => {
    const { raw, pcrs } = buildDoc(pki)
    const allow = [entryFor(pcrs, '0.1.9'), entryFor(pcrs, '0.2.0')]
    const result = await verifyAttestation(raw, FIELDS, optionsFor(pki, pcrs, { allow }))
    expect(result.entry.version).toBe('0.2.0')
  })

  it('accept the clock at exactly maxSkewMs, both ways', async () => {
    expect(await refusal({}, { now: NOW + 600_000 })).toBe('passed')
    expect(await refusal({}, { now: NOW - 600_000 })).toBe('passed')
  })

  it('are exported from the package entry as attestation', () => {
    expect(client.attestation.verifyAttestation).toBe(verifyAttestation)
    expect(client.attestation.AttestationError).toBe(AttestationError)
  })
})

describe('COSE envelope', () => {
  it('refuses a tag other than 18', async () => expect(await refusal({ tag: 98 })).toBe('attestation_format'))
  it('refuses bytes that are not CBOR', async () => {
    const { pcrs } = buildDoc(pki)
    expect(await codeOf(() => verifyAttestation(new Uint8Array(randomBytes(64)), FIELDS, optionsFor(pki, pcrs)))).toBe('attestation_format')
  })
  it('refuses an array that is not a 4-element COSE_Sign1', async () => {
    expect(await refusal({ mangle: cose => cose.pop() })).toBe('attestation_format')
  })
  it('refuses alg ES256 and a missing alg', async () => {
    expect(await refusal({ header: new Map([[1, -7]]) })).toBe('attestation_signature')
    expect(await refusal({ header: new Map() })).toBe('attestation_signature')
  })
  it('refuses a payload that is not a map', async () => {
    expect(await refusal({ mangle: cose => { cose[2] = cbor([1, 2]) } })).toBe('attestation_format')
  })
  it('refuses floats, duplicate keys and nested tags in the payload', async () => {
    expect(await refusal({ set: { timestamp: 1.5 } })).toBe('attestation_format')
    expect(await refusal({ set: { module_id: new Raw([0xc1, 0x00]) } })).toBe('attestation_format')
    const dup = cbor(new Map([['digest', 'SHA384']]))
    expect(await refusal({ mangle: cose => { cose[2] = Buffer.concat([Buffer.from([0xa2]), dup.subarray(1), dup.subarray(1)]) } })).toBe('attestation_format')
  })
})

describe('signature', () => {
  it('refuses one flipped signature byte', async () => {
    expect(await refusal({ mangle: cose => { cose[3][0] ^= 1 } })).toBe('attestation_signature')
  })
  it('refuses one flipped payload byte (inside PCR2)', async () => {
    const pcrs = makePcrs()
    const { raw } = buildDoc(pki, { pcrs })
    const copy = raw.slice()
    copy[Buffer.from(copy).indexOf(pcrs.get(2)) + 10] ^= 1
    expect(await codeOf(() => verifyAttestation(copy, FIELDS, optionsFor(pki, pcrs)))).toBe('attestation_signature')
  })
  it('refuses a document signed by a key other than the leaf', async () => {
    expect(await refusal({ signingKey: p384().privateKey })).toBe('attestation_signature')
  })
  it('refuses a truncated signature', async () => {
    expect(await refusal({ mangle: cose => { cose[3] = cose[3].subarray(0, 95) } })).toBe('attestation_signature')
  })
  it('refuses a leaf key that is not P-384', async () => {
    const leafKey = p256()
    const other = buildPki({ leafKey })
    expect(await refusal({ signingKey: leafKey.privateKey }, {}, FIELDS, other)).toBe('attestation_signature')
  })
})

describe('document fields and size limits', () => {
  const cases: [string, Parameters<typeof buildDoc>[1], AttestationCode][] = [
    ['no module_id', { drop: ['module_id'] }, 'attestation_format'],
    ['digest other than SHA384', { set: { digest: 'SHA256' } }, 'attestation_format'],
    ['no timestamp', { drop: ['timestamp'] }, 'attestation_format'],
    ['timestamp 0', { set: { timestamp: 0 } }, 'attestation_format'],
    ['pcrs not a map', { set: { pcrs: [] } }, 'attestation_format'],
    ['a PCR of 47 bytes', { set: { pcrs: new Map([[0, randomBytes(48)], [1, randomBytes(48)], [2, randomBytes(48)], [3, randomBytes(47)]]) } }, 'attestation_format'],
    ['no PCR2', { set: { pcrs: new Map([[0, randomBytes(48)], [1, randomBytes(48)]]) } }, 'attestation_format'],
    ['nonce over 512 bytes', { set: { nonce: randomBytes(513) } }, 'attestation_format'],
    ['user_data over 512 bytes', { set: { user_data: randomBytes(513) } }, 'attestation_format'],
    ['public_key over 1024 bytes', { set: { public_key: randomBytes(1025) } }, 'attestation_format'],
    ['certificate over 1024 bytes', { set: { certificate: randomBytes(1025) } }, 'attestation_format'],
    ['cabundle entry over 1024 bytes', { set: { cabundle: [pki.root, randomBytes(1025)] } }, 'attestation_format'],
    ['cabundle of 9 entries', { set: { cabundle: Array(9).fill(pki.root) } }, 'attestation_format'],
    ['empty cabundle', { set: { cabundle: [] } }, 'attestation_format'],
  ]
  for (const [name, change, code] of cases) it(`refuses ${name}`, async () => expect(await refusal(change)).toBe(code))
})

describe('certificate chain', () => {
  const chainCase = (o: Parameters<typeof buildPki>[0]) => {
    const other = buildPki(o)
    return refusal({}, {}, FIELDS, other)
  }
  it('refuses a document chained to a different root', async () => {
    const other = buildPki()
    const { raw, pcrs } = buildDoc(other)
    expect(await codeOf(() => verifyAttestation(raw, FIELDS, optionsFor(pki, pcrs)))).toBe('attestation_root')
  })
  it('refuses a cabundle out of order', async () => {
    expect(await refusal({ set: { cabundle: [pki.root, pki.int2, pki.int1] } })).toBe('attestation_chain')
  })
  it('refuses a missing intermediate', async () => {
    expect(await refusal({ set: { cabundle: [pki.root, pki.int1] } })).toBe('attestation_chain')
  })
  it('refuses a forged intermediate with the right name under the pinned root', async () => {
    const forger = p384()
    const int1 = makeCert({ ca: true, pathLen: 1, keyUsage: KEY_CERT_SIGN, notBefore: NOW - DAY, notAfter: NOW + DAY, subject: 'Test Regional', issuer: 'Test Nitro Root', publicKey: forger.publicKey, signingKey: forger.privateKey })
    expect(await refusal({ set: { cabundle: [pki.root, int1, pki.int2] } })).toBe('attestation_chain')
  })
  it('refuses a leaf that is a CA', async () => expect(await chainCase({ leaf: { ca: true } })).toBe('attestation_chain'))
  it('refuses a leaf with a pathLenConstraint', async () => expect(await chainCase({ leaf: { ca: false, pathLen: 0 } })).toBe('attestation_chain'))
  it('refuses a leaf without digitalSignature', async () => expect(await chainCase({ leaf: { keyUsage: KEY_CERT_SIGN } })).toBe('attestation_chain'))
  it('refuses a leaf without keyUsage', async () => expect(await chainCase({ leaf: { keyUsage: undefined } })).toBe('attestation_chain'))
  it('refuses an intermediate without keyCertSign', async () => expect(await chainCase({ int2: { keyUsage: DIGITAL_SIGNATURE } })).toBe('attestation_chain'))
  it('refuses an intermediate without keyUsage', async () => expect(await chainCase({ int1: { keyUsage: undefined } })).toBe('attestation_chain'))
  it('refuses an intermediate that is not a CA', async () => expect(await chainCase({ int2: { ca: false } })).toBe('attestation_chain'))
  it('refuses an intermediate without basicConstraints', async () => expect(await chainCase({ int1: { ca: undefined } })).toBe('attestation_chain'))
  it('refuses a root without keyCertSign', async () => expect(await chainCase({ root: { keyUsage: DIGITAL_SIGNATURE } })).toBe('attestation_chain'))
  it('refuses a pathLenConstraint violated by an intermediate', async () => expect(await chainCase({ int1: { pathLen: 0 } })).toBe('attestation_chain'))
  it('refuses a pathLenConstraint violated by the root', async () => expect(await chainCase({ root: { pathLen: 1 } })).toBe('attestation_chain'))
  it('accepts tight pathLenConstraints', async () => expect(await chainCase({ root: { pathLen: 2 } })).toBe('passed'))
  it('refuses an unknown critical extension', async () => {
    expect(await chainCase({ int2: { extensions: [extension('1.2.3.4', der(0x05), true)] } })).toBe('attestation_chain')
  })
  it('accepts an unknown non-critical extension', async () => {
    expect(await chainCase({ int2: { extensions: [extension('1.2.3.4', der(0x05))] } })).toBe('passed')
  })
  it('refuses a duplicated extension', async () => {
    expect(await chainCase({ leaf: { extensions: [extension(OID.keyUsage, der(0x03, [7, DIGITAL_SIGNATURE]), true)] } })).toBe('attestation_chain')
  })
  it('refuses an intermediate key that is not P-384', async () => {
    const rootKey = p384()
    const weak = p256()
    const root = makeCert({ ca: true, keyUsage: KEY_CERT_SIGN, notBefore: NOW - DAY, notAfter: NOW + DAY, subject: 'R', publicKey: rootKey.publicKey, signingKey: rootKey.privateKey })
    const int1 = makeCert({ ca: true, keyUsage: KEY_CERT_SIGN, notBefore: NOW - DAY, notAfter: NOW + DAY, subject: 'I', issuer: 'R', publicKey: weak.publicKey, signingKey: rootKey.privateKey })
    const leafKey = p384()
    const leaf = makeCert({ ca: false, keyUsage: DIGITAL_SIGNATURE, notBefore: NOW - HOUR, notAfter: NOW + HOUR, subject: 'L', issuer: 'I', publicKey: leafKey.publicKey, signingKey: weak.privateKey })
    const custom = { keys: { leaf: leafKey }, root, cabundle: [root, int1], leaf }
    const { raw, pcrs } = buildDoc(custom as never)
    expect(await codeOf(() => verifyAttestation(raw, FIELDS, optionsFor(custom, pcrs)))).toBe('attestation_chain')
  })
  it('refuses an expired leaf', async () => expect(await chainCase({ leaf: { notAfter: NOW - 1000 } })).toBe('attestation_validity'))
  it('refuses an intermediate that is not valid yet', async () => expect(await chainCase({ int1: { notBefore: NOW + HOUR } })).toBe('attestation_validity'))
  it('refuses an expired root', async () => expect(await chainCase({ root: { notAfter: NOW - DAY } })).toBe('attestation_validity'))
})

describe('clock', () => {
  it('refuses a document older or newer than maxSkewMs', async () => {
    expect(await refusal({}, { now: NOW + 600_001 })).toBe('attestation_clock')
    expect(await refusal({}, { now: NOW - 600_001 })).toBe('attestation_clock')
    expect(await refusal({}, { now: NOW + 10_001, maxSkewMs: 10_000 })).toBe('attestation_clock')
  })
})

describe('measurements', () => {
  it('refuses an all-zero PCR0, even when the allowlist names it', async () => {
    const pcrs = makePcrs()
    pcrs.set(0, Buffer.alloc(48))
    const { raw } = buildDoc(pki, { pcrs })
    expect(await codeOf(() => verifyAttestation(raw, FIELDS, optionsFor(pki, pcrs)))).toBe('attestation_debug')
  })
  it('refuses a fully zeroed (debug-mode) document', async () => {
    const pcrs = makePcrs(true)
    const { raw } = buildDoc(pki, { pcrs })
    expect(await codeOf(() => verifyAttestation(raw, FIELDS, optionsFor(pki, pcrs)))).toBe('attestation_debug')
  })
  it('refuses a PCR outside the allowlist', async () => {
    const { raw, pcrs } = buildDoc(pki)
    const entry = entryFor(pcrs)
    for (const i of [0, 1, 2] as const) {
      const allow = [{ ...entry, pcrs: { ...entry.pcrs, [i]: 'cd'.repeat(48) } }]
      expect(await codeOf(() => verifyAttestation(raw, FIELDS, optionsFor(pki, pcrs, { allow })))).toBe('attestation_measurement')
    }
  })
  it('refuses a release whose version is not the attested one', async () => {
    const { raw, pcrs } = buildDoc(pki)
    expect(await codeOf(() => verifyAttestation(raw, FIELDS, optionsFor(pki, pcrs, { allow: [entryFor(pcrs, '0.2.1')] })))).toBe('attestation_version')
  })
})

describe('allowlist shape', () => {
  const { raw, pcrs } = buildDoc(pki)
  const entry = entryFor(pcrs)
  const bad: [string, unknown][] = [
    ['{}', {}],
    ['only PCR1', { version: '0.2.0', pcrs: { 1: entry.pcrs[1] } }],
    ['empty pcrs', { version: '0.2.0', pcrs: {} }],
    ['PCR3 added', { ...entry, pcrs: { ...entry.pcrs, 3: entry.pcrs[0] } }],
    ['upper-case hex', { ...entry, pcrs: { ...entry.pcrs, 0: entry.pcrs[0].toUpperCase() } }],
    ['95 hex characters', { ...entry, pcrs: { ...entry.pcrs, 1: entry.pcrs[1].slice(1) } }],
    ['no version', { pcrs: entry.pcrs }],
    ['version not x.y.z', { ...entry, version: 'v0.2.0' }],
    ['pcrs as a Map', { version: '0.2.0', pcrs: new Map(Object.entries(entry.pcrs)) }],
    ['null', null],
  ]
  for (const [name, value] of bad) {
    it(`refuses an entry with ${name}`, async () => {
      // A good entry next to it: one malformed entry is a broken build, not a partial match.
      const allow = [entry, value] as AllowEntry[]
      expect(await codeOf(() => verifyAttestation(raw, FIELDS, optionsFor(pki, pcrs, { allow })))).toBe('attestation_allowlist')
    })
  }
  it('ignores other keys on an entry, such as the generated module\'s release fields', async () => {
    const allow = [{ ...entry, release_url: 'https://github.com/thehappieco/wappie/releases/tag/reader-v0.2.0', measurements_sha256: 'f'.repeat(64) }]
    expect(await codeOf(() => verifyAttestation(raw, FIELDS, optionsFor(pki, pcrs, { allow })))).toBe('passed')
  })
  it('refuses an allowlist that is not an array', async () => {
    expect(await codeOf(() => verifyAttestation(raw, FIELDS, optionsFor(pki, pcrs, { allow: { 0: entry } as never })))).toBe('attestation_allowlist')
  })
})

describe('request, policy, nonce, user_data and key', () => {
  it('refuses fields for another request or resource', async () => {
    const other = { ...FIELDS, request_id: 'BBBBBBBBBBBBBBBBBBBBBB' }
    expect(await refusal({}, {}, other)).toBe('attestation_request')
    expect(await refusal({}, {}, { ...FIELDS, resource: 'https://api.wappie.thehappie.co/mcp' })).toBe('attestation_request')
    expect(await refusal({}, { resource: 'https://api.wappie.thehappie.co/mcp' })).toBe('attestation_request')
  })
  it('refuses a policy hash that was not published', async () => {
    expect(await refusal({}, { policies: ['c'.repeat(64)] })).toBe('attestation_policy')
    expect(await refusal({}, { policies: [] })).toBe('attestation_policy')
  })
  it('refuses a missing, shorter or different nonce', async () => {
    expect(await refusal({ drop: ['nonce'] })).toBe('attestation_nonce')
    expect(await refusal({ set: { nonce: NONCE.subarray(0, 16) } })).toBe('attestation_nonce')
    expect(await refusal({}, { nonce: new Uint8Array(randomBytes(32)) })).toBe('attestation_nonce')
  })
  // Each: the document committed to FIELDS, the descriptor claims something else
  // that the request, resource and policy checks accept.
  it('refuses user_data made for another request id', async () => {
    const claimed = { ...FIELDS, request_id: 'CCCCCCCCCCCCCCCCCCCCCC' }
    expect(await refusal({}, { requestId: claimed.request_id }, claimed)).toBe('attestation_user_data')
  })
  it('refuses user_data made for another resource', async () => {
    const claimed = { ...FIELDS, resource: 'https://mcp.example.test/mcp' }
    expect(await refusal({}, { resource: claimed.resource }, claimed)).toBe('attestation_user_data')
  })
  it('refuses user_data made for another TLS key', async () => {
    expect(await refusal({}, {}, { ...FIELDS, tls_spki_sha256: 'd'.repeat(64) })).toBe('attestation_user_data')
  })
  it('refuses user_data made under another policy', async () => {
    const claimed = { ...FIELDS, policy_sha256: 'e'.repeat(64) }
    expect(await refusal({}, { policies: [POLICY, claimed.policy_sha256] }, claimed)).toBe('attestation_user_data')
  })
  it('refuses a missing or short user_data', async () => {
    expect(await refusal({ drop: ['user_data'] })).toBe('attestation_user_data')
    expect(await refusal({ set: { user_data: userData(FIELDS).subarray(0, 31) } })).toBe('attestation_user_data')
  })
  it('refuses a request document without a 32-byte key', async () => {
    expect(await refusal({ drop: ['public_key'] })).toBe('attestation_public_key')
    expect(await refusal({ set: { public_key: randomBytes(33) } })).toBe('attestation_public_key')
    expect(await refusal({ set: { public_key: randomBytes(294) } })).toBe('attestation_public_key')
  })
  it('refuses a key on the public route', async () => {
    const fields = { ...FIELDS, request_id: '' }
    expect(await refusal({ fields }, { requestId: '', requirePublicKey: false }, fields)).toBe('attestation_public_key')
  })
  it('returns a key the console can compare with reader_public_key', async () => {
    const result = await verifySynthetic()
    expect(Buffer.from(result.publicKey!).equals(READER_KEY)).toBe(true)
    expect(Buffer.from(result.publicKey!).equals(randomBytes(32))).toBe(false)
  })
})

describe('options', () => {
  const cases: [string, Partial<VerifyOptions>, AttestationCode][] = [
    ['a 15-byte nonce', { nonce: new Uint8Array(15) }, 'attestation_nonce'],
    ['a 65-byte nonce', { nonce: new Uint8Array(65) }, 'attestation_nonce'],
    ['a nonce that is not bytes', { nonce: 'abc' as never }, 'attestation_nonce'],
    ['a malformed policy hash', { policies: ['B'.repeat(64)] }, 'attestation_policy'],
    ['policies that are not an array', { policies: 'b' as never }, 'attestation_policy'],
    ['a malformed request id', { requestId: 'short' }, 'attestation_request'],
    ['an empty resource', { resource: '' }, 'attestation_request'],
    ['a NaN clock', { now: Number.NaN }, 'attestation_clock'],
    ['a negative skew', { maxSkewMs: -1 }, 'attestation_clock'],
    ['requirePublicKey missing', { requirePublicKey: undefined as never }, 'attestation_public_key'],
    ['a root that is not bytes', { rootDer: 'pem' as never }, 'attestation_root'],
  ]
  for (const [name, extra, code] of cases) it(`refuses ${name}`, async () => expect(await refusal({}, extra)).toBe(code))
  it('refuses fields that are not strings', async () => {
    expect(await refusal({}, {}, { ...FIELDS, policy_sha256: 7 } as never)).toBe('attestation_user_data')
    expect(await refusal({}, {}, null as never)).toBe('attestation_user_data')
  })
  it('uses the pinned AWS root when none is given', async () => {
    const { raw, pcrs } = buildDoc(pki)
    expect(await codeOf(() => verifyAttestation(raw, FIELDS, { ...optionsFor(pki, pcrs), rootDer: undefined }))).toBe('attestation_root')
  })
})
