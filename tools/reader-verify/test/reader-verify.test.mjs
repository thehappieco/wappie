// reader-verify against a synthetic enclave: documents from the verifier's own
// test fixtures (packages/client/test/attestationFixtures.mjs), served by a stub
// GET /attestation that binds whatever nonce the CLI sent. No network.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { X509Certificate, createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { createServer } from 'node:https'
import { join } from 'node:path'
import tls from 'node:tls'
import { fileURLToPath } from 'node:url'
import { main, requestAttestation } from '../reader-verify.mjs'
import {
  DAY, DIGITAL_SIGNATURE, FIELDS, KEY_CERT_SIGN, NOW, RESOURCE,
  buildDoc, buildPki, der, extension, hex, makeCert, makePcrs, p384,
} from '../../../packages/client/test/attestationFixtures.mjs'

const CLI = fileURLToPath(new URL('../reader-verify.mjs', import.meta.url))
const pki = buildPki()
const pcrs = makePcrs()
const SPKI = 'a'.repeat(64)
const STEADY = 'b'.repeat(64)
const TRANSITION = 'c'.repeat(64)
const fields = { ...FIELDS, request_id: '', policy_sha256: STEADY }

function measurements(over = {}) {
  return JSON.stringify({
    schema: 'wappie-reader-measurements/v1', reader_id: 'enclave', version: '0.2.0', resource: RESOURCE,
    source: { repository: 'thehappieco/wappie', commit: '0'.repeat(40) },
    pcrs: { 0: hex(pcrs.get(0)), 1: hex(pcrs.get(1)), 2: hex(pcrs.get(2)) },
    policies: [{ phase: 'transition', file: 't.json', sha256: TRANSITION }, { phase: 'steady', file: 's.json', sha256: STEADY }],
    ...over,
  })
}

const dir = mkdtempSync(join(tmpdir(), 'reader-verify-'))
function file(name, text) {
  const path = join(dir, name)
  writeFileSync(path, text)
  return path
}

// The stub reader: a fresh document per call, over this call's nonce.
function reader({ status = 200, served = SPKI, useNonce = true, docFields = fields, body } = {}) {
  return async (host, nonce) => {
    assert.equal(host, 'mcp.wappie.thehappie.co')
    assert.match(nonce, /^[A-Za-z0-9_-]{43}$/)
    const set = useNonce ? { nonce: Buffer.from(nonce, 'base64url') } : {}
    const { raw } = buildDoc(pki, { pcrs, set, drop: ['public_key'], fields: docFields })
    const attestation = { format: 'aws-nitro-v1', document: Buffer.from(raw).toString('base64url'), reader_id: 'enclave', pcr0: hex(pcrs.get(0)), ...fields }
    return { status, body: body ?? JSON.stringify({ attestation }), spkiSha256: served }
  }
}

async function run(argv, deps) {
  const lines = []
  const code = await main(argv, { now: NOW, rootDer: pki.root, ...deps }, line => lines.push(line))
  assert.equal(lines.length, 1, 'one line of output')
  return { code, result: JSON.parse(lines[0]) }
}

test('a genuine reader passes and the result names the release and policy', async () => {
  const { code, result } = await run(['--measurements', file('m.json', measurements())], { requestAttestation: reader() })
  assert.equal(code, 0)
  assert.equal(result.ok, true)
  assert.equal(result.reader_version, '0.2.0')
  assert.equal(result.pcr0, hex(pcrs.get(0)))
  assert.equal(result.policy_sha256, STEADY)
  assert.equal(result.policy_phase, 'steady')
  assert.equal(result.tls_spki_sha256, SPKI)
  assert.match(result.document_sha256, /^[0-9a-f]{64}$/)
})

test('a certificate key the document does not name is refused', async () => {
  const { code, result } = await run(['--measurements', file('m.json', measurements())], { requestAttestation: reader({ served: 'd'.repeat(64) }) })
  assert.equal(code, 1)
  assert.deepEqual(result, { ok: false, code: 'tls_spki_mismatch' })
})

test('a document over another nonce is refused', async () => {
  const { result } = await run(['--measurements', file('m.json', measurements())], { requestAttestation: reader({ useNonce: false }) })
  assert.equal(result.code, 'attestation_nonce')
})

test('an image outside the release is refused', async () => {
  const other = measurements({ pcrs: { 0: 'ab'.repeat(48), 1: hex(pcrs.get(1)), 2: hex(pcrs.get(2)) } })
  const { result } = await run(['--measurements', file('other.json', other)], { requestAttestation: reader() })
  assert.equal(result.code, 'attestation_measurement')
})

test('a policy hash the release does not publish is refused', async () => {
  const onlyTransition = measurements({ policies: [{ phase: 'transition', file: 't.json', sha256: TRANSITION }] })
  const { result } = await run(['--measurements', file('t.json', onlyTransition)], { requestAttestation: reader() })
  assert.equal(result.code, 'attestation_policy')
})

test('--sha256 pins the measurements file', async () => {
  const text = measurements()
  const path = file('pinned.json', text)
  const good = createHash('sha256').update(text).digest('hex')
  assert.equal((await run(['--measurements', path, '--sha256', good], { requestAttestation: reader() })).code, 0)
  const { result } = await run(['--measurements', path, '--sha256', 'f'.repeat(64)], { requestAttestation: reader() })
  assert.equal(result.code, 'measurements_sha256')
})

test('measurements can come from an https URL', async () => {
  const fetched = []
  const fetchBytes = async url => { fetched.push(url); return Buffer.from(measurements()) }
  const url = 'https://github.com/thehappieco/wappie/releases/download/reader-v0.2.0/measurements.json'
  const { code } = await run(['--measurements', url], { requestAttestation: reader(), fetchBytes })
  assert.equal(code, 0)
  assert.deepEqual(fetched, [url])
  assert.equal((await run(['--measurements', 'http://example.test/m.json'], { requestAttestation: reader() })).result.code, 'measurements_url')
})

test('malformed measurements are refused before the reader is asked', async () => {
  const asked = []
  const requestAttestation = async () => { asked.push(1) }
  for (const bad of [
    measurements({ schema: 'other' }),
    measurements({ pcrs: { 0: hex(pcrs.get(0)).toUpperCase(), 1: hex(pcrs.get(1)), 2: hex(pcrs.get(2)) } }),
    measurements({ pcrs: { 1: hex(pcrs.get(1)) } }),
    measurements({ version: 'v1' }),
    measurements({ policies: [] }),
    'not json',
  ]) {
    const { result } = await run(['--measurements', file('bad.json', bad)], { requestAttestation })
    assert.equal(result.code, 'measurements_invalid')
  }
  assert.equal(asked.length, 0)
})

test('HTTP errors and malformed responses are reported by code', async () => {
  const m = file('m.json', measurements())
  assert.equal((await run(['--measurements', m], { requestAttestation: reader({ status: 503, body: '{"code":"tls_not_ready"}' }) })).result.code, 'http_503')
  assert.equal((await run(['--measurements', m], { requestAttestation: reader({ body: '{"attestation":{"format":"other"}}' }) })).result.code, 'response_invalid')
  assert.equal((await run(['--measurements', m], { requestAttestation: reader({ body: '<html>' }) })).result.code, 'response_invalid')
})

test('--record keeps each attested SPKI once, for ct-watch', async () => {
  const record = join(dir, 'attested.txt')
  const args = ['--measurements', file('m.json', measurements()), '--record', record]
  await run(args, { requestAttestation: reader() })
  await run(args, { requestAttestation: reader() })
  assert.equal(readFileSync(record, 'utf8'), `${SPKI}\n`)
})

test('bad arguments are a usage error', async () => {
  assert.equal((await run([], {})).result.code, 'usage')
  assert.equal((await run(['--measurements', 'm.json', '--nope'], {})).result.code, 'usage')
  assert.equal((await run(['--measurements', 'm.json', '--host', 'https://mcp.wappie.thehappie.co/'], {})).result.code, 'usage')
})

test('the script prints one JSON line and exits 1 on failure', () => {
  const out = spawnSync(process.execPath, [CLI, '--measurements', join(dir, 'missing.json')], { encoding: 'utf8' })
  assert.equal(out.status, 1)
  assert.deepEqual(JSON.parse(out.stdout), { ok: false, code: 'measurements_unreadable' })
  assert.equal(out.stderr, '')
})

// The one piece the stubs skip: the real HTTPS request, and reading the SPKI
// of the certificate that actually answered. A local server with a throwaway
// CA added to this process's trust store (tls.setDefaultCACertificates).
test('requestAttestation reports the SPKI of the serving certificate', { skip: typeof tls.setDefaultCACertificates !== 'function' && 'needs tls.setDefaultCACertificates' }, async () => {
  const caKey = p384()
  const leafKey = p384()
  const ca = makeCert({ ca: true, keyUsage: KEY_CERT_SIGN, notBefore: Date.now() - DAY, notAfter: Date.now() + DAY, subject: 'reader-verify test CA', publicKey: caKey.publicKey, signingKey: caKey.privateKey })
  const san = extension('2.5.29.17', der(0x30, der(0x82, Buffer.from('localhost'))))
  const leaf = makeCert({ ca: false, keyUsage: DIGITAL_SIGNATURE, notBefore: Date.now() - DAY, notAfter: Date.now() + DAY, subject: 'localhost', issuer: 'reader-verify test CA', publicKey: leafKey.publicKey, signingKey: caKey.privateKey, issuerPublicKey: caKey.publicKey, extensions: [san] })
  const pem = der => new X509Certificate(der).toString()
  const previous = tls.getCACertificates('default')
  tls.setDefaultCACertificates([...previous, pem(ca)])
  const seen = []
  const server = createServer({ key: leafKey.privateKey.export({ type: 'pkcs8', format: 'pem' }), cert: pem(leaf) + pem(ca) }, (req, res) => {
    seen.push(req.url)
    res.writeHead(200, { 'content-type': 'application/json' }).end('{"attestation":null}')
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  try {
    const response = await requestAttestation(`localhost:${server.address().port}`, 'n'.repeat(43))
    assert.equal(response.status, 200)
    assert.equal(response.body, '{"attestation":null}')
    assert.equal(response.spkiSha256, createHash('sha256').update(leafKey.publicKey.export({ type: 'spki', format: 'der' })).digest('hex'))
    assert.deepEqual(seen, [`/attestation?nonce=${'n'.repeat(43)}`])
  } finally {
    server.close()
    tls.setDefaultCACertificates(previous)
  }
})

test('requestAttestation refuses a certificate it cannot verify', async () => {
  const key = p384()
  const self = makeCert({ ca: false, keyUsage: DIGITAL_SIGNATURE, notBefore: Date.now() - DAY, notAfter: Date.now() + DAY, subject: 'localhost', publicKey: key.publicKey, signingKey: key.privateKey })
  const server = createServer({ key: key.privateKey.export({ type: 'pkcs8', format: 'pem' }), cert: new X509Certificate(self).toString() }, (req, res) => res.end('{}'))
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  try {
    await assert.rejects(requestAttestation(`localhost:${server.address().port}`, 'n'.repeat(43)), { code: 'fetch_failed' })
  } finally {
    server.close()
  }
})
