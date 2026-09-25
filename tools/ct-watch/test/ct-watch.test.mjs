// ct-watch against a fake crt.sh: listings as ?output=json returns them, and
// certificates built with the verifier's DER fixtures. No network.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { X509Certificate, createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { QUERIES, coversReader, main, readAttested } from '../ct-watch.mjs'
import { DAY, DIGITAL_SIGNATURE, NOW, der, extension, makeCert, p384 } from '../../../packages/client/test/attestationFixtures.mjs'

const dir = mkdtempSync(join(tmpdir(), 'ct-watch-'))
const caKey = p384()

// One certificate for these names, and the crt.sh row that lists it.
function issue(id, names, { precert = false } = {}) {
  const key = p384()
  const san = extension('2.5.29.17', der(0x30, ...names.map(n => der(0x82, Buffer.from(n)))))
  const certDer = makeCert({ ca: false, keyUsage: DIGITAL_SIGNATURE, notBefore: NOW - DAY, notAfter: NOW + 90 * DAY, subject: names[0], issuer: 'Test CA', publicKey: key.publicKey, signingKey: caKey.privateKey, issuerPublicKey: caKey.publicKey, extensions: [san] })
  const x509 = new X509Certificate(certDer)
  const spki = createHash('sha256').update(key.publicKey.export({ type: 'spki', format: 'der' })).digest('hex')
  const row = { issuer_ca_id: 7, issuer_name: 'C=US, O=Test, CN=Test CA', common_name: names[0], name_value: names.join('\n'), id, entry_timestamp: '2026-09-24T12:00:00.000', not_before: '2026-09-23T12:00:00', not_after: '2026-12-22T12:00:00', serial_number: x509.serialNumber.toLowerCase(), result_count: 1 }
  return { row, pem: x509.toString(), spki, precert }
}

// A fake fetch that answers crt.sh listings from `listing` (query -> rows) and
// downloads from `certs` (id -> pem), and records what it was asked.
function crtsh({ listing, certs, down = false }) {
  const asked = []
  const fetchImpl = async url => {
    const u = new URL(url)
    asked.push(u.search)
    assert.equal(u.origin, 'https://crt.sh')
    if (down) return new Response('busy', { status: 502 })
    if (u.searchParams.has('q')) {
      assert.equal(u.searchParams.get('output'), 'json')
      return new Response(JSON.stringify(listing[u.searchParams.get('q')] ?? []))
    }
    const pem = certs[u.searchParams.get('d')]
    return pem ? new Response(pem) : new Response('not found', { status: 404 })
  }
  return { fetchImpl, asked }
}

async function run(argv, fetchImpl) {
  const lines = []
  const code = await main(argv, fetchImpl, line => lines.push(line))
  assert.equal(lines.length, 1)
  return { code, result: JSON.parse(lines[0]) }
}

const enclave = issue(101, ['mcp.wappie.thehappie.co', '0123456789abcdef.boot.mcp.wappie.thehappie.co'])
const rogue = issue(202, ['mcp.wappie.thehappie.co'])
const wildcard = issue(303, ['*.wappie.thehappie.co'])
const api = issue(404, ['api.wappie.thehappie.co'])
const attestedFile = join(dir, 'attested.txt')
writeFileSync(attestedFile, `# from reader-verify --record\n${enclave.spki}\n`)

test('names that can serve the reader', () => {
  for (const n of ['mcp.wappie.thehappie.co', 'MCP.wappie.thehappie.co.', 'abc.boot.mcp.wappie.thehappie.co', '*.mcp.wappie.thehappie.co', '*.wappie.thehappie.co']) assert.equal(coversReader(n), true, n)
  for (const n of ['api.wappie.thehappie.co', 'app.wappie.thehappie.co', '*.thehappie.co', 'mcp.wappie.thehappie.co.evil.test', 'xmcp.wappie.thehappie.co']) assert.equal(coversReader(n), false, n)
})

test('only attested keys: clean, and the precertificate is fetched once', async () => {
  const precert = { ...enclave.row, id: 100 }
  const { fetchImpl, asked } = crtsh({ listing: { [QUERIES[0]]: [precert, enclave.row], [QUERIES[2]]: [enclave.row, api.row] }, certs: { 100: enclave.pem, 101: enclave.pem } })
  const { code, result } = await run(['--attested', attestedFile], fetchImpl)
  assert.equal(code, 0)
  assert.deepEqual(result, { ok: true, checked: 1, flagged: [], unchecked: [] })
  assert.deepEqual(asked.filter(s => s.startsWith('?d=')), ['?d=100']) // not the api. certificate, not twice
})

test('a certificate on an unattested key is flagged, wildcards included', async () => {
  const { fetchImpl } = crtsh({ listing: { [QUERIES[0]]: [enclave.row, rogue.row], [QUERIES[2]]: [wildcard.row] }, certs: { 101: enclave.pem, 202: rogue.pem, 303: wildcard.pem } })
  const { code, result } = await run(['--attested', attestedFile], fetchImpl)
  assert.equal(code, 1)
  assert.equal(result.ok, false)
  assert.deepEqual(result.flagged.map(f => [f.id, f.spki_sha256]), [[202, rogue.spki], [303, wildcard.spki]])
  assert.deepEqual(result.flagged[1].names, ['*.wappie.thehappie.co'])
  assert.equal(result.flagged[0].url, 'https://crt.sh/?id=202')
})

test('--spki adds keys on the command line', async () => {
  const { fetchImpl } = crtsh({ listing: { [QUERIES[0]]: [rogue.row] }, certs: { 202: rogue.pem } })
  assert.equal((await run(['--spki', rogue.spki], fetchImpl)).code, 0)
})

test('--since skips certificates issued before it', async () => {
  const { fetchImpl } = crtsh({ listing: { [QUERIES[0]]: [rogue.row] }, certs: { 202: rogue.pem } })
  assert.equal((await run(['--attested', attestedFile, '--since', '2026-09-24T00:00:00Z'], fetchImpl)).code, 0)
  assert.equal((await run(['--attested', attestedFile, '--since', '2026-09-01T00:00:00Z'], fetchImpl)).code, 1)
})

test('--cache avoids downloading a certificate twice', async () => {
  const cache = join(dir, 'cache.json')
  const first = crtsh({ listing: { [QUERIES[0]]: [enclave.row] }, certs: { 101: enclave.pem } })
  await run(['--attested', attestedFile, '--cache', cache], first.fetchImpl)
  assert.deepEqual(JSON.parse(readFileSync(cache, 'utf8')), { 101: enclave.spki })
  const second = crtsh({ listing: { [QUERIES[0]]: [enclave.row] }, certs: {} })
  assert.equal((await run(['--attested', attestedFile, '--cache', cache], second.fetchImpl)).code, 0)
  assert.equal(second.asked.filter(s => s.startsWith('?d=')).length, 0)
})

test('an incomplete check exits 2, never 0', async () => {
  const missing = crtsh({ listing: { [QUERIES[0]]: [rogue.row] }, certs: {} })
  const { code, result } = await run(['--attested', attestedFile], missing.fetchImpl)
  assert.equal(code, 2)
  assert.deepEqual(result.unchecked, [{ id: 202, code: 'crtsh_unavailable' }])
  const swapped = crtsh({ listing: { [QUERIES[0]]: [rogue.row] }, certs: { 202: enclave.pem } })
  assert.deepEqual((await run(['--attested', attestedFile], swapped.fetchImpl)).result.unchecked, [{ id: 202, code: 'certificate_mismatch' }])
  const down = crtsh({ listing: {}, certs: {}, down: true })
  assert.deepEqual(await run(['--attested', attestedFile], down.fetchImpl), { code: 2, result: { ok: false, code: 'crtsh_unavailable' } })
})

test('bad input is refused', async () => {
  const { fetchImpl } = crtsh({ listing: {}, certs: {} })
  assert.equal((await run([], fetchImpl)).result.code, 'usage')
  assert.equal((await run(['--spki', 'xyz'], fetchImpl)).result.code, 'attested_invalid')
  assert.equal((await run(['--attested', join(dir, 'none.txt')], fetchImpl)).result.code, 'attested_unreadable')
  assert.equal((await run(['--spki', enclave.spki, '--since', 'yesterday'], fetchImpl)).result.code, 'usage')
  assert.deepEqual([...readAttested(`["${enclave.spki.toUpperCase()}"]`)], [enclave.spki])
})
