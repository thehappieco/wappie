// TLS inside the enclave: the ACME account and TLS-ALPN-01 order against a
// fake ACME server that really dials the challenge listener, the per-boot key
// and certificate in the run directory, and the PROXY v2 listeners in front
// of node:http.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer as createHTTPServer } from 'node:http'
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { connect as tlsConnect, createSecureContext } from 'node:tls'
import { accountId, createAcmeClient, createChallenges, newAccountKey } from '../acme.mjs'
import { encodeProxyV2, createProxiedTLSListener } from '../proxy.mjs'
import { bootMaterial, createCertificates } from '../tls.mjs'
import { certificationRequest, pem, spkiSha256 } from '../x509.mjs'
import { closedAfter, createFakeAcme, issueLeaf, proxiedRequest, testCA } from './fixtures.mjs'

const NAMES = ['mcp.wappie.thehappie.co', '0123456789abcdef.boot.mcp.wappie.thehappie.co']
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)))
const close = server => new Promise(resolve => server.close(() => resolve()))

async function acmeSetup(t, fail = {}) {
  const ca = testCA()
  const challenges = createChallenges()
  const challengeServer = challenges.server()
  const challengePort = await listen(challengeServer)
  const acme = await createFakeAcme({ ca, challengePort: () => challengePort, fail }).listen()
  const dir = await mkdtemp(join(tmpdir(), 'wappie-run-'))
  t.after(async () => { await close(challengeServer); await acme.close(); await rm(dir, { recursive: true, force: true }) })
  return { ca, challenges, challengePort, acme, dir }
}

test('acme: registers with terms agreed and no contact, validates both names over TLS-ALPN-01, and returns a chain for our key', async t => {
  const { ca, challenges, acme, dir } = await acmeSetup(t)
  const accountKey = newAccountKey()
  const client = createAcmeClient({ directory: acme.directory, accountKey, challenges, wait: () => Promise.resolve() })
  const uri = await client.ensureAccount()
  assert.match(uri, /\/acme\/acct\/1000$/)
  assert.equal(accountId(uri), 1000)
  // The same key registers to the same account (a crash between sealing the key and storing the URI).
  const again = createAcmeClient({ directory: acme.directory, accountKey, challenges })
  assert.equal(await again.ensureAccount(), uri)
  const material = await bootMaterial(dir)
  const chain = await client.issue(NAMES, certificationRequest(NAMES, material.privateKey))
  assert.equal(acme.validations, 2)
  assert.equal(challenges.size(), 0, 'challenge certificates are dropped once validated')
  assert.ok(chain.endsWith(ca.pem))
})

test('acme: a failed validation is reported with a code, and the certificate manager backs off from 1 to 30 minutes', async t => {
  const { challenges, acme, dir } = await acmeSetup(t, { validation: true })
  const client = createAcmeClient({ directory: acme.directory, accountKey: newAccountKey(), challenges, wait: () => Promise.resolve() })
  const material = await bootMaterial(dir)
  await assert.rejects(client.issue(NAMES, certificationRequest(NAMES, material.privateKey)), { code: 'acme_challenge_invalid' })
  const waits = [], events = []
  const certificates = createCertificates({ dir, material, names: NAMES, acme: client, log: { event: (event, fields) => events.push({ event, ...fields }) },
    wait: async ms => { waits.push(ms); if (waits.length === 7) acme.fail.validation = false } })
  await certificates.ready()
  assert.deepEqual(waits, [60_000, 120_000, 240_000, 480_000, 960_000, 1_800_000, 1_800_000])
  assert.equal(events.filter(entry => entry.event === 'certificate_order_failed').length, 7)
  assert.deepEqual(events[0], { event: 'certificate_order_failed', failures: 1, code: 'acme_challenge_invalid' })
  assert.ok(certificates.spkiSha256())
})

test('challenge listener: answers only acme-tls/1 for a name with a pending challenge, and closes after the handshake', async t => {
  const { challenges, challengePort } = await acmeSetup(t)
  challenges.set('mcp.wappie.thehappie.co', 'token.thumbprint')
  const handshake = (servername, alpn) => new Promise(resolve => {
    const socket = tlsConnect({ host: '127.0.0.1', port: challengePort, servername, ALPNProtocols: alpn, rejectUnauthorized: false }, () => { const result = { ok: true, alpn: socket.alpnProtocol }; socket.destroy(); resolve(result) })
    socket.on('error', error => resolve({ ok: false, code: error.code }))
  })
  assert.deepEqual(await handshake('mcp.wappie.thehappie.co', ['acme-tls/1']), { ok: true, alpn: 'acme-tls/1' })
  assert.equal((await handshake('mcp.wappie.thehappie.co', ['http/1.1'])).ok, false, 'no ordinary TLS on the challenge port')
  assert.equal((await handshake('other.example', ['acme-tls/1'])).ok, false)
})

test('per-boot material: 0700 run directory, 0600 files, reused by a restarted Node, never recreated within a boot', async t => {
  const { challenges, acme, dir } = await acmeSetup(t)
  const runDir = join(dir, 'wappie')
  const material = await bootMaterial(runDir)
  assert.match(material.bootId, /^[0-9a-f]{16}$/)
  assert.equal((await stat(runDir)).mode & 0o777, 0o700)
  for (const name of ['boot_id', 'tls-key.pem']) assert.equal((await stat(join(runDir, name))).mode & 0o777, 0o600)
  const client = createAcmeClient({ directory: acme.directory, accountKey: newAccountKey(), challenges, wait: () => Promise.resolve() })
  const certificates = createCertificates({ dir: runDir, material, names: NAMES, acme: client })
  assert.equal(certificates.spkiSha256(), null, 'no certificate, no SPKI to attest')
  await certificates.ready()
  assert.equal(certificates.spkiSha256(), spkiSha256(material.spki))
  assert.ok(certificates.daysLeft() >= 89)
  assert.equal(acme.issued, 1)
  // A Node restart in the same boot: same id, same key, the saved certificate, no new order.
  const restarted = await bootMaterial(runDir)
  assert.equal(restarted.bootId, material.bootId)
  assert.deepEqual(restarted.spki, material.spki)
  const again = createCertificates({ dir: runDir, material: restarted, names: NAMES, acme: client })
  await again.ready()
  assert.equal(acme.issued, 1)
  assert.equal((await stat(join(runDir, 'tls-chain.pem'))).mode & 0o777, 0o600)
  // Thirty days before expiry the same key is renewed in the background while the old certificate keeps serving.
  const late = createCertificates({ dir: runDir, material: restarted, names: NAMES, acme: client, now: () => Date.now() + 61 * 86_400_000 })
  await late.ready()
  assert.ok(late.secureContext())
  await new Promise(resolve => setTimeout(resolve, 300))
  assert.equal(acme.issued, 2)
  assert.match(await readFile(join(runDir, 'tls-key.pem'), 'utf8'), /BEGIN PRIVATE KEY/)
})

test('PROXY v2 listener: the header source is the client address; coalesced or separate writes; TLS 1.2+ and http/1.1 only', async t => {
  const ca = testCA()
  const material = await bootMaterial(await mkdtemp(join(tmpdir(), 'wappie-run-')))
  const chain = pem('CERTIFICATE', issueLeaf(ca, material.spki, NAMES)) + ca.pem
  const context = createSecureContext({ key: material.keyPem, cert: chain, minVersion: 'TLSv1.2' })
  const seen = []
  const http = createHTTPServer((req, res) => { seen.push({ address: req.socket.remoteAddress, port: req.socket.remotePort }); res.end('ok') })
  const rejected = []
  const listener = createProxiedTLSListener({ httpServer: http, secureContext: () => context, onRejected: code => rejected.push(code), headerTimeoutMs: 300 })
  const port = await listen(listener)
  t.after(() => close(listener))
  const answer = await proxiedRequest({ port, proxy: encodeProxyV2({ address: '203.0.113.9', port: 40000 }), ca: ca.pem })
  assert.equal(answer.status, 200)
  assert.equal(answer.alpn, 'http/1.1')
  assert.equal(spkiSha256(answer.peer.publicKey.export({ type: 'spki', format: 'der' })), spkiSha256(material.spki))
  assert.equal((await proxiedRequest({ port, proxy: encodeProxyV2({ address: '2001:db8::7', port: 1 }), ca: ca.pem, coalesce: true })).status, 200)
  assert.deepEqual(seen, [{ address: '203.0.113.9', port: 40000 }, { address: '2001:db8:0:0:0:0:0:7', port: 1 }])
  // No header, a v1 header, LOCAL, garbage, silence and a truncated header all close the socket.
  const local = encodeProxyV2({ address: '203.0.113.9', port: 1 }); local[12] = 0x20
  assert.equal(await closedAfter(port, Buffer.from('\x16\x03\x01\x00\x05hello')), true)
  assert.equal(await closedAfter(port, Buffer.from('PROXY TCP4 203.0.113.9 127.0.0.1 1 443\r\n')), true)
  assert.equal(await closedAfter(port, local), true)
  assert.equal(await closedAfter(port, Buffer.alloc(0)), true)
  assert.equal(await closedAfter(port, encodeProxyV2({ address: '203.0.113.9', port: 1 }).subarray(0, 20)), true)
  assert.deepEqual(rejected.sort(), ['proxy_invalid', 'proxy_invalid', 'proxy_local', 'proxy_timeout', 'proxy_timeout'])
  await assert.rejects(proxiedRequest({ port, proxy: encodeProxyV2({ address: '203.0.113.9', port: 1 }), ca: ca.pem, alpn: ['h2'] }))
})
