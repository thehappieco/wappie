// Unit tests for the enclave's pure pieces, each against the vectors and
// rules of docs/mcp-enclave.md: policy canonicalization, the HMAC guard,
// user_data, PROXY v2, boot.json, the log sink schema and the relay secret.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { attestationUserData, createAttestor, decodeAttestationDocument, decodeNonce, userDataPreimage } from '../../attestation.mjs'
import { createLog } from '../../log.mjs'
import { attest } from '../attest.mjs'
import { parseBootJson } from '../boot.mjs'
import { imageConstants } from '../constants.mjs'
import { canonicalPolicy, createPolicyWatch, policySha256 } from '../policy.mjs'
import { canonicalString, createHmacGuard, createReplayCache, signature, signedHeaders } from '../hmac.mjs'
import { lineAllowed } from '../logsink.mjs'
import { encodeProxyV2, parseProxyV2, SIGNATURE } from '../proxy.mjs'
import { createSecrets, secretFrom } from '../secrets.mjs'
import { fakeDocument, fakeNsm, goHeaders, PCR0 } from './fixtures.mjs'

const SECRET = 'wappie-test-relay-secret-0123456789abcdefghij'
const RESOURCE = 'https://mcp.wappie.thehappie.co/mcp'

test('policy: the contract vector, stable under key reordering and whitespace, sensitive to array order and shape', () => {
  const text = '{ "Version": "2012-10-17", "Statement": [ { "Sid": "A", "Effect": "Allow" } ] }'
  assert.equal(canonicalPolicy(text).toString(), '{"Statement":[{"Effect":"Allow","Sid":"A"}],"Version":"2012-10-17"}')
  assert.equal(policySha256(text), '50647085b9c42d40af6dec1918c5cb5d97788849feb2377004e08874304d3373')
  assert.equal(policySha256('{"Statement":[{"Effect":"Allow","Sid":"A"}],\n  "Version":"2012-10-17"}'), policySha256(text))
  assert.notEqual(policySha256('{"Version":"2012-10-17","Statement":[{"Sid":"B"},{"Sid":"A"}]}'), policySha256('{"Version":"2012-10-17","Statement":[{"Sid":"A"},{"Sid":"B"}]}'))
  assert.notEqual(policySha256('{"Action":["kms:Decrypt"]}'), policySha256('{"Action":"kms:Decrypt"}'))
  // JCS: UTF-16 code-unit order, ECMAScript numbers, JSON string escaping.
  assert.equal(canonicalPolicy('{"b":1,"a":1e3,"\\u00e9":"x","A":"\\u2028"}').toString(), '{"A":" ","a":1000,"b":1,"é":"x"}')
  for (const bad of ['[]', 'null', '{', '"x"']) assert.throws(() => policySha256(bad), { code: 'policy_invalid' })
})

test('policy: the CLI prints the hash and the canonical bytes, and fails on garbage', () => {
  const cli = fileURLToPath(new URL('../policy.mjs', import.meta.url))
  const input = '{ "Version": "2012-10-17", "Statement": [ { "Sid": "A", "Effect": "Allow" } ] }'
  assert.equal(execFileSync(process.execPath, [cli], { input }).toString(), '50647085b9c42d40af6dec1918c5cb5d97788849feb2377004e08874304d3373\n')
  assert.equal(execFileSync(process.execPath, [cli, '--canonical'], { input }).toString(), '{"Statement":[{"Effect":"Allow","Sid":"A"}],"Version":"2012-10-17"}')
  assert.throws(() => execFileSync(process.execPath, [cli], { input: 'nope', stdio: 'pipe' }))
})

test('policy watch: unknown before a read, stale after 20 minutes, a failed read keeps the last value until then', async () => {
  let at = 0, fail = false
  const events = []
  const watch = createPolicyWatch({ read: async () => { if (fail) throw new Error('x'); return '{"a":1}' }, now: () => at, log: { event: code => events.push(code) } })
  assert.equal(watch.current(), null)
  assert.equal(await watch.refresh(), true)
  assert.equal(watch.current(), policySha256('{"a":1}'))
  fail = true; at = 10 * 60_000
  assert.equal(await watch.refresh(), false)
  assert.equal(watch.current(), policySha256('{"a":1}'))
  at = 20 * 60_000 + 1
  assert.equal(watch.current(), null)
  assert.deepEqual(events, ['policy_read_failed'])
})

test('hmac: both contract vectors', () => {
  const body = Buffer.from('{"nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}')
  const target = '/internal/requests/AAAAAAAAAAAAAAAAAAAAAA/prepare'
  const fields = { direction: 'to-reader', readerId: 'enclave', method: 'POST', target, timestamp: '1790300000', nonce: 'BBBBBBBBBBBBBBBBBBBBBB', bodySha256: '5abfe6385851c7e99e840bf25362e735b4adc8b617704a5cab1c8cf3aeae5a8f' }
  assert.equal(signature(SECRET, fields), 'v1=4966d2e42ab13456589657b9df8429cd70b95f1ec2f9273e6e27b76aabe53456')
  assert.equal(canonicalString(fields).split('\n').length, 8)
  const toGo = { direction: 'to-go', readerId: 'enclave', method: 'GET', target: '/v1/mcp/enclave/cimd?url=https%3A%2F%2Fclaude.ai%2Foauth%2Fmcp-oauth-client-metadata', timestamp: '1790300000', nonce: 'CCCCCCCCCCCCCCCCCCCCCC', bodySha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }
  assert.equal(signature(SECRET, toGo), 'v1=9d67d123516b7dc431b14a28223a654d8f57299cc83022ae17cbc4554baef616')
  // The outbound helper produces what an independent implementation of the contract accepts.
  const headers = signedHeaders({ secret: SECRET, direction: 'to-reader', readerId: 'enclave', method: 'POST', target, body, now: () => 1790300000_000 })
  assert.match(headers['x-wappie-nonce'], /^[A-Za-z0-9_-]{22}$/)
  assert.equal(headers['x-wappie-signature'], goHeaders(SECRET, { method: 'POST', target, body, now: 1790300000_000, nonce: headers['x-wappie-nonce'] })['x-wappie-signature'])
})

test('hmac guard: missing, stale (±60 s), wrong secret, wrong reader, tampered body or target, replay, and a full cache fails closed', async () => {
  let at = 1790300000_000
  const secrets = createSecrets({ current: 'A'.repeat(43), open: async () => Buffer.from('') })
  const guard = createHmacGuard({ readerId: 'enclave', secrets, now: () => at })
  const target = '/internal/healthz'
  const request = (headers, body, method = 'GET') => new Request('https://mcp.wappie.thehappie.co:8443' + target, { method, headers, body })
  const code = response => response?.headers.get('x-wappie-code')
  const ok = goHeaders('A'.repeat(43), { method: 'GET', target, now: at })
  assert.equal(await guard(request(ok), { target }), undefined)
  assert.equal(code(await guard(request(ok), { target })), 'hmac_replay')
  assert.equal(code(await guard(request({}), { target })), 'hmac_missing')
  assert.equal(code(await guard(request({ ...goHeaders('A'.repeat(43), { method: 'GET', target, now: at }), 'x-wappie-signature': 'v1=' + '0'.repeat(63) }), { target })), 'hmac_missing')
  assert.equal(code(await guard(request(goHeaders('A'.repeat(43), { method: 'GET', target, now: at - 61_000 })), { target })), 'hmac_stale')
  assert.equal(code(await guard(request(goHeaders('A'.repeat(43), { method: 'GET', target, now: at + 61_000 })), { target })), 'hmac_stale')
  assert.equal(await guard(request(goHeaders('A'.repeat(43), { method: 'GET', target, now: at - 59_000 })), { target }), undefined)
  assert.equal(code(await guard(request(goHeaders('B'.repeat(43), { method: 'GET', target, now: at })), { target })), 'hmac_bad')
  assert.equal(code(await guard(request(goHeaders('A'.repeat(43), { method: 'GET', target, now: at, reader: 'hosted' })), { target })), 'hmac_missing')
  assert.equal(code(await guard(request(goHeaders('A'.repeat(43), { method: 'GET', target: '/internal/healthz?x=1', now: at })), { target })), 'hmac_bad')
  const posted = goHeaders('A'.repeat(43), { method: 'POST', target, body: Buffer.from('{"a":1}'), now: at })
  assert.equal(code(await guard(request(posted, '{"a":2}', 'POST'), { target })), 'hmac_bad')
  const refused = await guard(request(goHeaders('B'.repeat(43), { method: 'GET', target, now: at })), { target })
  assert.equal(refused.status, 401)
  assert.deepEqual(await refused.json(), { code: 'unauthorized' })
  // A full cache refuses with 503 even a valid request.
  const tiny = createHmacGuard({ readerId: 'enclave', secrets, now: () => at, replay: createReplayCache({ max: 1, now: () => at }) })
  assert.equal(await tiny(request(goHeaders('A'.repeat(43), { method: 'GET', target, now: at })), { target }), undefined)
  const full = await tiny(request(goHeaders('A'.repeat(43), { method: 'GET', target, now: at })), { target })
  assert.equal(full.status, 503)
  assert.deepEqual(await full.json(), { code: 'replay_cache_full' })
  at += 62_000 // the first entry expires and is swept
  assert.equal(await tiny(request(goHeaders('A'.repeat(43), { method: 'GET', target, now: at })), { target }), undefined)
})

test('relay secret rotation: current and previous accepted, previous dropped on the first request under current', async () => {
  const at = Date.now()
  const opened = []
  const secrets = createSecrets({ current: 'S'.repeat(43), open: async ciphertext => { opened.push(ciphertext.toString()); return Buffer.from(ciphertext.toString() === 'good' ? 'T'.repeat(43) + '\n' : 'short') }, log: { event() {} } })
  const guard = createHmacGuard({ readerId: 'enclave', secrets, now: () => at })
  const target = '/internal/healthz'
  const call = secret => guard(new Request('https://x' + target, { headers: goHeaders(secret, { method: 'GET', target, now: at }) }), { target })
  await assert.rejects(secrets.rotate(Buffer.from('bad')), { code: 'bad_request' })
  assert.equal(secrets.count(), 1)
  await secrets.rotate(Buffer.from('good'))
  assert.equal(secrets.current, 'T'.repeat(43))
  assert.equal(secrets.count(), 2)
  assert.equal(await call('S'.repeat(43)), undefined, 'Go still signs with the old secret')
  assert.equal(secrets.count(), 2)
  assert.equal(await call('T'.repeat(43)), undefined)
  assert.equal(secrets.count(), 1, 'the first request under the new secret retires the old one')
  assert.equal((await call('S'.repeat(43)))?.status, 401)
  assert.throws(() => secretFrom(Buffer.from('x'.repeat(44))), { code: 'bad_request' })
  const failing = createSecrets({ current: 'S'.repeat(43), open: async () => { throw new Error('AccessDenied') } })
  await assert.rejects(failing.rotate(Buffer.from('x')), { code: 'kms_failed' })
})

test('user_data: the contract vector, the preimage layout, and 0x00 inside a field is refused', () => {
  const fields = { request_id: 'AAAAAAAAAAAAAAAAAAAAAA', resource: RESOURCE, tls_spki_sha256: 'a'.repeat(64), policy_sha256: 'b'.repeat(64), reader_version: '0.2.0' }
  assert.equal(attestationUserData(fields).toString('hex'), 'a63c1d0bc8fd8789d35f08c48db83edc71e71ae751d624ff9159fa5c3d50aad8')
  assert.equal(userDataPreimage(fields).toString(), ['wappie-mcp-attest/v1', 'AAAAAAAAAAAAAAAAAAAAAA', RESOURCE, 'a'.repeat(64), 'b'.repeat(64), '0.2.0'].join('\0'))
  assert.throws(() => userDataPreimage({ ...fields, request_id: 'a\0b' }))
  assert.equal(decodeNonce(Buffer.alloc(16, 1).toString('base64url')).length, 16)
  assert.equal(decodeNonce(Buffer.alloc(64, 1).toString('base64url')).length, 64)
  for (const bad of [Buffer.alloc(15).toString('base64url'), Buffer.alloc(65).toString('base64url'), Buffer.alloc(32).toString('base64'), 'A'.repeat(21) + 'B', 12, null]) assert.equal(decodeNonce(bad), null)
})

test('attestor: the NSM request carries the raw key, the nonce and user_data; refusals come before the NSM is asked', async () => {
  const bin = await fakeNsm()
  const asked = []
  let spki = null, policy = null
  const attestor = createAttestor({
    attest: async fields => { asked.push(fields); return attest(fields, { bin }) },
    readerId: 'enclave', readerVersion: '0.2.0', resource: RESOURCE, spki: () => spki, policy: () => policy,
  })
  const publicKey = randomBytes(32), nonce = randomBytes(32)
  await assert.rejects(attestor.attestation({ requestId: 'AAAAAAAAAAAAAAAAAAAAAA', publicKey, nonce }), { code: 'tls_not_ready', status: 503 })
  spki = 'c'.repeat(64)
  await assert.rejects(attestor.attestation({ requestId: 'AAAAAAAAAAAAAAAAAAAAAA', publicKey, nonce }), { code: 'policy_unknown' })
  assert.equal(asked.length, 0)
  policy = 'd'.repeat(64)
  const object = await attestor.attestation({ requestId: 'AAAAAAAAAAAAAAAAAAAAAA', publicKey, nonce })
  assert.deepEqual(Object.keys(object), ['format', 'document', 'request_id', 'resource', 'reader_id', 'reader_version', 'tls_spki_sha256', 'policy_sha256', 'pcr0'])
  assert.equal(object.format, 'aws-nitro-v1')
  assert.equal(object.pcr0, PCR0)
  const decoded = decodeAttestationDocument(Buffer.from(object.document, 'base64url'))
  assert.deepEqual(decoded.publicKey, publicKey)
  assert.deepEqual(decoded.nonce, nonce)
  assert.deepEqual(decoded.userData, attestationUserData({ request_id: 'AAAAAAAAAAAAAAAAAAAAAA', resource: RESOURCE, tls_spki_sha256: spki, policy_sha256: policy, reader_version: '0.2.0' }))
  const open = await attestor.attestation({ requestId: '', publicKey: null, nonce })
  assert.equal(decodeAttestationDocument(Buffer.from(open.document, 'base64url')).publicKey, null)
  const failing = createAttestor({ attest: async fields => attest(fields, { bin: await fakeNsm({ mode: 'fail' }) }), readerId: 'enclave', readerVersion: '0.2.0', resource: RESOURCE, spki: () => spki, policy: () => policy })
  await assert.rejects(failing.attestation({ requestId: '', publicKey: null, nonce }), { code: 'attest_failed' })
  const huge = createAttestor({ attest: async () => Buffer.alloc(16 * 1024 + 1), readerId: 'enclave', readerVersion: '0.2.0', resource: RESOURCE, spki: () => spki, policy: () => policy })
  await assert.rejects(huge.attestation({ requestId: '', publicKey: null, nonce }), { code: 'attest_failed' })
})

test('nsm-attest contract: hex arguments, "-" for absent fields, exit codes mapped to codes', async () => {
  const bin = await fakeNsm()
  const document = await attest({ publicKey: Buffer.alloc(32, 1) }, { bin })
  assert.deepEqual(decodeAttestationDocument(document).publicKey, Buffer.alloc(32, 1))
  assert.equal(decodeAttestationDocument(document).nonce, null)
  await assert.rejects(attest({ publicKey: Buffer.alloc(0) }, { bin }), { message: 'attest_bad_input' })
  await assert.rejects(attest({}, { bin: '/nonexistent/nsm-attest' }), { message: 'attest_unavailable' })
  await assert.rejects(attest({}, { bin: await fakeNsm({ mode: 'fail' }) }), { message: 'attest_nsm_error' })
  // The parse-only decoder reads both the tagged and the untagged form.
  assert.equal(decodeAttestationDocument(fakeDocument()).pcrs[0], PCR0)
  assert.equal(decodeAttestationDocument(fakeDocument().subarray(1)).pcrs[0], PCR0)
  assert.throws(() => decodeAttestationDocument(Buffer.concat([fakeDocument(), Buffer.from([0])])), { code: 'attest_failed' })
})

test('PROXY v2: IPv4, IPv6 and mapped IPv4 parse; v1, LOCAL, UNIX, UDP, oversize, truncated and garbage are refused', () => {
  const v4 = encodeProxyV2({ address: '203.0.113.7', port: 51000 })
  assert.deepEqual(parseProxyV2(Buffer.concat([v4, Buffer.from('rest')])), { address: '203.0.113.7', port: 51000, length: 28 })
  const v6 = encodeProxyV2({ address: '2001:db8::1', port: 443 })
  assert.deepEqual(parseProxyV2(v6), { address: '2001:db8:0:0:0:0:0:1', port: 443, length: 52 })
  assert.equal(parseProxyV2(encodeProxyV2({ address: '::ffff:c633:6407', port: 1 })).address, '198.51.100.7')
  for (let cut = 1; cut < v4.length; cut++) assert.ok(parseProxyV2(v4.subarray(0, cut)).need > 0, `prefix of ${cut} bytes waits`)
  assert.equal(parseProxyV2(Buffer.from('PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n')).error, 'proxy_invalid')
  assert.equal(parseProxyV2(Buffer.from('\x16\x03\x01\x02\x00')).error, 'proxy_invalid')
  const edit = (index, value) => { const copy = Buffer.from(v4); copy[index] = value; return copy }
  assert.equal(parseProxyV2(edit(12, 0x20)).error, 'proxy_local')
  assert.equal(parseProxyV2(edit(12, 0x11)).error, 'proxy_invalid')
  assert.equal(parseProxyV2(edit(13, 0x31)).error, 'proxy_family') // UNIX stream
  assert.equal(parseProxyV2(edit(13, 0x12)).error, 'proxy_family') // UDP over IPv4
  assert.equal(parseProxyV2(edit(13, 0x00)).error, 'proxy_family') // UNSPEC
  const oversize = Buffer.from(v4); oversize.writeUInt16BE(521, 14)
  assert.equal(parseProxyV2(oversize).error, 'proxy_invalid')
  const short = Buffer.from(v4); short.writeUInt16BE(8, 14)
  assert.equal(parseProxyV2(short).error, 'proxy_invalid')
  // TLVs after the address block are ignored, up to the 536-byte cap.
  const withTlv = Buffer.concat([v4, Buffer.alloc(508)]); withTlv.writeUInt16BE(12 + 508, 14)
  assert.equal(parseProxyV2(withTlv).length, 536)
  // Fuzz: random bytes after a valid signature never throw, and never parse unless well formed.
  for (let i = 0; i < 2000; i++) {
    const data = Buffer.concat([SIGNATURE, randomBytes(Math.floor(Math.random() * 64))])
    const result = parseProxyV2(data)
    assert.ok(result.need || result.error || (result.address && result.length <= 536))
  }
  for (let i = 0; i < 2000; i++) assert.ok(parseProxyV2(randomBytes(1 + Math.floor(Math.random() * 40))).error || true)
})

test('boot.json: exactly one key with standard base64 of 1 to 6144 bytes, at most 16 KiB', () => {
  const good = Buffer.from(JSON.stringify({ relay_secret_ciphertext: Buffer.alloc(200, 7).toString('base64') }))
  assert.equal(parseBootJson(good).relayCiphertext.length, 200)
  const refused = [
    { relay_secret_ciphertext: 'AAAA', extra: 1 }, {}, { relay_secret_ciphertext: 7 }, { relay_secret_ciphertext: '' },
    { relay_secret_ciphertext: Buffer.alloc(10).toString('base64url') + '-' }, { relay_secret_ciphertext: 'AAA' },
    { relay_secret_ciphertext: Buffer.alloc(6145).toString('base64') }, ['x'], 'x', null,
  ]
  for (const body of refused) assert.throws(() => parseBootJson(Buffer.from(JSON.stringify(body))), { code: 'boot_json_invalid' }, JSON.stringify(body)?.slice(0, 40))
  assert.throws(() => parseBootJson(Buffer.alloc(16 * 1024 + 1, 0x20)), { code: 'boot_json_invalid' })
  assert.throws(() => parseBootJson(Buffer.from('{"relay_secret_ciphertext":"AAAA"')), { code: 'boot_json_invalid' })
})

test('log sink schema: createLog lines pass, anything off-schema is refused', () => {
  const lines = []
  const log = createLog(line => lines.push(line), () => Date.parse('2026-09-25T10:00:00Z'))
  log.request({ route: 'POST /internal/requests/{id}/prepare', status: 200, ms: 12.4, connection: 'c', client: 'k', code: 'too_many_prepares' })
  log.request({ route: 'unmatched', status: 404, ms: 0 })
  log.event('health', { uptime_s: 5, policy_ok: true, pcr0: 'ab'.repeat(6), spki: 'x'.repeat(12), note: 'free text' })
  log.event('certificate_order_failed', { failures: 2, code: 'acme_rate_limited' })
  log.event('certificate_order_failed', { code: 'Not A Code' })
  for (const line of lines) assert.equal(lineAllowed(line), true, line)
  assert.equal(JSON.parse(lines[2]).spki, undefined, 'a non-hex string is dropped by createLog')
  assert.equal(JSON.parse(lines[2]).note, undefined)
  assert.equal(JSON.parse(lines[4]).code, undefined)
  const ts = '2026-09-25T10:00:00.000Z'
  const refused = [
    { ts, event: 'x', query: 'hello' }, { ts, route: '/mcp', status: 200 }, { ts, route: 'GET /mcp?q=1', status: 200 }, { ts, status: 99 },
    { ts, event: 'Health' }, { ts, conn: 'abc' }, { ts, pcr0: 'AB'.repeat(6) }, { ts, count: Infinity }, { ts, nested: { a: 1 } }, { event: 'x' },
    { ts: '2026-09-25', event: 'x' }, { ts, event: 'x', Key: 1 }, { ts, event: 'x', message: 'x'.repeat(3000) },
  ]
  for (const entry of refused) assert.equal(lineAllowed(JSON.stringify(entry)), false, JSON.stringify(entry).slice(0, 60))
  assert.equal(lineAllowed('not json'), false)
})

test('image constants: markers left by an unfilled build refuse the boot', () => {
  assert.throws(() => imageConstants(), { message: 'constants_invalid' })
})

test('the parse-only decoder reads PCR0 from a real production document (spike Day 3)', async t => {
  const { readFile } = await import('node:fs/promises')
  let text
  try { text = await readFile(new URL('../../../client/testdata/attestation/att.b64', import.meta.url), 'utf8') } catch { t.skip('no spike document in packages/client/testdata'); return }
  const decoded = decodeAttestationDocument(Buffer.from(text.trim(), 'base64'))
  assert.equal(decoded.pcrs[0], '3094ef1a62c59b9a1bb1c9bcee8774917c5c5a37e1b30fe2ca2afb65a28b76ba1dae07170d71d21a2500675521c6028b')
  assert.equal(decoded.publicKey.length, 294, 'the per-boot RSA-2048 SPKI of a KMS document')
})
