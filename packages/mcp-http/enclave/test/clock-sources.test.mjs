// Where the clock's cross-checks come from (reader 0.6.1): the Date of every
// KMS answer (a client middleware) and of the health probe, and the NSM
// timestamp of every document nsm-attest makes. Also the caps that keep
// nsm-attest from crowding out the time feed, and durations that a step of
// the system clock cannot make negative.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer as createHTTPServer } from 'node:http'
import { randomBytes } from 'node:crypto'
import { GetKeyPolicyCommand } from '@aws-sdk/client-kms'
import { AttestationError, createAttestor } from '../../attestation.mjs'
import { createLimiter } from '../../limits.mjs'
import { createLog } from '../../log.mjs'
import { ATTESTATION_ALL_PER_MINUTE, ATTESTATION_PER_MINUTE, createRouter } from '../../router.mjs'
import { attest, createAttestLimit } from '../attest.mjs'
import { nsmRange } from '../clock.mjs'
import { clockSkew, createHealthLine } from '../health.mjs'
import { createKms, dateRangeMiddleware, kmsClient } from '../kms.mjs'
import { lineAllowed } from '../logsink.mjs'
import { fakeNsm, PCR0 } from './fixtures.mjs'

const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)))
const CREDENTIALS = { accessKeyId: 'AKIDTEST', secretAccessKey: 'test-secret' } // never leaves the fake handler

/** A KMS requestHandler that answers each attempt from `answers` (status, body, headers) and records it. Headers may be a function, called as the answer is made. */
function fakeKmsHandler(answers) {
  const seen = []
  return {
    seen,
    handle: async request => {
      const answer = answers[Math.min(seen.length, answers.length - 1)]
      seen.push(request)
      const body = new TextEncoder().encode(JSON.stringify(answer.body))
      const headers = typeof answer.headers === 'function' ? answer.headers() : answer.headers
      return { response: { statusCode: answer.status, headers: { 'content-type': 'application/x-amz-json-1.1', ...headers }, body } }
    },
  }
}

const POLICY = { Policy: '{"Version":"2012-10-17"}', PolicyName: 'default' }
const httpDate = offsetMs => new Date(Date.now() + offsetMs).toUTCString()

test('wappieDateRange: a successful KMS answer gives one range from its Date header', async () => {
  const ranges = []
  const handler = fakeKmsHandler([{ status: 200, body: POLICY, headers: () => ({ date: httpDate(-7000) }) }])
  const client = kmsClient(CREDENTIALS, { onRange: range => ranges.push(range), requestHandler: handler })
  const out = await client.send(new GetKeyPolicyCommand({ KeyId: 'alias/test', PolicyName: 'default' }))
  assert.equal(out.Policy, POLICY.Policy)
  assert.equal(ranges.length, 1)
  // KMS is 7 s behind us: the range holds 7 s and is about 1 s wide (Date has whole seconds).
  assert.ok(ranges[0].lo <= 7000 && ranges[0].hi >= 7000 && ranges[0].hi - ranges[0].lo < 2000, JSON.stringify(ranges[0]))
  assert.ok(Number.isFinite(ranges[0].anchor) && Number.isFinite(ranges[0].mono))
})

test('wappieDateRange: a 4xx carries its Date on $response; a header in any case counts', async () => {
  const ranges = []
  const handler = fakeKmsHandler([{ status: 400, body: { __type: 'NotFoundException', message: 'no such key' }, headers: () => ({ Date: httpDate(0), 'x-amzn-errortype': 'NotFoundException' }) }])
  const client = kmsClient(CREDENTIALS, { onRange: range => ranges.push(range), requestHandler: handler })
  const error = await client.send(new GetKeyPolicyCommand({ KeyId: 'alias/test', PolicyName: 'default' })).catch(e => e)
  assert.equal(error.name, 'NotFoundException')
  assert.ok(error.$response, 'the SDK attaches the raw response to the error')
  assert.equal(handler.seen.length, 1, 'a client fault is not retried')
  assert.equal(ranges.length, 1)
  assert.ok(ranges[0].lo <= 0 && ranges[0].hi >= 0, JSON.stringify(ranges[0]))
})

test('wappieDateRange: each retried attempt gives its own range; no Date or an unusable one gives none', async () => {
  const ranges = []
  const handler = fakeKmsHandler([
    { status: 500, body: { __type: 'KMSInternalException', message: 'try again' }, headers: () => ({ date: httpDate(0), 'x-amzn-errortype': 'KMSInternalException' }) },
    { status: 200, body: POLICY, headers: () => ({ date: httpDate(0) }) },
  ])
  const client = kmsClient(CREDENTIALS, { onRange: range => ranges.push(range), requestHandler: handler })
  await client.send(new GetKeyPolicyCommand({ KeyId: 'alias/test', PolicyName: 'default' }))
  assert.equal(handler.seen.length, 2)
  assert.equal(ranges.length, 2)
  for (const headers of [{}, { date: 'not a date' }]) {
    const quiet = []
    const none = kmsClient(CREDENTIALS, { onRange: range => quiet.push(range), requestHandler: fakeKmsHandler([{ status: 200, body: POLICY, headers }]) })
    await none.send(new GetKeyPolicyCommand({ KeyId: 'alias/test', PolicyName: 'default' }))
    assert.equal(quiet.length, 0, JSON.stringify(headers))
  }
  // Without onRange nothing is added, and a throwing onRange never fails the call.
  const plain = kmsClient(CREDENTIALS, { requestHandler: fakeKmsHandler([{ status: 200, body: POLICY, headers: { date: httpDate(0) } }]) })
  assert.equal(plain.middlewareStack.identify().some(name => name.startsWith('wappieDateRange')), false)
  const throwing = kmsClient(CREDENTIALS, { onRange: () => { throw new Error('boom') }, requestHandler: fakeKmsHandler([{ status: 200, body: POLICY, headers: { date: httpDate(0) } }]) })
  assert.equal((await throwing.send(new GetKeyPolicyCommand({ KeyId: 'alias/test', PolicyName: 'default' }))).Policy, POLICY.Policy)
})

test('wappieDateRange: a transport failure gives no range; a step mid-call gives none', async () => {
  const ranges = []
  const failing = dateRangeMiddleware(range => ranges.push(range))(async () => { throw Object.assign(new Error('socket'), { code: 'ECONNRESET' }) })
  await assert.rejects(failing({}), { code: 'ECONNRESET' })
  let wall = 1_800_000_000_000, mono = 0
  const stepped = dateRangeMiddleware(range => ranges.push(range), { now: () => wall, mono: () => mono })(async () => {
    wall += 10_000; mono += 10 // the system clock stepped while we waited
    return { response: { statusCode: 200, headers: { date: new Date(wall).toUTCString() } } }
  })
  await stepped({})
  assert.equal(ranges.length, 0)
})

test('createKms: durations come from the monotonic clock, whole and never negative', async () => {
  const logged = []
  const client = { send: async () => { await new Promise(resolve => setTimeout(resolve, 15)); return { Policy: '{}' } } }
  const kms = createKms({ client, keys: { spki: Buffer.alloc(1) }, attest: async () => Buffer.from('doc'), log: (op, fields) => logged.push({ op, ...fields }) })
  const realNow = Date.now
  Date.now = () => realNow() - 3_600_000 // the wall clock is stepped back meanwhile: no effect
  try { await kms.keyPolicy('arn:aws:kms:eu-west-1:1:key/test') } finally { Date.now = realNow }
  assert.equal(logged.length, 1)
  assert.ok(Number.isInteger(logged[0].ms) && logged[0].ms >= 10 && logged[0].ms < 5000, JSON.stringify(logged[0]))
})

test('health probe: the Date answer also gives a clock range; the line merges the clock fields and keeps uptime monotonic', async t => {
  const http = createHTTPServer((req, res) => { res.writeHead(400, { date: httpDate(-3000) }); res.end() })
  const port = await listen(http)
  t.after(() => new Promise(resolve => http.close(resolve)))
  const ranges = []
  const skew = await clockSkew({ url: `http://127.0.0.1:${port}/`, onRange: range => ranges.push(range) })
  assert.ok(skew >= 2000 && skew <= 4100, `skew ${skew}`)
  assert.equal(ranges.length, 1)
  assert.ok(ranges[0].lo <= 3000 && ranges[0].hi >= 3000 && ranges[0].hi - ranges[0].lo < 1500, JSON.stringify(ranges[0]))
  assert.equal(await clockSkew({ url: 'http://127.0.0.1:1/', onRange: range => ranges.push(range) }), null)
  assert.equal(ranges.length, 1)

  let mono = 10_000
  const lines = []
  const clock = { fields: () => ({ clock_ok: true, clock_unc_ms: 14, nsm_skew_ms: undefined, clock_refused: 0 }) }
  const line = createHealthLine({ log: createLog(entry => lines.push(entry)), probe: async () => null, fields: () => ({ connections: 1 }), clock, mono: () => mono })
  mono += 125_400
  const entry = await line.tick()
  assert.equal(entry.uptime_s, 125)
  assert.equal(entry.clock_ok, true)
  assert.equal(entry.clock_unc_ms, 14)
  assert.equal('nsm_skew_ms' in entry, false)
  assert.equal(lineAllowed(lines[0]), true)
})

test('attest limit: at most 2 runs at once, a bounded queue in arrival order, then attest_busy', async () => {
  const limit = createAttestLimit({ inFlight: 2, queue: 2 })
  const gates = [], order = []
  const job = name => limit.run(() => new Promise(resolve => { order.push(name); gates.push(resolve) }).then(() => name))
  const runs = ['a', 'b', 'c', 'd'].map(job)
  await new Promise(resolve => setImmediate(resolve))
  assert.deepEqual(order, ['a', 'b'])
  assert.deepEqual(limit.counts(), { running: 2, waiting: 2 })
  await assert.rejects(job('e'), { message: 'attest_busy' })
  gates[1]()
  assert.equal(await runs[1], 'b')
  await new Promise(resolve => setImmediate(resolve))
  assert.deepEqual(order, ['a', 'b', 'c'])
  gates[0](); gates[2]()
  await new Promise(resolve => setImmediate(resolve))
  assert.deepEqual(order, ['a', 'b', 'c', 'd'])
  gates[3]()
  assert.deepEqual(await Promise.all(runs), ['a', 'b', 'c', 'd'])
  assert.deepEqual(limit.counts(), { running: 0, waiting: 0 })
  // A failing run frees its slot as well.
  await assert.rejects(limit.run(async () => { throw new Error('attest_nsm_error') }), { message: 'attest_nsm_error' })
  assert.deepEqual(limit.counts(), { running: 0, waiting: 0 })
})

test('attest: runs share the cap, the NSM time is bracketed, and the public route answers 503 attest_busy when full', async () => {
  const bin = await fakeNsm()
  const samples = []
  const document = await attest({ nonce: Buffer.alloc(16, 7) }, { bin, onSample: sample => samples.push(sample) })
  assert.ok(document.length > 0)
  assert.equal(samples.length, 1)
  const { sent, received, sentMono, receivedMono, timestamp } = samples[0]
  assert.ok(sent <= timestamp && timestamp <= received, JSON.stringify(samples[0]))
  assert.ok(receivedMono >= sentMono)
  const range = nsmRange(samples[0])
  assert.ok(range.lo <= 0 && range.hi >= 0, JSON.stringify(range))
  // A failed run gives no sample.
  await assert.rejects(attest({}, { bin: await fakeNsm({ mode: 'fail' }), onSample: sample => samples.push(sample) }), { message: 'attest_nsm_error' })
  assert.equal(samples.length, 1)
  // A full queue refuses before anything runs.
  const full = createAttestLimit({ inFlight: 1, queue: 0 })
  let release
  const holding = full.run(() => new Promise(resolve => { release = resolve }))
  await assert.rejects(attest({}, { bin, limit: full }), { message: 'attest_busy' })
  const attestor = createAttestor({
    attest: fields => attest(fields, { bin, limit: full }), readerId: 'enclave', readerVersion: '0.6.0', resource: 'https://mcp.example/mcp',
    spki: () => 'a'.repeat(64), policy: () => 'b'.repeat(64),
  })
  const busy = await attestor.attestation({ requestId: '', publicKey: null, nonce: randomBytes(16) }).catch(e => e)
  assert.ok(busy instanceof AttestationError)
  assert.deepEqual([busy.code, busy.status], ['attest_busy', 503])
  release()
  await holding
  const object = await attestor.attestation({ requestId: '', publicKey: null, nonce: randomBytes(16) })
  assert.equal(object.pcr0, PCR0)
})

test('/attestation: 10 a minute per address and 60 a minute from all addresses together', async () => {
  let now = Date.UTC(2026, 10, 19)
  let asked = 0
  const router = createRouter({
    state: { connections: new Map() }, metadata: { respond: () => null, resourceMetadataUrl: 'https://reader.test/.well-known/oauth-protected-resource/mcp' },
    as: {}, internal: () => Response.json({}), verifier: { verifyAccessToken: async () => { throw new Error('no tokens here') } },
    limiter: createLimiter(() => now), log: { event() {} }, publicHost: 'reader.test',
    attestation: async () => { asked++; return { format: 'test' } },
  })
  const get = async source => {
    const meta = {}
    const response = await router.handle(new Request(`https://reader.test/attestation?nonce=${randomBytes(16).toString('base64url')}`, { headers: { host: 'reader.test', 'x-forwarded-for': source } }), { remoteAddress: '127.0.0.1' }, meta)
    return { status: response.status, code: meta.code, retryAfter: response.headers.get('retry-after') }
  }
  assert.equal(ATTESTATION_PER_MINUTE, 10)
  assert.equal(ATTESTATION_ALL_PER_MINUTE, 60)
  for (let i = 0; i < 10; i++) assert.equal((await get('192.0.2.1')).status, 200)
  assert.equal((await get('192.0.2.1')).status, 429, 'per address')
  // 50 more from other addresses use up the global minute.
  for (let i = 0; i < 50; i++) assert.equal((await get(`198.51.100.${i}`)).status, 200)
  const refused = await get('203.0.113.9')
  assert.deepEqual([refused.status, refused.code], [429, 'rate_limited'])
  assert.ok(Number(refused.retryAfter) >= 1)
  assert.equal(asked, 60)
  // The buckets refill: one second later one more request goes through.
  now += 1000
  assert.equal((await get('203.0.113.9')).status, 200)
  router.close()
})
