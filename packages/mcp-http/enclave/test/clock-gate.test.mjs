// The clock gate (reader 0.6.1): what a reader whose clock is not trusted
// still answers, what it refuses with 503 clock_unknown, and what it stops
// doing on its own (relay calls to Go, the local expiry sweeps), all through
// the whole enclave. The boot waits for a trusted clock and fails with exit
// 78 without one; ACME is never gated.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { RelayError } from '../../internal.mjs'
import { createClock, createKmsCheck } from '../clock.mjs'
import { lineAllowed } from '../logsink.mjs'
import { EXIT_BOOT_FAILED } from '../main.mjs'
import { createSignedRelay } from '../relay.mjs'
import { goHeaders } from './fixtures.mjs'
import { connect, fakeClock, form, REDIRECT_URI, RESOURCE, rpc, world } from './world.mjs'

const json = response => JSON.parse(response.body)
const events = (w, name) => w.lines.map(line => JSON.parse(line)).filter(entry => entry.event === name)
const settle = () => new Promise(resolve => setTimeout(resolve, 50)) // a request's line is written once its response has gone

function assertClockUnknown(response, what) {
  assert.equal(response.status, 503, `${what}: ${response.body}`)
  assert.deepEqual(json(response), { code: 'clock_unknown' }, what)
  assert.equal(response.headers['cache-control'], 'no-store', what)
  assert.equal(response.headers['retry-after'], '60', what)
  assert.equal(response.headers['x-wappie-code'], undefined, what)
}

test('public listener: /mcp and every /mcp/* route answer 503 clock_unknown while the clock is not trusted; discovery, icons, the page, robots.txt and /attestation stay open, other paths keep their 404', async t => {
  const clock = fakeClock()
  const w = await world(t, { clock })
  await w.start()
  const done = await connect(w)
  assert.equal((await rpc(w, done.tokens.access_token)).status, 200)

  clock.open = false
  assertClockUnknown(await rpc(w, done.tokens.access_token), 'POST /mcp')
  assertClockUnknown(await w.public('/mcp/token', form({ grant_type: 'refresh_token', refresh_token: done.tokens.refresh_token, client_id: done.clientId, resource: RESOURCE })), '/mcp/token')
  const query = new URLSearchParams({ response_type: 'code', client_id: done.clientId, redirect_uri: REDIRECT_URI, code_challenge: 'x'.repeat(43), code_challenge_method: 'S256', resource: RESOURCE })
  assertClockUnknown(await w.public(`/mcp/authorize?${query}`), '/mcp/authorize')
  assertClockUnknown(await w.public('/mcp/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: 'Claude', redirect_uris: [REDIRECT_URI] }) }), '/mcp/register')
  assertClockUnknown(await w.public('/mcp/revoke', form({ token: done.tokens.refresh_token, client_id: done.clientId })), '/mcp/revoke')
  assertClockUnknown(await w.public('/mcp/authorize/complete', form({ request: 'x', proof: 'y' })), '/mcp/authorize/complete')
  assertClockUnknown(await w.public('/mcp/Not-A-Route'), 'an unknown /mcp/* path')
  assertClockUnknown(await w.public('/mcp', { method: 'GET' }), 'GET /mcp')

  for (const path of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-authorization-server', '/favicon.ico', '/', '/robots.txt']) {
    assert.equal((await w.public(path)).status, 200, path)
  }
  const attested = await w.public(`/attestation?nonce=${randomBytes(32).toString('base64url')}`)
  assert.equal(attested.status, 200, attested.body)
  assert.ok(json(attested).attestation)
  for (const path of ['/nope', '/mcpx', '/v1/mcp']) assert.equal((await w.public(path)).status, 404, path)

  await settle()
  const refused = w.lines.map(line => JSON.parse(line)).filter(entry => entry.code === 'clock_unknown')
  assert.ok(refused.some(entry => entry.route === 'POST /mcp' && entry.status === 503))
  assert.ok(refused.some(entry => entry.route === 'unmatched' && entry.status === 503), 'an unknown /mcp/* path is logged as unmatched')
  for (const line of w.lines) assert.equal(lineAllowed(line), true, line)

  // Trusted again: everything is as it was.
  clock.open = true
  assert.equal((await rpc(w, done.tokens.access_token)).status, 200)
})

test('internal listener: the HMAC guard runs first; a valid or stale signature gets 503 clock_unknown (healthz\'s stale one with the health object), healthz 200 with state clock_unknown; unsigned or forged stays 401', async t => {
  const clock = fakeClock()
  const w = await world(t, { clock })
  await w.start()
  const healthz = '/internal/healthz', other = `/internal/requests/${'A'.repeat(22)}`
  const stale = (path, secret = w.relaySecret) => goHeaders(secret, { method: 'GET', target: path, now: Date.now() - 90_000 })

  clock.open = false
  const heardBefore = clock.go.length
  // No valid signature: 401 whatever the clock says, so an unsigned caller learns nothing of it.
  for (const [what, options] of [['unsigned', { signed: {} }], ['wrong secret', { secret: 'x'.repeat(43) }], ['stale, wrong secret', { signed: stale(healthz, 'x'.repeat(43)) }]]) {
    for (const path of [healthz, other]) {
      const response = await w.internal(path, options)
      assert.equal(response.status, 401, `${what} ${path}`)
      assert.deepEqual(json(response), { code: 'unauthorized' })
    }
  }
  assert.equal(clock.go.length, heardBefore, 'a forged timestamp records nothing')
  // Go's real signature that looks stale: our clock is the likely fault.
  // healthz's 503 carries the health object, so Go still learns why; any other route's is bare.
  const staleHealth = await w.internal(healthz, { signed: stale(healthz) })
  assert.equal(staleHealth.status, 503, staleHealth.body)
  for (const [name, value] of [['cache-control', 'no-store'], ['retry-after', '60'], ['x-wappie-code', undefined]]) assert.equal(staleHealth.headers[name], value, name)
  const staleBody = json(staleHealth)
  assert.equal(staleBody.code, 'clock_unknown')
  assert.equal(staleBody.state, 'clock_unknown')
  assert.match(staleBody.boot_id, /^[0-9a-f]{16}$/)
  assert.match(staleBody.pcr0, /^[0-9a-f]{96}$/)
  for (const key of ['clock_ok', 'clock_unc_ms', 'nsm_skew_ms', 'go_skew_ms', 'clock_code', 'clock_disagree_kms', 'kms_skew_lo_ms', 'kms_skew_hi_ms', 'clock_corr_hour_ms', 'clock_corr_day_ms']) assert.ok(key in staleBody, key)
  assert.equal(staleBody.clock_ok, false)
  assert.equal(staleBody.clock_code, 'unc_high')
  assertClockUnknown(await w.internal(other, { signed: stale(other) }), 'stale request')
  const postStale = `/internal/connections/${'0'.repeat(8)}-0000-4000-8000-${'0'.repeat(12)}/revoke`
  assertClockUnknown(await w.internal(postStale, { method: 'POST', signed: goHeaders(w.relaySecret, { method: 'POST', target: postStale, now: Date.now() - 90_000 }) }), 'stale POST')
  assert.equal(clock.go.length, heardBefore + 3, 'Go\'s time is heard from a stale but verified signature')
  // A valid one: every route but healthz is refused, healthz says why.
  assertClockUnknown(await w.internal(other), 'valid request')
  const health = await w.internal(healthz)
  assert.equal(health.status, 200, health.body)
  const body = json(health)
  assert.deepEqual(Object.keys(staleBody), [...Object.keys(body), 'code'], 'the stale 503 is the health object, code added')
  assert.equal(body.state, 'clock_unknown')
  assert.equal(body.clock_ok, false)
  assert.equal(body.clock_unc_ms, null)
  assert.equal(body.nsm_skew_ms, null)
  assert.ok('go_skew_ms' in body)

  // Trusted: a stale signature is 401 hmac_stale as before, healthz is ready.
  clock.open = true
  const staleOk = await w.internal(healthz, { signed: stale(healthz) })
  assert.equal(staleOk.status, 401)
  assert.deepEqual(json(staleOk), { code: 'unauthorized' })
  const ready = json(await w.internal(healthz))
  assert.deepEqual([ready.state, ready.clock_ok, ready.clock_unc_ms], ['ready', true, 12])
  assert.equal((await w.internal(other)).status, 404, 'an unknown request id, as before')

  await settle()
  const codes = w.lines.map(line => JSON.parse(line)).filter(entry => entry.route === 'internal').map(entry => entry.code)
  for (const code of ['hmac_missing', 'hmac_bad', 'clock_unknown', 'hmac_stale']) assert.ok(codes.includes(code), code)
  for (const line of w.lines) assert.equal(lineAllowed(line), true, line)
})

test('the relay sends nothing to Go while the clock is not trusted, counts each refusal, and the sweeps skip their turn', async t => {
  const clock = fakeClock()
  const w = await world(t, { clock })
  const e = await w.start()
  const done = await connect(w)
  const record = e.state.connections.get(done.connectionId)
  record.expires_at = new Date(Date.now() - 1000).toISOString()

  clock.open = false
  const calls = w.go.calls.length
  assert.equal(await e.reader.sweep(), false)
  assert.equal(await e.reader.contentSweep(), null)
  assert.ok(e.state.connections.has(done.connectionId), 'an expired connection is kept while the clock is not trusted')
  await assert.rejects(e.reader.checkActive(done.connectionId, { force: true }))
  assert.equal(w.go.calls.length, calls, 'nothing reached Go')
  assert.ok(clock.refused >= 1)

  clock.open = true
  assert.equal(await e.reader.sweep(), true)
  assert.equal(e.state.connections.has(done.connectionId), false, 'the next sweep with a trusted clock expires it')
  assert.ok(w.go.calls.length > calls, 'Go hears from the reader again')
})

test('the signed relay: a call refused for the clock is RelayError clock_unknown, made before anything is signed or fetched', async () => {
  let open = false, refused = 0, fetched = 0, signed = 0
  const clock = { ok: () => open, noteRefused: () => { refused++ } }
  const secrets = { get current() { signed++; return 'S'.repeat(43) } }
  const relay = createSignedRelay({ base: 'https://api.example', readerId: 'enclave', secrets, clock, fetch: async () => { fetched++; return new Response(null, { status: 204 }) } })
  for (const call of [() => relay.status('c'), () => relay.stateGet('infra'), () => relay.sending('c', 'k', 'POST', 'send', { body: {} }), () => relay.budgetHit('c', 'x'), () => relay.reseal('c')]) {
    await assert.rejects(call(), error => error instanceof RelayError && error.code === 'clock_unknown')
  }
  assert.equal(await relay.revoke('c'), false, 'revoke stays best effort')
  assert.deepEqual([fetched, signed, refused], [0, 0, 6])
  open = true
  assert.equal(await relay.activate('c'), true)
  assert.deepEqual([fetched, refused], [1, 6])
})

test('ACME is not gated: a clock that turns untrusted during the boot still gets the certificate, and the reader then serves only what the gate allows', async t => {
  let w = null
  // Trusted until the first order reaches the ACME server, then not.
  const clock = fakeClock({ open: () => w === null || w.acme.orders.size === 0 })
  w = await world(t, { clock })
  await w.start()
  assert.equal(w.acme.issued, 1)
  assert.equal(events(w, 'enclave_ready').length, 1)
  assert.equal(json(await w.internal('/internal/healthz')).state, 'clock_unknown')
  assertClockUnknown(await w.public('/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }), 'POST /mcp')
  assert.equal((await w.public(`/attestation?nonce=${randomBytes(32).toString('base64url')}`)).status, 200)
})

test('boot: step 2b waits for the clock after the first attestation and before the relay secret; a clock that never becomes trusted ends the boot with clock_unknown and exit 78', async t => {
  let at = 0
  const clock = createClock({ readState: async () => { throw new Error('missing') }, perf: () => at, wait: async ms => { at += ms }, probe: async () => {} })
  const w = await world(t, { clock })
  await assert.rejects(w.start(), { name: 'BootFailure', code: 'clock_unknown' })
  assert.deepEqual(w.exits, [EXIT_BOOT_FAILED])
  assert.equal(at, 180_000, 'it waited the whole READY_TIMEOUT_MS')
  const names = w.lines.map(line => JSON.parse(line).event)
  assert.ok(names.indexOf('clock_wait') >= 0 && names.indexOf('clock_wait') < names.indexOf('boot_failed'))
  assert.deepEqual(events(w, 'boot_failed').map(entry => entry.code), ['clock_unknown'])
  assert.ok(w.nsmCalls.length >= 1, 'the first attestation came before the wait')
  assert.deepEqual(w.kms.calls, [], 'the relay secret was never opened')
  assert.deepEqual(w.go.calls, [], 'Go never heard from the reader')
  for (const line of w.lines) assert.equal(lineAllowed(line), true, line)
})

test('a real clock behind the gate: the boot waits for agreement, then the gate closes above 5 s and reopens only below 1 s', async t => {
  const helper = { v: 1, state: 'ok', synced: true, nsm_skew_ms: 3, rtt_us: 400, corr_hour_ms: 0, corr_day_ms: 0, freq_ppm: -17, steps: 1 }
  const monoNs = () => Number(process.hrtime.bigint())
  const kms = createKmsCheck()
  let probes = 0
  // KMS agrees: a range of 1.2 s around zero, taken now.
  const probe = async () => { probes++; const m = performance.now(); kms.add({ lo: -900, hi: 300, anchor: Date.now() - m, mono: m }) }
  const seen = []
  const log = { event: (event, fields = {}) => seen.push({ event, ...fields }) }
  const clock = createClock({ readState: async () => JSON.stringify({ ...helper, mono_ns: monoNs(), last_good_mono_ns: monoNs() }), kms, probe, log, wait: () => new Promise(resolve => setTimeout(resolve, 1)) })
  const w = await world(t, { clock })
  const e = await w.start()
  assert.ok(probes >= 2, 'two KMS ranges after synced, as the boot rule asks')
  const done = await connect(w)
  assert.equal((await rpc(w, done.tokens.access_token)).status, 200)
  const healthOf = async () => json(await w.internal('/internal/healthz'))
  const keys = ['state', 'clock_ok', 'nsm_skew_ms', 'clock_code', 'clock_disagree_kms', 'clock_corr_hour_ms', 'clock_corr_day_ms']
  assert.deepEqual(Object.fromEntries(Object.entries(await healthOf()).filter(([key]) => keys.includes(key))),
    { state: 'ready', clock_ok: true, nsm_skew_ms: 3, clock_code: 'ok', clock_disagree_kms: 0, clock_corr_hour_ms: 0, clock_corr_day_ms: 0 })
  const opened = await healthOf()
  assert.ok(Number.isInteger(opened.kms_skew_lo_ms) && Number.isInteger(opened.kms_skew_hi_ms) && opened.kms_skew_lo_ms <= opened.kms_skew_hi_ms, JSON.stringify(opened))

  const set = async skew => { helper.nsm_skew_ms = skew; await clock.refresh() }
  await set(4000) // open, and under 5 s: stays open
  assert.equal((await rpc(w, done.tokens.access_token)).status, 200)
  await set(6000) // over 5 s: closes
  assertClockUnknown(await rpc(w, done.tokens.access_token), 'over 5 s')
  const closed = await healthOf()
  assert.deepEqual([closed.state, closed.clock_ok, closed.clock_code], ['clock_unknown', false, 'unc_high'])
  assert.ok(closed.clock_unc_ms > 6000)
  await set(2000) // closed, and not under 1 s: stays closed
  assertClockUnknown(await rpc(w, done.tokens.access_token), 'closed at 2 s')
  await set(300) // under 1 s: reopens
  assert.equal((await rpc(w, done.tokens.access_token)).status, 200)

  // The health line carries the clock's fields, and passes the sink's schema.
  const entry = await e.health.tick()
  for (const key of ['clock_ok', 'clock_unc_ms', 'nsm_skew_ms', 'clock_freq_ppm', 'clock_steps', 'clock_refused', 'kms_skew_lo_ms', 'kms_skew_hi_ms']) assert.ok(key in entry, key)
  assert.equal(entry.clock_ok, true)
  assert.deepEqual(seen.filter(item => item.event === 'clock_state').map(item => item.code), ['helper_stale', 'ok', 'unc_high', 'ok'])
  for (const line of w.lines) assert.equal(lineAllowed(line), true, line)
})
