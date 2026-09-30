// The reader against what the archive server sends it for AI integrations,
// stage B1 (docs/mcp-enclave.md §18.7, §18.11). go-b1-shapes.json holds those
// bodies byte for byte, pinned against Go's encoders by
// internal/mcpauth/ai_shapes_test.go; here each goes through the parser the
// enclave uses for it: the AI request's nonce, the consent's and the
// renewal's relays, a console's job, the status of an `ai` row with its
// `ai_off`, the authorization Go picks for a connector, the stored results
// and the month's usage. A field Go adds that the reader would refuse, or a
// value it would read differently, fails here.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { derivedBytes } from '@whatserver2/mcp/reader'
import { decodeNonce } from '../../attestation.mjs'
import { createRelay } from '../../internal.mjs'
import { LinkError } from '../../link.mjs'
import { createLog } from '../../log.mjs'
import { parseRelay } from '../content.mjs'
import { createBudgets } from '../ai/budget.mjs'
import { parseAIRelay } from '../ai/install.mjs'
import { AI_FUNCTIONS, AI_PROVIDERS } from '../ai/policy.mjs'
import { createAIService } from '../ai/service.mjs'
import { MEDIA_KINDS } from '../media/policy.mjs'

const shapes = JSON.parse(readFileSync(new URL('./go-b1-shapes.json', import.meta.url), 'utf8'))
const bytesOf = name => JSON.stringify(shapes[name])
const body = name => JSON.parse(bytesOf(name))
// A clock a month before the pinned expiry, inside an AI authorization's 90 days.
const now = () => Date.parse(shapes.consent_relay_ai.expires_at) - 30 * 86_400_000
const refused = code => error => error instanceof LinkError && error.code === code
const RESOURCE = 'https://mcp.wappie.thehappie.co/mcp'

test('every name Go pins is one this test reads', () => {
  assert.deepEqual(Object.keys(shapes).filter(name => name !== '_comment').sort(), ['ai_derived_items', 'ai_derived_none', 'ai_job', 'ai_job_redo', 'ai_pick_active', 'ai_pick_reseal',
    'ai_request', 'ai_usage_month', 'consent_relay_ai', 'renewal_relay_ai', 'status_attested_ai', 'status_attested_ai_off', 'status_attested_ai_reseal'])
})

test('the AI request\'s body is the nonce the prepare route decodes', () => {
  assert.deepEqual(Object.keys(body('ai_request')), ['nonce'])
  assert.equal(decodeNonce(body('ai_request').nonce).length, 16)
})

test('the consent\'s and the renewal\'s relays read as AI relays, never as a content connection\'s', () => {
  for (const name of ['consent_relay_ai', 'renewal_relay_ai']) {
    const relayed = parseAIRelay(body(name), { now })
    assert.equal(relayed.connection_id, shapes[name].connection_id, name)
    assert.equal(relayed.tenant_id, shapes[name].tenant_id, name)
    assert.equal(relayed.kid, shapes[name].kid, name)
    assert.equal(relayed.expiry, Date.parse(shapes[name].expires_at), name)
    assert.equal(relayed.sealed.toString('base64url'), shapes[name].sealed, name)
    assert.throws(() => parseRelay(body(name), { now }), refused('bad_request'), name)
    // Without the kind, or with a content relay's fields, it is not an AI relay.
    const { kind: _kind, ...bare } = body(name)
    assert.throws(() => parseAIRelay(bare, { now }), refused('bad_request'), name)
    assert.throws(() => parseAIRelay({ ...body(name), media: false }, { now }), refused('bad_request'), name)
  }
})

/** The AI service over a state with no records, a relay answering `answers[route]`, and nothing else. */
function service(answers = {}) {
  const calls = []
  const relay = {
    async ai(id, apiKey, method, route, options = {}) {
      calls.push({ id, method, route, query: options.query ?? null })
      const found = answers[route]
      if (!found) throw new Error(`unexpected route ${route}`)
      return found
    },
  }
  const state = { connections: new Map() }
  const ai = createAIService({ state, relay, log: createLog(() => {}), resource: RESOURCE, archive: 'https://api.wappie.thehappie.co', consoleURL: 'https://app.wappie.thehappie.co',
    attestor: null, readerVersion: '0.5.0', pendingTTLMs: 60_000, newRecipient: async () => null, connkeys: new Map(), fetch: async () => { throw new Error('no archive here') },
    transport: async () => { throw new Error('no provider here') }, media: () => null })
  return { ai, state, calls }
}

test('a console\'s job, and its redo, are the fields POST /internal/ai/jobs takes, and nothing else', async () => {
  for (const name of ['ai_job', 'ai_job_redo']) {
    const { ai, state } = service()
    // Shape accepted: no such record here.
    await assert.rejects(ai.submit(body(name)), refused('not_found'), name)
    // The record exists but holds no keys: the gate answers, so the body was read.
    state.connections.set(shapes[name].authorization_id, { kind: 'ai', connection_id: shapes[name].authorization_id, functions: {}, features: {} })
    await assert.rejects(ai.submit(body(name)), error => refused('ai_paused')(error) && error.status === 409, name)
    for (const odd of [{ extra: true }, { origin: 'connector' }, { redo: 'false' }, { feature: 'sticker' }]) {
      await assert.rejects(ai.submit({ ...body(name), ...odd }), refused('bad_request'), `${name} ${JSON.stringify(odd)}`)
    }
    const { redo: _redo, ...missing } = body(name)
    await assert.rejects(ai.submit(missing), refused('bad_request'), name)
  }
  assert.equal(shapes.ai_job.redo, false)
  assert.equal(shapes.ai_job_redo.redo, true)
})

test('the status of an ai row: its kind, service account and ai_off as Go writes them', async () => {
  const answerTo = async text => {
    const fetch = async () => new Response(text, { status: 200, headers: { 'content-type': 'application/json' } })
    return createRelay({ archive: 'https://api.wappie.thehappie.co', fetch, prefix: '/v1/mcp/enclave', headersFor: () => ({}), mediaKinds: MEDIA_KINDS, send: true,
      ai: { functions: AI_FUNCTIONS, providers: Object.keys(AI_PROVIDERS) } }).status('0199b3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b')
  }
  const service = '0199b3c4-0000-7000-8000-00000000c0de'
  assert.deepEqual(await answerTo(bytesOf('status_attested_ai')), { status: 'active', expires_at: '2026-10-28T12:00:00Z', kind: 'ai', service_user_id: service, media: false, media_off: [],
    send: null, send_self: false, ai_off: { functions: [], providers: [], paused: false, monthly_tokens: null } })
  assert.deepEqual(await answerTo(bytesOf('status_attested_ai_off')), { status: 'active', expires_at: '2026-10-28T12:00:00Z', kind: 'ai', service_user_id: service, media: false,
    media_off: ['pdf', 'zip'], send: null, send_self: false, ai_off: { functions: ['document', 'image', 'video'], providers: ['anthropic'], paused: true, monthly_tokens: 2_500_000 } })
  assert.deepEqual((await answerTo(bytesOf('status_attested_ai_reseal'))).status, 'reseal')
  // Without its ai_off an ai row reads as paused: nothing runs on a status Go did not finish.
  const { ai_off: _off, ...bare } = body('status_attested_ai')
  assert.equal((await answerTo(JSON.stringify(bare))).ai_off.paused, true)
})

test('the authorization Go picks for a connector, active or waiting for its renewal', async () => {
  for (const [name, state] of [['ai_pick_active', 'active'], ['ai_pick_reseal', 'reseal']]) {
    const { ai, calls } = service({ ai: { status: 200, data: body(name) } })
    const connector = ai.connectorFor({ connection_id: '0199b3c4-1111-7222-8333-444455556666', api_key: 'wsk_fixture', tenant_id: '01a08e0e-c546-7db3-9c44-e6352636d330' })
    assert.deepEqual(await connector.pick('0199b3c4-3333-7444-8555-666677778888', 'audio'), { authorization_id: shapes[name].authorization_id, requester_id: shapes[name].requester_id, state })
    assert.deepEqual(calls[0].query, { device_id: '0199b3c4-3333-7444-8555-666677778888', feature: 'audio' })
  }
  const { ai } = service({ ai: { status: 404, data: { code: 'ai_not_enabled' } } })
  assert.equal(await ai.connectorFor({ connection_id: '0199b3c4-1111-7222-8333-444455556666', api_key: 'wsk_fixture' }).pick('0199b3c4-3333-7444-8555-666677778888', 'audio'), null)
})

test('stored results: the items a connector\'s grant would open, their sealed bytes read in Go\'s spelling', async () => {
  const item = shapes.ai_derived_items.items[0]
  const bytes = derivedBytes(item.sealed)
  assert.ok(bytes, 'Go\'s sealed spelling is one the reader reads')
  assert.equal(bytes.subarray(0, 4).toString('latin1'), 'WDRV')
  assert.equal(item.sealed, bytes.toString('base64url'))
  const { ai } = service({ 'ai/derived': { status: 200, data: body('ai_derived_items') } })
  const connector = ai.connectorFor({ connection_id: '0199b3c4-1111-7222-8333-444455556666', api_key: 'wsk_fixture' })
  const row = { device_id: item.device_id, uid: item.message_uid }
  let handed = null
  assert.equal(await connector.stored(row, 'audio', { derived: async (_row, items) => { handed = items; return 'opened' } }), 'opened')
  assert.deepEqual(handed, shapes.ai_derived_items.items)
  assert.equal(await connector.stored(row, 'video', { derived: async () => 'never' }), null)
  const none = service({ 'ai/derived': { status: 200, data: body('ai_derived_none') } })
  assert.equal(await none.ai.connectorFor({ connection_id: '0199b3c4-1111-7222-8333-444455556666', api_key: 'wsk_fixture' }).stored(row, 'audio', { derived: async () => 'never' }), null)
})

test('the month\'s usage is what the budget reads from Go', () => {
  const at = () => Date.parse(`${shapes.ai_usage_month.month}-15T12:00:00Z`)
  const budgets = createBudgets({ now: at })
  budgets.fromGo('a', body('ai_usage_month'))
  assert.deepEqual(budgets.used('a'), { tokens: shapes.ai_usage_month.charged_tokens, items: shapes.ai_usage_month.items_today })
  // 240,000 tokens are under a cap of 240,001 and at one of 240,000; two items under a limit of three.
  assert.equal(budgets.allows({ connection_id: 'a', budget: { monthly_tokens: 240_001, request_items_per_day: 3 } }, null), true)
  assert.equal(budgets.limit({ connection_id: 'a', budget: { monthly_tokens: 240_000, request_items_per_day: 3 } }, null), 'month')
  assert.equal(budgets.limit({ connection_id: 'a', budget: { monthly_tokens: 240_001, request_items_per_day: 2 } }, null), 'day')
})
