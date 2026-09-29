// The reader against what the archive server sends it since attachments
// stage A0 (docs/mcp-enclave.md §16.3). go-a0-shapes.json holds those bodies
// byte for byte, pinned against Go's encoders by
// internal/mcpauth/shapes_test.go; here they go through the reader's own
// parsers, then through the whole enclave. Go omits `media` from a relay
// unless it is true, because 0.3.0's relay parser is strict; 0.4.0 reads it,
// and a missing one as false. The hosted status parser reads only the fields
// it knows, and the attested reader's also reads `media` and `media_off`.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { bundleBody, LinkError } from '../../link.mjs'
import { createRelay } from '../../internal.mjs'
import { parseRelay } from '../content.mjs'
import { MEDIA_KINDS } from '../media/policy.mjs'
import { callTool, connectContent, world } from './world.mjs'

const shapes = JSON.parse(readFileSync(new URL('./go-a0-shapes.json', import.meta.url), 'utf8'))
const bytesOf = name => JSON.stringify(shapes[name])
// A clock a month before the pinned expiry, inside a content consent's 90 days.
const now = () => Date.parse(shapes.consent_relay_content.expires_at) - 30 * 86_400_000

test('0.4.0 takes every relay Go sends it, reading media as Go writes it and a missing one as false', () => {
  for (const [name, media] of [['consent_relay_content', false], ['renewal_relay', false], ['consent_relay_media', true]]) {
    const relayed = parseRelay(JSON.parse(bytesOf(name)), { now })
    assert.equal(relayed.connection_id, shapes[name].connection_id, name)
    assert.equal(relayed.tenant_id, shapes[name].tenant_id, name)
    assert.equal(relayed.kid, shapes[name].kid, name)
    assert.equal(relayed.expiry, Date.parse(shapes[name].expires_at), name)
    assert.equal(relayed.media, media, name)
  }
  // The hosted reader and the 2a path take the metadata relay unchanged.
  assert.equal(bundleBody.safeParse(JSON.parse(bytesOf('consent_relay_metadata'))).success, true)
  // Anything but a boolean is a bad request, as any other malformed field.
  for (const media of ['true', 1, null, {}]) {
    assert.throws(() => parseRelay({ ...JSON.parse(bytesOf('consent_relay_media')), media }, { now }), error => error instanceof LinkError && error.code === 'bad_request', String(media))
  }
})

test('the hosted relay reads Go\'s status answers as before media existed; the attested one also reads media and media_off', async () => {
  const answerTo = async (body, options = {}) => {
    const fetch = async () => new Response(body, { status: 200, headers: { 'content-type': 'application/json' } })
    return createRelay({ archive: 'https://api.wappie.thehappie.co', fetch, prefix: '/v1/mcp/enclave', headersFor: () => ({}), ...options }).status('0199b3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b')
  }
  for (const name of ['status_hosted', 'status_attested_metadata', 'status_attested_content', 'status_attested_media']) {
    const { media: _media, media_off: _off, ...before } = shapes[name]
    assert.deepEqual(await answerTo(bytesOf(name)), await answerTo(JSON.stringify(before)), name)
  }
  assert.deepEqual(await answerTo(bytesOf('status_attested_media')), {
    status: 'active', expires_at: shapes.status_attested_media.expires_at, kind: 'content', service_user_id: shapes.status_attested_media.service_user_id,
  })
  const attested = body => answerTo(body, { mediaKinds: MEDIA_KINDS })
  assert.deepEqual(await attested(bytesOf('status_attested_media')), {
    status: 'active', expires_at: shapes.status_attested_media.expires_at, kind: 'content', service_user_id: shapes.status_attested_media.service_user_id, media: true, media_off: ['pdf', 'zip'],
  })
  const content = await attested(bytesOf('status_attested_content'))
  assert.equal(content.media, false)
  assert.deepEqual(content.media_off, [])
  // A status without the fields is false and []; unknown kinds, non-strings and duplicates are dropped; only JSON true is true.
  const { media: _media, media_off: _off, ...bare } = shapes.status_attested_media
  assert.deepEqual([(await attested(JSON.stringify(bare))).media, (await attested(JSON.stringify(bare))).media_off], [false, []])
  const odd = await attested(JSON.stringify({ ...bare, media: 'true', media_off: ['zip', 'heic', 7, 'zip', 'audio'] }))
  assert.deepEqual([odd.media, odd.media_off], [false, ['audio', 'zip']])
  assert.deepEqual((await attested(JSON.stringify({ ...bare, media_off: 'pdf' }))).media_off, [])
})

test('the enclave serves a content connection on Go\'s relay and status, with and without media, and refuses a media relay for a text consent', async t => {
  const w = await world(t)
  const e = await w.start()
  const done = await connectContent(w)
  assert.equal(done.relayed.status, 204, done.relayed.body)
  // world.mjs relays exactly the fields Go sends for a consent without attachments, in its order.
  assert.deepEqual(['connection_id', 'tenant_id', 'kid', 'sealed', 'expires_at', 'kind'], Object.keys(shapes.consent_relay_content))

  const connection = w.go.connections.get(done.connectionId)
  for (const name of ['status_attested_content', 'status_attested_media']) {
    const { media, media_off } = shapes[name]
    connection.extra = { media, media_off }
    assert.equal(await e.reader.checkActive(done.connectionId, { force: true }), 'serve', name)
    const numbers = await callTool(w, done.tokens.access_token, 'list_numbers')
    assert.equal(numbers.isError, false, numbers.text)
    assert.deepEqual(await e.reader.contentSweep(), { checked: 1, wiped: 0, unreachable: 0 }, name)
    assert.equal(e.facts.content.holds(done.connectionId), true, name)
  }

  // Go says the consent includes attachments; the sealed bundle does not: nothing is proven or attached.
  const mark = w.go.archiveRequests.length
  const refused = await connectContent(w, { relay: { media: true } })
  assert.equal(refused.relayed.status, 400, refused.relayed.body)
  assert.equal(JSON.parse(refused.relayed.body).code, 'invalid_bundle')
  assert.equal(w.go.archiveRequests.slice(mark).some(item => item.path === '/v1/grants'), false, 'refused before the grant proof')
  assert.equal(e.state.connections.has(refused.connectionId), false)
  assert.equal(e.facts.content.holds(refused.connectionId), false)
})
