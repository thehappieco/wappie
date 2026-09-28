// The reader that is live (0.3.0) against what the archive server sends it
// since attachments stage A0 (docs/mcp-enclave.md §16.3). go-a0-shapes.json
// holds those bodies byte for byte, pinned against Go's encoders by
// internal/mcpauth/shapes_test.go; here they go through 0.3.0's own parsers,
// then through the whole enclave. Go omits `media` from a relay unless it is
// true, because the relay parser is strict; the status parser reads only the
// fields it knows, so `media` and `media_off` always ride along.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { bundleBody, LinkError } from '../../link.mjs'
import { createRelay } from '../../internal.mjs'
import { parseRelay } from '../content.mjs'
import { callTool, connectContent, world } from './world.mjs'

const shapes = JSON.parse(readFileSync(new URL('./go-a0-shapes.json', import.meta.url), 'utf8'))
const bytesOf = name => JSON.stringify(shapes[name])
// A clock a month before the pinned expiry, inside a content consent's 90 days.
const now = () => Date.parse(shapes.consent_relay_content.expires_at) - 30 * 86_400_000

test('0.3.0 takes every relay Go sends it unless the consent asks for attachments, which it refuses before opening anything', () => {
  for (const name of ['consent_relay_content', 'renewal_relay']) {
    const relayed = parseRelay(JSON.parse(bytesOf(name)), { now })
    assert.equal(relayed.connection_id, shapes[name].connection_id, name)
    assert.equal(relayed.tenant_id, shapes[name].tenant_id, name)
    assert.equal(relayed.kid, shapes[name].kid, name)
    assert.equal(relayed.expiry, Date.parse(shapes[name].expires_at), name)
  }
  // The hosted reader and the 2a path take the metadata relay unchanged.
  assert.equal(bundleBody.safeParse(JSON.parse(bytesOf('consent_relay_metadata'))).success, true)
  // A media consent never reaches 0.3.0 in practice (the console seals
  // version 2 only for a release that declares it, and 0.3.0 refuses a
  // version-2 bundle anyway); if it did, the strict body refuses it first,
  // and Go undoes the consent.
  assert.throws(() => parseRelay(JSON.parse(bytesOf('consent_relay_media')), { now }), error => error instanceof LinkError && error.code === 'bad_request')
})

test('0.3.0 reads Go\'s status answers as it read them before media and media_off existed', async () => {
  const answerTo = async body => {
    const fetch = async () => new Response(body, { status: 200, headers: { 'content-type': 'application/json' } })
    return createRelay({ archive: 'https://api.wappie.thehappie.co', fetch, prefix: '/v1/mcp/enclave', headersFor: () => ({}) }).status('0199b3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b')
  }
  for (const name of ['status_hosted', 'status_attested_metadata', 'status_attested_content', 'status_attested_media']) {
    const { media: _media, media_off: _off, ...before } = shapes[name]
    assert.deepEqual(await answerTo(bytesOf(name)), await answerTo(JSON.stringify(before)), name)
  }
  assert.deepEqual(await answerTo(bytesOf('status_attested_media')), {
    status: 'active', expires_at: shapes.status_attested_media.expires_at, kind: 'content', service_user_id: shapes.status_attested_media.service_user_id,
  })
})

test('the enclave serves a content connection on Go\'s relay and status, with and without media, and refuses a media relay', async t => {
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

  const refused = await connectContent(w, { relay: { media: true } })
  assert.equal(refused.relayed.status, 400, refused.relayed.body)
  assert.equal(JSON.parse(refused.relayed.body).code, 'bad_request')
  assert.equal(e.state.connections.has(refused.connectionId), false)
  assert.equal(e.facts.content.holds(refused.connectionId), false)
})
