// The reader against what the archive server sends it since sending stage S0
// (docs/mcp-enclave.md §17.3, §17.17). go-s0-shapes.json holds those bodies
// byte for byte, pinned against Go's encoders by
// internal/mcpauth/shapes_test.go; here they go through the reader's own
// parsers, then through the whole enclave. S0 shipped no reader, and 0.4.x
// refused a relay with any send field (its parser was strict), so a consent
// with sending failed closed there. From 0.5.0 the relay's send fields are
// read and must equal what the owner sealed (§17.2 rule 5): a relay that
// claims sending the bundle does not carry still fails closed, before any
// grant proof. Every body Go sends for a connection without sending reads
// exactly as before.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { bundleBody, LinkError } from '../../link.mjs'
import { createRelay } from '../../internal.mjs'
import { parseRelay } from '../content.mjs'
import { MEDIA_KINDS } from '../media/policy.mjs'
import { callTool, connectContent, connectMedia, world } from './world.mjs'

const shapes = JSON.parse(readFileSync(new URL('./go-s0-shapes.json', import.meta.url), 'utf8'))
const a0 = JSON.parse(readFileSync(new URL('./go-a0-shapes.json', import.meta.url), 'utf8'))
const bytesOf = name => JSON.stringify(shapes[name])
// A clock a month before the pinned expiry, inside a content consent's 90 days.
const now = () => Date.parse(shapes.consent_relay_content.expires_at) - 30 * 86_400_000
const refusedAsBadRequest = error => error instanceof LinkError && error.code === 'bad_request'

test('every relay Go sends without sending is the one A0 sent, and 0.4.x takes it as before', () => {
  for (const name of ['consent_relay_metadata', 'consent_relay_content', 'consent_relay_media', 'renewal_relay']) {
    assert.equal(bytesOf(name), JSON.stringify(a0[name]), name)
  }
  for (const [name, media] of [['consent_relay_content', false], ['renewal_relay', false], ['consent_relay_media', true]]) {
    const relayed = parseRelay(JSON.parse(bytesOf(name)), { now })
    assert.equal(relayed.connection_id, shapes[name].connection_id, name)
    assert.equal(relayed.media, media, name)
  }
  assert.equal(bundleBody.safeParse(JSON.parse(bytesOf('consent_relay_metadata'))).success, true)
})

test('0.5.0 reads the send fields of Go\'s relays, and refuses a send field without send or of the wrong type as a bad request', () => {
  assert.deepEqual(pick(parseRelay(JSON.parse(bytesOf('consent_relay_send')), { now })), { media: false, send: 'draft', send_self: false, send_groups: false, send_chats: [] })
  assert.deepEqual(pick(parseRelay(JSON.parse(bytesOf('consent_relay_send_all')), { now })), { media: true, send: 'draft', send_self: true, send_groups: true, send_chats: [] })
  for (const name of ['consent_relay_content', 'consent_relay_media', 'renewal_relay']) {
    assert.deepEqual(pick(parseRelay(JSON.parse(bytesOf(name)), { now })), { media: name === 'consent_relay_media', send: null, send_self: false, send_groups: false, send_chats: [] }, name)
  }
  // Each field without send, as Go never sends it, and every other shape, is refused.
  for (const extra of [{ send_self: true }, { send_groups: true }, { send_chats: [] }, { send: 'none' }, { send: true }, { send: 'draft', send_self: 'true' },
    { send: 'draft', send_groups: 1 }, { send: 'direct', send_chats: {} }, { send: 'direct', send_chats: [{ device_id: 'x', chat_key: 'y' }] },
    { send: 'direct', send_chats: [{ device_id: '0199b3c4-3333-7444-8555-666677778888', chat_key: '' }] }]) {
    assert.throws(() => parseRelay({ ...JSON.parse(bytesOf('consent_relay_content')), ...extra }, { now }), refusedAsBadRequest, JSON.stringify(extra))
  }
})
const pick = ({ media, send, send_self, send_groups, send_chats }) => ({ media, send, send_self, send_groups, send_chats })

test('both status parsers read Go\'s answers with send and send_self exactly as they read them before S0', async () => {
  const answerTo = async (body, options = {}) => {
    const fetch = async () => new Response(body, { status: 200, headers: { 'content-type': 'application/json' } })
    return createRelay({ archive: 'https://api.wappie.thehappie.co', fetch, prefix: '/v1/mcp/enclave', headersFor: () => ({}), ...options }).status('0199b3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b')
  }
  const statuses = Object.keys(shapes).filter(name => name.startsWith('status_'))
  assert.deepEqual(statuses.sort(), ['status_attested_content', 'status_attested_media', 'status_attested_metadata', 'status_attested_send', 'status_attested_send_self', 'status_hosted'])
  for (const name of statuses) {
    const { send, send_self, ...before } = shapes[name]
    for (const options of [{}, { mediaKinds: MEDIA_KINDS }]) {
      const read = await answerTo(bytesOf(name), options)
      assert.deepEqual(read, await answerTo(JSON.stringify(before), options), name)
      assert.equal(Object.hasOwn(read, 'send') || Object.hasOwn(read, 'send_self'), false, name)
    }
    // The attested reader's parser (0.5.0) reads them too; a missing send is null and a missing send_self false.
    const enclave = { mediaKinds: MEDIA_KINDS, send: true }
    const read = await answerTo(bytesOf(name), enclave)
    assert.deepEqual([read.send, read.send_self], [send ?? null, send_self === true], name)
    const { send: _send, send_self: _self, ...rest } = read
    assert.deepEqual(rest, await answerTo(JSON.stringify(before), { mediaKinds: MEDIA_KINDS }), name)
    assert.deepEqual([(await answerTo(JSON.stringify(before), enclave)).send, (await answerTo(JSON.stringify(before), enclave)).send_self], [null, false], name)
  }
  for (const odd of [{ send: 'none' }, { send: true }, { send_self: 'true' }, { send: 'DRAFT', send_self: 1 }]) {
    const read = await answerTo(JSON.stringify({ ...shapes.status_attested_send, ...odd }), { mediaKinds: MEDIA_KINDS, send: true })
    assert.deepEqual([read.send, read.send_self], [Object.hasOwn(odd, 'send') ? null : 'draft', false], JSON.stringify(odd))
  }
  // A connection without sending answers as A0 did but for the two new fields, null and false.
  for (const name of ['status_attested_metadata', 'status_attested_content', 'status_attested_media']) {
    const { send, send_self, ...rest } = shapes[name]
    assert.deepEqual([send, send_self], [null, false], name)
    assert.deepEqual(rest, a0[name], name)
  }
  assert.deepEqual(shapes.status_hosted, a0.status_hosted)
})

test('the enclave serves a content connection on Go\'s S0 status, and refuses a consent with sending before any proof', async t => {
  const w = await world(t)
  const e = await w.start()
  const done = await connectContent(w)
  assert.equal(done.relayed.status, 204, done.relayed.body)
  const connection = w.go.connections.get(done.connectionId)
  for (const name of ['status_attested_content', 'status_attested_send', 'status_attested_send_self']) {
    const { media, media_off, send, send_self } = shapes[name]
    connection.extra = { media, media_off, send, send_self }
    assert.equal(await e.reader.checkActive(done.connectionId, { force: true }), 'serve', name)
    const numbers = await callTool(w, done.tokens.access_token, 'list_numbers')
    assert.equal(numbers.isError, false, numbers.text)
    assert.deepEqual(await e.reader.contentSweep(), { checked: 1, wiped: 0, unreachable: 0 }, name)
    assert.equal(e.facts.content.holds(done.connectionId), true, name)
  }
  const media = await connectMedia(w)
  w.go.connections.get(media.connectionId).extra = { media: true, media_off: [], send: 'draft', send_self: true }
  assert.equal(await e.reader.checkActive(media.connectionId, { force: true }), 'serve')

  // Go relays a consent with sending the owner never sealed: the reader refuses it as an invalid bundle once
  // it opened it, before it proves anything, and Go undoes the consent.
  for (const relay of [{ send: 'draft' }, { send: 'draft', send_self: true, send_groups: true, media: true }]) {
    const mark = w.go.archiveRequests.length
    const refused = await connectContent(w, { relay })
    assert.equal(refused.relayed.status, 400, refused.relayed.body)
    assert.equal(JSON.parse(refused.relayed.body).code, 'invalid_bundle')
    assert.equal(w.go.archiveRequests.slice(mark).some(item => item.path === '/v1/grants'), false, 'refused before the grant proof')
    assert.equal(e.state.connections.has(refused.connectionId), false)
    assert.equal(e.facts.content.holds(refused.connectionId), false)
  }
})
