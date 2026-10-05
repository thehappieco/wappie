// The identifiers a result carries (docs/mcp-enclave.md §19.32, the owner's
// decision of 2026-10-05): the ones a tool takes, once. No WhatsApp message
// id, no sender phone JID or LID beside sender_key, no chat aliases or row
// uid, no number's own phone, no copy of a hit's ids in its source, no
// contact row uid; a reply's quoted message by uid where this call read it;
// a contact's phones only for a phone query or when the user asked; and
// resolve_contact's cursor sealed. Inputs accept what they did.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Client } from '@modelcontextprotocol/client'
import { InMemoryTransport } from '@modelcontextprotocol/server'
import { validateConfig } from '../config.mjs'
import { createReader } from '../reader.mjs'
import { createServer } from '../server.mjs'
import { contactKey, contentFixture, device, interval, service, token, uid, workspace } from './content-fixture.mjs'

const chat = '5511999990000@s.whatsapp.net', group = '120363041234567890@g.us'
const senderLID = '4242@lid', senderPN = '5511977770000@s.whatsapp.net', oldSender = '5511966660000@s.whatsapp.net'
const otherDevice = '018f3a2b-2222-7000-8000-00000000cccc'
const contentConfig = (server, extra = {}) => validateConfig({ server, workspace, device_ids: [device], timezone: 'UTC',
  allow_plaintext: true, credential_source: 'enclave', service_user_id: service, max_scan_messages: 100, ...extra })
const metadataConfig = server => validateConfig({ server, workspace, device_ids: [device], timezone: 'UTC', credential_source: 'provided' })
async function contentProvider(f, extra = {}) {
  const handle = await f.handle()
  return { token: async () => ({ token, kind: 'api_key' }), serviceKey: async () => handle, expectedEpoch: () => 1, contactPack: async () => null, ...extra }
}
async function connect(config, provider) {
  const [serverSide, clientSide] = InMemoryTransport.createLinkedPair()
  await createServer(config, provider).connect(serverSide)
  const client = new Client({ name: 'synthetic-identifiers-test', version: '1' }, { versionNegotiation: { mode: 'auto' } })
  await client.connect(clientSide)
  return client
}
const data = result => { assert.notEqual(result.isError, true, result.content?.[0]?.text); return JSON.parse(result.content[0].text) }
/** Keys no result may carry anywhere (§19.32). */
const removed = ['wa_id', 'sender_pn', 'sender_lid', 'chat_pn', 'chat_lid', 'keys', 'reply_to', 'contact_uid', 'message_uid', 'phone']
function keysOf(value, found = new Set()) {
  if (Array.isArray(value)) for (const item of value) keysOf(item, found)
  else if (value && typeof value === 'object') for (const [key, item] of Object.entries(value)) { found.add(key); keysOf(item, found) }
  return found
}
function noRemoved(value, where) {
  const keys = keysOf(value)
  for (const key of removed) assert.equal(keys.has(key), false, `${where}: ${key}`)
  const json = JSON.stringify(value)
  // The sender's phone, whose LID is known, and WhatsApp's message ids reach no result.
  assert.equal(json.includes(senderPN.split('@')[0]), false, `${where}: the sender's phone`)
  assert.equal(json.includes('synthetic-'), false, `${where}: a wa_id`)
}

/**
 * Ten rows, all of `chat` but seq 6 (of `group`), from a sender known by LID
 * and phone, except seq 1 (an older row, by phone only). Replies: seq 4 quotes
 * seq 2 (same chat, older); seq 3 a message the archive does not hold; seq 5
 * a message of another chat; seq 9 a wa_id two rows of the chat share.
 */
async function world({ contacts = 2 } = {}) {
  const f = await contentFixture({ rows: 10, contacts, scanPage: 4 })
  for (const row of f.rows) Object.assign(row, { sender_key: senderLID, sender_lid: senderLID, sender_pn: senderPN })
  const bySeq = seq => f.rows.find(row => row.seq === seq)
  delete bySeq(1).sender_key; delete bySeq(1).sender_lid; bySeq(1).sender_pn = oldSender
  bySeq(6).chat_key = group; bySeq(6).is_group = true
  bySeq(4).reply_to = 'synthetic-2'
  bySeq(3).reply_to = 'synthetic-not-archived'
  bySeq(5).reply_to = 'synthetic-6'
  bySeq(7).wa_id = 'synthetic-twice'; bySeq(8).wa_id = 'synthetic-twice'; bySeq(9).reply_to = 'synthetic-twice'
  f.contacts[0].contact_pn = '5511955550000@s.whatsapp.net'
  return f
}

test('messages, hits and counts carry sender_key and chat_key only, and a reply its quoted message\'s uid where this call read it', async () => {
  const f = await world()
  try {
    const client = await connect(contentConfig(f.server), await contentProvider(f))
    const page = data(await client.callTool({ name: 'list_messages', arguments: { device_id: device, chat_key: chat } }))
    noRemoved(page, 'list_messages')
    const replies = Object.fromEntries(page.messages.map(message => [message.seq, message.reply_to_uid]))
    // seq 4 quotes seq 2, which the page holds; the others quote nothing this call read, or a wa_id two rows share.
    assert.deepEqual(replies, { 10: undefined, 9: undefined, 8: undefined, 7: undefined, 5: undefined, 4: uid(2), 3: undefined, 2: undefined, 1: undefined })
    assert.equal(page.messages.find(message => message.seq === 4).sender_key, senderLID)
    // A row the archive keyed by phone (no LID known then) keeps that as its sender_key, which search's sender_keys takes.
    assert.equal(page.messages.find(message => message.seq === 1).sender_key, oldSender)
    const fields = Object.keys(page.messages.find(message => message.seq === 4))
    assert.deepEqual(fields.slice(0, fields.indexOf('body')), ['uid', 'device_id', 'chat_key', 'sender_key', 'ts', 'kind', 'type', 'source', 'reply_to_uid', 'order_ts', 'seq', 'is_from_me'])

    // One message on its own: nothing else was read, so no quoted uid, and nothing is fetched to find one.
    const mark = f.state.requests.length
    const one = data(await client.callTool({ name: 'get_message', arguments: { device_id: device, uid: uid(4) } }))
    noRemoved(one, 'get_message')
    assert.equal(Object.hasOwn(one.message, 'reply_to_uid'), false)
    assert.equal(one.message.sender_key, senderLID)
    assert.equal(f.since(mark).some(call => call.includes('/messages?') || call.includes('/scan')), false)
    noRemoved(data(await client.callTool({ name: 'list_revisions', arguments: { device_id: device, uid: uid(4) } })), 'list_revisions')

    // Across chats: the scan reads the quoted row after the hit (older, a later page) and still names it; a quote
    // of another chat's wa_id names nothing, nor does a wa_id two rows share.
    for (const args of [{ ...interval, limit: 20 }, { ...interval, query: 'exame', limit: 20 }]) {
      const hits = data(await client.callTool({ name: 'search_messages', arguments: args }))
      noRemoved(hits, `search_messages ${JSON.stringify(args)}`)
      const found = Object.fromEntries(hits.messages.map(hit => [hit.seq, hit.reply_to_uid]))
      assert.equal(found[4], uid(2), JSON.stringify(args))
      for (const seq of [3, 5, 9]) if (seq in found) assert.equal(found[seq], undefined, `${JSON.stringify(args)} seq ${seq}`)
      for (const hit of hits.messages) {
        assert.equal(typeof hit.source, 'string', 'no source object repeats the hit\'s ids')
        assert.equal(Object.hasOwn(hit, 'reply_to_uid'), hit.seq === 4, `seq ${hit.seq}: an unresolved reply leaves no key behind`)
        assert.deepEqual(Object.keys(hit).slice(-2), ['structured_content', 'archive_status'])
      }
    }
    const counts = data(await client.callTool({ name: 'activity_summary', arguments: interval }))
    noRemoved(counts, 'activity_summary')
    for (const item of counts.activity) assert.deepEqual(Object.keys(item), ['chat_key', 'sender_key', 'is_group', 'direction', 'archived_messages', 'first_order_ts', 'last_order_ts', 'sample_uid'])
    assert.deepEqual(counts.activity.map(item => item.sender_key).sort(), [senderLID, senderLID, oldSender].sort())

    // Inputs are unchanged: sender_keys still takes a phone JID or a LID, which the archive matches alike.
    const filtered = await client.callTool({ name: 'search_messages', arguments: { ...interval, sender_keys: [senderPN, senderLID, oldSender] } })
    assert.notEqual(filtered.isError, true, filtered.content[0].text)
    assert.ok(f.since(0).some(call => call.includes(`sender_keys=${encodeURIComponent([senderPN, senderLID, oldSender].join(','))}`)))
    await client.close()
  } finally { await f.close() }
})

test('a chat is its chat_key, name and preview; a number is its id and a name that is never its phone', async () => {
  const f = await world()
  try {
    await f.addChat({ chat_key: chat, chat_pn: chat, chat_lid: '1234567@lid', keys: [chat, '1234567@lid'], name: 'Ana', preview: 'Oi', last_ts: '2026-09-15T20:00:00.000Z' })
    const reader = await createReader(contentConfig(f.server), await contentProvider(f))
    const chats = await reader.listChats({ device_id: device })
    assert.deepEqual(Object.keys(chats.chats[0]), ['chat_key', 'is_group', 'last_ts', 'name', 'preview'])
    assert.equal(JSON.stringify(chats).includes('1234567@lid'), false)
    assert.equal(JSON.stringify(chats).includes(uid(70_000)), false, 'the chat row uid, which no tool takes')

    const cases = [
      [{ label: '', pn: '5511900000001:7@s.whatsapp.net', lid: '99887766@lid' }, 'Number 1'],
      [{ label: '', push_name: 'Ana Souza', pn: '5511900000001:7@s.whatsapp.net' }, 'Ana Souza'],
      [{ push_name: 'Ana Souza', pn: '5511900000001:7@s.whatsapp.net' }, 'Número autorizado'],
      // The owner's own label is theirs, whatever it says.
      [{ label: '+55 11 90000-0001', pn: '5511900000001:7@s.whatsapp.net' }, '+55 11 90000-0001'],
    ]
    for (const [number, name] of cases) {
      f.state.number = number
      const listed = await reader.listNumbers()
      assert.deepEqual(Object.keys(listed.numbers[0]), ['id', 'name', 'status', 'paused'], name)
      assert.equal(listed.numbers[0].name, name)
      if (name !== number.label) assert.equal(JSON.stringify(listed).includes('5511900000001'), false, `${name}: the number's own phone`)
    }
  } finally { await f.close() }
})

test('resolve_contact: phones for a phone query or include_phones only, no contact uid, and a sealed cursor bound to the connection and number', async () => {
  const f = await world({ contacts: 2200 })
  try {
    const client = await connect(contentConfig(f.server, { device_ids: [device, otherDevice] }), await contentProvider(f))
    const resolve = args => client.callTool({ name: 'resolve_contact', arguments: { device_id: device, ...args } })
    const tool = (await client.listTools()).tools.find(item => item.name === 'resolve_contact')
    assert.deepEqual(Object.keys(tool.inputSchema.properties), ['device_id', 'query', 'limit', 'include_phones', 'after_key'])
    assert.equal(tool.inputSchema.properties.include_phones.type, 'boolean')

    const named = data(await resolve({ query: 'Roberto' }))
    assert.equal(named.candidates.length, 1)
    assert.deepEqual(named.candidates[0].identifiers, [contactKey(1), '5511955550000@s.whatsapp.net'])
    assert.equal(Object.hasOwn(named.candidates[0], 'phones'), false)
    assert.equal(keysOf(named).has('contact_uid'), false)
    assert.equal(JSON.stringify(named).includes(uid(10_001)), false)
    for (const args of [{ query: '11955550000' }, { query: '+5511955550000' }, { query: 'Roberto', include_phones: true }]) {
      assert.deepEqual(data(await resolve(args)).candidates[0].phones, ['+5511955550000'], JSON.stringify(args))
    }
    // A few digits are not a phone number the user gave.
    for (const candidate of data(await resolve({ query: '0000' })).candidates) assert.equal(Object.hasOwn(candidate, 'phones'), false)

    // The cursor: sealed, so the last contact's key (a third party's JID) does not reach the model; it carries the choice.
    const asked = data(await resolve({ query: 'Roberto', include_phones: true }))
    assert.deepEqual(Object.keys(asked.next), ['device_id', 'query', 'limit', 'include_phones', 'after_key'])
    assert.equal(asked.next.include_phones, true)
    assert.equal(Object.hasOwn(named.next, 'include_phones'), false)
    const cursor = named.next.after_key
    assert.match(cursor, /^c1\.[A-Za-z0-9_-]+$/)
    assert.equal(Buffer.from(cursor.slice(3), 'base64url').includes(contactKey(2000)), false)
    assert.notEqual(cursor, asked.next.after_key, 'a fresh IV each time')
    let mark = f.state.requests.length
    const rest = data(await client.callTool({ name: 'resolve_contact', arguments: named.next }))
    assert.equal(rest.coverage.archived_contacts_examined, 200)
    assert.ok(f.since(mark).includes(`GET /v1/devices/${device}/contacts?limit=500&after_key=${encodeURIComponent(contactKey(2000))}`))
    // A key, as 0.5.0 handed out, is still a cursor.
    mark = f.state.requests.length
    data(await resolve({ query: 'Roberto', after_key: contactKey(2100) }))
    assert.ok(f.since(mark).includes(`GET /v1/devices/${device}/contacts?limit=500&after_key=${encodeURIComponent(contactKey(2100))}`))

    // A changed cursor, another number's, another connection's: refused before anything is read.
    const flipped = cursor.slice(0, -2) + (cursor.at(-2) === 'A' ? 'B' : 'A') + cursor.at(-1)
    const guidance = 'Could not read the archive (invalid_cursor). Pass next.after_key exactly as returned, or call resolve_contact again without after_key.'
    for (const args of [{ query: 'Roberto', after_key: flipped }, { query: 'Roberto', after_key: 'c1.' }, { device_id: otherDevice, query: 'Roberto', after_key: cursor }]) {
      mark = f.state.requests.length
      const refused = await resolve(args)
      assert.equal(refused.isError, true, JSON.stringify(args))
      assert.equal(refused.content[0].text, guidance)
      assert.deepEqual(f.since(mark), [], JSON.stringify(args))
    }
    const elsewhere = await createReader(contentConfig(f.server), await contentProvider(f, { token: async () => ({ token: `${token.split('.')[0]}.${Buffer.alloc(32, 7).toString('base64url')}`, kind: 'api_key' }) }))
    await assert.rejects(elsewhere.resolveContact({ device_id: device, query: 'Roberto', after_key: cursor }), { code: 'invalid_cursor' })
    await client.close()
  } finally { await f.close() }
})

test('a metadata connection: the same identifiers, a phone query\'s phones, and hits without a source object', async () => {
  const f = await world({ contacts: 600 })
  try {
    const reader = await createReader(metadataConfig(f.server), { token: async () => ({ token, kind: 'api_key' }) })
    const hits = await reader.searchMessages({ ...interval, limit: 20 })
    noRemoved(hits, 'search_messages')
    assert.equal(hits.messages.find(hit => hit.seq === 4).reply_to_uid, uid(2))
    for (const hit of hits.messages) assert.equal(hit.source, 'live')
    noRemoved(await reader.listMessages({ device_id: device, chat_key: chat, limit: 50 }), 'list_messages')
    noRemoved(await reader.activitySummary({ ...interval }), 'activity_summary')
    const found = await reader.resolveContact({ device_id: device, query: '11955550000' })
    assert.deepEqual(found.candidates[0].phones, ['+5511955550000'])
    assert.match(found.next.after_key, /^c1\./)
    const byKey = await reader.resolveContact({ device_id: device, query: contactKey(2) })
    assert.equal(Object.hasOwn(byKey.candidates[0], 'phones'), false)
  } finally { await f.close() }
})

test('no instruction, tool description or parameter description names an identifier results no longer carry', async () => {
  const f = await world()
  try {
    const shapes = [[contentConfig(f.server, { send: 'draft', send_self: true }), await contentProvider(f, { send: { mode: 'draft', self: true, consoleURL: 'https://app.wappie.thehappie.co/console', draft() {}, sendSelf() {}, outgoing() {}, observe() {} } })],
      [metadataConfig(f.server), { token: async () => ({ token, kind: 'api_key' }) }]]
    for (const [config, provider] of shapes) {
      const client = await connect(config, provider)
      const words = [client.getInstructions()]
      for (const tool of (await client.listTools()).tools) {
        words.push(tool.description)
        for (const property of Object.values(tool.inputSchema.properties ?? {})) words.push(property.description)
      }
      for (const text of words) assert.doesNotMatch(text, /\b(?:sender_pn|sender_lid|chat_pn|chat_lid|wa_id|contact_uid)\b/, text)
      await client.close()
    }
  } finally { await f.close() }
})
