// A connection's history window and reading limits in the reader
// (docs/mcp-enclave.md §19.19): with `history_days` nothing older than that
// many days before the call exists for the connection (lists and searches stop
// at the floor, get_message and open_attachment answer outside_window), and a
// provider's `limits` are checked before a counted tool runs and given what it
// returned, with limit_reached saying when the limit resets. The enclave's
// side (budgets.mjs) is a fake `provider.limits` here.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Client } from '@modelcontextprotocol/client'
import { InMemoryTransport } from '@modelcontextprotocol/server'
import { ArchiveError } from '@whatserver2/client'
import { LocalConfigError, validateConfig } from '../config.mjs'
import { createReader } from '../reader.mjs'
import { createServer } from '../server.mjs'
import { at, contentFixture, device, service, token as contentToken, workspace as contentWorkspace } from './content-fixture.mjs'
import { body, fixture, vector, workspace } from './fixture.mjs'

const DAY = 86_400_000
const metadataOnly = token => ({
  token: async () => ({ token, kind: 'api_key' }),
  serviceKey: () => { throw new LocalConfigError('plaintext_opt_in_required') },
  contactPack: () => { throw new LocalConfigError('plaintext_opt_in_required') },
})
const provided = (server, extra = {}) => validateConfig({ server, workspace, device_ids: [vector.device], credential_source: 'provided', ...extra })
/** The clock as the reader reads it (the archive's own clock is real). */
const clockAt = (t, iso) => t.mock.timers.enable({ apis: ['Date'], now: Date.parse(iso) })

test('history_days is a hosted connection\'s only: a local configuration refuses it', () => {
  assert.equal(provided('http://127.0.0.1:1').history_days, null)
  assert.equal(provided('http://127.0.0.1:1', { history_days: 30 }).history_days, 30)
  for (const days of [0, 367, 7.5, '30']) assert.throws(() => provided('http://127.0.0.1:1', { history_days: days }), { code: 'invalid_config' }, String(days))
  assert.throws(() => validateConfig({ server: 'http://127.0.0.1:1', workspace, token_file: './token', history_days: 30 }), { code: 'invalid_config' })
})

test('the history floor: list_messages stops at it, list_revisions leaves older versions out, get_message answers outside_window', async t => {
  const f = await fixture()
  try {
    // The fixture's message was sent on 2026-09-01T12:00:00Z.
    clockAt(t, '2026-09-20T00:00:00Z')
    const narrow = await createReader(provided(f.server, { history_days: 7 }), metadataOnly(f.token))
    const listed = await narrow.listMessages({ device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net', limit: 3 })
    assert.deepEqual([listed.messages.length, listed.has_more, listed.next], [0, false, undefined], 'nothing past the floor, and no page beyond it')
    await assert.rejects(narrow.getMessage({ device_id: vector.device, uid: body.row }), error => error instanceof ArchiveError && error.code === 'outside_window')
    const revisions = await narrow.listRevisions({ device_id: vector.device, uid: body.row, limit: 1 })
    assert.deepEqual([revisions.revisions.length, revisions.truncated], [0, false])
    const wide = await createReader(provided(f.server, { history_days: 30 }), metadataOnly(f.token))
    const all = await wide.listMessages({ device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net', limit: 3 })
    assert.deepEqual([all.messages.length, all.has_more], [1, true], 'inside the window the page is as without one')
    assert.equal((await wide.getMessage({ device_id: vector.device, uid: body.row })).message.uid, body.row)
    assert.equal((await wide.listRevisions({ device_id: vector.device, uid: body.row, limit: 1 })).truncated, true)
    const whole = await createReader(provided(f.server), metadataOnly(f.token))
    assert.equal((await whole.getMessage({ device_id: vector.device, uid: body.row })).message.uid, body.row, 'no window: the whole history')
  } finally { await f.close() }
})

test('the history floor: a search\'s lower bound is clamped to it, a range wholly before it reads nothing, and list_chats leaves out chats with nothing after it', async t => {
  const f = await contentFixture({ rows: 6, contacts: 1 })
  try {
    // The fixture's messages arrived on 2026-09-15T20:00:00.000Z.
    clockAt(t, '2026-09-20T00:00:00Z')
    const config = days => validateConfig({ server: f.server, workspace: contentWorkspace, device_ids: [device], credential_source: 'provided', max_scan_messages: 100, history_days: days })
    const reader = days => createReader(config(days), metadataOnly(contentToken))
    const mark = f.state.requests.length
    const seen = await (await reader(7)).searchMessages({ device_id: device, period: 'all' })
    assert.equal(seen.messages.length, 6)
    assert.equal(seen.range.from, '2026-09-13T00:00:00.000Z', 'the floor, not 1970')
    assert.equal(seen.range.definition, 'From the Unix epoch until now. This connection reads only the last 7 days.')
    const scans = f.state.requests.slice(mark).filter(item => item.path.endsWith('/messages/scan'))
    assert.ok(scans.length > 0 && scans.every(item => new URL(item.target, 'http://x').searchParams.get('from') === '2026-09-13T00:00:00.000Z'))
    const summary = await (await reader(7)).activitySummary({ device_id: device, period: 'all' })
    assert.equal(summary.activity[0].archived_messages, 6)
    const late = await (await reader(1)).searchMessages({ device_id: device, period: 'all' })
    assert.deepEqual([late.messages.length, late.has_more], [0, false], 'every message is older than the floor')
    const before = f.state.requests.length
    const empty = await (await reader(1)).searchMessages({ device_id: device, from: '2026-09-15T00:00:00Z', until: '2026-09-16T00:00:00Z' })
    assert.deepEqual([empty.messages.length, empty.has_more], [0, false])
    assert.equal(f.state.requests.slice(before).some(item => item.path.endsWith('/messages/scan')), false, 'a range wholly before the floor is never asked for')
    // Chats only now: a search's closing check reads one chat, and this fixture answers every chat it has.
    await f.addChat({ chat_key: 'recent@s.whatsapp.net', last_ts: '2026-09-19T00:00:00Z' })
    await f.addChat({ chat_key: 'old@s.whatsapp.net', last_ts: '2026-08-01T00:00:00Z' })
    await f.addChat({ chat_key: 'unknown@s.whatsapp.net' })
    const chats = await (await reader(7)).listChats({ device_id: device, limit: 10 })
    assert.deepEqual(chats.chats.map(chat => chat.chat_key), ['recent@s.whatsapp.net'])
    assert.equal((await (await reader(null)).listChats({ device_id: device, limit: 10 })).chats.length, 3)
  } finally { await f.close() }
})

/** A fake `provider.limits`: counts what it is told, refuses `before` once `refuse` names the kind. */
function fakeLimits() {
  const limits = { counted: [], checked: [], refuse: null,
    before(kind) { this.checked.push(kind); if (this.refuse === kind) throw Object.assign(new ArchiveError('limit_reached', 429), { reset_at: '2026-09-21T00:00:00Z' }) },
    count(kind, n) { this.counted.push([kind, n]) } }
  return limits
}
async function connect(config, provider) {
  const [serverSide, clientSide] = InMemoryTransport.createLinkedPair()
  await createServer(config, provider).connect(serverSide)
  const client = new Client({ name: 'synthetic-window-test', version: '1' }, { versionNegotiation: { mode: 'auto' } })
  await client.connect(clientSide)
  return client
}
const call = (client, name, args) => client.callTool({ name, arguments: args })

test('reading limits: the tools that return messages are checked first and counted after; previews, counts and contacts are not; limit_reached says when it resets', async t => {
  const f = await fixture()
  try {
    clockAt(t, '2026-09-20T00:00:00Z')
    const limits = fakeLimits()
    const client = await connect(provided(f.server), { ...metadataOnly(f.token), limits })
    const input = { device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net' }
    assert.equal((await call(client, 'list_messages', input)).isError, undefined)
    assert.equal((await call(client, 'get_message', { device_id: vector.device, uid: body.row })).isError, undefined)
    assert.equal((await call(client, 'list_revisions', { device_id: vector.device, uid: body.row })).isError, undefined)
    await call(client, 'list_chats', { device_id: vector.device })
    await call(client, 'list_numbers', {})
    assert.deepEqual(limits.checked, ['messages', 'messages', 'messages'])
    assert.deepEqual(limits.counted, [['messages', 1], ['messages', 1], ['messages', 2]])
    limits.refuse = 'messages'
    const before = f.state.requests.length
    const refused = await call(client, 'list_messages', input)
    assert.equal(refused.isError, true)
    assert.equal(refused.content[0].text, 'Could not read the archive (limit_reached). This connection reached its reading limit for now; it resets at 2026-09-21T00:00:00Z.')
    assert.equal(f.state.requests.length, before, 'a refused call reads nothing')
    assert.equal((await call(client, 'list_chats', { device_id: vector.device })).isError, undefined, 'previews are not counted, nor refused')
    await client.close()
    // The window's sentence, word for word.
    const narrow = await connect(provided(f.server, { history_days: 7 }), metadataOnly(f.token))
    const outside = await call(narrow, 'get_message', { device_id: vector.device, uid: body.row })
    assert.equal(outside.content[0].text, 'Could not read the archive (outside_window). This message is outside the window this connection may read.')
    await narrow.close()
  } finally { await f.close() }
})

const consoleURL = 'https://app.wappie.thehappie.co/console'
const enclaveConfig = (server, extra = {}) => validateConfig({ server, workspace: contentWorkspace, device_ids: [device], timezone: 'UTC',
  allow_plaintext: true, credential_source: 'enclave', service_user_id: service, max_scan_messages: 100, media: true, ...extra })

test('open_attachment under a window and limits: an older message is refused before anything opens; content counts one attachment, a pending answer none', async t => {
  const f = await contentFixture({ rows: 1, contacts: 1 })
  try {
    const handle = await f.handle()
    const old = await f.addMedia({ ts: '2026-08-01T00:00:00Z', media: { media_type: 'image' } })
    const recent = await f.addMedia({ ts: at, media: { media_type: 'image' } })
    clockAt(t, '2026-09-20T00:00:00Z')
    let pending = false
    const media = { host: 'claude.ai', profile: 'chatgpt.com', why: () => null, consoleURL, resultMaxBytes: 1_572_864, calls: [],
      async open(request, archive) { this.calls.push(request); await archive.row(); return pending ? { header: { status: 'pending', retry_after_s: 5 }, body: '', images: [] } : { header: { images: 1 }, body: '', images: [{ data: new Uint8Array([1]), mimeType: 'image/png' }] } } }
    const limits = fakeLimits()
    const provider = { token: async () => ({ token: contentToken, kind: 'api_key' }), serviceKey: async () => handle, expectedEpoch: () => 1, renewalURL: () => `${consoleURL}?mcp_renew=x`,
      contactPack: async () => null, media, limits }
    const client = await connect(enclaveConfig(f.server, { history_days: 30 }), provider)
    const refused = await call(client, 'open_attachment', { device_id: device, uid: old.uid })
    assert.equal(refused.isError, true)
    assert.match(refused.content[0].text, /^Could not open the attachment \(outside_window\)\. This message is outside the window this connection may read\./)
    assert.equal(media.calls.length, 0, 'nothing opened')
    const opened = await call(client, 'open_attachment', { device_id: device, uid: recent.uid })
    assert.equal(opened.isError, undefined, opened.content[0].text)
    // The host profile (§19.23) words the image note: the profile, not the redirect host.
    assert.match(opened.content[0].text, /this ChatGPT model does not receive images/)
    pending = true
    await call(client, 'open_attachment', { device_id: device, uid: recent.uid })
    assert.deepEqual(limits.checked, ['attachments', 'attachments', 'attachments'])
    assert.deepEqual(limits.counted, [['attachments', 1]])
    limits.refuse = 'attachments'
    const capped = await call(client, 'open_attachment', { device_id: device, uid: recent.uid })
    assert.match(capped.content[0].text, /^Could not open the attachment \(limit_reached\)\. This connection reached its reading limit for now; it resets at 2026-09-21T00:00:00Z\./)
    assert.equal(media.calls.length, 2)
    await client.close()
  } finally { await f.close() }
})
