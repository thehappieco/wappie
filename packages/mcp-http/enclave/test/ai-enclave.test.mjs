// AI integrations in the whole enclave (docs/mcp-enclave.md §18.7 to §18.15):
// AI requests and their attested descriptors; install, with the grants,
// configuration tags, keys and models checked before anything is kept
// (N-AI-1, N-AI-12); jobs from the console and from a media connection's
// open_attachment through the fake Go, the synthetic archive and local
// provider stubs (never a real provider); I3a at every job (N-AI-1b);
// reuse (N-AI-5, N-AI-6); the budget (N-AI-9, N-AI-13); the providers per
// function (N-AI-11); the error map's effects and stops (N-AI-14); the log
// (N-AI-8); revocation mid-call; renewal.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes, randomUUID } from 'node:crypto'
import { openDerived } from '@whatserver2/mcp/reader'
import { contentFixture } from '@whatserver2/mcp/test/content-fixture'
import { vector, workspace } from '@whatserver2/mcp/test/fixture'
import { AI_REQUESTS_PENDING_MAX } from '../ai/policy.mjs'
import { CONSOLE_URL } from '../constants.mjs'
import { lineAllowed } from '../logsink.mjs'
import { runWorker } from '../media/jail.mjs'
import { createProviderStubs, STUB_KEYS } from './ai-stubs.mjs'
import { encryptMedia, fakeJailSpawn, JPEG_MAGIC, LABELS, PDF_MAGIC, sha256, withScenario } from './media-fixtures.mjs'
import {
  aiOff, aiRenewLabels, aiScope, aiTags, callTool, connectAI, connectMedia, contentGrants, DSK, newApiKey, openAttachment as open, ORIGIN, requestAI, sealContent, world,
} from './world.mjs'

const fakeJail = () => ({ checkJail: async () => ({ ok: true, cpuset: false }), runWorker, spawn: fakeJailSpawn() })
const tick = (ms = 20) => new Promise(resolve => setTimeout(resolve, ms))
const events = w => w.lines.map(line => JSON.parse(line)).filter(entry => entry.event)

/**
 * The world with the fake jail and the provider stubs. `w.control.pending`
 * makes open_attachment's inline wait end at once (the host's wait over).
 */
async function aiWorld(t) {
  const w = await world(t, { archive: token => contentFixture({ token, rows: 2, contacts: 1 }) })
  w.jail = fakeJail()
  const stubs = createProviderStubs()
  w.aiTransport = stubs.transport
  w.control = { pending: false }
  w.mediaDelay = (ms, signal) => (w.control.pending ? Promise.resolve() : new Promise(resolve => {
    const timer = setTimeout(resolve, ms)
    signal?.addEventListener('abort', () => { clearTimeout(timer); resolve() }, { once: true })
  }))
  const e = await w.start()
  return { w, e, stubs }
}
/** A voice note in the synthetic archive: Ogg bytes, encrypted as WhatsApp does, its key sealed like the archive's. */
async function voiceNote(w, { size = 4000, seconds = 14, media = {}, fields = {}, plaintext } = {}) {
  const key = randomBytes(32)
  const body = plaintext ?? Buffer.concat([Buffer.from('OggS'), randomBytes(size - 4)])
  const object = encryptMedia(body, key, LABELS.ptt)
  const row = await w.f.addMedia({ key, object, ...fields,
    media: { media_type: 'ptt', mimetype: 'audio/ogg; codecs=opus', file_length: body.length, file_enc_sha256: sha256(object).toString('base64'), seconds, ...media } })
  return { row, plaintext: body }
}
async function attachment(w, { type, plaintext, label = LABELS[type], media = {} }) {
  const key = randomBytes(32)
  const object = encryptMedia(plaintext, key, label)
  return w.f.addMedia({ key, object, media: { media_type: type, file_length: plaintext.length, file_enc_sha256: sha256(object).toString('base64'), ...media } })
}
/** Installs an AI authorization and says so. */
async function installed(w, options) {
  const done = await connectAI(w, options)
  assert.equal(done.relayed.status, 204, done.relayed.body)
  w.go.connections.get(done.connectionId).status = 'active'
  return done
}
/** A console job, polled to its end: `{submitted, state}`. */
async function consoleJob(w, done, { uid, feature = 'audio', redo = false, requester = randomUUID() }) {
  const submitted = await w.internal('/internal/ai/jobs', { method: 'POST', body: { authorization_id: done.connectionId, device_id: vector.device, uid, feature, origin: 'console', requester_id: requester, redo } })
  if (submitted.status !== 202) return { submitted, state: null }
  const { job } = JSON.parse(submitted.body)
  for (let n = 0; n < 500; n++) {
    const answer = await w.internal(`/internal/ai/jobs/${job}?requester_id=${requester}`)
    const state = JSON.parse(answer.body)
    if (state.state === 'done' || state.state === 'failed') return { submitted, state, job, requester }
    await tick()
  }
  throw new Error('the job never ended')
}
/** The stored record of (uid, feature), opened with the number's DSK as the console would. */
function storedRecord(w, uid, feature) {
  const item = w.go.ai.derived.find(entry => entry.message_uid === uid && entry.feature === feature)
  if (!item) return null
  return openDerived(DSK(), { namespace: vector.tenant, device_id: item.device_id, message_uid: uid, feature, epoch: item.epoch }, Buffer.from(item.sealed, 'base64url'))
}
const headerOf = value => JSON.parse(value.content[0].text.split('\n')[0])

test('an AI request: an attested descriptor of its own key, kind ai; at most AI_REQUESTS_PENDING_MAX live', async t => {
  const { w } = await aiWorld(t)
  const { status, descriptor, nonce } = await requestAI(w)
  assert.equal(status, 200)
  assert.deepEqual(Object.keys(descriptor), ['request_id', 'kind', 'reader_public_key', 'kid', 'resource', 'reader_version', 'expires_at', 'attestation'])
  assert.deepEqual([descriptor.kind, descriptor.resource, descriptor.reader_version], ['ai', 'https://mcp.wappie.thehappie.co/mcp', '0.5.0'])
  assert.match(descriptor.request_id, /^[A-Za-z0-9_-]{22}$/)
  assert.equal(descriptor.attestation.request_id, descriptor.request_id)
  const call = w.nsmCalls.at(-1)
  assert.deepEqual([Buffer.from(call.publicKey).toString('base64url'), Buffer.from(call.nonce)], [descriptor.reader_public_key, nonce])
  for (let n = 1; n < AI_REQUESTS_PENDING_MAX; n++) assert.equal((await requestAI(w)).status, 200)
  const refused = await requestAI(w)
  assert.deepEqual([refused.status, JSON.parse(refused.body).code], [429, 'too_many_prepares'])
  const bad = await w.internal('/internal/ai/requests', { method: 'POST', body: { nonce: 'short' } })
  assert.equal(bad.status, 400)
})

test('install: the grants, the tags, the keys and the models checked, then activated and kept; the key goes to its provider only', async t => {
  const { w, e, stubs } = await aiWorld(t)
  const done = await connectAI(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'], document: ['anthropic', 'claude-synthetic-5'] }, { lang: 'pt-BR' }) })
  assert.equal(done.relayed.status, 204, done.relayed.body)
  assert.equal(w.go.connections.get(done.connectionId).status, 'active', 'activated by the enclave')
  const record = e.state.connections.get(done.connectionId)
  assert.deepEqual([record.kind, record.consent_version, record.redirect_host, record.key_mode, record.request, record.kid], ['ai', 1, 'console', 'ephemeral', done.request.request_id, done.request.kid])
  assert.deepEqual(record.epochs, { [vector.device]: 1 })
  assert.deepEqual(record.ns, { [vector.device]: vector.tenant })
  assert.deepEqual(Object.keys(record.keys_sha256).sort(), ['anthropic', 'google'])
  assert.equal(JSON.stringify(record).includes(STUB_KEYS.google), false, 'the provider keys are never in sealed state')
  assert.equal(record.api_key, done.token)
  assert.equal(e.reader.state.connections.get(done.connectionId).family_id, undefined, 'no token family')
  // One model list per key, each to its own host with its own header.
  const lists = stubs.keyed().filter(call => call.route === 'models')
  assert.deepEqual(lists.map(call => call.provider).sort(), ['anthropic', 'google'])
  for (const call of lists) assert.equal(call.key, STUB_KEYS[call.provider])
  assert.ok(events(w).some(entry => entry.event === 'ai_installed'))
  // The record survives the sweep that revokes unclaimed OAuth connections.
  await e.reader.sweep()
  assert.equal(e.state.connections.has(done.connectionId), true)
  // A second relay for the same request is refused.
  const again = await w.internal(`/internal/ai/requests/${done.request.request_id}/bundle`, { method: 'POST', body: { connection_id: randomUUID(), tenant_id: workspace, kid: done.request.kid, sealed: done.sealed, expires_at: done.expiresAt, kind: 'ai' } })
  assert.equal(again.status, 404, 'the request is gone once installed')
})

test('N-AI-1: Go seals a bundle of its own to the attested key, with the operator\'s API key and the person\'s genuine grants: the tags fail, invalid_bundle, nothing installed', async t => {
  const { w, e, stubs } = await aiWorld(t)
  // Go has no DSK: its tags are made with a key of its own.
  const done = await connectAI(w, { token: w.apiKey, tagDSK: new Uint8Array(32).fill(3) })
  assert.deepEqual([done.relayed.status, JSON.parse(done.relayed.body).code], [400, 'invalid_bundle'])
  assert.equal(e.state.connections.has(done.connectionId), false)
  assert.equal(w.go.connections.get(done.connectionId).status, 'pending', 'never activated')
  assert.equal(stubs.keyed().length, 0, 'no key checked before the tags hold')
  assert.ok(events(w).some(entry => entry.event === 'ai_tag_mismatch'))
  assert.ok(events(w).some(entry => entry.event === 'ai_install_failed' && entry.code === 'invalid_bundle'))
  // Other ways a relay fails, before anything is kept.
  for (const [label, options, code] of [
    ['a content bundle under the AI labels', { bundle: { version: 2, kind: 'content' } }, 'invalid_bundle'],
    ['sealed under the content labels', { labels: { info: 'wappie-mcp-connect/v2', aad: '[]' } }, 'invalid_bundle'],
    ['another workspace', { relay: { tenant_id: '018f3a2b-2222-7000-8000-00000000cccc' } }, 'invalid_bundle'],
    ['the relay without kind ai', { relay: { kind: 'content' } }, 'bad_request'],
    ['grants of another service', { grants: { user: randomUUID() } }, 'grant_proof_failed'],
  ]) {
    const refused = await connectAI(w, options)
    assert.deepEqual([refused.relayed.status, JSON.parse(refused.relayed.body).code], [400, code], label)
    assert.equal(e.state.connections.has(refused.connectionId), false, label)
  }
})

test('N-AI-12 at install: a model on the list\'s second page installs; one on no page is ai_model_unavailable, a rejected key ai_key_rejected, past AI_MODELS_PAGES_MAX pages ai_provider_failed; a failed activation keeps nothing', async t => {
  const { w, e, stubs } = await aiWorld(t)
  stubs.pageSize = 2
  stubs.models.google = ['g-1', 'g-2', 'gemini-synthetic-flash']
  assert.equal((await connectAI(w)).relayed.status, 204)
  stubs.models.google = ['g-1', 'g-2']
  const missing = await connectAI(w)
  assert.deepEqual([missing.relayed.status, JSON.parse(missing.relayed.body).code], [400, 'ai_model_unavailable'])
  stubs.models.google = Array.from({ length: 12 }, (_, n) => `g-${n}`)
  const long = await connectAI(w)
  assert.deepEqual([long.relayed.status, JSON.parse(long.relayed.body).code], [502, 'ai_provider_failed'])
  stubs.models.google = ['gemini-synthetic-flash']
  const rejected = await connectAI(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { keys: { google: 'wappie-test-key-google-rrrrrrrrrrrrrrrr' } }) })
  assert.deepEqual([rejected.relayed.status, JSON.parse(rejected.relayed.body).code], [400, 'ai_key_rejected'])
  for (const done of [missing, long, rejected]) {
    assert.equal(e.state.connections.has(done.connectionId), false)
    assert.equal(w.go.connections.get(done.connectionId).status, 'pending')
  }
  // Go answers the activation with 409: 502, nothing kept (the install's order).
  const request = (await requestAI(w)).descriptor
  const activation = w.go.connections
  const original = activation.set.bind(activation)
  activation.set = (id, row) => original(id, { ...row, status: 'revoked' })
  const late = await connectAI(w, { request })
  activation.set = original
  assert.deepEqual([late.relayed.status, JSON.parse(late.relayed.body).code], [502, 'relay_failed'])
  assert.equal(e.state.connections.has(late.connectionId), false)
})

test('a console job: audio to Google, the transcript sealed and stored under the number\'s key, charged by its usage, reused never by another language', async t => {
  const { w, e, stubs } = await aiWorld(t)
  const done = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { lang: 'pt-BR', requesters: 'console' }) })
  const { row, plaintext } = await voiceNote(w)
  const first = await consoleJob(w, done, { uid: row.uid })
  assert.equal(first.submitted.status, 202, first.submitted.body)
  assert.deepEqual(first.state, { state: 'done' })
  const [call] = stubs.generations('google')
  assert.equal(call.path, '/v1beta/models/gemini-synthetic-flash:generateContent')
  assert.equal(call.body.systemInstruction.parts[0].text.endsWith('The expected language is pt-BR.'), true)
  assert.deepEqual(call.body.contents[0].parts.map(part => Object.keys(part)[0]), ['inlineData', 'text'])
  assert.deepEqual(Buffer.from(call.body.contents[0].parts[0].inlineData.data, 'base64'), plaintext, 'the verified plaintext, as sent')
  assert.equal(call.body.contents[0].parts[0].inlineData.mimeType, 'audio/ogg')
  const record = storedRecord(w, row.uid, 'audio')
  assert.deepEqual([record.text, record.lang, record.provider, record.model, record.prompt_version, record.flags], [stubs.text, 'pt-BR', 'google', 'gemini-synthetic-flash', 'audio/1', []])
  assert.equal(record.source_sha256, sha256(plaintext).toString('hex'))
  assert.deepEqual(record.usage, { input_tokens: 424, output_tokens: 741, seconds: 15 }, 'Google\'s audio tokens ÷ 25 are the seconds')
  // Counted at Go: one item, the tokens Google reported, and the tokens charged: input plus output, the thinking included.
  const usage = w.go.ai.usage.find(item => item.body.items === 1)
  assert.deepEqual(usage.body, { device_id: vector.device, feature: 'audio', provider: 'google', model: 'gemini-synthetic-flash', origin: 'console', requester_id: first.requester,
    items: 1, reused: 0, failures: 0, input_tokens: 424, output_tokens: 741, seconds: 15, charged_tokens: 424 + 741 })
  // A second ask: stored, no call.
  const again = await w.internal('/internal/ai/jobs', { method: 'POST', body: { authorization_id: done.connectionId, device_id: vector.device, uid: row.uid, feature: 'audio', origin: 'console', requester_id: randomUUID(), redo: false } })
  assert.deepEqual([again.status, JSON.parse(again.body)], [200, { stored: true }])
  // A redo asks again and replaces the record, flagged redo.
  const redo = await consoleJob(w, done, { uid: row.uid, redo: true })
  assert.deepEqual(redo.state, { state: 'done' })
  assert.equal(stubs.generations('google').length, 2)
  assert.deepEqual(storedRecord(w, row.uid, 'audio').flags, ['redo'])
  // The same file on another message: reused, not sent again (N-AI-6), and it counts no tokens.
  const before = e.facts.content.ai.budgets.used(done.connectionId)
  const copy = await voiceNote(w, { plaintext })
  assert.deepEqual((await consoleJob(w, done, { uid: copy.row.uid })).state, { state: 'done' })
  assert.equal(stubs.generations('google').length, 2, 'reused')
  assert.equal(storedRecord(w, copy.row.uid, 'audio').text, stubs.text)
  const reuse = w.go.ai.usage.find(item => item.body.reused === 1)
  assert.deepEqual([reuse.body.items, reuse.body.input_tokens, reuse.body.output_tokens, reuse.body.charged_tokens], [0, 0, 0, 0], 'a reuse is no call: no item, no tokens')
  assert.deepEqual(e.facts.content.ai.budgets.used(done.connectionId), before, 'the month\'s tokens and the day\'s items stay')
  assert.ok(events(w).some(entry => entry.event === 'ai_reused'))
  // The same file on a second person's authorization in another language: never reused (N-AI-6).
  const other = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { lang: 'es', requesters: 'console' }) })
  const third = await voiceNote(w, { plaintext })
  assert.deepEqual((await consoleJob(w, other, { uid: third.row.uid })).state, { state: 'done' })
  assert.equal(stubs.generations('google').length, 3, 'sent again for es')
  // And in the same language, by that second person: reused.
  const same = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { lang: 'pt-BR', requesters: 'console' }) })
  const fourth = await voiceNote(w, { plaintext })
  assert.deepEqual((await consoleJob(w, same, { uid: fourth.row.uid })).state, { state: 'done' })
  assert.equal(stubs.generations('google').length, 3, 'reused by the second person\'s authorization')
  // The health line counts them.
  const health = await e.health.tick()
  assert.ok(health.ai_records >= 3 && health.ai_keys >= 3 && health.ai_jobs >= 4)
  assert.deepEqual([health.ai_queue, health.ai_in_flight], [0, 0])
})

test('N-AI-5: a row whose declared file_sha256 names another file\'s hash gets no reuse; the hash is the one the enclave verified', async t => {
  const { w, stubs } = await aiWorld(t)
  const done = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { requesters: 'console' }) })
  const first = await voiceNote(w)
  assert.deepEqual((await consoleJob(w, done, { uid: first.row.uid })).state, { state: 'done' })
  // Another file whose row claims the first one's hash (the sender's claim, readable to Go).
  const liar = await voiceNote(w, { media: { file_sha256: sha256(first.plaintext).toString('base64') } })
  assert.deepEqual((await consoleJob(w, done, { uid: liar.row.uid })).state, { state: 'done' })
  assert.equal(stubs.generations('google').length, 2, 'sent: its own hash differs')
  assert.equal(storedRecord(w, liar.row.uid, 'audio').source_sha256, sha256(liar.plaintext).toString('hex'))
})

test('N-AI-11: Google for audio and OpenAI for documents: a voice note never reaches OpenAI, a document never reaches Google, neither key the other\'s host', async t => {
  const { w, stubs } = await aiWorld(t)
  const done = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'], document: ['openai', 'gpt-synthetic-mini'] }, { requesters: 'console' }) })
  const voice = await voiceNote(w)
  const pdf = await attachment(w, { type: 'document', plaintext: withScenario(PDF_MAGIC, { pages: ['Orçamento de teste: R$ 1.200,00, válido até 15/10.', ''] }), media: { mimetype: 'application/pdf' } })
  assert.deepEqual((await consoleJob(w, done, { uid: voice.row.uid })).state, { state: 'done' })
  assert.deepEqual((await consoleJob(w, done, { uid: pdf.uid, feature: 'document' })).state, { state: 'done' })
  const google = stubs.generations('google'), openai = stubs.generations('openai')
  assert.deepEqual([google.length, openai.length], [1, 1])
  assert.equal(JSON.stringify(google).includes('Orçamento'), false, 'no document to Google')
  assert.equal(openai[0].path, '/v1/responses')
  assert.equal(openai[0].body.store, false)
  const content = openai[0].body.input[0].content
  assert.deepEqual(content.map(part => part.type), ['input_image', 'input_text'], 'the scanned page\'s image, then the text')
  assert.ok(content[1].text.startsWith('<document>\n--- page 1 ---\nOrçamento de teste'))
  assert.equal(JSON.stringify(openai).includes(Buffer.from(voice.plaintext).toString('base64').slice(0, 40)), false, 'no voice note to OpenAI')
  for (const call of stubs.keyed()) assert.equal(call.key, STUB_KEYS[call.provider], `${call.provider} got its own key`)
})

test('an image job: the re-encoded image through the jail, to Anthropic, with the system prompt and the text part', async t => {
  const { w, stubs } = await aiWorld(t)
  const done = await installed(w, { scope: aiScope({ image: ['anthropic', 'claude-synthetic-5'] }, { lang: 'pt-BR', requesters: 'console' }) })
  const photo = await attachment(w, { type: 'image', plaintext: withScenario(JPEG_MAGIC, { width: 800, height: 600 }), media: { mimetype: 'image/jpeg' } })
  assert.deepEqual((await consoleJob(w, done, { uid: photo.uid, feature: 'image' })).state, { state: 'done' })
  const [call] = stubs.generations('anthropic')
  assert.deepEqual(call.body.messages[0].content.map(part => part.type), ['image', 'text'])
  assert.equal(call.body.messages[0].content[0].source.media_type, 'image/jpeg')
  assert.equal(call.body.messages[0].content[1].text, 'Describe this image.')
  assert.ok(call.body.system.endsWith('Write in pt-BR.'))
  assert.equal(storedRecord(w, photo.uid, 'image').text, stubs.text)
})

test('a media connection\'s open_attachment: a stored transcript, one made inline, pending then stored, not enabled, paused with its renewal link', async t => {
  const { w, e, stubs } = await aiWorld(t)
  const auth = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { lang: 'pt-BR' }) })
  const media = await connectMedia(w)
  const note = await voiceNote(w)
  // Not covered: ai_not_enabled, an answer, no isError.
  const none = (await open(w, media, { uid: note.row.uid })).value
  assert.equal(none.isError, undefined, none.content[0].text)
  assert.match(none.content[0].text, /^Could not open the attachment \(ai_not_enabled\)\. This voice note or audio is not transcribed/)
  // Go picks the authorization for this connection's creator: the job runs inline.
  const other = await voiceNote(w)
  w.go.ai.picks.set(`${media.connectionId}|${vector.device}|audio`, { authorization_id: auth.connectionId, requester_id: randomUUID(), state: 'active' })
  // An answer about the attachment is kept (§16.9): the same call still hears ai_not_enabled, with no new pick asked.
  const asked = w.go.ai.calls.filter(call => call.route === 'ai').length
  assert.match((await open(w, media, { uid: note.row.uid })).value.content[0].text, /\(ai_not_enabled\)/)
  assert.equal(w.go.ai.calls.filter(call => call.route === 'ai').length, asked)
  const inline = (await open(w, media, { uid: other.row.uid })).value
  assert.equal(inline.isError, undefined, inline.content[0].text)
  const header = headerOf(inline)
  assert.deepEqual(Object.keys(header), ['uid', 'media_type', 'sniffed', 'file_length', 'seconds_claimed', 'derived', 'part', 'next_cursor', 'status', 'open_url', 'notes', 'source'])
  assert.deepEqual([header.sniffed, header.derived.provider, header.derived.lang, header.status], ['transcript', 'google', 'pt-BR', 'complete'])
  assert.equal(header.open_url, `${CONSOLE_URL}?workspace=${workspace}&open_device=${vector.device}&open_message=${other.row.uid}`)
  assert.equal(header.notes[0], 'This is an AI transcript made by Google with the user\'s own key; it may contain errors. Quote it as a transcript, not as the speaker\'s exact words.')
  assert.equal(inline.content[0].text.split('\n').slice(1).join('\n'), stubs.text)
  assert.equal(stubs.generations('google').length, 1)
  assert.equal(w.go.ai.usage.at(-1).body.origin, 'connector')
  // Stored now: read with the connection's own key, no job (a fresh message id reads it too, not the cache).
  const stored = (await open(w, media, { uid: other.row.uid, cursor: 'c0' })).value
  assert.equal(headerOf(stored).sniffed, 'transcript')
  assert.equal(stubs.generations('google').length, 1)
  assert.ok(w.go.ai.calls.some(call => call.route === 'ai/derived' && call.id === media.connectionId && call.authorization === `Bearer ${media.token}`), 'the media connection\'s own key')
  // get_message names the stored function.
  const message = await callTool(w, media.tokens.access_token, 'get_message', { device_id: vector.device, uid: other.row.uid })
  assert.deepEqual([message.data.message.attachment.openable, message.data.message.attachment.derived], [true, ['audio']])
  // A slow provider: pending once the host's wait is over, then the stored result; the repeat joins the job.
  let release
  stubs.answer = call => ({ ...stubs.ok(call.provider, call.route), until: new Promise(resolve => { release = resolve }) })
  const slow = await voiceNote(w)
  w.control.pending = true
  const waiting = (await open(w, media, { uid: slow.row.uid })).value
  assert.equal(waiting.isError, undefined)
  const pending = headerOf(waiting)
  assert.deepEqual([pending.status, pending.retry_after_s], ['pending', 5])
  assert.equal(pending.notes[0], 'Still transcribing this attachment with the user\'s AI provider; nothing has failed. Call open_attachment again with the same arguments after 5 seconds.')
  assert.equal(headerOf((await open(w, media, { uid: slow.row.uid })).value).status, 'pending', 'the repeat joins the job')
  await tick(50)
  assert.equal(stubs.generations('google').length, 2, 'one job, one call')
  release()
  for (let n = 0; n < 100 && !storedRecord(w, slow.row.uid, 'audio'); n++) await tick()
  w.control.pending = false
  const after = (await open(w, media, { uid: slow.row.uid })).value
  assert.equal(headerOf(after).sniffed, 'transcript')
  stubs.answer = null
  // The only authorization Go finds is the user's own in reseal: ai_paused with the renewal link, a failure, never cached.
  const resealed = await voiceNote(w)
  w.go.ai.picks.set(`${media.connectionId}|${vector.device}|audio`, { authorization_id: auth.connectionId, requester_id: randomUUID(), state: 'reseal' })
  for (let n = 0; n < 2; n++) {
    const paused = (await open(w, media, { uid: resealed.row.uid })).value
    assert.equal(paused.isError, true)
    const [line, json] = paused.content[0].text.split('\n')
    assert.equal(line, 'Could not open the attachment (ai_paused). AI transcription on this number is paused since the reader was updated or restarted, until the user renews it with their password. Give the user renew_url exactly as returned; do not retry.')
    assert.equal(JSON.parse(json).renew_url, `${CONSOLE_URL}?workspace=${workspace}&ai_renew=${auth.connectionId}`)
  }
  assert.equal(w.go.ai.calls.filter(call => call.route === 'ai' && call.id === media.connectionId).length >= 5, true, 'asked again each time: not cached')
  // Kind audio off: media_not_allowed, before anything is asked.
  w.go.connections.get(media.connectionId).extra.media_off = ['audio']
  w.skew += 61_000
  const off = (await open(w, media, { uid: resealed.row.uid })).value
  assert.match(off.content[0].text, /^Could not open the attachment \(media_not_allowed\)/)
})

test('a video: transcribed by Gemini where an authorization covers it; the preview path where none does, or kind video is off', async t => {
  const { w, stubs } = await aiWorld(t)
  const auth = await installed(w, { scope: aiScope({ video: ['google', 'gemini-synthetic-flash'] }) })
  const media = await connectMedia(w)
  const mp4 = Buffer.concat([Buffer.from([0, 0, 0, 0x18]), Buffer.from('ftypisom'), randomBytes(3000)])
  const thumbnail = Buffer.concat([Buffer.from(JPEG_MAGIC), Buffer.from(`\n@@SCENARIO@@${JSON.stringify({ width: 64, height: 48 })}`)])
  const key = randomBytes(32)
  const object = encryptMedia(mp4, key, LABELS.video)
  const video = await w.f.addMedia({ key, object, thumbnail, media: { media_type: 'video', mimetype: 'video/mp4', file_length: mp4.length, file_enc_sha256: sha256(object).toString('base64'), seconds: 12 } })
  const preview = (await open(w, media, { uid: video.uid })).value
  assert.equal(headerOf(preview).sniffed, 'thumbnail', 'no authorization: the preview, as before')
  w.go.ai.picks.set(`${media.connectionId}|${vector.device}|video`, { authorization_id: auth.connectionId, requester_id: randomUUID(), state: 'active' })
  // The answer in prompt video/2's sections: stored as the model wrote it, read by the connection under English headings.
  stubs.text = '[TRANSCRIPT]\nOi, aqui é um vídeo sintético.\n[SHOWN]\nUm círculo azul num fundo branco.'
  // Google counts a video as VIDEO tokens, never AUDIO (B0's usage): no seconds of its own.
  stubs.usage.google = { promptTokenCount: 1160, candidatesTokenCount: 116, thoughtsTokenCount: 277, promptTokensDetails: [{ modality: 'TEXT', tokenCount: 68 }, { modality: 'VIDEO', tokenCount: 1092 }] }
  const other = await w.f.addMedia({ key, object, thumbnail, media: { media_type: 'video', mimetype: 'video/mp4', file_length: mp4.length, file_enc_sha256: sha256(object).toString('base64'), seconds: 12 } })
  const described = (await open(w, media, { uid: other.uid })).value
  const header = headerOf(described)
  assert.deepEqual([header.sniffed, header.derived.feature], ['transcript', 'video'])
  assert.equal(described.content[0].text.split('\n').slice(1).join('\n'), 'Speech:\nOi, aqui é um vídeo sintético.\n\nOn screen:\nUm círculo azul num fundo branco.')
  assert.deepEqual([storedRecord(w, other.uid, 'video').text, storedRecord(w, other.uid, 'video').prompt_version], [stubs.text, 'video/2'])
  // Reported as measured, with the claimed 12 s (Google measures no seconds of a video); charged its tokens alone.
  assert.deepEqual(storedRecord(w, other.uid, 'video').usage, { input_tokens: 1160, output_tokens: 393, seconds: 12 })
  const charged = w.go.ai.usage.find(item => item.id === auth.connectionId && item.body.items === 1).body
  assert.deepEqual([charged.seconds, charged.charged_tokens], [12, 1160 + 393])
  assert.equal(header.notes[0], 'This is an AI transcript and description of the video made by Google with the user\'s own key; it may contain errors. Quote it as such, not as the speaker\'s exact words.')
  const [call] = stubs.generations('google')
  assert.equal(call.body.contents[0].parts[0].inlineData.mimeType, 'video/mp4')
  assert.equal(call.body.contents[0].parts[1].text, 'Transcribe and describe this video.')
  // Kind video off: the preview path again.
  w.go.connections.get(media.connectionId).extra.media_off = ['video']
  w.skew += 61_000
  const third = await w.f.addMedia({ key, object, thumbnail, media: { media_type: 'video', mimetype: 'video/mp4', file_length: mp4.length, file_enc_sha256: sha256(object).toString('base64') } })
  assert.equal(headerOf((await open(w, media, { uid: third.uid })).value).sniffed, 'thumbnail')
})

test('N-AI-1b: a forged grant (DSK′ with matching tags) at install, the genuine grant afterwards: every call fails I3a with grant_mismatch, and nothing reaches a provider', async t => {
  const { w, e, stubs } = await aiWorld(t)
  const forged = new Uint8Array(randomBytes(32))
  const done = await installed(w, { grants: { dsk: forged }, tagDSK: forged, scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { requesters: 'console' }) })
  assert.equal(e.state.connections.get(done.connectionId).kind, 'ai', 'the install saw only DSK′: its tags held')
  // Go now serves the genuine grant for the same service.
  await contentGrants(w, done.request.reader_public_key, { service: done.service, token: done.token })
  const note = await voiceNote(w)
  const job = await consoleJob(w, done, { uid: note.row.uid })
  assert.deepEqual(job.state, { state: 'failed', code: 'grant_mismatch' })
  assert.equal(stubs.generations().length, 0, 'nothing reached a provider')
  assert.equal(w.go.ai.derived.length, 0)
  assert.ok(events(w).some(entry => entry.event === 'ai_tag_mismatch'))
  // The media key was never opened and the ciphertext never fetched.
  assert.equal(w.go.archiveRequests.some(item => item.path === `/v1/media/${note.row.uid}`), false)
})

test('N-AI-8: a sentinel transcript, key, key suffix and model name never reach the sink, whatever happens', async t => {
  const { w, stubs } = await aiWorld(t)
  const key = 'wappie-test-key-google-SENTINELKEY0000000SNTL'
  stubs.keys.google = key
  stubs.models.google = ['sentinel-model-7c1f']
  stubs.text = 'SENTINEL-TRANSCRIPT-7c1f: a senha é 4321.'
  const done = await installed(w, { scope: aiScope({ audio: ['google', 'sentinel-model-7c1f'] }, { keys: { google: key }, requesters: 'console' }) })
  const note = await voiceNote(w)
  assert.deepEqual((await consoleJob(w, done, { uid: note.row.uid })).state, { state: 'done' })
  stubs.answer = () => ({ status: 400, body: { error: { code: 400, message: 'SENTINEL-ERROR-BODY sentinel-model-7c1f is not supported', status: 'INVALID_ARGUMENT' } } })
  const failing = await voiceNote(w)
  assert.deepEqual((await consoleJob(w, done, { uid: failing.row.uid })).state, { state: 'failed', code: 'ai_model_unavailable' })
  assert.ok(w.lines.length > 0)
  for (const line of w.lines) {
    assert.equal(lineAllowed(line), true, line)
    for (const secret of [key, 'SNTL', 'SENTINEL', 'sentinel-model', '4321', note.row.uid, failing.row.uid, done.token]) assert.equal(line.includes(secret), false, `${secret} in ${line}`)
  }
  assert.ok(events(w).some(entry => entry.event === 'ai_paused' && entry.code === 'ai_model_unavailable'))
})

test('N-AI-9: Go reports no usage and a cap ten times the bundle\'s: the enclave stops at the bundle\'s', async t => {
  const { w, stubs } = await aiWorld(t)
  // 1,000 tokens a month: the first voice note (424 in, 741 out) passes them.
  const done = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { requesters: 'console', tokens: 1000 }) })
  w.go.connections.get(done.connectionId).extra.ai_off = aiOff({ monthly_tokens: 10_000 })
  const first = await voiceNote(w)
  assert.deepEqual((await consoleJob(w, done, { uid: first.row.uid })).state, { state: 'done' })
  const second = await voiceNote(w)
  const refused = await consoleJob(w, done, { uid: second.row.uid })
  assert.deepEqual([refused.submitted.status, JSON.parse(refused.submitted.body).code], [409, 'ai_budget_reached'])
  assert.equal(stubs.generations().length, 1)
  assert.ok(events(w).some(entry => entry.event === 'ai_budget_reached'))
})

test('N-AI-9 with calls never answered: the parent stalls then drops each answer once the upload is done; each attempt is an item, each is charged at its bound, and the cap trips', async t => {
  const { w, e, stubs } = await aiWorld(t)
  // 1,000 tokens a month: one voice note's bound (its body's bytes ÷ 4 and the output limit) is past them.
  const done = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { requesters: 'console', tokens: 1000, items: 50 }) })
  stubs.answer = () => ({ delayMs: 20, network: true })
  const note = await voiceNote(w)
  const failed = await consoleJob(w, done, { uid: note.row.uid })
  assert.deepEqual(failed.state, { state: 'failed', code: 'ai_budget_reached', limit: 'month' }, 'the second attempt never leaves')
  assert.equal(stubs.generations('google').length, 1, 'one call reached the provider')
  const charged = w.go.ai.usage.filter(item => item.id === done.connectionId && item.body.failures === 1)
  assert.equal(charged.length, 1)
  const [call] = stubs.generations('google')
  const bound = Math.ceil(Buffer.byteLength(JSON.stringify(call.body)) / 4) + 16_000
  assert.deepEqual([charged[0].body.items, charged[0].body.input_tokens, charged[0].body.output_tokens, charged[0].body.charged_tokens], [0, 0, 0, bound],
    'at its bound, as a failure: no tokens reported, the input bound and the output limit charged')
  assert.equal(storedRecord(w, note.row.uid, 'audio'), null)
  assert.deepEqual(e.facts.content.ai.budgets.used(done.connectionId), { tokens: bound, items: 1 })
  // The next job stops at the gate, before anything leaves, and says which limit.
  const next = await voiceNote(w)
  const refused = await consoleJob(w, done, { uid: next.row.uid })
  assert.deepEqual([refused.submitted.status, JSON.parse(refused.submitted.body)], [409, { code: 'ai_budget_reached', limit: 'month' }])
  assert.equal(stubs.generations('google').length, 1)
  // With room for more, every attempt that leaves is an item of the day, and the day's items stop the retries too.
  const daily = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { requesters: 'console', items: 1 }) })
  const third = await voiceNote(w)
  assert.deepEqual((await consoleJob(w, daily, { uid: third.row.uid })).state, { state: 'failed', code: 'ai_budget_reached', limit: 'day' })
  assert.equal(stubs.generations('google').length, 2, 'one attempt, then the day\'s items stop the retry')
  assert.equal(w.go.ai.usage.filter(item => item.id === daily.connectionId && item.body.failures === 1).length, 1)
})

test('N-AI-13: a voice note that claims 1 s and holds 25 minutes: counted by the provider\'s own duration, else by the bytes bound; the cap trips where the real use would', async t => {
  const { w, stubs } = await aiWorld(t)
  stubs.usage.openai = { type: 'duration', seconds: 1500 }
  // 40,000 tokens a month; a duration answer counts 25 tokens a second.
  const openai = await installed(w, { scope: aiScope({ audio: ['openai', 'whisper-synthetic'] }, { requesters: 'console', tokens: 40_000 }) })
  const long = await voiceNote(w, { size: 375_000, seconds: 1 })
  assert.deepEqual((await consoleJob(w, openai, { uid: long.row.uid })).state, { state: 'done' })
  const [call] = stubs.generations('openai')
  assert.deepEqual([call.path, call.body.file.name, call.body.model, call.body.response_format, call.body.language], ['/v1/audio/transcriptions', 'audio.ogg', 'whisper-synthetic', 'json', undefined])
  const charged = w.go.ai.usage.filter(item => item.id === openai.connectionId && item.body.items === 1).at(-1).body
  assert.deepEqual([charged.seconds, charged.input_tokens, charged.output_tokens, charged.charged_tokens], [1500, 0, 0, 1500 * 25], 'the duration the provider measured, at 25 tokens a second')
  // 37,500 of 40,000 tokens counted: one more call goes, and the one after it does not.
  const next = await voiceNote(w, { size: 1000, seconds: 1 })
  assert.deepEqual((await consoleJob(w, openai, { uid: next.row.uid })).state, { state: 'done' })
  const stopped = await voiceNote(w, { size: 1000, seconds: 1 })
  assert.equal(JSON.parse((await consoleJob(w, openai, { uid: stopped.row.uid })).submitted.body).code, 'ai_budget_reached')
  // A duration answer without its seconds: the bytes bound at 25 tokens a second, never the claim; the claim is only reported.
  stubs.usage.openai = { type: 'duration' }
  const bounded = await installed(w, { scope: aiScope({ audio: ['openai', 'whisper-synthetic'] }, { requesters: 'console' }) })
  const quiet = await voiceNote(w, { size: 375_000, seconds: 1 })
  assert.deepEqual((await consoleJob(w, bounded, { uid: quiet.row.uid })).state, { state: 'done' })
  const lengthBound = w.go.ai.usage.filter(item => item.id === bounded.connectionId && item.body.items === 1).at(-1).body
  assert.deepEqual([lengthBound.seconds, lengthBound.charged_tokens], [1, 1500 * 25], '375,000 bytes at 250 a second')
  assert.deepEqual(storedRecord(w, quiet.row.uid, 'audio').usage, { seconds: 1 }, 'the record keeps what was reported: no tokens')
  // An answer with no usage at all: the input bound (the body's bytes ÷ 4) and the output limit, and never less than the length bound.
  stubs.usage.openai = undefined
  const silent = await voiceNote(w, { size: 375_000, seconds: 1 })
  assert.deepEqual((await consoleJob(w, bounded, { uid: silent.row.uid })).state, { state: 'done' })
  const unmeasured = w.go.ai.usage.filter(item => item.id === bounded.connectionId && item.body.items === 1).at(-1).body
  assert.deepEqual([unmeasured.input_tokens, unmeasured.output_tokens, unmeasured.seconds], [0, 0, 1])
  assert.ok(unmeasured.charged_tokens >= Math.ceil(375_000 / 4) + 16_000, `${unmeasured.charged_tokens}`)
})

test('N-AI-14 in a job: an answer cut with no text is ai_output_limit, unstored and charged, and a Redo asks again; a rejected key pauses its provider with an alert; a refusal is stored', async t => {
  const { w, stubs } = await aiWorld(t)
  const done = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'], document: ['anthropic', 'claude-synthetic-5'] }, { requesters: 'console' }) })
  const note = await voiceNote(w)
  stubs.answer = () => ({ status: 200, body: { candidates: [{ content: { parts: [{ text: 'thinking…', thought: true }] }, finishReason: 'MAX_TOKENS' }], usageMetadata: { promptTokenCount: 424, candidatesTokenCount: 0, thoughtsTokenCount: 16_000 } } })
  assert.deepEqual((await consoleJob(w, done, { uid: note.row.uid })).state, { state: 'failed', code: 'ai_output_limit' })
  assert.equal(storedRecord(w, note.row.uid, 'audio'), null, 'nothing stored')
  assert.deepEqual([w.go.ai.usage.at(-1).body.output_tokens, w.go.ai.usage.at(-1).body.charged_tokens], [16_000, 424 + 16_000], 'charged: the provider billed the thinking')
  stubs.answer = null
  assert.deepEqual((await consoleJob(w, done, { uid: note.row.uid, redo: true })).state, { state: 'done' })
  assert.deepEqual(storedRecord(w, note.row.uid, 'audio').flags, ['redo'])
  // A safety stop: stored as refused, with no text, so it is not sent again; a connector reads it as ai_refused.
  stubs.answer = () => ({ status: 200, body: { candidates: [{ content: { parts: [] }, finishReason: 'PROHIBITED_CONTENT' }], usageMetadata: { promptTokenCount: 424 } } })
  const blocked = await voiceNote(w)
  assert.deepEqual((await consoleJob(w, done, { uid: blocked.row.uid })).state, { state: 'done' })
  assert.deepEqual([storedRecord(w, blocked.row.uid, 'audio').text, storedRecord(w, blocked.row.uid, 'audio').flags], ['', ['refused']])
  // A key the provider rejects: that provider's functions pause until a renewal, Go is told, the other provider goes on.
  stubs.answer = () => ({ status: 401, body: { error: { code: 401, message: 'API key expired.', status: 'UNAUTHENTICATED' } } })
  const rejected = await voiceNote(w)
  assert.deepEqual((await consoleJob(w, done, { uid: rejected.row.uid })).state, { state: 'failed', code: 'ai_key_rejected' })
  assert.deepEqual(w.go.ai.alerts.at(-1).body, { code: 'ai_key_rejected', provider: 'google' })
  assert.equal(w.go.ai.usage.at(-1).body.failures, 1, 'a failure is counted, never charged')
  const later = await voiceNote(w)
  assert.equal(JSON.parse((await consoleJob(w, done, { uid: later.row.uid })).submitted.body).code, 'ai_paused')
  stubs.answer = null
  const pdf = await attachment(w, { type: 'document', plaintext: withScenario(PDF_MAGIC, { pages: ['Uma página de texto sintético, longa o bastante para não ser digitalizada.'] }), media: { mimetype: 'application/pdf' } })
  assert.deepEqual((await consoleJob(w, done, { uid: pdf.uid, feature: 'document' })).state, { state: 'done' }, 'Anthropic is not paused')
})

test('a revocation during a provider call aborts the job: nothing stored or charged, and the next call fails', async t => {
  const { w, e, stubs } = await aiWorld(t)
  const done = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { requesters: 'console' }) })
  let reached
  const inCall = new Promise(resolve => { reached = resolve })
  stubs.answer = call => { reached(); return { ...stubs.ok(call.provider, call.route), until: new Promise(() => {}) } }
  const note = await voiceNote(w)
  const job = consoleJob(w, done, { uid: note.row.uid })
  await inCall
  const revoked = await w.internal(`/internal/connections/${done.connectionId}/revoke`, { method: 'POST' })
  assert.equal(revoked.status, 204)
  assert.deepEqual((await job).state, { state: 'failed', code: 'ai_paused' })
  assert.equal(w.go.ai.derived.length, 0)
  assert.equal(w.go.ai.usage.some(item => item.body.items > 0), false, 'no answer, no item')
  // The call had left: the provider may have it whole, so it is counted as a failure, charged at its bound (§18.9).
  const [aborted] = w.go.ai.usage.filter(item => item.body.failures === 1)
  assert.ok(aborted && aborted.body.charged_tokens > 0 && aborted.body.input_tokens === 0, 'charged at its bound, with no tokens reported')
  assert.equal(e.facts.content.ai.holds(done.connectionId), false)
  const next = await w.internal('/internal/ai/jobs', { method: 'POST', body: { authorization_id: done.connectionId, device_id: vector.device, uid: note.row.uid, feature: 'audio', origin: 'console', requester_id: randomUUID(), redo: false } })
  assert.equal(next.status, 404)
})

test('a PUT answered derived_exists answers the stored record, or replaces one of an older epoch no grant opens; storage_paused answers unstored; a busy authorization answers ai_busy', async t => {
  const { w, stubs } = await aiWorld(t)
  const auth = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }) })
  const media = await connectMedia(w)
  w.go.ai.picks.set(`${media.connectionId}|${vector.device}|audio`, { authorization_id: auth.connectionId, requester_id: randomUUID(), state: 'active' })
  // Another authorization stores a record while this job waits for its provider.
  let release
  stubs.answer = call => ({ ...stubs.ok(call.provider, call.route), until: new Promise(resolve => { release = resolve }) })
  const note = await voiceNote(w)
  const answer = open(w, media, { uid: note.row.uid })
  for (let n = 0; n < 100 && !release; n++) await tick()
  const { sealDerived } = await import('../ai/derived.mjs')
  const theirs = sealDerived(DSK(), { namespace: vector.tenant, device_id: vector.device, message_uid: note.row.uid, feature: 'audio', epoch: 1 }, {
    v: 1, feature: 'audio', text: 'The other authorization\'s transcript.', provider: 'google', model: 'gemini-synthetic-flash', prompt_version: 'audio/1',
    created_at: '2026-10-01T09:30:15.123Z', source_sha256: sha256(note.plaintext).toString('hex'), usage: {}, flags: [] })
  w.go.ai.derived.push({ message_uid: note.row.uid, feature: 'audio', device_id: vector.device, epoch: 1, sealed: theirs.toString('base64url'), dedupe_tag: 'A'.repeat(43), authorization_id: randomUUID(), created_at: '2026-10-01T09:30:15Z' })
  release()
  const { value } = await answer
  assert.equal(value.content[0].text.split('\n').slice(1).join('\n'), 'The other authorization\'s transcript.')
  stubs.answer = null
  // A record stored under an older epoch (the number's epoch rotated since): no current grant opens it, so the job's record replaces it.
  const rotated = await voiceNote(w)
  const old = sealDerived(randomBytes(32), { namespace: vector.tenant, device_id: vector.device, message_uid: rotated.row.uid, feature: 'audio', epoch: 7 }, {
    v: 1, feature: 'audio', text: 'Sealed under an epoch no grant holds now.', provider: 'google', model: 'gemini-synthetic-flash', prompt_version: 'audio/1',
    created_at: '2026-09-01T09:30:15.123Z', source_sha256: sha256(rotated.plaintext).toString('hex'), usage: {}, flags: [] })
  w.go.ai.derived.push({ message_uid: rotated.row.uid, feature: 'audio', device_id: vector.device, epoch: 7, sealed: old.toString('base64url'), dedupe_tag: 'B'.repeat(43), authorization_id: randomUUID(), created_at: '2026-09-01T09:30:15Z' })
  const replaced = (await open(w, media, { uid: rotated.row.uid })).value
  assert.equal(replaced.content[0].text.split('\n').slice(1).join('\n'), stubs.text)
  const puts = w.go.ai.calls.filter(call => call.method === 'PUT' && call.route === `ai/derived/${rotated.row.uid}/audio`)
  assert.deepEqual(puts.map(call => call.body.redo), [false, true], 'refused as derived_exists, then replaced')
  assert.deepEqual([storedRecord(w, rotated.row.uid, 'audio').text, w.go.ai.derived.filter(item => item.message_uid === rotated.row.uid).length], [stubs.text, 1])
  assert.equal(events(w).filter(entry => entry.event === 'ai_store_failed').length, 0)
  // Storage paused: the caller still gets the transcript, unstored, and the log says so.
  w.go.ai.storagePaused = true
  const paused = await voiceNote(w)
  const unstored = (await open(w, media, { uid: paused.row.uid })).value
  assert.equal(unstored.content[0].text.split('\n').slice(1).join('\n'), stubs.text)
  assert.equal(storedRecord(w, paused.row.uid, 'audio'), null)
  assert.ok(events(w).some(entry => entry.event === 'ai_store_failed'))
  w.go.ai.storagePaused = false
  // One running and AI_LINE_MAX waiting for this authorization: the next is ai_busy.
  stubs.answer = call => ({ ...stubs.ok(call.provider, call.route), until: new Promise(() => {}) })
  const consoleAuth = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { requesters: 'console' }) })
  const notes = []
  for (let n = 0; n < 6; n++) notes.push(await voiceNote(w, { size: 100 }))
  const answers = []
  for (const item of notes) answers.push(await w.internal('/internal/ai/jobs', { method: 'POST', body: { authorization_id: consoleAuth.connectionId, device_id: vector.device, uid: item.row.uid, feature: 'audio', origin: 'console', requester_id: randomUUID(), redo: false } }))
  assert.deepEqual(answers.map(item => item.status), [202, 202, 202, 202, 202, 429])
  assert.deepEqual(JSON.parse(answers[5].body), { code: 'ai_busy', retry_after_s: 20 })
  await w.internal(`/internal/connections/${consoleAuth.connectionId}/revoke`, { method: 'POST' })
})

test('renewal of an AI authorization: a model changed within its provider passes with fresh tags and is committed; a changed provider is refused', async t => {
  const { w, e, stubs } = await aiWorld(t)
  stubs.models.google = ['gemini-synthetic-flash', 'gemini-synthetic-pro']
  const done = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { requesters: 'console' }) })
  const prepare = async () => {
    const answer = await w.internal(`/internal/connections/${done.connectionId}/renewal`, { method: 'POST', body: { nonce: randomBytes(32).toString('base64url') } })
    assert.equal(answer.status, 200, answer.body)
    return JSON.parse(answer.body)
  }
  const renew = async (descriptor, scope) => {
    const service = randomUUID(), token = newApiKey()
    await contentGrants(w, descriptor.reader_public_key, { service, token })
    const bundle = { version: 3, kind: 'ai', purpose: 'renewal', connection_id: done.connectionId, server_url: ORIGIN, workspace_id: workspace, service_user_id: service,
      device_ids: [vector.device], token, key_mode: 'ephemeral', consent_version: 1, expires_at: done.expiresAt, ...scope }
    bundle.cfg_tags = aiTags(bundle, { request: descriptor.renewal_id, kid: descriptor.kid })
    const { sealed } = await sealContent(descriptor.reader_public_key, bundle, aiRenewLabels(descriptor.renewal_id, done.connectionId, descriptor.kid))
    const relayed = await w.internal(`/internal/connections/${done.connectionId}/renewal/${descriptor.renewal_id}/bundle`, { method: 'POST', body: {
      connection_id: done.connectionId, tenant_id: workspace, kid: descriptor.kid, sealed, expires_at: done.expiresAt, kind: 'ai' } })
    return { relayed, service, token }
  }
  const descriptor = await prepare()
  assert.deepEqual([descriptor.kind, descriptor.consent_version, descriptor.functions, descriptor.budget.monthly_tokens], ['ai', 1, { audio: { provider: 'google', model: 'gemini-synthetic-flash' } }, 5_000_000])
  assert.deepEqual(descriptor.features, { [vector.device]: { audio: { mode: 'request', requesters: 'console' } } })
  // Another provider for the function: a new authorization, not a renewal.
  const moved = await renew(descriptor, aiScope({ audio: ['openai', 'gpt-synthetic-transcribe'] }, { requesters: 'console' }))
  assert.deepEqual([moved.relayed.status, JSON.parse(moved.relayed.body).code], [400, 'invalid_bundle'])
  // Another model of the same provider: staged, then committed once Go names the new service.
  const next = await prepare()
  const renewed = await renew(next, aiScope({ audio: ['google', 'gemini-synthetic-pro'] }, { requesters: 'console' }))
  assert.equal(renewed.relayed.status, 204, renewed.relayed.body)
  Object.assign(w.go.connections.get(done.connectionId), { service_user_id: renewed.service, api_key: renewed.token })
  await e.reader.contentSweep()
  const record = e.state.connections.get(done.connectionId)
  assert.deepEqual([record.service_user_id, record.functions.audio.model, record.request], [renewed.service, 'gemini-synthetic-pro', next.renewal_id])
  const note = await voiceNote(w)
  assert.deepEqual((await consoleJob(w, done, { uid: note.row.uid })).state, { state: 'done' }, 'the renewed tags hold at job time')
  assert.equal(stubs.generations('google').at(-1).path, '/v1beta/models/gemini-synthetic-pro:generateContent')
})

test('after a restart an AI authorization holds no key and waits in reseal; Go\'s reseal wipes its keys within the sweep', async t => {
  const { w, e } = await aiWorld(t)
  const done = await installed(w, { scope: aiScope({ audio: ['google', 'gemini-synthetic-flash'] }, { requesters: 'console' }) })
  assert.equal(e.facts.content.ai.holds(done.connectionId), true)
  w.go.connections.get(done.connectionId).status = 'reseal'
  await e.reader.contentSweep()
  assert.equal(e.facts.content.ai.holds(done.connectionId), false)
  assert.equal(e.state.connections.get(done.connectionId).kind, 'ai', 'kept for its renewal')
  const note = await voiceNote(w)
  assert.equal(JSON.parse((await consoleJob(w, done, { uid: note.row.uid })).submitted.body).code, 'ai_paused')
  // A restart: the record loads from sealed state without keys, and Go is told.
  w.go.connections.get(done.connectionId).status = 'active'
  await w.enclave.close()
  const again = await w.start()
  assert.equal(again.state.connections.get(done.connectionId)?.kind, 'ai')
  assert.equal(again.facts.content.ai.holds(done.connectionId), false)
  assert.ok(w.go.reseals.includes(done.connectionId))
})
