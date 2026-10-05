// Reader 0.6.0 in the enclave (docs/mcp-enclave.md §19), under the image's
// `any` policy: any client's request, its attested descriptor (user_data v2
// over every field), consent version 4 and link bundle v2 with their checks
// per tier, the version-4 renewal, the tiers' lifetimes and reading limits,
// the history window, the attested live list, and the logs that never name a
// client. The documents a request needs are served by a fake fetcher standing
// in for the parent's egress proxy (cimd-fetch.test.mjs tests the real one).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes, randomUUID } from 'node:crypto'
import { vector, workspace } from '@whatserver2/mcp/test/fixture'
import { attestationUserData, attestationUserDataV2, decodeAttestationDocument, descriptorSHA256 } from '../../attestation.mjs'
import { backButton, pkce, proof, sealBundle } from '../../test/harness.mjs'
import { CLIENT_LIMITS, TESTED_CLIENTS } from '../constants.mjs'
import { lineAllowed } from '../logsink.mjs'
import {
  callTool, CONSOLE_ORIGIN, consentLabels, contentGrants, DAY, deviceChecks, form, newApiKey, ORIGIN, renewLabels, resealed, RESOURCE, rpc, sealContent, world,
} from './world.mjs'

const CLAUDE = 'https://claude.ai/oauth/mcp-oauth-client-metadata'
const CLAUDE_REDIRECT = 'https://claude.ai/api/mcp/auth_callback'
const CODEX = 'https://chatgpt.com/oauth/codex/client.json'
const AGENT = 'https://agent.example.com/oauth/client.json'
const AGENT_REDIRECT = 'https://agent.example.com/oauth/callback'
const AGENT_NAME = 'Example Agent'

/** The documents the fake egress serves, by URL, and every fetch it was asked for. */
function documents() {
  const docs = new Map([[AGENT, { client_id: AGENT, client_name: AGENT_NAME, redirect_uris: [AGENT_REDIRECT, 'http://127.0.0.1/callback'] }]])
  const calls = []
  return {
    docs, calls,
    async fetch({ host, path }) {
      const url = `https://${host}${path}`
      calls.push(url)
      return docs.has(url) ? { ok: true, body: Buffer.from(JSON.stringify(docs.get(url))), cacheControl: 'max-age=600' } : { ok: false, code: 'status' }
    },
  }
}

/** The enclave under the image's `any` policy (no refusal floor, to keep the tests fast). */
async function anyWorld(t, options = {}) {
  const w = await world(t, options)
  w.clientPolicy = { refusalFloorMs: 0 }
  w.cimdFetcher = documents()
  const e = await w.start()
  return { w, e }
}

let sources = 0
/** A fresh /24 per request: the per-address budgets of one test never meet another's, and the network check has its own network. */
const fresh = () => `203.0.${++sources % 250}.${10 + (sources % 200)}`

/** GET /mcp/authorize as the assistant, then the descriptor and its prepared, attested form as Go would read them. */
async function authorize(w, { clientId, redirectUri, source = fresh(), query = {} }) {
  const { verifier, challenge } = pkce()
  const params = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: 'S256',
    resource: RESOURCE, scope: 'wappie:read', state: 'st', ...query })
  const response = await w.public(`/mcp/authorize?${params}`, { source })
  const started = { response, verifier, challenge, source, clientId, redirectUri }
  if (response.status !== 302) return started
  started.id = new URL(response.headers.location).searchParams.get('mcp_connect')
  started.descriptor = JSON.parse((await w.internal(`/internal/requests/${started.id}`)).body)
  started.nonce = randomBytes(32)
  const prepared = await w.internal(`/internal/requests/${started.id}/prepare`, { method: 'POST', body: { nonce: started.nonce.toString('base64url') } })
  assert.equal(prepared.status, 200, prepared.body)
  started.prepared = JSON.parse(prepared.body)
  return started
}

/** The completion from `source` (the request's network unless said otherwise) and the code exchange. */
async function complete(w, started, done, { source = started.source } = {}) {
  done.completed = await w.public('/mcp/authorize/complete', { ...form({ request: started.id, proof: done.signature }),
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: CONSOLE_ORIGIN }, source })
  if (done.completed.status !== 302) return done
  const code = new URL(done.completed.headers.location).searchParams.get('code')
  const exchanged = await w.public('/mcp/token', { ...form({ grant_type: 'authorization_code', code, client_id: started.clientId, code_verifier: started.verifier,
    redirect_uri: started.redirectUri, resource: RESOURCE }), source: started.source })
  assert.equal(exchanged.status, 200, exchanged.body)
  done.tokens = JSON.parse(exchanged.body)
  return done
}

/** A metadata consent as link bundle v2 (§19.15), relayed with what the console was shown. */
async function consentMetadata(w, started, { bundle = {}, relay = {}, expiresAt = new Date(Date.now() + 30 * DAY).toISOString(), until } = {}) {
  const d = started.prepared
  const linkSecret = randomBytes(32).toString('base64url')
  const history = d.trust === 'unknown' ? d.limits.history_days.default : null
  const sealedBundle = { version: 2, kind: 'metadata', server_url: ORIGIN, workspace_id: workspace, device_ids: [vector.device], token: w.apiKey, allow_plaintext: false,
    timezone: 'UTC', link_secret: linkSecret, client_id: d.client_id, trust: d.trust, started_ack: true, history_days: history, ...bundle }
  for (const name of Object.keys(sealedBundle)) if (sealedBundle[name] === undefined) delete sealedBundle[name]
  const { sealed, sealedBytes } = await sealBundle(d, sealedBundle)
  const connectionId = randomUUID()
  w.go.connections.set(connectionId, { status: 'pending', expires_at: expiresAt })
  const done = { connectionId, expiresAt }
  done.relayed = await w.internal(`/internal/requests/${started.id}/bundle`, { method: 'POST', body: {
    kind: 'metadata', connection_id: connectionId, tenant_id: workspace, kid: d.kid, sealed, expires_at: expiresAt,
    trust: d.trust, client_local: d.client_local, history_days: sealedBundle.history_days ?? null, ...relay } })
  if (done.relayed.status !== 204) return done
  done.signature = proof(linkSecret, { requestID: started.id, clientID: d.client_id, codeChallenge: d.code_challenge, sealedBytes })
  return until === 'bundle' ? done : complete(w, started, done)
}

/**
 * A text consent of version 4 (§19.15): the client, tier, ticks and window
 * sealed and bound to each number by its device check over the v4 scope;
 * Go relays the tier and window the console was shown. `fields` change the
 * bundle, `scope` only what the checks were computed over.
 */
async function consentContent(w, started, { fields = {}, scope = {}, relay = {}, expiresAt = new Date(Date.now() + 7 * DAY).toISOString(), until } = {}) {
  const d = started.prepared
  const service = randomUUID(), token = newApiKey()
  await contentGrants(w, d.reader_public_key, { service, token })
  const linkSecret = randomBytes(32).toString('base64url')
  const bundle = {
    version: 2, kind: 'content', purpose: 'consent', server_url: ORIGIN, workspace_id: workspace, service_user_id: service, device_ids: [vector.device], token,
    key_mode: 'ephemeral', consent_version: 4, expires_at: expiresAt, timezone: 'UTC', link_secret: linkSecret,
    client_id: d.client_id, client_kind: d.client_kind, client_local: d.client_local, trust: d.trust, started_ack: true, unknown_ack: d.trust === 'unknown',
    history_days: d.trust === 'unknown' ? d.limits.history_days.default : null, ...fields,
  }
  for (const name of Object.keys(bundle)) if (bundle[name] === undefined) delete bundle[name]
  if (bundle.consent_version >= 3) bundle.device_checks = deviceChecks({ ...bundle, ...scope }, { request: started.id, kid: d.kid })
  const { sealed, sealedBytes } = await sealContent(d.reader_public_key, bundle, consentLabels(started.id, d.kid))
  const connectionId = randomUUID()
  w.go.connections.set(connectionId, { status: 'pending', expires_at: expiresAt, kind: 'content', service_user_id: service, api_key: token,
    extra: { media: bundle.media === true, media_off: [], send: bundle.send ?? null, send_self: bundle.send_self === true } })
  const done = { connectionId, expiresAt, service, token, bundle }
  done.relayed = await w.internal(`/internal/requests/${started.id}/bundle`, { method: 'POST', body: {
    kind: 'content', connection_id: connectionId, tenant_id: workspace, kid: d.kid, sealed, expires_at: expiresAt,
    trust: d.trust, client_local: d.client_local, history_days: bundle.history_days ?? null,
    ...(bundle.media ? { media: true } : {}), ...(bundle.send ? { send: bundle.send, ...(bundle.send_self ? { send_self: true } : {}) } : {}), ...relay } })
  if (done.relayed.status !== 204 || until === 'bundle') return done
  done.signature = proof(linkSecret, { requestID: started.id, clientID: d.client_id, codeChallenge: d.code_challenge, sealedBytes })
  return complete(w, started, done)
}

/** The prepared descriptor's attestation is user_data v2 over the descriptor (§19.13). */
function assertAttestedWhole(described, { publicKey = true } = {}) {
  const document = decodeAttestationDocument(Buffer.from(described.attestation.document, 'base64url'))
  assert.deepEqual(document.userData, attestationUserDataV2(described.attestation, descriptorSHA256(described)))
  assert.notDeepEqual(document.userData, attestationUserData(described.attestation), 'never v1 for a descriptor')
  if (publicKey) assert.deepEqual(document.publicKey, Buffer.from(described.reader_public_key, 'base64url'))
  else assert.equal(document.publicKey, null)
  return document
}
const events = (w, name) => w.lines.map(line => JSON.parse(line)).filter(entry => entry.event === name)

test('a request of any client (§19.6, §19.12): tested ids served from the image and never fetched, an unknown document fetched; descriptor v2 attested whole', async t => {
  const { w } = await anyWorld(t)
  const tested = await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT })
  assert.equal(tested.response.status, 302, tested.response.body)
  const d = tested.prepared
  assert.deepEqual([d.descriptor_version, d.kind, d.trust, d.tested_id, d.client_name, d.client_host, d.client_local, d.limits_tier], [2, 'connect', 'tested', 'claude', 'Claude', 'claude.ai', false, 'web_tested'])
  assert.deepEqual(d.limits, CLIENT_LIMITS.web_tested)
  const { attestation, ...bare } = d
  assert.deepEqual(bare, tested.descriptor, 'the prepared descriptor is the one Go reads, plus its attestation')
  assertAttestedWhole(d)
  const local = await authorize(w, { clientId: CODEX, redirectUri: 'http://127.0.0.1:1455/callback' })
  assert.deepEqual([local.prepared.trust, local.prepared.tested_id, local.prepared.client_local, local.prepared.limits_tier, local.prepared.redirect_uri],
    ['tested', 'codex', true, 'local_tested', 'http://127.0.0.1:1455/callback'])
  assert.deepEqual(w.cimdFetcher.calls, [], 'no tested id was fetched')
  const unknown = await authorize(w, { clientId: AGENT, redirectUri: AGENT_REDIRECT })
  const u = unknown.prepared
  assert.deepEqual([u.trust, u.client_name, u.claimed_name, u.client_host, u.registrable, u.limits_tier, u.drift], ['unknown', 'agent.example.com', AGENT_NAME, 'agent.example.com', 'example.com', 'unknown', false])
  assert.deepEqual(w.cimdFetcher.calls, [AGENT])
  assertAttestedWhole(u)
  // Changing a field Go relays breaks the attestation: the console recomputes over what it is shown.
  assert.notDeepEqual(attestationUserDataV2(u.attestation, descriptorSHA256({ ...u, client_name: 'Claude' })),
    decodeAttestationDocument(Buffer.from(u.attestation.document, 'base64url')).userData)
  // A host the predicate refuses is the same refusal page, whatever the reason.
  for (const clientId of ['https://api.wappie.thehappie.co/client.json', 'https://github.io/client.json', 'https://bucket.s3.amazonaws.com/client.json', 'https://127.0.0.1/client.json']) {
    const refused = await authorize(w, { clientId, redirectUri: AGENT_REDIRECT })
    assert.equal(refused.response.status, 400, clientId)
    assert.match(refused.response.body, /invalid_client/)
  }
  assert.equal(w.cimdFetcher.calls.length, 1, 'a refused id is never fetched')
})

test('link bundle v2 in the enclave (§19.15, §19.17): the record carries the client fields, an unknown client\'s window holds, its refresh idles out in 7 days', async t => {
  const { w, e } = await anyWorld(t)
  const started = await authorize(w, { clientId: AGENT, redirectUri: AGENT_REDIRECT })
  const done = await consentMetadata(w, started, { bundle: { history_days: 7 }, relay: { history_days: 7 } })
  assert.equal(done.completed.status, 302, done.completed.body)
  const record = e.state.connections.get(done.connectionId)
  assert.deepEqual([record.client_kind, record.client_host, record.registrable, record.trust, record.limits_tier, record.profile, record.history_days, record.started_ack, record.claimed_name],
    ['cimd', 'agent.example.com', 'example.com', 'unknown', 'unknown', 'default', 7, true, AGENT_NAME])
  const refresh = [...e.state.tokens.values()].find(token => token.kind === 'refresh' && token.connection_id === done.connectionId)
  assert.equal(refresh.expires_at - refresh.issued_at, CLIENT_LIMITS.unknown.idle_days.metadata * DAY)
  // The window (§19.19): the archive's message is weeks old, so a 7-day connection cannot read it.
  const listed = await callTool(w, done.tokens.access_token, 'list_messages', { device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net' })
  assert.deepEqual([listed.isError, listed.data.messages.length, listed.data.has_more], [false, 0, false])
  const message = await callTool(w, done.tokens.access_token, 'get_message', { device_id: vector.device, uid: listed.data.messages[0]?.uid ?? randomUUID() })
  assert.equal(message.isError, true)
  // Refusals, each on a fresh request.
  for (const [label, options, code] of [
    ['a version-1 bundle', { bundle: { version: 1, kind: undefined, client_id: undefined, trust: undefined, started_ack: undefined, history_days: undefined } }, 'invalid_bundle'],
    ['no "I started this"', { bundle: { started_ack: false } }, 'invalid_bundle'],
    ['another client', { bundle: { client_id: 'https://agent.example.com/other.json' } }, 'invalid_bundle'],
    ['a tier it was not shown', { bundle: { trust: 'tested', history_days: null }, relay: { trust: 'tested', history_days: null } }, 'invalid_bundle'],
    ['a window the tier lacks', { bundle: { history_days: 14 }, relay: { history_days: 14 } }, 'invalid_bundle'],
    ['Go relays another window', { relay: { history_days: 90 } }, 'invalid_bundle'],
    ['Go relays it as local', { relay: { client_local: true } }, 'invalid_bundle'],
    ['past the tier\'s ceiling', { expiresAt: new Date(Date.now() + 91 * DAY).toISOString() }, 'bad_request'],
  ]) {
    const refused = await consentMetadata(w, await authorize(w, { clientId: AGENT, redirectUri: AGENT_REDIRECT }), options)
    assert.equal(refused.relayed.status, 400, label)
    assert.equal(JSON.parse(refused.relayed.body).code, code, label)
  }
})

test('consent version 4 by tier (§19.15): a tested web client drafts; an unknown one never sends and needs the second tick; a local app never sends; the ceilings', async t => {
  const { w, e } = await anyWorld(t)
  // Tested web: drafts and the own chat, as 0.5.0, under version 4.
  const web = await consentContent(w, await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT }), { fields: { send: 'draft', send_self: true } })
  assert.equal(web.completed?.status, 302, web.relayed.body)
  const record = e.state.connections.get(web.connectionId)
  assert.deepEqual([record.consent_version, record.send, record.trust, record.client_kind, record.tested_id, record.unknown_ack, record.history_days], [4, 'draft', 'tested', 'cimd', 'claude', false, null])
  // Unknown: text with the second tick and its window.
  const unknown = await consentContent(w, await authorize(w, { clientId: AGENT, redirectUri: AGENT_REDIRECT }), { fields: { media: true } })
  assert.equal(unknown.completed?.status, 302, unknown.relayed.body)
  const unknownRecord = e.state.connections.get(unknown.connectionId)
  assert.deepEqual([unknownRecord.trust, unknownRecord.unknown_ack, unknownRecord.history_days, unknownRecord.media, unknownRecord.limits_tier], ['unknown', true, 30, true, 'unknown'])
  const refresh = [...e.state.tokens.values()].find(token => token.kind === 'refresh' && token.connection_id === unknown.connectionId)
  assert.equal(refresh.expires_at - refresh.issued_at, CLIENT_LIMITS.unknown.idle_days.content * DAY, 'an unknown text refresh dies after 3 days unused')
  const refusals = [
    [CLAUDE, CLAUDE_REDIRECT, 'version 3 on a 0.6.0 request', { fields: { consent_version: 3, send: 'draft', client_id: undefined, client_kind: undefined, client_local: undefined, trust: undefined, started_ack: undefined, unknown_ack: undefined, history_days: undefined } }, 'invalid_bundle'],
    [CLAUDE, CLAUDE_REDIRECT, 'version 1 on a 0.6.0 request', { fields: { consent_version: 1, client_id: undefined, client_kind: undefined, client_local: undefined, trust: undefined, started_ack: undefined, unknown_ack: undefined, history_days: undefined } }, 'invalid_bundle'],
    [CLAUDE, CLAUDE_REDIRECT, 'no "I started this"', { fields: { started_ack: undefined } }, 'invalid_bundle'],
    [CLAUDE, CLAUDE_REDIRECT, 'checks over another scope', { scope: { history_days: 30 } }, 'invalid_bundle'],
    [AGENT, AGENT_REDIRECT, 'unknown without the second tick', { fields: { unknown_ack: false } }, 'invalid_bundle'],
    [AGENT, AGENT_REDIRECT, 'unknown with drafts', { fields: { send: 'draft' } }, 'invalid_bundle'],
    [AGENT, AGENT_REDIRECT, 'unknown sealed as tested', { fields: { trust: 'tested', unknown_ack: false, history_days: null }, relay: { trust: 'unknown' } }, 'invalid_bundle'],
    [AGENT, AGENT_REDIRECT, 'another client_id', { fields: { client_id: 'https://agent.example.com/other.json' } }, 'invalid_bundle'],
    [AGENT, AGENT_REDIRECT, 'sealed as local', { fields: { client_local: true } }, 'invalid_bundle'],
    [AGENT, AGENT_REDIRECT, 'a window the tier lacks', { fields: { history_days: 14 }, relay: { history_days: 14 } }, 'invalid_bundle'],
    [AGENT, AGENT_REDIRECT, 'Go relays another window', { relay: { history_days: 7 } }, 'invalid_bundle'],
    [AGENT, AGENT_REDIRECT, 'Go relays it as tested', { relay: { trust: 'tested' } }, 'invalid_bundle'],
    [AGENT, AGENT_REDIRECT, 'past the 30-day text ceiling', { expiresAt: new Date(Date.now() + 31 * DAY).toISOString() }, 'bad_request'],
    [AGENT, AGENT_REDIRECT, 'a bundle past the ceiling under Go\'s', { fields: { expires_at: new Date(Date.now() + 31 * DAY).toISOString() } }, 'invalid_bundle'],
    [CODEX, 'http://127.0.0.1:1455/callback', 'a local app with drafts', { fields: { send: 'draft' } }, 'invalid_bundle'],
    [CODEX, 'http://127.0.0.1:1455/callback', 'a local app past 30 days', { expiresAt: new Date(Date.now() + 31 * DAY).toISOString() }, 'bad_request'],
  ]
  for (const [clientId, redirectUri, label, options, code] of refusals) {
    const done = await consentContent(w, await authorize(w, { clientId, redirectUri }), options)
    assert.equal(done.relayed.status, 400, `${label}: ${done.relayed.body}`)
    assert.equal(JSON.parse(done.relayed.body).code, code, label)
  }
  // A local app (Codex) inside its ceiling: text, no sending, the tested local tier.
  const codex = await consentContent(w, await authorize(w, { clientId: CODEX, redirectUri: 'http://127.0.0.1:1455/callback' }))
  assert.equal(codex.completed?.status, 302, codex.relayed.body)
  assert.deepEqual([e.state.connections.get(codex.connectionId).limits_tier, e.state.connections.get(codex.connectionId).profile], ['local_tested', 'chatgpt.com'])
})

test('at most three live connections of untested clients and tokens per workspace (§19.10): the fourth is 409 too_many_unknown, at relay and at completion', async t => {
  const { w } = await anyWorld(t)
  const attached = []
  for (let n = 0; n < 3; n++) attached.push(await authorize(w, { clientId: AGENT, redirectUri: AGENT_REDIRECT }))
  // Two attach, the third completes; a fourth attaches while those wait.
  const first = await consentMetadata(w, attached[0])
  assert.equal(first.completed.status, 302)
  const second = await consentContent(w, attached[1])
  assert.equal(second.completed?.status, 302, second.relayed.body)
  const third = await consentMetadata(w, attached[2])
  assert.equal(third.completed.status, 302)
  const fourth = await consentMetadata(w, await authorize(w, { clientId: AGENT, redirectUri: AGENT_REDIRECT }))
  assert.deepEqual([fourth.relayed.status, JSON.parse(fourth.relayed.body).code], [409, 'too_many_unknown'])
  const text = await consentContent(w, await authorize(w, { clientId: AGENT, redirectUri: AGENT_REDIRECT }))
  assert.deepEqual([text.relayed.status, JSON.parse(text.relayed.body).code], [409, 'too_many_unknown'])
  // A tested client is not held back.
  const tested = await consentMetadata(w, await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT }))
  assert.equal(tested.completed.status, 302)
})

test('the network check (§19.12) in the enclave: the PROXY v2 source of the completion must share the request\'s /24', async t => {
  const { w } = await anyWorld(t)
  const started = await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT, source: '198.51.100.10' })
  const done = await consentMetadata(w, { ...started, source: '198.51.100.10' })
  assert.equal(done.completed.status, 302)
  const other = await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT, source: '198.51.100.10' })
  const linkSecret = randomBytes(32).toString('base64url')
  const d = other.prepared
  const { sealed, sealedBytes } = await sealBundle(d, { version: 2, kind: 'metadata', server_url: ORIGIN, workspace_id: workspace, device_ids: [vector.device], token: w.apiKey,
    allow_plaintext: false, link_secret: linkSecret, client_id: d.client_id, trust: 'tested', started_ack: true, history_days: null })
  const connectionId = randomUUID(), expiresAt = new Date(Date.now() + DAY).toISOString()
  w.go.connections.set(connectionId, { status: 'pending', expires_at: expiresAt })
  assert.equal((await w.internal(`/internal/requests/${other.id}/bundle`, { method: 'POST', body: { kind: 'metadata', connection_id: connectionId, tenant_id: workspace,
    kid: d.kid, sealed, expires_at: expiresAt, trust: 'tested', client_local: false, history_days: null } })).status, 204)
  const signature = proof(linkSecret, { requestID: other.id, clientID: d.client_id, codeChallenge: d.code_challenge, sealedBytes })
  const refused = await w.public('/mcp/authorize/complete', { ...form({ request: other.id, proof: signature }), headers: { 'content-type': 'application/x-www-form-urlencoded', origin: CONSOLE_ORIGIN }, source: '198.51.101.10' })
  assert.equal(refused.status, 400)
  assert.match(refused.body, /ip_mismatch/)
  assert.equal(w.go.connections.get(connectionId).status, 'revoked')
  // The request line is written once the response has gone, so it may follow the answer by a moment.
  const refusedLine = () => w.lines.map(entry => JSON.parse(entry)).find(entry => entry.route === 'POST /mcp/authorize/complete' && entry.code === 'ip_mismatch')
  for (let n = 0; n < 100 && !refusedLine(); n++) await new Promise(resolve => setTimeout(resolve, 10))
  assert.equal(refusedLine()?.ip_mismatch, true)
})

test('the way back in the enclave (§19.30): a wrong proof from the request\'s network gets the button, another network the console link; the console\'s Cancel ends the assistant\'s wait only from the request\'s network', async t => {
  const { w } = await anyWorld(t)
  const decline = (started, source) => w.public('/mcp/authorize/decline', { ...form({ request: started.id }),
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: CONSOLE_ORIGIN }, source })
  const waitFor = async find => { for (let n = 0; n < 100 && !find(); n++) await new Promise(resolve => setTimeout(resolve, 10)); return find() }
  const lines = () => w.lines.map(entry => JSON.parse(entry))
  // A completion from another network: the console page, no button, and the request's state nowhere on it.
  const other = await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT, source: '198.51.100.10', query: { state: 'st-complete' } })
  // consentMetadata posts the completion from `source`: here another network than the request's.
  const done = await consentMetadata(w, { ...other, source: '198.51.101.10' })
  assert.equal(done.relayed.status, 204, done.relayed.body)
  assert.equal(done.completed.status, 400)
  assert.equal(done.completed.headers.location, undefined)
  assert.match(done.completed.body, /<small>Wappie MCP: ip_mismatch<\/small>/)
  assert.equal(backButton(done.completed.body), null)
  assert.ok(done.completed.body.includes(CONSOLE_ORIGIN))
  assert.equal(done.completed.body.includes('st-complete'), false)
  // A wrong proof from the request's own network: one button back to the assistant, with access_denied, its state and iss;
  // the request lives on, and the right proof then completes it.
  const near = await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT, source: '198.51.100.10', query: { state: 'st-wrong' } })
  const relayed = await consentMetadata(w, near, { until: 'bundle' })
  assert.equal(relayed.relayed.status, 204, relayed.relayed.body)
  const wrong = await complete(w, near, { signature: 'A'.repeat(43) }, { source: '198.51.100.30' })
  assert.equal(wrong.completed.status, 400)
  assert.equal(wrong.completed.headers.location, undefined)
  assert.match(wrong.completed.body, /<small>Wappie MCP: invalid_proof<\/small>/)
  const button = backButton(wrong.completed.body)
  assert.deepEqual([button.base, button.params, button.label], [CLAUDE_REDIRECT, { error: 'access_denied', state: 'st-wrong', iss: ORIGIN }, 'Back to claude.ai'])
  assert.equal((await complete(w, near, relayed, { source: '198.51.100.30' })).completed.status, 302)
  // Cancel from the request's own network: the browser goes straight back, and the request is gone.
  const cancelled = await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT, source: '198.51.100.10', query: { state: 'st-cancel' } })
  const declined = await decline(cancelled, '198.51.100.20')
  assert.equal(declined.status, 302)
  const location = new URL(declined.headers.location)
  assert.deepEqual([`${location.origin}${location.pathname}`, Object.fromEntries(location.searchParams)], [CLAUDE_REDIRECT, { error: 'access_denied', state: 'st-cancel', iss: ORIGIN }])
  assert.equal((await w.internal(`/internal/requests/${cancelled.id}`)).status, 404)
  const line = await waitFor(() => lines().find(entry => entry.route === 'POST /mcp/authorize/decline' && entry.code === 'declined'))
  assert.deepEqual([line.status, line.ip_mismatch], [302, false])
  // Cancel from another network: the request ends, and the browser goes back to the console with nothing of the request.
  const far = await authorize(w, { clientId: AGENT, redirectUri: AGENT_REDIRECT, source: '198.51.100.10', query: { state: 'st-far' } })
  const refused = await decline(far, '198.51.102.10')
  assert.deepEqual([refused.status, refused.headers.location, refused.body], [302, `${CONSOLE_ORIGIN}/console`, ''])
  assert.equal((await w.internal(`/internal/requests/${far.id}`)).status, 404)
  const farLine = await waitFor(() => lines().find(entry => entry.route === 'POST /mcp/authorize/decline' && entry.code === 'ip_mismatch'))
  assert.deepEqual([farLine.status, farLine.ip_mismatch], [302, true])
  assert.equal(w.lines.filter(entry => entry.includes('/mcp/authorize/decline')).every(entry => lineAllowed(entry)), true, 'the parent\'s sink admits the lines')
  // From anywhere but the console, nothing happens.
  const kept = await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT, source: '198.51.100.10' })
  const forged = await w.public('/mcp/authorize/decline', { ...form({ request: kept.id }), headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://evil.example' }, source: '198.51.100.10' })
  assert.equal(forged.status, 400)
  assert.equal((await w.internal(`/internal/requests/${kept.id}`)).status, 200)
})

test('the version-4 renewal (§19.16): an unknown text connection renews with its own client, tier and window under fresh checks; a version-3 bundle and a changed window are refused', async t => {
  const { w, e } = await anyWorld(t)
  const done = await consentContent(w, await authorize(w, { clientId: AGENT, redirectUri: AGENT_REDIRECT }))
  assert.equal(done.completed?.status, 302, done.relayed.body)
  await e.close()
  const again = await w.start()
  const waiting = (await resealed(w, done.tokens.access_token, done.connectionId)).numbers
  // An unknown connection's block names its tier and the window the person chose (§19.29).
  assert.deepEqual([waiting.data.connection.tier, waiting.data.connection.history_days], ['unknown', 30])
  const renew = async fields => {
    const nonce = randomBytes(32)
    const prepared = await w.internal(`/internal/connections/${done.connectionId}/renewal`, { method: 'POST', body: { nonce: nonce.toString('base64url') } })
    assert.equal(prepared.status, 200, prepared.body)
    const renewal = JSON.parse(prepared.body)
    const service = randomUUID(), token = newApiKey()
    await contentGrants(w, renewal.reader_public_key, { service, token })
    const connection = w.go.connections.get(done.connectionId)
    const bundle = { version: 2, kind: 'content', purpose: 'renewal', server_url: ORIGIN, workspace_id: workspace, service_user_id: service, device_ids: [vector.device], token,
      key_mode: 'ephemeral', consent_version: 4, expires_at: connection.expires_at, connection_id: done.connectionId,
      client_id: AGENT, client_kind: 'cimd', client_local: false, trust: 'unknown', started_ack: true, unknown_ack: true, history_days: 30, ...fields }
    for (const name of Object.keys(bundle)) if (bundle[name] === undefined) delete bundle[name]
    if (bundle.consent_version >= 3) bundle.device_checks = deviceChecks(bundle, { request: renewal.renewal_id, kid: renewal.kid })
    const { sealed } = await sealContent(renewal.reader_public_key, bundle, renewLabels(renewal.renewal_id, done.connectionId, renewal.kid))
    const relayed = await w.internal(`/internal/connections/${done.connectionId}/renewal/${renewal.renewal_id}/bundle`, { method: 'POST', body: {
      connection_id: done.connectionId, tenant_id: workspace, kid: renewal.kid, sealed, expires_at: connection.expires_at, kind: 'content' } })
    return { renewal, service, token, relayed }
  }
  // Refusals first: a connection keeps three live renewals, and each prepare makes the oldest give way.
  for (const [label, fields] of [
    ['a version-3 bundle for a version-4 record', { consent_version: 3, send: 'draft', client_id: undefined, client_kind: undefined, client_local: undefined, trust: undefined, started_ack: undefined, unknown_ack: undefined, history_days: undefined }],
    ['another window', { history_days: 7 }], ['another client', { client_id: 'https://agent.example.com/other.json' }], ['as tested', { trust: 'tested', unknown_ack: false, history_days: null }],
  ]) {
    const refused = await renew(fields)
    assert.equal(refused.relayed.status, 400, label)
    assert.equal(JSON.parse(refused.relayed.body).code, 'invalid_bundle', label)
  }
  const renewed = await renew({})
  const r = renewed.renewal
  assert.deepEqual([r.descriptor_version, r.kind, r.consent_version, r.client_kind, r.client_id, r.client_host, r.registrable, r.trust, r.limits_tier, r.unknown_ack, r.history_days, r.claimed_name, r.client_name],
    [2, 'renewal', 4, 'cimd', AGENT, 'agent.example.com', 'example.com', 'unknown', 'unknown', true, 30, AGENT_NAME, 'agent.example.com'])
  assert.deepEqual(r.limits, CLIENT_LIMITS.unknown)
  assert.equal('bearer_sha256' in r || 'allowed_networks' in r, false)
  assertAttestedWhole(r)
  assert.equal(renewed.relayed.status, 204, renewed.relayed.body)
  // Go swaps, and the next call commits: the record keeps its client fields.
  const connection = w.go.connections.get(done.connectionId)
  connection.service_user_id = renewed.service
  connection.status = 'active'
  const numbers = await callTool(w, done.tokens.access_token, 'list_numbers')
  assert.equal(numbers.isError, false, numbers.text)
  const record = again.state.connections.get(done.connectionId)
  assert.deepEqual([record.trust, record.history_days, record.unknown_ack, record.client_kind], ['unknown', 30, true, 'cimd'])
})

test('reading limits in the enclave (§19.19): the tier\'s first-hour budget answers limit_reached and Go hears budget_hit once; 20 calls a minute for an untested client', async t => {
  // A rebuilt image whose tested web tier has a first-hour budget of two
  // messages: the archive's message is weeks old, and only a tier without a
  // window reads it whatever the date.
  const limits = structuredClone(CLIENT_LIMITS)
  limits.web_tested.first_hour = { messages: 2, attachments: 1 }
  const { w } = await anyWorld(t, { constants: { CLIENT_LIMITS: limits } })
  const done = await consentMetadata(w, await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT }))
  assert.equal(done.completed.status, 302)
  const tool = () => callTool(w, done.tokens.access_token, 'list_messages', { device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net' })
  // One message a call: two calls start under the limit, the third does not.
  for (let n = 0; n < 2; n++) assert.equal((await tool()).isError, false)
  const capped = await tool()
  assert.equal(capped.isError, true, capped.text)
  assert.match(capped.text, /^Could not read the archive \(limit_reached\)\. This connection reached its reading limit for now; it resets at \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\.$/)
  await tool()
  assert.deepEqual(w.go.budgetHits, [{ id: done.connectionId, code: 'first_hour_messages' }], 'once per window')
  assert.deepEqual(events(w, 'budget_hit').map(entry => entry.code), ['first_hour_messages'])
  // Previews are not counted.
  assert.equal((await callTool(w, done.tokens.access_token, 'list_chats', { device_id: vector.device })).isError, false)
  // The calls a minute: 20 for this tier, whatever the tools answer.
  for (let n = 0; n < 25; n++) assert.notEqual((await rpc(w, done.tokens.access_token)).status, 429, 'a tested client keeps 60')
  const unknown = await consentMetadata(w, await authorize(w, { clientId: AGENT, redirectUri: AGENT_REDIRECT }))
  const statuses = []
  for (let n = 0; n < 21; n++) statuses.push((await rpc(w, unknown.tokens.access_token)).status)
  assert.deepEqual([statuses.slice(0, 20).every(status => status === 200), statuses[20]], [true, 429], '20 calls a minute, then 429')
})

test('reading limits under concurrency (§19.19): a JSON-RPC batch takes one call a minute per element and its tool calls cannot all pass one check; a batch larger than a minute is refused whole', async t => {
  const limits = structuredClone(CLIENT_LIMITS)
  limits.web_tested.first_hour = { messages: 2, attachments: 1 }
  const { w } = await anyWorld(t, { constants: { CLIENT_LIMITS: limits } })
  const done = await consentMetadata(w, await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT }))
  assert.equal(done.completed.status, 302)
  const call = id => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'list_messages', arguments: { device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net' } } })
  // Eight calls in one POST, all run at once: two start under the limit (one message each), six are refused.
  const batch = await rpc(w, done.tokens.access_token, Array.from({ length: 8 }, (_, n) => call(n + 1)))
  assert.equal(batch.status, 200, batch.body)
  const answers = batch.body.startsWith('event:')
    ? batch.body.split('\n').filter(line => line.startsWith('data: ')).map(line => JSON.parse(line.slice(6))).flat()
    : JSON.parse(batch.body)
  assert.equal(answers.length, 8)
  const texts = answers.map(answer => answer.result.content[0].text)
  assert.equal(texts.filter(text => !text.startsWith('Could not read')).length, 2, texts.join('\n'))
  assert.equal(texts.filter(text => text.startsWith('Could not read the archive (limit_reached)')).length, 6)
  assert.deepEqual(w.go.budgetHits, [{ id: done.connectionId, code: 'first_hour_messages' }])
  // Calls sent at once in separate requests are held the same way.
  const again = await consentMetadata(w, await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT }))
  const parallel = await Promise.all(Array.from({ length: 6 }, () => callTool(w, again.tokens.access_token, 'list_messages', { device_id: vector.device, chat_key: '5511999990000@s.whatsapp.net' })))
  assert.equal(parallel.filter(result => !result.isError).length, 2, parallel.map(result => result.text).join('\n'))
  // The batch took eight of the minute's 60 calls: 52 more pass, then 429.
  const statuses = []
  for (let n = 0; n < 53; n++) statuses.push((await rpc(w, done.tokens.access_token)).status)
  assert.deepEqual([statuses.slice(0, 52).every(status => status === 200), statuses[52]], [true, 429])
  // An untested client's 20 a minute: a batch of 21 is refused whole and takes nothing; one of 20 takes them all.
  const unknown = await consentMetadata(w, await authorize(w, { clientId: AGENT, redirectUri: AGENT_REDIRECT }))
  const list = n => Array.from({ length: n }, (_, i) => ({ jsonrpc: '2.0', id: i + 1, method: 'tools/list', params: {} }))
  const large = await rpc(w, unknown.tokens.access_token, list(21))
  assert.deepEqual([large.status, JSON.parse(large.body).error.message], [400, 'Too many calls in one batch.'])
  assert.equal((await rpc(w, unknown.tokens.access_token, list(20))).status, 200)
  assert.equal((await rpc(w, unknown.tokens.access_token)).status, 429)
  // Each request's line is written once its response has gone: the last one may follow by a moment.
  const codes = () => w.lines.map(line => JSON.parse(line)).filter(entry => entry.route === 'POST /mcp').map(entry => entry.code).filter(Boolean)
  for (let n = 0; n < 100 && !codes().includes('rate_limited'); n++) await new Promise(resolve => setTimeout(resolve, 10))
  assert.ok(codes().includes('batch_too_large') && codes().includes('rate_limited'), JSON.stringify(codes()))
})

test('the attested live list (§19.22): the workspace\'s live ids sorted, AI records left out, the console\'s nonce, user_data v2 and no public key', async t => {
  const { w, e } = await anyWorld(t)
  const one = await consentMetadata(w, await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT }))
  const two = await consentContent(w, await authorize(w, { clientId: AGENT, redirectUri: AGENT_REDIRECT }))
  e.state.connections.set('11111111-1111-4111-8111-111111111111', { connection_id: '11111111-1111-4111-8111-111111111111', tenant_id: workspace, kind: 'ai' })
  e.state.connections.set('22222222-2222-4222-8222-222222222222', { connection_id: '22222222-2222-4222-8222-222222222222', tenant_id: randomUUID() })
  const nonce = randomBytes(32).toString('base64url')
  const answer = await w.internal(`/internal/workspaces/${workspace}/live-list`, { method: 'POST', body: { nonce } })
  assert.equal(answer.status, 200, answer.body)
  const list = JSON.parse(answer.body)
  assert.deepEqual(Object.keys(list), ['descriptor_version', 'kind', 'workspace_id', 'nonce', 'connection_ids', 'at', 'attestation'])
  assert.deepEqual([list.descriptor_version, list.kind, list.workspace_id, list.nonce], [2, 'live_list', workspace, nonce])
  assert.deepEqual(list.connection_ids, [one.connectionId, two.connectionId].sort())
  assert.equal(list.attestation.request_id, '')
  const document = assertAttestedWhole(list, { publicKey: false })
  assert.deepEqual(document.nonce, Buffer.from(nonce, 'base64url'))
  for (const body of [{ nonce: 'short' }, { nonce, extra: 1 }, {}]) assert.equal((await w.internal(`/internal/workspaces/${workspace}/live-list`, { method: 'POST', body })).status, 400)
  let limited = 0
  for (let n = 0; n < 10; n++) if ((await w.internal(`/internal/workspaces/${workspace}/live-list`, { method: 'POST', body: { nonce } })).status === 429) limited++
  assert.equal(limited, 1, 'ten a minute per workspace')
})

test('logs (§19.24): the authorize line\'s flags, client_resolved and cimd_fetch, the health counters; no line names a client\'s host, name or URL', async t => {
  const { w, e } = await anyWorld(t)
  const sentinelHost = 'sentinel-7f3a.example.org', sentinelName = 'Sentinel Ninetynine'
  const id = `https://${sentinelHost}/oauth/client.json`
  w.cimdFetcher.docs.set(id, { client_id: id, client_name: sentinelName, redirect_uris: [`https://${sentinelHost}/cb`, 'cursor://x'] })
  const started = await authorize(w, { clientId: id, redirectUri: `https://${sentinelHost}/cb` })
  const done = await consentMetadata(w, started)
  assert.equal(done.completed.status, 302)
  await callTool(w, done.tokens.access_token, 'list_numbers')
  const tick = await e.health.tick()
  assert.deepEqual([tick.clients_unknown, tick.connections_unknown, tick.connections_token, tick.cimd_fetches, tick.cimd_refusals, tick.tested_drift, tick.ip_mismatches, tick.budget_hits],
    [1, 1, 0, 1, 0, 0, 0, 0])
  assert.equal((await e.health.tick()).cimd_fetches, 0, 'counts since the last line')
  const entries = w.lines.map(line => JSON.parse(line))
  const authorizeLine = entries.find(entry => entry.route === 'GET /mcp/authorize' && entry.unknown === true)
  assert.deepEqual([authorizeLine.local, authorizeLine.cimd, authorizeLine.drift, authorizeLine.resource_default], [false, true, false, false])
  assert.deepEqual(events(w, 'client_resolved').filter(entry => entry.ignored_uris === 1).length, 1)
  assert.deepEqual(Object.keys(events(w, 'cimd_fetch')[0]).sort(), ['code', 'event', 'ms', 'ts'])
  for (const line of w.lines) {
    assert.equal(lineAllowed(line), true, line)
    for (const secret of [sentinelHost, sentinelName, 'sentinel-7f3a', 'example.org', 'agent.example.com', 'claude.ai', 'https://']) assert.equal(line.includes(secret), false, line)
  }
})

test('the descriptor vectors\' shapes are the reader\'s: each kind of attest-v2.json has the members this image writes', async t => {
  const { w } = await anyWorld(t)
  const v2 = JSON.parse(await import('node:fs/promises').then(fs => fs.readFile(new URL('../../test/vectors/attest-v2.json', import.meta.url), 'utf8')))
  const keys = kind => v2.descriptors.filter(item => item.kind === kind).map(item => Object.keys(item.descriptor).sort())
  const connect = await authorize(w, { clientId: AGENT, redirectUri: AGENT_REDIRECT })
  for (const shape of keys('connect')) assert.deepEqual(shape, Object.keys(connect.prepared).sort())
  const token = JSON.parse((await w.internal('/internal/token-requests', { method: 'POST', body: { nonce: randomBytes(32).toString('base64url') } })).body)
  for (const shape of keys('token')) assert.deepEqual(shape, Object.keys(token).sort())
  const list = JSON.parse((await w.internal(`/internal/workspaces/${workspace}/live-list`, { method: 'POST', body: { nonce: randomBytes(32).toString('base64url') } })).body)
  for (const shape of keys('live_list')) assert.deepEqual(shape, Object.keys(list).sort())
  const ai = JSON.parse((await w.internal('/internal/ai/requests', { method: 'POST', body: { nonce: randomBytes(32).toString('base64url') } })).body)
  for (const shape of keys('ai')) assert.deepEqual(shape, Object.keys(ai).sort())
  assert.deepEqual(TESTED_CLIENTS.map(entry => entry.id), ['claude', 'chatgpt', 'chatgpt_cb', 'codex', 'claude_code', 'claude_dcr', 'chatgpt_dcr'])
})

test('public wildcard names that resolve inside (127.0.0.1.nip.io, 169.254.169.254.sslip.io) pass the host check and die at the parent\'s proxy: one uniform refusal, the domain remembered', async t => {
  const { w } = await anyWorld(t)
  // The parent's proxy resolves the name, finds a private address and answers 403 private_address; the enclave sees proxy_refused.
  const proxy = w.cimdFetcher
  const refused = new Set(['127.0.0.1.nip.io', '169.254.169.254.sslip.io', '10.0.0.5.nip.io'])
  const real = proxy.fetch
  proxy.fetch = async request => (refused.has(request.host) ? (proxy.calls.push(`https://${request.host}${request.path}`), { ok: false, code: 'proxy_refused', network: true }) : real(request))
  const bodies = new Set()
  for (const host of ['127.0.0.1.nip.io', '169.254.169.254.sslip.io']) {
    const answer = await authorize(w, { clientId: `https://${host}/client.json`, redirectUri: `https://${host}/cb` })
    assert.equal(answer.response.status, 400, host)
    bodies.add(answer.response.body)
  }
  assert.equal(bodies.size, 1)
  assert.match([...bodies][0], /invalid_client/)
  // A network failure is remembered for the registrable domain: another name under nip.io is not fetched within the minute.
  const again = await authorize(w, { clientId: 'https://10.0.0.5.nip.io/client.json', redirectUri: 'https://10.0.0.5.nip.io/cb' })
  assert.equal(again.response.status, 400)
  assert.deepEqual(proxy.calls, ['https://127.0.0.1.nip.io/client.json', 'https://169.254.169.254.sslip.io/client.json'])
  assert.deepEqual(events(w, 'cimd_fetch').map(entry => entry.code), ['proxy_refused', 'proxy_refused'])
})

test('the version-4 renewal of a tested web client with drafts (§19.16): the send fields and the client\'s renew under the v4 scope; a check over the consent\'s request is refused', async t => {
  const { w, e } = await anyWorld(t)
  const started = await authorize(w, { clientId: CLAUDE, redirectUri: CLAUDE_REDIRECT })
  const done = await consentContent(w, started, { fields: { send: 'draft' } })
  assert.equal(done.completed?.status, 302, done.relayed.body)
  w.go.connections.get(done.connectionId).api_key = done.token
  await e.close()
  await w.start()
  const nonce = randomBytes(32)
  const prepare = async () => JSON.parse((await w.internal(`/internal/connections/${done.connectionId}/renewal`, { method: 'POST', body: { nonce: nonce.toString('base64url') } })).body)
  const renewWith = async (renewal, { request = renewal.renewal_id, fields = {} } = {}) => {
    const service = randomUUID(), token = newApiKey()
    await contentGrants(w, renewal.reader_public_key, { service, token })
    const connection = w.go.connections.get(done.connectionId)
    const bundle = { version: 2, kind: 'content', purpose: 'renewal', server_url: ORIGIN, workspace_id: workspace, service_user_id: service, device_ids: [vector.device], token,
      key_mode: 'ephemeral', consent_version: 4, expires_at: connection.expires_at, connection_id: done.connectionId, send: 'draft',
      client_id: CLAUDE, client_kind: 'cimd', client_local: false, trust: 'tested', started_ack: true, unknown_ack: false, history_days: null, ...fields }
    bundle.device_checks = deviceChecks(bundle, { request, kid: renewal.kid })
    const { sealed } = await sealContent(renewal.reader_public_key, bundle, renewLabels(renewal.renewal_id, done.connectionId, renewal.kid))
    return w.internal(`/internal/connections/${done.connectionId}/renewal/${renewal.renewal_id}/bundle`, { method: 'POST', body: {
      connection_id: done.connectionId, tenant_id: workspace, kid: renewal.kid, sealed, expires_at: connection.expires_at, kind: 'content' } })
  }
  const stale = await renewWith(await prepare(), { request: started.id })
  assert.deepEqual([stale.status, JSON.parse(stale.body).code], [400, 'invalid_bundle'], 'checks made for the consent, not this renewal')
  const dropped = await renewWith(await prepare(), { fields: { send: undefined } })
  assert.equal(dropped.status, 400, 'a renewal never changes the consent')
  const renewal = await prepare()
  assert.deepEqual([renewal.kind, renewal.consent_version, renewal.send, renewal.trust, renewal.tested_id, renewal.client_name, renewal.limits_tier, renewal.history_days],
    ['renewal', 4, 'draft', 'tested', 'claude', 'Claude', 'web_tested', null])
  assertAttestedWhole(renewal)
  const accepted = await renewWith(renewal)
  assert.equal(accepted.status, 204, accepted.body)
})

test('the version-4 renewal of a tested local app (§19.16): a Codex loopback text connection renews as the app it is; a bundle adding drafts or changing the client is refused', async t => {
  const { w, e } = await anyWorld(t)
  const started = await authorize(w, { clientId: CODEX, redirectUri: 'http://127.0.0.1:49152/callback' })
  assert.deepEqual([started.prepared.trust, started.prepared.client_local, started.prepared.limits_tier, started.prepared.tested_id], ['tested', true, 'local_tested', 'codex'])
  const done = await consentContent(w, started)
  assert.equal(done.completed?.status, 302, done.relayed.body)
  await e.close()
  const again = await w.start()
  assert.equal((await resealed(w, done.tokens.access_token, done.connectionId)).numbers.data.connection.tier, 'local_tested')
  const renew = async (fields = {}) => {
    const prepared = await w.internal(`/internal/connections/${done.connectionId}/renewal`, { method: 'POST', body: { nonce: randomBytes(32).toString('base64url') } })
    assert.equal(prepared.status, 200, prepared.body)
    const renewal = JSON.parse(prepared.body)
    const service = randomUUID(), token = newApiKey()
    await contentGrants(w, renewal.reader_public_key, { service, token })
    const connection = w.go.connections.get(done.connectionId)
    const bundle = { version: 2, kind: 'content', purpose: 'renewal', server_url: ORIGIN, workspace_id: workspace, service_user_id: service, device_ids: [vector.device], token,
      key_mode: 'ephemeral', consent_version: 4, expires_at: connection.expires_at, connection_id: done.connectionId,
      client_id: CODEX, client_kind: 'cimd', client_local: true, trust: 'tested', started_ack: true, unknown_ack: false, history_days: null, ...fields }
    for (const name of Object.keys(bundle)) if (bundle[name] === undefined) delete bundle[name]
    bundle.device_checks = deviceChecks(bundle, { request: renewal.renewal_id, kid: renewal.kid })
    const { sealed } = await sealContent(renewal.reader_public_key, bundle, renewLabels(renewal.renewal_id, done.connectionId, renewal.kid))
    const relayed = await w.internal(`/internal/connections/${done.connectionId}/renewal/${renewal.renewal_id}/bundle`, { method: 'POST', body: {
      connection_id: done.connectionId, tenant_id: workspace, kid: renewal.kid, sealed, expires_at: connection.expires_at, kind: 'content' } })
    return { renewal, service, relayed }
  }
  for (const [label, fields] of [
    ['drafts on a local app', { send: 'draft' }], ['a web client', { client_local: false }], ['another app', { client_id: 'https://claude.ai/oauth/claude-code-client-metadata' }],
    ['a window it never had', { history_days: 30 }],
  ]) {
    const refused = await renew(fields)
    assert.equal(refused.relayed.status, 400, label)
    assert.equal(JSON.parse(refused.relayed.body).code, 'invalid_bundle', label)
  }
  const renewed = await renew()
  const r = renewed.renewal
  assert.deepEqual([r.kind, r.consent_version, r.client_kind, r.client_id, r.tested_id, r.client_local, r.client_name, r.trust, r.limits_tier, r.history_days],
    ['renewal', 4, 'cimd', CODEX, 'codex', true, 'Codex', 'tested', 'local_tested', null])
  assert.deepEqual(r.limits, CLIENT_LIMITS.local_tested)
  assertAttestedWhole(r)
  assert.equal(renewed.relayed.status, 204, renewed.relayed.body)
  const connection = w.go.connections.get(done.connectionId)
  connection.service_user_id = renewed.service
  connection.status = 'active'
  const numbers = await callTool(w, done.tokens.access_token, 'list_numbers')
  assert.equal(numbers.isError, false, numbers.text)
  const record = again.state.connections.get(done.connectionId)
  assert.deepEqual([record.client_local, record.trust, record.limits_tier, record.tested_id, record.send ?? null], [true, 'tested', 'local_tested', 'codex', null])
})
