// Fakes for the enclave tests: an NSM helper (a stub nsm-attest binary that
// writes a COSE_Sign1-shaped CBOR document), an in-memory KMS with the same
// interface as kms.mjs, a Go that serves /v1/mcp/enclave/* with its own HMAC
// check (written from the contract, not from hmac.mjs) in front of the
// synthetic archive, and an ACME server that validates TLS-ALPN-01 by really
// connecting to the challenge listener. Nothing here is imported by the image.
import { createServer as createHTTPServer, request as httpRequest } from 'node:http'
import { connect as netConnect } from 'node:net'
import { Duplex } from 'node:stream'
import { createHash, createHmac, createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign as signData, timingSafeEqual, verify as verifyData } from 'node:crypto'
import { access, chmod, constants as fsConstants, mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { connect as tlsConnect } from 'node:tls'
import * as asn1js from 'asn1js'
import { bits, explicit, integer, octets, oid, pem, selfSigned, seq, set, tlv, utf8 } from '../x509.mjs'

// ---- CBOR encoding (test side only) -------------------------------------------
function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n])
  if (n < 256) return Buffer.from([(major << 5) | 24, n])
  if (n < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b }
  if (n < 2 ** 32) { const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b }
  const b = Buffer.alloc(9); b[0] = (major << 5) | 27; b.writeBigUInt64BE(BigInt(n), 1); return b
}
export function cbor(value) {
  if (value === null) return Buffer.from([0xf6])
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value)
  if (typeof value === 'string') { const bytes = Buffer.from(value, 'utf8'); return Buffer.concat([head(3, bytes.length), bytes]) }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.concat([head(2, value.length), Buffer.from(value)])
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)])
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])])
  if (value && value.tag !== undefined) return Buffer.concat([head(6, value.tag), cbor(value.value)])
  throw new Error('cbor: unsupported')
}

export const PCR0 = 'ab'.repeat(48)

/** A COSE_Sign1-shaped document (unsigned; the reader never verifies its own). */
export function fakeDocument({ publicKey = null, nonce = null, userData = null, pcr0 = PCR0 } = {}) {
  const payload = new Map([
    ['module_id', 'i-test-enc0123456789'], ['digest', 'SHA384'], ['timestamp', Date.now()],
    ['pcrs', new Map([[0, Buffer.from(pcr0, 'hex')], [1, Buffer.alloc(48, 1)], [2, Buffer.alloc(48, 2)], [3, Buffer.alloc(48, 3)]])],
    ['certificate', Buffer.alloc(8)], ['cabundle', [Buffer.alloc(8)]],
    ['public_key', publicKey], ['user_data', userData], ['nonce', nonce],
  ])
  return cbor({ tag: 18, value: [cbor(new Map([[1, -35]])), new Map(), cbor(payload), Buffer.alloc(96)] })
}

/**
 * Writes a stub nsm-attest with the real one's argument and exit-code
 * contract. It runs with an empty environment, so the shebang is absolute.
 * `mode: 'fail'` exits 1 (an NSM error). It goes under os.tmpdir(), which must
 * allow exec: where it does not (the probe enclave's /tmp is a noexec tmpfs)
 * this says so, rather than every boot failing later as attest_failed. Set
 * TMPDIR to a directory that does (deploy/enclave/probe does).
 */
export async function fakeNsm({ mode = 'ok' } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'wappie-nsm-'))
  const bin = join(dir, 'nsm-attest')
  const fixtures = new URL('./fixtures.mjs', import.meta.url).href
  await writeFile(bin, `#!${process.execPath}
const args = process.argv.slice(2)
if (args.length !== 3) process.exit(3)
const field = (text, min, max) => { if (text === '-') return null; if (!/^([0-9a-f]{2})*$/.test(text)) process.exit(3); const b = Buffer.from(text, 'hex'); if (b.length < min || b.length > max) process.exit(3); return b }
const publicKey = field(args[0], 1, 1024), nonce = field(args[1], 0, 512), userData = field(args[2], 0, 512)
if (${JSON.stringify(mode)} === 'fail') process.exit(1)
const { fakeDocument } = await import(${JSON.stringify(fixtures)})
process.stdout.write(fakeDocument({ publicKey, nonce, userData }))
`)
  await chmod(bin, 0o755)
  try { await access(bin, fsConstants.X_OK) } catch (error) {
    throw new Error(`fakeNsm: ${bin} cannot be executed (${error.code}); ${dir} may be on a noexec mount: set TMPDIR to a directory that allows exec`)
  }
  return bin
}

// ---- KMS ------------------------------------------------------------------------
const same = (a, b) => JSON.stringify(Object.entries(a).sort()) === JSON.stringify(Object.entries(b).sort())
export const kmsRefusal = name => Object.assign(new Error(name), { name, $fault: 'client' })

/**
 * An in-memory KMS with kms.mjs's interface: ciphertext blobs name an entry,
 * and Decrypt checks the key ARN and the encryption context exactly.
 * `encrypt` stands in for the owner's `aws kms encrypt`.
 */
export function fakeKms({ policy = '{"Version":"2012-10-17","Statement":[]}', attest } = {}) {
  const entries = new Map()
  const kms = {
    calls: [], policy, down: false,
    blob(keyArn, plaintext, context) {
      const id = randomBytes(16)
      entries.set(id.toString('hex'), { keyArn, plaintext: Buffer.from(plaintext), context })
      return Buffer.concat([Buffer.from('KMSBLOB'), id])
    },
    encrypt(keyArn, plaintext, context) { return kms.blob(keyArn, plaintext, context) },
    async decrypt(keyArn, ciphertext, context) {
      kms.calls.push({ op: 'decrypt', keyArn, context })
      if (kms.down) throw Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' })
      if (attest) await attest({ publicKey: Buffer.alloc(294, 7) })
      const bytes = Buffer.from(ciphertext)
      const entry = bytes.subarray(0, 7).toString() === 'KMSBLOB' ? entries.get(bytes.subarray(7).toString('hex')) : undefined
      if (!entry || entry.keyArn !== keyArn || !same(entry.context, context)) throw kmsRefusal('InvalidCiphertextException')
      return Buffer.from(entry.plaintext)
    },
    async dataKey(keyArn, context) {
      kms.calls.push({ op: 'dataKey', keyArn, context })
      if (kms.down) throw Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' })
      const key = randomBytes(32)
      return { key: Buffer.from(key), ciphertextBlob: kms.blob(keyArn, key, context) }
    },
    async keyPolicy(keyArn) {
      kms.calls.push({ op: 'keyPolicy', keyArn })
      if (kms.down) throw new Error('kms_unavailable')
      return kms.policy
    },
  }
  return kms
}

// ---- Go ---------------------------------------------------------------------------
/** The to-go signature exactly as docs/mcp-enclave.md §4 writes it. */
export function contractSignature(secret, { direction, reader, method, target, timestamp, nonce, body }) {
  const canonical = ['wappie-mcp-hmac/v1', direction, reader, method, target, timestamp, nonce, createHash('sha256').update(body).digest('hex')].join('\n')
  return 'v1=' + createHmac('sha256', Buffer.from(secret, 'utf8')).update(canonical, 'utf8').digest('hex')
}

/** Headers Go would send to the reader (`to-reader`). */
export function goHeaders(secret, { method, target, body = Buffer.alloc(0), reader = 'enclave', now = Date.now(), nonce = randomBytes(16).toString('base64url') }) {
  const timestamp = String(Math.floor(now / 1000))
  return { 'x-wappie-reader': reader, 'x-wappie-timestamp': timestamp, 'x-wappie-nonce': nonce, 'x-wappie-signature': contractSignature(secret, { direction: 'to-reader', reader, method, target, timestamp, nonce, body }) }
}

/**
 * Go's /v1/mcp/enclave/* (HMAC checked against `secrets()`, the list Go
 * accepts) in front of the synthetic archive at `upstream`. `go.onAnswer()`,
 * when set, is called once each answer has gone, after whatever the call
 * changed here (world.mjs's `until` looks again then).
 *
 * Content connections: a connection row may carry `kind` and
 * `service_user_id` (the status route answers both) and `extra`, fields the
 * status answer carries as they are, the way a newer Go adds them; `reseal`
 * moves a live row to `reseal`, and `revokes` records every revoke with its
 * body. The archive side accepts every API key in `tokens` in place of the
 * fixture's own (`upstreamToken`), and answers `/v1/grants` for a key from
 * `grants` (token -> {user_id, grants}), which is how a test seals grants to
 * a key the enclave minted.
 *
 * Sending (docs/mcp-enclave.md §17.7): the draft, send, refusals and outbound
 * routes check the bearer (a connection row's `api_key`, when set, else any
 * key in `tokens`), answer 403 unless the row's `extra.send` is set (and
 * `extra.send_self` for an own-chat send), keep every draft, send and refusal
 * in `outbound`, and record each call's body in `sendCalls`. `sending`
 * shapes Go's side: `ineligible` (chat keys that never wrote), `ownChat`,
 * `draftsPending`, `outcome` ('sent', 'uncertain', 'offline', or 'drop',
 * which records the send and closes the socket unanswered) and `answer`
 * (route, body) -> {status, body} (or {status, raw}, a text body as a proxy
 * writes one) to replace an answer outright.
 *
 * AI (docs/mcp-enclave.md §18.11): the pick, derived, usage and alerts
 * routes check the bearer as the send routes do. `ai.picks` maps
 * `${connection}|${device}|${feature}` to Go's pick (else 404); `ai.derived`
 * holds the stored records of the whole workspace (a PUT inserts, or
 * replaces on a redo; `ai.storagePaused` answers 409); `ai.usage` and
 * `ai.alerts` record what the enclave posted, `ai.usageAnswers` maps a row to
 * its `GET …/ai/usage` answer, and `ai.calls` records every call.
 */
export function createEnclaveGo({ upstream, secrets, now = Date.now, upstreamToken, workspace }) {
  const go = { connections: new Map(), cimd: new Map(), state: new Map(), calls: [], refused: 0, activations: 0, down: false, nonces: new Set(),
    revokes: [], reseals: [], tokens: new Set(), grants: new Map(), archiveRequests: [], budgetHits: [],
    outbound: [], sendCalls: [], sending: { ineligible: new Set(), ownChat: '5511900000001@s.whatsapp.net', draftsPending: 20, outcome: 'sent', answer: null },
    ai: { picks: new Map(), derived: [], usage: [], alerts: [], usageAnswers: new Map(), storagePaused: false, calls: [] }, onAnswer: null }
  const json = (res, value, status = 200) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)) }
  const http = createHTTPServer(async (req, res) => {
    res.once('finish', () => go.onAnswer?.())
    const chunks = []
    for await (const chunk of req) chunks.push(chunk)
    const body = Buffer.concat(chunks)
    const url = new URL(req.url, 'http://go')
    if (!url.pathname.startsWith('/v1/mcp/enclave/')) {
      let authorization = req.headers.authorization
      const presented = authorization?.startsWith('Bearer ') ? authorization.slice(7) : null
      if (presented && go.tokens.has(presented)) {
        go.archiveRequests.push({ method: req.method, path: url.pathname, query: url.search, token: presented })
        if (url.pathname === '/v1/grants' && go.grants.has(presented)) return json(res, { tenant_id: workspace, ...go.grants.get(presented) })
        authorization = `Bearer ${upstreamToken}`
      }
      const forwarded = await fetch(upstream + req.url, { method: req.method, headers: authorization ? { authorization } : {}, body: req.method === 'GET' ? undefined : body })
      // Content-Length passes through: the reader refuses ciphertext without it (docs/mcp-enclave.md §16.5).
      const length = forwarded.headers.get('content-length')
      res.writeHead(forwarded.status, { 'content-type': forwarded.headers.get('content-type') ?? 'application/json', ...(length ? { 'content-length': length } : {}) })
      res.end(Buffer.from(await forwarded.arrayBuffer()))
      return
    }
    if (go.down) { res.destroy(); return }
    go.calls.push({ method: req.method, path: url.pathname, target: req.url })
    const h = name => req.headers[name] ?? ''
    const fields = { direction: 'to-go', reader: h('x-wappie-reader'), method: req.method, target: req.url, timestamp: h('x-wappie-timestamp'), nonce: h('x-wappie-nonce'), body }
    const given = Buffer.from(h('x-wappie-signature'))
    const ok = h('x-wappie-reader') === 'enclave' && Math.abs(now() / 1000 - Number(fields.timestamp)) <= 60 && !go.nonces.has(fields.nonce) &&
      secrets().some(secret => { const expected = Buffer.from(contractSignature(secret, fields)); return expected.length === given.length && timingSafeEqual(expected, given) })
    if (!ok) { go.refused++; return json(res, { code: 'unauthorized' }, 401) }
    go.nonces.add(fields.nonce)
    let match
    if ((match = /^\/v1\/mcp\/enclave\/connections\/([^/]+)$/.exec(url.pathname)) && req.method === 'GET') {
      const connection = go.connections.get(match[1])
      if (!connection) return json(res, { code: 'not_found' }, 404)
      return json(res, { status: connection.status, expires_at: connection.expires_at, ...(connection.kind ? { kind: connection.kind, service_user_id: connection.service_user_id ?? null } : {}), ...connection.extra })
    }
    if ((match = /^\/v1\/mcp\/enclave\/connections\/([^/]+)\/reseal$/.exec(url.pathname)) && req.method === 'POST') {
      const connection = go.connections.get(match[1])
      go.reseals.push(match[1])
      if (go.resealDown) { res.destroy(); return }
      if (!connection) return json(res, { code: 'not_found' }, 404)
      if (!['content', 'ai'].includes(connection.kind) || !['active', 'reseal'].includes(connection.status)) return json(res, { code: 'connection_state' }, 409)
      connection.status = 'reseal'
      res.writeHead(204); res.end(); return
    }
    if ((match = /^\/v1\/mcp\/enclave\/connections\/([^/]+)\/activate$/.exec(url.pathname)) && req.method === 'POST') {
      const connection = go.connections.get(match[1])
      if (!connection) return json(res, { code: 'not_found' }, 404)
      if (connection.status !== 'pending') return json(res, { code: 'connection_state' }, 409)
      connection.status = 'active'; go.activations++
      res.writeHead(204); res.end(); return
    }
    if ((match = /^\/v1\/mcp\/enclave\/connections\/([^/]+)\/revoke$/.exec(url.pathname)) && req.method === 'POST') {
      const connection = go.connections.get(match[1])
      if (body.length && (req.headers['content-type'] !== 'application/json' || JSON.stringify(JSON.parse(body.toString('utf8'))) !== '{"reason":"reuse_detected"}')) return json(res, { code: 'bad_request' }, 400)
      go.revokes.push({ id: match[1], body: body.toString('utf8') })
      if (connection) connection.status = 'revoked'
      res.writeHead(204); res.end(); return
    }
    // §19.19: a reading limit or a token's network, by code alone (strict body), on the caller's own rows.
    if ((match = /^\/v1\/mcp\/enclave\/connections\/([^/]+)\/budget-hit$/.exec(url.pathname)) && req.method === 'POST') {
      let parsed = null
      try { parsed = JSON.parse(body.toString('utf8')) } catch { /* refused below */ }
      if (!parsed || Object.keys(parsed).length !== 1 || typeof parsed.code !== 'string') return json(res, { code: 'bad_request' }, 400)
      if (!go.connections.has(match[1])) return json(res, { code: 'not_found' }, 404)
      go.budgetHits.push({ id: match[1], code: parsed.code })
      res.writeHead(204); res.end(); return
    }
    if ((match = /^\/v1\/mcp\/enclave\/connections\/([^/]+)\/(drafts|send|refusals|outbound)$/.exec(url.pathname))) return sendRoute(req, res, match[1], match[2], url, body)
    if ((match = /^\/v1\/mcp\/enclave\/connections\/([^/]+)\/(ai(?:\/.*)?)$/.exec(url.pathname))) return aiRoute(req, res, match[1], match[2], url, body)
    if (url.pathname === '/v1/mcp/enclave/cimd' && req.method === 'GET') {
      const entry = go.cimd.get(url.searchParams.get('url'))
      if (!entry) return json(res, { code: 'cimd_unavailable' }, 502)
      res.writeHead(200, { 'content-type': 'application/json' }); res.end(entry); return
    }
    if ((match = /^\/v1\/mcp\/enclave\/state\/(as-clients|as-connections|as-tokens|infra)$/.exec(url.pathname))) {
      const row = go.state.get(match[1])
      if (req.method === 'GET') {
        if (!row) return json(res, { code: 'not_found' }, 404)
        res.writeHead(200, { 'content-type': 'application/octet-stream', 'x-wappie-generation': String(row.generation) }); res.end(row.blob); return
      }
      if (req.method === 'PUT') {
        const expected = Number(url.searchParams.get('if_generation'))
        if (body.length > 12 * 1024 * 1024) return json(res, { code: 'body_too_large' }, 413)
        if ((row?.generation ?? 0) !== expected) return json(res, { code: 'generation_mismatch', generation: row?.generation ?? 0 }, 409)
        go.state.set(match[1], { generation: expected + 1, blob: body })
        return json(res, { generation: expected + 1 })
      }
    }
    json(res, { code: 'not_found' }, 404)
  })
  /** The send routes, as §17.7 orders them, over `go.outbound`. */
  async function sendRoute(req, res, id, route, url, body) {
    const connection = go.connections.get(id)
    const presented = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null
    let parsed = null
    if (body.length) { try { parsed = JSON.parse(body.toString('utf8')) } catch { return json(res, { code: 'bad_request' }, 400) } }
    go.sendCalls.push({ route, method: req.method, id, authorization: req.headers.authorization ?? null, body: parsed, query: url.search })
    if (!connection || !presented || (connection.api_key ? presented !== connection.api_key : !go.tokens.has(presented))) return json(res, { code: 'not_found' }, 404)
    const override = go.sending.answer?.(route, parsed)
    if (override) {
      res.writeHead(override.status, { 'content-type': override.raw === undefined ? 'application/json' : 'text/html' })
      res.end(override.raw ?? (override.body === undefined ? '' : JSON.stringify(override.body)))
      return
    }
    const stamp = () => new Date(now()).toISOString().replace('Z', '123Z')
    const refuse = (row, code, status, extra = {}) => { go.outbound.push({ ...row, id: randomUUID(), status: 'refused', code, created_at: stamp() }); return json(res, { code, message: code, ...extra }, status) }
    const extra = connection.extra ?? {}
    if (route === 'drafts' && req.method === 'POST') {
      const names = Object.keys(parsed ?? {})
      if (!parsed || names.some(name => !['id', 'device_id', 'chat_key', 'reply_to_uid', 'epoch', 'sealed'].includes(name)) || !/^[A-Za-z0-9_-]+$/.test(parsed.sealed ?? '') ||
        Buffer.from(parsed.sealed, 'base64url').length > 16_384 || !Number.isInteger(parsed.epoch)) return json(res, { code: 'bad_request' }, 400)
      const row = { connection: id, kind: 'draft', device_id: parsed.device_id, chat_key: parsed.chat_key, reply_to_uid: parsed.reply_to_uid ?? null, decided_at: null, edited: false, message_uid: null }
      if (connection.status !== 'active') return json(res, { code: 'connection_state' }, 409)
      if (!extra.send) return json(res, { code: 'send_not_allowed' }, 403)
      if (go.sending.ineligible.has(parsed.chat_key)) return refuse(row, 'chat_not_eligible', 422)
      if (parsed.chat_key.endsWith('@g.us') && !extra.send_groups) return refuse(row, 'group_not_allowed', 422)
      if (go.outbound.some(item => item.id === parsed.id)) return json(res, { code: 'draft_exists' }, 409)
      if (go.outbound.filter(item => item.connection === id && item.status === 'pending').length >= go.sending.draftsPending) return refuse(row, 'rate_limited', 429, { retry_at: '2026-10-02T09:30:15.123456Z' })
      const expires = new Date(now() + 86_400_000).toISOString().replace('Z', '456Z')
      go.outbound.push({ ...row, id: parsed.id, status: 'pending', code: null, created_at: stamp(), epoch: parsed.epoch, sealed: parsed.sealed, expires_at: expires })
      return json(res, { id: parsed.id, expires_at: expires }, 201)
    }
    if (route === 'send' && req.method === 'POST') {
      if (!parsed || parsed.kind !== 'self' || !/^[A-Za-z0-9_-]{22}$/.test(parsed.client_ref ?? '') || typeof parsed.text !== 'string') return json(res, { code: 'bad_request' }, 400)
      const row = { connection: id, kind: 'self', device_id: parsed.device_id, chat_key: go.sending.ownChat, reply_to_uid: null, edited: false, client_ref: parsed.client_ref }
      if (connection.status !== 'active') return json(res, { code: 'connection_state' }, 409)
      if (!extra.send || !extra.send_self) return json(res, { code: 'send_not_allowed' }, 403)
      const sent = { ...row, id: randomUUID(), status: 'sending', code: null, created_at: stamp(), decided_at: null, message_uid: null, text: parsed.text }
      go.outbound.push(sent)
      if (go.sending.outcome === 'drop') { res.destroy(); return }
      if (go.sending.outcome === 'offline') { Object.assign(sent, { status: 'refused', code: 'device_offline' }); return json(res, { code: 'device_offline' }, 409) }
      if (go.sending.outcome === 'uncertain') { sent.status = 'uncertain'; return json(res, { code: 'send_uncertain' }, 502) }
      Object.assign(sent, { status: 'sent', message_uid: randomUUID(), wa_id: `3EB0${randomBytes(8).toString('hex').toUpperCase()}`, decided_at: stamp() })
      return json(res, { id: sent.id, message_uid: sent.message_uid, wa_id: sent.wa_id, timestamp: sent.decided_at, duplicate: false })
    }
    if (route === 'refusals' && req.method === 'POST') {
      if (!extra.send) return json(res, { code: 'not_found' }, 404)
      if (!parsed || !['draft', 'self', 'send'].includes(parsed.kind) ||
        !['text_not_allowed', 'cross_chat_blocked', 'chat_not_allowed', 'recipient_mismatch', 'rate_limited', 'chat_not_eligible', 'group_not_allowed'].includes(parsed.code) ||
        (parsed.kind === 'self') !== (parsed.chat_key === undefined)) return json(res, { code: 'bad_request' }, 400)
      go.outbound.push({ connection: id, id: randomUUID(), kind: parsed.kind, status: 'refused', code: parsed.code, device_id: parsed.device_id, chat_key: parsed.chat_key ?? null,
        reply_to_uid: null, created_at: stamp(), decided_at: null, edited: false, message_uid: null })
      res.writeHead(204); res.end(); return
    }
    if (route === 'outbound' && req.method === 'GET') {
      const limit = Number(url.searchParams.get('limit') ?? 20), status = url.searchParams.get('status'), device = url.searchParams.get('device_id')
      const items = go.outbound.filter(item => item.connection === id && (!status || item.status === status) && (!device || item.device_id === device)).reverse().slice(0, limit)
        .map(({ id: itemID, kind, status: itemStatus, code, device_id, chat_key, reply_to_uid, created_at, decided_at, edited, message_uid }) =>
          ({ id: itemID, kind, status: itemStatus, code: code ?? null, device_id, chat_key: chat_key ?? null, reply_to_uid: reply_to_uid ?? null, created_at, decided_at: decided_at ?? null, edited, message_uid: message_uid ?? null }))
      return json(res, { items, next: null })
    }
    return json(res, { code: 'not_found' }, 404)
  }
  /** The AI routes (§18.11), over `go.ai`. */
  async function aiRoute(req, res, id, route, url, body) {
    const connection = go.connections.get(id)
    const presented = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null
    let parsed = null
    if (body.length) { try { parsed = JSON.parse(body.toString('utf8')) } catch { return json(res, { code: 'bad_request' }, 400) } }
    go.ai.calls.push({ route, method: req.method, id, query: url.search, body: parsed, authorization: req.headers.authorization ?? null })
    if (!connection || !presented || (connection.api_key ? presented !== connection.api_key : !go.tokens.has(presented))) return json(res, { code: 'not_found' }, 404)
    const q = name => url.searchParams.get(name)
    const listed = items => items.map(({ message_uid, feature, device_id, epoch, sealed, created_at }) => ({ message_uid, feature, device_id, epoch, sealed, created_at }))
    let match
    if (route === 'ai' && req.method === 'GET') {
      const pick = go.ai.picks.get(`${id}|${q('device_id')}|${q('feature')}`)
      return pick ? json(res, pick) : json(res, { code: 'ai_not_enabled' }, 404)
    }
    if (route === 'ai/derived' && req.method === 'GET') {
      if (q('uid')) return json(res, { items: listed(go.ai.derived.filter(item => item.device_id === q('device_id') && item.message_uid === q('uid'))) })
      const pairs = (q('tags') ?? '').split(',')
      if (!pairs.length || pairs.length > 25 || pairs.some(pair => !/^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/.test(pair))) return json(res, { code: 'bad_request' }, 400)
      return json(res, { items: listed(go.ai.derived.filter(item => item.feature === q('feature') && pairs.includes(`${item.device_id}.${item.dedupe_tag}`))) })
    }
    if ((match = /^ai\/derived\/([0-9a-f-]{36})\/(audio|video|image|document)$/.exec(route)) && req.method === 'PUT') {
      const names = Object.keys(parsed ?? {}).sort().join()
      if (names !== 'dedupe_tag,device_id,epoch,redo,sealed' || !/^[A-Za-z0-9_-]+$/.test(parsed.sealed) || !/^[A-Za-z0-9_-]{43}$/.test(parsed.dedupe_tag) || typeof parsed.redo !== 'boolean') return json(res, { code: 'bad_request' }, 400)
      if (go.ai.storagePaused) return json(res, { code: 'storage_paused' }, 409)
      const at = go.ai.derived.findIndex(item => item.message_uid === match[1] && item.feature === match[2])
      if (at >= 0 && !parsed.redo) return json(res, { code: 'derived_exists' }, 409)
      const row = { message_uid: match[1], feature: match[2], device_id: parsed.device_id, epoch: parsed.epoch, sealed: parsed.sealed, dedupe_tag: parsed.dedupe_tag, authorization_id: id, created_at: new Date(now()).toISOString() }
      if (at >= 0) go.ai.derived[at] = row; else go.ai.derived.push(row)
      res.writeHead(204); res.end(); return
    }
    if (route === 'ai/usage' && req.method === 'POST') { go.ai.usage.push({ id, body: parsed }); res.writeHead(204); res.end(); return }
    if (route === 'ai/usage' && req.method === 'GET') return json(res, go.ai.usageAnswers.get(id) ?? { month: q('month'), charged_tokens: 0, items_today: 0 })
    if (route === 'ai/alerts' && req.method === 'POST') { go.ai.alerts.push({ id, body: parsed }); res.writeHead(204); res.end(); return }
    return json(res, { code: 'not_found' }, 404)
  }
  go.listen = async () => { await new Promise(resolve => http.listen(0, '127.0.0.1', resolve)); go.url = `http://127.0.0.1:${http.address().port}`; return go }
  go.close = () => new Promise(resolve => { http.closeAllConnections?.(); http.close(resolve) })
  return go
}

// ---- A test CA and an ACME server ---------------------------------------------------
const name = cn => seq(set(seq(oid('2.5.4.3'), utf8(cn))))
function time(ms) { return tlv(0x17, Buffer.from(new Date(ms).toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z', 'ascii')) }

/** A CA key and self-signed certificate that the test clients trust. */
export function testCA() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const der = selfSigned({ names: ['Wappie Test CA'], privateKey, notBefore: Date.now() - 3_600_000, notAfter: Date.now() + 365 * 86_400_000, ca: true })
  return { privateKey, der, pem: pem('CERTIFICATE', der) }
}

/** A leaf for `spkiDer` naming `names`, issued by `ca`. */
export function issueLeaf(ca, spkiDer, names, { notAfter = Date.now() + 90 * 86_400_000 } = {}) {
  const alg = seq(oid('1.2.840.10045.4.3.2'))
  const san = seq(oid('2.5.29.17'), octets(seq(...names.map(value => tlv(0x82, Buffer.from(value, 'ascii'))))))
  const tbs = seq(explicit(0, integer([2])), integer(randomBytes(8)), alg, name('Wappie Test CA'), seq(time(Date.now() - 60_000), time(notAfter)), name(names[0]), spkiDer, explicit(3, seq(san)))
  return seq(tbs, alg, bits(signData('sha256', tbs, ca.privateKey)))
}

/** The SubjectPublicKeyInfo of a DER CSR (after checking its self-signature). */
export function csrSpki(der) {
  const { result } = asn1js.fromBER(new Uint8Array(der))
  const info = result.valueBlock.value[0]
  const spki = Buffer.from(info.valueBlock.value[2].toBER(false))
  const signature = Buffer.from(result.valueBlock.value[2].valueBlock.valueHexView)
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' })
  if (!verifyData('sha256', Buffer.from(info.toBER(false)), key, signature)) throw new Error('csr signature')
  return spki
}

const b64u = value => Buffer.from(value).toString('base64url')

/**
 * An ACME server (RFC 8555 subset) that checks every JWS signature and nonce
 * and validates tls-alpn-01 by connecting to `challengePort()` with ALPN
 * acme-tls/1 and SNI, then checking the challenge certificate's names and
 * acmeIdentifier extension. `fail.validation` makes validation fail.
 */
export function createFakeAcme({ ca, challengePort, fail = {} }) {
  const acme = { accounts: new Map(), orders: new Map(), authzs: new Map(), certs: new Map(), nonces: new Set(), validations: 0, issued: 0, fail }
  let base
  const nonce = () => { const value = b64u(randomBytes(12)); acme.nonces.add(value); return value }
  const problem = (res, status, type) => { res.writeHead(status, { 'content-type': 'application/problem+json', 'replay-nonce': nonce() }); res.end(JSON.stringify({ type: `urn:ietf:params:acme:error:${type}` })) }
  const reply = (res, status, body, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json', 'replay-nonce': nonce(), ...headers }); res.end(typeof body === 'string' ? body : JSON.stringify(body)) }
  async function validate(authz, keyAuthorization) {
    acme.validations++
    const domain = authz.identifier.value
    return new Promise(resolve => {
      const socket = tlsConnect({ host: '127.0.0.1', port: challengePort(), servername: domain, ALPNProtocols: ['acme-tls/1'], rejectUnauthorized: false }, () => {
        const cert = socket.getPeerX509Certificate()
        const der = cert?.raw
        socket.destroy()
        const digest = createHash('sha256').update(keyAuthorization).digest()
        const extension = Buffer.from('06082b0601050507011f', 'hex') // id-pe-acmeIdentifier
        const good = socket.alpnProtocol === 'acme-tls/1' && cert && cert.subjectAltName === `DNS:${domain}` && der.includes(extension) && der.includes(Buffer.concat([Buffer.from([0x04, 0x20]), digest]))
        resolve(good && !acme.fail.validation)
      })
      socket.on('error', () => resolve(false))
    })
  }
  const http = createHTTPServer(async (req, res) => {
    const chunks = []
    for await (const chunk of req) chunks.push(chunk)
    const url = new URL(req.url, base)
    if (url.pathname === '/directory') return reply(res, 200, { newNonce: `${base}/nonce`, newAccount: `${base}/account`, newOrder: `${base}/order`, meta: { termsOfService: `${base}/tos` } })
    if (url.pathname === '/nonce') { res.writeHead(200, { 'replay-nonce': nonce(), 'cache-control': 'no-store' }); res.end(); return }
    if (req.method !== 'POST' || req.headers['content-type'] !== 'application/jose+json') return problem(res, 400, 'malformed')
    const jws = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    const header = JSON.parse(Buffer.from(jws.protected, 'base64url').toString('utf8'))
    if (header.alg !== 'ES256' || header.url !== `${base}${url.pathname}` || !acme.nonces.delete(header.nonce)) return problem(res, 400, 'badNonce')
    let jwk
    if (header.jwk) jwk = header.jwk
    else { jwk = acme.accounts.get(header.kid)?.jwk; if (!jwk) return problem(res, 400, 'accountDoesNotExist') }
    const key = createPublicKey({ key: jwk, format: 'jwk' })
    if (!verifyData('sha256', Buffer.from(`${jws.protected}.${jws.payload}`), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(jws.signature, 'base64url'))) return problem(res, 400, 'malformed')
    const payload = jws.payload ? JSON.parse(Buffer.from(jws.payload, 'base64url').toString('utf8')) : undefined
    const thumb = b64u(createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest())
    if (url.pathname === '/account') {
      if (!payload?.termsOfServiceAgreed || payload.contact) return problem(res, 400, 'malformed')
      const existing = [...acme.accounts.entries()].find(([, account]) => account.thumb === thumb)
      if (existing) return reply(res, 200, { status: 'valid' }, { location: existing[0] })
      const uri = `${base}/acme/acct/${1000 + acme.accounts.size}`
      acme.accounts.set(uri, { jwk, thumb })
      return reply(res, 201, { status: 'valid' }, { location: uri })
    }
    if (url.pathname === '/order') {
      const id = randomUUID()
      const authorizations = payload.identifiers.map(identifier => {
        const authzId = randomUUID()
        acme.authzs.set(authzId, { status: 'pending', identifier, token: b64u(randomBytes(16)), thumb })
        return `${base}/authz/${authzId}`
      })
      acme.orders.set(id, { status: 'pending', identifiers: payload.identifiers, authorizations, finalize: `${base}/finalize/${id}`, thumb })
      return reply(res, 201, acme.orders.get(id), { location: `${base}/orders/${id}` })
    }
    let match
    if ((match = /^\/authz\/(.+)$/.exec(url.pathname))) {
      const authz = acme.authzs.get(match[1])
      return reply(res, 200, { status: authz.status, identifier: authz.identifier, challenges: [{ type: 'http-01', url: `${base}/nope`, token: authz.token }, { type: 'tls-alpn-01', url: `${base}/challenge/${match[1]}`, token: authz.token, status: authz.status }] })
    }
    if ((match = /^\/challenge\/(.+)$/.exec(url.pathname))) {
      const authz = acme.authzs.get(match[1])
      authz.status = 'processing'
      authz.status = (await validate(authz, `${authz.token}.${authz.thumb}`)) ? 'valid' : 'invalid'
      for (const order of acme.orders.values()) {
        const states = order.authorizations.map(item => acme.authzs.get(item.split('/').pop()).status)
        if (states.includes('invalid')) order.status = 'invalid'
        else if (states.every(item => item === 'valid') && order.status === 'pending') order.status = 'ready'
      }
      return reply(res, 200, { type: 'tls-alpn-01', status: authz.status })
    }
    if ((match = /^\/orders\/(.+)$/.exec(url.pathname))) return reply(res, 200, acme.orders.get(match[1]))
    if ((match = /^\/finalize\/(.+)$/.exec(url.pathname))) {
      const order = acme.orders.get(match[1])
      if (order.status !== 'ready') return problem(res, 403, 'orderNotReady')
      const spki = csrSpki(Buffer.from(payload.csr, 'base64url'))
      const leaf = issueLeaf(ca, spki, order.identifiers.map(item => item.value))
      acme.certs.set(match[1], pem('CERTIFICATE', leaf) + ca.pem)
      acme.issued++
      order.status = 'valid'; order.certificate = `${base}/cert/${match[1]}`
      return reply(res, 200, order)
    }
    if ((match = /^\/cert\/(.+)$/.exec(url.pathname))) {
      res.writeHead(200, { 'content-type': 'application/pem-certificate-chain', 'replay-nonce': nonce() }); res.end(acme.certs.get(match[1])); return
    }
    problem(res, 404, 'malformed')
  })
  acme.listen = async () => { await new Promise(resolve => http.listen(0, '127.0.0.1', resolve)); base = `http://127.0.0.1:${http.address().port}`; acme.url = base; acme.directory = `${base}/directory`; return acme }
  acme.close = () => new Promise(resolve => { http.closeAllConnections?.(); http.close(resolve) })
  return acme
}


// ---- A client that speaks PROXY v2 then TLS, like haproxy in front of a client -----
/**
 * One HTTPS request through a PROXY v2 listener. `proxy` is the header to
 * send first (null sends none); `coalesce` puts it in the same write as the
 * TLS ClientHello, which is how haproxy usually sends it.
 */
export function proxiedRequest({ port, proxy, ca, servername = 'mcp.wappie.thehappie.co', method = 'GET', path = '/', headers = {}, body, coalesce = false, alpn = ['http/1.1'] }) {
  return new Promise((resolve, reject) => {
    const raw = netConnect(port, '127.0.0.1', () => {
      let transport = raw
      if (proxy && !coalesce) raw.write(proxy)
      if (proxy && coalesce) {
        let first = true
        transport = new Duplex({
          read() { raw.resume() },
          write(chunk, encoding, callback) { if (first) { first = false; chunk = Buffer.concat([proxy, chunk]) } raw.write(chunk, callback) },
          final(callback) { raw.end(); callback() },
          destroy(error, callback) { raw.destroy(); callback(error) },
        })
        raw.on('data', chunk => { if (!transport.push(chunk)) raw.pause() })
        raw.on('end', () => transport.push(null))
        raw.on('close', () => transport.destroy())
      }
      const tls = tlsConnect({ socket: transport, servername, ca, ALPNProtocols: alpn }, () => {
        const req = httpRequest({ createConnection: () => tls, method, path, headers: { host: 'mcp.wappie.thehappie.co', connection: 'close', ...headers } }, res => {
          const chunks = []
          res.on('data', chunk => chunks.push(chunk))
          res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), bytes: Buffer.concat(chunks), peer: tls.getPeerX509Certificate(), alpn: tls.alpnProtocol }))
        })
        req.on('error', reject)
        req.end(body)
      })
      tls.on('error', reject)
    })
    raw.on('error', reject)
  })
}

/** Resolves true when the server closes a raw connection after `bytes` without answering. */
export function closedAfter(port, bytes, { waitMs = 2000 } = {}) {
  return new Promise(resolve => {
    const socket = netConnect(port, '127.0.0.1', () => { if (bytes.length) socket.write(bytes) })
    let answered = false
    socket.on('data', () => { answered = true })
    socket.on('close', () => resolve(!answered))
    socket.on('error', () => {})
    setTimeout(() => { socket.destroy(); resolve(false) }, waitMs).unref()
  })
}
