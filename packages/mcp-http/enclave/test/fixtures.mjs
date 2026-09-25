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
import { chmod, mkdtemp, writeFile } from 'node:fs/promises'
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
 * `mode: 'fail'` exits 1 (an NSM error).
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
 * accepts) in front of the synthetic archive at `upstream`.
 */
export function createEnclaveGo({ upstream, secrets, now = Date.now }) {
  const go = { connections: new Map(), cimd: new Map(), state: new Map(), calls: [], refused: 0, activations: 0, down: false, nonces: new Set() }
  const json = (res, value, status = 200) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)) }
  const http = createHTTPServer(async (req, res) => {
    const chunks = []
    for await (const chunk of req) chunks.push(chunk)
    const body = Buffer.concat(chunks)
    const url = new URL(req.url, 'http://go')
    if (!url.pathname.startsWith('/v1/mcp/enclave/')) {
      const forwarded = await fetch(upstream + req.url, { method: req.method, headers: req.headers.authorization ? { authorization: req.headers.authorization } : {}, body: req.method === 'GET' ? undefined : body })
      res.writeHead(forwarded.status, { 'content-type': forwarded.headers.get('content-type') ?? 'application/json' })
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
      return connection ? json(res, { status: connection.status, expires_at: connection.expires_at }) : json(res, { code: 'not_found' }, 404)
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
      if (connection) connection.status = 'revoked'
      res.writeHead(204); res.end(); return
    }
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
          res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), peer: tls.getPeerX509Certificate(), alpn: tls.alpnProtocol }))
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
