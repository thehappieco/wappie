// The enclave's own fetch of a client document (docs/mcp-enclave.md §19.9),
// through a fake CONNECT proxy standing in for the parent's egress proxy and
// a document server whose certificate a test root signs: the TLS is verified
// here, a wrong certificate fails, only a 200 JSON body of at most 8 KiB is a
// document, redirects are never followed, and each phase has its deadline.
// Nothing here leaves the host: the proxy dials a loopback server whatever
// host the CONNECT names.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer as createHttpsServer } from 'node:https'
import { connect, createServer as createNetServer } from 'node:net'
import { CIMD_MAX_BYTES } from '../../cimd.mjs'
import { CIMD_USER_AGENT, createCIMDFetcher } from '../cimd-fetch.mjs'
import { CIMD_EGRESS } from '../constants.mjs'
import { issueLeaf, testCA } from './fixtures.mjs'

const HOST = 'agent.example.com'
const pem = (label, der) => `-----BEGIN ${label}-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`

/** A TLS document server for `names`, its certificate issued by `ca`; `handler(req, res)` answers. */
async function documentServer(t, ca, names, handler) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const cert = pem('CERTIFICATE', issueLeaf(ca, publicKey.export({ type: 'spki', format: 'der' }), names))
  const requests = []
  const server = createHttpsServer({ key: privateKey.export({ type: 'pkcs8', format: 'pem' }), cert }, (req, res) => { requests.push({ method: req.method, url: req.url, headers: req.headers }); handler(req, res) })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve) }))
  return { port: server.address().port, requests }
}

/**
 * The parent's proxy as the enclave sees it: one CONNECT, then `200
 * Connection established` and the bytes of `target`, or `refuse` (a 403 with
 * the proxy's code). It records each request head.
 */
async function connectProxy(t, { target, refuse = null }) {
  const heads = [], sockets = new Set()
  const server = createNetServer(socket => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
    let head = Buffer.alloc(0)
    socket.on('error', () => {})
    socket.on('data', function onData(chunk) {
      head = Buffer.concat([head, chunk])
      const end = head.indexOf('\r\n\r\n')
      if (end < 0) return
      socket.off('data', onData)
      heads.push(head.subarray(0, end).toString('latin1'))
      if (refuse) { socket.end(`HTTP/1.1 403 Forbidden\r\nX-Wappie-Egress: ${refuse}\r\nContent-Length: 0\r\n\r\n`); return }
      const upstream = connect({ host: '127.0.0.1', port: target() }, () => {
        sockets.add(upstream)
        socket.write('HTTP/1.1 200 Connection established\r\n\r\n')
        const rest = head.subarray(end + 4)
        if (rest.length) upstream.write(rest)
        socket.pipe(upstream).pipe(socket)
      })
      upstream.on('error', () => socket.destroy())
    })
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise(resolve => { for (const socket of sockets) socket.destroy(); server.close(resolve) }))
  return { port: server.address().port, heads }
}

/** A fetcher through a fresh proxy to a document server answering with `handler`, under `ca`'s root (or `roots`). */
async function setup(t, handler, { names = [HOST], roots, refuse, timeouts = {} } = {}) {
  const ca = testCA()
  const documents = await documentServer(t, ca, names, handler)
  const proxy = await connectProxy(t, { target: () => documents.port, refuse })
  const fetcher = createCIMDFetcher({ address: '127.0.0.1', port: proxy.port, ca: roots ?? [ca.pem], ...timeouts })
  return { fetcher, documents, proxy }
}
const json = (res, value, headers = {}) => { res.writeHead(200, { 'content-type': 'application/json', ...headers }); res.end(JSON.stringify(value)) }
const fetchDoc = fetcher => fetcher.fetch({ host: HOST, path: '/oauth/client.json' })

test('the fetcher\'s address is the parent proxy\'s bridge (entrypoint.sh, measured): 127.0.0.8:3128 to vsock 8007, and no /etc/hosts line', () => {
  assert.deepEqual(CIMD_EGRESS, { address: '127.0.0.8', port: 3128, vsock: 8007 })
  const script = readFileSync(new URL('../../../../deploy/enclave/entrypoint.sh', import.meta.url), 'utf8')
  assert.ok(script.includes(`bridge TCP-LISTEN:${CIMD_EGRESS.port},bind=${CIMD_EGRESS.address},reuseaddr,fork VSOCK-CONNECT:3:${CIMD_EGRESS.vsock}`))
  assert.equal(script.includes(`'${CIMD_EGRESS.address} `), false, 'the host is named only in CONNECT and in the SNI')
  for (const reserved of [8003, 8004, 8005, 8006]) assert.equal(script.split('\n').filter(line => line.includes(`VSOCK-CONNECT:3:${reserved}`)).length, reserved === 8003 ? 0 : 1)
})

test('a document: CONNECT host:443 to the proxy, TLS verified against the roots with SNI and hostname, one GET with Accept and User-Agent, and its Cache-Control', async t => {
  const document = { client_id: `https://${HOST}/oauth/client.json`, redirect_uris: [`https://${HOST}/cb`] }
  const { fetcher, documents, proxy } = await setup(t, (req, res) => json(res, document, { 'cache-control': 'max-age=600' }))
  const answer = await fetchDoc(fetcher)
  assert.equal(answer.ok, true, JSON.stringify(answer))
  assert.deepEqual(JSON.parse(answer.body.toString('utf8')), document)
  assert.equal(answer.cacheControl, 'max-age=600')
  assert.deepEqual(proxy.heads, [`CONNECT ${HOST}:443 HTTP/1.1\r\nHost: ${HOST}:443`])
  assert.equal(documents.requests.length, 1)
  const [request] = documents.requests
  assert.deepEqual([request.method, request.url], ['GET', '/oauth/client.json'])
  assert.deepEqual(request.headers, { host: HOST, accept: 'application/json', 'user-agent': CIMD_USER_AGENT, connection: 'close' }, 'no cookie, no credential, nothing else')
  // A media type with parameters is still JSON.
  const charset = await setup(t, (req, res) => json(res, document, { 'content-type': 'application/json; charset=utf-8' }))
  assert.equal((await fetchDoc(charset.fetcher)).ok, true)
})

test('TLS: a certificate for another name, or from a root the image does not hold, is tls_failed and nothing is asked', async t => {
  const other = await setup(t, (req, res) => json(res, {}), { names: ['other.example.com'] })
  assert.deepEqual(await fetchDoc(other.fetcher), { ok: false, code: 'tls_failed', network: true })
  assert.equal(other.documents.requests.length, 0)
  const stranger = await setup(t, (req, res) => json(res, {}), { roots: [testCA().pem] })
  assert.deepEqual(await fetchDoc(stranger.fetcher), { ok: false, code: 'tls_failed', network: true })
  assert.equal(stranger.documents.requests.length, 0)
})

test('the proxy refuses (a private address, a refused host, its budgets) or is not there: proxy_refused, a network failure', async t => {
  const refused = await setup(t, (req, res) => json(res, {}), { refuse: 'private_address' })
  assert.deepEqual(await fetchDoc(refused.fetcher), { ok: false, code: 'proxy_refused', network: true })
  assert.equal(refused.documents.requests.length, 0)
  const port = await new Promise(resolve => { const server = createNetServer(); server.listen(0, '127.0.0.1', () => { const { port: free } = server.address(); server.close(() => resolve(free)) }) })
  assert.deepEqual(await createCIMDFetcher({ address: '127.0.0.1', port, ca: [testCA().pem] }).fetch({ host: HOST, path: '/x' }), { ok: false, code: 'proxy_refused', network: true })
})

test('only a 200 JSON body of at most 8 KiB, identity-encoded, is a document; a redirect is never followed', async t => {
  const cases = [
    ['redirect', (req, res) => { res.writeHead(302, { location: `https://${HOST}/elsewhere.json` }); res.end() }],
    ['redirect', (req, res) => { res.writeHead(308, { location: 'https://127.0.0.1/' }); res.end() }],
    ['status', (req, res) => { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}') }],
    ['status', (req, res) => { res.writeHead(204); res.end() }],
    ['content_type', (req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('{}') }],
    ['content_type', (req, res) => { res.writeHead(200, { 'content-type': 'application/jsonx' }); res.end('{}') }],
    ['content_type', (req, res) => { res.writeHead(200); res.end('{}') }],
    ['content_type', (req, res) => { res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' }); res.end('{}') }],
    ['too_large', (req, res) => { res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(CIMD_MAX_BYTES + 1) }); res.end('x'.repeat(CIMD_MAX_BYTES + 1)) }],
    ['too_large', (req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.write('x'.repeat(CIMD_MAX_BYTES)); res.end('y') }],
  ]
  for (const [code, handler] of cases) {
    const { fetcher, documents } = await setup(t, handler)
    const answer = await fetchDoc(fetcher)
    assert.equal(answer.ok, false, code)
    assert.equal(answer.code, code)
    assert.equal(documents.requests.length, 1, 'one request, never a second one')
  }
  const exact = await setup(t, (req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('x'.repeat(CIMD_MAX_BYTES)) })
  assert.equal((await fetchDoc(exact.fetcher)).body.length, CIMD_MAX_BYTES, 'exactly 8 KiB is a body')
})

test('deadlines: headers within their time, the body within its own after them, and everything within the total: each overrun is timeout', async t => {
  const timeouts = { headersMs: 300, bodyMs: 300, totalMs: 900 }
  const slowHeaders = await setup(t, (req, res) => { setTimeout(() => json(res, {}), 600).unref() }, { timeouts })
  assert.deepEqual(await fetchDoc(slowHeaders.fetcher), { ok: false, code: 'timeout', network: true })
  const trickle = await setup(t, (req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    let sent = 0
    const timer = setInterval(() => { if (res.destroyed || ++sent > 10) { clearInterval(timer); res.end() } else res.write(' ') }, 100)
    timer.unref()
  }, { timeouts })
  assert.deepEqual(await fetchDoc(trickle.fetcher), { ok: false, code: 'timeout', network: true })
  const total = await setup(t, (req, res) => {
    setTimeout(() => { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{'); setTimeout(() => res.end('}'), 250).unref() }, 250).unref()
  }, { timeouts: { headersMs: 300, bodyMs: 300, totalMs: 400 } })
  const begun = performance.now()
  assert.deepEqual(await fetchDoc(total.fetcher), { ok: false, code: 'timeout', network: true })
  assert.ok(performance.now() - begun < 700, 'the total deadline ends it, whatever the phases allow')
})
