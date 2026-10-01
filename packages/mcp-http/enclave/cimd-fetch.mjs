// The enclave's own fetch of a client document (docs/mcp-enclave.md §19.9,
// D15): Go and the parent can refuse or delay it, never forge it.
//
// One request per document: `CONNECT <host>:443` to the parent's egress proxy
// on 127.0.0.8:3128 (entrypoint.sh bridges it to vsock 8007, where the proxy
// checks the host, resolves it once and dials only public addresses), then TLS
// 1.2 or later with SNI the client's host, verified here against Node's
// bundled root store (part of the measured image) with the hostname checked,
// then one HTTP/1.1 `GET` with `Accept` and `User-Agent` and nothing else a
// server could tie to a person: no cookies, no credentials. Only a 200 with an
// `application/json` body of at most 8 KiB is a document; a redirect is never
// followed. The headers must come within 3 s of the request, the body within
// 2 s of the headers, and everything within 5 s.
//
// The answer is `{ok: true, body, cacheControl}` or `{ok: false, code,
// network}`, the code the `cimd_fetch` event carries (never the host):
// `proxy_refused`, `tls_failed`, `status`, `redirect`, `content_type`,
// `too_large` or `timeout`. `network` marks the failures that say nothing of
// the document, for which cimd.mjs remembers the whole registrable domain.
import { request as httpRequest } from 'node:http'
import { connect } from 'node:net'
import { connect as tlsConnect, rootCertificates } from 'node:tls'
import { CIMD_MAX_BYTES } from '../cimd.mjs'
import { CIMD_EGRESS } from './constants.mjs'

export const CIMD_HEADERS_MS = 3_000
export const CIMD_BODY_MS = 2_000
export const CIMD_TOTAL_MS = 5_000
export const CIMD_USER_AGENT = 'wappie-cimd/1'
/** The proxy's answer to CONNECT: a status line and headers, nothing more. */
const PROXY_HEAD_MAX = 4096
/** The response headers of a document server. */
const HEADERS_MAX = 8192

class FetchFailure extends Error {
  constructor(code, network = false) { super(code); this.code = code; this.network = network }
}

/** `CONNECT host:443` on a fresh connection to the proxy; resolves to the socket once it answered 200. */
function tunnel({ address, port, host, signal }) {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: address, port })
    let head = Buffer.alloc(0), settled = false
    const fail = code => { if (settled) return; settled = true; socket.destroy(); reject(new FetchFailure(code, true)) }
    const onAbort = () => fail('timeout')
    signal.addEventListener('abort', onAbort, { once: true })
    socket.once('error', () => fail('proxy_refused'))
    socket.once('close', () => fail('proxy_refused'))
    socket.once('connect', () => socket.write(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}:443\r\n\r\n`))
    socket.on('data', function onData(chunk) {
      head = Buffer.concat([head, chunk])
      const end = head.indexOf('\r\n\r\n')
      if (end < 0) { if (head.length > PROXY_HEAD_MAX) fail('proxy_refused'); return }
      socket.off('data', onData)
      // A proxy that says anything past its head, or anything but 200, is not a tunnel.
      if (!/^HTTP\/1\.[01] 200[ \r]/.test(head.subarray(0, end + 2).toString('latin1')) || head.length !== end + 4) return fail('proxy_refused')
      settled = true
      signal.removeEventListener('abort', onAbort)
      socket.removeAllListeners('close')
      socket.removeAllListeners('error')
      resolve(socket)
    })
  })
}

/** TLS over the tunnel: SNI `host`, the roots given, the hostname checked by Node. */
function secure({ socket, host, ca, signal }) {
  return new Promise((resolve, reject) => {
    let settled = false
    const tls = tlsConnect({ socket, servername: host, host, ca, minVersion: 'TLSv1.2', rejectUnauthorized: true, ALPNProtocols: ['http/1.1'] })
    const fail = () => { if (settled) return; settled = true; tls.destroy(); socket.destroy(); reject(new FetchFailure(signal.aborted ? 'timeout' : 'tls_failed', true)) }
    signal.addEventListener('abort', fail, { once: true })
    tls.once('error', fail)
    tls.once('secureConnect', () => {
      if (settled) return
      settled = true
      signal.removeEventListener('abort', fail)
      tls.removeAllListeners('error')
      resolve(tls)
    })
  })
}

/** The one GET over an open TLS socket; resolves to `{status, contentType, cacheControl, body}`. */
function get({ tls, host, path, signal, headersMs, bodyMs }) {
  return new Promise((resolve, reject) => {
    let settled = false, timer = null
    const done = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal.removeEventListener('abort', onAbort)
      if (error) { tls.destroy(); reject(error) } else resolve(value)
    }
    const onAbort = () => done(new FetchFailure('timeout', true))
    signal.addEventListener('abort', onAbort, { once: true })
    const req = httpRequest({
      host, path, method: 'GET', agent: false, createConnection: () => tls, maxHeaderSize: HEADERS_MAX, insecureHTTPParser: false,
      headers: { Accept: 'application/json', 'User-Agent': CIMD_USER_AGENT },
    })
    timer = setTimeout(() => done(new FetchFailure('timeout', true)), headersMs)
    req.once('error', error => done(error instanceof FetchFailure ? error : new FetchFailure(error?.code === 'HPE_HEADER_OVERFLOW' ? 'too_large' : 'status')))
    req.once('response', response => {
      clearTimeout(timer)
      const status = response.statusCode
      if (status >= 300 && status < 400) { response.destroy(); return done(new FetchFailure('redirect')) }
      if (status !== 200) { response.destroy(); return done(new FetchFailure('status')) }
      const type = String(response.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase()
      const encoding = String(response.headers['content-encoding'] ?? 'identity').trim().toLowerCase()
      if (type !== 'application/json' || encoding !== 'identity') { response.destroy(); return done(new FetchFailure('content_type')) }
      const declared = Number(response.headers['content-length'])
      if (Number.isFinite(declared) && declared > CIMD_MAX_BYTES) { response.destroy(); return done(new FetchFailure('too_large')) }
      timer = setTimeout(() => { response.destroy(); done(new FetchFailure('timeout', true)) }, bodyMs)
      const chunks = []
      let size = 0
      response.on('data', chunk => {
        size += chunk.length
        if (size > CIMD_MAX_BYTES) { response.destroy(); return done(new FetchFailure('too_large')) }
        chunks.push(chunk)
      })
      response.once('error', () => done(new FetchFailure('status')))
      response.once('aborted', () => done(new FetchFailure('status')))
      response.once('end', () => done(null, { body: Buffer.concat(chunks, size), cacheControl: typeof response.headers['cache-control'] === 'string' ? response.headers['cache-control'] : undefined }))
    })
    req.end()
  })
}

/**
 * The fetcher cimd.mjs is given (`policy.fetcher`). `address` and `port` are
 * the proxy's (CIMD_EGRESS), `ca` the roots (tls.rootCertificates); tests
 * point them at a fake proxy and a test root, and may shorten the timeouts.
 */
export function createCIMDFetcher({ address = CIMD_EGRESS.address, port = CIMD_EGRESS.port, ca = rootCertificates,
  headersMs = CIMD_HEADERS_MS, bodyMs = CIMD_BODY_MS, totalMs = CIMD_TOTAL_MS } = {}) {
  return {
    async fetch({ host, path }) {
      const signal = AbortSignal.timeout(totalMs)
      let tls = null
      try {
        const socket = await tunnel({ address, port, host, signal })
        tls = await secure({ socket, host, ca, signal })
        const { body, cacheControl } = await get({ tls, host, path, signal, headersMs, bodyMs })
        return { ok: true, body, cacheControl }
      } catch (error) {
        if (error instanceof FetchFailure) return { ok: false, code: error.code, network: error.network }
        return { ok: false, code: 'proxy_refused', network: true }
      } finally { tls?.destroy() }
    },
  }
}
