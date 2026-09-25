// A minimal ACME client (RFC 8555) with TLS-ALPN-01 (RFC 8737) only, and the
// challenge listener that answers it. Written here rather than taken from a
// library because the image is measured: this is the whole flow, with
// node:crypto for the JWS and x509.mjs for the two DER structures.
//
// Why TLS-ALPN-01 and why CAA matters more than the method: the parent owns
// the address and port 443 and could answer any challenge, so what stops it
// from getting a certificate for mcp. is the CAA record naming this enclave's
// ACME account (whose key only ever exists sealed under the reader KMS key).
// The listener on 5445 only speaks ALPN acme-tls/1; the parent's haproxy routes
// by ALPN, so ordinary clients never reach it.
import { createHash, createPrivateKey, generateKeyPairSync, sign as signData } from 'node:crypto'
import { createSecureContext, createServer as createTLSServer } from 'node:tls'
import { alpnChallengeCertificate, pem } from './x509.mjs'

export const ALPN = 'acme-tls/1'
const MAX_RESPONSE = 64 * 1024
const b64u = value => Buffer.from(value).toString('base64url')

export class AcmeError extends Error {
  constructor(code, status = 0) { super(code); this.name = 'AcmeError'; this.code = code; this.status = status }
}

/** `urn:ietf:params:acme:error:rateLimited` -> `acme_rate_limited`. */
function problemCode(problem) {
  const type = typeof problem?.type === 'string' ? problem.type : ''
  const name = /^urn:ietf:params:acme:error:([A-Za-z]{1,40})$/.exec(type)?.[1]
  return name ? `acme_${name.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase()}` : 'acme_failed'
}

/** RFC 7638 thumbprint of an EC public JWK. */
export function thumbprint(jwk) {
  return b64u(createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest())
}

/** A new ACME account key (EC P-256) as the private JWK kept in `infra`. */
export function newAccountKey() {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' })
}

/** The numeric id Let's Encrypt puts at the end of an account URI (the CAA accounturi), or null. */
export const accountId = uri => { const match = /\/acct\/([0-9]{1,20})$/.exec(uri ?? ''); return match ? Number(match[1]) : null }

/**
 * Challenge certificates by domain, and the TLS listener that serves them.
 * Only a client that offers acme-tls/1 and names a domain with a pending
 * challenge completes a handshake; it then gets the connection closed, as
 * RFC 8737 §3 asks.
 */
export function createChallenges() {
  const contexts = new Map()
  return {
    set(domain, keyAuthorization) {
      const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
      const certificate = alpnChallengeCertificate({ domain, keyAuthorization, privateKey })
      contexts.set(domain, createSecureContext({ key: privateKey.export({ type: 'pkcs8', format: 'pem' }), cert: pem('CERTIFICATE', certificate), minVersion: 'TLSv1.2' }))
    },
    delete(domain) { contexts.delete(domain) },
    size: () => contexts.size,
    server() {
      const server = createTLSServer({
        SNICallback: (servername, callback) => {
          const context = contexts.get(String(servername).toLowerCase())
          callback(context ? null : new Error('no challenge'), context)
        },
        ALPNCallback: ({ protocols }) => (protocols.includes(ALPN) ? ALPN : undefined),
      }, socket => socket.end())
      server.on('tlsClientError', () => {})
      return server
    },
  }
}

/**
 * `directory` is the ACME directory URL; `accountKey` the private JWK;
 * `accountUri` the account URL once known. `fetch` and `wait` are injectable
 * for tests. Nothing here logs: callers log codes.
 */
export function createAcmeClient({ directory, accountKey, accountUri = null, challenges, fetch = globalThis.fetch, wait = ms => new Promise(resolve => setTimeout(resolve, ms)), pollMs = 2000, maxPolls = 60 }) {
  const key = createPrivateKey({ key: accountKey, format: 'jwk' })
  const publicJwk = { crv: accountKey.crv, kty: accountKey.kty, x: accountKey.x, y: accountKey.y }
  const keyThumbprint = thumbprint(publicJwk)
  let urls = null, nonce = null, account = accountUri

  async function request(url, init = {}) {
    let response
    try { response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(30_000), ...init }) } catch { throw new AcmeError('acme_unavailable') }
    const replay = response.headers.get('replay-nonce')
    if (replay && /^[A-Za-z0-9_-]{1,512}$/.test(replay)) nonce = replay
    const data = Buffer.from(await response.arrayBuffer())
    if (data.length > MAX_RESPONSE) throw new AcmeError('acme_response_too_large', response.status)
    return { response, data }
  }
  const json = data => { try { return JSON.parse(data.toString('utf8')) } catch { throw new AcmeError('acme_bad_response') } }

  async function directoryUrls() {
    if (urls) return urls
    const { response, data } = await request(directory)
    const body = response.ok ? json(data) : null
    if (!body || typeof body.newNonce !== 'string' || typeof body.newAccount !== 'string' || typeof body.newOrder !== 'string') throw new AcmeError('acme_bad_directory', response.status)
    urls = body
    return urls
  }
  async function freshNonce() {
    if (nonce) { const value = nonce; nonce = null; return value }
    await request((await directoryUrls()).newNonce, { method: 'HEAD' })
    if (!nonce) throw new AcmeError('acme_no_nonce')
    const value = nonce; nonce = null
    return value
  }
  /** A signed POST; `payload` undefined is POST-as-GET. Retries a badNonce twice, as RFC 8555 §6.5 expects. */
  async function post(url, payload, { accept = 'application/json', useJwk = false } = {}) {
    for (let attempt = 0; ; attempt++) {
      const header = { alg: 'ES256', nonce: await freshNonce(), url, ...(useJwk ? { jwk: publicJwk } : { kid: account }) }
      const protectedPart = b64u(JSON.stringify(header)), payloadPart = payload === undefined ? '' : b64u(JSON.stringify(payload))
      const signature = signData('sha256', Buffer.from(`${protectedPart}.${payloadPart}`), { key, dsaEncoding: 'ieee-p1363' })
      const result = await request(url, { method: 'POST', headers: { 'content-type': 'application/jose+json', accept }, body: JSON.stringify({ protected: protectedPart, payload: payloadPart, signature: b64u(signature) }) })
      if (result.response.ok) return result
      let problem = null
      try { problem = JSON.parse(result.data.toString('utf8')) } catch { /* not a problem document */ }
      const code = problemCode(problem)
      if (code === 'acme_bad_nonce' && attempt < 2) continue
      throw new AcmeError(code, result.response.status)
    }
  }
  const retryAfter = response => { const seconds = Number(response.headers.get('retry-after')); return Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds * 1000, 30_000) : pollMs }

  async function poll(url, done) {
    for (let i = 0; i < maxPolls; i++) {
      const { response, data } = await post(url)
      const body = json(data)
      const verdict = done(body)
      if (verdict) return body
      await wait(retryAfter(response))
    }
    throw new AcmeError('acme_poll_timeout')
  }

  return {
    get accountUri() { return account },
    /** Registers the account (terms agreed, no contact) unless its URI is already known. */
    async ensureAccount() {
      if (account) return account
      const { response } = await post((await directoryUrls()).newAccount, { termsOfServiceAgreed: true }, { useJwk: true })
      const location = response.headers.get('location')
      if (!location || !/^https?:\/\//.test(location)) throw new AcmeError('acme_no_account', response.status)
      account = location
      return account
    },
    /** Orders a certificate for `names` with a DER CSR; resolves to the PEM chain. */
    async issue(names, csr) {
      await this.ensureAccount()
      const ordered = await post((await directoryUrls()).newOrder, { identifiers: names.map(value => ({ type: 'dns', value })) })
      const orderUrl = ordered.response.headers.get('location')
      let order = json(ordered.data)
      if (!orderUrl || !Array.isArray(order.authorizations) || typeof order.finalize !== 'string') throw new AcmeError('acme_bad_order', ordered.response.status)
      const armed = []
      try {
        for (const url of order.authorizations) {
          const authorization = json((await post(url)).data)
          if (authorization.status === 'valid') continue
          const challenge = (authorization.challenges ?? []).find(item => item?.type === 'tls-alpn-01')
          const domain = String(authorization.identifier?.value ?? '').toLowerCase()
          if (!challenge || typeof challenge.url !== 'string' || !/^[A-Za-z0-9_-]{16,256}$/.test(challenge.token ?? '') || !names.includes(domain)) throw new AcmeError('acme_no_challenge')
          challenges.set(domain, `${challenge.token}.${keyThumbprint}`)
          armed.push(domain)
          await post(challenge.url, {})
          const settled = await poll(url, body => body.status !== 'pending' && body.status !== 'processing')
          if (settled.status !== 'valid') throw new AcmeError('acme_challenge_invalid')
        }
      } finally { for (const domain of armed) challenges.delete(domain) }
      order = await poll(orderUrl, body => body.status !== 'pending')
      if (order.status === 'ready') {
        await post(order.finalize, { csr: b64u(csr) })
        order = await poll(orderUrl, body => body.status !== 'processing' && body.status !== 'ready')
      }
      if (order.status !== 'valid' || typeof order.certificate !== 'string') throw new AcmeError('acme_order_invalid')
      const { data } = await post(order.certificate, undefined, { accept: 'application/pem-certificate-chain' })
      const chain = data.toString('utf8')
      if (!chain.includes('-----BEGIN CERTIFICATE-----')) throw new AcmeError('acme_bad_certificate')
      return chain
    },
  }
}
