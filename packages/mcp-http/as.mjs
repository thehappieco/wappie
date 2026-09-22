// The OAuth 2.1 authorization server: registration, the authorization request
// that hands off to the console, the consent completion that turns a proof into
// a code, the token endpoint and revocation. Everything here is hand-written
// because the SDK ships only the resource-server half; it is deliberately small
// and every branch is exercised by the negative matrix in test/as.test.mjs.
import { randomBytes } from 'node:crypto'
import { RegistrationError } from './clients.mjs'
import { dummyProof, LinkError, MAX_PROOF_ATTEMPTS, verifyProof } from './link.mjs'
import { GrantError, hash, wellFormed } from './tokens.mjs'
import { SCOPE } from './metadata.mjs'
import { RelayError } from './internal.mjs'

export const PENDING_MAX = 1000
export const PENDING_UNCONSENTED_MAX = 200
export const PENDING_PER_IP = 10
export const TOKEN_PER_IP = 300
export const REGISTER_PER_IP = 5
export const CIMD_FETCH_PER_IP = 3
export const MAX_STATE_CHARS = 512
const challengeShape = /^[A-Za-z0-9_-]{43,128}$/
const requestIDShape = /^[A-Za-z0-9_-]{22}$/
const noStore = { 'Cache-Control': 'no-store', Pragma: 'no-cache' }

const oauthError = (status, error, description, extra = {}) => Response.json({ error, error_description: description }, { status, headers: { ...noStore, ...extra } })
/** Browser-facing failures get a static page; the code comes from a fixed set, never from input. */
const page = (status, code) => new Response(`<!doctype html><meta charset="utf-8"><title>Wappie MCP</title><p>Wappie MCP: ${code}.</p>`,
  { status, headers: { ...noStore, 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff' } })
const redirect = location => new Response(null, { status: 302, headers: { ...noStore, Location: location } })
const text = value => (typeof value === 'string' ? value : undefined)

/** Parses a form body, refusing anything but urlencoded and any repeated field. */
async function form(request) {
  if (!(request.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase().startsWith('application/x-www-form-urlencoded')) return null
  const params = new URLSearchParams(await request.text())
  for (const name of new Set(params.keys())) if (params.getAll(name).length > 1) return null
  return params
}

export function createAuthorizationServer({ state, clients, cimd, tokens, limiter, relay, log, now, publicOrigin, consoleURL, resource, pendingTTLMs }) {
  const consoleOrigin = new URL(consoleURL).origin
  const tooMany = (meta, retryAfter) => { meta.code = 'rate_limited'; return oauthError(429, 'temporarily_unavailable', 'too many requests', { 'Retry-After': String(retryAfter) }) }
  function expirePending(id, pending) {
    state.pending.delete(id)
    if (pending.connection_id) void relay.revoke(pending.connection_id)
  }
  /** A live pending request, or undefined; expired ones are dropped (and their Go row revoked) on sight. */
  function pendingFor(id) {
    if (!requestIDShape.test(id ?? '')) return undefined
    const pending = state.pending.get(id)
    if (!pending) return undefined
    if (pending.expires_at <= now()) { expirePending(id, pending); return undefined }
    return pending
  }
  /**
   * Room for one more pending request. A request nobody has consented to yet
   * (no bundle) is only a browser tab that may never come back, so the oldest
   * one makes way; only when every slot holds a consented request is the
   * caller refused, and those are bounded by the connections Go allows.
   */
  function makeRoom() {
    const unconsented = [...state.pending.entries()].filter(([, pending]) => !pending.bundle)
    if (unconsented.length < PENDING_UNCONSENTED_MAX && state.pending.size < PENDING_MAX) return true
    if (unconsented.length === 0) return false
    const [oldest] = unconsented.reduce((found, entry) => (entry[1].created_at < found[1].created_at ? entry : found))
    state.pending.delete(oldest)
    return true
  }
  return {
    pendingFor,
    sweepPending() { for (const [id, pending] of state.pending) if (pending.expires_at <= now()) expirePending(id, pending) },

    async register(request, ip, meta) {
      if (request.method !== 'POST') return oauthError(405, 'invalid_request', 'POST only', { Allow: 'POST' })
      const taken = limiter.take('register', ip, REGISTER_PER_IP)
      if (!taken.ok) return tooMany(meta, taken.retryAfter)
      let body
      if (!(request.headers.get('content-type') ?? '').toLowerCase().startsWith('application/json')) { meta.code = 'invalid_client_metadata'; return oauthError(400, 'invalid_client_metadata', 'the registration must be application/json') }
      try { body = await request.json() } catch { meta.code = 'invalid_client_metadata'; return oauthError(400, 'invalid_client_metadata', 'the registration must be valid JSON') }
      try {
        const record = clients.register(body)
        meta.client = record.client_id
        await state.save()
        return Response.json(clients.describe(record), { status: 201, headers: noStore })
      } catch (error) {
        if (!(error instanceof RegistrationError)) throw error
        meta.code = error.code
        return oauthError(error.status ?? 400, error.code, error.description, error.status === 429 ? { 'Retry-After': '60' } : {})
      }
    },

    async authorize(request, ip, meta) {
      if (request.method !== 'GET') return page(405, 'method_not_allowed')
      // The address budget is spent before anything is looked at, so a refused
      // request (or one that would make the relay fetch a document) costs the
      // caller as much as an accepted one.
      const taken = limiter.take('authorize', ip, 20)
      if (!taken.ok) { meta.code = 'rate_limited'; return page(429, 'too_many_requests') }
      let mine = 0
      for (const pending of state.pending.values()) if (pending.ip === ip) mine++
      if (mine >= PENDING_PER_IP) { meta.code = 'too_many_pending'; return page(429, 'too_many_requests') }
      const params = new URL(request.url).searchParams
      for (const name of new Set(params.keys())) if (params.getAll(name).length > 1) { meta.code = 'invalid_request'; return page(400, 'invalid_request') }
      const clientID = params.get('client_id') ?? ''
      let starved = false
      const client = clients.get(clientID) ?? await cimd.resolve(clientID, { allowFetch: () => { const budget = limiter.take('cimd', ip, CIMD_FETCH_PER_IP); starved = !budget.ok; return budget.ok } })
      if (starved) { meta.code = 'rate_limited'; return page(429, 'too_many_requests') }
      if (!client) { meta.code = 'invalid_client'; return page(400, 'invalid_client') }
      meta.client = client.client_id
      const redirectURI = params.get('redirect_uri')
      if (!client.redirect_uris.includes(redirectURI)) { meta.code = 'invalid_redirect_uri'; return page(400, 'invalid_redirect_uri') }
      // From here on the redirect target is trusted, so errors travel back to the client.
      const fail = code => {
        meta.code = code
        const location = new URL(redirectURI)
        location.searchParams.set('error', code)
        if (params.has('state')) location.searchParams.set('state', params.get('state'))
        location.searchParams.set('iss', publicOrigin)
        return redirect(location.href)
      }
      if (params.get('response_type') !== 'code') return fail('unsupported_response_type')
      const challenge = params.get('code_challenge') ?? ''
      if (!challengeShape.test(challenge) || params.get('code_challenge_method') !== 'S256') return fail('invalid_request')
      if (params.get('resource') !== resource) return fail('invalid_target')
      const scope = params.get('scope')
      if (scope !== null && (scope.trim() === '' || scope.split(' ').filter(Boolean).some(item => item !== SCOPE))) return fail('invalid_scope')
      const stateParam = params.get('state')
      if (stateParam !== null && (stateParam.length === 0 || stateParam.length > MAX_STATE_CHARS)) return fail('invalid_request')
      if (!makeRoom()) { meta.code = 'too_many_pending'; return page(429, 'too_many_requests') }
      const id = randomBytes(16).toString('base64url')
      state.pending.set(id, {
        id, client_id: client.client_id, client_name: client.client_name, redirect_uri: redirectURI, redirect_host: client.redirect_host,
        state: stateParam ?? undefined, code_challenge: challenge, resource, scope: SCOPE, ip,
        created_at: now(), expires_at: now() + pendingTTLMs, proof_attempts: 0,
      })
      const location = new URL(consoleURL)
      location.searchParams.set('mcp_connect', id)
      return redirect(location.href)
    },

    async complete(request, ip, meta) {
      if (request.method !== 'POST') return page(405, 'method_not_allowed')
      // CSRF: the consent form is posted by the console, and only by the console.
      if (request.headers.get('origin') !== consoleOrigin) { meta.code = 'invalid_origin'; return page(400, 'invalid_origin') }
      const taken = limiter.take('complete', ip, 10)
      if (!taken.ok) { meta.code = 'rate_limited'; return page(429, 'too_many_requests') }
      const params = await form(request)
      if (!params) { meta.code = 'invalid_request'; return page(400, 'invalid_request') }
      const id = params.get('request') ?? '', proof = params.get('proof') ?? ''
      const pending = pendingFor(id)
      if (!pending || !pending.bundle) { dummyProof(); meta.code = 'invalid_proof'; return page(400, 'invalid_proof') }
      meta.client = pending.client_id
      meta.connection = pending.connection_id
      let bundle = null
      try { bundle = await verifyProof(state, pending, proof) } catch (error) { if (!(error instanceof LinkError)) throw error }
      if (!bundle) {
        pending.proof_attempts++
        if (pending.proof_attempts >= MAX_PROOF_ATTEMPTS) { expirePending(id, pending); meta.code = 'proof_burned'; return page(400, 'invalid_proof') }
        meta.code = 'invalid_proof'
        return page(400, 'invalid_proof')
      }
      state.pending.delete(id)
      try { await relay.activate(pending.connection_id) } catch (error) {
        if (!(error instanceof RelayError)) throw error
        void relay.revoke(pending.connection_id)
        meta.code = 'activation_failed'
        return page(502, 'activation_failed')
      }
      state.connections.set(pending.connection_id, {
        connection_id: pending.connection_id, tenant_id: pending.tenant_id, workspace_id: bundle.workspace_id, device_ids: bundle.device_ids,
        timezone: bundle.timezone ?? 'UTC', api_key: bundle.token, expires_at: pending.bundle.expires_at, client_id: pending.client_id, created_at: now(),
      })
      clients.consented(pending.client_id)
      await state.save()
      const code = tokens.issueCode({ client_id: pending.client_id, redirect_uri: pending.redirect_uri, code_challenge: pending.code_challenge, resource, connection_id: pending.connection_id })
      const location = new URL(pending.redirect_uri)
      location.searchParams.set('code', code)
      if (pending.state !== undefined) location.searchParams.set('state', pending.state)
      location.searchParams.set('iss', publicOrigin)
      return redirect(location.href)
    },

    async token(request, ip, meta) {
      if (request.method !== 'POST') return oauthError(405, 'invalid_request', 'POST only', { Allow: 'POST' })
      // Before the grant is known only the address can be charged, and coarsely:
      // client_id is public (one CIMD URL serves every user of an assistant), so
      // a bucket keyed on it would let anyone with a garbage grant starve them
      // all. The fair buckets below key on what the grant itself identifies.
      const taken = limiter.take('token', ip, TOKEN_PER_IP)
      if (!taken.ok) return tooMany(meta, taken.retryAfter)
      const params = await form(request)
      if (!params) { meta.code = 'invalid_request'; return oauthError(400, 'invalid_request', 'the request must be a form without repeated fields') }
      const grant = params.get('grant_type'), clientID = text(params.get('client_id') ?? undefined)
      if (!clientID || clientID.length > 2048) { meta.code = 'invalid_request'; return oauthError(400, 'invalid_request', 'client_id is required') }
      meta.client = clientID
      const target = params.get('resource')
      try {
        if (grant === 'authorization_code') {
          if (target !== resource) { meta.code = 'invalid_target'; return oauthError(400, 'invalid_target', 'resource must name this MCP server') }
          const code = params.get('code') ?? ''
          const connection = wellFormed('code', code) ? state.codes.get(hash(code))?.connection_id : undefined
          if (connection) {
            meta.connection = connection
            const perConnection = limiter.take('token_connection', connection, 20)
            if (!perConnection.ok) return tooMany(meta, perConnection.retryAfter)
          }
          const pair = await tokens.exchangeCode({ code, client_id: clientID, code_verifier: params.get('code_verifier') ?? '', redirect_uri: params.get('redirect_uri') ?? '', resource: target })
          return Response.json(pair, { headers: noStore })
        }
        if (grant === 'refresh_token') {
          if (target !== null && target !== resource) { meta.code = 'invalid_target'; return oauthError(400, 'invalid_target', 'resource must name this MCP server') }
          const presented = params.get('refresh_token') ?? ''
          const known = wellFormed('refresh', presented) ? state.tokens.get(hash(presented)) : undefined
          if (known) {
            meta.connection = known.connection_id
            const perFamily = limiter.take('token_family', known.family_id, 20)
            if (!perFamily.ok) return tooMany(meta, perFamily.retryAfter)
          }
          const pair = await tokens.refresh({ refresh_token: presented, client_id: clientID })
          return Response.json(pair, { headers: noStore })
        }
        meta.code = 'unsupported_grant_type'
        return oauthError(400, 'unsupported_grant_type', 'use authorization_code or refresh_token')
      } catch (error) {
        if (error instanceof GrantError) { meta.code = 'invalid_grant'; return oauthError(400, 'invalid_grant', 'the grant is invalid, expired or revoked') }
        if (error instanceof RelayError) { meta.code = 'archive_unavailable'; return oauthError(503, 'server_error', 'the archive is unavailable', { 'Retry-After': '5' }) }
        throw error
      }
    },

    async revoke(request, meta) {
      if (request.method !== 'POST') return oauthError(405, 'invalid_request', 'POST only', { Allow: 'POST' })
      const params = await form(request)
      if (!params) { meta.code = 'invalid_request'; return oauthError(400, 'invalid_request', 'the request must be a form without repeated fields') }
      meta.client = text(params.get('client_id') ?? undefined)
      // RFC 7009: the answer is 200 whether or not the token was known.
      if (await tokens.revoke(params.get('token') ?? '')) meta.code = 'revoked'
      return new Response(null, { status: 200, headers: noStore })
    },
  }
}
