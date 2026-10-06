// Console connection tokens (docs/mcp-enclave.md §19.18, `console_token_v1`):
// a connection for a tool that cannot run an OAuth flow but can send a fixed
// `Authorization: Bearer wmcp_k_…` header. The precedent is the AI
// authorization (§18.7): a console-made, attested request with no OAuth
// client, no PKCE and no completion proof. The sealed bundle, made in the
// person's browser, is the consent.
//
// The bearer is born in the browser and never reaches Go or this process:
// the bundle carries its SHA-256 (`bearer_sha256`), which is kept only inside
// the sealed state as a token record of kind `key`, and the networks it may be
// used from. A token is always of the `token` tier: the unknown tier's checks
// (text behind the second tick, a history window, the reading limits, no
// drafts or sending) and its own lifetimes, with no refresh token at all.
//
// Go asks for a request (`request`): a key minted for it alone and an
// attested descriptor of kind `token` (user_data v2 over it, §19.13). Go
// relays the bundle (`acceptBundle`): opened with that key, validated, for
// text proven against the grants with the device checks of version 4, then
// the row activated in Go, and only then the connection and its token kept.
// A pending request lives in this process's memory for PENDING_TTL_MS.
import { randomBytes } from 'node:crypto'
import { hpke } from '@whatserver2/client'
import { CONSOLE_TOKEN_CLIENT_ID, validateTokenBundle } from '@whatserver2/mcp/bundle'
import { LocalConfigError } from '@whatserver2/mcp/config'
import { RelayError } from '../internal.mjs'
import { bundleBody, connectionTaken, LinkError, unknownLive } from '../link.mjs'
import { fingerprint } from '../log.mjs'

export const TOKEN_INFO = Buffer.from('wappie-mcp-token/v1')
/** A token request's bundle: one request, one attested key, one resource. */
export const tokenAAD = (requestID, kid, resource) => Buffer.from(JSON.stringify(['wappie/mcp-token', 1, requestID, kid, resource]))
/** Token requests live at once (else 429 `too_many_prepares`). */
export const TOKEN_REQUESTS_PENDING_MAX = 20
const HOUR_MS = 3_600_000
const ENC_LEN = 32, TAG_LEN = 16

/**
 * The relayed body (§19.18 step 5): the BundleRelay plus `kind` (`metadata`
 * or `content`), the person's `history_days`, and `media` (absent is false;
 * only text may carry attachments). Strict; the expiry within the token
 * tier's ceiling for that kind.
 */
export function parseTokenRelay(body, { now, limits }) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || (body.kind !== 'metadata' && body.kind !== 'content')) throw new LinkError('bad_request')
  const { kind, history_days, media, ...rest } = body
  if (!Number.isSafeInteger(history_days) || (media !== undefined && typeof media !== 'boolean') || (kind === 'metadata' && media === true)) throw new LinkError('bad_request')
  const parsed = bundleBody.safeParse(rest)
  if (!parsed.success) throw new LinkError('bad_request')
  const { connection_id, tenant_id, kid, sealed: encoded, expires_at } = parsed.data
  const sealed = Buffer.from(encoded, 'base64url')
  if (sealed.toString('base64url') !== encoded || sealed.length < ENC_LEN + TAG_LEN) throw new LinkError('bad_request')
  const expiry = Date.parse(expires_at)
  if (!Number.isFinite(expiry) || expiry <= now() || expiry > now() + limits.ceiling_hours[kind] * HOUR_MS) throw new LinkError('bad_request')
  return { kind, connection_id, tenant_id, kid, sealed, expiry, history_days, media: media === true }
}

/** A metadata token's bundle, opened and validated (validateTokenBundle); invalid_bundle otherwise. The plaintext is zeroed. */
async function openMetadataBundle(recipient, sealed, { aad, now }) {
  let plain
  try {
    plain = await hpke.open(recipient.privateKey, new Uint8Array(sealed.subarray(0, ENC_LEN)), new Uint8Array(TOKEN_INFO), new Uint8Array(aad), new Uint8Array(sealed.subarray(ENC_LEN)))
  } catch { throw new LinkError('invalid_bundle') }
  try {
    let value
    try { value = JSON.parse(Buffer.from(plain).toString('utf8')) } catch { throw new LinkError('invalid_bundle') }
    try { return validateTokenBundle(value, now()) } catch (error) {
      if (error instanceof LocalConfigError) throw new LinkError('invalid_bundle')
      throw error
    }
  } finally { plain.fill(0) }
}

/**
 * `limits` is CLIENT_LIMITS.token; `openContent(recipient, sealed, options)`
 * and `prove(privateKey, bundle, {request, kid})` are content.mjs's
 * openContentBundle and proveGrants bound to the archive; `connkeys` holds a
 * text token's key; `origin` is the resource's.
 */
export function createConsoleTokens({ state, relay, log, now = Date.now, resource, origin, attestor, newRecipient, readerVersion, ttlMs, limits, unknownLiveMax,
  openContent, prove, connkeys, max = TOKEN_REQUESTS_PENDING_MAX }) {
  const requests = new Map()
  const live = request => request.expires_at > now()
  const conn = id => ({ conn: fingerprint(id) })
  function sweep() { for (const [id, request] of requests) if (!live(request)) requests.delete(id) }
  const choices = limits.history_days.choices
  const named = (id, except) => [...requests.values()].some(request => request !== except && request.accepting === id)

  /** Whether a bearer's hash is already a token here (of any kind): a second connection never shares it. */
  const knownHash = hash => state.tokens.has(hash)

  return {
    /** POST /internal/token-requests: a fresh attested request (§19.18 step 1). */
    async request(nonce) {
      if (!nonce) throw new LinkError('bad_request')
      sweep()
      if (requests.size >= max) throw new LinkError('too_many_prepares', 429)
      const recipient = await newRecipient()
      const id = randomBytes(16).toString('base64url')
      const expiresAt = now() + ttlMs
      const descriptor = {
        descriptor_version: 2, kind: 'token', request_id: id, kid: recipient.kid, reader_public_key: recipient.publicKeyEncoded,
        client_kind: 'token', trust: 'unknown', limits_tier: 'token', limits: structuredClone(limits), resource, reader_version: readerVersion,
        expires_at: new Date(expiresAt).toISOString(),
      }
      const attestation = await attestor.attestation({ requestId: id, publicKey: recipient.publicKey, nonce, descriptor })
      if (requests.size >= max) throw new LinkError('too_many_prepares', 429)
      requests.set(id, { id, recipient, created_at: now(), expires_at: expiresAt })
      return { ...descriptor, attestation }
    },

    /**
     * POST /internal/token-requests/{id}/bundle (§19.18 step 6): 204 only once
     * the bundle opened and fits the request, a text token's grants and
     * device checks are proven and Go activated the row; then the connection
     * and its token record are kept and the sealed state saved.
     */
    async acceptBundle(requestID, body) {
      const request = requests.get(requestID)
      if (!request || !live(request)) throw new LinkError('not_found', 404)
      const relayed = parseTokenRelay(body, { now, limits })
      if (request.accepting) throw new LinkError('bundle_exists', 409)
      const id = relayed.connection_id
      if (connectionTaken(state, null, id) || named(id, request)) throw new LinkError('bad_request')
      if (relayed.kid !== request.recipient.kid) throw new LinkError('unknown_kid')
      if (!choices.includes(relayed.history_days)) throw new LinkError('invalid_bundle')
      if (unknownLive(state, relayed.tenant_id, null) >= unknownLiveMax) throw new LinkError('too_many_unknown', 409)
      state.activating ??= new Set()
      state.activating.add(id)
      request.accepting = id
      try {
        const aad = tokenAAD(request.id, relayed.kid, resource)
        const text = relayed.kind === 'content'
        const ceiling = now() + limits.ceiling_hours[relayed.kind] * HOUR_MS
        let bundle, epochs = null
        if (text) {
          bundle = await openContent(request.recipient, relayed.sealed, { info: TOKEN_INFO, aad, purpose: 'token', origin, tenant: relayed.tenant_id, now })
          // The token's own client, the unknown tier and its second tick, the window Go relayed, attachments as Go records them, never sending.
          if (bundle.consent_version !== 4 || bundle.client_kind !== 'token' || bundle.client_id !== CONSOLE_TOKEN_CLIENT_ID || bundle.trust !== 'unknown' ||
            bundle.client_local !== false || bundle.started_ack !== true || bundle.unknown_ack !== true || bundle.history_days !== relayed.history_days ||
            (bundle.media === true) !== relayed.media || bundle.send !== undefined || Date.parse(bundle.expires_at) > ceiling) throw new LinkError('invalid_bundle')
        } else {
          bundle = await openMetadataBundle(request.recipient, relayed.sealed, { aad, now })
          if (bundle.server_url !== origin || bundle.workspace_id !== relayed.tenant_id || bundle.history_days !== relayed.history_days ||
            Date.parse(bundle.expires_at) > ceiling) throw new LinkError('invalid_bundle')
        }
        if (knownHash(bundle.bearer_sha256)) throw new LinkError('invalid_bundle')
        if (text) {
          try { ({ epochs } = await prove(request.recipient.privateKey, bundle, { request: request.id, kid: relayed.kid })) } catch (error) {
            log.event(error?.deviceCheck ? 'device_check_failed' : 'grant_proof_failed', conn(id))
            throw error
          }
        }
        // Activation in Go, as the AI path does; a failure leaves nothing here and Go undoes its row.
        try { await relay.activate(id) } catch (error) {
          if (!(error instanceof RelayError)) throw error
          void relay.revoke(id)
          throw new LinkError('relay_failed', 502)
        }
        // Another unknown connection or token may have landed while the grants were proven.
        if (state.connections.has(id) || unknownLive(state, relayed.tenant_id, null) >= unknownLiveMax) {
          void relay.revoke(id)
          throw new LinkError('too_many_unknown', 409)
        }
        const expires = new Date(Math.min(Date.parse(bundle.expires_at), relayed.expiry)).toISOString()
        const family = randomBytes(16).toString('base64url')
        const record = {
          connection_id: id, tenant_id: relayed.tenant_id, workspace_id: bundle.workspace_id, device_ids: [...bundle.device_ids], timezone: bundle.timezone ?? 'UTC',
          api_key: bundle.token, expires_at: expires, client_id: CONSOLE_TOKEN_CLIENT_ID, created_at: now(), family_id: family,
          // The client fields (§19.17), written once: the token tier, no host, no name (Go's ledger keeps the label).
          client_kind: 'token', client_host: null, registrable: null, shared_suffix: null, client_local: false, client_name: null, claimed_name: null,
          trust: 'unknown', tested_id: null, profile: 'default', limits_tier: 'token', started_ack: true, unknown_ack: text,
          history_days: bundle.history_days, allowed_networks: [...bundle.allowed_networks], bearer_sha256: bundle.bearer_sha256,
          ...(text ? {
            kind: 'content', service_user_id: bundle.service_user_id, key_mode: bundle.key_mode, consent_version: 4, media: bundle.media === true,
            epochs: { ...epochs }, consented_expires_at: expires,
          } : {}),
        }
        state.connections.set(id, record)
        state.tokens.set(bundle.bearer_sha256, {
          hash: bundle.bearer_sha256, kind: 'key', connection_id: id, client_id: CONSOLE_TOKEN_CLIENT_ID, family_id: family, expires_at: Date.parse(expires),
        })
        if (text) connkeys.set(id, request.recipient.privateKey)
        requests.delete(request.id)
        await state.save().catch(() => {})
        log.event('token_installed', conn(id))
      } catch (error) {
        log.event('token_install_failed', { ...conn(id), code: error instanceof LinkError ? error.code : 'install_failed' })
        throw error
      } finally { state.activating.delete(id); delete request.accepting }
    },

    sweep,
    size: () => requests.size,
    clear() { requests.clear() },
  }
}
