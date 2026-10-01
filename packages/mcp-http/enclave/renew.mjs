// Renewal of a content connection (docs/mcp-enclave.md §15.9): a new key here,
// a new service account in Go, and the same connection id, token family and
// expiry. The assistant never reconnects; its creator follows the console
// link with their password after a restart (`reseal`), or at any time.
//
// Go asks for a renewal (`prepare`): a fresh per-renewal key, attested with
// `request_id = renewal_id`, so the console's verifier needs no change. The
// console seals a `purpose: 'renewal'` bundle and grants to that key; Go
// relays the bundle (`acceptBundle`), which is opened, proven against the
// grants and staged. Go then swaps key and service in one transaction, and the
// next status that names the new service (a tool call forces one) commits
// the stage (`commit`). An uncommitted stage dies with its renewal's TTL.
//
// A connection with sending (docs/mcp-enclave.md §17.2 rules 6 and 7) renews
// its consent's send fields unchanged, under fresh device checks made for
// this renewal, and its draft keys are pinned again from the DSKs this
// renewal's grants open.
//
// An AI authorization (docs/mcp-enclave.md §18.7 step 7) renews the same way,
// through `ai`'s hooks (ai/service.mjs): its descriptor names its functions,
// features and budget, its bundle is an AI bundle under its own labels with
// fresh configuration tags and its models checked again, and the commit also
// swaps its provider keys.
//
// From reader 0.6.0 (§19.16) the descriptor is version 2, of kind `renewal`
// (or `ai_renewal`), and attested whole (user_data v2), so every field the
// renewal card shows is the image's word: the consent's version and scope,
// and the client and tier the record was given (a record 0.5.0 wrote reads as
// `legacy`, tested, under the tested web limits). A version-4 record renews
// with a version-4 bundle that names the same client, tier, ticks and history
// window; a token's hash and networks are never part of a renewal.
import { randomBytes } from 'node:crypto'
import { LinkError } from '../link.mjs'
import { fingerprint } from '../log.mjs'

export const RENEWAL_TTL_MS = 20 * 60_000
export const RENEWALS_LIVE_MAX = 3
export const RENEWALS_PER_HOUR = 10
const HOUR_MS = 3_600_000

/** A content record's deadline: its expiry, never later than what was consented (verifier.mjs clamps the same way). */
export function contentDeadline(record) {
  const consented = record.consented_expires_at
  return typeof consented === 'string' && !(Date.parse(record.expires_at) <= Date.parse(consented)) ? consented : record.expires_at
}

/**
 * The client members of a renewal descriptor (§19.16) for a content record:
 * the record's own, written once at completion or install, or, for a record
 * 0.5.0 wrote, `legacy`, tested and the tested web limits, with nulls where
 * the ledger's name is shown instead. `limits` is CLIENT_LIMITS.
 */
export function clientDescription(record, limits) {
  if (!record.client_kind) {
    return { client_kind: 'legacy', client_id: record.client_id ?? null, tested_id: null, client_host: null, registrable: null, shared_suffix: null,
      client_local: false, client_name: null, claimed_name: null, trust: 'tested', limits_tier: 'web_tested', limits: structuredClone(limits.web_tested),
      unknown_ack: false, history_days: null }
  }
  return {
    client_kind: record.client_kind, client_id: record.client_id, tested_id: record.tested_id ?? null, client_host: record.client_host ?? null,
    registrable: record.registrable ?? null, shared_suffix: record.shared_suffix ?? null, client_local: record.client_local === true,
    client_name: record.client_name ?? null, claimed_name: record.claimed_name ?? null, trust: record.trust, limits_tier: record.limits_tier,
    limits: structuredClone(limits[record.limits_tier]), unknown_ack: record.unknown_ack === true, history_days: record.history_days ?? null,
  }
}

/**
 * Whether a version-4 renewal bundle renews this version-4 record's consent
 * as it is (§19.16): the same client, kind, locality and tier, the "I
 * started this" tick, the same second tick (sealed again for a client Wappie
 * has not tested) and the same history window, and no token hash or
 * networks, which the record pins and no renewal carries.
 */
export const renewalFits = (record, bundle) => bundle.client_id === record.client_id && bundle.client_kind === record.client_kind &&
  bundle.client_local === (record.client_local === true) && bundle.trust === record.trust && bundle.started_ack === true &&
  bundle.unknown_ack === (record.unknown_ack === true) && bundle.history_days === (record.history_days ?? null) &&
  bundle.bearer_sha256 === undefined && bundle.allowed_networks === undefined

/**
 * `open(recipient, sealed, {aad, tenant, connectionID})` and
 * `prove(privateKey, bundle, {request, kid})` are content.mjs's, bound to the
 * renewal labels and the archive; `parseRelay(body)` checks the relayed body;
 * `onProofFailed(id, error)` logs a failed proof by what failed. `ai`, when
 * given, renews `ai` records too: `describe(record)` adds the descriptor's
 * fields, `accept({record, renewal, body, renewalID, connectionID})` opens,
 * checks and proves the bundle and resolves to the stage (with its `ai`
 * part), and `apply(record, stage.ai)` commits that part. `limits` (the
 * image's CLIENT_LIMITS, from reader 0.6.0) makes every descriptor version
 * 2, attested whole; without it they are 0.5.0's.
 */
export function createRenewals({ state, connkeys, log, now = Date.now, resource, attestor, newRecipient, open, prove, parseRelay, renewAAD, onCommit = () => {},
  onProofFailed = id => log.event('grant_proof_failed', { conn: fingerprint(id) }), ai = null, limits = null }) {
  const renewals = new Map()
  // connection id -> times of the renewals prepared in the last hour.
  const history = new Map()
  const conn = id => ({ conn: fingerprint(id) })
  const live = renewal => renewal.expires_at > now()
  const recordFor = id => {
    const record = state.connections.get(id)
    return record && (record.kind === 'content' || (ai && record.kind === 'ai')) ? record : null
  }
  function forConnection(id) { return [...renewals.values()].filter(renewal => renewal.connection_id === id) }
  function drop(renewalID) { renewals.delete(renewalID) }
  const sameSet = (a, b) => a.length === b.length && a.every(item => b.includes(item))

  return {
    /** POST /internal/connections/{id}/renewal: `{renewal_id, …, attestation}`, or LinkError / AttestationError. */
    async prepare(connectionID, nonce) {
      const record = recordFor(connectionID)
      if (!record) throw new LinkError('not_found', 404)
      if (!nonce) throw new LinkError('bad_request')
      const at = now()
      const recent = (history.get(connectionID) ?? []).filter(time => at - time < HOUR_MS)
      if (recent.length >= RENEWALS_PER_HOUR) { history.set(connectionID, recent); throw new LinkError('too_many_prepares', 429) }
      recent.push(at)
      history.set(connectionID, recent)
      const recipient = await newRecipient()
      const renewalID = randomBytes(16).toString('base64url')
      const expiresAt = at + RENEWAL_TTL_MS
      // The consent the renewal must seal again (§16.2 rule 7, §17.2 rule 7).
      // The send fields are there only when the consent has them. On 0.5.0
      // these were not attested, so a wrong value could only make
      // acceptBundle refuse the renewal; from 0.6.0 the whole descriptor is.
      const described = {
        renewal_id: renewalID, connection_id: connectionID, kid: recipient.kid, reader_public_key: recipient.publicKeyEncoded, resource,
        device_ids: [...record.device_ids], expires_at: new Date(expiresAt).toISOString(), connection_expires_at: contentDeadline(record),
        ...(record.kind === 'ai' ? ai.describe(record) : {
          consent_version: record.consent_version ?? 1, media: record.media === true,
          ...(record.send ? { send: record.send, ...(record.send_self === true ? { send_self: true } : {}), ...(record.send_groups === true ? { send_groups: true } : {}) } : {}),
        }),
      }
      const descriptor = limits
        ? { descriptor_version: 2, ...described, kind: record.kind === 'ai' ? 'ai_renewal' : 'renewal', ...(record.kind === 'ai' ? {} : clientDescription(record, limits)) }
        : described
      const attestation = await attestor.attestation({ requestId: renewalID, publicKey: recipient.publicKey, nonce, ...(limits ? { descriptor } : {}) })
      // At most three live per connection: the oldest makes way.
      const current = forConnection(connectionID).filter(live).sort((a, b) => a.created_at - b.created_at)
      while (current.length >= RENEWALS_LIVE_MAX) drop(current.shift().renewal_id)
      const renewal = { renewal_id: renewalID, connection_id: connectionID, recipient, created_at: at, expires_at: expiresAt }
      renewals.set(renewalID, renewal)
      log.event('renewal_prepared', conn(connectionID))
      return { ...descriptor, attestation }
    },

    /** POST /internal/connections/{id}/renewal/{renewal_id}/bundle: stages the new key after the grant proof (204). */
    async acceptBundle(connectionID, renewalID, body) {
      const record = recordFor(connectionID)
      const renewal = renewals.get(renewalID)
      if (!record || !renewal || renewal.connection_id !== connectionID || !live(renewal)) throw new LinkError('not_found', 404)
      if (record.kind === 'ai') {
        if (renewal.stage || renewal.accepting) throw new LinkError('bundle_exists', 409)
        renewal.accepting = true
        try {
          renewal.stage = await ai.accept({ record, renewal, body, renewalID, connectionID })
          log.event('renewal_staged', conn(connectionID))
        } finally { delete renewal.accepting }
        return
      }
      const relayed = parseRelay(body)
      // A renewal renews the key, never the consent: its relay never carries `media` or a send field.
      if (relayed.connection_id !== connectionID || relayed.tenant_id !== record.tenant_id || relayed.media ||
        relayed.send !== null || relayed.send_self || relayed.send_groups || relayed.send_chats.length) throw new LinkError('bad_request')
      if (renewal.stage || renewal.accepting) throw new LinkError('bundle_exists', 409)
      if (relayed.kid !== renewal.recipient.kid) throw new LinkError('unknown_kid')
      renewal.accepting = true
      try {
        const bundle = await open(renewal.recipient, relayed.sealed, { aad: renewAAD(renewalID, connectionID, relayed.kid, resource), tenant: relayed.tenant_id, connectionID })
        // A renewal changes the key and the service, nothing else: not the
        // workspace, not the numbers, not the deadline, not the consent
        // (its version and whether it includes attachments).
        if (bundle.service_user_id === record.service_user_id || bundle.workspace_id !== record.workspace_id ||
          !sameSet(bundle.device_ids, record.device_ids) || bundle.consent_version !== (record.consent_version ?? 1) ||
          (bundle.media === true) !== (record.media === true) || (bundle.send ?? null) !== (record.send ?? null) ||
          (bundle.send_self === true) !== (record.send_self === true) || (bundle.send_groups === true) !== (record.send_groups === true) ||
          // A version-4 consent renews as it is: the same client, tier, ticks and window (§19.16).
          (bundle.consent_version === 4 && !renewalFits(record, bundle)) ||
          Math.min(Date.parse(bundle.expires_at), relayed.expiry) !== Date.parse(contentDeadline(record))) throw new LinkError('invalid_bundle')
        let proven
        try { proven = await prove(renewal.recipient.privateKey, bundle, { request: renewalID, kid: relayed.kid }) } catch (error) {
          onProofFailed(connectionID, error)
          throw error
        }
        // The deadline this renewal's card showed and the bundle carried: the
        // commit narrows the consented deadline to it, never widens it.
        renewal.stage = { key: renewal.recipient.privateKey, api_key: bundle.token, service_user_id: bundle.service_user_id, epochs: proven.epochs,
          expires_at: contentDeadline(record), ...(proven.draftsTo ? { drafts_to: proven.draftsTo } : {}) }
        log.event('renewal_staged', conn(connectionID))
      } finally { delete renewal.accepting }
    },

    /** Whether a live staged renewal waits for the connection. */
    staged: connectionID => forConnection(connectionID).some(renewal => renewal.stage && live(renewal)),

    /**
     * Commits the stage whose service Go now names as active: the new key
     * replaces the old one, the record takes the new API key, service and
     * epochs, and every renewal of the connection is dropped. False when no
     * live stage names that service.
     */
    async commit(record, status) {
      if (status.status !== 'active' || typeof status.service_user_id !== 'string') return false
      const id = record.connection_id
      const renewal = forConnection(id).find(item => item.stage && live(item) && item.stage.service_user_id === status.service_user_id)
      if (!renewal) return false
      const { key, api_key, service_user_id, epochs, expires_at, drafts_to, ai: aiStage } = renewal.stage
      connkeys.wipe(id)
      connkeys.set(id, key)
      const consented = [record.consented_expires_at, expires_at].filter(value => typeof value === 'string')
        .reduce((earliest, value) => (earliest === undefined || Date.parse(value) < Date.parse(earliest) ? value : earliest), undefined)
      Object.assign(record, { api_key, service_user_id, epochs: { ...epochs }, renewed_at: now(), ...(consented ? { consented_expires_at: consented } : {}),
        ...(drafts_to ? { drafts_to: structuredClone(drafts_to) } : {}) })
      if (aiStage && record.kind === 'ai') ai.apply(record, aiStage)
      for (const item of forConnection(id)) drop(item.renewal_id)
      await state.save().catch(() => {})
      onCommit(id)
      return true
    },

    /** Everything about a connection that is gone. */
    forget(connectionID) { for (const item of forConnection(connectionID)) drop(item.renewal_id); history.delete(connectionID) },
    sweep() {
      const at = now()
      for (const renewal of [...renewals.values()]) if (!live(renewal)) drop(renewal.renewal_id)
      for (const [id, times] of history) { const recent = times.filter(time => at - time < HOUR_MS); if (recent.length) history.set(id, recent); else history.delete(id) }
    },
    clear() { renewals.clear(); history.clear() },
    size: () => renewals.size,
  }
}
