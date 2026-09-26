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
 * `open(recipient, sealed, {aad, tenant, connectionID})` and
 * `prove(privateKey, bundle)` are content.mjs's, bound to the renewal labels
 * and the archive; `parseRelay(body)` checks the relayed body.
 */
export function createRenewals({ state, connkeys, log, now = Date.now, resource, attestor, newRecipient, open, prove, parseRelay, renewAAD, onCommit = () => {} }) {
  const renewals = new Map()
  // connection id -> times of the renewals prepared in the last hour.
  const history = new Map()
  const conn = id => ({ conn: fingerprint(id) })
  const live = renewal => renewal.expires_at > now()
  const recordFor = id => {
    const record = state.connections.get(id)
    return record && record.kind === 'content' ? record : null
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
      const attestation = await attestor.attestation({ requestId: renewalID, publicKey: recipient.publicKey, nonce })
      // At most three live per connection: the oldest makes way.
      const current = forConnection(connectionID).filter(live).sort((a, b) => a.created_at - b.created_at)
      while (current.length >= RENEWALS_LIVE_MAX) drop(current.shift().renewal_id)
      const renewal = { renewal_id: renewalID, connection_id: connectionID, recipient, created_at: at, expires_at: at + RENEWAL_TTL_MS }
      renewals.set(renewalID, renewal)
      log.event('renewal_prepared', conn(connectionID))
      return {
        renewal_id: renewalID, connection_id: connectionID, kid: recipient.kid, reader_public_key: recipient.publicKeyEncoded, resource,
        device_ids: [...record.device_ids], expires_at: new Date(renewal.expires_at).toISOString(), connection_expires_at: contentDeadline(record), attestation,
      }
    },

    /** POST /internal/connections/{id}/renewal/{renewal_id}/bundle: stages the new key after the grant proof (204). */
    async acceptBundle(connectionID, renewalID, body) {
      const record = recordFor(connectionID)
      const renewal = renewals.get(renewalID)
      if (!record || !renewal || renewal.connection_id !== connectionID || !live(renewal)) throw new LinkError('not_found', 404)
      const relayed = parseRelay(body)
      if (relayed.connection_id !== connectionID || relayed.tenant_id !== record.tenant_id) throw new LinkError('bad_request')
      if (renewal.stage || renewal.accepting) throw new LinkError('bundle_exists', 409)
      if (relayed.kid !== renewal.recipient.kid) throw new LinkError('unknown_kid')
      renewal.accepting = true
      try {
        const bundle = await open(renewal.recipient, relayed.sealed, { aad: renewAAD(renewalID, connectionID, relayed.kid, resource), tenant: relayed.tenant_id, connectionID })
        // A renewal changes the key and the service, nothing else: not the
        // workspace, not the numbers, not the deadline.
        if (bundle.service_user_id === record.service_user_id || bundle.workspace_id !== record.workspace_id ||
          !sameSet(bundle.device_ids, record.device_ids) ||
          Math.min(Date.parse(bundle.expires_at), relayed.expiry) !== Date.parse(contentDeadline(record))) throw new LinkError('invalid_bundle')
        let epochs
        try { epochs = await prove(renewal.recipient.privateKey, bundle) } catch (error) {
          log.event('grant_proof_failed', conn(connectionID))
          throw error
        }
        // The deadline this renewal's card showed and the bundle carried: the
        // commit narrows the consented deadline to it, never widens it.
        renewal.stage = { key: renewal.recipient.privateKey, api_key: bundle.token, service_user_id: bundle.service_user_id, epochs, expires_at: contentDeadline(record) }
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
      const { key, api_key, service_user_id, epochs, expires_at } = renewal.stage
      connkeys.wipe(id)
      connkeys.set(id, key)
      const consented = [record.consented_expires_at, expires_at].filter(value => typeof value === 'string')
        .reduce((earliest, value) => (earliest === undefined || Date.parse(value) < Date.parse(earliest) ? value : earliest), undefined)
      Object.assign(record, { api_key, service_user_id, epochs: { ...epochs }, renewed_at: now(), ...(consented ? { consented_expires_at: consented } : {}) })
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
