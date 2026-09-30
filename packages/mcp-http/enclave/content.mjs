// Content connections in the attested reader, ephemeral mode
// (docs/mcp-enclave.md §15). A content connection opens message text, chat and
// contact names and filenames with the per-request key the console verified
// in an attestation, sealed its bundle and every grant to, and registered as
// the connection's own service account. That key lives in `connkeys` only,
// in this process's memory; a restart loses it, and the connection waits in
// `reseal` (Go keeps the row, the token family survives) until its creator
// renews it in the console with their password.
//
// A consent of version 2 may include attachments (`media`, docs/mcp-enclave.md
// §16): the sealed record says so, and such a connection's reader gets the
// media service (media/service.mjs), which opens them in jailed workers.
//
// A consent of version 3 includes sending (§17): drafts, and the own chat
// when the person turned it on. Its bundle carries a device check per number,
// which only a holder of that number's key can make and which binds the whole
// scope; the key a draft is sealed to is pinned here, at install, from the
// DSK the grant proof opened. Such a connection's reader gets the sending
// service (send/service.mjs).
//
// This file is reachable from enclave/main.mjs only. The hosted reader
// (../server.mjs on the pilot) never imports it: there a bundle labelled
// `content` is a bad request, `link.openBundle` refuses anything but v1, and
// '../provider.mjs' refuses every content-opening read.
import { timingSafeEqual } from 'node:crypto'
import { ArchiveClient, bytes, hpke, seal } from '@whatserver2/client'
import { deviceCheck, deviceScope, validateContentBundle } from '@whatserver2/mcp/bundle'
import { LocalConfigError } from '@whatserver2/mcp/config'
import { validTimezone } from '@whatserver2/mcp/time'
import { RelayError } from '../internal.mjs'
import { bundleBody, connectionTaken, LinkError, proofFor, proofMatches } from '../link.mjs'
import { fingerprint } from '../log.mjs'
import { newRecipient as mintRecipient } from '../state.mjs'
import { createConnKeys } from './connkeys.mjs'
import { padResponse } from './media/pad.mjs'
import { createMediaService } from './media/service.mjs'
import { contentConfigFor, contentProviderFor } from './provider.mjs'
import { createRenewals } from './renew.mjs'
import { createSendService } from './send/service.mjs'

export const CONSENT_INFO = Buffer.from('wappie-mcp-connect/v2')
export const RENEW_INFO = Buffer.from('wappie-mcp-renew/v1')
/** Consent: one request, one attested key, one resource. */
export const consentAAD = (requestID, kid, resource) => Buffer.from(JSON.stringify(['wappie/mcp-connect', 2, requestID, kid, resource]))
/** Renewal: one renewal, one connection, one attested key, one resource. */
export const renewAAD = (renewalID, connectionID, kid, resource) => Buffer.from(JSON.stringify(['wappie/mcp-renew', 1, renewalID, connectionID, kid, resource]))
/** A content connection lasts at most 90 days; Go's expiry may carry an hour of slack. */
export const MAX_CONTENT_MS = (90 * 24 + 1) * 3_600_000
export const KEY_MODE = 'ephemeral'
const ENC_LEN = 32, TAG_LEN = 16
const linkSecretShape = /^[A-Za-z0-9_-]{43}$/
// Never in a v2 bundle: a service key (the key lives here only), contacts (out
// of 2b) and a plaintext flag (content is what `kind` says).
const forbidden = ['service_private_key', 'contacts', 'allow_plaintext']
const RESEAL_BACKOFF_START_MS = 1000, RESEAL_BACKOFF_MAX_MS = 60_000
/** The grant proof's archive call gives up first: Go waits 10 s for the bundle relay it runs inside. */
export const PROOF_TIMEOUT_MS = 8000

const uuidShape = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
/** A relayed `send_chats` (S3): a list of `{device_id, chat_key}`, or null. */
function relayedChats(value) {
  if (!Array.isArray(value) || value.length > 100) return null
  const chats = []
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item) || Object.keys(item).length !== 2 || typeof item.device_id !== 'string' || !uuidShape.test(item.device_id) ||
      typeof item.chat_key !== 'string' || item.chat_key.length < 1 || item.chat_key.length > 128) return null
    chats.push({ device_id: item.device_id, chat_key: item.chat_key })
  }
  return chats
}
/** Two chat lists as sets. */
const sameChats = (a, b) => {
  const key = chat => `${chat.device_id}\n${chat.chat_key}`
  const left = new Set(a.map(key)), right = new Set(b.map(key))
  return left.size === right.size && [...left].every(item => right.has(item))
}

/**
 * The relayed body: 2a's BundleRelay plus `"kind": "content"`, `"media":
 * true` when the consent includes attachments (Go leaves it out otherwise;
 * absent is false, §16.2 rule 3), and the sending fields of a version-3
 * consent (§17.2 rule 4): `send`, with `send_self`, `send_groups` and (S3)
 * `send_chats`, each only when present. A renewal's relay carries none.
 */
export function parseRelay(body, { now }) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || body.kind !== 'content') throw new LinkError('bad_request')
  const { kind: _kind, media, send, send_self, send_groups, send_chats, ...rest } = body
  if (media !== undefined && typeof media !== 'boolean') throw new LinkError('bad_request')
  if ((send !== undefined && send !== 'draft' && send !== 'direct') || [send_self, send_groups].some(flag => flag !== undefined && typeof flag !== 'boolean') ||
    (send === undefined && (send_self !== undefined || send_groups !== undefined || send_chats !== undefined))) throw new LinkError('bad_request')
  const chats = send_chats === undefined ? [] : relayedChats(send_chats)
  if (!chats) throw new LinkError('bad_request')
  const parsed = bundleBody.safeParse(rest)
  if (!parsed.success) throw new LinkError('bad_request')
  const { connection_id, tenant_id, kid, sealed: encoded, expires_at } = parsed.data
  const sealed = Buffer.from(encoded, 'base64url')
  if (sealed.toString('base64url') !== encoded || sealed.length < ENC_LEN + TAG_LEN) throw new LinkError('bad_request')
  const expiry = Date.parse(expires_at)
  if (!Number.isFinite(expiry) || expiry <= now() || expiry > now() + MAX_CONTENT_MS) throw new LinkError('bad_request')
  return { connection_id, tenant_id, kid, sealed, expiry, media: media === true, send: send ?? null, send_self: send_self === true, send_groups: send_groups === true, send_chats: chats }
}

/** Whether what Go relays and what the owner sealed say the same about attachments and sending (§16.2 rule 3, §17.2 rule 5). */
export const relayMatches = (relayed, bundle) => relayed.media === (bundle.media === true) && relayed.send === (bundle.send ?? null) &&
  relayed.send_self === (bundle.send_self === true) && relayed.send_groups === (bundle.send_groups === true) && sameChats(relayed.send_chats, bundle.send_chats ?? [])

/**
 * Opens a v2 bundle sealed to `recipient` under `info` and `aad`, validates it
 * with the reader's schema and checks what binds it to this route. Throws
 * LinkError('invalid_bundle'); the plaintext is zeroed whatever happens.
 */
export async function openContentBundle(recipient, sealed, { info, aad, purpose, origin, tenant, connectionID, now }) {
  let plain
  try {
    plain = await hpke.open(recipient.privateKey, new Uint8Array(sealed.subarray(0, ENC_LEN)), new Uint8Array(info), new Uint8Array(aad), new Uint8Array(sealed.subarray(ENC_LEN)))
  } catch { throw new LinkError('invalid_bundle') }
  try {
    let value
    try { value = JSON.parse(Buffer.from(plain).toString('utf8')) } catch { throw new LinkError('invalid_bundle') }
    if (!value || typeof value !== 'object' || Array.isArray(value) || forbidden.some(name => Object.hasOwn(value, name))) throw new LinkError('invalid_bundle')
    let bundle
    try { bundle = validateContentBundle(value, now()) } catch (error) {
      if (error instanceof LocalConfigError) throw new LinkError('invalid_bundle')
      throw error
    }
    // The reader's schema is the rule; these are what binds the bundle to this
    // request, checked here again whatever the schema says.
    if (bundle.version !== 2 || bundle.kind !== 'content' || bundle.purpose !== purpose || bundle.key_mode !== KEY_MODE ||
      ![1, 2, 3].includes(bundle.consent_version) || (bundle.media === true && bundle.consent_version < 2) ||
      (bundle.consent_version === 3) !== (bundle.send !== undefined) || (bundle.send !== undefined) !== (bundle.device_checks !== undefined) ||
      bundle.server_url !== origin || bundle.workspace_id !== tenant || !Array.isArray(bundle.device_ids) || bundle.device_ids.length === 0 ||
      new Set(bundle.device_ids).size !== bundle.device_ids.length || typeof bundle.service_user_id !== 'string' || typeof bundle.token !== 'string' ||
      !Number.isFinite(Date.parse(bundle.expires_at)) || (bundle.timezone !== undefined && !validTimezone(bundle.timezone))) throw new LinkError('invalid_bundle')
    if (purpose === 'consent' && (typeof bundle.link_secret !== 'string' || !linkSecretShape.test(bundle.link_secret) ||
      Buffer.from(bundle.link_secret, 'base64url').toString('base64url') !== bundle.link_secret || bundle.connection_id !== undefined)) throw new LinkError('invalid_bundle')
    if (purpose === 'renewal' && (bundle.link_secret !== undefined || bundle.connection_id !== connectionID)) throw new LinkError('invalid_bundle')
    return bundle
  } finally { plain.fill(0) }
}

/**
 * The grant proof (§15.4 step 4): with the bundle's key, the grants Go serves
 * belong to the bundle's service, name exactly its numbers, and each opens
 * with `privateKey` at its epoch. Any failure is LinkError('grant_proof_failed').
 *
 * A version-3 bundle's device checks (§17.2 rules 3 and 5) are recomputed
 * from each DSK as it opens, before it is zeroed, over the scope with
 * `request` (the consent's request id or the renewal id) and `kid`: a
 * mismatch is LinkError('invalid_bundle') with `deviceCheck` set, and
 * nothing is kept. On success each number's pin is kept, `{pub, ns, epoch}`:
 * the X25519 public key of its DSK, the namespace its grant opens under and
 * the epoch, the only key a draft is ever sealed to. Every opened device key
 * is zeroed at once. Resolves to `{epochs, draftsTo}` (`draftsTo` null
 * without checks).
 */
export async function proveGrants(privateKey, bundle, { archive, fetch, timeoutMS = PROOF_TIMEOUT_MS, request, kid }) {
  const failed = () => new LinkError('grant_proof_failed')
  let grants
  try { grants = await new ArchiveClient({ serverURL: archive, workspaceID: bundle.workspace_id, token: bundle.token, timeoutMS, ...(fetch ? { fetch } : {}) }).grants() } catch { throw failed() }
  if (grants.user_id?.toLowerCase() !== bundle.service_user_id) throw failed()
  const devices = grants.grants.map(grant => grant.device_id.toLowerCase())
  if (new Set(devices).size !== devices.length || devices.length !== bundle.device_ids.length || !bundle.device_ids.every(device => devices.includes(device))) throw failed()
  const epochs = {}
  const checks = bundle.device_checks ?? null
  const draftsTo = checks ? {} : null
  const service = bytes.parseUUID(bundle.service_user_id)
  for (const grant of grants.grants) {
    if (!Number.isSafeInteger(grant.epoch) || grant.epoch < 1 || grant.epoch > 65535) throw failed()
    const device = grant.device_id.toLowerCase()
    let dsk, mismatch = false
    try {
      const ns = (grant.archive_tenant_id || bundle.workspace_id).toLowerCase()
      const namespace = bytes.parseUUID(ns)
      const row = await seal.grantRow(namespace, bytes.parseUUID(grant.device_id), service, grant.epoch)
      dsk = await seal.openDirect(privateKey, seal.Kind.DeviceGrant, namespace, row, bytes.fromBase64(grant.sealed_dsk))
      if (dsk.length !== 32) throw failed()
      if (checks) {
        const scope = deviceScope(bundle, { deviceID: device, epoch: grant.epoch, request, kid })
        const expected = Buffer.from(deviceCheck(dsk, { namespace: ns, deviceID: device, epoch: grant.epoch, scope }))
        const given = Buffer.from(typeof checks[device] === 'string' ? checks[device] : '')
        mismatch = expected.length !== given.length || !timingSafeEqual(expected, given)
        if (!mismatch) draftsTo[device] = { pub: Buffer.from(await hpke.publicFromPrivate(dsk)).toString('base64url'), ns, epoch: grant.epoch }
      }
    } catch { throw failed() } finally { dsk?.fill(0) }
    if (mismatch) throw Object.assign(new LinkError('invalid_bundle'), { deviceCheck: true })
    epochs[device] = grant.epoch
  }
  return { epochs, draftsTo }
}

/**
 * The `content` object startReader takes. `state` is the opened state, whose
 * `wipeConnection` is wrapped here so that every path that forgets a
 * connection (revoke, expiry, family death, reconciliation) also drops its
 * key, its renewals and its attachments. `attestor` is createAttestor's;
 * `fetch` reaches the archive for grant proofs and ciphertext (tests inject
 * it; the enclave uses the global one), and `jail` replaces media-jail in
 * tests.
 */
export function createContent({ state, relay, log, now = Date.now, archive, consoleURL, resource, attestor, fetch, newRecipient = mintRecipient, jail }) {
  const connkeys = createConnKeys()
  const origin = new URL(resource).origin
  const conn = id => ({ conn: fingerprint(id) })
  function dropKey(id) { if (connkeys.wipe(id)) log.event('connkey_wiped', conn(id)) }
  // startReader binds the status check once it exists (useStatusCheck).
  let statusCheck = null
  const media = createMediaService({
    log, now, archive, consoleURL, ...(fetch ? { fetch } : {}), ...(jail ? { jail } : {}),
    checkActive: { mediaStatus: id => (statusCheck ? statusCheck.mediaStatus(id) : Promise.resolve({ answer: false, media: false, media_off: [] })) },
  })
  const sending = createSendService({
    log, now, relay, consoleURL,
    checkActive: { sendStatus: id => (statusCheck ? statusCheck.sendStatus(id) : Promise.resolve({ answer: false, send: null, send_self: false })) },
  })
  /** The proof's failure, logged by what failed: a device check, or the grants. */
  const proofFailed = (id, error) => log.event(error?.deviceCheck ? 'device_check_failed' : 'grant_proof_failed', conn(id))

  const renewals = createRenewals({
    state, connkeys, log, now, resource, attestor, newRecipient,
    open: (recipient, sealed, options) => openContentBundle(recipient, sealed, { ...options, info: RENEW_INFO, purpose: 'renewal', origin, now }),
    prove: (privateKey, bundle, binding) => proveGrants(privateKey, bundle, { archive, fetch, ...binding }),
    parseRelay: body => parseRelay(body, { now }),
    renewAAD,
    onCommit: id => log.event('renewal_committed', conn(id)),
    onProofFailed: proofFailed,
  })

  // Connections whose reseal Go has not heard yet, retried with §8's backoff.
  const resealQueue = new Set()
  let resealTimer = null, resealFailures = 0, bootDeferred = false

  const wipeState = state.wipeConnection
  state.wipeConnection = id => {
    dropKey(id)
    renewals.forget(id)
    resealQueue.delete(id)
    media.wipe(id)
    sending.wipe(id)
    return wipeState(id)
  }

  /** Tells Go this connection has no key: true when Go keeps it (as `reseal`), false when Go has no live row. */
  async function requestReseal(id) {
    log.event('reseal_requested', conn(id))
    try { return await relay.reseal(id) } catch (error) {
      log.event('reseal_failed', conn(id))
      throw error
    }
  }

  function scheduleReseal() {
    if (resealTimer || resealQueue.size === 0) return
    const delay = Math.min(RESEAL_BACKOFF_MAX_MS, RESEAL_BACKOFF_START_MS * 2 ** Math.min(resealFailures, 10))
    resealTimer = setTimeout(() => { resealTimer = null; void retryReseals() }, delay)
    resealTimer.unref?.()
  }
  async function retryReseals() {
    let changed = false
    for (const id of [...resealQueue]) {
      if (!state.connections.has(id) || connkeys.has(id)) { resealQueue.delete(id); continue }
      try {
        const kept = await requestReseal(id)
        resealQueue.delete(id)
        if (!kept && state.wipeConnection(id)) changed = true
        resealFailures = 0
      } catch (error) {
        if (!(error instanceof RelayError)) throw error
        resealFailures++
        break
      }
    }
    if (changed) await state.save().catch(() => {})
    scheduleReseal()
  }

  return {
    /** Whether this process holds a key for the connection. */
    holds: id => connkeys.has(id),
    counts() {
      let connections = 0
      for (const record of state.connections.values()) if (record.kind === 'content') connections++
      return { connections, keys: connkeys.size() }
    },

    /** POST /internal/requests/{id}/bundle with `"kind": "content"`: 204 only after the grant proof. */
    async acceptBundle(pending, body) {
      const relayed = parseRelay(body, { now })
      if (pending.bundle || pending.accepting) throw new LinkError('bundle_exists', 409)
      // Go names the connection: an id that is already a connection here, or
      // another request's, would hand this consent's key to someone else's tokens.
      if (connectionTaken(state, pending, relayed.connection_id)) throw new LinkError('bad_request')
      if (!pending.recipient || relayed.kid !== pending.recipient.kid) throw new LinkError('unknown_kid')
      pending.accepting = relayed.connection_id
      try {
        const bundle = await openContentBundle(pending.recipient, relayed.sealed, {
          info: CONSENT_INFO, aad: consentAAD(pending.id, relayed.kid, pending.resource), purpose: 'consent', origin, tenant: relayed.tenant_id, now,
        })
        // What Go records and what the owner sealed must say the same about
        // attachments and sending, before anything is proven against the archive.
        if (!relayMatches(relayed, bundle)) throw new LinkError('invalid_bundle')
        const expiry = Math.min(Date.parse(bundle.expires_at), relayed.expiry)
        let proven
        try { proven = await proveGrants(pending.recipient.privateKey, bundle, { archive, fetch, request: pending.id, kid: relayed.kid }) } catch (error) {
          proofFailed(relayed.connection_id, error)
          throw error
        }
        const { epochs, draftsTo } = proven
        pending.tenant_id = relayed.tenant_id
        pending.connection_id = relayed.connection_id
        pending.bundle = { sealed: relayed.sealed, kid: relayed.kid, connection_id: relayed.connection_id, expires_at: new Date(expiry).toISOString(), kind: 'content' }
        // Only until the proof: the consent completion takes it from here.
        pending.content = { bundle, epochs, draftsTo }
        log.event('content_accepted', { ...conn(relayed.connection_id), numbers: bundle.device_ids.length })
        return { connection_id: relayed.connection_id }
      } finally { delete pending.accepting }
    },

    /** The proof posted to /mcp/authorize/complete; the opened bundle on success, else null. */
    async verifyProof(pending, proof) {
      const bundle = pending.content?.bundle
      if (!bundle) return null
      const secret = Buffer.from(bundle.link_secret, 'base64url')
      try {
        const expected = proofFor(secret, { requestID: pending.id, clientID: pending.client_id, codeChallenge: pending.code_challenge, sealed: pending.bundle.sealed })
        return proofMatches(expected, proof) ? bundle : null
      } finally { secret.fill(0) }
    },

    /** After Go activated the connection: the record's content fields, and the request's key moves into memory for it. */
    install(pending, record) {
      const { bundle, epochs, draftsTo } = pending.content
      // The deadline the owner consented to (the earlier of the bundle's and
      // Go's at relay time): Go's status answers may bring it forward, never
      // past this, and a renewal keeps it.
      // `consent_version`, `media`, the send fields and `redirect_host` are the consent's: no renewal writes them.
      Object.assign(record, {
        kind: 'content', service_user_id: bundle.service_user_id, key_mode: KEY_MODE, consent_version: bundle.consent_version, media: bundle.media === true,
        redirect_host: pending.redirect_host, epochs: { ...epochs }, consented_expires_at: pending.bundle.expires_at,
        // Sending (§17.2 rule 6), and the keys drafts are sealed to, pinned from the DSKs the proof opened.
        ...(bundle.send ? { send: bundle.send, send_self: bundle.send_self === true, send_groups: bundle.send_groups === true, drafts_to: structuredClone(draftsTo) } : {}),
      })
      connkeys.set(record.connection_id, pending.recipient.privateKey)
      delete pending.content
      delete pending.recipient
      log.event('connkey_installed', conn(record.connection_id))
    },

    serverFor: record => ({
      config: contentConfigFor(record, archive),
      provider: contentProviderFor(record, connkeys, consoleURL, {
        onStaleGrant: () => log.event('stale_grant', conn(record.connection_id)),
        ...(record.media === true ? { media: media.forConnection(record) } : {}),
        ...(record.send === 'draft' || record.send === 'direct' ? { send: sending.forConnection(record) } : {}),
      }),
    }),
    /** Pads a media connection's /mcp responses (router.mjs, §16.10). */
    padResponse,
    /** startReader's status check, which attachment calls ask for `media` and `media_off`. */
    useStatusCheck(checkActive) { statusCheck = checkActive },
    /** The attachment service: main.mjs runs its boot check and reads its counts. */
    media,
    /** The sending service: main.mjs reads its counts. */
    sending,

    /**
     * The status rules (§15.8) for a content record, given Go's live answer
     * (the caller has already turned an unknown or past-deadline row into
     * false): 'serve', 'reseal', or false to wipe the connection.
     */
    async decide(record, status) {
      const id = record.connection_id
      if (status.kind !== 'content' || (status.status !== 'active' && status.status !== 'reseal')) return false
      if (status.status === 'reseal') { dropKey(id); media.wipe(id, 'reseal'); sending.wipe(id); return 'reseal' }
      // Attachments follow every answer: off, or narrowed to the kinds still on (§16.9). Text is untouched.
      if (record.media === true) {
        if (status.media !== true) media.wipe(id, 'media_off')
        else media.narrow(id, status.media_off)
      }
      if (await renewals.commit(record, status)) return 'serve'
      if (status.service_user_id !== record.service_user_id) {
        log.event('service_mismatch', conn(id))
        return false
      }
      if (connkeys.has(id)) return 'serve'
      // Active in Go with no key here: Go must learn that the key is gone.
      try { if (!(await requestReseal(id))) return false } catch (error) {
        if (!(error instanceof RelayError)) throw error
      }
      return 'reseal'
    },
    /** Whether a staged renewal waits for Go's answer (a cached status must not hide it). */
    pending: id => renewals.staged(id),

    /**
     * At start, no content record has a key: 'keep' (Go holds it as reseal, or
     * Go is away and is retried) or 'wipe'. Once one reseal fails, the rest go
     * straight to the background retry: the boot must not wait out a relay
     * timeout for every record while Go is down.
     */
    async onBoot(record) {
      const id = record.connection_id
      const defer = () => { resealQueue.add(id); scheduleReseal(); return 'keep' }
      if (bootDeferred) return defer()
      try { return (await requestReseal(id)) ? 'keep' : 'wipe' } catch (error) {
        if (!(error instanceof RelayError)) throw error
        bootDeferred = true
        resealFailures++
        return defer()
      }
    },

    renewal: { prepare: renewals.prepare, acceptBundle: renewals.acceptBundle, commit: renewals.commit },

    /** Drops expired renewals; the 60 s content sweep calls it. */
    sweep() { renewals.sweep() },

    close() {
      if (resealTimer) { clearTimeout(resealTimer); resealTimer = null }
      resealQueue.clear()
      renewals.clear()
      media.close()
      sending.close()
      connkeys.wipeAll()
    },
    /** For tests: the key holder (the enclave never hands it out). */
    get connkeys() { return connkeys },
  }
}
