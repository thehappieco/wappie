import { createDecipheriv, hkdfSync } from 'node:crypto'
import { ArchiveClient, ArchiveError, auth, bytes, hpke, seal } from '@whatserver2/client'
import { openContactPack, MAX_CONTACT_PACK_BYTES } from '@whatserver2/client/crypto/contactPack'
import { contactCandidates, matchesText, excerpt } from './contacts.mjs'
import { resolveRange } from './time.mjs'
import { Opener } from '@whatserver2/client/api/opener'
import { loadCredential, LocalConfigError, readerMode, readPrivateFile } from './config.mjs'

/** Contact pages of 500 a hosted-content resolve_contact reads per call, whatever matched. */
export const CONTACT_PAGES = 4
/** History reads in flight at once when search hits are labelled (local and hosted-metadata). */
export const HISTORY_CONCURRENCY = 4
const omitted = () => ({ state: 'absent' })
const textFields = ['uid', 'device_id', 'wa_id', 'chat_key', 'sender_key', 'sender_lid', 'sender_pn', 'ts', 'kind', 'type', 'source', 'target_uid', 'target_rel', 'reply_to', 'order_ts']
function metadata(message) {
  const result = {}
  for (const key of textFields) if (typeof message[key] === 'string') result[key] = message[key]
  for (const key of ['seq', 'is_from_me', 'is_group', 'view_once', 'ephemeral']) if (typeof message[key] === 'number' || typeof message[key] === 'boolean') result[key] = message[key]
  if (message.media) result.attachment = {
    media_type: message.media.media_type, mimetype: message.media.mimetype,
    file_length: message.media.file_length, download_status: message.media.download_status,
  }
  return result
}
/** A link a provider offers, if it is a plain https URL; nothing else reaches the model. */
export function safeLink(value) {
  if (typeof value !== 'string' || value.length > 2048 || /[\s<>"'`]/.test(value)) return null
  try { return new URL(value).protocol === 'https:' ? value : null } catch { return null }
}
/**
 * A message's console link from the enclave (docs/mcp-enclave.md §16.7): a
 * plain https link that begins with `${consoleURL}?`, as the instructions
 * promise the model, or null.
 */
export function consoleLink(value, consoleURL) {
  const link = safeLink(value)
  return link && typeof consoleURL === 'string' && link.startsWith(`${consoleURL}?`) ? link : null
}
const keyLockedReason = 'The authorized key could not open this content.'
const contentLockedReason = 'The key this connection holds could not open this content.'
function openedText(value, max, reason = keyLockedReason) {
  if (value.state === 'ok') return { state: 'ok', value: value.value.slice(0, max), truncated: value.value.length > max }
  if (value.state === 'tampered') return { state: 'tampered' }
  if (value.state === 'absent') return omitted()
  return { state: 'locked', reason }
}
/**
 * The only service key a hosted-content reader accepts: an `hpke.PrivateKey`
 * handle, a non-extractable X25519 CryptoKey plus its 32-byte public half.
 * Bytes or strings are refused, so no key material passes through here and
 * nothing of the handle is ever zeroed (it belongs to the provider).
 */
function serviceKeyHandle(value) {
  const key = value?.key, publicRaw = value?.publicRaw
  if (!value || typeof value !== 'object' || ArrayBuffer.isView(value) ||
    !(key instanceof CryptoKey) || key.extractable !== false || key.type !== 'private' || key.algorithm?.name !== 'X25519' ||
    !(publicRaw instanceof Uint8Array) || publicRaw.length !== 32) throw new LocalConfigError('invalid_service_key')
  return { key, publicRaw }
}
// ---- Derived records (docs/mcp-enclave.md §18.8) ------------------------------
//
// What an AI provider made of an attachment, sealed in the attested reader
// under a key derived from the DSK that opened the source; the enclave seals
// (packages/mcp-http/enclave/ai/derived.mjs), the reader and the console open.

export const DERIVED_LABEL = 'wappie-derived/v1'
/** A record's plaintext at most; the envelope adds 35 bytes. */
export const DERIVED_MAX_BYTES = 524_288
/** AI_TEXT_MAX_CHARS: a record's text, in UTF-16 code units. */
export const DERIVED_TEXT_MAX_CHARS = 200_000
export const DERIVED_FEATURES = Object.freeze(['audio', 'video', 'image', 'document'])
export const DERIVED_PROVIDERS = Object.freeze(['anthropic', 'openai', 'google'])
export const DERIVED_FLAGS = Object.freeze(['cut', 'refused', 'no_speech', 'partial', 'redo'])
export const DERIVED_MAGIC = Buffer.from('WDRV')
const DERIVED_HEADER = 7, DERIVED_IV = 12, DERIVED_TAG = 16
const uuidShape = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const invalidDerived = () => new LocalConfigError('invalid_derived')
function derivedScope(scope) {
  if (!scope || !uuidShape.test(scope.namespace ?? '') || !uuidShape.test(scope.device_id ?? '') || (scope.message_uid !== undefined && !uuidShape.test(scope.message_uid)) ||
    (scope.feature !== undefined && !DERIVED_FEATURES.includes(scope.feature)) || !Number.isInteger(scope.epoch) || scope.epoch < 1 || scope.epoch > 65535) throw invalidDerived()
  return scope
}
/** The AAD binding a record to its namespace, number, message, function and epoch. */
export function derivedAAD(scope) {
  const { namespace, device_id, message_uid, feature, epoch } = derivedScope(scope)
  if (message_uid === undefined || feature === undefined) throw invalidDerived()
  return Buffer.from(JSON.stringify(['wappie/derived', 1, namespace, device_id, message_uid, feature, epoch]))
}
/** HKDF-SHA256 over DSK(device, epoch) under `label` ‖ device ‖ u16be epoch, salt the namespace: 32 bytes the caller zeroes. */
export function numberKey(dsk, label, { namespace, device_id, epoch }) {
  if (!(dsk instanceof Uint8Array) || dsk.length !== 32) throw invalidDerived()
  derivedScope({ namespace, device_id, epoch })
  const epochBytes = Buffer.alloc(2)
  epochBytes.writeUInt16BE(epoch)
  return Buffer.from(hkdfSync('sha256', dsk, Buffer.from(bytes.parseUUID(namespace)), Buffer.concat([Buffer.from(label), Buffer.from(bytes.parseUUID(device_id)), epochBytes]), 32))
}
/** `k` of a number's derived records: 32 bytes the caller zeroes. */
export const derivedKey = (dsk, scope) => numberKey(dsk, DERIVED_LABEL, scope)

const recordKeys = ['v', 'feature', 'text', 'lang', 'provider', 'model', 'prompt_version', 'created_at', 'source_sha256', 'usage', 'flags']
const usageKeys = ['input_tokens', 'output_tokens', 'seconds']
/**
 * A record's plaintext, checked as §18.8 writes it: every field and nothing
 * else, `feature` the expected one, the text within its cap, known flags
 * once each, an empty text only for a refusal or a transcript without
 * speech. Throws LocalConfigError('invalid_derived').
 */
export function validateDerivedRecord(value, feature) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalidDerived()
  const keys = Object.keys(value)
  const { usage, flags } = value
  if (keys.some(key => !recordKeys.includes(key)) || recordKeys.some(key => key !== 'lang' && !Object.hasOwn(value, key)) ||
    value.v !== 1 || !DERIVED_FEATURES.includes(value.feature) || (feature !== undefined && value.feature !== feature) ||
    typeof value.text !== 'string' || value.text.length > DERIVED_TEXT_MAX_CHARS ||
    (value.lang !== undefined && (typeof value.lang !== 'string' || !/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}$/.test(value.lang))) ||
    !DERIVED_PROVIDERS.includes(value.provider) || typeof value.model !== 'string' || !/^[a-z0-9][a-z0-9._:-]{0,63}$/.test(value.model) ||
    typeof value.prompt_version !== 'string' || /^([a-z]+)\/[1-9]\d{0,3}$/.exec(value.prompt_version)?.[1] !== value.feature ||
    typeof value.created_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value.created_at) || !Number.isFinite(Date.parse(value.created_at)) ||
    typeof value.source_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.source_sha256) ||
    !usage || typeof usage !== 'object' || Array.isArray(usage) || Object.keys(usage).some(key => !usageKeys.includes(key)) ||
    Object.values(usage).some(count => !Number.isSafeInteger(count) || count < 0) ||
    !Array.isArray(flags) || new Set(flags).size !== flags.length || flags.some(flag => !DERIVED_FLAGS.includes(flag))) throw invalidDerived()
  const empty = value.text === '', refused = flags.includes('refused'), silent = flags.includes('no_speech')
  if ((empty && !refused && !silent) || ((refused || silent) && !empty) || (refused && silent)) throw invalidDerived()
  return value
}
/** Opens an envelope with `key` (derivedKey's) for exactly `scope`, or throws LocalConfigError('invalid_derived'). */
export function openDerivedWith(key, scope, envelope) {
  const aad = derivedAAD(scope)
  const sealed = Buffer.isBuffer(envelope) ? envelope : envelope instanceof Uint8Array ? Buffer.from(envelope.buffer, envelope.byteOffset, envelope.byteLength) : null
  if (!sealed || sealed.length < DERIVED_HEADER + DERIVED_IV + DERIVED_TAG || sealed.length > DERIVED_MAX_BYTES + DERIVED_HEADER + DERIVED_IV + DERIVED_TAG ||
    !sealed.subarray(0, 4).equals(DERIVED_MAGIC) || sealed[4] !== 1 || sealed.readUInt16BE(5) !== scope.epoch) throw invalidDerived()
  let plain
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, sealed.subarray(DERIVED_HEADER, DERIVED_HEADER + DERIVED_IV))
    decipher.setAAD(aad)
    decipher.setAuthTag(sealed.subarray(sealed.length - DERIVED_TAG))
    plain = Buffer.concat([decipher.update(sealed.subarray(DERIVED_HEADER + DERIVED_IV, sealed.length - DERIVED_TAG)), decipher.final()])
  } catch { plain?.fill(0); throw invalidDerived() }
  try {
    let parsed
    try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain)) } catch { throw invalidDerived() }
    return validateDerivedRecord(parsed, scope.feature)
  } finally { plain.fill(0) }
}
/**
 * Opens a derived record with the DSK that opened its source (§18.8), for
 * exactly this namespace, number, message, function and epoch. Anything
 * else throws LocalConfigError('invalid_derived'): another message's record,
 * a moved row, a tampered byte, a record Go sealed to the device public key.
 */
export function openDerived(dsk, scope, envelope) {
  const key = derivedKey(dsk, derivedScope(scope))
  try { return openDerivedWith(key, scope, envelope) } finally { key.fill(0) }
}
/**
 * A stored record's `sealed` as Go's JSON carries it, or null: unpadded
 * base64url as the enclave writes it (§17.7's form), or padded standard
 * base64; either only in its canonical spelling.
 */
export function derivedBytes(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil((DERIVED_MAX_BYTES + 35) / 3) * 4) return null
  const url = /^[A-Za-z0-9_-]+$/.test(value)
  if (!url && !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null
  const decoded = Buffer.from(value, url ? 'base64url' : 'base64')
  return decoded.toString(url ? 'base64url' : 'base64') === value ? decoded : null
}

/** Runs `work` over `items` with at most `limit` in flight; the first failure stops new work. */
async function bounded(items, limit, work) {
  let next = 0, failed = false
  async function worker() {
    while (!failed && next < items.length) {
      const index = next++
      try { await work(items[index], index) } catch (error) { failed = true; throw error }
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
}
/**
 * `provider` replaces every credential file read in the hosted modes:
 * - hosted-metadata (`credential_source: 'provided'`): only `token()` is ever
 *   called; content never opens, whatever the config or the provider says.
 * - hosted-content (`credential_source: 'enclave'`): `token()`, `serviceKey()`
 *   (an `hpke.PrivateKey` handle, never bytes) and `expectedEpoch(device)`
 *   (the grant epoch consented for that number). `contactPack()` is never
 *   asked: there is no personal snapshot in this mode. The optional
 *   `onStaleGrant({device_id})` is told, best effort, each time a grant is
 *   refused as `stale_grant`, so the enclave can log the event; it is neither
 *   awaited nor allowed to throw into the tool. On a connection whose sealed
 *   consent includes attachments (`config.media`), `media` is the enclave's
 *   `{host, why(row), openURL(row), consoleURL, open(request, archive), resultMaxBytes}`
 *   (docs/mcp-enclave.md §16.5): `openAttachment` hands it the call and an
 *   `archive` of the two reads it needs, every attachment the reader
 *   describes says whether it opens, and get_message's also names the
 *   console link where the user sees the original. On a reader that
 *   declares ai_v1 (§18.12) `media` also has `ai: true` and
 *   `derivedOf(row)` (the functions whose AI result is stored, which
 *   get_message adds as `derived`), and the `archive` gains `derived(row,
 *   items)`, which opens a stored result with this connection's own grant.
 *   On a connection whose
 *   sealed consent includes sending (`config.send`), `send` is the enclave's
 *   `{mode, self, consoleURL, draft(input, archive), sendSelf(input),
 *   outgoing(query), observe(device, chatKey, text)}` (§17.8): the three
 *   sending methods hand it the call, `draft` with an `archive` whose
 *   `chat()` looks the named chat up, and every message body, caption and
 *   file name the reader returns is shown to `observe` first, the source of
 *   the cross-chat fingerprints (§17.11).
 * A local (files) config ignores the provider.
 */
export async function createReader(config, provider) {
  const mode = readerMode(config)
  // Source URLs name the archive the reader talks to. A hosted reader's is an
  // internal address the assistant can neither reach nor has any use for.
  const hosted = mode !== 'local'
  const content = mode === 'hosted-content'
  // Whether this reader opens anything. A provided credential never does, even
  // on a hand-built config that sets allow_plaintext: the guarantee is the mode's.
  const opens = mode !== 'hosted-metadata' && config.allow_plaintext === true
  /**
   * Why a value is locked, in the words that are true of this connection. A
   * provided credential can never open content, so the reason must not read
   * like a setting somebody forgot to turn on; a local install with plaintext
   * off really did leave one off; the attested reader tried and its key failed.
   */
  const lockedReason = mode === 'hosted-metadata'
    ? 'Sealed content. This connection reads metadata only, and the key that opens it never leaves the devices of the user.'
    : content ? contentLockedReason : 'Encrypted content. Local reading has not been enabled for this MCP server.'
  const openedReason = content ? contentLockedReason : keyLockedReason
  const openedValue = value => openedText(value, config.max_text_chars, openedReason)
  const locked = () => ({ state: 'locked', reason: lockedReason })
  const credential = await loadCredential(config, provider)
  if (content && (typeof provider.serviceKey !== 'function' || typeof provider.expectedEpoch !== 'function')) throw new LocalConfigError('credential_provider_required')
  // Attachments open only on the attested reader, for a consent that includes them.
  const media = content && config.media === true && typeof provider.media?.open === 'function' ? provider.media : null
  // Sending too, for a consent that includes it (§17.8).
  const send = content && (config.send === 'draft' || config.send === 'direct') && typeof provider.send?.draft === 'function' ? provider.send : null
  /**
   * Every opened text of one chat that goes back to the assistant is shown to
   * the fingerprint store before it leaves (§17.11), best effort: a failure
   * there never fails a read.
   */
  function observe(device, chatKey, value) {
    if (!send || value?.state !== 'ok' || typeof chatKey !== 'string') return
    try { send.observe(device, chatKey, value.value) } catch { /* best effort */ }
  }
  const api = new ArchiveClient({ serverURL: config.server, workspaceID: config.workspace, token: credential.token })
  const allowed = device => !config.device_ids || config.device_ids.includes(device)
  function permit(device) { if (!allowed(device)) throw new ArchiveError('not_authorized', 403) }
  /** The refusal for a grant this connection's key no longer fits, after telling the provider (best effort). */
  function staleGrant(device) {
    try {
      const told = provider?.onStaleGrant?.({ device_id: device })
      if (typeof told?.then === 'function') told.then(undefined, () => {})
    } catch {}
    return new ArchiveError('stale_grant')
  }
  /**
   * Runs `operation(opener, serviceKey, keys)` with the number's grant opened
   * as every read opens it (grants fetched now, the consented epoch, the
   * service key). `keys` is `{dsk, namespace, epoch}`: the raw DSK, valid only
   * until `operation` settles (it is zeroed then), and the namespace and epoch
   * of the grant that opened it, which the AI results' keys derive from
   * (docs/mcp-enclave.md §18.8).
   */
  async function withOpener(device, operation, revalidate = false) {
    permit(device)
    if (!opens) {
      const result = await operation(null)
      if (revalidate) await api.listChats(device, { limit: 1 })
      return result
    }
    if (credential.kind === 'session') {
      const password = await readPrivateFile(config.password_file)
      try {
        return await auth.withDeviceKey({ serverURL: config.server, token: credential.token,
          email: credential.email, password: password.toString('utf8').replace(/\r?\n$/, ''), deviceID: device,
          expectedTenantID: config.workspace, expectedUserID: credential.userID,
          signal: AbortSignal.timeout(30_000),
          maxKDF: { m: 128 * 1024, t: 5, p: 4 }, maxAuthResponseBytes: 4 * 1024 * 1024,
        }, async (raw, epoch, namespace) => {
          const result = await operation(new Opener(api.keySource(device), bytes.parseUUID(namespace), bytes.parseUUID(device), device, await hpke.importArchiveKey(raw)),
            undefined, { dsk: raw, namespace: namespace.toLowerCase(), epoch })
          if (revalidate) await api.listChats(device, { limit: 1 })
          return result
        })
      } finally { password.fill(0) }
    }
    // Fetch grants on every operation. A locally held key never bypasses a
    // revoked grant, a restricted API key, or current workspace permissions.
    const grants = await api.grants()
    if (grants.user_id !== config.service_user_id) throw new ArchiveError('account_mismatch')
    const grant = grants.grants.find(item => item.device_id === device)
    if (!grant) throw new ArchiveError('not_authorized', 403)
    if (!Number.isSafeInteger(grant.epoch) || grant.epoch < 1 || grant.epoch > 65535) throw new ArchiveError('invalid_grant')
    // The attested reader holds a key for the grants consented to. Another
    // epoch means the number's access changed since; only a renewal fixes that.
    if (content && grant.epoch !== await provider.expectedEpoch(device)) throw staleGrant(device)
    let data, raw, archive
    try {
      let serviceKey
      if (content) serviceKey = serviceKeyHandle(await provider.serviceKey())
      else {
        data = await readPrivateFile(config.service_key_file)
        const encoded = data.toString('utf8').trim()
        if (!/^[A-Za-z0-9_-]{43}$/.test(encoded)) throw new LocalConfigError('invalid_service_key')
        raw = Buffer.from(encoded, 'base64url')
        if (raw.length !== 32 || raw.toString('base64url') !== encoded) throw new LocalConfigError('invalid_service_key')
        serviceKey = await hpke.importArchiveKey(raw)
      }
      const namespace = bytes.parseUUID(grant.archive_tenant_id || config.workspace)
      const deviceBytes = bytes.parseUUID(device)
      const row = await seal.grantRow(namespace, deviceBytes, bytes.parseUUID(grants.user_id), grant.epoch)
      if (content) {
        try { archive = await seal.openDirect(serviceKey, seal.Kind.DeviceGrant, namespace, row, bytes.fromBase64(grant.sealed_dsk)) }
        catch { throw staleGrant(device) }
      } else archive = await seal.openDirect(serviceKey, seal.Kind.DeviceGrant, namespace, row, bytes.fromBase64(grant.sealed_dsk))
      const result = await operation(new Opener(api.keySource(device), namespace, deviceBytes, device, await hpke.importArchiveKey(archive)), serviceKey,
        { dsk: archive, namespace: (grant.archive_tenant_id || config.workspace).toLowerCase(), epoch: grant.epoch })
      if (revalidate) {
        const current = await api.grants()
        const same = current.grants.find(item => item.device_id === device)
        if (current.user_id !== grants.user_id || !same || same.epoch !== grant.epoch || same.sealed_dsk !== grant.sealed_dsk || same.archive_tenant_id !== grant.archive_tenant_id) throw new ArchiveError('not_authorized', 403)
      }
      return result
    } finally { data?.fill(0); raw?.fill(0); archive?.fill(0) }
  }
  /**
   * A row's attachment with its opened filename. On a media connection it also
   * carries the dimensions and length the row has, and whether open_attachment
   * would open it (`openable`, and `why` not when false), from the row alone;
   * with `link` (get_message), `open_url` too: the console link where the user
   * sees or hears the original (§16.7).
   */
  function attachmentOf(row, filename, link = false) {
    const attachment = { ...metadata(row).attachment, filename }
    if (!media) return attachment
    for (const key of ['seconds', 'width', 'height']) if (typeof row.media[key] === 'number') attachment[key] = row.media[key]
    const why = media.why(row)
    attachment.openable = why === null
    if (why !== null) attachment.why = why
    const url = link ? consoleLink(media.openURL?.(row), media.consoleURL) : null
    if (url) attachment.open_url = url
    return attachment
  }
  async function messages(rows, device, opener, { link = false } = {}) {
    if (rows.some(row => row.device_id !== device)) throw new ArchiveError('device_mismatch')
    await opener?.prefetch(rows.map(row => row.content_key_id))
    return Promise.all(rows.map(async row => {
      const body = row.body_sealed && opener ? await opener.body(row) : null
      const filename = row.media?.filename_sealed && opener ? await opener.fileName(row) : null
      observe(device, row.chat_key, body)
      observe(device, row.chat_key, filename)
      return { ...metadata(row),
        body: row.body_sealed ? opener ? openedValue(body) : locked() : omitted(),
        ...(row.media ? { attachment: attachmentOf(row, row.media.filename_sealed ? opener ? openedValue(filename) : locked() : omitted(), link) } : {}),
        structured_content: row.payload_sealed ? { state: 'unsupported', reason: 'This MCP version does not open structured content.' } : omitted(),
      }
    }))
  }
  async function personalContacts(serviceKey) {
    // A personal snapshot is a local file only. No hosted mode has one, and
    // none asks the provider: the attested reader leaves the snapshot out.
    if (hosted || !config.contacts_file) return null
    const scope = { server_url: config.server, workspace_id: config.workspace, service_user_id: config.service_user_id, device_ids: config.device_ids }
    if (!serviceKey) throw new LocalConfigError('contact_pack_requires_service_scope')
    const data = await readPrivateFile(config.contacts_file, { maxBytes: MAX_CONTACT_PACK_BYTES })
    try { return await openContactPack(serviceKey, JSON.parse(data.toString('utf8')), scope) }
    catch { throw new LocalConfigError('invalid_contact_pack') }
    finally { data.fill(0) }
  }
  async function historyStatus(row, device) {
    try {
      const history = await api.history(row.uid)
      if (history.device_id !== device) throw new ArchiveError('device_mismatch')
      const version = history.versions.find(item => item.message.uid === row.uid)
      const latest = history.versions.at(-1)
      return { state: history.deletion ? 'deleted' : version ? latest?.message.uid === row.uid ? 'latest_archived' : 'superseded' : 'control_event',
        revision: version?.revision, valid_from: version?.from, valid_until: version?.until,
        latest_uid: latest?.message.uid, deleted_at: history.deletion?.at }
    } catch (error) {
      if (error instanceof ArchiveError && error.status === 404) return { state: 'unavailable' }
      throw error
    }
  }
  async function archiveRead(capability, operation) {
    try { return await operation() }
    catch (error) {
      if (error instanceof ArchiveError && error.status === 404) throw new ArchiveError(`${capability}_not_found`, 404)
      throw error
    }
  }
  async function scan(input, activity = false) {
    const { device_id, query = '', limit = 20, before } = input
    permit(device_id)
    // Same refusal, two different truths: a local install can be opted in, a
    // provided credential never can, and the code is what the model quotes.
    if (query && !opens) throw new LocalConfigError(mode === 'hosted-metadata' ? 'content_sealed_metadata_only' : 'plaintext_required_for_text_search')
    /**
     * Where the archive must not learn which messages matched. Stopping at
     * `limit`, or asking for the history of each hit, would tell the server
     * which rows hold the words, so a text query on the attested reader scans
     * the whole budget and labels no hit: its REST calls depend only on the
     * range, the filters and the budget.
     */
    const fixedWindow = content && Boolean(query) && !activity
    if (before && (!input.from || !input.until || input.period)) throw new LocalConfigError('continuation_requires_fixed_range')
    let range
    try { range = resolveRange(input, config.timezone) } catch { throw new LocalConfigError('invalid_time_range') }
    return withOpener(device_id, async opener => {
      const counters = { examined: 0, matched: 0, locked: 0, tampered: 0, structured_content_unsearched: 0, missing_sent_time: 0 }
      const hits = [], groups = new Map(), seen = new Set()
      let cursor = before, hasMore = false, stopped = false, omittedHits = 0, deadlineReached = false
      const deadline = Date.now() + 45_000
      const budget = config.max_scan_messages
      while (counters.examined < budget && !stopped) {
        const reply = await archiveRead('archive_scan', () => api.scanMessages(device_id, {
          from: range.from, until: range.until, limit: Math.min(100, budget - counters.examined), before: cursor,
          chatKey: input.chat_key, senderKeys: input.sender_keys, direction: input.direction, type: input.type,
          kind: activity ? 'message' : input.kind,
        }))
        if (!reply.messages.length && reply.has_more) throw new ArchiveError('invalid_response')
        const rows = [...reply.messages].reverse()
        if (!activity) await opener?.prefetch(rows.map(row => row.content_key_id))
        hasMore = reply.has_more
        for (let index = 0; index < rows.length; index++) {
          const row = rows[index]
          const key = `${row.order_ts}/${row.seq}`
          if (seen.has(key) || (cursor && cursor.ts === row.order_ts && cursor.seq === row.seq)) throw new ArchiveError('invalid_response')
          seen.add(key)
          counters.examined++
          if (!row.ts) counters.missing_sent_time++
          if (row.payload_sealed) counters.structured_content_unsearched++
          cursor = { ts: row.order_ts, seq: row.seq }
          const hasAttachment = Boolean(row.media)
          if (input.has_attachment !== undefined && input.has_attachment !== hasAttachment) {
            if (Date.now() > deadline) { hasMore = index < rows.length - 1 || reply.has_more; stopped = deadlineReached = true; break }
            continue
          }
          if (activity) {
            const groupKey = JSON.stringify([row.chat_key, row.sender_key || row.sender_pn || row.sender_lid || '', row.is_from_me])
            const item = groups.get(groupKey) || { chat_key: row.chat_key, sender_key: row.sender_key, sender_pn: row.sender_pn, sender_lid: row.sender_lid,
              is_group: row.is_group === true, direction: row.is_from_me ? 'outgoing' : 'incoming', archived_messages: 0,
              first_order_ts: row.order_ts, last_order_ts: row.order_ts, sample_uid: row.uid }
            item.archived_messages++; item.first_order_ts = row.order_ts
            groups.set(groupKey, item)
            counters.matched++
          } else {
            const body = row.body_sealed ? opener ? await opener.body(row) : locked() : omitted()
            const filename = row.media?.filename_sealed ? opener ? await opener.fileName(row) : locked() : omitted()
            for (const value of [body, filename]) if (value.state === 'locked' || value.state === 'tampered') counters[value.state]++
            const searchable = [body, filename].filter(value => value.state === 'ok').map(value => value.value).join('\n')
            if (!query || matchesText(searchable, query)) {
              counters.matched++
              if (fixedWindow && hits.length >= limit) omittedHits++
              else {
                observe(device_id, row.chat_key, body)
                observe(device_id, row.chat_key, filename)
                hits.push({ ...metadata(row), body: body.state === 'ok' ? excerpt(body.value, query, config.max_text_chars) : opener ? openedValue(body) : body,
                  ...(row.media ? { attachment: attachmentOf(row, opener ? openedValue(filename) : filename) } : {}),
                  structured_content: row.payload_sealed ? { state: 'unsupported' } : omitted(),
                  // Filled after the scan (see below); the key keeps its place.
                  archive_status: fixedWindow ? { state: 'not_checked' } : undefined,
                  // A local install's server is the address its user reads the
                  // archive at, so the citation links to it. A hosted reader's is
                  // the API on the host's loopback: an internal address the
                  // assistant can neither reach nor has any use for.
                  source: { ...(hosted ? {} : { server: config.server, url: `${config.server}/v1/messages/${row.uid}` }),
                    workspace_id: config.workspace, device_id, message_uid: row.uid, chat_key: row.chat_key },
                })
              }
            }
          }
          const deadlinePassed = Date.now() > deadline
          if ((!activity && !fixedWindow && hits.length >= limit) || deadlinePassed) {
            hasMore = index < rows.length - 1 || reply.has_more
            stopped = true
            deadlineReached = deadlinePassed
            break
          }
        }
        if (!hasMore || stopped) break
        if (!reply.next_ts || reply.next_seq === undefined) throw new ArchiveError('invalid_response')
        cursor = { ts: reply.next_ts, seq: reply.next_seq }
      }
      // Revision status of each hit, after the scan and a few at a time. Only
      // where the hits are no secret from the archive: a local reader, the
      // metadata reader, and a query-less search, which selects by metadata
      // the server already holds.
      if (!fixedWindow) await bounded(hits, HISTORY_CONCURRENCY, async hit => { hit.archive_status = await historyStatus(hit, device_id) })
      const next = hasMore && cursor ? { ...input, period: undefined, from: range.from, until: range.until, before: cursor } : undefined
      return { workspace_id: config.workspace, device_id, range,
        ...(activity ? { activity: [...groups.values()], counting: 'Archived original message events in this page only, grouped by chat, sender and direction. Counts are not totals for the full archive.' } : { messages: hits }),
        ...(fixedWindow ? { omitted_hits: omittedHits } : {}),
        coverage: { ...counters, scan_limit: budget, interval_exhausted: !hasMore, live_read: true,
          ...(query ? { text_search_complete: !hasMore && !counters.locked && !counters.tampered && !counters.structured_content_unsearched } : {}),
          ...(fixedWindow ? { fixed_window: true, deadline_reached: deadlineReached } : {}),
          note: fixedWindow
            ? 'A text query examines a fixed window of archived messages per call, whatever it finds: follow next for the rest of the range, and narrow the range or filters when omitted_hits is above zero. Hits are not checked against later edits or deletions (archive_status not_checked); use list_revisions before calling one current. This reads the stored archive, not complete WhatsApp history. Missing sent times use archive arrival time. Structured payloads and attachment contents are not searched.'
            : 'This reads the stored archive, not complete WhatsApp history. Concurrent backfills can require a rescan. Missing sent times use archive arrival time. Structured payloads and attachment contents are not searched.' },
        has_more: hasMore, ...(next ? { next } : {}),
      }
    }, true)
  }
  /** A message with an attachment on `device`, or `attachment_not_found` (a 404, another number, no `media`). */
  async function attachmentRow(device, uid) {
    let row
    try { row = await api.getMessage(uid) } catch (error) {
      if (error instanceof ArchiveError && error.status === 404) throw new ArchiveError('attachment_not_found', 404)
      throw error
    }
    if (row.device_id !== device || !row.media || typeof row.media !== 'object') throw new ArchiveError('attachment_not_found', 404)
    return row
  }
  /**
   * An attachment's media key (`what` 'key') or sealed preview
   * ('thumbnail'), and its filename and caption, opened with `opener`
   * (§16.5's `archive.open`). The caller owns the bytes and zeroes them.
   */
  async function openedMedia(opener, row, what) {
    await opener.prefetch([row.content_key_id])
    const [sealed, filename, caption] = await Promise.all([what === 'key' ? opener.mediaKey(row) : opener.thumbnail(row), opener.fileName(row), opener.body(row)])
    const text = value => (value.state === 'ok' ? value.value : null)
    const opened = { filename: text(filename), caption: text(caption) }
    if (sealed.state === 'tampered') throw new ArchiveError('attachment_tampered')
    if (sealed.state === 'locked') throw new ArchiveError('attachment_locked')
    if (sealed.state === 'ok') opened[what] = sealed.value
    else if (what === 'key') throw new ArchiveError('attachment_unverifiable')
    return opened
  }
  /** The user part of a JID or phone number: before any '@' and any ':' device suffix. */
  const userOf = jid => (typeof jid === 'string' ? jid.split('@')[0].split(':')[0] : '')
  /**
   * One chat of a number by key (§17.3's filter), for a draft: null when the
   * number has none, else its keys, whether it is a group or the number's
   * own chat (`<pn>@s.whatsapp.net` or `<lid>@lid`, §17.5), and its name
   * opened as list_chats opens it (null when it has none or it stays locked).
   */
  async function chatByKey(device, chatKey) {
    const reply = await api.listChats(device, { chatKey })
    const chat = reply.chats[0]
    if (!chat) return null
    const number = (await api.listDevices()).devices.find(item => item.id === device)
    const own = [userOf(number?.pn) && `${userOf(number.pn)}@s.whatsapp.net`, userOf(number?.lid) && `${userOf(number.lid)}@lid`].filter(Boolean)
    const keys = [...new Set([chat.chat_key, chat.chat_pn, chat.chat_lid, ...(Array.isArray(chat.keys) ? chat.keys : [])].filter(key => typeof key === 'string' && key))]
    return withOpener(device, async opener => {
      await opener?.prefetch([chat.name_key_id])
      const name = chat.name_sealed && opener ? await opener.chatName(chat) : null
      return { chat_key: chat.chat_key, keys, is_group: chat.is_group === true, own: chat.is_group !== true && keys.some(key => own.includes(key)),
        name: name?.state === 'ok' ? name.value : null }
    })
  }
  return {
    searchMessages(input) { return scan(input) },
    activitySummary(input) { return scan(input, true) },
    async resolveContact({ device_id, query, limit = 20, after_key }) {
      permit(device_id)
      // Without plaintext no archived name is ever readable and no personal
      // snapshot exists (config.mjs refuses contacts_file without it), so a
      // query that names somebody can never match, however many pages are
      // fetched. Answering with a next cursor made the assistant walk every
      // contact in the archive — six thousand of them, a dozen calls — to learn
      // nothing. A phone number has no letters and an explicit identifier keeps
      // its '@'; a name needs neither, and that is the whole test.
      if (!opens && /\p{L}/u.test(query) && !query.includes('@')) {
        return { workspace_id: config.workspace, device_id, candidates: [], omitted_candidates: 0, ambiguous: false, names_searchable: false,
          instruction: mode === 'hosted-metadata'
            ? 'Contact names are sealed on this connection, so no name can match and paging would find nothing. Tell the user so, ask for the phone number, and resolve that instead.'
            : 'Contact names stay locked while local plaintext access is off, so no name can match. Resolve a phone number instead, or ask the user to enable plaintext in the local configuration.',
          coverage: { archived_contacts_examined: 0, unavailable_names: 0, archive_has_more: false, personal_snapshot: null, complete: false,
            note: 'A name query was not run: this connection cannot read names. The empty result says nothing about whether the contact exists.' } }
      }
      return withOpener(device_id, async (opener, serviceKey) => {
        // The attested reader reads a fixed number of pages whatever matched, so
        // the archive cannot tell from the paging which contact was looked for.
        // Elsewhere one page per call, as the names are local or not readable.
        const pages = content ? CONTACT_PAGES : 1
        const contacts = []
        let reply, afterKey = after_key
        for (let page = 0; page < pages; page++) {
          reply = await archiveRead('archive_contacts', () => api.listContacts(device_id, { limit: 500, afterKey }))
          await opener?.prefetch(reply.contacts.map(contact => contact.content_key_id))
          contacts.push(...reply.contacts)
          if (!reply.has_more) break
          afterKey = reply.next_key
        }
        const pack = await personalContacts(serviceKey)
        let unavailable = 0
        const archived = []
        for (const contact of contacts) {
          const names = []
          if (opener) {
            for (const [kind, value] of Object.entries(await opener.contactNames(contact))) {
              if (value.state === 'ok') names.push({ name: value.value.slice(0, 256), source: `archive_${kind}` })
              else if (value.state !== 'absent') unavailable++
            }
          } else if (contact.full_name_sealed || contact.push_name_sealed || contact.business_name_sealed) unavailable++
          archived.push({ ...contact, names })
        }
        const result = contactCandidates(archived, pack?.contacts || [], query, limit)
        return { workspace_id: config.workspace, device_id, ...result,
          coverage: { archived_contacts_examined: contacts.length, unavailable_names: unavailable,
            archive_has_more: reply.has_more, personal_snapshot: pack ? { created_at: pack.created_at, contacts: pack.contacts.length } : null,
            complete: !reply.has_more && !result.omitted_candidates && !unavailable,
            note: 'Personal contacts are a snapshot, not a synchronized address book. Narrow the query when candidates are omitted. An empty incomplete result does not prove a contact is absent.' },
          ...(reply.has_more ? { next: { device_id, query, limit, after_key: reply.next_key } } : {}),
        }
      }, true)
    },
    async listNumbers() {
      const reply = await api.listDevices()
      // plaintext_enabled alone reads like a switch left off; plaintext_available
      // says whether the connection has a switch at all.
      return { workspace_id: config.workspace, plaintext_enabled: opens, plaintext_available: mode !== 'hosted-metadata',
        timezone: config.timezone, now: new Date().toISOString(),
        numbers: reply.devices.filter(device => allowed(device.id)).map(device => ({
          id: device.id, name: device.label || device.push_name || device.pn || 'Unnamed number',
          phone: device.pn, status: device.status, paused: device.paused === true,
        })),
      }
    },
    async listChats({ device_id, limit }) {
      permit(device_id)
      const reply = await api.listChats(device_id, { limit })
      return withOpener(device_id, async opener => {
        await opener?.prefetch(reply.chats.flatMap(chat => [chat.name_key_id, chat.last_body_key_id]))
        return { workspace_id: config.workspace, device_id, truncated: reply.truncated,
          chats: await Promise.all(reply.chats.map(async chat => {
            const preview = chat.last_body_sealed && opener ? await opener.chatPreview(chat) : null
            // A preview is the chat's last message body: a source, unlike its name.
            observe(device_id, chat.chat_key, preview)
            return {
              uid: chat.uid, chat_key: chat.chat_key, chat_pn: chat.chat_pn, chat_lid: chat.chat_lid, keys: chat.keys, is_group: chat.is_group === true, last_ts: chat.last_ts,
              name: chat.name_sealed ? opener ? openedValue(await opener.chatName(chat)) : locked() : omitted(),
              preview: chat.last_body_sealed ? opener ? openedValue(preview) : locked() : omitted(),
            }
          })),
        }
      })
    },
    async listMessages({ device_id, chat_key, limit, before }) {
      permit(device_id)
      const reply = await api.listMessages(device_id, { chatKey: chat_key, limit, before })
      return withOpener(device_id, async opener => ({ workspace_id: config.workspace, device_id, chat_key: reply.chat_key,
        messages: await messages(reply.messages, device_id, opener), has_more: reply.has_more,
        ...(reply.has_more && reply.next_ts && reply.next_seq !== undefined ? { next: { ts: reply.next_ts, seq: reply.next_seq } } : {}),
      }))
    },
    async getMessage({ device_id, uid }) {
      permit(device_id)
      const reply = await api.getMessage(uid)
      if (reply.device_id !== device_id) throw new ArchiveError('not_authorized', 403)
      const result = await withOpener(device_id, async opener => ({ workspace_id: config.workspace, message: (await messages([reply], device_id, opener, { link: true }))[0] }))
      // On readers with AI (§18.12): the functions whose result is stored for
      // this attachment, from one derived read; lists and searches leave it out.
      if (result.message.attachment && typeof media?.derivedOf === 'function') {
        try {
          const features = await media.derivedOf(reply)
          if (Array.isArray(features) && features.length) result.message.attachment.derived = features
        } catch { /* best effort: the message reads as before */ }
      }
      return result
    },
    /**
     * open_attachment (docs/mcp-enclave.md §16.5): the enclave's
     * `media.open(request, archive)` for this call. `archive.row()` reads the
     * message (another number's, or one without an attachment, is
     * `attachment_not_found`, like a 404); `archive.open(row, what)` opens,
     * with the grants of every read, the media key (`what` 'key') or the
     * sealed preview ('thumbnail'), plus the filename and caption. The caller
     * owns the bytes and zeroes them.
     */
    async openAttachment({ device_id, uid, cursor, pages, images = true }) {
      permit(device_id)
      if (!media) throw new ArchiveError('media_not_allowed')
      let chat = null
      const archive = {
        async row() {
          const row = await attachmentRow(device_id, uid)
          chat = row.chat_key
          return row
        },
        open(row, what) {
          return withOpener(device_id, opener => openedMedia(opener, row, what))
        },
        /**
         * The first of Go's stored records for this message (§18.12) that this
         * connection's own grant opens, as `{feature, text, lang?, provider,
         * model, prompt_version, created_at, source_sha256, usage, flags}`, or
         * null. `items` are `{message_uid, feature, device_id, epoch, sealed}`;
         * one of another message, number or epoch is skipped, and so is one
         * the key cannot open.
         */
        derived(row, items) {
          return withOpener(device_id, async (_opener, _serviceKey, keys) => {
            for (const item of Array.isArray(items) ? items : []) {
              const sealed = derivedBytes(item?.sealed)
              if (!sealed || !keys || item.message_uid !== row.uid || item.device_id !== device_id || item.epoch !== keys.epoch || !DERIVED_FEATURES.includes(item.feature)) continue
              try {
                const { v: _v, ...record } = openDerived(keys.dsk, { namespace: keys.namespace, device_id, message_uid: row.uid, feature: item.feature, epoch: item.epoch }, sealed)
                return record
              } catch { /* another key's record: the next one */ } finally { sealed.fill(0) }
            }
            return null
          })
        },
      }
      const result = await media.open({ device_id, uid, cursor, pages, images }, archive)
      if (send) {
        // An answer the enclave kept (a cache, or a parallel call's open) read
        // no row in this call: the message says which chat its text belongs to.
        if (chat === null) {
          try { const row = await api.getMessage(uid); if (row.device_id === device_id) chat = row.chat_key } catch { /* best effort */ }
        }
        for (const text of [result.body, result.header?.filename, result.header?.caption]) if (typeof text === 'string' && text) observe(device_id, chat, { state: 'ok', value: text })
      }
      return result
    },
    /**
     * The enclave's AI jobs (docs/mcp-enclave.md §18.10), on the attested
     * reader only, which builds this reader for an `ai` record and never
     * serves it as an MCP server: every open uses that record's own grants
     * (I2). `work` runs inside one withOpener of `device_id` and gets
     * `{row(), open(row, what), keys}`: the message row (as open_attachment
     * reads it), its media key or preview with filename and caption (the
     * caller zeroes them), and `{dsk, namespace, epoch}` of the grant that
     * opens this content, which the job tags and seals with (I3a, I5). The
     * DSK is zeroed when `work` settles.
     */
    async aiJob({ device_id, uid }, work) {
      permit(device_id)
      if (!content) throw new LocalConfigError('credential_provider_required')
      return withOpener(device_id, (opener, _serviceKey, keys) => work({ row: () => attachmentRow(device_id, uid), open: (row, what) => openedMedia(opener, row, what), keys }))
    },
    /**
     * The DSKs of several of this record's numbers from one grants read (the
     * dedupe lookup, §18.8): `work(device, {dsk, namespace, epoch})` runs in
     * order for each device whose grant opens at its consented epoch, and the
     * others are skipped. Each DSK is zeroed once its call settles.
     */
    async aiKeys(devices, work) {
      if (!content) throw new LocalConfigError('credential_provider_required')
      for (const device of devices) permit(device)
      const grants = await api.grants()
      if (grants.user_id !== config.service_user_id) throw new ArchiveError('account_mismatch')
      const serviceKey = serviceKeyHandle(await provider.serviceKey())
      for (const device of devices) {
        const grant = grants.grants.find(item => item.device_id === device)
        if (!grant || !Number.isSafeInteger(grant.epoch) || grant.epoch !== await provider.expectedEpoch(device)) continue
        const ns = (grant.archive_tenant_id || config.workspace).toLowerCase()
        let dsk
        try {
          const namespace = bytes.parseUUID(ns)
          const row = await seal.grantRow(namespace, bytes.parseUUID(device), bytes.parseUUID(grants.user_id), grant.epoch)
          try { dsk = await seal.openDirect(serviceKey, seal.Kind.DeviceGrant, namespace, row, bytes.fromBase64(grant.sealed_dsk)) } catch { continue }
          await work(device, { dsk, namespace: ns, epoch: grant.epoch })
        } finally { dsk?.fill(0) }
      }
    },
    /**
     * draft_message (§17.8): the enclave runs every step. `archive.chat()` is
     * step 5's lookup, asked only once the cheaper refusals passed: the chat
     * under that key on that number or null, its name opened as list_chats
     * opens it, every key it is known by, and whether it is the number's own.
     */
    async draftMessage(input) {
      permit(input.device_id)
      if (!send) throw new ArchiveError('send_not_allowed')
      return send.draft(input, { chat: () => chatByKey(input.device_id, input.chat_key) })
    },
    /** send_to_self (§17.8): the enclave runs every step; Go resolves the own chat. */
    async sendToSelf(input) {
      permit(input.device_id)
      if (!send || config.send_self !== true || typeof send.sendSelf !== 'function') throw new ArchiveError('send_not_allowed')
      return send.sendSelf(input)
    },
    /** list_outgoing (§17.8): a page of the connection's ledger, from Go through the enclave. */
    async listOutgoing(input) {
      if (input.device_id !== undefined) permit(input.device_id)
      if (!send) throw new ArchiveError('send_not_allowed')
      return send.outgoing(input)
    },
    async listRevisions({ device_id, uid, limit = 50 }) {
      permit(device_id)
      const reply = await api.history(uid)
      if (reply.device_id !== device_id) throw new ArchiveError('not_authorized', 403)
      return withOpener(device_id, async opener => {
        const versions = reply.versions.slice(0, limit)
        const opened = await messages(versions.map(version => version.message), device_id, opener)
        return { workspace_id: config.workspace, device_id, chat_key: reply.chat_key,
          revisions: versions.map((version, index) => ({ revision: version.revision, from: version.from, until: version.until, message: opened[index] })),
          truncated: reply.versions.length > limit, deleted: Boolean(reply.deletion),
        }
      })
    },
  }
}
