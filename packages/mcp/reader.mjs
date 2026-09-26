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
 *   awaited nor allowed to throw into the tool.
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
        }, async (raw, _epoch, namespace) => {
          const result = await operation(new Opener(api.keySource(device), bytes.parseUUID(namespace), bytes.parseUUID(device), device, await hpke.importArchiveKey(raw)))
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
      const result = await operation(new Opener(api.keySource(device), namespace, deviceBytes, device, await hpke.importArchiveKey(archive)), serviceKey)
      if (revalidate) {
        const current = await api.grants()
        const same = current.grants.find(item => item.device_id === device)
        if (current.user_id !== grants.user_id || !same || same.epoch !== grant.epoch || same.sealed_dsk !== grant.sealed_dsk || same.archive_tenant_id !== grant.archive_tenant_id) throw new ArchiveError('not_authorized', 403)
      }
      return result
    } finally { data?.fill(0); raw?.fill(0); archive?.fill(0) }
  }
  async function messages(rows, device, opener) {
    if (rows.some(row => row.device_id !== device)) throw new ArchiveError('device_mismatch')
    await opener?.prefetch(rows.map(row => row.content_key_id))
    return Promise.all(rows.map(async row => ({ ...metadata(row),
      body: row.body_sealed ? opener ? openedValue(await opener.body(row)) : locked() : omitted(),
      ...(row.media ? { attachment: { ...metadata(row).attachment, filename: row.media.filename_sealed ? opener ? openedValue(await opener.fileName(row)) : locked() : omitted() } } : {}),
      structured_content: row.payload_sealed ? { state: 'unsupported', reason: 'This MCP version does not open structured content.' } : omitted(),
    })))
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
              else hits.push({ ...metadata(row), body: body.state === 'ok' ? excerpt(body.value, query, config.max_text_chars) : opener ? openedValue(body) : body,
                ...(row.media ? { attachment: { ...metadata(row).attachment, filename: opener ? openedValue(filename) : filename } } : {}),
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
          chats: await Promise.all(reply.chats.map(async chat => ({
            uid: chat.uid, chat_key: chat.chat_key, chat_pn: chat.chat_pn, chat_lid: chat.chat_lid, keys: chat.keys, is_group: chat.is_group === true, last_ts: chat.last_ts,
            name: chat.name_sealed ? opener ? openedValue(await opener.chatName(chat)) : locked() : omitted(),
            preview: chat.last_body_sealed ? opener ? openedValue(await opener.chatPreview(chat)) : locked() : omitted(),
          }))),
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
      return withOpener(device_id, async opener => ({ workspace_id: config.workspace, message: (await messages([reply], device_id, opener))[0] }))
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
