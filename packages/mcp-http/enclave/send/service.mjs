// Sending in the attested reader (docs/mcp-enclave.md §17): the one object
// content.mjs builds, which gives each connection whose sealed consent
// includes sending its `provider.send` (§17.8's interface) and holds what
// sending keeps in memory: the cross-chat fingerprints, dedupe and the
// enclave's own counts, all wiped with the connection.
//
// Go decides every draft and send (§17.5, §17.7); the enclave repeats first
// what it can see, so that the model hears early and a refusal costs no
// call: the sealed consent and Go's status (the gate), the text rules, its
// own counts. Everything it refuses itself that Go keeps a code for goes to
// the ledger through the refusals route, best effort. Every call to Go
// carries the connection's own key.
import { ArchiveError } from '@whatserver2/client'
import { LocalConfigError } from '@whatserver2/mcp/config'
import { fingerprint } from '../../log.mjs'
import { CONSOLE_URL } from '../constants.mjs'
import { messageURLs } from '../provider.mjs'
import { createDedupe } from './dedupe.mjs'
import { createDrafts } from './drafts.mjs'
import { createFingerprints } from './fingerprints.mjs'
import { LEDGER_ROUTE_TIMEOUT_MS } from './policy.mjs'
import { createSends, createWindows } from './sends.mjs'

/** A refusal the reader words (§17.8): an ArchiveError with `retry_at`, `why` or `keep` as own properties. */
export function refusal(code, extra = {}) {
  const error = new ArchiveError(code)
  for (const [name, value] of Object.entries(extra)) if (value !== undefined) error[name] = value
  return error
}
const safeCode = error => ((error instanceof ArchiveError || error instanceof LocalConfigError) && /^[a-z][a-z0-9_]{0,47}$/.test(error.code) ? error.code : 'read_failed')
const retryShape = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/
/** Go's codes a draft or a send passes on as they are (§17.7). */
const PASSED = new Set(['chat_not_eligible', 'chat_not_allowed', 'group_not_allowed', 'reply_not_found', 'text_not_allowed', 'device_offline',
  'send_in_progress', 'storage_paused', 'send_uncertain', 'draft_exists'])

/**
 * Go's answer on a draft or send route, other than its success, as the
 * refusal the model reads: 403 is `send_not_allowed`, and so is a row that is
 * no longer active (409 `connection_state`); 404 means the connection or its
 * key is not Go's any more (`unauthorized`, as every tool answers then); a
 * limit carries `retry_at`; anything else is `send_failed`.
 */
export function fromGo({ status, data }) {
  const code = typeof data?.code === 'string' ? data.code : ''
  if (status === 403 || (status === 409 && code === 'connection_state')) return refusal('send_not_allowed')
  if (status === 404) return refusal('unauthorized')
  if (status === 429) return refusal('rate_limited', { retry_at: typeof data?.retry_at === 'string' && retryShape.test(data.retry_at) ? data.retry_at : undefined })
  if ((status === 409 || status === 422 || status === 502) && PASSED.has(code)) return refusal(code)
  return refusal('send_failed')
}

const OUTBOUND_KINDS = new Set(['draft', 'self', 'send'])
const OUTBOUND_STATUSES = new Set(['pending', 'sending', 'sent', 'uncertain', 'discarded', 'expired', 'revoked', 'refused'])
const uuidShape = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const timeOrNull = value => value === null || (typeof value === 'string' && Number.isFinite(Date.parse(value)))
/** One ledger row as Go lists it (§17.7), or null. */
function outboundItem(item) {
  if (!item || typeof item !== 'object' || !uuidShape.test(item.id ?? '') || !OUTBOUND_KINDS.has(item.kind) || !OUTBOUND_STATUSES.has(item.status) ||
    !uuidShape.test(item.device_id ?? '') || !(item.code === null || /^[a-z][a-z0-9_]{0,39}$/.test(item.code ?? '')) ||
    !(item.chat_key === null || typeof item.chat_key === 'string') || !(item.reply_to_uid === null || uuidShape.test(item.reply_to_uid ?? '')) ||
    !timeOrNull(item.created_at) || item.created_at === null || !timeOrNull(item.decided_at) || typeof item.edited !== 'boolean' ||
    !(item.message_uid === null || uuidShape.test(item.message_uid ?? ''))) return null
  const { id, kind, status, code, device_id, chat_key, reply_to_uid, created_at, decided_at, edited, message_uid } = item
  return { id, kind, status, code, device_id, chat_key, reply_to_uid, created_at, decided_at, edited, message_uid }
}

/**
 * `checkActive.sendStatus(id)` is verifier.mjs's; `relay` is the signed relay
 * (relay.mjs `sending`); `consoleURL` is CONSOLE_URL, where every link begins.
 */
export function createSendService({ log, now = Date.now, relay, checkActive, consoleURL = CONSOLE_URL }) {
  const fingerprints = createFingerprints({ now })
  const dedupe = createDedupe({ now })
  const windows = createWindows({ now })
  const counters = { drafts: 0, sends: 0 }
  const event = (name, id, code) => log.event(name, { conn: fingerprint(id), ...(code ? { code } : {}) })

  /**
   * §17.8 step 2: the consent sealed with the connection says sending (and,
   * for `self`, the own chat), and Go's status says so now. A reseal is
   * `reconsent_required`, a connection Go no longer serves `unauthorized`.
   * The ledger (`ledger`) is read on any served connection.
   */
  async function gate(record, { self = false, ledger = false } = {}) {
    if (record.send !== 'draft' && record.send !== 'direct') throw refusal('send_not_allowed')
    if (self && record.send_self !== true) throw refusal('send_not_allowed')
    const status = await checkActive.sendStatus(record.connection_id)
    if (status.answer === 'reseal') throw new LocalConfigError('reconsent_required')
    if (status.answer !== 'serve') throw refusal('unauthorized')
    if (!ledger && (status.send === null || (self && status.send_self !== true))) throw refusal('send_not_allowed')
  }

  /** Writes a refusal the enclave decided to the ledger (the refusals route), best effort. */
  async function recordRefusal(record, body) {
    try { await relay.sending(record.connection_id, record.api_key, 'POST', 'refusals', { body, timeout: LEDGER_ROUTE_TIMEOUT_MS }) } catch { /* the refusal stands */ }
  }

  const ctx = { relay, now, consoleURL, dedupe, fingerprints, windows, gate, recordRefusal, event, fromGo, refusal, codeOf: safeCode, counters }
  const draft = createDrafts(ctx)
  const sendSelf = createSends(ctx)

  /** list_outgoing: a page of the connection's ledger, newest first, with each sent message's console link (§17.8). */
  async function outgoing(record, query) {
    await gate(record, { ledger: true })
    const params = { limit: String(query.limit ?? 20) }
    for (const name of ['before', 'status', 'device_id']) if (query[name] !== undefined) params[name] = String(query[name])
    let answer
    try { answer = await relay.sending(record.connection_id, record.api_key, 'GET', 'outbound', { query: params, timeout: LEDGER_ROUTE_TIMEOUT_MS }) } catch { throw refusal('read_failed') }
    if (answer.status === 404) throw refusal('unauthorized')
    if (answer.status !== 200 || !Array.isArray(answer.data?.items) || !(answer.data.next === null || (typeof answer.data.next === 'string' && answer.data.next.length <= 64))) throw refusal('read_failed')
    const links = messageURLs(consoleURL, record.tenant_id)
    const items = []
    for (const raw of answer.data.items) {
      const item = outboundItem(raw)
      if (!item) throw refusal('read_failed')
      const url = item.message_uid ? links.message(item.device_id, item.message_uid) : null
      items.push(url ? { ...item, open_url: url } : item)
    }
    return { items, next: answer.data.next, drafts_url: links.drafts(record.connection_id) }
  }

  return {
    /** `provider.send` for a record whose sealed consent includes sending (§17.8). */
    forConnection(record) {
      const id = record.connection_id
      return {
        mode: record.send, self: record.send_self === true, consoleURL,
        draft: (input, archive) => draft(record, input, archive),
        sendSelf: input => sendSelf(record, input),
        outgoing: query => outgoing(record, query),
        observe(device, chatKey, text) { try { fingerprints.observe(id, device, chatKey, text) } catch { /* best effort */ } },
      }
    },
    /** Everything sending keeps of a connection: its fingerprints and their key, dedupe and its counts. */
    wipe(id) { fingerprints.wipe(id); dedupe.wipe(id); windows.drafts.forget(id); windows.sends.forget(id) },
    /** Drafts and sends since the last call, and fingerprints held now (the health line, §17.12). */
    counts() {
      const counts = { drafts: counters.drafts, sends: counters.sends, fp_entries: fingerprints.size() }
      counters.drafts = 0
      counters.sends = 0
      return counts
    },
    close() { fingerprints.clear(); dedupe.clear() },
    /** For tests. */
    get fingerprints() { return fingerprints },
  }
}
