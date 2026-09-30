// draft_message in the enclave (docs/mcp-enclave.md §17.6, §17.8). A draft is
// the assistant's text sealed here to the number's archive key, pinned at
// install from the DSK this process opened (§17.2 rule 5), never a key taken
// from a grant fetched later: Go serves the grants and could forge one. Go
// stores the envelope in its ledger and cannot open it; the person opens it
// in the console, checks the text and the recipient, and sends it there.
//
// The steps, in order, every refusal a §17.8 code and nothing sealed before
// the sixth: (1) the schema and the number, in the reader; (2) the gate; (3)
// the text rules, a refusal recorded; (4) dedupe; (5) the chat, looked up and
// its name opened by the reader, then this connection's hourly count, a
// refusal recorded; (6) the fingerprints give `cross_chat`, and the draft is
// sealed under a fresh id; (7) Go's route, whose 4xx is the answer (Go
// recorded it); (8) the dedupe entry, `draft_created`, the answer.
import { randomUUID } from 'node:crypto'
import { bytes, seal } from '@whatserver2/client'
import { messageURLs } from '../provider.mjs'
import { FILENAME_MAX_CHARS } from '../media/policy.mjs'
import { cut } from '../media/result.mjs'
import { dedupeKey } from './dedupe.mjs'
import { DRAFT_ROUTE_TIMEOUT_MS, DRAFT_SEALED_MAX_BYTES } from './policy.mjs'
import { normalizeNewlines, textRefusal } from './textrules.mjs'

/**
 * The sealed plaintext (§17.6): UTF-8 of JSON.stringify of exactly these keys,
 * in this order. The console compares every field with Go's row and refuses a
 * draft whose row says anything else (`draft_mismatch`).
 */
export function draftPlaintext({ connection, device, chatKey, replyTo, text, createdAt, crossChat }) {
  return JSON.stringify({ v: 1, connection_id: connection, device_id: device, chat_key: chatKey, reply_to_uid: replyTo ?? null, text, created_at: createdAt,
    cross_chat: crossChat.map(chat => ({ device_id: chat.device_id, chat_key: chat.chat_key })) })
}

/**
 * The envelope: sealDirect to the pinned public key, as Kind.McpDraft, under
 * the pinned namespace and epoch, bound to draftRow. `pin` is the record's
 * `drafts_to[device]` ({pub, ns, epoch}); the envelope is at most
 * DRAFT_SEALED_MAX_BYTES or this throws.
 */
export async function sealDraft(pin, { connection, device, draft, replyTo, chatKey, plaintext }) {
  const namespace = bytes.parseUUID(pin.ns)
  const row = await seal.draftRow(namespace, bytes.parseUUID(device), bytes.parseUUID(connection), bytes.parseUUID(draft), replyTo ? bytes.parseUUID(replyTo) : null, chatKey)
  const sealed = await seal.sealDirect(new Uint8Array(Buffer.from(pin.pub, 'base64url')), seal.Kind.McpDraft, namespace, row, pin.epoch, new Uint8Array(Buffer.from(plaintext, 'utf8')))
  if (sealed.length > DRAFT_SEALED_MAX_BYTES) throw new Error('draft_too_large')
  return sealed
}

/** A chat key Go's ledger holds (§17.19): no white space, comma or control character, 128 characters at most. */
const chatKeyShape = key => typeof key === 'string' && key.length > 0 && [...key].length <= 128 && !/[\u0000- ,\u007F- ]/.test(key) && !/\s/.test(key)

/**
 * `ctx` is service.mjs's: the relay, the store of fingerprints, dedupe, the
 * hourly window, the gate, the refusal recorder, the event log, Go's answers
 * as refusals, and the counters of the health line.
 */
export function createDrafts(ctx) {
  const { relay, now, consoleURL, dedupe, fingerprints, windows, gate, recordRefusal, event, fromGo, refusal, codeOf, counters } = ctx

  async function create(record, input, text, archive) {
    const id = record.connection_id, device = input.device_id, chatKey = input.chat_key, replyTo = input.reply_to_uid ?? null
    // 5. The chat: the number has it under that key, and its name, opened by
    // the reader as list_chats opens it, goes back in the answer.
    const chat = await archive.chat()
    if (!chat) throw refusal('chat_not_eligible')
    if (chat.is_group && record.send_groups !== true) throw refusal('group_not_allowed')
    const pin = record.drafts_to?.[device]
    if (!pin) throw refusal('send_not_allowed')
    const taken = windows.drafts.take(id)
    if (!taken.slot) {
      await recordRefusal(record, { kind: 'draft', device_id: device, chat_key: chatKey, code: 'rate_limited' })
      throw refusal('rate_limited', { retry_at: taken.retry_at })
    }
    try {
      // 6. What this text repeats from other chats; the number's own chat, a note to self, is never marked.
      const crossChat = chat.own ? [] : fingerprints.check(id, { device, keys: chat.keys }, text)
      for (let attempt = 0; ; attempt++) {
        const draft = randomUUID()
        const plaintext = draftPlaintext({ connection: id, device, chatKey, replyTo, text, createdAt: new Date(now()).toISOString(), crossChat })
        const sealed = await sealDraft(pin, { connection: id, device, draft, replyTo, chatKey, plaintext })
        // 7. Go's route: 201, or a refusal Go has already written to the ledger.
        let answer
        try {
          answer = await relay.sending(id, record.api_key, 'POST', 'drafts', { timeout: DRAFT_ROUTE_TIMEOUT_MS,
            body: { id: draft, device_id: device, chat_key: chatKey, ...(replyTo ? { reply_to_uid: replyTo } : {}), epoch: pin.epoch, sealed: Buffer.from(sealed).toString('base64url') } })
        } catch { throw refusal('send_failed') }
        if (answer.status === 201 && answer.data?.id === draft && typeof answer.data.expires_at === 'string' && Number.isFinite(Date.parse(answer.data.expires_at))) {
          counters.drafts++
          event('draft_created', id)
          const links = messageURLs(consoleURL, record.tenant_id)
          return { draft_id: draft, device_id: device, chat_key: chatKey, chat_name: typeof chat.name === 'string' ? cut(chat.name, FILENAME_MAX_CHARS) : null,
            is_group: chat.is_group === true, reply_to_uid: replyTo, expires_at: answer.data.expires_at,
            review_url: links.draft(device, draft), drafts_url: links.drafts(id) }
        }
        const error = fromGo(answer)
        // Two random ids that collide: draw again, once.
        if (error.code === 'draft_exists' && attempt === 0) continue
        throw error.code === 'draft_exists' ? refusal('send_failed') : error
      }
    } catch (error) {
      windows.drafts.release(id, taken.slot)
      throw error
    }
  }

  /** provider.send.draft for `record`: the §17.8 steps from the gate on. */
  return async function draft(record, input, archive) {
    const id = record.connection_id
    try {
      // 2. The gate: the sealed consent, and Go's answer now.
      await gate(record)
      // 3. The text rules, on the text as given once its line breaks are LF.
      const text = normalizeNewlines(input.text)
      const why = textRefusal(text)
      if (why) {
        await recordRefusal(record, { kind: 'draft', device_id: input.device_id, chat_key: input.chat_key, code: 'text_not_allowed' })
        throw refusal('text_not_allowed', { why })
      }
      if (!chatKeyShape(input.chat_key)) throw refusal('chat_not_eligible')
      // 4. An identical call within the window answers this one's draft.
      const key = dedupeKey({ connection: id, tool: 'draft_message', device: input.device_id, chatKey: input.chat_key, replyTo: input.reply_to_uid, text })
      return await dedupe.run(id, key, () => create(record, input, text, archive))
    } catch (error) {
      event('draft_refused', id, codeOf(error))
      throw error
    }
  }
}
