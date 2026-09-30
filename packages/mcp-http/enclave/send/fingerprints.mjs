// Cross-chat fingerprints (docs/mcp-enclave.md §17.11). The assistant picks
// the chat a draft goes to, and a message it read can talk it into copying
// one chat's content into another: an address, a changed PIX key, a link.
// Every text the reader returns that belongs to one chat (message bodies,
// captions, previews and open_attachment text; never chat or contact names)
// is fingerprinted here, keyed per connection, and a draft whose text repeats
// what came from another chat is marked: the console shows the person which
// chats in its banner. It catches copies, not paraphrases, and only of the
// last FP_TTL_MS of this connection's reads; the card says so.
//
// Nothing here leaves the enclave, and nothing derived from a text goes to
// Go: the fingerprint key is random per connection and held in memory only,
// wiped with the connection.
import { createHmac, randomBytes } from 'node:crypto'
import { FP_CROSS_CHAT_MAX, FP_MAX_PER_CONNECTION, FP_SHINGLE_WORDS, FP_TTL_MS } from './policy.mjs'

// Words: runs between white space and punctuation. Symbols stay in the word
// they touch ("r$", an emoji), so a copy keeps its shape.
const WORD = /[^\s\p{P}]+/gu
const URL_LIKE = /(?:https?:\/\/|www\.)[^\s<>"'`]+|(?<![\p{L}\p{N}@._-])(?:[\p{L}\p{N}-]+\.)+\p{L}{2,}\/[^\s<>"'`]*/gu
const EMAIL = /[\p{L}\p{N}._%+-]+@(?:[\p{L}\p{N}-]+\.)+\p{L}{2,}/gu
// Digits with the separators phone numbers, CPF and CNPJ are written with,
// and at most one space between groups.
const DIGITS = /\d(?:[\d().\/+-]| (?=[\d(+]))*\d/g
const DATE = /^(?:\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}[./-]\d{1,2}[./-]\d{1,2})$/
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g
const CPF_CNPJ = /(?<!\d)(?:\d{3}\.?\d{3}\.?\d{3}-?\d{2}|\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2})(?!\d)/g
const AMOUNT = /(r\$|us\$|\$|€|£|brl|usd|eur)\s?(\d[\d.,]*\d|\d)|(\d[\d.,]*\d|\d)\s?(reais|real|dólares|dolares|euros)\b/gu
const CURRENCY = { 'r$': 'brl', brl: 'brl', reais: 'brl', real: 'brl', 'us$': 'usd', $: 'usd', usd: 'usd', dólares: 'usd', dolares: 'usd', '€': 'eur', eur: 'eur', euros: 'eur', '£': 'gbp' }
const digitsOf = value => value.replace(/\D/g, '')

/** A URL as host and path: no scheme, no leading www., no query or fragment, no trailing punctuation or slash. */
function urlPiece(value) {
  const bare = value.replace(/^https?:\/\//, '').replace(/^www\./, '').split(/[?#]/)[0].replace(/[.,;:!?)\]}'"»]+$/u, '').replace(/\/+$/, '')
  return bare.length >= 4 ? bare : null
}

/**
 * What a text is fingerprinted as: `[kind, normalized]` pairs, each once.
 * The text is NFKC-normalized and case-folded; every window of
 * FP_SHINGLE_WORDS words is a piece, and so is every entity in it (URLs by
 * host and path, e-mail addresses, runs of 8 or more digits, currency
 * amounts, and PIX-like keys: random-key UUIDs, CPF and CNPJ).
 */
export function pieces(text) {
  if (typeof text !== 'string' || !text) return []
  const normalized = text.normalize('NFKC').toLowerCase()
  const out = new Set()
  const words = normalized.match(WORD) ?? []
  for (let at = 0; at + FP_SHINGLE_WORDS <= words.length; at++) out.add(`w\u0000${words.slice(at, at + FP_SHINGLE_WORDS).join(' ')}`)
  for (const [url] of normalized.matchAll(URL_LIKE)) { const piece = urlPiece(url); if (piece) out.add(`url\u0000${piece}`) }
  for (const [email] of normalized.matchAll(EMAIL)) out.add(`email\u0000${email.replace(/^[._%+-]+/, '')}`)
  for (const [run] of normalized.matchAll(DIGITS)) {
    // A run joined across a space is a piece, and so is each group of it that is long enough on its own.
    for (const part of [run, ...run.split(' ')]) if (!DATE.test(part) && digitsOf(part).length >= 8) out.add(`digits\u0000${digitsOf(part)}`)
  }
  for (const [key] of normalized.matchAll(UUID)) out.add(`pix\u0000${key}`)
  for (const [key] of normalized.matchAll(CPF_CNPJ)) out.add(`pix\u0000${digitsOf(key)}`)
  for (const match of normalized.matchAll(AMOUNT)) {
    const currency = CURRENCY[match[1] ?? match[4]], amount = digitsOf(match[2] ?? match[3])
    if (currency && amount) out.add(`amount\u0000${currency}:${amount}`)
  }
  return [...out]
}

/**
 * The per-connection store. `observe(id, device, chatKey, text)` records
 * where each fingerprint of `text` came from; `check(id, target, text)`
 * returns the chats other than `target` (`{device, keys}`, the chat under
 * every key it is known by) that `text` repeats, most repeated first, at most
 * FP_CROSS_CHAT_MAX. An entry lives FP_TTL_MS from its last sighting, and past
 * FP_MAX_PER_CONNECTION the least recently seen go first.
 */
export function createFingerprints({ now = Date.now } = {}) {
  // connection id -> { key: 32 random bytes, entries: Map(fingerprint -> Map(`device\nchat` -> last seen)) },
  // entries in the order they were last seen.
  const connections = new Map()
  let total = 0
  const fingerprintsOf = (key, text) => pieces(text).map(piece => createHmac('sha256', key).update(piece, 'utf8').digest().subarray(0, 8).toString('hex'))
  function expire(state) {
    const limit = now() - FP_TTL_MS
    for (const [fingerprint, chats] of state.entries) {
      let newest = 0
      for (const at of chats.values()) newest = Math.max(newest, at)
      if (newest > limit) break
      state.entries.delete(fingerprint)
      total--
    }
  }
  return {
    observe(id, device, chatKey, text) {
      if (typeof text !== 'string' || !text || typeof chatKey !== 'string' || !chatKey) return
      let state = connections.get(id)
      if (!state) connections.set(id, state = { key: randomBytes(32), entries: new Map() })
      const at = now(), where = `${device}\n${chatKey}`
      for (const fingerprint of fingerprintsOf(state.key, text)) {
        let chats = state.entries.get(fingerprint)
        if (chats) state.entries.delete(fingerprint)
        else { chats = new Map(); total++ }
        chats.set(where, at)
        state.entries.set(fingerprint, chats)
      }
      while (state.entries.size > FP_MAX_PER_CONNECTION) { state.entries.delete(state.entries.keys().next().value); total-- }
      expire(state)
    },
    check(id, target, text) {
      const state = connections.get(id)
      if (!state) return []
      expire(state)
      const limit = now() - FP_TTL_MS
      const hits = new Map()
      for (const fingerprint of new Set(fingerprintsOf(state.key, text))) {
        for (const [where, at] of state.entries.get(fingerprint) ?? []) {
          if (at <= limit) continue
          const [device, chatKey] = where.split('\n')
          if (device === target.device && target.keys.includes(chatKey)) continue
          hits.set(where, (hits.get(where) ?? 0) + 1)
        }
      }
      return [...hits].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, FP_CROSS_CHAT_MAX)
        .map(([where]) => { const [device_id, chat_key] = where.split('\n'); return { device_id, chat_key } })
    },
    wipe(id) {
      const state = connections.get(id)
      if (!state) return
      total -= state.entries.size
      state.key.fill(0)
      connections.delete(id)
    },
    /** Entries held now, all connections (the health line's fp_entries). */
    size: () => total,
    clear() { for (const id of [...connections.keys()]) this.wipe(id) },
  }
}
