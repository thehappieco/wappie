// Cross-chat fingerprints (docs/mcp-enclave.md §17.11). The assistant picks
// the chat a draft goes to, and a message it read can talk it into copying
// one chat's content into another: an address, a changed PIX key, a link.
// Every text the reader returns that belongs to one chat (message bodies,
// captions, file names, previews and open_attachment text; never chat or
// contact names) is fingerprinted here, keyed per connection, and a draft
// whose text repeats what came from another chat is marked: the console
// shows the person which chats in its banner. It catches copies, not
// paraphrases, only of the last FP_TTL_MS of this connection's reads, and of
// a long text only its first and last FP_TEXT_MAX_CHARS / 2; the card says so.
//
// Anyone who can message a number writes the texts this reads, and it runs
// on the reader's one thread before every read's answer leaves: every
// pattern is linear in the text (each starts only where its run starts, and
// bounds every run it repeats), a text is fingerprinted up to
// FP_TEXT_MAX_CHARS, and one text adds at most FP_SHINGLES_PER_TEXT shingles.
//
// Nothing here leaves the enclave, and nothing derived from a text goes to
// Go: the fingerprint key is random per connection and held in memory only,
// wiped with the connection.
import { createHmac, randomBytes } from 'node:crypto'
import { FP_CROSS_CHAT_MAX, FP_ENTITIES_PER_CONNECTION, FP_SHINGLE_WORDS, FP_SHINGLES_PER_CONNECTION, FP_SHINGLES_PER_TEXT, FP_TEXT_MAX_CHARS, FP_TTL_MS } from './policy.mjs'

// Words: runs between white space and punctuation. Symbols stay in the word
// they touch ("r$", an emoji), so a copy keeps its shape.
const WORD = /[^\s\p{P}]+/gu
const URL_LIKE = /(?:https?:\/\/|www\.)[^\s<>"'`]+|(?<![\p{L}\p{N}@._-])(?:[\p{L}\p{N}-]{1,63}\.){1,8}\p{L}{2,24}\/[^\s<>"'`]*/gu
const EMAIL = /(?<![\p{L}\p{N}._%+-])[\p{L}\p{N}._%+-]{1,64}@(?:[\p{L}\p{N}-]{1,63}\.){1,8}\p{L}{2,24}/gu
// Digits with the separators phone numbers, CPF and CNPJ are written with,
// and at most one space between groups.
const DIGITS = /\d(?:[\d().\/+-]| (?=[\d(+]))*\d/g
const DATE = /^(?:\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}[./-]\d{1,2}[./-]\d{1,2})$/
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g
const CPF_CNPJ = /(?<!\d)(?:\d{3}\.?\d{3}\.?\d{3}-?\d{2}|\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2})(?!\d)/g
const AMOUNT = /(r\$|us\$|\$|€|£|brl|usd|eur)\s?(?<![\d.,])(\d[\d.,]{0,30}\d|\d)|(?<![\d.,])(\d[\d.,]{0,30}\d|\d)\s?(reais|real|dólares|dolares|euros)\b/gu
const CURRENCY = { 'r$': 'brl', brl: 'brl', reais: 'brl', real: 'brl', 'us$': 'usd', $: 'usd', usd: 'usd', dólares: 'usd', dolares: 'usd', '€': 'eur', eur: 'eur', euros: 'eur', '£': 'gbp' }
const digitsOf = value => value.replace(/\D/g, '')

/** A URL as host and path: no scheme, no leading www., no query or fragment, no trailing punctuation or slash. */
function urlPiece(value) {
  const bare = value.replace(/^https?:\/\//, '').replace(/^www\./, '').split(/[?#]/)[0].replace(/[.,;:!?)\]}'"»]+$/u, '').replace(/\/+$/, '')
  return bare.length >= 4 ? bare : null
}

const lowSurrogate = code => code >= 0xdc00 && code <= 0xdfff
/** The first `n` code units of `text`, never half of a surrogate pair. */
const head = (text, n) => text.slice(0, lowSurrogate(text.charCodeAt(n)) ? n - 1 : n)
/** The last `n` code units of `text`, never half of a surrogate pair. */
const tail = (text, n) => { const at = Math.max(0, text.length - n); return text.slice(lowSurrogate(text.charCodeAt(at)) ? at + 1 : at) }
const fold = text => text.normalize('NFKC').toLowerCase()

/**
 * What of a text is fingerprinted, NFKC-normalized and case-folded: the whole
 * of it, or, past FP_TEXT_MAX_CHARS (before or after folding, which can
 * lengthen a text), its first and last halves of that.
 */
function folded(text) {
  const half = FP_TEXT_MAX_CHARS / 2
  if (text.length <= FP_TEXT_MAX_CHARS) {
    const whole = fold(text)
    return whole.length <= FP_TEXT_MAX_CHARS ? [whole] : [head(whole, half), tail(whole, half)]
  }
  return [head(fold(head(text, half)), half), tail(fold(tail(text, half)), half)]
}

/**
 * What a text is fingerprinted as: `kind\0normalized` strings, each once,
 * shingles (kind `w`) first and in the text's order. Every window of
 * FP_SHINGLE_WORDS words is a piece, and so is every entity (URLs by host
 * and path, e-mail addresses, runs of 8 or more digits, currency amounts, and
 * PIX-like keys: random-key UUIDs, CPF and CNPJ), in what folded() keeps.
 */
export function pieces(text) {
  if (typeof text !== 'string' || !text) return []
  const shingles = new Set(), entities = new Set()
  for (const normalized of folded(text)) {
    const words = normalized.match(WORD) ?? []
    for (let at = 0; at + FP_SHINGLE_WORDS <= words.length; at++) shingles.add(`w\u0000${words.slice(at, at + FP_SHINGLE_WORDS).join(' ')}`)
    for (const [url] of normalized.matchAll(URL_LIKE)) { const piece = urlPiece(url); if (piece) entities.add(`url\u0000${piece}`) }
    for (const [email] of normalized.matchAll(EMAIL)) entities.add(`email\u0000${email.replace(/^[._%+-]+/, '')}`)
    for (const [run] of normalized.matchAll(DIGITS)) {
      // A run joined across a space is a piece, and so is each group of it that is long enough on its own.
      for (const part of [run, ...run.split(' ')]) if (!DATE.test(part) && digitsOf(part).length >= 8) entities.add(`digits\u0000${digitsOf(part)}`)
    }
    for (const [key] of normalized.matchAll(UUID)) entities.add(`pix\u0000${key}`)
    for (const [key] of normalized.matchAll(CPF_CNPJ)) entities.add(`pix\u0000${digitsOf(key)}`)
    for (const match of normalized.matchAll(AMOUNT)) {
      const currency = CURRENCY[match[1] ?? match[4]], amount = digitsOf(match[2] ?? match[3])
      if (currency && amount) entities.add(`amount\u0000${currency}:${amount}`)
    }
  }
  return [...shingles, ...entities]
}

/**
 * One budget of fingerprints: `chats` maps `device\nchat` to its fingerprints
 * with when each was last seen there, least recently seen first; `holders`
 * maps a fingerprint to the chats it was seen in; `size` counts (fingerprint,
 * chat) entries.
 */
const bucket = () => ({ chats: new Map(), holders: new Map(), size: 0 })
function add(store, where, fingerprint, at) {
  let chat = store.chats.get(where)
  if (!chat) store.chats.set(where, chat = new Map())
  if (chat.has(fingerprint)) chat.delete(fingerprint)
  else {
    store.size++
    let holders = store.holders.get(fingerprint)
    if (!holders) store.holders.set(fingerprint, holders = new Set())
    holders.add(where)
  }
  chat.set(fingerprint, at)
}
function drop(store, where, chat, fingerprint) {
  chat.delete(fingerprint)
  store.size--
  const holders = store.holders.get(fingerprint)
  holders.delete(where)
  if (!holders.size) store.holders.delete(fingerprint)
  if (!chat.size) store.chats.delete(where)
}
/** Drops every entry last seen at or before `limit`. */
function expire(store, limit) {
  for (const [where, chat] of store.chats) {
    for (const [fingerprint, at] of chat) {
      if (at > limit) break
      drop(store, where, chat, fingerprint)
    }
  }
}
/**
 * Past `cap`, the chat holding the most entries loses its least recently
 * seen: one text, or one chat, that floods the store pushes out its own
 * entries, never the few another chat left.
 */
function trim(store, cap) {
  while (store.size > cap) {
    let largest = null, second = 0
    for (const entry of store.chats) {
      if (!largest || entry[1].size > largest[1].size) { second = largest?.[1].size ?? 0; largest = entry } else if (entry[1].size > second) second = entry[1].size
    }
    const [where, chat] = largest
    let n = Math.min(store.size - cap, chat.size - second + 1)
    for (const fingerprint of chat.keys()) {
      if (n-- <= 0) break
      drop(store, where, chat, fingerprint)
    }
  }
}

/**
 * The per-connection store. `observe(id, device, chatKey, text)` records
 * where each fingerprint of `text` came from; `check(id, target, text)`
 * returns the chats other than `target` (`{device, keys}`, the chat under
 * every key it is known by) that `text` repeats, most repeated first, at most
 * FP_CROSS_CHAT_MAX. An entry lives FP_TTL_MS from its last sighting. Shingles
 * and entities have their own budgets (FP_SHINGLES_PER_CONNECTION,
 * FP_ENTITIES_PER_CONNECTION), so shingles never push out a PIX key or a
 * link; past a budget the chat holding the most loses its least recently
 * seen. One text adds at most FP_SHINGLES_PER_TEXT shingles, spread evenly
 * across it, and every entity it has.
 */
export function createFingerprints({ now = Date.now } = {}) {
  // connection id -> { key: 32 random bytes, shingles: bucket, entities: bucket }
  const connections = new Map()
  /** `[shingle?, fingerprint]` for each piece. */
  const fingerprintsOf = (key, found) => found.map(piece => [piece.startsWith('w\u0000'),
    createHmac('sha256', key).update(piece, 'utf8').digest().subarray(0, 8).toString('hex')])
  /** A text's pieces with its shingles thinned to FP_SHINGLES_PER_TEXT, evenly spaced. */
  function sampled(text) {
    const found = pieces(text)
    const count = found.findIndex(piece => !piece.startsWith('w\u0000'))
    const shingles = count === -1 ? found.length : count
    if (shingles <= FP_SHINGLES_PER_TEXT) return found
    const stride = Math.ceil(shingles / FP_SHINGLES_PER_TEXT)
    return found.filter((piece, index) => index >= shingles || index % stride === 0)
  }
  function expireAll(state) {
    const limit = now() - FP_TTL_MS
    expire(state.shingles, limit)
    expire(state.entities, limit)
  }
  return {
    observe(id, device, chatKey, text) {
      if (typeof text !== 'string' || !text || typeof chatKey !== 'string' || !chatKey) return
      let state = connections.get(id)
      if (!state) connections.set(id, state = { key: randomBytes(32), shingles: bucket(), entities: bucket() })
      const at = now(), where = `${device}\n${chatKey}`
      for (const [shingle, fingerprint] of fingerprintsOf(state.key, sampled(text))) add(shingle ? state.shingles : state.entities, where, fingerprint, at)
      expireAll(state)
      trim(state.shingles, FP_SHINGLES_PER_CONNECTION)
      trim(state.entities, FP_ENTITIES_PER_CONNECTION)
    },
    check(id, target, text) {
      const state = connections.get(id)
      if (!state) return []
      expireAll(state)
      const hits = new Map()
      for (const [shingle, fingerprint] of fingerprintsOf(state.key, pieces(text))) {
        for (const where of (shingle ? state.shingles : state.entities).holders.get(fingerprint) ?? []) {
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
      state.key.fill(0)
      connections.delete(id)
    },
    /** Entries held now, all connections (the health line's fp_entries). */
    size() {
      let total = 0
      for (const state of connections.values()) total += state.shingles.size + state.entities.size
      return total
    },
    clear() { for (const id of [...connections.keys()]) this.wipe(id) },
  }
}
