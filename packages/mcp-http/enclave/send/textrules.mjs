// The text rules (docs/mcp-enclave.md §17.10, §17.19): what no draft or send
// may carry, checked here before anything is sealed or sent, and again by Go
// (internal/mcpauth/textrules.go) before any text leaves for WhatsApp. One
// table, one set of vectors (test/send-text-vectors.json), read by both.
//
// A text is refused, in this order, for control characters (the C0 controls
// but tab and newline, DEL, the C1 controls, and a surrogate on its own), for
// the bidi embeddings, overrides and isolates, for being empty once white
// space is trimmed as trim() trims it, and, where links are refused (an
// own-chat or direct send), for a link. Every other character is kept, the
// invisible ones included: the console marks them for the person, which is
// what they are for.

/** Anything that starts a web address: an own-chat or direct send refuses it. */
export const LINK = /(?:https?:\/\/|www\.)/i
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/
const DIRECTION = /[‪-‮⁦-⁩]/

/** CR LF and CR become LF, as the enclave and Go both do before a text is checked, sealed or sent. */
export const normalizeNewlines = text => text.replace(/\r\n?/g, '\n')

/**
 * Why the rules refuse `text`, in the words the reader's guidance uses
 * ('control characters', 'text-direction controls', 'empty' or 'links'), or
 * null when it passes. `links` refuses a web address too.
 */
export function textRefusal(text, { links = false } = {}) {
  if (typeof text !== 'string') return 'control characters'
  const normalized = normalizeNewlines(text)
  if (CONTROL.test(normalized)) return 'control characters'
  if (DIRECTION.test(normalized)) return 'text-direction controls'
  if (normalized.trim() === '') return 'empty'
  if (links && LINK.test(normalized)) return 'links'
  return null
}
