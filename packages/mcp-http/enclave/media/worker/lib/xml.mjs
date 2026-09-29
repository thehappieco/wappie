// A small XML reader for the office worker's own parsers (docx, pptx, odt,
// ods). Callback-style and iterative: no recursion, a depth ceiling, no DTD
// (a DOCTYPE is refused, so no entity expansion), only the five predefined
// entities and character references. Element and attribute names are resolved
// through their namespace declarations and written with a canonical prefix
// (w:, a:, p:, r:, text:, table:, office:, ...), so a producer that binds the
// same namespaces to other prefixes, or to the default namespace, reads the
// same; a namespace outside the list keeps its local name behind "{uri}".

import { refuse } from './frames.mjs'

const NAMESPACES = {
  'http://schemas.openxmlformats.org/wordprocessingml/2006/main': 'w',
  'http://purl.oclc.org/ooxml/wordprocessingml/main': 'w',
  'http://schemas.openxmlformats.org/drawingml/2006/main': 'a',
  'http://purl.oclc.org/ooxml/drawingml/main': 'a',
  'http://schemas.openxmlformats.org/presentationml/2006/main': 'p',
  'http://purl.oclc.org/ooxml/presentationml/main': 'p',
  'http://schemas.openxmlformats.org/officeDocument/2006/relationships': 'r',
  'http://purl.oclc.org/ooxml/officeDocument/relationships': 'r',
  'http://schemas.openxmlformats.org/package/2006/relationships': 'rel',
  'http://schemas.openxmlformats.org/markup-compatibility/2006': 'mc',
  'urn:oasis:names:tc:opendocument:xmlns:office:1.0': 'office',
  'urn:oasis:names:tc:opendocument:xmlns:text:1.0': 'text',
  'urn:oasis:names:tc:opendocument:xmlns:table:1.0': 'table',
  'urn:oasis:names:tc:opendocument:xmlns:drawing:1.0': 'draw',
}

const XML_NS = 'http://www.w3.org/XML/1998/namespace'

// Deeper than any document a person writes; a crafted one gets `damaged`.
export const MAX_DEPTH = 1_000

const ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" }

/** Decode an XML part's bytes: a BOM or the declared encoding, else UTF-8. */
export function decodeXml(bytes) {
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return new TextDecoder('utf-16le').decode(bytes)
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return new TextDecoder('utf-16be').decode(bytes)
  const prolog = bytes.toString('latin1', 0, Math.min(bytes.length, 200))
  const declared = /^(?:\xef\xbb\xbf)?<\?xml[^>]*encoding\s*=\s*["']([A-Za-z0-9._-]+)["']/.exec(prolog)?.[1]?.toLowerCase()
  const label = declared && /^(?:iso-8859-1|latin1|windows-1252|cp1252|us-ascii)$/.test(declared) ? 'windows-1252' : 'utf-8'
  return new TextDecoder(label).decode(bytes)
}

export function unescapeXml(s) {
  if (s.indexOf('&') === -1) return s
  return s.replace(/&(#x[0-9A-Fa-f]{1,6}|#[0-9]{1,7}|[A-Za-z]{2,4});/g, (whole, body) => {
    if (body[0] !== '#') return ENTITIES[body] ?? whole
    const cp = body[1] === 'x' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10)
    return cp > 0 && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff) ? String.fromCodePoint(cp) : ''
  })
}

function resolve(qname, scope, isAttribute) {
  const colon = qname.indexOf(':')
  const prefix = colon === -1 ? '' : qname.slice(0, colon)
  const local = colon === -1 ? qname : qname.slice(colon + 1)
  // An unprefixed attribute is in no namespace.
  if (!prefix && isAttribute) return local
  if (prefix === 'xml') return `xml:${local}`
  const uri = scope[prefix]
  // An undeclared prefix (some producers leave w14: and the like undeclared)
  // keeps its name as written; nothing here depends on those.
  if (uri === undefined) return qname
  if (!uri) return local
  const canonical = NAMESPACES[uri]
  return canonical ? `${canonical}:${local}` : `{${uri}}${local}`
}

const ATTRIBUTE = /([^\s=/]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g

/**
 * Parse `text`, calling handler.open(name, attrs), handler.text(string) and
 * handler.close(name). Text outside the root element is dropped. A handler may
 * throw to stop; anything malformed is ERROR damaged.
 */
export function parseXml(text, handler) {
  const n = text.length
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0
  const stack = []
  let scope = { xml: XML_NS }
  const scopes = []
  while (i < n) {
    const lt = text.indexOf('<', i)
    if (lt === -1) break
    if (lt > i && stack.length) handler.text(unescapeXml(text.slice(i, lt)))
    const c = text.charCodeAt(lt + 1)
    if (c === 0x2f) {
      const gt = text.indexOf('>', lt + 2)
      if (gt === -1) throw refuse('damaged')
      const qname = text.slice(lt + 2, gt).trim()
      const top = stack.pop()
      if (!top || top.qname !== qname) throw refuse('damaged')
      handler.close(top.name)
      scope = scopes.pop()
      i = gt + 1
      continue
    }
    if (c === 0x3f) {
      const end = text.indexOf('?>', lt + 2)
      if (end === -1) throw refuse('damaged')
      i = end + 2
      continue
    }
    if (c === 0x21) {
      if (text.startsWith('!--', lt + 1)) {
        const end = text.indexOf('-->', lt + 4)
        if (end === -1) throw refuse('damaged')
        i = end + 3
        continue
      }
      if (text.startsWith('![CDATA[', lt + 1)) {
        const end = text.indexOf(']]>', lt + 9)
        if (end === -1) throw refuse('damaged')
        if (stack.length) handler.text(text.slice(lt + 9, end))
        i = end + 3
        continue
      }
      // <!DOCTYPE and every other declaration: no DTD is ever read.
      throw refuse('damaged')
    }
    const gt = tagEnd(text, lt + 1)
    const selfClosing = text.charCodeAt(gt - 1) === 0x2f
    const body = text.slice(lt + 1, selfClosing ? gt - 1 : gt)
    const space = body.search(/[\s]/)
    const qname = space === -1 ? body : body.slice(0, space)
    if (!qname) throw refuse('damaged')
    const raw = []
    let declares = false
    if (space !== -1 && body.indexOf('=', space) !== -1) {
      ATTRIBUTE.lastIndex = space
      for (let m; (m = ATTRIBUTE.exec(body)); ) {
        const value = unescapeXml(m[2] ?? m[3])
        if (m[1] === 'xmlns' || m[1].startsWith('xmlns:')) {
          if (!declares) {
            scope = Object.create(scope)
            declares = true
          }
          scope[m[1] === 'xmlns' ? '' : m[1].slice(6)] = value
        } else {
          raw.push(m[1], value)
        }
      }
    }
    const attrs = {}
    for (let k = 0; k < raw.length; k += 2) attrs[resolve(raw[k], scope, true)] = raw[k + 1]
    const name = resolve(qname, scope, false)
    if (stack.length >= MAX_DEPTH) throw refuse('damaged')
    handler.open(name, attrs)
    if (selfClosing) {
      handler.close(name)
      if (declares) scope = Object.getPrototypeOf(scope)
    } else {
      stack.push({ qname, name })
      scopes.push(declares ? Object.getPrototypeOf(scope) : scope)
    }
    i = gt + 1
  }
  if (stack.length) throw refuse('damaged')
}

/** The index of the '>' that ends the tag starting at `from`, quotes respected. */
function tagEnd(text, from) {
  const gt = text.indexOf('>', from)
  if (gt === -1) throw refuse('damaged')
  const slice = text.slice(from, gt)
  if (slice.indexOf('"') === -1 && slice.indexOf("'") === -1) return gt
  let quote = 0
  for (let j = from; j < text.length; j++) {
    const ch = text.charCodeAt(j)
    if (quote) {
      if (ch === quote) quote = 0
    } else if (ch === 0x22 || ch === 0x27) {
      quote = ch
    } else if (ch === 0x3e) {
      return j
    }
  }
  throw refuse('damaged')
}
