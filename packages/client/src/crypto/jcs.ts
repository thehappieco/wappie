// RFC 8785, the JSON Canonicalization Scheme.
//
// One serialization of a JSON value that two parties compute independently and
// hash: the console over a consent's scope before it seals the bundle, the
// attested reader over the scope it opened (docs/mcp-enclave.md §17.2, the
// device check). A difference of one byte fails the check, so both sides call
// this one function and nothing else.
//
// ECMAScript's own JSON.stringify already writes strings and numbers the way
// JCS asks (§3.2.2: the shortest round-trip number, the minimal string
// escapes with lower-case hex), so what is left is the order of object keys
// (§3.2.3: by UTF-16 code units, which is what Array.prototype.sort compares)
// and refusing what is not I-JSON (§3.1): a number that is not finite, a lone
// surrogate, and anything JSON has no word for.

export class CanonicalJSONError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CanonicalJSONError'
  }
}

// A surrogate that is not half of a pair: I-JSON (RFC 7493 §2.1) forbids it,
// and JSON.stringify would write it as an escape rather than fail.
const loneSurrogate = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

function text(value: string): string {
  if (loneSurrogate.test(value)) throw new CanonicalJSONError('a string holds a lone surrogate')
  return JSON.stringify(value)
}

function plainObject(value: object): value is Record<string, unknown> {
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

function serialize(value: unknown): string {
  if (value === null || value === true || value === false) return String(value)
  if (typeof value === 'string') return text(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new CanonicalJSONError('a number is not finite')
    // -0 is written 0, as JSON.stringify writes it and §3.2.2.3 asks.
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(serialize).join(',')}]`
  if (typeof value === 'object' && plainObject(value)) {
    const keys = Object.keys(value).sort()
    return `{${keys.map(key => `${text(key)}:${serialize(value[key])}`).join(',')}}`
  }
  // undefined, a function, a bigint, a symbol, a Date, a Map: JSON has none
  // of them, and dropping one silently is how two sides hash different scopes.
  throw new CanonicalJSONError(`not a JSON value: ${typeof value}`)
}

/** The canonical JSON text of `value` (RFC 8785); hash its UTF-8 bytes. */
export function canonicalJSON(value: unknown): string {
  return serialize(value)
}
