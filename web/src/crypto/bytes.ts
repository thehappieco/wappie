// Byte plumbing shared by the crypto modules.
//
// Kept apart from the algorithms so the interesting files contain only the
// protocol, and so the encodings — which is where a reimplementation quietly
// goes wrong — are written once.

// Bytes is a Bytes known to be backed by a plain ArrayBuffer.
//
// TypeScript 5.7 made Bytes generic over its buffer and WebCrypto refuses
// anything that might be shared memory. Naming the narrow form once keeps that
// detail out of every signature below.
export type Bytes = Uint8Array<ArrayBuffer>

export function concat(...parts: Bytes[]): Bytes {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

export function equal(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

const utf8 = new TextEncoder()

export function encodeUTF8(s: string): Bytes {
  // Copied rather than returned directly: TextEncoder is typed as producing a
  // possibly-shared buffer, and WebCrypto will not accept one.
  return new Uint8Array(utf8.encode(s))
}

/** i2osp2 is RFC 8017's two-byte big-endian integer, which HPKE uses throughout. */
export function i2osp2(n: number): Bytes {
  return new Uint8Array([(n >>> 8) & 0xff, n & 0xff])
}

export function readUint32BE(b: Bytes, at: number): number {
  return ((b[at] << 24) >>> 0) + (b[at + 1] << 16) + (b[at + 2] << 8) + b[at + 3]
}

export function readUint16BE(b: Bytes, at: number): number {
  return (b[at] << 8) + b[at + 1]
}

export function toBase64(b: Bytes): string {
  let s = ''
  // Chunked: a single spread of a multi-megabyte array overflows the argument
  // stack, and attachments get that large.
  for (let i = 0; i < b.length; i += 0x8000) {
    s += String.fromCharCode(...b.subarray(i, i + 0x8000))
  }
  return btoa(s)
}

export function fromBase64(s: string): Bytes {
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function toHex(b: Bytes): string {
  let s = ''
  for (const x of b) s += x.toString(16).padStart(2, '0')
  return s
}

export function fromHex(s: string): Bytes {
  const clean = s.trim().replace(/[\s:-]/g, '')
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new Error('não é hexadecimal')
  }
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

// ---------------------------------------------------------------------------
// UUIDs
//
// Present as 16 raw bytes, not as a string. The sealed values are bound to the
// bytes, so a client that carried the hyphenated text around and converted late
// would have one more place to get it wrong.
// ---------------------------------------------------------------------------

const uuidPattern = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/

export function parseUUID(s: string): Bytes {
  if (!uuidPattern.test(s)) throw new Error(`não é um uuid: ${s}`)
  return fromHex(s.replace(/-/g, ''))
}

export function formatUUID(b: Bytes): string {
  if (b.length !== 16) throw new Error('um uuid tem 16 bytes')
  const h = toHex(b)
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}

/**
 * newUUIDv7 mints a time-ordered identifier, matching Go's uuid.NewV7.
 *
 * v7 rather than the v4 crypto.randomUUID gives, because these become primary
 * keys: a device id sorts by when it was created, so rows inserted together
 * land together in the index instead of scattering across it.
 *
 * The client picks the device id rather than the server because a key grant
 * binds to the device, so the grants have to be sealed before the row exists.
 */
export function newUUIDv7(): string {
  const b = crypto.getRandomValues(new Uint8Array(16)) as Bytes
  const ms = Date.now()
  const view = new DataView(b.buffer)
  // 48 bits of milliseconds, big endian, split because DataView has no 48-bit
  // integer and a Number cannot hold one shifted left by 32 without loss.
  view.setUint16(0, Math.floor(ms / 2 ** 32), false)
  view.setUint32(2, ms >>> 0, false)
  b[6] = (b[6] & 0x0f) | 0x70 // version 7
  b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
  return formatUUID(b)
}

/**
 * uuidV5 is the name-based UUID Go's uuid.NewSHA1 produces.
 *
 * Needed because a content key's row identity is derived from its own id
 * rather than stored, so that a key sealed for one slot cannot be presented as
 * another. The derivation has to match byte for byte or no content key opens.
 */
export async function uuidV5(namespace: Bytes, name: Bytes): Promise<Bytes> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', concat(namespace, name)))
  const out = digest.slice(0, 16)
  out[6] = (out[6] & 0x0f) | 0x50 // version 5
  out[8] = (out[8] & 0x3f) | 0x80 // RFC 4122 variant
  return out
}
