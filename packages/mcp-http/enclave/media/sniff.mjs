// What an attachment's plaintext is, from its first bytes (docs/mcp-enclave.md
// §16.5): the row's `mimetype` and the filename are never trusted, and the
// HKDF label binds only the family. Plain text is the one kind the reader's
// Node reads itself, and it only decodes it: no structure is interpreted.
import { JOB_TEXT_MAX_BYTES, TEXT_MIMETYPES, TEXT_SNIFF_BYTES } from './policy.mjs'

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
const CFB = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
const starts = (bytes, prefix) => bytes.length >= prefix.length && [...prefix].every((value, index) => bytes[index] === value)
const ascii = (bytes, at, text) => bytes.length >= at + text.length && [...text].every((char, index) => bytes[at + index] === char.charCodeAt(0))

/** The image kinds, which the image worker takes. */
export const IMAGE_SNIFFED = Object.freeze(['jpeg', 'png', 'gif', 'webp'])

/** `mimetype` lower-cased and without parameters. */
const essence = mimetype => (typeof mimetype === 'string' ? mimetype.split(';')[0].trim().toLowerCase() : '')

/**
 * `{sniffed, kind}` for the first bytes of a plaintext, or null (§16.5's
 * table). `zip` and `cfb` are of kind 'office' until the office worker says
 * whether a zip is an office file or an archive.
 */
export function sniff(input, mimetype) {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input.buffer, input.byteOffset, input.byteLength)
  if (starts(bytes, [0xff, 0xd8, 0xff])) return { sniffed: 'jpeg', kind: 'image' }
  if (starts(bytes, PNG)) return { sniffed: 'png', kind: 'image' }
  if (ascii(bytes, 0, 'GIF87a') || ascii(bytes, 0, 'GIF89a')) return { sniffed: 'gif', kind: 'image' }
  if (ascii(bytes, 0, 'RIFF') && ascii(bytes, 8, 'WEBP')) return { sniffed: 'webp', kind: 'image' }
  if (bytes.subarray(0, 1024).includes('%PDF-')) return { sniffed: 'pdf', kind: 'pdf' }
  if (starts(bytes, [0x50, 0x4b, 0x03, 0x04]) || starts(bytes, [0x50, 0x4b, 0x05, 0x06])) return { sniffed: 'zip', kind: 'office' }
  if (starts(bytes, CFB)) return { sniffed: 'cfb', kind: 'office' }
  if (TEXT_MIMETYPES.includes(essence(mimetype)) && !bytes.subarray(0, TEXT_SNIFF_BYTES).includes(0)) return { sniffed: 'text', kind: 'text' }
  return null
}

// windows-1252 differs from latin1 only in 0x80-0x9F; the five bytes it
// leaves undefined decode to their C1 code point, which the cleaning drops.
const CP1252 = [0x20ac, 0x81, 0x201a, 0x192, 0x201e, 0x2026, 0x2020, 0x2021, 0x2c6, 0x2030, 0x160, 0x2039, 0x152, 0x8d, 0x17d, 0x8f,
  0x90, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014, 0x2dc, 0x2122, 0x161, 0x203a, 0x153, 0x9d, 0x17e, 0x178]
function windows1252(bytes) {
  let text = ''
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    const codes = Array.from(bytes.subarray(offset, offset + 8192), byte => (byte >= 0x80 && byte <= 0x9f ? CP1252[byte - 0x80] : byte))
    text += String.fromCharCode(...codes)
  }
  return text
}

/**
 * Text as the reader passes it on, from a worker frame or a decoded file:
 * `\r\n` and `\r` become `\n`, and C0 controls other than tab and newline,
 * DEL and C1 controls are removed (§16.11).
 */
export const cleanText = text => text.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, '')

/** The largest prefix of UTF-8 `bytes` no longer than `max` that ends on a character boundary. */
function utf8Boundary(bytes, max) {
  let end = Math.min(max, bytes.length)
  if (end === bytes.length) return end
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) end--
  return end
}

/**
 * Decodes a plain-text file (§16.5): a UTF-8 BOM is dropped; a UTF-16 BOM
 * decodes as UTF-16LE or BE; otherwise fatal UTF-8, falling back to
 * windows-1252. At most JOB_TEXT_MAX_BYTES are decoded, cut back to a
 * character boundary of the encoding; `cut` says more was there.
 */
export function decodeText(bytes, max = JOB_TEXT_MAX_BYTES) {
  let text, cut
  if (starts(bytes, [0xff, 0xfe]) || starts(bytes, [0xfe, 0xff])) {
    const little = bytes[0] === 0xff
    let body = bytes.subarray(2)
    cut = body.length > max
    let end = Math.min(max, body.length) & ~1
    // A high surrogate at the end would lose its pair.
    const unit = at => (little ? body[at] | (body[at + 1] << 8) : (body[at] << 8) | body[at + 1])
    if (cut && end >= 2 && unit(end - 2) >= 0xd800 && unit(end - 2) <= 0xdbff) end -= 2
    body = body.subarray(0, end)
    if (!little) {
      const swapped = Buffer.alloc(body.length)
      for (let index = 0; index + 1 < body.length; index += 2) { swapped[index] = body[index + 1]; swapped[index + 1] = body[index] }
      body = swapped
    }
    text = new TextDecoder('utf-16le').decode(body)
    if (!little) body.fill(0)
  } else {
    const body = starts(bytes, [0xef, 0xbb, 0xbf]) ? bytes.subarray(3) : bytes
    cut = body.length > max
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(body.subarray(0, utf8Boundary(body, max)))
    } catch {
      text = windows1252(body.subarray(0, Math.min(max, body.length)))
    }
  }
  return { text: cleanText(text), cut }
}
