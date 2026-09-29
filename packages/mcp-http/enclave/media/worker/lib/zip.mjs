// The office worker's zip reader (docs/mcp-enclave.md §16.11): the central
// directory, with the bomb checks applied before anything is inflated, and an
// inflater that counts. It serves both kinds that come as zip archives: office
// (OOXML and ODF packages) and zip (listed by name), so a flaw here needs both
// kinds off (§16.12).
//
// The checks, all on the central directory first: at most `limits.entries`
// entries (else too_large/entries); every entry's declared size within
// `limits.ratio` times its compressed size, and all declared sizes within
// `limits.inflated` bytes (else too_large/inflated). Inflating then counts
// again: an entry may not produce more than it declared, and all entries
// inflated in one job stay within `limits.inflated`.

import { crc32, inflateRawSync } from 'node:zlib'
import { refuse } from './frames.mjs'

const EOCD = 0x06054b50
const EOCD64_LOCATOR = 0x07064b50
const EOCD64 = 0x06064b50
const CENTRAL = 0x02014b50
const LOCAL = 0x04034b50

// CP437, the encoding of a name without the UTF-8 flag (bit 11): 0x80-0xFF.
const CP437 =
  'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀' +
  'αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ '

function cp437(bytes) {
  let s = ''
  for (const b of bytes) s += b < 0x80 ? String.fromCharCode(b) : CP437[b - 0x80]
  return s
}

const utf8 = new TextDecoder('utf-8')

/**
 * Read the central directory of `buf` and apply the declared checks.
 * Returns { entries }, each { name, method, flags, crc, compressed, size,
 * offset, directory, encrypted }, in central-directory order.
 */
export function readZip(buf, limits) {
  const end = findEnd(buf)
  let count = buf.readUInt16LE(end + 10)
  let cdSize = buf.readUInt32LE(end + 12)
  let cdOffset = buf.readUInt32LE(end + 16)
  if (buf.readUInt16LE(end + 4) !== 0 || buf.readUInt16LE(end + 6) !== 0) throw refuse('unsupported')
  if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    ;({ count, cdSize, cdOffset } = zip64End(buf, end))
  }
  if (count > limits.entries) throw refuse('too_large', 'entries')
  if (cdOffset + cdSize > buf.length) throw refuse('damaged')

  const entries = []
  let declared = 0
  let at = cdOffset
  for (let k = 0; k < count; k++) {
    if (at + 46 > buf.length || buf.readUInt32LE(at) !== CENTRAL) throw refuse('damaged')
    const flags = buf.readUInt16LE(at + 8)
    const method = buf.readUInt16LE(at + 10)
    const crc = buf.readUInt32LE(at + 16)
    let compressed = buf.readUInt32LE(at + 20)
    let size = buf.readUInt32LE(at + 24)
    const nameLength = buf.readUInt16LE(at + 28)
    const extraLength = buf.readUInt16LE(at + 30)
    const commentLength = buf.readUInt16LE(at + 32)
    let offset = buf.readUInt32LE(at + 42)
    const nameStart = at + 46
    const extraStart = nameStart + nameLength
    const next = extraStart + extraLength + commentLength
    if (next > buf.length) throw refuse('damaged')
    if (size === 0xffffffff || compressed === 0xffffffff || offset === 0xffffffff) {
      ;({ size, compressed, offset } = zip64Extra(buf, extraStart, extraLength, { size, compressed, offset }))
    }
    const nameBytes = buf.subarray(nameStart, extraStart)
    const name = flags & 0x800 ? utf8.decode(nameBytes) : cp437(nameBytes)
    if (size > 0 && (compressed === 0 || size / compressed > limits.ratio)) throw refuse('too_large', 'inflated')
    declared += size
    if (declared > limits.inflated) throw refuse('too_large', 'inflated')
    entries.push({
      name,
      method,
      flags,
      crc,
      compressed,
      size,
      offset,
      directory: name.endsWith('/'),
      encrypted: (flags & 0x1) !== 0 || method === 99,
    })
    at = next
  }
  return { entries }
}

function findEnd(buf) {
  const floor = Math.max(0, buf.length - 22 - 0xffff)
  for (let at = buf.length - 22; at >= floor; at--) {
    if (buf.readUInt32LE(at) === EOCD && at + 22 + buf.readUInt16LE(at + 20) <= buf.length) return at
  }
  throw refuse('damaged')
}

function zip64End(buf, end) {
  const locator = end - 20
  if (locator < 0 || buf.readUInt32LE(locator) !== EOCD64_LOCATOR) throw refuse('damaged')
  const record = Number(buf.readBigUInt64LE(locator + 8))
  if (!Number.isSafeInteger(record) || record + 56 > buf.length || buf.readUInt32LE(record) !== EOCD64) throw refuse('damaged')
  const count = Number(buf.readBigUInt64LE(record + 32))
  const cdSize = Number(buf.readBigUInt64LE(record + 40))
  const cdOffset = Number(buf.readBigUInt64LE(record + 48))
  if (![count, cdSize, cdOffset].every(Number.isSafeInteger)) throw refuse('damaged')
  return { count, cdSize, cdOffset }
}

// The zip64 extended information extra field (0x0001) holds, in this order,
// whichever of size, compressed size and offset are 0xFFFFFFFF in the record.
function zip64Extra(buf, start, length, fields) {
  const out = { ...fields }
  for (let at = start; at + 4 <= start + length; ) {
    const id = buf.readUInt16LE(at)
    const size = buf.readUInt16LE(at + 2)
    if (at + 4 + size > start + length) break
    if (id === 0x0001) {
      let p = at + 4
      const take = () => {
        if (p + 8 > at + 4 + size) throw refuse('damaged')
        const v = Number(buf.readBigUInt64LE(p))
        p += 8
        if (!Number.isSafeInteger(v)) throw refuse('damaged')
        return v
      }
      if (fields.size === 0xffffffff) out.size = take()
      if (fields.compressed === 0xffffffff) out.compressed = take()
      if (fields.offset === 0xffffffff) out.offset = take()
      return out
    }
    at += 4 + size
  }
  throw refuse('damaged')
}

/**
 * The inflater for one job. `budget` counts every byte inflated, so the
 * entries a job reads stay within `limits.inflated` whatever they declared.
 */
export class Inflater {
  constructor(buf, limits) {
    this.buf = buf
    this.left = limits.inflated
  }

  /** The entry's bytes, checked against its declared size and CRC-32. */
  read(entry) {
    if (entry.encrypted) throw refuse('encrypted')
    const at = entry.offset
    if (at + 30 > this.buf.length || this.buf.readUInt32LE(at) !== LOCAL) throw refuse('damaged')
    const start = at + 30 + this.buf.readUInt16LE(at + 26) + this.buf.readUInt16LE(at + 28)
    const data = this.buf.subarray(start, start + entry.compressed)
    if (data.length !== entry.compressed) throw refuse('damaged')
    if (entry.size > this.left) throw refuse('too_large', 'inflated')
    let out
    if (entry.method === 0) {
      if (entry.size !== entry.compressed) throw refuse('damaged')
      out = Buffer.from(data)
    } else if (entry.method === 8) {
      try {
        // One byte more than declared: an entry that inflates past its
        // declared size is refused as a bomb, one that falls short is damaged.
        out = inflateRawSync(data, { maxOutputLength: Math.max(1, entry.size + 1) })
      } catch (e) {
        if (e?.code === 'ERR_BUFFER_TOO_LARGE') throw refuse('too_large', 'inflated')
        throw refuse('damaged')
      }
      if (out.length > entry.size) throw refuse('too_large', 'inflated')
    } else {
      throw refuse('unsupported')
    }
    if (out.length !== entry.size || crc32(out) !== entry.crc) throw refuse('damaged')
    this.left -= out.length
    return out
  }
}
