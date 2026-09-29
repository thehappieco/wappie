// Just enough of the Compound File Binary format ([MS-CFB]) to classify a
// CFB file before any parser runs (docs/mcp-enclave.md §16.11): the names in
// its directory. A `Workbook` or `Book` stream is a legacy Excel workbook;
// `EncryptionInfo` is a password-protected OOXML package; anything else (Word
// 97 and PowerPoint 97 files, Outlook messages) is not opened. No stream
// content is read here. Every chain is bounded by the file's own sector
// count, so a loop or an out-of-range sector is `damaged`, never a hang.

import { refuse } from './frames.mjs'

const SIGNATURE = Buffer.from('d0cf11e0a1b11ae1', 'hex')
const END_OF_CHAIN = 0xfffffffe
const MAX_REGULAR = 0xfffffffa

/** The upper-cased names of every storage and stream in the directory. */
export function cfbNames(buf, maxEntries) {
  if (buf.length < 512 || !buf.subarray(0, 8).equals(SIGNATURE)) throw refuse('damaged')
  if (buf.readUInt16LE(0x1c) !== 0xfffe) throw refuse('damaged')
  const shift = buf.readUInt16LE(0x1e)
  if (shift !== 9 && shift !== 12) throw refuse('damaged')
  const size = 1 << shift
  const sectors = Math.floor((buf.length - size) / size) + (buf.length % size ? 1 : 0)
  const sector = (n) => {
    if (n > MAX_REGULAR || n >= sectors) throw refuse('damaged')
    const at = (n + 1) * size
    return buf.subarray(at, Math.min(at + size, buf.length))
  }

  // The FAT: its sector numbers come from the header's 109 DIFAT slots, then
  // the DIFAT chain (each DIFAT sector ends with the next one's number).
  const fatSectors = []
  const fatCount = buf.readUInt32LE(0x2c)
  if (fatCount > sectors) throw refuse('damaged')
  for (let k = 0; k < 109 && fatSectors.length < fatCount; k++) fatSectors.push(buf.readUInt32LE(0x4c + 4 * k))
  let difat = buf.readUInt32LE(0x44)
  for (let hops = 0; fatSectors.length < fatCount; hops++) {
    if (hops > sectors || difat > MAX_REGULAR) throw refuse('damaged')
    const s = sector(difat)
    const slots = size / 4 - 1
    for (let k = 0; k < slots && fatSectors.length < fatCount; k++) fatSectors.push(s.readUInt32LE(4 * k))
    difat = s.readUInt32LE(4 * slots)
  }
  const fat = []
  for (const n of fatSectors) {
    const s = sector(n)
    for (let k = 0; k + 4 <= s.length; k += 4) fat.push(s.readUInt32LE(k))
  }

  // The directory stream: 128-byte entries, name in UTF-16LE (length in
  // bytes with the terminator), type 1 storage, 2 stream, 5 root.
  const names = []
  const seen = new Set()
  let entries = 0
  for (let n = buf.readUInt32LE(0x30); n !== END_OF_CHAIN; n = fat[n]) {
    if (seen.has(n) || n === undefined || n > MAX_REGULAR) throw refuse('damaged')
    seen.add(n)
    const s = sector(n)
    for (let k = 0; k + 128 <= s.length; k += 128) {
      const type = s[k + 0x42]
      if (type !== 1 && type !== 2) continue
      if (++entries > maxEntries) throw refuse('too_large', 'entries')
      const length = s.readUInt16LE(k + 0x40)
      if (length < 2 || length > 64 || length % 2) throw refuse('damaged')
      names.push(s.toString('utf16le', k, k + length - 2).toUpperCase())
    }
  }
  return names
}

/** Classify a CFB file: 'xls', 'encrypted' or null (not opened). */
export function classifyCfb(buf, maxEntries) {
  const names = new Set(cfbNames(buf, maxEntries))
  if (names.has('ENCRYPTIONINFO') || names.has('ENCRYPTEDPACKAGE')) return 'encrypted'
  if (names.has('WORKBOOK') || names.has('BOOK')) return 'xls'
  return null
}
