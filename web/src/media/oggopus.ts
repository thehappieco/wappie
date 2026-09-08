// Repackaging a recording as Ogg Opus.
//
// A voice note is Opus in an Ogg container. That is what WhatsApp's own clients
// record, and it is what they draw a waveform and a play button for. But the
// browser that would record one does not necessarily produce that: Chrome's
// MediaRecorder writes Opus inside a WebM container, Firefox will write Ogg if
// asked, and Safari writes AAC in MP4 and cannot be talked out of it.
//
// The Opus data is identical in the first two cases — same encoder, same
// packets — so this is a repackaging and not a transcode. Nothing is decoded,
// nothing is re-encoded, and nothing about the audio changes. The packets are
// lifted out of one container and written into the other, which costs a pass
// over a file that is measured in tens of kilobytes.
//
// Written out longhand rather than pulled from a library for the same reason
// the rest of this client is: it is a format, formats are checkable, and a
// dependency that ships a WebAssembly decoder to move bytes between two
// containers would be a much larger thing to trust.

import type { Bytes } from '../crypto/bytes'

/** SAMPLE_RATE is the only rate Ogg Opus counts in, whatever was recorded. */
const SAMPLE_RATE = 48_000

/**
 * webmToOggOpus repackages a WebM recording as Ogg Opus.
 *
 * Answers null rather than throwing when the input is not what it claims — a
 * different codec, a lacing scheme this does not read, a truncated file. The
 * caller then sends what it already had, which is worse for the recipient than
 * a voice note and much better than a corrupt one.
 */
export function webmToOggOpus(webm: Uint8Array, serial = randomSerial()): Bytes | null {
  const track = readOpusTrack(webm)
  if (!track) return null
  const audio = readPackets(webm, track.number)
  if (audio.packets.length === 0) return null
  return writeOgg(track.head, audio.packets, serial, audio.discardNs)
}

// ---------------------------------------------------------------------------
// Reading: just enough Matroska to find the Opus packets
// ---------------------------------------------------------------------------

const ID_SEGMENT = 0x18538067
const ID_TRACKS = 0x1654ae6b
const ID_TRACK_ENTRY = 0xae
const ID_TRACK_NUMBER = 0xd7
const ID_TRACK_TYPE = 0x83
const ID_CODEC_ID = 0x86
const ID_CODEC_PRIVATE = 0x63a2
const ID_CLUSTER = 0x1f43b675
const ID_SIMPLE_BLOCK = 0xa3
const ID_BLOCK_GROUP = 0xa0
const ID_BLOCK = 0xa1
const ID_DISCARD_PADDING = 0x75a2

interface Element {
  id: number
  /** Where the payload begins. */
  from: number
  /** Where the payload ends, and where the next sibling begins. */
  to: number
}

interface OpusTrack {
  number: number
  /** The OpusHead identification header, from CodecPrivate. */
  head: Uint8Array
}

/**
 * walk visits the children of a container, shallowly.
 *
 * Recursion is by calling walk again on a child, which keeps each caller
 * looking only at the level it cares about — and keeps a malformed size from
 * running the reader off the end, because every bound is clamped to the
 * parent's.
 */
function* walk(bytes: Uint8Array, from: number, to: number): Generator<Element> {
  let at = from
  while (at < to) {
    const id = readVint(bytes, at, true)
    if (!id) return
    const size = readVint(bytes, id.next, false)
    if (!size) return
    const start = size.next
    // An unknown size runs to the end of the parent, which is how a live
    // recording writes its Segment: the length was not known when it opened.
    const end = size.unknown ? to : Math.min(to, start + size.value)
    if (end < start) return
    yield { id: id.value, from: start, to: end }
    at = end
  }
}

/**
 * inside walks a Segment's contents, stepping into Clusters rather than over
 * them.
 *
 * This is the difference between reading a finished file and reading a
 * recording. A muxer writing live does not know how long a Cluster will be when
 * it opens one, so it writes the length as "unknown" — and an unknown length
 * does not mean "to the end of the file". It ends wherever the next element
 * that cannot be a Cluster's child begins.
 *
 * Treating a Cluster as an ordinary container therefore makes the first one
 * appear to swallow every Cluster after it, and a ten-minute recording comes
 * out three seconds long: valid Ogg, clean checksums, almost none of the audio.
 * Stepping in instead puts the blocks of every Cluster into one flat run, in
 * order, and never mis-bounds anything. A finished file, whose Clusters do
 * declare their length, reads exactly the same way.
 */
function* inside(bytes: Uint8Array, from: number, to: number): Generator<Element> {
  let at = from
  while (at < to) {
    const id = readVint(bytes, at, true)
    if (!id) return
    const size = readVint(bytes, id.next, false)
    if (!size) return
    const start = size.next
    if (id.value === ID_CLUSTER) {
      at = start
      continue
    }
    const end = size.unknown ? to : Math.min(to, start + size.value)
    if (end < start) return
    yield { id: id.value, from: start, to: end }
    at = end
  }
}

function readOpusTrack(webm: Uint8Array): OpusTrack | null {
  for (const top of walk(webm, 0, webm.length)) {
    if (top.id !== ID_SEGMENT) continue
    for (const child of inside(webm, top.from, top.to)) {
      if (child.id !== ID_TRACKS) continue
      for (const entry of walk(webm, child.from, child.to)) {
        if (entry.id !== ID_TRACK_ENTRY) continue
        const found = readTrackEntry(webm, entry)
        if (found) return found
      }
    }
  }
  return null
}

function readTrackEntry(webm: Uint8Array, entry: Element): OpusTrack | null {
  let number = 0
  let audio = false
  let opus = false
  let head: Uint8Array | null = null

  for (const field of walk(webm, entry.from, entry.to)) {
    switch (field.id) {
      case ID_TRACK_NUMBER:
        number = readUint(webm, field.from, field.to)
        break
      case ID_TRACK_TYPE:
        audio = readUint(webm, field.from, field.to) === 2
        break
      case ID_CODEC_ID:
        opus = readAscii(webm, field.from, field.to) === 'A_OPUS'
        break
      case ID_CODEC_PRIVATE:
        head = webm.subarray(field.from, field.to)
        break
      default:
        break
    }
  }

  if (!number || !audio || !opus) return null
  // Without the identification header there is nothing to describe the stream
  // with, and inventing one would mean guessing the channel count and the
  // pre-skip — two numbers that decide what the recipient hears.
  if (!head || head.length < 19 || readAscii(head, 0, 8) !== 'OpusHead') return null
  return { number, head }
}

/**
 * readPackets pulls every Opus packet for one track, in order.
 *
 * It also collects the end padding, which is the part easy to miss. Opus
 * encodes in whole frames, so the last one runs past where the recording
 * actually stopped — by twenty milliseconds in the file this was checked
 * against. Matroska says how much to throw away in DiscardPadding; Ogg says the
 * same thing by putting a smaller number in its final granule position. Ignore
 * it and the voice note plays fractionally long, and every duration read off it
 * is wrong by that much.
 */
function readPackets(webm: Uint8Array, track: number): { packets: Uint8Array[]; discardNs: number } {
  const packets: Uint8Array[] = []
  let discardNs = 0
  for (const top of walk(webm, 0, webm.length)) {
    if (top.id !== ID_SEGMENT) continue
    for (const item of inside(webm, top.from, top.to)) {
      if (item.id === ID_SIMPLE_BLOCK) {
        collect(webm, item, track, packets)
        continue
      }
      if (item.id !== ID_BLOCK_GROUP) continue
      const before = packets.length
      let padding = 0
      for (const inner of walk(webm, item.from, item.to)) {
        if (inner.id === ID_BLOCK) collect(webm, inner, track, packets)
        if (inner.id === ID_DISCARD_PADDING) padding = readInt(webm, inner.from, inner.to)
      }
      // Counted only when the group actually contributed a packet of ours: a
      // group belonging to another track says nothing about this one.
      if (packets.length > before && padding > 0) discardNs += padding
    }
  }
  return { packets, discardNs }
}

function collect(webm: Uint8Array, block: Element, track: number, into: Uint8Array[]): void {
  const number = readVint(webm, block.from, false)
  if (!number || number.value !== track) return
  // Two bytes of relative timecode, then the flags. The timecode is not needed:
  // Ogg counts in decoded samples, which the packets themselves declare.
  const flags = number.next + 2
  if (flags >= block.to) return
  // Bits 1 and 2 are the lacing scheme. A recorder writing Opus does not lace,
  // and reading a scheme wrongly would split one packet into several — so an
  // unexpected value is refused rather than guessed at.
  if ((webm[flags] & 0x06) !== 0) return
  const payload = webm.subarray(flags + 1, block.to)
  if (payload.length > 0) into.push(payload)
}

/**
 * readVint reads an EBML variable-length integer.
 *
 * The marker bit is part of an element ID and is stripped from a size, which is
 * the whole difference between the two and the usual place this goes wrong.
 */
function readVint(
  bytes: Uint8Array,
  at: number,
  keepMarker: boolean,
): { value: number; next: number; unknown: boolean } | null {
  if (at >= bytes.length) return null
  const first = bytes[at]
  if (first === 0) return null
  let width = 1
  while (width <= 8 && !(first & (0x80 >> (width - 1)))) width++
  if (width > 8 || at + width > bytes.length) return null

  let value = keepMarker ? first : first & (0xff >> width)
  let allOnes = (first & (0xff >> width)) === 0xff >> width
  for (let i = 1; i < width; i++) {
    // Multiplication rather than a shift: a size can exceed 32 bits, and a
    // shift in JavaScript silently wraps at that point.
    value = value * 256 + bytes[at + i]
    if (bytes[at + i] !== 0xff) allOnes = false
  }
  return { value, next: at + width, unknown: !keepMarker && allOnes }
}

function readUint(bytes: Uint8Array, from: number, to: number): number {
  let value = 0
  for (let i = from; i < to; i++) value = value * 256 + bytes[i]
  return value
}

/** readInt reads a signed big-endian EBML integer. */
function readInt(bytes: Uint8Array, from: number, to: number): number {
  if (to <= from) return 0
  let value = bytes[from] & 0x80 ? bytes[from] - 256 : bytes[from]
  for (let i = from + 1; i < to; i++) value = value * 256 + bytes[i]
  return value
}

function readAscii(bytes: Uint8Array, from: number, to: number): string {
  let out = ''
  for (let i = from; i < to && i < bytes.length; i++) {
    if (bytes[i] === 0) break
    out += String.fromCharCode(bytes[i])
  }
  return out
}

// ---------------------------------------------------------------------------
// Writing: Ogg pages
// ---------------------------------------------------------------------------

/**
 * opusSamples reports how many samples at 48 kHz a packet decodes to.
 *
 * Read out of the packet's own first byte rather than assumed, because it is
 * what the granule position is counted in — and a granule position that does
 * not match the audio is a file that plays at the wrong length, or seeks to the
 * wrong place, on a player that trusts it.
 */
export function opusSamples(packet: Uint8Array): number {
  if (packet.length === 0) return 0
  const toc = packet[0]
  const config = toc >> 3
  let frameMs: number
  if (config < 12) {
    // SILK: 10, 20, 40 or 60 ms, in that order within each bandwidth.
    frameMs = [10, 20, 40, 60][config % 4]
  } else if (config < 16) {
    // Hybrid: 10 or 20 ms.
    frameMs = [10, 20][config % 2]
  } else {
    // CELT: 2.5, 5, 10 or 20 ms.
    frameMs = [2.5, 5, 10, 20][config % 4]
  }

  let frames: number
  switch (toc & 0x03) {
    case 0:
      frames = 1
      break
    case 1:
    case 2:
      frames = 2
      break
    default:
      // Arbitrary count, declared in the byte after the table of contents.
      if (packet.length < 2) return 0
      frames = packet[1] & 0x3f
      break
  }
  return Math.round((frameMs * SAMPLE_RATE) / 1000) * frames
}

function writeOgg(
  head: Uint8Array,
  packets: Uint8Array[],
  serial: number,
  discardNs: number,
): Bytes {
  const pages: Uint8Array[] = []
  let sequence = 0

  // Each header packet gets a page of its own, which the format requires.
  pages.push(page([head], 0, serial, sequence++, 0x02))
  pages.push(page([opusTags()], 0, serial, sequence++, 0x00))

  const discard = Math.max(0, Math.round((discardNs * SAMPLE_RATE) / 1e9))

  let granule = 0
  let written = 0
  let batch: Uint8Array[] = []
  let segments = 0

  const flush = (last: boolean) => {
    if (batch.length === 0 && !last) return
    // The end padding comes off the final page and only the final page: that
    // is the whole mechanism Ogg has for saying "stop before the packets do".
    // Never backwards, though — a granule position below the one before it is a
    // stream a player will refuse to seek in.
    const at = Math.max(written, last ? granule - discard : granule)
    written = at
    pages.push(page(batch, at, serial, sequence++, last ? 0x04 : 0x00))
    batch = []
    segments = 0
  }

  for (let i = 0; i < packets.length; i++) {
    const packet = packets[i]
    const needed = Math.floor(packet.length / 255) + 1
    // A page carries at most 255 segments, so a packet that will not fit
    // starts a new one. Packets are never split across pages here, which the
    // format allows and which keeps the granule position exact.
    if (segments + needed > 255) flush(false)
    batch.push(packet)
    segments += needed
    granule += opusSamples(packet)
    if (i === packets.length - 1) flush(true)
  }

  return concat(pages)
}

/** page builds one Ogg page, with its checksum. */
function page(
  packets: Uint8Array[],
  granule: number,
  serial: number,
  sequence: number,
  flags: number,
): Uint8Array {
  const table: number[] = []
  let bodyLength = 0
  for (const packet of packets) {
    let left = packet.length
    while (left >= 255) {
      table.push(255)
      left -= 255
    }
    table.push(left)
    bodyLength += packet.length
  }
  // A page with no packets at all still needs one terminating lace, or a
  // reader sees a page it cannot end.
  if (table.length === 0) table.push(0)

  const out = new Uint8Array(27 + table.length + bodyLength)
  const view = new DataView(out.buffer)
  out.set([0x4f, 0x67, 0x67, 0x53], 0) // "OggS"
  out[4] = 0 // stream structure version
  out[5] = flags
  writeUint64LE(view, 6, granule)
  view.setUint32(14, serial, true)
  view.setUint32(18, sequence, true)
  view.setUint32(22, 0, true) // checksum, filled in below
  out[26] = table.length
  out.set(table, 27)

  let at = 27 + table.length
  for (const packet of packets) {
    out.set(packet, at)
    at += packet.length
  }

  view.setUint32(22, crc32(out), true)
  return out
}

/**
 * crc32 is Ogg's checksum, which is not the common one.
 *
 * Same polynomial as the CRC-32 everywhere else, and none of the rest: no input
 * reflection, no output reflection, no initial value and no final xor. Using
 * the familiar variant produces a file every player rejects, with nothing to
 * say why.
 */
export function crc32(bytes: Uint8Array): number {
  let crc = 0
  for (const byte of bytes) {
    crc = ((crc << 8) ^ CRC_TABLE[((crc >>> 24) ^ byte) & 0xff]) >>> 0
  }
  return crc >>> 0
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let value = (i << 24) >>> 0
    for (let bit = 0; bit < 8; bit++) {
      value = ((value & 0x80000000) !== 0 ? ((value << 1) ^ 0x04c11db7) : value << 1) >>> 0
    }
    table[i] = value
  }
  return table
})()

/** opusTags is the comment header, which the format requires and nothing reads. */
function opusTags(): Uint8Array {
  const vendor = new TextEncoder().encode('whatserver2')
  const out = new Uint8Array(8 + 4 + vendor.length + 4)
  out.set(new TextEncoder().encode('OpusTags'), 0)
  const view = new DataView(out.buffer)
  view.setUint32(8, vendor.length, true)
  out.set(vendor, 12)
  view.setUint32(12 + vendor.length, 0, true) // no user comments
  return out
}

function writeUint64LE(view: DataView, at: number, value: number): void {
  // Through BigInt because a granule position passes 2^32 after about a day of
  // audio, and the shift that would otherwise be used wraps long before that.
  view.setBigUint64(at, BigInt(Math.max(0, Math.round(value))), true)
}

function concat(parts: Uint8Array[]): Bytes {
  let length = 0
  for (const part of parts) length += part.length
  const out = new Uint8Array(length)
  let at = 0
  for (const part of parts) {
    out.set(part, at)
    at += part.length
  }
  return out
}

function randomSerial(): number {
  return crypto.getRandomValues(new Uint32Array(1))[0]
}
