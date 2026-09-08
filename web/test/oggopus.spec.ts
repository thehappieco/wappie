import { describe, expect, it } from 'vitest'

import { crc32, opusSamples, webmToOggOpus } from '../src/media/oggopus'

// A voice note is Opus in an Ogg container, and the browser that records one
// hands back Opus in a WebM container instead. The audio is the same encoder's
// output either way, so moving it between the two is a repackaging — no
// decoding, no re-encoding, nothing about the sound changed.
//
// Which means it is checkable: the packets that go in must come out byte for
// byte, in order, and the pages around them must be the ones a player expects.
// Everything below builds a WebM by hand, repackages it, and reads the result
// back the way a player would.

const PRE_SKIP = 312

/** A 20 ms CELT packet at full band, which is what a recorder emits. */
function packet(byte = 0xf8, length = 40): Uint8Array {
  const out = new Uint8Array(length)
  out[0] = byte
  for (let i = 1; i < length; i++) out[i] = (i * 7) & 0xff
  return out
}

describe('how long an Opus packet lasts', () => {
  it('reads twenty milliseconds out of a CELT packet', () => {
    // 48 kHz × 20 ms. The granule position is counted in these, so a wrong
    // answer is a file that plays at the wrong length.
    expect(opusSamples(new Uint8Array([0xf8]))).toBe(960)
  })

  it('reads ten milliseconds out of a narrowband SILK packet', () => {
    expect(opusSamples(new Uint8Array([0x00]))).toBe(480)
  })

  it('reads sixty milliseconds, the longest SILK frame', () => {
    expect(opusSamples(new Uint8Array([0x18]))).toBe(2880)
  })

  it('doubles for a two-frame packet', () => {
    expect(opusSamples(new Uint8Array([0xf9]))).toBe(1920)
    expect(opusSamples(new Uint8Array([0xfa]))).toBe(1920)
  })

  it('reads an arbitrary frame count out of the byte after the header', () => {
    expect(opusSamples(new Uint8Array([0xfb, 5]))).toBe(4800)
  })

  it('answers nothing for a packet with nothing in it', () => {
    expect(opusSamples(new Uint8Array(0))).toBe(0)
    // Code 3 promises a count byte that is not there.
    expect(opusSamples(new Uint8Array([0xfb]))).toBe(0)
  })
})

describe("Ogg's checksum, which is not the usual one", () => {
  it('is the unreflected CRC-32, so one byte gives the polynomial itself', () => {
    // Same polynomial as everywhere else and none of the rest: no input or
    // output reflection, no initial value, no final xor. The familiar variant
    // produces a file every player rejects with nothing to say why.
    expect(crc32(new Uint8Array([0x01])) >>> 0).toBe(0x04c11db7)
  })

  it('is zero over nothing', () => {
    expect(crc32(new Uint8Array(0))).toBe(0)
  })
})

describe('repackaging a recording', () => {
  it('writes an Ogg stream a player can walk', () => {
    const pages = read(webmToOggOpus(webm([packet(), packet(), packet()]), 0x12345678)!)

    expect(pages.length).toBeGreaterThanOrEqual(3)
    for (const p of pages) {
      expect(p.capture).toBe('OggS')
      expect(p.version).toBe(0)
      expect(p.serial).toBe(0x12345678)
      // Recomputed with the checksum field zeroed, which is what a player does.
      expect(p.crcOK).toBe(true)
    }
    expect(pages.map((p) => p.sequence)).toEqual(pages.map((_, i) => i))
  })

  it('opens with the identification header, alone on its own page', () => {
    const pages = read(webmToOggOpus(webm([packet()]))!)
    expect(pages[0].flags & 0x02).toBe(0x02) // beginning of stream
    expect(pages[0].packets).toHaveLength(1)
    expect(ascii(pages[0].packets[0], 0, 8)).toBe('OpusHead')
    expect(pages[0].granule).toBe(0)
  })

  it('follows with the comment header the format requires', () => {
    const pages = read(webmToOggOpus(webm([packet()]))!)
    expect(ascii(pages[1].packets[0], 0, 8)).toBe('OpusTags')
    expect(pages[1].granule).toBe(0)
  })

  it('closes the stream, so a player knows it reached the end', () => {
    const pages = read(webmToOggOpus(webm([packet(), packet()]))!)
    expect(pages.at(-1)!.flags & 0x04).toBe(0x04)
  })

  it('gives back exactly the packets it was given, in order', () => {
    // The whole claim of this module. Nothing is decoded, so anything other
    // than byte equality means the audio was damaged in transit.
    const original = [packet(0xf8, 40), packet(0xf8, 17), packet(0xf8, 300)]
    const pages = read(webmToOggOpus(webm(original))!)
    const carried = pages.slice(2).flatMap((p) => p.packets)

    expect(carried).toHaveLength(original.length)
    for (let i = 0; i < original.length; i++) {
      expect(Array.from(carried[i])).toEqual(Array.from(original[i]))
    }
  })

  it('counts the granule position in samples the packets decode to', () => {
    const pages = read(webmToOggOpus(webm([packet(), packet(), packet()]))!)
    // Three twenty-millisecond packets. The pre-skip is not added on top: it is
    // part of what those packets already decode to, and the player subtracts
    // it. Adding it here makes every file play six milliseconds long — which is
    // what the first version of this did, and what a real recording run through
    // ffmpeg caught.
    expect(pages.at(-1)!.granule).toBe(3 * 960)
  })

  it('stops where the recording stopped, not where the last packet ends', () => {
    // Opus encodes in whole frames, so the last one runs past the end of the
    // audio. Matroska says how much to throw away and Ogg says the same thing
    // by putting a smaller number in the final granule position. Without this
    // the voice note is longer than it was.
    const pages = read(webmToOggOpus(webm([packet(), packet()], { discardMs: 13.5 }))!)
    expect(pages.at(-1)!.granule).toBe(2 * 960 - 648)
  })

  it('ignores padding that would run the granule backwards', () => {
    const pages = read(webmToOggOpus(webm([packet()], { discardMs: 5000 }))!)
    expect(pages.at(-1)!.granule).toBeGreaterThanOrEqual(0)
  })

  it('splits a long packet into laces rather than truncating it', () => {
    const long = packet(0xf8, 600)
    const pages = read(webmToOggOpus(webm([long]))!)
    const carried = pages.slice(2).flatMap((p) => p.packets)
    expect(carried[0]).toHaveLength(600)
  })

  it('starts another page rather than overflowing the segment table', () => {
    // A page holds 255 segments and no more. Three hundred packets cannot
    // share one, and a writer that does not notice produces a page whose
    // declared length disagrees with its contents.
    const many = Array.from({ length: 300 }, () => packet(0xf8, 20))
    const pages = read(webmToOggOpus(webm(many))!)
    const audio = pages.slice(2)
    expect(audio.length).toBeGreaterThan(1)
    for (const p of audio) expect(p.segments).toBeLessThanOrEqual(255)
    expect(audio.flatMap((p) => p.packets)).toHaveLength(300)
  })

  it('reads a packet out of a BlockGroup as well as a SimpleBlock', () => {
    const pages = read(webmToOggOpus(webm([packet()], { grouped: true }))!)
    expect(pages.slice(2).flatMap((p) => p.packets)).toHaveLength(1)
  })

  it('reads every Cluster, not only the first', () => {
    const many = Array.from({ length: 9 }, () => packet())
    const pages = read(webmToOggOpus(webm(many, { perCluster: 3 }))!)
    expect(pages.slice(2).flatMap((p) => p.packets)).toHaveLength(9)
  })

  it('reads every Cluster even when none of them declared a length', () => {
    // The case a finished file cannot produce, and a live recording always
    // does. Read as ordinary containers, the first Cluster appears to run to
    // the end of the file and swallows every one after it — leaving a valid,
    // checksum-clean Ogg holding the first few seconds of a recording of any
    // length, with nothing anywhere to say the rest was dropped.
    const many = Array.from({ length: 9 }, () => packet())
    const pages = read(webmToOggOpus(webm(many, { perCluster: 3, openClusters: true }))!)
    expect(pages.slice(2).flatMap((p) => p.packets)).toHaveLength(9)
  })

  it('reads the eight-byte form of an unknown length, which is what libwebm writes', () => {
    const many = Array.from({ length: 9 }, () => packet())
    const pages = read(
      webmToOggOpus(webm(many, { perCluster: 3, openClusters: true, wideUnknown: true }))!,
    )
    expect(pages.slice(2).flatMap((p) => p.packets)).toHaveLength(9)
  })

  it('finds the track when the Clusters have no declared length either', () => {
    const pages = read(webmToOggOpus(webm([packet()], { openClusters: true }))!)
    expect(pages[0].packets).toHaveLength(1)
  })

  it('handles a Segment whose length was unknown while recording', () => {
    // Which is how a live recording writes it: the size is not known when the
    // element is opened, so every bit of it is set.
    const pages = read(webmToOggOpus(webm([packet()], { unknownSize: true }))!)
    expect(pages.slice(2).flatMap((p) => p.packets)).toHaveLength(1)
  })
})

describe('refusing rather than guessing', () => {
  it('refuses a track that is not Opus', () => {
    expect(webmToOggOpus(webm([packet()], { codec: 'A_VORBIS' }))).toBeNull()
  })

  it('refuses a track with no identification header', () => {
    // Inventing one would mean guessing the channel count and the pre-skip,
    // which are two of the things that decide what the recipient hears.
    expect(webmToOggOpus(webm([packet()], { head: false }))).toBeNull()
  })

  it('refuses a laced block rather than splitting one packet into several', () => {
    expect(webmToOggOpus(webm([packet()], { laced: true }))).toBeNull()
  })

  it('refuses a recording with no audio in it at all', () => {
    expect(webmToOggOpus(webm([]))).toBeNull()
  })

  it('refuses bytes that are not a WebM', () => {
    expect(webmToOggOpus(new Uint8Array(64).fill(0x41))).toBeNull()
    expect(webmToOggOpus(new Uint8Array(0))).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Building a WebM by hand
// ---------------------------------------------------------------------------

interface Shape {
  codec?: string
  head?: boolean
  laced?: boolean
  grouped?: boolean
  unknownSize?: boolean
  /** Milliseconds of encoder padding to throw away at the end. */
  discardMs?: number
  /** How many blocks go in each Cluster. One Cluster by default. */
  perCluster?: number
  /** Write each Cluster's length as unknown, the way a live recorder does. */
  openClusters?: boolean
  /** Use the eight-byte form of "unknown", which is what libwebm writes. */
  wideUnknown?: boolean
}

function webm(packets: Uint8Array[], shape: Shape = {}): Uint8Array {
  const opusHead = () => {
    const out = new Uint8Array(19)
    out.set(new TextEncoder().encode('OpusHead'), 0)
    out[8] = 1 // version
    out[9] = 1 // channels
    out[10] = PRE_SKIP & 0xff
    out[11] = PRE_SKIP >> 8
    new DataView(out.buffer).setUint32(12, 48_000, true)
    return out
  }

  const fields = [
    element([0xd7], new Uint8Array([1])), // TrackNumber
    element([0x83], new Uint8Array([2])), // TrackType: audio
    element([0x86], new TextEncoder().encode(shape.codec ?? 'A_OPUS')),
  ]
  if (shape.head !== false) fields.push(element([0x63, 0xa2], opusHead()))
  const tracks = element([0x16, 0x54, 0xae, 0x6b], element([0xae], cat(fields)))

  const blocks = packets.map((p, i) => {
    const body = cat([
      new Uint8Array([0x81]), // track 1, as a VINT
      new Uint8Array([0x00, 0x00]), // relative timecode
      new Uint8Array([shape.laced ? 0x82 : 0x80]), // flags: lacing lives here
      p,
    ])
    const last = i === packets.length - 1
    if (shape.discardMs && last) {
      // DiscardPadding is nanoseconds, signed, and only ever on the last block.
      return element([0xa0], cat([element([0xa1], body), element([0x75, 0xa2], nanos(shape.discardMs))]))
    }
    if (shape.grouped) return element([0xa0], element([0xa1], body))
    return element([0xa3], body)
  })
  // Split across Clusters, because that is what a recording of any length is.
  const per = shape.perCluster ?? Math.max(1, blocks.length)
  const clusters: Uint8Array[] = []
  for (let at = 0; at < Math.max(1, blocks.length); at += per) {
    const contents = cat([element([0xe7], new Uint8Array([0])), ...blocks.slice(at, at + per)])
    clusters.push(
      shape.openClusters
        ? // An unknown length: every value bit set. A muxer writing live does
          // not know how long a Cluster will be when it opens one.
          cat([
            new Uint8Array([0x1f, 0x43, 0xb6, 0x75]),
            shape.wideUnknown
              ? new Uint8Array([0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
              : new Uint8Array([0xff]),
            contents,
          ])
        : element([0x1f, 0x43, 0xb6, 0x75], contents),
    )
  }

  const body = cat([tracks, ...clusters])
  const segment = shape.unknownSize
    ? cat([new Uint8Array([0x18, 0x53, 0x80, 0x67, 0xff]), body])
    : element([0x18, 0x53, 0x80, 0x67], body)
  return segment
}

/** nanos encodes a duration as the signed big-endian integer EBML wants. */
function nanos(ms: number): Uint8Array {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigInt64(0, BigInt(Math.round(ms * 1e6)), false)
  return out
}

function element(id: number[], payload: Uint8Array): Uint8Array {
  return cat([new Uint8Array(id), size(payload.length), payload])
}

/** size encodes an EBML length, widening until it fits. */
function size(n: number): Uint8Array {
  for (let width = 1; width <= 8; width++) {
    const limit = 2 ** (7 * width) - 1
    if (n >= limit) continue
    const out = new Uint8Array(width)
    let left = n
    for (let i = width - 1; i >= 0; i--) {
      out[i] = left & 0xff
      left = Math.floor(left / 256)
    }
    out[0] |= 0x80 >> (width - 1)
    return out
  }
  throw new Error('length beyond EBML')
}

function cat(parts: Uint8Array[]): Uint8Array {
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

// ---------------------------------------------------------------------------
// Reading an Ogg stream the way a player would
// ---------------------------------------------------------------------------

interface Page {
  capture: string
  version: number
  flags: number
  granule: number
  serial: number
  sequence: number
  segments: number
  packets: Uint8Array[]
  crcOK: boolean
}

function read(ogg: Uint8Array): Page[] {
  const pages: Page[] = []
  let at = 0
  while (at + 27 <= ogg.length) {
    const view = new DataView(ogg.buffer, ogg.byteOffset + at)
    const segments = ogg[at + 26]
    const table = ogg.subarray(at + 27, at + 27 + segments)
    let bodyLength = 0
    for (const lace of table) bodyLength += lace
    const total = 27 + segments + bodyLength
    const whole = ogg.subarray(at, at + total)

    // The checksum covers the page with its own checksum field zeroed.
    const blanked = whole.slice()
    blanked.set([0, 0, 0, 0], 22)

    const body = ogg.subarray(at + 27 + segments, at + total)
    const packets: Uint8Array[] = []
    let cursor = 0
    let start = 0
    for (const lace of table) {
      cursor += lace
      if (lace < 255) {
        packets.push(body.subarray(start, cursor))
        start = cursor
      }
    }

    pages.push({
      capture: ascii(ogg, at, at + 4),
      version: ogg[at + 4],
      flags: ogg[at + 5],
      granule: Number(view.getBigUint64(6, true)),
      serial: view.getUint32(14, true),
      sequence: view.getUint32(18, true),
      segments,
      packets,
      crcOK: crc32(blanked) === view.getUint32(22, true),
    })
    at += total
  }
  return pages
}

function ascii(bytes: Uint8Array, from: number, to: number): string {
  let out = ''
  for (let i = from; i < to && i < bytes.length; i++) out += String.fromCharCode(bytes[i])
  return out
}
