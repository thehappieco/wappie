// A QR encoder, byte mode, versions 1 to 40.
//
// Written here rather than installed, for the same reason HPKE is: everything
// in this bundle runs in the origin that holds an unlocked archive key, and a
// package that can read every message is not a small thing to add for one
// screen. This file touches no keys and produces a grid of booleans.
//
// It is also the safest kind of code to write by hand — a mistake is visible.
// A wrong QR does not scan, and nobody is left believing something worked.
//
// Structure follows ISO/IEC 18004: pick the smallest version that fits, build
// the bit stream, split it into blocks with Reed-Solomon parity, interleave,
// draw the function patterns, lay the data along the zigzag, and choose the
// mask that scores best.

/** Matrix is row-major: matrix[y][x], true meaning a dark module. */
export type Matrix = boolean[][]

export type ECLevel = 'L' | 'M' | 'Q' | 'H'

const ECL_INDEX: Record<ECLevel, number> = { L: 0, M: 1, Q: 2, H: 3 }
// The format field does not use the same order as the error-correction levels.
const ECL_FORMAT_BITS: Record<ECLevel, number> = { L: 1, M: 0, Q: 3, H: 2 }

// Error-correction codewords per block, indexed [level][version]. Index 0 is
// unused: versions start at 1. Straight from the standard's tables.
const ECC_PER_BLOCK: number[][] = [
  // 0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31  32  33  34  35  36  37  38  39  40
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
]

// How many blocks the data is split into, indexed [level][version].
const NUM_BLOCKS: number[][] = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
]

const MIN_VERSION = 1
const MAX_VERSION = 40

export class QRError extends Error {}

/**
 * encode turns text into a module grid.
 *
 * Byte mode only. The alphanumeric and numeric modes pack tighter, and the
 * payloads here are base64 — which alphanumeric mode cannot even express, since
 * it has no lower case.
 */
export function encode(text: string, level: ECLevel = 'M'): Matrix {
  const data = new TextEncoder().encode(text)
  const version = smallestVersion(data.length, level)
  const size = version * 4 + 17

  const codewords = buildCodewords(data, version, level)

  const modules: Matrix = Array.from({ length: size }, () => new Array<boolean>(size).fill(false))
  const reserved: boolean[][] = Array.from({ length: size }, () =>
    new Array<boolean>(size).fill(false),
  )
  const grid = { modules, reserved, size, version, level }

  drawFunctionPatterns(grid)
  drawCodewords(grid, codewords)

  // Every mask produces a readable code; the score only decides which is
  // easiest for a scanner. Lowest wins.
  let best = 0
  let bestScore = Infinity
  for (let mask = 0; mask < 8; mask++) {
    applyMask(grid, mask)
    drawFormatBits(grid, mask)
    const score = penalty(grid)
    if (score < bestScore) {
      bestScore = score
      best = mask
    }
    applyMask(grid, mask) // XOR again to undo
  }
  applyMask(grid, best)
  drawFormatBits(grid, best)
  return modules
}

/** svgPath renders a matrix as one SVG path, for a viewBox of size+2*quiet. */
export function svgPath(matrix: Matrix, quiet = 4): { path: string; extent: number } {
  const parts: string[] = []
  for (let y = 0; y < matrix.length; y++) {
    for (let x = 0; x < matrix.length; x++) {
      if (matrix[y][x]) parts.push(`M${x + quiet} ${y + quiet}h1v1h-1z`)
    }
  }
  return { path: parts.join(''), extent: matrix.length + quiet * 2 }
}

// ---------------------------------------------------------------------------
// Choosing a version and building the bit stream
// ---------------------------------------------------------------------------

/** charCountBits is how wide the length field is, which changes with version. */
function charCountBits(version: number): number {
  return version <= 9 ? 8 : 16
}

function rawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64
  if (version >= 2) {
    const numAlign = Math.floor(version / 7) + 2
    result -= (25 * numAlign - 10) * numAlign - 55
    if (version >= 7) result -= 36
  }
  return result
}

function dataCodewords(version: number, level: ECLevel): number {
  const ecl = ECL_INDEX[level]
  return (
    Math.floor(rawDataModules(version) / 8) -
    ECC_PER_BLOCK[ecl][version] * NUM_BLOCKS[ecl][version]
  )
}

function smallestVersion(byteLength: number, level: ECLevel): number {
  for (let version = MIN_VERSION; version <= MAX_VERSION; version++) {
    const capacity = dataCodewords(version, level) * 8
    if (4 + charCountBits(version) + byteLength * 8 <= capacity) return version
  }
  throw new QRError(`${byteLength} bytes não cabem em um QR code`)
}

/** buildCodewords produces the interleaved data and parity bytes. */
function buildCodewords(data: Uint8Array, version: number, level: ECLevel): number[] {
  const bits: number[] = []
  const push = (value: number, width: number) => {
    for (let i = width - 1; i >= 0; i--) bits.push((value >>> i) & 1)
  }

  push(0b0100, 4) // byte mode
  push(data.length, charCountBits(version))
  for (const b of data) push(b, 8)

  const capacity = dataCodewords(version, level) * 8
  push(0, Math.min(4, capacity - bits.length)) // terminator
  push(0, (8 - (bits.length % 8)) % 8) // to a byte boundary

  const bytes: number[] = []
  for (let i = 0; i < bits.length; i += 8) {
    let value = 0
    for (let j = 0; j < 8; j++) value = (value << 1) | bits[i + j]
    bytes.push(value)
  }
  // The two pad bytes the standard names, alternating.
  for (let pad = 0xec; bytes.length < capacity / 8; pad ^= 0xec ^ 0x11) bytes.push(pad)

  return interleave(bytes, version, level)
}

function interleave(data: number[], version: number, level: ECLevel): number[] {
  const ecl = ECL_INDEX[level]
  const blocks = NUM_BLOCKS[ecl][version]
  const eccLen = ECC_PER_BLOCK[ecl][version]
  const rawCodewords = Math.floor(rawDataModules(version) / 8)
  // The blocks are not all the same size. The shorter ones come first, and the
  // remainder is spread one byte at a time over the longer ones.
  const shortBlocks = blocks - (rawCodewords % blocks)
  const shortLen = Math.floor(rawCodewords / blocks)

  const divisor = rsDivisor(eccLen)
  const built: number[][] = []
  for (let i = 0, at = 0; i < blocks; i++) {
    const take = shortLen - eccLen + (i < shortBlocks ? 0 : 1)
    const chunk = data.slice(at, at + take)
    at += take
    const ecc = rsRemainder(chunk, divisor)
    // A placeholder so every block has the same length while interleaving; it
    // is skipped on the way out.
    if (i < shortBlocks) chunk.push(0)
    built.push(chunk.concat(ecc))
  }

  const out: number[] = []
  for (let i = 0; i < built[0].length; i++) {
    for (let j = 0; j < built.length; j++) {
      if (i !== shortLen - eccLen || j >= shortBlocks) out.push(built[j][i])
    }
  }
  return out
}

// ---------------------------------------------------------------------------
// Reed-Solomon over GF(256), with the QR primitive polynomial x^8+x^4+x^3+x^2+1
// ---------------------------------------------------------------------------

function gfMultiply(x: number, y: number): number {
  let z = 0
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d)
    z ^= ((y >>> i) & 1) * x
  }
  return z & 0xff
}

/** rsDivisor is the generator polynomial of the given degree, monic implied. */
function rsDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0)
  result[degree - 1] = 1
  let root = 1
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = gfMultiply(result[j], root)
      if (j + 1 < result.length) result[j] ^= result[j + 1]
    }
    root = gfMultiply(root, 0x02)
  }
  return result
}

function rsRemainder(data: number[], divisor: number[]): number[] {
  const result = divisor.map(() => 0)
  for (const b of data) {
    const factor = b ^ (result.shift() as number)
    result.push(0)
    divisor.forEach((coefficient, i) => {
      result[i] ^= gfMultiply(coefficient, factor)
    })
  }
  return result
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

interface Grid {
  modules: Matrix
  /** reserved marks the function patterns, which the data skips and the mask spares. */
  reserved: boolean[][]
  size: number
  version: number
  level: ECLevel
}

function setFunction(grid: Grid, x: number, y: number, dark: boolean): void {
  if (x < 0 || y < 0 || x >= grid.size || y >= grid.size) return
  grid.modules[y][x] = dark
  grid.reserved[y][x] = true
}

function bit(value: number, index: number): boolean {
  return ((value >>> index) & 1) !== 0
}

function drawFunctionPatterns(grid: Grid): void {
  for (let i = 0; i < grid.size; i++) {
    setFunction(grid, 6, i, i % 2 === 0)
    setFunction(grid, i, 6, i % 2 === 0)
  }

  drawFinder(grid, 3, 3)
  drawFinder(grid, grid.size - 4, 3)
  drawFinder(grid, 3, grid.size - 4)

  const positions = alignmentPositions(grid)
  for (let i = 0; i < positions.length; i++) {
    for (let j = 0; j < positions.length; j++) {
      // The three corners already hold finder patterns.
      const corner =
        (i === 0 && j === 0) ||
        (i === 0 && j === positions.length - 1) ||
        (i === positions.length - 1 && j === 0)
      if (!corner) drawAlignment(grid, positions[i], positions[j])
    }
  }

  // Reserve the format and version areas now; the real bits go in once a mask
  // has been chosen.
  drawFormatBits(grid, 0)
  drawVersionBits(grid)
}

function drawFinder(grid: Grid, cx: number, cy: number): void {
  for (let dy = -4; dy <= 4; dy++) {
    for (let dx = -4; dx <= 4; dx++) {
      const distance = Math.max(Math.abs(dx), Math.abs(dy))
      setFunction(grid, cx + dx, cy + dy, distance !== 2 && distance !== 4)
    }
  }
}

function drawAlignment(grid: Grid, cx: number, cy: number): void {
  for (let dy = -2; dy <= 2; dy++) {
    for (let dx = -2; dx <= 2; dx++) {
      setFunction(grid, cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1)
    }
  }
}

function alignmentPositions(grid: Grid): number[] {
  if (grid.version === 1) return []
  const count = Math.floor(grid.version / 7) + 2
  const step =
    grid.version === 32 ? 26 : Math.ceil((grid.version * 4 + 4) / (count * 2 - 2)) * 2
  const result = [6]
  for (let pos = grid.size - 7; result.length < count; pos -= step) result.splice(1, 0, pos)
  return result
}

function drawFormatBits(grid: Grid, mask: number): void {
  const data = (ECL_FORMAT_BITS[grid.level] << 3) | mask
  let rem = data
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537)
  const bits = ((data << 10) | rem) ^ 0x5412

  for (let i = 0; i <= 5; i++) setFunction(grid, 8, i, bit(bits, i))
  setFunction(grid, 8, 7, bit(bits, 6))
  setFunction(grid, 8, 8, bit(bits, 7))
  setFunction(grid, 7, 8, bit(bits, 8))
  for (let i = 9; i < 15; i++) setFunction(grid, 14 - i, 8, bit(bits, i))

  for (let i = 0; i < 8; i++) setFunction(grid, grid.size - 1 - i, 8, bit(bits, i))
  for (let i = 8; i < 15; i++) setFunction(grid, 8, grid.size - 15 + i, bit(bits, i))
  setFunction(grid, 8, grid.size - 8, true) // always dark
}

function drawVersionBits(grid: Grid): void {
  if (grid.version < 7) return
  let rem = grid.version
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25)
  const bits = (grid.version << 12) | rem

  for (let i = 0; i < 18; i++) {
    const dark = bit(bits, i)
    const a = grid.size - 11 + (i % 3)
    const b = Math.floor(i / 3)
    setFunction(grid, a, b, dark)
    setFunction(grid, b, a, dark)
  }
}

/** drawCodewords lays the bytes along the zigzag, skipping function modules. */
function drawCodewords(grid: Grid, codewords: number[]): void {
  let i = 0
  for (let right = grid.size - 1; right >= 1; right -= 2) {
    // Column 6 is the vertical timing pattern; the zigzag steps over it.
    if (right === 6) right = 5
    for (let vert = 0; vert < grid.size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j
        const upward = ((right + 1) & 2) === 0
        const y = upward ? grid.size - 1 - vert : vert
        if (!grid.reserved[y][x] && i < codewords.length * 8) {
          grid.modules[y][x] = bit(codewords[i >>> 3], 7 - (i & 7))
          i++
        }
      }
    }
  }
}

function maskAt(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0:
      return (x + y) % 2 === 0
    case 1:
      return y % 2 === 0
    case 2:
      return x % 3 === 0
    case 3:
      return (x + y) % 3 === 0
    case 4:
      return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0
    case 5:
      return ((x * y) % 2) + ((x * y) % 3) === 0
    case 6:
      return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0
    default:
      return ((((x + y) % 2) + ((x * y) % 3)) % 2) === 0
  }
}

/** applyMask is its own inverse: it XORs, so calling it twice undoes it. */
function applyMask(grid: Grid, mask: number): void {
  for (let y = 0; y < grid.size; y++) {
    for (let x = 0; x < grid.size; x++) {
      if (!grid.reserved[y][x] && maskAt(mask, x, y)) {
        grid.modules[y][x] = !grid.modules[y][x]
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Mask scoring
//
// Four rules from the standard, penalising what confuses a scanner: long runs
// of one colour, solid blocks, patterns that look like a finder, and an
// unbalanced ratio of dark to light. Only the choice of mask depends on this,
// so an imprecision here costs legibility rather than correctness.
// ---------------------------------------------------------------------------

const PENALTY_RUN = 3
const PENALTY_BLOCK = 3
const PENALTY_FINDER = 40
const PENALTY_BALANCE = 10

function penalty(grid: Grid): number {
  const { modules, size } = grid
  let result = 0

  for (let y = 0; y < size; y++) {
    let colour = false
    let run = 0
    const history = [0, 0, 0, 0, 0, 0, 0]
    for (let x = 0; x < size; x++) {
      if (modules[y][x] === colour) {
        run++
        if (run === 5) result += PENALTY_RUN
        else if (run > 5) result++
      } else {
        addHistory(history, run, size)
        if (!colour) result += countFinderLike(history) * PENALTY_FINDER
        colour = modules[y][x]
        run = 1
      }
    }
    result += terminateHistory(history, colour, run, size) * PENALTY_FINDER
  }

  for (let x = 0; x < size; x++) {
    let colour = false
    let run = 0
    const history = [0, 0, 0, 0, 0, 0, 0]
    for (let y = 0; y < size; y++) {
      if (modules[y][x] === colour) {
        run++
        if (run === 5) result += PENALTY_RUN
        else if (run > 5) result++
      } else {
        addHistory(history, run, size)
        if (!colour) result += countFinderLike(history) * PENALTY_FINDER
        colour = modules[y][x]
        run = 1
      }
    }
    result += terminateHistory(history, colour, run, size) * PENALTY_FINDER
  }

  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const colour = modules[y][x]
      if (
        colour === modules[y][x + 1] &&
        colour === modules[y + 1][x] &&
        colour === modules[y + 1][x + 1]
      ) {
        result += PENALTY_BLOCK
      }
    }
  }

  let dark = 0
  for (const row of modules) for (const module of row) if (module) dark++
  const total = size * size
  const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1
  return result + k * PENALTY_BALANCE
}

function addHistory(history: number[], run: number, size: number): void {
  // The area outside the symbol counts as light, so the first run is extended.
  if (history[0] === 0) run += size
  history.pop()
  history.unshift(run)
}

function terminateHistory(
  history: number[],
  colour: boolean,
  run: number,
  size: number,
): number {
  if (colour) {
    addHistory(history, run, size)
    run = 0
  }
  addHistory(history, run + size, size)
  return countFinderLike(history)
}

/** countFinderLike looks for the 1:1:3:1:1 ratio a finder pattern has. */
function countFinderLike(history: number[]): number {
  const n = history[1]
  const core =
    n > 0 && history[2] === n && history[3] === n * 3 && history[4] === n && history[5] === n
  return (
    (core && history[0] >= n * 4 && history[6] >= n ? 1 : 0) +
    (core && history[6] >= n * 4 && history[0] >= n ? 1 : 0)
  )
}
