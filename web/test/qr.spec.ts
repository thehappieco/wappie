import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL } from 'node:url'

import { encode, QRError, svgPath, type Matrix } from '../src/ui/qr'

// A QR encoder cannot be checked by reading it. The interesting failures are
// wrong entries in the block tables, a Reed-Solomon generator off by one term,
// or a misplaced module — and all of them produce a picture that looks exactly
// like a QR code and does not scan.
//
// So the fixtures below are not "what the code currently does". They were
// rendered to PNG and decoded by macOS CoreImage, which is an implementation
// nothing here shares a line with, and they matched the input. Twenty-eight
// codes were checked that way across versions 1 to 38 and all four error
// correction levels, including version 32, whose alignment spacing is a special
// case in the standard. These three are the ones kept, so a change that breaks
// scanning fails here instead of in front of somebody holding a phone.
//
// Regenerating them is not a fix. If they stop matching, either the encoder
// changed on purpose — and then the new output has to be decoded by something
// external before it is committed — or it broke.

interface Gold {
  text: string
  level: 'L' | 'M' | 'Q' | 'H'
  rows: string[]
}

const gold: Record<string, Gold> = JSON.parse(
  readFileSync(fileURLToPath(new URL('../testdata/qr.json', import.meta.url)), 'utf8'),
)

function render(matrix: Matrix): string[] {
  return matrix.map((row) => row.map((dark) => (dark ? '#' : '.')).join(''))
}

describe('the qr encoder', () => {
  for (const [name, want] of Object.entries(gold)) {
    it(`matches the decoded fixture: ${name}`, () => {
      expect(render(encode(want.text, want.level))).toEqual(want.rows)
    })
  }

  it('picks a version big enough and no bigger', () => {
    // Version 1 at level L holds 17 bytes in byte mode; 18 needs version 2.
    expect(encode('x'.repeat(17), 'L').length).toBe(21)
    expect(encode('x'.repeat(18), 'L').length).toBe(25)
  })

  it('puts a finder pattern in three corners and not the fourth', () => {
    const m = encode('anything', 'M')
    const size = m.length
    const finder = (x: number, y: number) =>
      m[y][x] && m[y + 6][x] && m[y][x + 6] && !m[y + 1][x + 1] && m[y + 2][x + 2]

    expect(finder(0, 0)).toBe(true)
    expect(finder(size - 7, 0)).toBe(true)
    expect(finder(0, size - 7)).toBe(true)
    // The fourth corner carries data, and a finder there would be read as a
    // different orientation.
    expect(finder(size - 7, size - 7)).toBe(false)
  })

  it('draws the timing patterns and the module that is always dark', () => {
    const m = encode('anything', 'M')
    for (let i = 8; i < m.length - 8; i++) {
      expect(m[6][i]).toBe(i % 2 === 0)
      expect(m[i][6]).toBe(i % 2 === 0)
    }
    expect(m[m.length - 8][8]).toBe(true)
  })

  it('refuses what cannot fit rather than truncating it', () => {
    // Silently encoding a prefix would produce a code that scans and says the
    // wrong thing, which is worse than one that does not scan.
    expect(() => encode('x'.repeat(3000), 'L')).toThrow(QRError)
  })

  it('renders a path with a quiet zone around it', () => {
    const m = encode('7', 'M')
    const { path, extent } = svgPath(m, 4)
    expect(extent).toBe(m.length + 8)
    expect(path.startsWith('M')).toBe(true)
    // One rectangle per dark module.
    const dark = m.flat().filter(Boolean).length
    expect(path.split('M').length - 1).toBe(dark)
  })
})
