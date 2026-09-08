import { describe, expect, it } from 'vitest'

import { enterSends } from '../src/ui/composerKeys'

const enter = { key: 'Enter', shiftKey: false, isComposing: false, keyCode: 13 }

describe('composer Enter key', () => {
  it('sends on desktop while preserving Shift+Enter for new lines', () => {
    expect(enterSends(enter, false)).toBe(true)
    expect(enterSends({ ...enter, shiftKey: true }, false)).toBe(false)
  })

  it('keeps the touch keyboard Enter key for new lines', () => {
    expect(enterSends(enter, true)).toBe(false)
  })

  it('never sends while an input method is confirming composed text', () => {
    expect(enterSends({ ...enter, isComposing: true }, false)).toBe(false)
    expect(enterSends({ ...enter, keyCode: 229 }, false)).toBe(false)
  })

  it('does not submit other keys', () => {
    expect(enterSends({ ...enter, key: 'a', keyCode: 65 }, false)).toBe(false)
  })
})
