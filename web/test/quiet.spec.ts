import { describe, expect, it } from 'vitest'

import { applyReceiptMode, state } from '../src/state/archive'

// The palette and the gates must never disagree.
//
// A grey window while read receipts are still going out is worse than no colour
// change at all: the whole point of the palette is that somebody can tell the
// posture at a glance and act on it. So both are driven off one flag, and this
// is the test that says so.

describe('the discreet posture', () => {
  it('is one flag, so the colour cannot disagree with the behaviour', () => {
    applyReceiptMode('active')
    expect(state.quiet).toBe(false)

    applyReceiptMode('passive')
    expect(state.quiet).toBe(true)
  })

  it('treats anything that is not "active" as discreet', () => {
    // The server is the source, and a mode this build does not recognise must
    // fail closed. Falling open would emit receipts somebody asked to withhold.
    applyReceiptMode('')
    expect(state.quiet).toBe(true)

    applyReceiptMode('something-new')
    expect(state.quiet).toBe(true)
  })
})
