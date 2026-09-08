// Reporting what has been read.
//
// Two different things used to be one thing: telling the ARCHIVE, which is how
// a badge clears, and telling WHATSAPP, which is a signal that leaves the
// machine. Behind one switch, a discreet device reported neither — so opening a
// conversation and reading every word in it left the badge exactly where it
// was. These tests are about the two staying apart.
//
// Every other condition here is a refusal, and each is a way the archive could
// end up reporting a read that never happened.

import { beforeEach, describe, expect, it, vi } from 'vitest'

import {
  forgetSeen,
  queued,
  readReceiptsEnabled,
  sawMessage,
  setReadReceipts,
} from '../src/state/reading'

const DWELL = 600

beforeEach(() => {
  forgetSeen()
  setReadReceipts(true)
  vi.useRealTimers()
})

/** dwell keeps a message on screen long enough to count as read. */
function dwell(waID: string) {
  sawMessage(waID, true)
  vi.advanceTimersByTime(DWELL + 1)
  sawMessage(waID, true)
}

describe('what still gets reported while discreet', () => {
  it('queues the read anyway, because the badge is ours', () => {
    // The whole bug. The switch governs what reaches WhatsApp; the server
    // refuses to forward in passive mode, and that refusal is the gate. Gating
    // here as well meant a badge could never clear while discreet.
    vi.useFakeTimers()
    setReadReceipts(false)
    dwell('M1')

    expect(queued()).toEqual(['M1'])
    expect(readReceiptsEnabled()).toBe(false)
  })

  it('still reports the switch honestly, because the UI says what it does', () => {
    setReadReceipts(false)
    expect(readReceiptsEnabled()).toBe(false)
    setReadReceipts(true)
    expect(readReceiptsEnabled()).toBe(true)
  })
})

describe('what stops a read being reported at all', () => {
  it('needs the message to stay on screen, not merely appear', () => {
    // Scrolling past something is not reading it. Without a dwell, dragging
    // the scrollbar through a conversation reports every message in it.
    vi.useFakeTimers()
    sawMessage('M1', true)
    vi.advanceTimersByTime(100)
    sawMessage('M1', true)

    expect(queued()).toEqual([])
  })

  it('discards the clock when the tab loses focus rather than pausing it', () => {
    // A message glimpsed for a moment before the window went behind another
    // was not read, and a read receipt cannot be taken back.
    vi.useFakeTimers()
    sawMessage('M1', true)
    vi.advanceTimersByTime(400)
    sawMessage('M1', false)
    vi.advanceTimersByTime(400)
    sawMessage('M1', true)

    expect(queued()).toEqual([])
  })

  it('refuses a message with no id', () => {
    vi.useFakeTimers()
    dwell('')
    expect(queued()).toEqual([])
  })

  it('forgets everything when the conversation changes', () => {
    vi.useFakeTimers()
    dwell('M1')
    expect(queued()).toEqual(['M1'])

    forgetSeen()
    expect(queued()).toEqual([])
  })

  it('reports a message once, not on every sighting', () => {
    vi.useFakeTimers()
    dwell('M1')
    sawMessage('M1', true)
    sawMessage('M1', true)

    expect(queued()).toEqual(['M1'])
  })
})
