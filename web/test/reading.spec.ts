// Incognito viewing must not mark the archive read or send WhatsApp receipts.
// Merely hiding the badge update would lose that promise after a reload.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import * as P from '../src/api/protocol'
import {
  forgetSeen,
  playedMessage,
  queued,
  readReceiptsEnabled,
  sawMessage,
  setReadReceipts,
} from '../src/state/reading'

const { request, archive } = vi.hoisted(() => ({
  request: vi.fn().mockResolvedValue({}),
  archive: { deviceID: 'device-1', openChatKey: 'chat-1@s.whatsapp.net' },
}))

vi.mock('../src/state/archive', () => ({
  connection: () => ({ request }),
  state: archive,
}))

const DWELL = 600
const BATCH = 400

beforeEach(() => {
  vi.useFakeTimers()
  forgetSeen()
  setReadReceipts(true)
  request.mockClear()
})

afterEach(() => {
  forgetSeen()
  vi.useRealTimers()
})

/** dwell keeps a message on screen long enough to count as read. */
function dwell(waID: string) {
  sawMessage(waID, true)
  vi.advanceTimersByTime(DWELL + 1)
  sawMessage(waID, true)
}

describe('incognito reading', () => {
  it('does not mark the archive read, preserving unread badges after a reload', async () => {
    setReadReceipts(false)
    dwell('M1')
    await vi.advanceTimersByTimeAsync(BATCH)

    expect(queued()).toEqual([])
    expect(request).not.toHaveBeenCalled()
    expect(readReceiptsEnabled()).toBe(false)
  })

  it('does not acknowledge playing a voice note or opening view-once media', async () => {
    setReadReceipts(false)
    await playedMessage('M1')
    expect(request).not.toHaveBeenCalled()
  })

  it('cancels an active read batch when incognito is enabled before it leaves', async () => {
    dwell('M1')
    expect(queued()).toEqual(['M1'])

    setReadReceipts(false)
    setReadReceipts(true)
    await vi.advanceTimersByTimeAsync(BATCH)
    expect(request).not.toHaveBeenCalled()
    expect(queued()).toEqual([])
  })

  it('requires a fresh dwell after leaving incognito', async () => {
    setReadReceipts(false)
    dwell('M1')
    setReadReceipts(true)
    sawMessage('M1', true)
    await vi.advanceTimersByTimeAsync(BATCH)
    expect(request).not.toHaveBeenCalled()

    vi.advanceTimersByTime(DWELL - BATCH)
    sawMessage('M1', true)
    await vi.advanceTimersByTimeAsync(BATCH)
    expect(request).toHaveBeenCalledOnce()
  })

  it('still reports the switch honestly, because the UI says what it does', () => {
    setReadReceipts(false)
    expect(readReceiptsEnabled()).toBe(false)
    setReadReceipts(true)
    expect(readReceiptsEnabled()).toBe(true)
  })
})

describe('active reading', () => {
  it('reports visible messages as one batch for the current device and chat', async () => {
    sawMessage('M1', true)
    sawMessage('M2', true)
    vi.advanceTimersByTime(DWELL)
    sawMessage('M1', true)
    sawMessage('M2', true)
    await vi.advanceTimersByTimeAsync(BATCH)

    expect(request).toHaveBeenCalledExactlyOnceWith(
      P.TypeMarkRead,
      { device_id: archive.deviceID, chat: archive.openChatKey, ids: ['M1', 'M2'] },
      P.TypeSendResult,
    )
  })

  it('reports deliberate playback separately', async () => {
    await playedMessage('M1')
    expect(request).toHaveBeenCalledExactlyOnceWith(
      P.TypeMarkRead,
      { device_id: archive.deviceID, chat: archive.openChatKey, ids: ['M1'], played: true },
      P.TypeSendResult,
    )
  })
})

describe('what stops a read being reported at all', () => {
  it('needs the message to stay on screen, not merely appear', () => {
    // Scrolling past something is not reading it. Without a dwell, dragging
    // the scrollbar through a conversation reports every message in it.
    sawMessage('M1', true)
    vi.advanceTimersByTime(100)
    sawMessage('M1', true)

    expect(queued()).toEqual([])
  })

  it('discards the clock when the tab loses focus rather than pausing it', () => {
    // A message glimpsed for a moment before the window went behind another
    // was not read, and a read receipt cannot be taken back.
    sawMessage('M1', true)
    vi.advanceTimersByTime(400)
    sawMessage('M1', false)
    vi.advanceTimersByTime(400)
    sawMessage('M1', true)

    expect(queued()).toEqual([])
  })

  it('discards a queued read when the message leaves focus before the batch sends', async () => {
    dwell('M1')
    sawMessage('M1', false)
    await vi.advanceTimersByTimeAsync(BATCH)
    expect(request).not.toHaveBeenCalled()
  })

  it('refuses a message with no id', () => {
    dwell('')
    expect(queued()).toEqual([])
  })

  it('forgets everything when the conversation changes', async () => {
    dwell('M1')
    expect(queued()).toEqual(['M1'])

    forgetSeen()
    expect(queued()).toEqual([])
    await vi.advanceTimersByTimeAsync(BATCH)
    expect(request).not.toHaveBeenCalled()
  })

  it('reports a message once, not on every sighting', () => {
    dwell('M1')
    sawMessage('M1', true)
    sawMessage('M1', true)

    expect(queued()).toEqual(['M1'])
  })
})
