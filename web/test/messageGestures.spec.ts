import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { createMessageGestures, replyOffset, REPLY_THRESHOLD, type MessagePointer } from '../src/ui/messageGestures'

function pointer(over: Partial<MessagePointer> = {}): MessagePointer {
  return { pointerId: 1, clientX: 100, clientY: 200, pointerType: 'touch', isPrimary: true, button: 0, ...over }
}

function setup() {
  const onHold = vi.fn()
  const onReply = vi.fn()
  const onOffset = vi.fn()
  const onPress = vi.fn()
  const onReady = vi.fn()
  const onSwipe = vi.fn()
  const onCapture = vi.fn()
  const onRelease = vi.fn()
  let selected = false
  let allowed = true
  const gestures = createMessageGestures({
    onHold, onReply, onOffset, onPress, onReady, onSwipe, onCapture, onRelease,
    canReply: () => allowed,
    hasSelection: () => selected,
  })
  return {
    gestures, onHold, onReply, onOffset, onPress, onReady, onSwipe, onCapture, onRelease,
    select: () => { selected = true },
    disallow: () => { allowed = false },
  }
}

beforeEach(() => vi.useFakeTimers())
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers() })

describe('message touch gestures', () => {
  it('leaves media taps uncaptured and only captures after a deliberate horizontal drag', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer(), { deferCapture: true })
    expect(ui.onCapture).not.toHaveBeenCalled()
    ui.gestures.pointerMove(pointer({ clientX: 108 }))
    expect(ui.onCapture).not.toHaveBeenCalled()
    ui.gestures.pointerUp(pointer({ clientX: 108 }))
    expect(ui.gestures.shouldSuppressClick()).toBe(false)
    expect(ui.onReply).not.toHaveBeenCalled()

    ui.gestures.pointerDown(pointer(), { deferCapture: true })
    expect(ui.gestures.pointerMove(pointer({ clientX: 120 }))).toBe(true)
    expect(ui.onCapture).toHaveBeenCalledExactlyOnceWith(1)
    ui.gestures.pointerMove(pointer({ clientX: 190 }))
    expect(ui.onCapture).toHaveBeenCalledOnce()
    ui.gestures.pointerUp(pointer({ clientX: 190 }))
    expect(ui.onReply).toHaveBeenCalledOnce()
    expect(ui.gestures.shouldSuppressClick()).toBe(true)
  })

  it('never captures a media pointer that becomes vertical scrolling or is canceled', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer(), { deferCapture: true })
    expect(ui.gestures.pointerMove(pointer({ clientX: 102, clientY: 220 }))).toBe(false)
    expect(ui.onCapture).not.toHaveBeenCalled()
    expect(ui.gestures.pointerMove(pointer({ clientX: 190, clientY: 220 }))).toBe(false)
    ui.gestures.pointerUp(pointer({ clientX: 190, clientY: 220 }))
    expect(ui.onReply).not.toHaveBeenCalled()
    ui.gestures.pointerDown(pointer(), { deferCapture: true })
    ui.gestures.pointerCancel(pointer())
    ui.gestures.pointerMove(pointer({ clientX: 190 }))
    ui.gestures.pointerUp(pointer({ clientX: 190 }))
    expect(ui.onCapture).not.toHaveBeenCalled()
    expect(ui.onReply).not.toHaveBeenCalled()
    expect(ui.gestures.shouldSuppressClick()).toBe(false)
  })

  it('suppresses media activation after a claimed swipe is canceled by a diagonal retreat', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer(), { deferCapture: true })
    ui.gestures.pointerMove(pointer({ clientX: 175 }))
    expect(ui.gestures.pointerMove(pointer({ clientX: 175, clientY: 290 }))).toBe(false)
    vi.advanceTimersByTime(2000)
    ui.gestures.pointerUp(pointer({ clientX: 175, clientY: 290 }))
    expect(ui.onReply).not.toHaveBeenCalled()
    expect(ui.gestures.shouldSuppressClick()).toBe(true)
    expect(ui.gestures.shouldSuppressClick()).toBe(false)
  })

  it('does not activate the media after holding longer than the compatibility-click timeout', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer(), { deferCapture: true })
    vi.advanceTimersByTime(2500)
    expect(ui.onHold).toHaveBeenCalledOnce()
    ui.gestures.pointerUp(pointer())
    expect(ui.gestures.shouldSuppressClick()).toBe(true)
    expect(ui.onReply).not.toHaveBeenCalled()
  })

  it('captures on press before a first move can leave the bubble, retaining it until release', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer({ pointerType: 'pen', clientX: 241 }))
    expect(ui.onCapture).toHaveBeenCalledExactlyOnceWith(1)
    expect(ui.onRelease).not.toHaveBeenCalled()
    expect(ui.gestures.pointerMove(pointer({ pointerType: 'pen', clientX: 256 }))).toBe(true)
    expect(ui.gestures.pointerMove(pointer({ pointerType: 'pen', clientX: 420 }))).toBe(true)
    expect(ui.onRelease).not.toHaveBeenCalled()
    expect(ui.onReply).not.toHaveBeenCalled()
    ui.gestures.pointerUp(pointer({ pointerType: 'pen', clientX: 420 }))
    expect(ui.onRelease).toHaveBeenCalledExactlyOnceWith(1)
    expect(ui.onReply).toHaveBeenCalledOnce()
    ui.gestures.pointerUp(pointer({ pointerType: 'pen', clientX: 420 }))
    vi.advanceTimersByTime(500)
    expect(ui.onHold).not.toHaveBeenCalled()
    expect(ui.onReply).toHaveBeenCalledOnce()
  })

  it('releases a canceled swipe once and ignores its late capture loss during the next gesture', () => {
    const ui = setup()
    // Browsers can deliver lostpointercapture while releasing it.
    ui.onRelease.mockImplementation(pointerId => ui.gestures.pointerCancel({ pointerId }))
    ui.gestures.pointerDown(pointer())
    ui.gestures.pointerMove(pointer({ clientX: 180 }))
    ui.gestures.pointerCancel(pointer())
    expect(ui.onRelease).toHaveBeenCalledExactlyOnceWith(1)
    ui.gestures.pointerUp(pointer({ clientX: 180 }))
    expect(ui.onReply).not.toHaveBeenCalled()
    ui.gestures.pointerDown(pointer({ pointerId: 2 }))
    ui.gestures.pointerCancel(pointer())
    expect(ui.gestures.pointerMove(pointer({ pointerId: 2, clientX: 180 }))).toBe(true)
    ui.gestures.pointerUp(pointer({ pointerId: 2, clientX: 180 }))
    expect(ui.onRelease).toHaveBeenCalledTimes(2)
    expect(ui.onRelease).toHaveBeenLastCalledWith(2)
    expect(ui.onReply).toHaveBeenCalledOnce()
  })

  it('releases capture on a hold or disposal without leaving a delayed reply behind', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    vi.advanceTimersByTime(450)
    expect(ui.onRelease).toHaveBeenCalledExactlyOnceWith(1)
    expect(ui.onHold).toHaveBeenCalledOnce()
    ui.gestures.pointerDown(pointer({ pointerId: 2 }))
    ui.gestures.pointerMove(pointer({ pointerId: 2, clientX: 180 }))
    ui.gestures.dispose()
    expect(ui.onRelease).toHaveBeenCalledTimes(2)
    ui.gestures.pointerUp(pointer({ pointerId: 2, clientX: 180 }))
    vi.advanceTimersByTime(500)
    expect(ui.onHold).toHaveBeenCalledOnce()
    expect(ui.onReply).not.toHaveBeenCalled()
  })

  it('a regular tap neither opens information nor starts a reply', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    vi.advanceTimersByTime(150)
    ui.gestures.pointerUp(pointer())
    vi.advanceTimersByTime(500)
    expect(ui.onHold).not.toHaveBeenCalled()
    expect(ui.onReply).not.toHaveBeenCalled()
    expect(ui.gestures.shouldSuppressClick()).toBe(false)
  })

  it('holding still opens actions once, with feedback only while pressing', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    expect(ui.onPress).toHaveBeenLastCalledWith(true)
    vi.advanceTimersByTime(450)
    expect(ui.onHold).toHaveBeenCalledOnce()
    expect(ui.onPress).toHaveBeenLastCalledWith(false)
    vi.advanceTimersByTime(100)
    ui.gestures.pointerUp(pointer())
    expect(ui.onReply).not.toHaveBeenCalled()
    expect(ui.gestures.shouldSuppressClick()).toBe(true)
    expect(ui.gestures.shouldSuppressClick()).toBe(false)
  })

  it('vertical scrolling cancels the hold and cannot become a later reply', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    expect(ui.gestures.pointerMove(pointer({ clientY: 216 }))).toBe(false)
    expect(ui.onRelease).toHaveBeenCalledExactlyOnceWith(1)
    expect(ui.gestures.pointerMove(pointer({ clientX: 185, clientY: 219 }))).toBe(false)
    vi.advanceTimersByTime(500)
    ui.gestures.pointerUp(pointer({ clientX: 185, clientY: 219 }))
    expect(ui.onHold).not.toHaveBeenCalled()
    expect(ui.onReply).not.toHaveBeenCalled()
  })

  it('allows a gradual rightward swipe and replies only after release', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    expect(ui.gestures.pointerMove(pointer({ clientX: 110 }))).toBe(false)
    expect(ui.gestures.pointerMove(pointer({ clientX: 115 }))).toBe(true)
    expect(ui.gestures.pointerMove(pointer({ clientX: 164, clientY: 205 }))).toBe(true)
    expect(ui.onReply).not.toHaveBeenCalled()
    expect(ui.onOffset).toHaveBeenLastCalledWith(64)
    ui.gestures.pointerUp(pointer({ clientX: 164, clientY: 205 }))
    expect(ui.onReply).toHaveBeenCalledOnce()
    expect(ui.onOffset).toHaveBeenLastCalledWith(0)
    expect(ui.gestures.shouldSuppressClick()).toBe(true)
    vi.advanceTimersByTime(500)
    expect(ui.onHold).not.toHaveBeenCalled()
  })

  it('reads native-style PointerEvent getters instead of spreading enumerable fields', () => {
    class NativePointer {
      get pointerId() { return 1 }
      get clientX() { return 100 }
      get clientY() { return 200 }
      get pointerType() { return 'touch' }
      get isPrimary() { return true }
      get button() { return 0 }
    }
    const ui = setup()
    const start = new NativePointer()
    expect(Object.keys(start)).toEqual([])
    ui.gestures.pointerDown(start)
    expect(ui.gestures.pointerMove(pointer({ clientX: 170 }))).toBe(true)
    ui.gestures.pointerUp(pointer({ clientX: 170 }))
    expect(ui.onReply).toHaveBeenCalledOnce()
    expect(ui.onHold).not.toHaveBeenCalled()
  })

  it('does not reply for a short swipe or one dragged back before release', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    ui.gestures.pointerMove(pointer({ clientX: 160 }))
    ui.gestures.pointerUp(pointer({ clientX: 160 }))
    expect(ui.onReply).not.toHaveBeenCalled()
    ui.gestures.pointerDown(pointer())
    ui.gestures.pointerMove(pointer({ clientX: 180 }))
    ui.gestures.pointerMove(pointer({ clientX: 130 }))
    ui.gestures.pointerUp(pointer({ clientX: 130 }))
    expect(ui.onReply).not.toHaveBeenCalled()
  })

  it('ignores leftward or diagonal drags and leaves scroll defaults intact', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    expect(ui.gestures.pointerMove(pointer({ clientX: 80 }))).toBe(false)
    ui.gestures.pointerUp(pointer({ clientX: 80 }))
    ui.gestures.pointerDown(pointer())
    expect(ui.gestures.pointerMove(pointer({ clientX: 118, clientY: 220 }))).toBe(false)
    vi.advanceTimersByTime(500)
    expect(ui.onHold).not.toHaveBeenCalled()
    expect(ui.onReply).not.toHaveBeenCalled()
  })

  it('preserves mouse selection and existing touch selections', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer({ pointerType: 'mouse' }))
    expect(ui.onCapture).not.toHaveBeenCalled()
    vi.advanceTimersByTime(500)
    expect(ui.onHold).not.toHaveBeenCalled()
    ui.select()
    ui.gestures.pointerDown(pointer())
    expect(ui.gestures.pointerMove(pointer({ clientX: 190 }))).toBe(false)
    vi.advanceTimersByTime(500)
    expect(ui.onHold).not.toHaveBeenCalled()
    expect(ui.onReply).not.toHaveBeenCalled()
  })

  it('cancels when native selection starts during the hold or swipe', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    ui.select()
    vi.advanceTimersByTime(500)
    expect(ui.onHold).not.toHaveBeenCalled()
    expect(ui.gestures.pointerMove(pointer({ clientX: 185 }))).toBe(false)
    ui.gestures.pointerUp(pointer({ clientX: 185 }))
    expect(ui.onReply).not.toHaveBeenCalled()
  })

  it('a second finger cancels rather than firing a hold during pinch zoom', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    ui.gestures.pointerDown(pointer({ pointerId: 2, isPrimary: false }))
    vi.advanceTimersByTime(500)
    ui.gestures.pointerUp(pointer())
    expect(ui.onHold).not.toHaveBeenCalled()
    expect(ui.onReply).not.toHaveBeenCalled()
  })

  it('ignores stale pointer events and rechecks whether replying is still allowed', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    expect(ui.gestures.pointerMove(pointer({ pointerId: 2, clientX: 190 }))).toBe(false)
    ui.gestures.pointerMove(pointer({ clientX: 190 }))
    ui.disallow()
    ui.gestures.pointerUp(pointer({ clientX: 190 }))
    expect(ui.onReply).not.toHaveBeenCalled()
  })

  it('cancels on pointer cancellation, navigation or disposal', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    ui.gestures.cancel()
    vi.advanceTimersByTime(500)
    expect(ui.onHold).not.toHaveBeenCalled()
    ui.gestures.pointerDown(pointer())
    ui.gestures.dispose()
    ui.gestures.pointerDown(pointer())
    vi.advanceTimersByTime(500)
    expect(ui.onHold).not.toHaveBeenCalled()
    expect(ui.onPress).toHaveBeenLastCalledWith(false)
  })

  it('leaves edge-back swipes to the operating system', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer({ clientX: 12 }))
    expect(ui.onCapture).not.toHaveBeenCalled()
    expect(ui.gestures.pointerMove(pointer({ clientX: 90 }))).toBe(false)
    vi.advanceTimersByTime(500)
    expect(ui.onHold).not.toHaveBeenCalled()
    expect(ui.onReply).not.toHaveBeenCalled()
  })

  it('does not suppress a subsequent deliberate tap after a hold', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    vi.advanceTimersByTime(450)
    ui.gestures.pointerUp(pointer())
    ui.gestures.pointerDown(pointer())
    ui.gestures.pointerUp(pointer())
    expect(ui.gestures.shouldSuppressClick()).toBe(false)
  })

  it('bounds visual movement and expires synthetic-click suppression', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    ui.gestures.pointerMove(pointer({ clientX: 450 }))
    expect(ui.onOffset).toHaveBeenLastCalledWith(replyOffset(350))
    ui.gestures.pointerUp(pointer({ clientX: 450 }))
    vi.advanceTimersByTime(1001)
    expect(ui.gestures.shouldSuppressClick()).toBe(false)
  })

  it('follows the finger up to the reply threshold and adds smooth resistance afterwards', () => {
    expect(replyOffset(0)).toBe(0)
    expect(replyOffset(32)).toBe(32)
    expect(replyOffset(REPLY_THRESHOLD)).toBe(REPLY_THRESHOLD)
    expect(replyOffset(100)).toBeGreaterThan(REPLY_THRESHOLD)
    expect(replyOffset(100)).toBeLessThan(100)
    expect(replyOffset(500)).toBeLessThan(96)
    expect(replyOffset(-20)).toBe(0)
  })

  it('signals readiness once per gesture while allowing a retreat before release', () => {
    const ui = setup()
    ui.gestures.pointerDown(pointer())
    ui.gestures.pointerMove(pointer({ clientX: 170 }))
    expect(ui.onReady).toHaveBeenCalledOnce()
    expect(ui.onSwipe).toHaveBeenLastCalledWith(true)
    ui.gestures.pointerMove(pointer({ clientX: 125 }))
    ui.gestures.pointerMove(pointer({ clientX: 175 }))
    expect(ui.onReady).toHaveBeenCalledOnce()
    ui.gestures.pointerUp(pointer({ clientX: 125 }))
    expect(ui.onReply).not.toHaveBeenCalled()
    expect(ui.onSwipe).toHaveBeenLastCalledWith(false)
    ui.gestures.pointerDown(pointer())
    ui.gestures.pointerMove(pointer({ clientX: 180 }))
    expect(ui.onReady).toHaveBeenCalledTimes(2)
  })
})
