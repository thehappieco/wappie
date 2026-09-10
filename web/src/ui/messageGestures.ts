export interface MessagePointer {
  pointerId: number
  clientX: number
  clientY: number
  pointerType: string
  isPrimary?: boolean
  button?: number
}

interface Options {
  onHold: () => void
  onReply: () => void
  onOffset: (px: number) => void
  onPress: (pressed: boolean) => void
  onReady?: () => void
  onSwipe?: (active: boolean) => void
  canReply: () => boolean
  hasSelection: () => boolean
}

export const REPLY_THRESHOLD = 64

/** Follow the finger, then add resistance instead of stopping abruptly. */
export function replyOffset(distance: number): number {
  const positive = Math.max(0, distance)
  return positive <= REPLY_THRESHOLD ? positive : REPLY_THRESHOLD + 32 * (1 - Math.exp(-(positive - REPLY_THRESHOLD) / 64))
}

/** Touch gestures only. Taps, mouse selection and vertical scrolling stay native. */
export function createMessageGestures(options: Options) {
  let pointer: MessagePointer | undefined
  let timer: ReturnType<typeof setTimeout> | undefined
  let swiping = false
  let distance = 0
  let suppressUntil = 0
  let disposed = false
  let signaled = false

  function clearTimer() {
    if (timer) clearTimeout(timer)
    timer = undefined
    options.onPress(false)
  }

  function cancel() {
    clearTimer()
    pointer = undefined
    swiping = false
    distance = 0
    options.onOffset(0)
    options.onSwipe?.(false)
  }

  function pointerDown(event: MessagePointer) {
    if (disposed) return
    if (pointer || event.isPrimary === false) { cancel(); return }
    if (event.pointerType !== 'touch' && event.pointerType !== 'pen') return
    if ((event.button ?? 0) !== 0 || options.hasSelection()) return
    // Leave the operating system's edge-back gesture alone.
    if (event.clientX < 24) return
    suppressUntil = 0
    signaled = false
    // Native PointerEvent fields are inherited getters, not enumerable own
    // properties. Spreading the event would silently lose the gesture origin.
    pointer = {
      pointerId: event.pointerId,
      clientX: event.clientX,
      clientY: event.clientY,
      pointerType: event.pointerType,
      isPrimary: event.isPrimary,
      button: event.button,
    }
    options.onPress(true)
    timer = setTimeout(() => {
      if (!pointer || options.hasSelection()) { cancel(); return }
      cancel()
      suppressUntil = Date.now() + 1000
      options.onHold()
    }, 450)
  }

  /** True means the horizontal gesture owns this move; prevent its default. */
  function pointerMove(event: MessagePointer): boolean {
    if (!pointer || event.pointerId !== pointer.pointerId) return false
    if (options.hasSelection()) { cancel(); return false }
    const dx = event.clientX - pointer.clientX
    const dy = event.clientY - pointer.clientY
    if (Math.hypot(dx, dy) < 10 && !swiping) return false
    clearTimer()
    if (!swiping) {
      // The first deliberate movement decides: never turn a vertical scroll
      // or leftward drag into a reply later in the same gesture.
      if (dx < 0 || Math.abs(dy) * 1.5 >= dx || !options.canReply()) {
        cancel()
        return false
      }
      if (dx < 12) return false
      swiping = true
      options.onSwipe?.(true)
    }
    if (Math.abs(dy) > Math.max(40, Math.abs(dx))) { cancel(); return false }
    distance = Math.max(0, dx)
    options.onOffset(replyOffset(distance))
    if (distance >= REPLY_THRESHOLD && !signaled) { signaled = true; options.onReady?.() }
    return true
  }

  function pointerUp(event: MessagePointer) {
    if (!pointer || event.pointerId !== pointer.pointerId) return
    if (swiping) pointerMove(event)
    const reply = swiping && distance >= REPLY_THRESHOLD && options.canReply() && !options.hasSelection()
    if (swiping) suppressUntil = Date.now() + 1000
    cancel()
    if (reply) options.onReply()
  }

  return {
    pointerDown,
    pointerMove,
    pointerUp,
    cancel,
    shouldSuppressClick() {
      const suppress = Date.now() < suppressUntil
      suppressUntil = 0
      return suppress
    },
    dispose() { disposed = true; cancel() },
  }
}

/** A message's own controls retain their click, context menu and touch gestures. */
export const MESSAGE_CONTROLS = 'a, button, input, textarea, select, audio, video, summary, dialog, [role="button"], [contenteditable="true"], [data-message-control]'
