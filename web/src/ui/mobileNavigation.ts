interface MobileNavigationOptions {
  /** Zero for the chat list or desktop, one for a chat, two for its details. */
  getDepth: () => number
  /** Close layers only. This callback must not open a chat or send requests. */
  closeTo: (depth: number) => void
}

interface Entry {
  depth: number
  /** Non-record history state is retained intact underneath our own entries. */
  original?: unknown
}

/**
 * Add browser Back support to the mobile screens without changing the URL.
 *
 * Call sync after a change to the visible depth, including a viewport change.
 * The initial history entry stays untouched. Only entries pushed by this
 * instance may be traversed when the UI itself closes a screen.
 */
export function installMobileNavigation({ getDepth, closeTo }: MobileNavigationOptions): {
  sync: () => void
  dispose: () => void
} {
  if (typeof window === 'undefined') return { sync() {}, dispose() {} }

  const browser = window
  const history = browser.history
  const key = `__wappieMobileNavigation_${crypto.randomUUID()}`
  let disposed = false
  let handlingPop = false
  let pending: { target: number; syncAgain: boolean } | undefined

  function depth(): number {
    const value = getDepth()
    return Number.isFinite(value) ? Math.max(0, Math.min(2, Math.trunc(value))) : 0
  }

  function ownEntry(): Entry | undefined {
    const state: unknown = history.state
    if (!record(state)) return undefined
    const entry = state[key]
    if (!record(entry) || !Number.isInteger(entry.depth) || Number(entry.depth) < 1 || Number(entry.depth) > 2) {
      return undefined
    }
    return entry as unknown as Entry
  }

  function originalState(): unknown {
    const state: unknown = history.state
    const entry = ownEntry()
    if (!entry) return state
    if (Object.hasOwn(entry, 'original')) return entry.original
    const copy = { ...(state as Record<string, unknown>) }
    delete copy[key]
    return copy
  }

  function push(nextDepth: number): void {
    const original = originalState()
    const state = record(original) ? { ...original } : {}
    const entry: Entry = { depth: nextDepth }
    if (!record(original)) entry.original = original
    history.pushState({ ...state, [key]: entry }, '')
  }

  function reconcile(allowPush: boolean): void {
    if (disposed || handlingPop) return
    if (pending) {
      if (allowPush) pending.syncAgain = true
      return
    }
    const wanted = depth()
    const current = ownEntry()?.depth ?? 0
    if (wanted < current) {
      pending = { target: wanted, syncAgain: false }
      // current is positive only for our own entries. In particular, depth
      // zero on desktop cannot send the browser back from an unrelated page.
      history.go(wanted - current)
      return
    }
    if (allowPush) {
      for (let next = current + 1; next <= wanted; next++) push(next)
    }
  }

  function sync(): void {
    reconcile(true)
  }

  function onPop(): void {
    if (disposed) return
    const landed = ownEntry()?.depth ?? 0
    const requested = pending
    pending = undefined

    // A UI close has already changed the visible state. If another UI action
    // happened while traversal was pending, preserve that newer intent and
    // reconcile it after this event instead of closing the new screen.
    const internal = requested?.target === landed
    handlingPop = true
    try {
      // Depth zero can mean a desktop layout with a conversation still open.
      // A no-op navigation must not ask its owner to clear that conversation.
      if (!internal && landed < depth()) closeTo(landed)
    } finally {
      handlingPop = false
    }

    // A watcher called synchronously by closeTo must not push the screen that
    // browser Back just removed. Forward cannot reopen a screen either; an
    // entry ahead of the visible state is safely traversed back again.
    reconcile(false)
    if (internal && requested?.syncAgain) queueMicrotask(sync)
  }

  browser.addEventListener('popstate', onPop)
  sync()

  return {
    sync,
    dispose() {
      if (disposed) return
      disposed = true
      browser.removeEventListener('popstate', onPop)
      if (ownEntry()) history.replaceState(originalState(), '')
    },
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype
}
