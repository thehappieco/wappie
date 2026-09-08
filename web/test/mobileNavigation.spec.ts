import { afterEach, describe, expect, it, vi } from 'vitest'

import { installMobileNavigation } from '../src/ui/mobileNavigation'

/** A history stack whose traversals, like a browser's, complete asynchronously. */
class Browser extends EventTarget {
  entries: unknown[]
  index = 1
  traversals: number[] = []
  history: {
    readonly state: unknown
    pushState: ReturnType<typeof vi.fn>
    replaceState: ReturnType<typeof vi.fn>
    go: ReturnType<typeof vi.fn>
  }

  constructor(initial: unknown = { router: 'messages', draft: { text: 'keep me' } }) {
    super()
    this.entries = [{ page: 'outside the app' }, initial]
    const browser = this
    this.history = {
      get state() { return browser.entries[browser.index] },
      pushState: vi.fn((state: unknown) => {
        this.entries.splice(++this.index, this.entries.length, structuredClone(state))
      }),
      replaceState: vi.fn((state: unknown) => {
        this.entries[this.index] = structuredClone(state)
      }),
      go: vi.fn((delta: number) => this.move(delta)),
    }
  }

  move(delta: number): void {
    const target = this.index + delta
    if (target >= 0 && target < this.entries.length) this.traversals.push(target)
  }

  flush(): void {
    const target = this.traversals.shift()
    if (target === undefined) return
    this.index = target
    this.dispatchEvent(new Event('popstate'))
  }

  flushAll(): void {
    for (let count = 0; this.traversals.length && count < 10; count++) this.flush()
    expect(this.traversals).toEqual([])
  }
}

const cleanups: (() => void)[] = []

function setup(initialDepth = 0, initialState?: unknown) {
  const browser = new Browser(initialState)
  vi.stubGlobal('window', browser)
  let depth = initialDepth
  let nav: ReturnType<typeof installMobileNavigation> | undefined
  const closeTo = vi.fn((target: number) => {
    depth = Math.min(depth, target)
    // Mirrors the application's Vue watcher with flush: 'sync'.
    nav?.sync()
  })
  nav = installMobileNavigation({ getDepth: () => depth, closeTo })
  cleanups.push(nav.dispose)
  return {
    browser,
    closeTo,
    nav,
    depth: () => depth,
    setDepth(next: number) {
      depth = next
      nav.sync()
    },
  }
}

afterEach(() => {
  while (cleanups.length) cleanups.pop()!()
  vi.unstubAllGlobals()
})

describe('mobile browser navigation', () => {
  it('leaves the initial history entry and its foreign state untouched', () => {
    const ui = setup()
    const baseline = ui.browser.history.state
    ui.nav.sync()
    expect(ui.browser.history.state).toBe(baseline)
    expect(ui.browser.history.pushState).not.toHaveBeenCalled()
    expect(ui.browser.history.replaceState).not.toHaveBeenCalled()
    expect(ui.browser.history.go).not.toHaveBeenCalled()
  })

  it('creates one entry per opened layer and preserves existing state fields', () => {
    const ui = setup()
    ui.setDepth(1)
    ui.setDepth(1)
    ui.setDepth(2)
    expect(ui.browser.history.pushState).toHaveBeenCalledTimes(2)
    expect(ui.browser.history.state).toMatchObject({ router: 'messages', draft: { text: 'keep me' } })
    expect(ui.browser.entries[1]).toEqual({ router: 'messages', draft: { text: 'keep me' } })
  })

  it('browser Back closes details and then the conversation without pushing a loop', () => {
    const ui = setup(2)
    ui.browser.move(-1)
    ui.browser.flushAll()
    expect(ui.depth()).toBe(1)
    expect(ui.closeTo).toHaveBeenLastCalledWith(1)
    ui.browser.move(-1)
    ui.browser.flushAll()
    expect(ui.depth()).toBe(0)
    expect(ui.closeTo).toHaveBeenLastCalledWith(0)
    expect(ui.browser.history.pushState).toHaveBeenCalledTimes(2)
    expect(ui.browser.history.go).not.toHaveBeenCalled()
    expect(ui.browser.index).toBe(1)
  })

  it('the UI Back button consumes its own entry only once', () => {
    const ui = setup(2)
    ui.setDepth(1)
    ui.nav.sync()
    expect(ui.browser.history.go).toHaveBeenCalledExactlyOnceWith(-1)
    ui.browser.flushAll()
    expect(ui.depth()).toBe(1)
    expect(ui.closeTo).not.toHaveBeenCalled()
    expect(ui.browser.index).toBe(2)
  })

  it('closing all layers or changing to desktop safely returns to the app base', () => {
    const ui = setup(2)
    ui.setDepth(0)
    expect(ui.browser.history.go).toHaveBeenCalledExactlyOnceWith(-2)
    ui.browser.flushAll()
    ui.nav.sync()
    expect(ui.browser.index).toBe(1)
    expect(ui.browser.history.go).toHaveBeenCalledTimes(1)
  })

  it('never traverses unrelated history when the UI closes a screen', () => {
    const ui = setup(1)
    ui.browser.history.replaceState({ router: 'another application view' })
    ui.setDepth(0)
    expect(ui.browser.history.go).not.toHaveBeenCalled()
    expect(ui.browser.history.state).toEqual({ router: 'another application view' })
  })

  it('handles a second UI close while the first traversal is still pending', async () => {
    const ui = setup(2)
    ui.setDepth(1)
    ui.setDepth(0)
    ui.browser.flushAll()
    await Promise.resolve()
    expect(ui.depth()).toBe(0)
    expect(ui.browser.index).toBe(1)
    expect(ui.browser.history.go.mock.calls).toEqual([[-1], [-1]])
  })

  it('retains a newly opened layer while an earlier UI close completes', async () => {
    const ui = setup(2)
    ui.setDepth(1)
    ui.setDepth(2)
    ui.browser.flushAll()
    await Promise.resolve()
    expect(ui.depth()).toBe(2)
    expect(ui.browser.index).toBe(3)
    expect(ui.closeTo).not.toHaveBeenCalled()
    ui.browser.move(-1)
    ui.browser.flushAll()
    expect(ui.depth()).toBe(1)
  })

  it('Forward cannot reopen a conversation or details', () => {
    const ui = setup(2)
    ui.browser.move(-1)
    ui.browser.flushAll()
    expect(ui.depth()).toBe(1)
    ui.browser.move(1)
    ui.browser.flushAll()
    expect(ui.depth()).toBe(1)
    expect(ui.browser.index).toBe(2)
    expect(ui.browser.history.pushState).toHaveBeenCalledTimes(2)
  })

  it('preserves the open desktop chat when Forward revisits an old mobile entry', () => {
    const browser = new Browser()
    vi.stubGlobal('window', browser)
    let mobile = true
    let chatOpen = true
    const closeTo = vi.fn(() => { chatOpen = false })
    const nav = installMobileNavigation({
      getDepth: () => mobile && chatOpen ? 1 : 0,
      closeTo,
    })
    cleanups.push(nav.dispose)

    mobile = false
    nav.sync()
    browser.flushAll()
    expect(chatOpen).toBe(true)
    expect(browser.index).toBe(1)

    browser.move(1)
    browser.flushAll()
    expect(chatOpen).toBe(true)
    expect(closeTo).not.toHaveBeenCalled()
    expect(browser.index).toBe(1)
    expect(browser.history.pushState).toHaveBeenCalledTimes(1)
  })

  it('retains non-object history state exactly when returning or disposing', () => {
    const ui = setup(1, 'foreign route state')
    ui.setDepth(0)
    ui.browser.flushAll()
    expect(ui.browser.history.state).toBe('foreign route state')
    ui.setDepth(1)
    ui.nav.dispose()
    expect(ui.browser.history.state).toBe('foreign route state')
  })

  it('disposes idempotently without navigating, erasing foreign state, or handling later events', () => {
    const ui = setup(1)
    ui.nav.dispose()
    ui.nav.dispose()
    expect(ui.browser.history.state).toEqual({ router: 'messages', draft: { text: 'keep me' } })
    expect(ui.browser.history.go).not.toHaveBeenCalled()
    ui.browser.move(-1)
    ui.browser.flushAll()
    expect(ui.closeTo).not.toHaveBeenCalled()
    ui.setDepth(2)
    expect(ui.browser.history.pushState).toHaveBeenCalledTimes(1)
  })

  it('does not adopt an earlier instance’s history entries', () => {
    const ui = setup(1)
    const olderEntry = ui.browser.history.state
    ui.nav.dispose()
    ui.browser.history.replaceState(olderEntry)
    const next = installMobileNavigation({ getDepth: () => 0, closeTo: vi.fn() })
    cleanups.push(next.dispose)
    next.sync()
    expect(ui.browser.history.go).not.toHaveBeenCalled()
    expect(ui.browser.history.state).toEqual(olderEntry)
  })

  it('can be imported and installed without a browser', () => {
    vi.stubGlobal('window', undefined)
    const closeTo = vi.fn()
    const nav = installMobileNavigation({ getDepth: () => 2, closeTo })
    nav.sync()
    nav.dispose()
    expect(closeTo).not.toHaveBeenCalled()
  })
})
