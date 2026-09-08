import { afterEach, describe, expect, it, vi } from 'vitest'

import { whenVisible } from '../src/ui/visible'

const cancel: Array<() => void> = []
const observers: Observer[] = []

class Observer {
  observed = new Set<Element>()
  disconnect = vi.fn(() => this.observed.clear())
  constructor(private callback: IntersectionObserverCallback) { observers.push(this) }
  observe(element: Element) { this.observed.add(element) }
  unobserve(element: Element) { this.observed.delete(element) }
  show(target: Element, isIntersecting = true) {
    this.callback([{ target, isIntersecting } as IntersectionObserverEntry], this as unknown as IntersectionObserver)
  }
}

afterEach(() => {
  for (const stop of cancel.splice(0)) stop()
  observers.length = 0
  vi.unstubAllGlobals()
})

describe('loading visible rows', () => {
  it('does not request an offscreen avatar and requests a visible one only once', () => {
    vi.stubGlobal('IntersectionObserver', Observer)
    const row = {} as Element
    const load = vi.fn()
    cancel.push(whenVisible(row, load))
    expect(load).not.toHaveBeenCalled()
    const observer = observers[0]!
    observer.show(row, false)
    expect(load).not.toHaveBeenCalled()
    observer.show(row)
    observer.show(row)
    expect(load).toHaveBeenCalledTimes(1)
    expect(observer.disconnect).toHaveBeenCalledTimes(1)
  })

  it('shares the observer across rows and cancels a removed row independently', () => {
    vi.stubGlobal('IntersectionObserver', Observer)
    const removed = {} as Element
    const visible = {} as Element
    const oldLoad = vi.fn()
    const visibleLoad = vi.fn()
    const stop = whenVisible(removed, oldLoad)
    cancel.push(stop, whenVisible(visible, visibleLoad))
    expect(observers).toHaveLength(1)
    stop()
    const observer = observers[0]!
    observer.show(removed)
    observer.show(visible)
    expect(oldLoad).not.toHaveBeenCalled()
    expect(visibleLoad).toHaveBeenCalledOnce()
  })

  it('ignores a late notification from an observer disconnected before a row was reused', () => {
    vi.stubGlobal('IntersectionObserver', Observer)
    const row = {} as Element
    const oldLoad = vi.fn()
    const nextLoad = vi.fn()
    const stop = whenVisible(row, oldLoad)
    cancel.push(stop)
    const oldObserver = observers[0]!
    stop()
    cancel.push(whenVisible(row, nextLoad))
    oldObserver.show(row)
    expect(oldLoad).not.toHaveBeenCalled()
    expect(nextLoad).not.toHaveBeenCalled()
    observers[1]!.show(row)
    expect(nextLoad).toHaveBeenCalledOnce()
  })

  it('still loads pictures when the browser has no visibility observer', () => {
    vi.stubGlobal('IntersectionObserver', undefined)
    const load = vi.fn()
    cancel.push(whenVisible({} as Element, load))
    expect(load).toHaveBeenCalledOnce()
  })
})
