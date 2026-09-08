// All badges share one observer, so a long contact list does not create one
// browser observer per row. A callback runs once, shortly before its row enters
// the visible area, and is removed when that row goes away.
let observer: IntersectionObserver | undefined
const waiting = new Map<Element, () => void>()

function disconnectIfIdle() {
  if (waiting.size) return
  observer?.disconnect()
  observer = undefined
}

export function whenVisible(element: Element, load: () => void): () => void {
  if (typeof IntersectionObserver === 'undefined') {
    load()
    return () => {}
  }
  observer ??= new IntersectionObserver((entries, source) => {
    if (source !== observer) return
    for (const entry of entries) {
      if (!entry.isIntersecting) continue
      const callback = waiting.get(entry.target)
      if (!callback) continue
      waiting.delete(entry.target)
      observer?.unobserve(entry.target)
      callback()
    }
    disconnectIfIdle()
  }, { rootMargin: '100px' })
  waiting.set(element, load)
  observer.observe(element)

  return () => {
    if (waiting.get(element) !== load) return
    waiting.delete(element)
    observer?.unobserve(element)
    disconnectIfIdle()
  }
}
