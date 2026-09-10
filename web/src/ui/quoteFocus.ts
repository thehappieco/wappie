export interface QuoteFocusOptions {
  reducedMotion?: boolean
}

/** Reveal a loaded quoted message without moving the page or opening its info. */
export function focusQuotedMessage(scroller: HTMLElement, waID: string, options: QuoteFocusOptions = {}): HTMLElement | null {
  if (!waID) return null
  const message = [...scroller.querySelectorAll<HTMLElement>('[data-message-id]')]
    .find(element => element.dataset.messageId === waID)
  if (!message) return null
  const bubble = message.matches('.bubble') ? message : message.querySelector<HTMLElement>('.bubble')
  if (!bubble) return null

  const viewport = scroller.getBoundingClientRect()
  const target = bubble.getBoundingClientRect()
  const center = viewport.top + scroller.clientTop + scroller.clientHeight / 2
  const desiredTop = scroller.scrollTop + target.top + target.height / 2 - center
  const top = Math.max(0, Math.min(desiredTop, Math.max(0, scroller.scrollHeight - scroller.clientHeight)))
  const reducedMotion = options.reducedMotion
    ?? scroller.ownerDocument.defaultView?.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    ?? false

  // Omitting left preserves horizontal position. scrollIntoView could also
  // scroll ancestor containers and the document, so only move this scroller.
  scroller.scrollTo({ top, behavior: reducedMotion ? 'auto' : 'smooth' })
  bubble.focus({ preventScroll: true })
  return bubble
}
