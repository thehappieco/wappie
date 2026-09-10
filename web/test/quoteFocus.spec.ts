import { describe, expect, it, vi } from 'vitest'
import { focusQuotedMessage } from '../src/ui/quoteFocus'

function fixture({ targetTop = 500, targetHeight = 80, scrollHeight = 2000, reducedMotion = false } = {}) {
  const actions: string[] = []
  const bubble = {
    dataset: {} as DOMStringMap,
    matches: vi.fn((selector: string) => selector === '.bubble'),
    querySelector: vi.fn(),
    getBoundingClientRect: vi.fn(() => ({ top: targetTop, height: targetHeight })),
    focus: vi.fn(() => { actions.push('focus') }),
    click: vi.fn(),
    scrollIntoView: vi.fn(),
  }
  const message = {
    dataset: { messageId: 'quoted-id' },
    matches: vi.fn(() => false),
    querySelector: vi.fn(() => bubble),
  }
  const matchMedia = vi.fn(() => ({ matches: reducedMotion }))
  const scroller = {
    querySelectorAll: vi.fn(() => [message]),
    getBoundingClientRect: vi.fn(() => ({ top: 100 })),
    scrollTop: 300,
    scrollLeft: 77,
    clientTop: 2,
    clientHeight: 400,
    scrollHeight,
    ownerDocument: { defaultView: { matchMedia } },
    scrollTo: vi.fn(() => { actions.push('scroll') }),
  }
  const focus = (id = 'quoted-id', options?: { reducedMotion?: boolean }) => focusQuotedMessage(scroller as unknown as HTMLElement, id, options)
  return { bubble, message, matchMedia, scroller, actions, focus }
}

describe('quoted message focus', () => {
  it('centers the bubble inside the vertical viewport, accounting for its border and existing scroll', () => {
    const { focus, bubble, scroller, actions } = fixture()
    expect(focus()).toBe(bubble)
    expect(scroller.scrollTo).toHaveBeenCalledExactlyOnceWith({ top: 538, behavior: 'smooth' })
    expect(bubble.focus).toHaveBeenCalledExactlyOnceWith({ preventScroll: true })
    expect(actions).toEqual(['scroll', 'focus'])
    expect(scroller.scrollLeft).toBe(77)
    expect(bubble.scrollIntoView).not.toHaveBeenCalled()
    expect(bubble.click).not.toHaveBeenCalled()
  })

  it.each([
    { targetTop: -200, expected: 0 },
    { targetTop: 5000, expected: 1600 },
  ])('clamps the target to the vertical scroll range at $expected', ({ targetTop, expected }) => {
    const { focus, scroller } = fixture({ targetTop })
    focus()
    expect(scroller.scrollTo).toHaveBeenCalledExactlyOnceWith({ top: expected, behavior: 'smooth' })
  })

  it('uses zero when the conversation content is shorter than its viewport', () => {
    const { focus, scroller } = fixture({ scrollHeight: 200 })
    focus()
    expect(scroller.scrollTo).toHaveBeenCalledExactlyOnceWith({ top: 0, behavior: 'smooth' })
  })

  it('compares IDs literally without interpolating quotes or CSS syntax into a selector', () => {
    const { focus, message, scroller, bubble } = fixture()
    const id = 'quote" ] #page [data-message-id="another\\id'
    message.dataset.messageId = id
    expect(focus(id)).toBe(bubble)
    expect(scroller.querySelectorAll).toHaveBeenCalledExactlyOnceWith('[data-message-id]')
    expect(message.querySelector).toHaveBeenCalledExactlyOnceWith('.bubble')
  })

  it('returns null without side effects when the ID is absent or unmatched', () => {
    const { focus, scroller, bubble, matchMedia } = fixture()
    expect(focus('')).toBeNull()
    expect(scroller.querySelectorAll).not.toHaveBeenCalled()
    expect(focus(' quoted-id ')).toBeNull()
    expect(scroller.scrollTo).not.toHaveBeenCalled()
    expect(bubble.focus).not.toHaveBeenCalled()
    expect(matchMedia).not.toHaveBeenCalled()
  })

  it('does nothing when a matching message has no bubble', () => {
    const { focus, message, scroller, bubble } = fixture()
    message.querySelector.mockReturnValue(null as unknown as typeof bubble)
    expect(focus()).toBeNull()
    expect(scroller.scrollTo).not.toHaveBeenCalled()
    expect(bubble.focus).not.toHaveBeenCalled()
  })

  it('also supports a data-message-id directly on the focusable bubble', () => {
    const { focus, scroller, bubble } = fixture()
    bubble.dataset.messageId = 'quoted-id'
    scroller.querySelectorAll.mockReturnValue([bubble as unknown as ReturnType<typeof scroller.querySelectorAll>[number]])
    expect(focus()).toBe(bubble)
    expect(bubble.querySelector).not.toHaveBeenCalled()
    expect(bubble.focus).toHaveBeenCalledOnce()
  })

  it('uses the scroller document’s reduced-motion preference when no override is supplied', () => {
    const { focus, scroller, matchMedia } = fixture({ reducedMotion: true })
    focus()
    expect(matchMedia).toHaveBeenCalledExactlyOnceWith('(prefers-reduced-motion: reduce)')
    expect(scroller.scrollTo).toHaveBeenCalledExactlyOnceWith({ top: 538, behavior: 'auto' })
  })

  it.each([
    { reducedMotion: true, behavior: 'auto' },
    { reducedMotion: false, behavior: 'smooth' },
  ] as const)('respects an explicit reducedMotion=$reducedMotion without querying the device', ({ reducedMotion, behavior }) => {
    const { focus, scroller, matchMedia } = fixture({ reducedMotion: !reducedMotion })
    focus('quoted-id', { reducedMotion })
    expect(matchMedia).not.toHaveBeenCalled()
    expect(scroller.scrollTo).toHaveBeenCalledExactlyOnceWith({ top: 538, behavior })
  })

  it('works when the document has no matchMedia capability', () => {
    const { focus, scroller } = fixture()
    Object.assign(scroller.ownerDocument, { defaultView: null })
    expect(focus()).not.toBeNull()
    expect(scroller.scrollTo).toHaveBeenCalledExactlyOnceWith({ top: 538, behavior: 'smooth' })
  })
})
