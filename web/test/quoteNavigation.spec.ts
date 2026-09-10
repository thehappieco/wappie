import { beforeEach, describe, expect, it, vi } from 'vitest'
const fixture = vi.hoisted(() => ({
  generation: 1, cursor: 'page-1' as string | null, available: true,
  state: { timeline: [] as { waID: string }[], loadingOlder: false, loadingChat: false, hasOlder: true, connected: true },
  loadOlder: vi.fn(), context: vi.fn(),
}))
vi.mock('../src/state/archive', () => ({ state: fixture.state, loadOlder: fixture.loadOlder, conversationPagingContext: fixture.context }))
import { QUOTE_PAGE_LIMIT, resolveQuotedMessage } from '../src/state/quoteNavigation'

function deferred<T>() { let resolve!: (value: T) => void; let reject!: (reason: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no }); return { promise, resolve, reject } }

beforeEach(() => {
  vi.clearAllMocks()
  fixture.generation = 1; fixture.cursor = 'page-1'; fixture.available = true
  Object.assign(fixture.state, { timeline: [], loadingOlder: false, loadingChat: false, hasOlder: true, connected: true })
  fixture.context.mockImplementation(() => {
    if (!fixture.available) return null
    const generation = fixture.generation
    return { current: () => fixture.generation === generation, cursor: () => fixture.cursor }
  })
  fixture.loadOlder.mockImplementation(async () => {
    const before = fixture.cursor
    fixture.cursor = `page-${fixture.loadOlder.mock.calls.length + 1}`
    return { status: 'loaded', before, after: fixture.cursor }
  })
})

describe('quoted-message navigation within one conversation', () => {
  it('finds a loaded original immediately, including our own message while offline', async () => {
    fixture.state.timeline = [{ waID: 'own-original' }]; fixture.state.connected = false
    expect(await resolveQuotedMessage('own-original')).toEqual({ status: 'found', waID: 'own-original' })
    expect(fixture.loadOlder).not.toHaveBeenCalled()
  })
  it('keeps loading across empty projections until the original appears and reports progress', async () => {
    const progress = vi.fn()
    fixture.loadOlder.mockImplementation(async () => {
      const before = fixture.cursor
      fixture.cursor = `page-${fixture.loadOlder.mock.calls.length + 1}`
      if (fixture.loadOlder.mock.calls.length === 4) fixture.state.timeline.unshift({ waID: 'original' })
      return { status: 'loaded', before, after: fixture.cursor }
    })
    expect(await resolveQuotedMessage('original', { onProgress: progress })).toEqual({ status: 'found', waID: 'original' })
    expect(fixture.loadOlder).toHaveBeenCalledTimes(4)
    expect(progress.mock.calls).toEqual([[1], [2], [3], [4]])
  })
  it('uses the view loader so each prepended page can preserve the reader’s place', async () => {
    const loadPage = vi.fn(async () => { fixture.state.timeline.push({ waID: 'original' }); return { status: 'loaded' as const, before: 'page-1', after: null } })
    expect(await resolveQuotedMessage('original', { loadPage })).toEqual({ status: 'found', waID: 'original' })
    expect(loadPage).toHaveBeenCalledOnce(); expect(fixture.loadOlder).not.toHaveBeenCalled()
  })
  it('reports a missing original when the archive ends, without opening another chat', async () => {
    fixture.loadOlder.mockImplementation(async () => { fixture.state.hasOlder = false; return { status: 'loaded', before: 'page-1', after: null } })
    expect(await resolveQuotedMessage('missing')).toEqual({ status: 'not_found' })
    expect(fixture.loadOlder).toHaveBeenCalledOnce()
  })
  it('does not start overlapping pagination or search while opening a chat', async () => {
    fixture.state.loadingOlder = true
    expect(await resolveQuotedMessage('missing')).toEqual({ status: 'busy' })
    fixture.state.loadingOlder = false; fixture.state.loadingChat = true
    expect(await resolveQuotedMessage('missing')).toEqual({ status: 'busy' })
    expect(fixture.loadOlder).not.toHaveBeenCalled()
  })
  it('does not issue requests without a current context, cursor, or connection', async () => {
    fixture.available = false
    expect(await resolveQuotedMessage('missing')).toEqual({ status: 'unavailable' })
    fixture.available = true; fixture.cursor = null
    expect(await resolveQuotedMessage('missing')).toEqual({ status: 'unavailable' })
    fixture.cursor = 'page-1'; fixture.state.connected = false
    expect(await resolveQuotedMessage('missing')).toEqual({ status: 'unavailable' })
    expect(fixture.loadOlder).not.toHaveBeenCalled()
  })
  it('stops a repeated cursor after one request even if visible messages changed', async () => {
    fixture.loadOlder.mockImplementation(async () => { fixture.state.timeline.push({ waID: 'unrelated' }); return { status: 'loaded', before: 'page-1', after: 'page-1' } })
    expect(await resolveQuotedMessage('missing')).toEqual({ status: 'unavailable' })
    expect(fixture.loadOlder).toHaveBeenCalledOnce()
  })
  it('detects a cycle through several previously visited cursors', async () => {
    fixture.loadOlder.mockImplementation(async () => { const before = fixture.cursor; fixture.cursor = before === 'page-1' ? 'page-2' : 'page-1'; return { status: 'loaded', before, after: fixture.cursor } })
    expect(await resolveQuotedMessage('missing')).toEqual({ status: 'unavailable' })
    expect(fixture.loadOlder).toHaveBeenCalledTimes(2)
  })
  it('stops at a bounded safety limit and leaves the cursor ready for a deliberate continuation', async () => {
    expect(await resolveQuotedMessage('missing')).toEqual({ status: 'limit' })
    expect(fixture.loadOlder).toHaveBeenCalledTimes(QUOTE_PAGE_LIMIT)
    const nextCursor = fixture.cursor
    fixture.loadOlder.mockImplementation(async () => { fixture.state.timeline.push({ waID: 'missing' }); return { status: 'loaded', before: nextCursor, after: 'older' } })
    expect(await resolveQuotedMessage('missing')).toEqual({ status: 'found', waID: 'missing' })
  })
  it('ignores a resolved target after the conversation context was replaced', async () => {
    const wait = deferred<{ status: string }>(); fixture.loadOlder.mockReturnValue(wait.promise)
    const pending = resolveQuotedMessage('original')
    fixture.generation++; fixture.state.timeline.push({ waID: 'original' })
    wait.resolve({ status: 'loaded' })
    expect(await pending).toEqual({ status: 'canceled' })
    expect(fixture.loadOlder).toHaveBeenCalledOnce()
  })
  it('cancellation prevents subsequent requests and progress, even if the last page found the target', async () => {
    const abort = new AbortController(); const progress = vi.fn(); const wait = deferred<{ status: string }>()
    fixture.loadOlder.mockReturnValue(wait.promise)
    const pending = resolveQuotedMessage('original', { signal: abort.signal, onProgress: progress })
    abort.abort(); fixture.state.timeline.push({ waID: 'original' }); wait.resolve({ status: 'loaded' })
    expect(await pending).toEqual({ status: 'canceled' }); expect(progress).not.toHaveBeenCalled()
    expect(await resolveQuotedMessage('original', { signal: abort.signal })).toEqual({ status: 'canceled' })
    expect(fixture.loadOlder).toHaveBeenCalledOnce()
  })
  it('reports a request error without retrying or exposing raw server output', async () => {
    fixture.loadOlder.mockRejectedValue(new Error('private server details'))
    expect(await resolveQuotedMessage('original')).toEqual({ status: 'error' })
    expect(fixture.loadOlder).toHaveBeenCalledOnce()
  })
  it('treats stale and skipped pages as terminal results', async () => {
    fixture.loadOlder.mockResolvedValue({ status: 'stale' })
    expect(await resolveQuotedMessage('original')).toEqual({ status: 'canceled' })
    fixture.loadOlder.mockResolvedValue({ status: 'idle' })
    expect(await resolveQuotedMessage('original')).toEqual({ status: 'unavailable' })
  })
})
