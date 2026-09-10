import { conversationPagingContext, loadOlder, state, type OlderPageProgress } from './archive'

// A malformed cursor or a very large archive must not keep the browser paging
// forever. Another deliberate click can continue from the pages already loaded.
export const QUOTE_PAGE_LIMIT = 100

export type QuoteNavigationResult =
  | { status: 'found'; waID: string }
  | { status: 'not_found' | 'limit' | 'unavailable' | 'busy' | 'canceled' | 'error' }

export interface QuoteNavigationOptions {
  signal?: AbortSignal
  onProgress?: (pages: number) => void
  /** The view can preserve its scroll position while each page is prepended. */
  loadPage?: () => Promise<OlderPageProgress>
}

/** Resolve only inside the current conversation; never open Info or another chat. */
export async function resolveQuotedMessage(waID: string, options: QuoteNavigationOptions = {}): Promise<QuoteNavigationResult> {
  const context = conversationPagingContext()
  if (!context || !waID) return { status: 'unavailable' }
  const current = () => !options.signal?.aborted && context.current()
  const found = () => state.timeline.some(message => message.waID === waID)
  if (!current()) return { status: 'canceled' }
  if (found()) return { status: 'found', waID }
  if (state.loadingChat || state.loadingOlder) return { status: 'busy' }
  if (!state.hasOlder) return { status: 'not_found' }
  if (!state.connected) return { status: 'unavailable' }

  const cursors = new Set<string>()
  const loadPage = options.loadPage ?? loadOlder
  for (let pages = 0; pages < QUOTE_PAGE_LIMIT; pages++) {
    if (!current()) return { status: 'canceled' }
    const cursor = context.cursor()
    if (!cursor || cursors.has(cursor)) return { status: 'unavailable' }
    cursors.add(cursor)
    try {
      const progress = await loadPage()
      if (!current() || progress.status === 'stale') return { status: 'canceled' }
      if (progress.status === 'idle') return { status: state.loadingOlder ? 'busy' : 'unavailable' }
      options.onProgress?.(pages + 1)
      if (!current()) return { status: 'canceled' }
      if (found()) return { status: 'found', waID }
      if (!state.hasOlder) return { status: 'not_found' }
      // Even pages consisting only of reactions can advance the cursor. A
      // repeated cursor cannot, regardless of how many visible messages changed.
      if (!progress.after || progress.after === progress.before) return { status: 'unavailable' }
    } catch {
      return { status: current() ? 'error' : 'canceled' }
    }
  }
  return { status: 'limit' }
}
