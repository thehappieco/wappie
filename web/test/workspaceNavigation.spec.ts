import { afterEach, describe, expect, it, vi } from 'vitest'
import { showWorkspaceView, workspaceViewURL } from '../src/ui/workspaceNavigation'

afterEach(() => vi.unstubAllGlobals())

describe('workspace screen navigation', () => {
  it('keeps hosted chat and console on the same origin with the active workspace and number', () => {
    const console = workspaceViewURL('admin', 'https://app.wappie.thehappie.co/?locale=fr&workspace=old&device=old', 'workspace-a', 'device-a')
    expect(console.toString()).toBe('https://app.wappie.thehappie.co/console?locale=fr&workspace=workspace-a&device=device-a')
    const chat = workspaceViewURL('archive', console.toString(), 'workspace-a', 'device-b')
    expect(chat.pathname).toBe('/')
    expect(chat.origin).toBe(console.origin)
    expect(chat.searchParams.get('device')).toBe('device-b')
  })

  it('does not replay a Stripe return after a deliberate screen change', () => {
    const result = workspaceViewURL('archive', 'https://app.wappie.thehappie.co/console?billing=change&workspace=a&device=old&locale=de#subscription', 'a', 'new')
    expect(result.searchParams.has('billing')).toBe(false)
    expect(result.searchParams.get('workspace')).toBe('a')
    expect(result.searchParams.get('locale')).toBe('de')
    expect(result.searchParams.get('device')).toBe('new')
    expect(result.hash).toBe('')
  })

  it('keeps self-hosted clients on their server and discards stale device selection', () => {
    const url = workspaceViewURL('admin', 'https://selfhost.example:8443/?device=previous', 'new-workspace')
    expect(url.toString()).toBe('https://selfhost.example:8443/console?workspace=new-workspace')
    expect(workspaceViewURL('archive', 'http://localhost:5173/console?workspace=old', '').toString()).toBe('http://localhost:5173/')
  })

  it('changes the current path without loading another document or replacing history metadata', () => {
    const entry = { wappieNavigation: { depth: 0 }, unrelated: 123 }
    const replaceState = vi.fn()
    const assign = vi.fn()
    vi.stubGlobal('location', { href: 'https://app.wappie.thehappie.co/', origin: 'https://app.wappie.thehappie.co', assign })
    vi.stubGlobal('history', { state: entry, replaceState })
    expect(showWorkspaceView('admin', 'space', 'phone')).toBe(true)
    expect(replaceState).toHaveBeenCalledExactlyOnceWith(entry, '', 'https://app.wappie.thehappie.co/console?workspace=space&device=phone')
    expect(assign).not.toHaveBeenCalled()
  })

  it('moves a still-open legacy console tab to the canonical app origin', () => {
    const assign = vi.fn()
    const replaceState = vi.fn()
    vi.stubGlobal('location', { href: 'https://console.wappie.thehappie.co/?locale=es', origin: 'https://console.wappie.thehappie.co', assign })
    vi.stubGlobal('history', { state: null, replaceState })
    expect(showWorkspaceView('archive', 'space', 'phone')).toBe(false)
    expect(assign).toHaveBeenCalledExactlyOnceWith('https://app.wappie.thehappie.co/?locale=es&workspace=space&device=phone')
    expect(replaceState).not.toHaveBeenCalled()
  })
})
