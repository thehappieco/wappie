import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { reactive, watchEffect } from 'vue'
import { applyPrivacyAppearance, initializeTheme, readPreference, setTheme, theme, writePreference } from '../src/ui/preferences'
let cleanup: (() => void) | undefined
let cookies: Map<string, string>
let saved: Map<string, string>
let writes: string[]
let media: EventTarget & { matches: boolean }
let doc: EventTarget & { documentElement: { dataset: Record<string, string> }; visibilityState: string; cookie?: string }
let win: EventTarget
beforeEach(() => {
  cookies = new Map(); saved = new Map(); writes = []
  media = Object.assign(new EventTarget(), { matches: true })
  doc = Object.assign(new EventTarget(), { documentElement: { dataset: {} }, visibilityState: 'visible' })
  Object.defineProperty(doc, 'cookie', { configurable: true, get: () => [...cookies].map(([k, v]) => `${k}=${v}`).join('; '), set: (v: string) => { writes.push(v); const [k, value] = v.split(';')[0].split('='); cookies.set(k, value) } })
  win = Object.assign(new EventTarget(), { matchMedia: () => media })
  vi.stubGlobal('document', doc); vi.stubGlobal('window', win)
  vi.stubGlobal('location', { hostname: 'console.wappie.thehappie.co', protocol: 'https:' })
  vi.stubGlobal('localStorage', { getItem: (key: string) => saved.get(key) ?? null, setItem: (key: string, value: string) => { saved.set(key, value) } })
})
afterEach(() => { cleanup?.(); cleanup = undefined; vi.unstubAllGlobals() })
describe('appearance preferences', () => {
  it('follows the system at startup and when it changes', () => {
    cleanup = initializeTheme(); expect(theme.value).toBe('system'); expect(doc.documentElement.dataset.theme).toBe('dark')
    media.matches = false; media.dispatchEvent(new Event('change')); expect(doc.documentElement.dataset.theme).toBe('light')
  })
  it('keeps explicit appearance despite a conflicting system setting', () => {
    cookies.set('wappie_theme', 'light'); cleanup = initializeTheme(); media.dispatchEvent(new Event('change'))
    expect(theme.value).toBe('light'); expect(doc.documentElement.dataset.theme).toBe('light')
    setTheme('dark'); media.matches = false; media.dispatchEvent(new Event('change')); expect(doc.documentElement.dataset.theme).toBe('dark')
  })
  it('does not override independent incognito state', () => {
    doc.documentElement.dataset.incognito = 'true'; cleanup = initializeTheme(); setTheme('light')
    expect(doc.documentElement.dataset).toEqual({ incognito: 'true', theme: 'light' })
  })
  it('returns to the selected console theme while its device stays discreet', () => {
    cookies.set('wappie_theme', 'light'); cleanup = initializeTheme()
    const device = reactive({ phase: 'ready', view: 'archive' as 'archive' | 'admin', quiet: true })
    const stop = watchEffect(() => applyPrivacyAppearance(device), { flush: 'sync' })
    try {
      expect(doc.documentElement.dataset).toEqual({ theme: 'light', surface: 'chat', incognito: 'true' })
      device.view = 'admin'
      expect(doc.documentElement.dataset).toEqual({ theme: 'light', surface: 'console' })
      setTheme('dark')
      expect(doc.documentElement.dataset).toEqual({ theme: 'dark', surface: 'console' })
      setTheme('light')
      expect(doc.documentElement.dataset).toEqual({ theme: 'light', surface: 'console' })
      device.view = 'archive'
      expect(doc.documentElement.dataset).toEqual({ theme: 'light', surface: 'chat', incognito: 'true' })
      expect(device.quiet).toBe(true)
    } finally { stop() }
  })
  it('follows system changes in the console without changing device privacy', () => {
    cleanup = initializeTheme()
    const device = { phase: 'ready', view: 'admin' as const, quiet: true }
    applyPrivacyAppearance(device)
    expect(doc.documentElement.dataset).toEqual({ theme: 'dark', surface: 'console' })
    media.matches = false; media.dispatchEvent(new Event('change'))
    expect(doc.documentElement.dataset).toEqual({ theme: 'light', surface: 'console' })
    expect(device.quiet).toBe(true)
  })
  it('removes the discreet palette during sign-out and connection transitions', () => {
    cleanup = initializeTheme()
    for (const phase of ['locked', 'connecting', 'error']) {
      applyPrivacyAppearance({ phase: 'ready', view: 'archive', quiet: true })
      applyPrivacyAppearance({ phase, view: 'archive', quiet: true })
      expect(doc.documentElement.dataset).toEqual({ theme: 'dark' })
    }
    applyPrivacyAppearance({ phase: 'ready', view: 'archive', quiet: false })
    expect(doc.documentElement.dataset).toEqual({ theme: 'dark', surface: 'chat' })
  })
  it('shares preferences only within the Wappie product domain', () => {
    writePreference('theme', 'dark'); expect(writes[0]).toContain('SameSite=Lax; Domain=wappie.thehappie.co; Secure'); expect(saved.get('wappie_theme')).toBe('dark')
    vi.stubGlobal('location', { hostname: 'unrelatedwappie.thehappie.co', protocol: 'https:' }); writePreference('locale', 'de'); expect(writes[1]).not.toContain('Domain=')
  })
  it('supports self-hosted localhost without a Secure or shared-domain cookie', () => {
    vi.stubGlobal('location', { hostname: 'localhost', protocol: 'http:' }); writePreference('locale', 'en')
    expect(writes[0]).not.toContain('Domain='); expect(writes[0]).not.toContain('Secure'); expect(readPreference('locale')).toBe('en')
  })
  it('uses shared cookie over stale local storage and refreshes on tab visibility', () => {
    saved.set('wappie_locale', 'pt'); cookies.set('wappie_locale', 'fr'); expect(readPreference('locale')).toBe('fr')
    cleanup = initializeTheme(); cookies.set('wappie_theme', 'light'); doc.dispatchEvent(new Event('visibilitychange')); expect(theme.value).toBe('light')
  })
  it('refreshes after another tab changes its preference', () => {
    cleanup = initializeTheme(); saved.set('wappie_theme', 'light'); win.dispatchEvent(Object.assign(new Event('storage'), { key: 'wappie_theme' })); expect(theme.value).toBe('light')
  })
  it('works when persistence is denied', () => {
    Object.defineProperty(doc, 'cookie', { get: () => { throw Error('denied') }, set: () => { throw Error('denied') } })
    vi.stubGlobal('localStorage', { getItem: () => { throw Error('denied') }, setItem: () => { throw Error('denied') } })
    cleanup = initializeTheme(); expect(() => setTheme('light')).not.toThrow(); expect(doc.documentElement.dataset.theme).toBe('light')
  })
  it('ignores malformed or unknown saved choices', () => {
    cookies.set('wappie_theme', '%XX'); cleanup = initializeTheme(); expect(theme.value).toBe('system')
    cookies.set('wappie_theme', 'quiet'); doc.dispatchEvent(new Event('visibilitychange')); expect(theme.value).toBe('system')
  })
  it('removes listeners on cleanup', () => {
    cleanup = initializeTheme(); cleanup(); media.matches = false; media.dispatchEvent(new Event('change')); expect(doc.documentElement.dataset.theme).toBe('dark')
  })
})
