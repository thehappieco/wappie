import { ref } from 'vue'

export type ThemePreference = 'light' | 'dark' | 'system'
type PreferenceName = 'theme' | 'locale'
const prefix = 'wappie_'

/** Preferences are non-sensitive and shared only with the Wappie product. */
export function readPreference(name: PreferenceName): string | null {
  try {
    const entry = document.cookie.split(';').map(part => part.trim()).find(part => part.startsWith(`${prefix}${name}=`))
    if (entry) return decodeURIComponent(entry.slice(entry.indexOf('=') + 1))
  } catch { /* Disabled cookies still allow a local preference. */ }
  try { return localStorage.getItem(`${prefix}${name}`) } catch { return null }
}

export function writePreference(name: PreferenceName, value: string): void {
  try { localStorage.setItem(`${prefix}${name}`, value) } catch { /* Private browsing can deny storage. */ }
  try {
    const host = location.hostname.toLowerCase()
    const shared = host === 'wappie.thehappie.co' || host.endsWith('.wappie.thehappie.co')
    document.cookie = `${prefix}${name}=${encodeURIComponent(value)}; Path=/; Max-Age=31536000; SameSite=Lax${shared ? '; Domain=wappie.thehappie.co' : ''}${location.protocol === 'https:' ? '; Secure' : ''}`
  } catch { /* A preference is still usable for the current page. */ }
}

export const theme = ref<ThemePreference>('system')
let media: MediaQueryList | null = null
let stopListening: (() => void) | null = null

/** A device's discreet reading palette applies only while its chat is visible. */
export function applyPrivacyAppearance(state: { phase: string; view: 'archive' | 'admin'; quiet: boolean }): void {
  if (typeof document === 'undefined') return
  const root = document.documentElement
  if (state.phase === 'ready') root.dataset.surface = state.view === 'archive' ? 'chat' : 'console'
  else delete root.dataset.surface
  if (root.dataset.surface === 'chat' && state.quiet) root.dataset.incognito = 'true'
  else delete root.dataset.incognito
}

function isTheme(value: string | null): value is ThemePreference {
  return value === 'light' || value === 'dark' || value === 'system'
}

function applyTheme(): void {
  if (typeof document === 'undefined') return
  document.documentElement.dataset.theme = theme.value === 'system' ? (media?.matches ? 'dark' : 'light') : theme.value
}

export function setTheme(value: ThemePreference): void {
  if (!isTheme(value)) return
  theme.value = value
  writePreference('theme', value)
  applyTheme()
}

/** Call before mounting the application, so the first frame has the chosen palette. */
export function initializeTheme(): () => void {
  stopListening?.()
  media = typeof window !== 'undefined' && typeof window.matchMedia === 'function'
    ? window.matchMedia('(prefers-color-scheme: dark)') : null
  const restore = () => {
    const saved = readPreference('theme')
    theme.value = isTheme(saved) ? saved : 'system'
    applyTheme()
  }
  const onStorage = (event: StorageEvent) => {
    if (event.key === `${prefix}theme` || event.key === null) restore()
  }
  const onVisibility = () => {
    if (document.visibilityState === 'visible') restore()
  }
  restore()
  media?.addEventListener('change', applyTheme)
  window.addEventListener('storage', onStorage)
  document.addEventListener('visibilitychange', onVisibility)
  const currentMedia = media
  const cleanup = () => {
    currentMedia?.removeEventListener('change', applyTheme)
    window.removeEventListener('storage', onStorage)
    document.removeEventListener('visibilitychange', onVisibility)
    if (stopListening === cleanup) stopListening = null
  }
  stopListening = cleanup
  return cleanup
}
