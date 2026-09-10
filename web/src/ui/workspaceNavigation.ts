/** UI navigation keeps both screens on one origin and keeps reloads in context. */
export function workspaceViewURL(view: 'archive' | 'admin', current: string, workspace: string, device = ''): URL {
  const url = new URL(current)
  if (url.hostname === 'console.wappie.thehappie.co') {
    url.protocol = 'https:'
    url.host = 'app.wappie.thehappie.co'
  }
  url.pathname = view === 'admin' ? '/console' : '/'
  url.hash = ''
  // A deliberate screen change must not replay a completed payment return.
  url.searchParams.delete('billing')
  if (workspace) url.searchParams.set('workspace', workspace)
  else url.searchParams.delete('workspace')
  if (device) url.searchParams.set('device', device)
  else url.searchParams.delete('device')
  return url
}

/** Same-document navigation preserves the open session and browser Back state. */
export function showWorkspaceView(view: 'archive' | 'admin', workspace: string, device = ''): boolean {
  const url = workspaceViewURL(view, location.href, workspace, device)
  if (url.origin !== location.origin) {
    location.assign(url.toString())
    return false
  }
  replaceNavigationURL(url.toString())
  return true
}
import { replaceNavigationURL } from './mobileNavigation'

/** A changed number must replace a stale deep link without losing mobile Back state. */
export function setWorkspaceDeviceURL(workspace: string, device: string): void {
  try {
    const url = new URL(location.href)
    url.searchParams.set('workspace', workspace)
    url.searchParams.set('device', device)
    replaceNavigationURL(url.toString())
  } catch { /* Non-browser clients and disabled history still open normally. */ }
}

/** Signing out leaves no previous account's device selection on the login URL. */
export function clearWorkspaceDeviceURL(): void {
  try {
    const url = new URL(location.href)
    if (!url.searchParams.has('device')) return
    url.searchParams.delete('device')
    replaceNavigationURL(url.toString())
  } catch { /* History is not required to clear authorization. */ }
}
