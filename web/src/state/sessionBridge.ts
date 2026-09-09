import { clearLocalSession, loadLocalSession, localSessionWasCleared, observeLocalSession, saveLocalSession, validBrowserLogin, type BrowserLogin, type SessionChange } from './sessionVault'

export const bridgeOrigin = 'https://api.wappie.thehappie.co'
export const browserOrigins = ['https://app.wappie.thehappie.co', 'https://console.wappie.thehappie.co'] as const
const channel = 'wappie/session-bridge/v1'
type Operation = 'read' | 'save' | 'clear'
interface BridgeRequest { channel: string; request: string; operation: Operation; login?: BrowserLogin; id?: string }
const changes = new Set<(change: SessionChange) => void>()
const clearedLogins = new Set<string>()
let bridge: Promise<HTMLIFrameElement> | undefined

function browserEpoch(): string | undefined {
  if (typeof document === 'undefined') return undefined
  try { return document.cookie.split('; ').find(value => value.startsWith('wappie_session_epoch='))?.slice('wappie_session_epoch='.length) }
  catch { return undefined }
}

function writeBrowserEpoch(value: string, seconds = 1209600): boolean {
  try {
    document.cookie = `wappie_session_epoch=${value}; Domain=wappie.thehappie.co; Path=/; Secure; SameSite=Strict; Max-Age=${seconds}`
    return browserEpoch() === value
  } catch { return false }
}

/** A public generation marker lets logout invalidate other origins even offline.
 * It is deliberately not a token, key, identity or server authentication cookie. */
export function beginBrowserSessionEpoch(): string | undefined {
  if (!sharedBrowserOrigin()) return undefined
  const value = crypto.randomUUID()
  return writeBrowserEpoch(value) ? value : undefined
}

export function browserSessionWasCleared(id: string, epoch?: string): boolean {
  return clearedLogins.has(id) || Boolean(epoch && browserEpoch() !== epoch)
}

export function sharedBrowserOrigin(): boolean {
  return typeof location !== 'undefined' && browserOrigins.some(origin => origin === location.origin)
}

function connectBridge(): Promise<HTMLIFrameElement> {
  if (bridge) return bridge
  bridge = new Promise<HTMLIFrameElement>((resolve, reject) => {
    const iframe = document.createElement('iframe')
    iframe.hidden = true
    iframe.title = 'Wappie session'
    iframe.src = bridgeOrigin + '/session-bridge.html'
    iframe.referrerPolicy = 'no-referrer'
    iframe.addEventListener('load', () => iframe.contentWindow?.postMessage({ channel, hello: true }, bridgeOrigin))
    // Origin isolation is required for IndexedDB and CryptoKey structured clone.
    iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin')
    const timeout = setTimeout(() => { cleanup(); iframe.remove(); reject(new Error('session bridge unavailable')) }, 6000)
    function cleanup() { clearTimeout(timeout); window.removeEventListener('message', ready) }
    function ready(event: MessageEvent) {
      if (event.origin !== bridgeOrigin || event.source !== iframe.contentWindow || event.data?.channel !== channel || event.data?.ready !== true) return
      cleanup()
      window.addEventListener('message', event => {
        if (event.origin !== bridgeOrigin || event.source !== iframe.contentWindow || event.data?.channel !== channel || event.data?.change?.kind !== 'cleared') return
        const change = event.data.change as SessionChange
        if (typeof change.id !== 'string' || change.id.length !== 36) return
        clearedLogins.add(change.id)
        // Clear fallback copies too, including writes waiting behind logout.
        void clearLocalSession(change.id).catch(() => {})
        for (const listener of changes) listener(change)
      })
      resolve(iframe)
    }
    window.addEventListener('message', ready)
    document.body.append(iframe)
  }).catch(error => { bridge = undefined; throw error })
  return bridge
}

async function requestBridge(operation: Operation, input: { login?: BrowserLogin; id?: string } = {}): Promise<BrowserLogin | null> {
  const iframe = await connectBridge()
  const request = crypto.randomUUID()
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { cleanup(); reject(new Error('session bridge timed out')) }, 6000)
    function cleanup() { clearTimeout(timeout); window.removeEventListener('message', receive) }
    function receive(event: MessageEvent) {
      if (event.origin !== bridgeOrigin || event.source !== iframe.contentWindow || event.data?.channel !== channel || event.data?.request !== request) return
      cleanup()
      if (!event.data.ok) { reject(new Error('browser storage unavailable')); return }
      if (operation === 'read' && event.data.login != null && !validBrowserLogin(event.data.login)) { reject(new Error('invalid browser session')); return }
      resolve(event.data.login ?? null)
    }
    window.addEventListener('message', receive)
    try { iframe.contentWindow!.postMessage({ channel, request, operation, ...input }, bridgeOrigin) }
    catch (error) { cleanup(); reject(error) }
  })
}

export async function rememberBrowserSession(login: BrowserLogin): Promise<'shared' | 'local'> {
  if (browserSessionWasCleared(login.id, login.epoch)) throw new Error('browser session was cleared')
  if (sharedBrowserOrigin() && login.epoch) writeBrowserEpoch(login.epoch, Math.max(1, Math.min(1209600, Math.floor((login.expiresAt - Date.now()) / 1000))))
  if (sharedBrowserOrigin() && login.epoch) {
    try {
      await requestBridge('save', { login })
      if (browserSessionWasCleared(login.id, login.epoch)) throw new Error('browser session was cleared')
      return 'shared'
    } catch { /* Browser policies may block iframe storage. */ }
  }
  if (browserSessionWasCleared(login.id, login.epoch)) throw new Error('browser session was cleared')
  await saveLocalSession(login)
  return 'local'
}

export async function readBrowserSession(): Promise<BrowserLogin | null> {
  if (sharedBrowserOrigin()) {
    try {
      const login = await requestBridge('read')
      if (login) {
        // Logout during an outage may only have cleared local storage. That
        // durable tombstone must override an old copy when the bridge returns.
        if (!login.epoch || browserSessionWasCleared(login.id, login.epoch) || await localSessionWasCleared(login.id)) {
          clearedLogins.add(login.id)
          void requestBridge('clear', { id: login.id }).catch(() => {})
          return loadLocalSession()
        }
        return login
      }
    } catch { /* Same-origin fallback still survives refresh and payment returns. */ }
  }
  return loadLocalSession()
}

export async function forgetBrowserSession(id: string, epoch?: string): Promise<void> {
  if (epoch && browserEpoch() === epoch) beginBrowserSessionEpoch()
  clearedLogins.add(id)
  await Promise.allSettled([clearLocalSession(id), ...(sharedBrowserOrigin() ? [requestBridge('clear', { id })] : [])])
}

export function observeBrowserSession(listener: (change: SessionChange) => void): () => void {
  changes.add(listener)
  const stop = observeLocalSession(change => { clearedLogins.add(change.id); listener(change) })
  return () => { changes.delete(listener); stop() }
}

/** Dedicated bridge page only. Every message is bound to its actual parent and exact UI origin. */
export function serveSessionBridge(): void {
  if (location.origin !== bridgeOrigin || window.parent === window) return
  const allowed = (origin: string) => browserOrigins.some(value => origin === value)
  let parentOrigin: string | undefined
  observeLocalSession(change => { if (parentOrigin) window.parent.postMessage({ channel, change }, parentOrigin) })
  window.addEventListener('message', event => {
    if (!allowed(event.origin) || event.source !== window.parent) return
    if (event.data?.channel === channel && event.data?.hello === true) {
      parentOrigin = event.origin
      window.parent.postMessage({ channel, ready: true }, event.origin)
      return
    }
    const req = event.data as BridgeRequest
    if (req?.channel !== channel || typeof req.request !== 'string' || req.request.length > 80) return
    if (!['read', 'save', 'clear'].includes(req.operation)) return
    parentOrigin = event.origin
    void (async () => {
      try {
        let login: BrowserLogin | null = null
        if (req.operation === 'read') login = await loadLocalSession()
        if (req.operation === 'save') {
          if (!validBrowserLogin(req.login) || req.login.realm !== bridgeOrigin || req.login.serverURL !== ''
            || !req.login.epoch || browserEpoch() !== req.login.epoch) throw new Error('invalid session')
          await saveLocalSession(req.login)
        }
        if (req.operation === 'clear') {
          if (typeof req.id !== 'string' || req.id.length !== 36) throw new Error('invalid session id')
          await clearLocalSession(req.id)
        }
        window.parent.postMessage({ channel, request: req.request, ok: true, login }, event.origin)
      } catch { window.parent.postMessage({ channel, request: req.request, ok: false }, event.origin) }
    })()
  })
}
