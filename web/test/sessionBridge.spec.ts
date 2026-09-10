import { IDBFactory } from 'fake-indexeddb'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { generateAccountKeys } from '../src/crypto/account'
import { importArchiveKey } from '../src/crypto/hpke'
import { clearLocalSession, loadLocalSession, type BrowserLogin } from '../src/state/sessionVault'

// Exercise the browser transport with real structured clone, WebCrypto and
// IndexedDB. The remote slot can disappear independently of first-party data,
// as a partitioned/ephemeral iframe does under browser privacy policies.
let remote: BrowserLogin | null
let cookies: string
let post: (data: Record<string, unknown>) => void

beforeEach(() => {
  vi.resetModules()
  remote = null
  cookies = ''
  vi.stubGlobal('indexedDB', new IDBFactory())
  vi.stubGlobal('BroadcastChannel', undefined)
  vi.stubGlobal('location', new URL('https://app.wappie.thehappie.co/'))
  const window = new EventTarget()
  const frameWindow = { postMessage(data: Record<string, unknown>) { post(data) } }
  function receive(data: Record<string, unknown>) {
    const event = new Event('message')
    Object.assign(event, { origin: 'https://api.wappie.thehappie.co', source: frameWindow, data: structuredClone(data) })
    window.dispatchEvent(event)
  }
  post = data => queueMicrotask(() => {
    if (data.hello) { receive({ channel: data.channel, ready: true }); return }
    if (data.operation === 'save') remote = structuredClone(data.login) as BrowserLogin
    if (data.operation === 'clear' && remote?.id === data.id) remote = null
    receive({ channel: data.channel, request: data.request, ok: true, login: data.operation === 'read' ? remote : null })
  })
  const frame = new EventTarget()
  Object.assign(frame, { contentWindow: frameWindow, setAttribute() {}, remove() {} })
  vi.stubGlobal('window', window)
  vi.stubGlobal('document', {
    get cookie() { return cookies },
    set cookie(value: string) { cookies = value.split(';')[0] },
    createElement() { return frame },
    body: { append() { queueMicrotask(() => frame.dispatchEvent(new Event('load'))) } },
  })
})
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

async function loginFixture(): Promise<BrowserLogin> {
  const { beginBrowserSessionEpoch } = await import('../src/state/sessionBridge')
  const pair = await generateAccountKeys()
  const accountKey = await importArchiveKey(pair.privateKey)
  pair.privateKey.fill(0)
  return { id: crypto.randomUUID(), realm: 'https://api.wappie.thehappie.co', serverURL: '',
    token: 'synthetic-local-fallback-token', expiresAt: Date.now() + 60_000,
    userID: crypto.randomUUID(), tenantID: crypto.randomUUID(), accountKey, epoch: beginBrowserSessionEpoch() }
}

describe('hosted browser storage transport', () => {
  it('keeps first-party authorization when an acknowledged iframe store later disappears', async () => {
    const bridge = await import('../src/state/sessionBridge')
    const login = await loginFixture()
    expect(await bridge.rememberBrowserSession(login)).toBe('local')
    await vi.waitFor(() => expect(remote?.id).toBe(login.id))
    expect((await loadLocalSession())?.id).toBe(login.id)
    remote = null
    const restored = await bridge.readBrowserSession()
    expect(restored?.id).toBe(login.id)
    expect(restored?.accountKey.key.extractable).toBe(false)
  })

  it('opens and restores the durable local login while the optional bridge is still connecting', async () => {
    const bridge = await import('../src/state/sessionBridge')
    const login = await loginFixture()
    const deliver = post
    const pending: Record<string, unknown>[] = []
    post = message => { pending.push(message) }
    expect(await bridge.rememberBrowserSession(login)).toBe('local')
    expect(remote).toBeNull()
    expect((await bridge.readBrowserSession())?.id).toBe(login.id)
    expect(pending.some(message => message.hello)).toBe(true)
    post = deliver
    pending.forEach(deliver)
    await vi.waitFor(() => expect(remote?.id).toBe(login.id))
  })

  it('shows a fresh sign-in without contacting a bridge that has no generation marker', async () => {
    const bridge = await import('../src/state/sessionBridge')
    const delivery = vi.fn(post)
    post = delivery
    expect(await bridge.readBrowserSession()).toBeNull()
    expect(delivery).not.toHaveBeenCalled()
  })

  it('keeps a rotated token last when an earlier bridge save is delayed', async () => {
    const bridge = await import('../src/state/sessionBridge')
    const first = await loginFixture()
    const next = { ...first, token: 'synthetic-rotated-token', expiresAt: first.expiresAt + 1000 }
    const deliver = post
    const pending: Record<string, unknown>[] = []
    post = message => { if (message.operation === 'save') pending.push(message); else deliver(message) }
    await bridge.rememberBrowserSession(first)
    await vi.waitFor(() => expect(pending).toHaveLength(1))
    await bridge.rememberBrowserSession(next)
    expect((await bridge.readBrowserSession())?.token).toBe(next.token)
    expect(pending).toHaveLength(1)
    deliver(pending.shift()!)
    await vi.waitFor(() => expect(pending).toHaveLength(1))
    deliver(pending.shift()!)
    await vi.waitFor(() => expect(remote?.token).toBe(next.token))
  })

  it('clears both acknowledged and local copies on logout', async () => {
    const bridge = await import('../src/state/sessionBridge')
    const login = await loginFixture()
    await bridge.rememberBrowserSession(login)
    await bridge.forgetBrowserSession(login.id, login.epoch)
    expect(remote).toBeNull()
    expect(await loadLocalSession()).toBeNull()
    expect(await bridge.readBrowserSession()).toBeNull()
  })

  it('a late local write after logout cannot reopen the acknowledged remote login', async () => {
    const bridge = await import('../src/state/sessionBridge')
    const login = await loginFixture()
    const encrypt = crypto.subtle.encrypt.bind(crypto.subtle)
    let release!: () => void
    const waiting = new Promise<void>(resolve => { release = resolve })
    vi.spyOn(crypto.subtle, 'encrypt').mockImplementationOnce(async (...args) => { await waiting; return encrypt(...args) })
    const saving = bridge.rememberBrowserSession(login)
    await vi.waitFor(() => expect(crypto.subtle.encrypt).toHaveBeenCalledOnce())
    await bridge.forgetBrowserSession(login.id, login.epoch)
    release()
    await expect(saving).rejects.toThrow('cleared')
    expect(await loadLocalSession()).toBeNull()
    expect(remote).toBeNull()
  })

  it('respects a durable local logout even when the remote slot still holds that login', async () => {
    const bridge = await import('../src/state/sessionBridge')
    const login = await loginFixture()
    await bridge.rememberBrowserSession(login)
    await clearLocalSession(login.id)
    expect(await bridge.readBrowserSession()).toBeNull()
  })
})
