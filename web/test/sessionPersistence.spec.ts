import { IDBFactory } from 'fake-indexeddb'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { generateAccountKeys } from '../src/crypto/account'
import { importArchiveKey } from '../src/crypto/hpke'
import { parseUUID, toBase64 } from '../src/crypto/bytes'
import { grantRow, Kind, sealDirect } from '../src/crypto/seal'
import { fromAccount, restoreAccountSession } from '../src/state/session'
import { clearLocalSession, loadLocalSession, saveLocalSession, type BrowserLogin } from '../src/state/sessionVault'
import { restoreSignIn } from '../src/api/auth'
import { stop } from '../src/state/archive'

const SERVER = 'https://selfhost.example.test'
const USER = '018f3a2b-2222-7000-8000-00000000aaaa'
const TENANT = '018f3a2b-2222-7000-8000-00000000bbbb'
const OTHER = '018f3a2b-2222-7000-8000-00000000cccc'
const DEVICE = '018f3a2b-2222-7000-8000-00000000dddd'

beforeEach(() => {
  vi.stubGlobal('indexedDB', new IDBFactory())
  vi.stubGlobal('location', new URL(SERVER))
})
afterEach(() => { stop({ logout: false }); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

async function fixture() {
  const keys = await generateAccountKeys()
  const accountKey = await importArchiveKey(keys.privateKey)
  keys.privateKey.fill(0)
  const expiresAt = Date.now() + 60_000
  const login: BrowserLogin = { id: crypto.randomUUID(), realm: SERVER, serverURL: SERVER, token: 'synthetic-base-session',
    expiresAt, userID: USER, tenantID: TENANT, accountKey }
  const user = { id: USER, tenant_id: TENANT, email: 'browser@example.test', role: 'owner', has_recovery: true,
    public_key: toBase64(keys.publicKey), wrapped_usk: 'opaque-password-wrap' }
  const deviceRaw = crypto.getRandomValues(new Uint8Array(32))
  const row = await grantRow(parseUUID(TENANT), parseUUID(DEVICE), parseUUID(USER), 1)
  const sealed = await sealDirect(keys.publicKey, Kind.DeviceGrant, parseUUID(TENANT), row, 1, deviceRaw)
  deviceRaw.fill(0)
  const me = { user, expires_at: new Date(expiresAt).toISOString(), grants: [{ device_id: DEVICE, label: 'Test number', epoch: 1, sealed_dsk: toBase64(sealed) }] }
  return { login, me }
}

function ok(body: unknown) { return new Response(JSON.stringify(body), { status: 200 }) }

async function rawRecord(): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('wappie-browser-session', 1)
    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      const db = request.result
      const tx = db.transaction('session')
      const record = tx.objectStore('session').get('current')
      record.onsuccess = () => resolve(record.result as Record<string, unknown>)
      tx.oncomplete = () => db.close()
    }
  })
}

describe('persistent browser authorization', () => {
  it('stores encrypted tokens and structured-cloned, non-extractable account keys', async () => {
    const { login } = await fixture()
    await saveLocalSession(login)
    const raw = await rawRecord()
    expect(raw).not.toHaveProperty('token')
    expect(JSON.stringify(raw)).not.toContain(login.token)
    expect((raw.wrappingKey as CryptoKey).extractable).toBe(false)
    const restored = await loadLocalSession()
    expect(restored?.token).toBe(login.token)
    expect(restored?.accountKey.key).not.toBe(login.accountKey.key)
    expect(restored?.accountKey.key.extractable).toBe(false)
    await expect(crypto.subtle.exportKey('pkcs8', restored!.accountKey.key)).rejects.toThrow()
  })

  it('restores after losing page memory and reopens grants using the stored CryptoKey', async () => {
    const { login, me } = await fixture()
    await saveLocalSession(login)
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => ok(me))
    const session = await restoreAccountSession()
    expect(session?.credential.token).toBe(login.token)
    expect(session?.archiveFor(DEVICE)?.key.extractable).toBe(false)
    expect(session?.readable).toEqual([{ deviceID: DEVICE, label: 'Test number' }])
    expect(fetch).toHaveBeenCalledWith(SERVER + '/v1/auth/me', expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer ' + login.token }) }))
  })

  it('uses current authorization and grants instead of persisted device access', async () => {
    const { login, me } = await fixture()
    await saveLocalSession(login)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(ok({ ...me, user: { ...me.user, role: 'member' }, grants: [] }))
    const session = await restoreAccountSession()
    expect(session?.readable).toEqual([])
    expect(session?.archiveFor(DEVICE)).toBeUndefined()
  })

  it('clears revoked authorization before any account can open', async () => {
    const { login } = await fixture()
    await saveLocalSession(login)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ code: 'unauthorized' }), { status: 401 }))
    expect(await restoreAccountSession()).toBeNull()
    expect(await loadLocalSession()).toBeNull()
  })

  it('preserves the vault on a temporary network outage so retry can succeed', async () => {
    const { login, me } = await fixture()
    await saveLocalSession(login)
    const fetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('network unavailable'))
    await expect(restoreAccountSession()).rejects.toThrow('network unavailable')
    expect((await loadLocalSession())?.id).toBe(login.id)
    fetch.mockImplementation(async () => ok(me))
    expect((await restoreAccountSession())?.readable).toHaveLength(1)
  })

  it('removes expired storage without using its token', async () => {
    const { login } = await fixture()
    await saveLocalSession(login)
    vi.spyOn(Date, 'now').mockReturnValue(login.expiresAt + 1)
    const fetch = vi.spyOn(globalThis, 'fetch')
    expect(await restoreAccountSession()).toBeNull()
    expect(await rawRecord()).toBeUndefined()
    expect(fetch).not.toHaveBeenCalled()
  })

  it('rejects an account/key mismatch and removes the unusable session', async () => {
    const { login, me } = await fixture()
    await saveLocalSession(login)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(ok({ ...me, user: { ...me.user, public_key: toBase64(new Uint8Array(32)) } }))
    expect(await restoreAccountSession()).toBeNull()
    expect(await loadLocalSession()).toBeNull()
  })

  it('switches workspace by an authorized derived token while preserving the base login', async () => {
    const { login, me } = await fixture()
    const selected = { ...me, user: { ...me.user, tenant_id: OTHER }, grants: [] }
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url).endsWith('/workspaces/session')) {
        expect(JSON.parse(String(init?.body))).toEqual({ tenant_id: OTHER })
        return ok({ token: 'synthetic-derived-session', expires_at: new Date(login.expiresAt).toISOString(), user: selected.user })
      }
      return ok((init?.headers as Record<string, string>).Authorization === 'Bearer synthetic-derived-session' ? selected : me)
    })
    const signed = await restoreSignIn(login, OTHER)
    expect(signed.token).toBe('synthetic-derived-session')
    expect(signed.tenantID).toBe(OTHER)
    expect(signed.browserLogin?.token).toBe(login.token)
    expect(signed.browserLogin?.tenantID).toBe(TENANT)
    expect(fetch).toHaveBeenCalledTimes(3)
  })

  it('falls back to the valid base workspace when a link requests an unavailable space', async () => {
    const { login, me } = await fixture()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async url => String(url).endsWith('/workspaces/session')
      ? new Response(JSON.stringify({ code: 'not_authorized' }), { status: 403 }) : ok(me))
    const signed = await restoreSignIn(login, OTHER)
    expect(signed.tenantID).toBe(TENANT)
    expect(signed.token).toBe(login.token)
    expect(signed.notice).toContain('espaço não está disponível')
    expect(signed.readable).toHaveLength(1)
  })

  it('bounds restoration requests to fifteen seconds', async () => {
    const { login } = await fixture()
    vi.useFakeTimers()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_url, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
    }))
    const restoring = expect(restoreSignIn(login)).rejects.toMatchObject({ name: 'AbortError' })
    await vi.advanceTimersByTimeAsync(15_000)
    await restoring
  })

  it('preserves storage on normal navigation but clears it and the session family on explicit logout', async () => {
    const { login, me } = await fixture()
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async url => String(url).endsWith('/logout') ? new Response(null, { status: 204 }) : ok(me))
    const signed = await restoreSignIn(login)
    const first = fromAccount(signed, SERVER)
    await first.remember?.()
    first.dispose?.()
    expect((await loadLocalSession())?.id).toBe(login.id)
    expect(fetch.mock.calls.some(([url]) => String(url).endsWith('/logout'))).toBe(false)
    const second = await restoreAccountSession()
    await second!.close()
    expect(await loadLocalSession()).toBeNull()
    expect(fetch).toHaveBeenCalledWith(SERVER + '/v1/auth/logout', expect.objectContaining({ body: JSON.stringify({ all_related: true }) }))
  })

  it('cannot resurrect a cleared login with a delayed save', async () => {
    const { login } = await fixture()
    const encrypt = crypto.subtle.encrypt.bind(crypto.subtle)
    let release!: () => void
    const waiting = new Promise<void>(resolve => { release = resolve })
    vi.spyOn(crypto.subtle, 'encrypt').mockImplementation(async (...args) => { await waiting; return encrypt(...args) })
    const saving = saveLocalSession(login)
    await clearLocalSession(login.id)
    release()
    await expect(saving).rejects.toThrow('cleared')
    expect(await loadLocalSession()).toBeNull()
  })

  it('an old tab logout cannot erase a newer login', async () => {
    const old = (await fixture()).login
    const fresh = (await fixture()).login
    await saveLocalSession(old)
    await saveLocalSession(fresh)
    await clearLocalSession(old.id)
    expect((await loadLocalSession())?.id).toBe(fresh.id)
  })

  it('replacement prevents an old save from overwriting the new account', async () => {
    const old = (await fixture()).login
    const fresh = (await fixture()).login
    await saveLocalSession(old)
    const encrypt = crypto.subtle.encrypt.bind(crypto.subtle)
    let release!: () => void
    const waiting = new Promise<void>(resolve => { release = resolve })
    vi.spyOn(crypto.subtle, 'encrypt').mockImplementationOnce(async (...args) => { await waiting; return encrypt(...args) })
    const delayed = saveLocalSession(old)
    // Let the old write reach encryption before replacing its current record.
    await vi.waitFor(() => expect(crypto.subtle.encrypt).toHaveBeenCalledOnce())
    await saveLocalSession(fresh)
    release()
    await expect(delayed).rejects.toThrow('cleared')
    expect((await loadLocalSession())?.id).toBe(fresh.id)
  })

  it('logout during a pending authorization response cannot reopen the account', async () => {
    const { login, me } = await fixture()
    await saveLocalSession(login)
    let respond!: (response: Response) => void
    const waiting = new Promise<Response>(resolve => { respond = resolve })
    vi.spyOn(globalThis, 'fetch').mockReturnValue(waiting)
    const pendingID = vi.fn()
    const restoring = restoreAccountSession(undefined, pendingID)
    await vi.waitFor(() => expect(pendingID).toHaveBeenCalledWith(login.id))
    await clearLocalSession(login.id)
    respond(ok(me))
    expect(await restoring).toBeNull()
  })

  it('updates the persisted token after a password rotation', async () => {
    const { login, me } = await fixture()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => ok(me))
    const session = fromAccount(await restoreSignIn(login), SERVER)
    await session.remember?.()
    const expires = new Date(login.expiresAt + 1000)
    await session.rotate?.('synthetic-new-token', expires)
    expect((await loadLocalSession())?.token).toBe('synthetic-new-token')
    expect((await loadLocalSession())?.expiresAt).toBe(expires.getTime())
  })
})
