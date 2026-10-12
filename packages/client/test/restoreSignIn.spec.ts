// restoreSignIn into a workspace other than the sign-in's makes a token of
// that workspace's. The caller hears of it as soon as the server answers, so
// that a page leaving meanwhile can sign it out; and a restore that does not
// use it after all signs it out itself, since nobody else holds it.
import { afterEach, expect, it, vi } from 'vitest'
import { AuthError, restoreSignIn } from '../src/api/auth.js'
import { toBase64 } from '../src/crypto/bytes.js'
import { importArchiveKey } from '../src/crypto/hpke.js'
import type { BrowserLogin } from '../src/session.js'

const SERVER = 'https://example.test'
const USER = '018f3a2b-2222-7000-8000-00000000eeee'
const BASE = '018f3a2b-2222-7000-8000-0000000000aa', OTHER = '018f3a2b-2222-7000-8000-0000000000bb'
const SIGN_IN = 'synthetic-sign-in-token', MINTED = 'synthetic-workspace-token'
afterEach(() => vi.unstubAllGlobals())

interface Call { path: string; token: string; body: string; at: number }

/** A sign-in in BASE, and a server whose second /me (the workspace token's) answers as answer says. */
async function serve(answer: (calls: Call[]) => Response | Promise<Response> | 'ok', publicKey?: Uint8Array) {
  const accountKey = await importArchiveKey(new Uint8Array(32).fill(1))
  const login: BrowserLogin = { id: 'login', realm: SERVER, serverURL: SERVER, token: SIGN_IN, expiresAt: Date.now() + 3_600_000, userID: USER, tenantID: BASE, accountKey }
  const user = (tenant: string) => ({ id: USER, tenant_id: tenant, email: 'owner@example.test', role: 'owner', wrapped_usk: '', public_key: toBase64(publicKey ?? accountKey.publicRaw), has_recovery: true })
  const calls: Call[] = []
  const heard: { token: string; calls: number }[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
    const path = new URL(url).pathname
    const token = ((init.headers as Record<string, string>).Authorization ?? '').replace('Bearer ', '')
    calls.push({ path, token, body: String(init.body ?? ''), at: calls.length })
    if (path === '/v1/auth/logout') return new Response(null, { status: 204 })
    if (path === '/v1/auth/workspaces/session') return Response.json({ token: MINTED, expires_at: new Date(login.expiresAt).toISOString(), user: user(OTHER) })
    if (path === '/v1/auth/me' && token === SIGN_IN) return Response.json({ user: { ...user(BASE), public_key: toBase64(accountKey.publicRaw) }, grants: [] })
    const reply = await answer(calls)
    return reply === 'ok' ? Response.json({ user: user(OTHER), grants: [] }) : reply
  }))
  const minted = (token: string) => { heard.push({ token, calls: calls.length }) }
  const logouts = () => calls.filter(call => call.path === '/v1/auth/logout').map(call => `${call.token} ${call.body}`)
  return { login, calls, heard, minted, logouts }
}

it('says which token it made as soon as the server answers, before the workspace\'s /me, and keeps it once restored', async () => {
  const { login, calls, heard, minted, logouts } = await serve(() => 'ok')
  const signed = await restoreSignIn(login, OTHER, minted)
  expect([signed.token, signed.tenantID]).toEqual([MINTED, OTHER])
  expect(calls.map(call => `${call.path} ${call.token}`)).toEqual([`/v1/auth/me ${SIGN_IN}`, `/v1/auth/workspaces/session ${SIGN_IN}`, `/v1/auth/me ${MINTED}`])
  // Heard of after the selection, before the /me that follows it.
  expect(heard).toEqual([{ token: MINTED, calls: 2 }])
  expect(logouts()).toEqual([])
  // The sign-in's own workspace makes nothing, and says nothing.
  const again = await serve(() => 'ok')
  expect((await restoreSignIn(again.login, BASE, again.minted)).token).toBe(SIGN_IN)
  expect([again.heard, again.logouts()]).toEqual([[], []])
})

it('signs out the token it made when the workspace\'s /me fails, and passes the failure on', async () => {
  for (const failure of [() => new Response(JSON.stringify({ code: 'unavailable' }), { status: 503 }), () => { throw new TypeError('network') }]) {
    const { login, heard, minted, logouts } = await serve(failure)
    await expect(restoreSignIn(login, OTHER, minted)).rejects.toBeDefined()
    expect(heard.map(entry => entry.token)).toEqual([MINTED])
    // This token alone, never the sign-in's, and never its family.
    expect(logouts()).toEqual([`${MINTED} {}`])
  }
})

it('signs out the token it made when its /me refuses it, and opens the sign-in\'s own workspace with the notice', async () => {
  const { login, minted, logouts } = await serve(() => new Response(JSON.stringify({ code: 'not_authorized' }), { status: 403 }))
  const signed = await restoreSignIn(login, OTHER, minted)
  expect([signed.token, signed.tenantID, signed.notice]).toEqual([SIGN_IN, BASE, expect.stringContaining('espaço')])
  expect(logouts()).toEqual([`${MINTED} {}`])
})

it('signs out the token it made when the session it opens is not this sign-in\'s account', async () => {
  const { login, minted, logouts } = await serve(() => 'ok', new Uint8Array(32).fill(9))
  await expect(restoreSignIn(login, OTHER, minted)).rejects.toBeInstanceOf(AuthError)
  expect(logouts()).toEqual([`${MINTED} {}`])
})
