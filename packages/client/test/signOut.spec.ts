import { afterEach, expect, it, vi } from 'vitest'
import { authRequest, signOut } from '../src/api/auth.js'

const server = 'https://example.test', logout = 'https://example.test/v1/auth/logout'
afterEach(() => vi.unstubAllGlobals())

function stubLogout() {
  const fetcher = vi.fn(async (_url: string, _init: RequestInit) => new Response(null, { status: 204 }))
  vi.stubGlobal('fetch', fetcher)
  return fetcher
}

it('keeps the boolean form: this session alone, or every related one, never with keepalive', async () => {
  const fetcher = stubLogout()
  await signOut(server, 'synthetic-token')
  await signOut(server, 'synthetic-token', true)
  await signOut(server, 'synthetic-token', false)
  expect(fetcher.mock.calls.map(([url, init]) => [url, init.body, 'keepalive' in init])).toEqual([
    [logout, '{}', false], [logout, '{"all_related":true}', false], [logout, '{}', false],
  ])
  expect(fetcher.mock.calls[0][1]).toMatchObject({
    method: 'POST', cache: 'no-store', redirect: 'error',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer synthetic-token' },
  })
})

it('sends a keepalive logout for a page that is leaving, dispatched before the caller could await it', () => {
  const fetcher = stubLogout()
  void signOut(server, 'minted-token', { keepalive: true })
  expect(fetcher).toHaveBeenCalledOnce()
  expect(fetcher.mock.calls[0][0]).toBe(logout)
  expect(fetcher.mock.calls[0][1]).toMatchObject({
    method: 'POST', body: '{}', keepalive: true, cache: 'no-store', redirect: 'error',
    headers: { Authorization: 'Bearer minted-token' },
  })
})

it('takes allRelated and keepalive apart in the options form', async () => {
  const fetcher = stubLogout()
  await signOut(server, 'synthetic-token', { allRelated: true, keepalive: true })
  await signOut(server, 'synthetic-token', { allRelated: true })
  await signOut(server, 'synthetic-token', {})
  expect(fetcher.mock.calls.map(([, init]) => [init.body, init.keepalive])).toEqual([
    ['{"all_related":true}', true], ['{"all_related":true}', undefined], ['{}', undefined],
  ])
})

it('stays best effort with keepalive: a failed or refused logout resolves', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('network') }))
  await expect(signOut(server, 'synthetic-token', { keepalive: true })).resolves.toBeUndefined()
  vi.stubGlobal('fetch', vi.fn(async () => new Response('{"code":"unauthorized"}', { status: 401 })))
  await expect(signOut(server, 'synthetic-token', { keepalive: true })).resolves.toBeUndefined()
})

it('leaves authRequest as its callers use it: a signal in fifth place, and no keepalive unless asked', async () => {
  const fetcher = stubLogout(), signal = new AbortController().signal
  await authRequest(server, '/v1/auth/logout', {}, 'synthetic-token', signal)
  await authRequest(server, '/v1/auth/logout', {}, 'synthetic-token', undefined, undefined, true)
  expect(fetcher.mock.calls[0][1]).toMatchObject({ signal })
  expect('keepalive' in fetcher.mock.calls[0][1]).toBe(false)
  expect(fetcher.mock.calls[1][1]).toMatchObject({ keepalive: true })
  expect('signal' in fetcher.mock.calls[1][1]).toBe(false)
})
