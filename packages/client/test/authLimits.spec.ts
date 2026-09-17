import { afterEach, expect, it, vi } from 'vitest'
import { withDeviceKey } from '../src/api/auth.js'

const input = { serverURL: 'https://example.test', token: 'synthetic-secret', email: 'reader@example.test', password: 'synthetic-password', deviceID: '018f3a2b-2222-7000-8000-00000000dddd' }
afterEach(() => vi.unstubAllGlobals())

it('refuses incomplete or invalid local cost limits before any network or key operation', async () => {
  const fetcher = vi.fn(), use = vi.fn()
  vi.stubGlobal('fetch', fetcher)
  for (const maxKDF of [{}, { m: 131072, t: 5 }, { m: 131072, t: 0, p: 4 }, { m: Infinity, t: 5, p: 4 }]) {
    await expect(withDeviceKey({ ...input, maxKDF: maxKDF as { m: number; t: number; p: number } }, use)).rejects.toMatchObject({ code: 'invalid_kdf_limits' })
  }
  await expect(withDeviceKey({ ...input, maxAuthResponseBytes: 0 }, use)).rejects.toMatchObject({ code: 'invalid_response_limit' })
  expect(fetcher).not.toHaveBeenCalled(); expect(use).not.toHaveBeenCalled()
})

it('refuses an incomplete challenge before derivation and keeps the caller cancellation signal', async () => {
  const signal = new AbortController().signal, use = vi.fn()
  const fetcher = vi.fn(async () => new Response(JSON.stringify({ salt: '', params: { alg: 'argon2id', m: 65536, t: 3 } })))
  vi.stubGlobal('fetch', fetcher)
  await expect(withDeviceKey({ ...input, signal, maxKDF: { m: 131072, t: 5, p: 4 }, maxAuthResponseBytes: 1024 }, use)).rejects.toMatchObject({ code: 'kdf_cost_exceeded' })
  expect(fetcher).toHaveBeenCalledTimes(1)
  expect(fetcher.mock.calls[0][1]).toMatchObject({ signal })
  expect(use).not.toHaveBeenCalled()
})

it('bounds streamed auth bodies even without a Content-Length header', async () => {
  const cancel = vi.fn(), use = vi.fn()
  vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(17)); controller.enqueue(new Uint8Array(17)) }, cancel,
  }))))
  await expect(withDeviceKey({ ...input, maxAuthResponseBytes: 32 }, use)).rejects.toMatchObject({ code: 'response_too_large' })
  expect(cancel).toHaveBeenCalledOnce(); expect(use).not.toHaveBeenCalled()
})
