import { readFileSync } from 'node:fs'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { Media } from '../src/api/media'
import type { SealedMessage } from '../src/api/protocol'
import { fromBase64 } from '../src/crypto/bytes'

const vectors = JSON.parse(readFileSync(new URL('../../internal/crypto/wamedia/testdata/vectors.json', import.meta.url), 'utf8'))
const vector: { media_key: string; plaintext: string; enc: string } = vectors.vectors[0]
const key = fromBase64(vector.media_key)
const message: SealedMessage = {
  uid: '018f3a2b-2222-7000-8000-00000000aaaa', seq: 1,
  device_id: '018f3a2b-2222-7000-8000-00000000bbbb', wa_id: 'fixture-media',
  chat_key: '1111@s.whatsapp.net', kind: 'message', type: 'image', is_from_me: false, source: 'live',
  media: { media_type: 'image', download_status: 'ready' },
}
const clients: Media[] = []

function client(): Media {
  const media = new Media('https://fixture.invalid', 'fixture-token')
  clients.push(media)
  return media
}

function response(): Response {
  return new Response(fromBase64(vector.enc))
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

afterEach(() => {
  for (const media of clients.splice(0)) media.release()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('attachment download lifetime', () => {
  it('shares an active download, decrypts its real ciphertext and revokes its cache on release', async () => {
    const fetcher = vi.fn().mockResolvedValue(response())
    vi.stubGlobal('fetch', fetcher)
    const revoke = vi.spyOn(URL, 'revokeObjectURL')
    const media = client()
    const opening = media.open(message, key)
    expect(media.open(message, key)).toBe(opening)
    const result = await opening
    expect(result.state).toBe('ready')
    if (result.state !== 'ready') throw new Error('fixture failed to decrypt')
    expect(result.bytes).toBe(fromBase64(vector.plaintext).length)
    expect(await media.open(message, key)).toEqual(result)
    expect(fetcher).toHaveBeenCalledOnce()
    media.release()
    expect(media.peek(message.uid)).toBeUndefined()
    expect(revoke).toHaveBeenCalledWith(result.url)
  })

  it('aborts the previous device download without replacing or removing a fresh request for the same message', async () => {
    const previous = deferred<Response>()
    const fresh = deferred<Response>()
    const signals: AbortSignal[] = []
    const fetcher = vi.fn((_url: unknown, init?: RequestInit) => {
      signals.push(init!.signal as AbortSignal)
      // Deliberately let the old fetch resolve after abort, as cached responses
      // and decryptions can finish after the browser has cancelled a request.
      return signals.length === 1 ? previous.promise : fresh.promise
    })
    vi.stubGlobal('fetch', fetcher)
    const media = client()
    const previousWork = media.open(message, key)
    media.release()
    expect(signals[0]!.aborted).toBe(true)
    const freshWork = media.open(message, key)
    expect(signals[1]!.aborted).toBe(false)
    previous.resolve(response())
    expect(await previousWork).toEqual({ state: 'error', message: 'o carregamento foi cancelado' })
    expect(media.peek(message.uid)).toBeUndefined()
    expect(media.open(message, key)).toBe(freshWork)
    fresh.resolve(response())
    const result = await freshWork
    expect(result.state).toBe('ready')
    expect(media.peek(message.uid)).toEqual(result)
    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it('revokes a decoded URL that completes at the same time as sign-out', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response()))
    const media = client()
    const create = URL.createObjectURL.bind(URL)
    const revoke = vi.spyOn(URL, 'revokeObjectURL')
    let lateURL = ''
    vi.spyOn(URL, 'createObjectURL').mockImplementationOnce((blob) => {
      lateURL = create(blob)
      media.release()
      return lateURL
    })
    expect(await media.open(message, key)).toEqual({ state: 'error', message: 'o carregamento foi cancelado' })
    expect(revoke).toHaveBeenCalledWith(lateURL)
    expect(media.peek(message.uid)).toBeUndefined()
  })
})
