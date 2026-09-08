// Attachments.
//
// The server streams ciphertext and nothing else: it never held the plaintext
// and could not produce it. What arrives here is exactly the blob the WhatsApp
// CDN served, and this file is the first place in the whole system where an
// attachment exists in the clear.
//
// Over HTTP rather than the websocket, deliberately. A two hundred megabyte
// video framed down the same connection as live messages would stall every
// other frame behind it and sit in memory on both ends; here it caches and
// resumes like any other file.

import type { Bytes } from '../crypto/bytes'
import { toHex } from '../crypto/bytes'
import { decrypt, sha256, type MediaType } from '../crypto/wamedia'
import { endpoint } from './endpoint'
import type * as P from './protocol'
import { uploadAttachment, type UploadRequest } from './upload'

export type MediaState =
  /** The server has the bytes and they opened. */
  | { state: 'ready'; url: string; bytes: number }
  /** Queued or downloading. Coming back later is the right move. */
  | { state: 'pending'; status: string }
  /** The URL expired before the archive reached it. Only the sender can fix that. */
  | { state: 'expired' }
  | { state: 'error'; message: string }

export class MediaFetchError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message)
    this.name = 'MediaFetchError'
  }
}

/**
 * Media fetches and decrypts attachments, caching the object URLs it makes.
 *
 * The cache is bounded and revokes what it evicts. Without that, scrolling a
 * conversation of photographs leaks every one of them for the life of the tab.
 */
export class Media {
  private readonly cache = new Map<string, MediaState>()
  private readonly inFlight = new Map<string, Promise<MediaState>>()
  private readonly downloads = new Set<AbortController>()
  private generation = 0

  constructor(
    private readonly serverURL: string,
    /** An API key or a session token; the endpoint takes either. */
    private readonly token: string,
    private readonly limit = 60,
  ) {}

  peek(uid: string): MediaState | undefined {
    return this.cache.get(uid)
  }

  /**
   * upload puts an attachment on WhatsApp's servers, going out.
   *
   * Here rather than anywhere else because this is the object that already
   * holds the session's credential privately. The alternative was widening
   * credential(), which exists for exactly one caller and says so.
   */
  upload(request: Omit<UploadRequest, 'serverURL' | 'token'>): Promise<P.UploadRef> {
    return uploadAttachment({ ...request, serverURL: this.serverURL, token: this.token })
  }

  /**
   * open downloads and decrypts one attachment.
   *
   * The media key comes from the caller because only the caller can produce it:
   * it is sealed in the message row and this server cannot open it.
   */
  open(message: P.SealedMessage, mediaKey: Bytes): Promise<MediaState> {
    const cached = this.cache.get(message.uid)
    if (cached) return Promise.resolve(cached)
    const running = this.inFlight.get(message.uid)
    if (running) return running

    const generation = this.generation
    const controller = new AbortController()
    this.downloads.add(controller)
    const work = this.fetchAndOpen(message, mediaKey, controller.signal)
      .catch((err): MediaState => ({ state: 'error', message: describe(err) }))
      .then((result): MediaState => {
        // A decoder may finish even after fetch has been aborted. Its object
        // URL must not outlive the device or session that requested it.
        if (generation !== this.generation || controller.signal.aborted) {
          if (result.state === 'ready') URL.revokeObjectURL(result.url)
          return { state: 'error', message: 'o carregamento foi cancelado' }
        }
        this.remember(message.uid, result)
        return result
      })
      .finally(() => {
        this.downloads.delete(controller)
        // release() permits an immediate fresh request for the same UID.
        // An older request finishing now must leave that new request alone.
        if (this.inFlight.get(message.uid) === work) this.inFlight.delete(message.uid)
      })
    this.inFlight.set(message.uid, work)
    return work
  }

  private async fetchAndOpen(message: P.SealedMessage, mediaKey: Bytes, signal: AbortSignal): Promise<MediaState> {
    const media = message.media
    if (!media) return { state: 'error', message: 'esta mensagem não tem anexo' }
    // 'gone' is WhatsApp's signed URL having expired before the archive
    // reached it — a history sync replays months-old messages with the address
    // minted back then. Nothing about it changes until the sender re-uploads,
    // so there is no point downloading.
    if (media.download_status === 'gone') return { state: 'expired' }

    const response = await fetch(this.endpoint(message.uid), {
      headers: { Authorization: `Bearer ${this.token}` },
      cache: 'default',
      signal,
    })
    signal.throwIfAborted()

    if (response.status === 409) {
      // Distinct from missing on purpose: the attachment exists and is not
      // ready, so the caller should come back rather than give up.
      return { state: 'pending', status: response.headers.get('X-Media-Status') ?? 'pendente' }
    }
    if (!response.ok) {
      throw new MediaFetchError(await describeResponse(response), response.status)
    }

    const ciphertext = new Uint8Array(await response.arrayBuffer())
    signal.throwIfAborted()

    // The hash covers the ciphertext, so it can be checked before any key is
    // used — a corrupted download is told apart from a wrong key here rather
    // than surfacing later as an indistinguishable MAC failure.
    if (media.file_enc_sha256) {
      const want = media.file_enc_sha256
      const got = await sha256(ciphertext)
      signal.throwIfAborted()
      if (toHex(got) !== toHex(base64ToBytes(want))) {
        throw new Error('o download não confere com o hash que a mensagem carrega')
      }
    }

    const plaintext = await decrypt(ciphertext, mediaKey, mediaTypeOf(media))
    signal.throwIfAborted()
    const blob = new Blob([plaintext as BlobPart], { type: media.mimetype || 'application/octet-stream' })
    return { state: 'ready', url: URL.createObjectURL(blob), bytes: plaintext.length }
  }

  private endpoint(uid: string): string {
    return endpoint(this.serverURL, `/v1/media/${uid}`)
  }

  private remember(uid: string, state: MediaState): void {
    // Only a decrypted blob is worth keeping. A pending one must be asked for
    // again, and caching an error would make a transient failure permanent.
    if (state.state !== 'ready') return
    this.cache.set(uid, state)
    while (this.cache.size > this.limit) {
      const oldest = this.cache.keys().next()
      if (oldest.done) break
      const evicted = this.cache.get(oldest.value)
      this.cache.delete(oldest.value)
      if (evicted?.state === 'ready') URL.revokeObjectURL(evicted.url)
    }
  }

  /** release cancels downloads and revokes every URL on device change or sign-out. */
  release(): void {
    this.generation++
    for (const controller of this.downloads) controller.abort()
    this.downloads.clear()
    this.inFlight.clear()
    for (const state of this.cache.values()) {
      if (state.state === 'ready') URL.revokeObjectURL(state.url)
    }
    this.cache.clear()
  }
}

/**
 * mediaTypeOf picks the HKDF label an attachment was encrypted under.
 *
 * Getting it wrong derives different keys and fails the MAC, with nothing to
 * point at. Several types share a label — a sticker uses the image keys, and
 * the round video note and the voice note ride on video and audio — which is
 * WhatsApp's scheme rather than an approximation made here.
 */
export function mediaTypeOf(media: P.SealedMedia): MediaType {
  switch (media.media_type) {
    case 'image':
    case 'sticker':
    case 'video':
    case 'ptv':
    case 'audio':
    case 'ptt':
    case 'document':
      return media.media_type
    default:
      return 'document'
  }
}

function base64ToBytes(s: string): Bytes {
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

async function describeResponse(response: Response): Promise<string> {
  const text = (await response.text().catch(() => '')).trim()
  if (response.status === 404) return text || 'o anexo não está no armazenamento'
  if (response.status === 401) return 'a credencial foi recusada'
  if (response.status === 503) return 'o armazenamento de objetos não está configurado no servidor'
  return text || `o servidor respondeu ${response.status}`
}

function describe(err: unknown): string {
  if (err instanceof Error) return err.message
  return String(err)
}
