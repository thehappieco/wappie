import { t } from '../ui/i18n'
// Putting an attachment on WhatsApp's servers.
//
// Over HTTP and not the websocket, for the same reason downloads are: a two
// hundred megabyte video framed down the connection that carries live messages
// would stall every other frame behind it and sit in memory on both ends.
//
// This is also the one direction where plaintext passes through our server.
// WhatsApp's upload takes cleartext and encrypts on the way out, and its
// exported API offers no way to hand it ciphertext somebody else produced — so
// an attachment being *sent* is exposed exactly as outbound text already is.
// Receiving has no such compromise: it arrives encrypted and is stored without
// ever being opened. Worth stating rather than papering over.

import { endpoint } from './endpoint'
import type * as P from './protocol'

/** Progress is how far a body has gone. Only the XHR path can report it. */
export interface Progress {
  sent: number
  total: number
}

export interface UploadRequest {
  serverURL: string
  /** An API key or a session token; the endpoint takes either. */
  token: string
  deviceID: string
  /**
   * kind is the `?type=` and MUST be the same string sent as the frame's type.
   *
   * It selects whatsmeow's MediaType, which selects the HKDF label the media
   * key is derived from. Upload as one kind and send as another and every step
   * answers 200 while the recipient — and this archive — get a file that will
   * never open.
   */
  kind: string
  blob: Blob
  onProgress?: (progress: Progress) => void
  signal?: AbortSignal
}

export class UploadError extends Error {
  constructor(
    message: string,
    readonly status: number,
    /** Whether trying the same file again could ever work. */
    readonly retryable: boolean,
  ) {
    super(message)
    this.name = 'UploadError'
  }
}

/**
 * uploadAttachment posts the bytes and returns where they landed.
 *
 * The answer is forwarded into the send frame untouched. Go renders []byte as
 * base64 strings, so decoding media_key or file_enc_sha256 here and
 * re-serialising them produces JSON the server cannot read — reported back as
 * "upload is required", which points at the wrong thing entirely. Nothing in
 * this client looks inside those fields.
 */
export async function uploadAttachment(request: UploadRequest): Promise<P.UploadRef> {
  const url = uploadURL(request.serverURL, request.deviceID, request.kind)
  const body = await (canReportProgress() ? viaXHR(url, request) : viaFetch(url, request))
  return JSON.parse(body) as P.UploadRef
}

/**
 * uploadURL builds the address, with the query the server requires.
 *
 * Through endpoint()'s params rather than by appending to the path: endpoint
 * clears the query, so a hand-built "/v1/upload?device=..." loses both
 * parameters and the server answers "device is required" — which reads like a
 * broken device picker rather than a broken URL.
 */
export function uploadURL(serverURL: string, deviceID: string, kind: string): string {
  return endpoint(serverURL, '/v1/upload', { device: deviceID, type: kind })
}

/**
 * describeUploadFailure turns a status into something worth reading.
 *
 * Deliberately not the download's mapping. The same 409 means opposite things
 * on the two endpoints: downloading, it means the attachment exists and is not
 * ready yet, so come back; uploading, it means the device is not connected and
 * nothing will change until it is. Reusing one for the other turns a hard
 * failure into a spinner that never resolves.
 */
export function describeUploadFailure(status: number, detail: string): UploadError {
  const text = detail.trim()
  switch (status) {
    case 400:
      return new UploadError(text || t('o servidor recusou o pedido'), status, false)
    case 401:
      return new UploadError(t('a credencial foi recusada; entre de novo'), status, false)
    case 404:
      return new UploadError(t('esse aparelho não existe mais'), status, false)
    case 409:
      return new UploadError(t('esse aparelho não está conectado ao WhatsApp agora'), status, true)
    case 413:
      return new UploadError(text || t('o arquivo passa do limite deste servidor'), status, false)
    case 502:
      return new UploadError(t('o WhatsApp recusou o arquivo: ') + (text || t('sem detalhe')), status, true)
    default:
      return new UploadError(text || t('o servidor respondeu {v0}', { v0: status }), status, status >= 500)
  }
}

function canReportProgress(): boolean {
  return typeof XMLHttpRequest === 'function'
}

/**
 * viaXHR uploads with progress.
 *
 * fetch cannot report how much of a request body has gone out — the browsers
 * that support a streaming request body are not the browsers this has to run
 * in — and an attachment large enough to be worth a progress bar is exactly
 * the one where its absence reads as the app having frozen.
 */
function viaXHR(url: string, request: UploadRequest): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', url, true)
    xhr.setRequestHeader('Authorization', `Bearer ${request.token}`)
    xhr.setRequestHeader('Content-Type', 'application/octet-stream')
    xhr.responseType = 'text'

    if (request.onProgress) {
      xhr.upload.onprogress = (event) => {
        request.onProgress?.({
          sent: event.loaded,
          total: event.lengthComputable ? event.total : request.blob.size,
        })
      }
    }
    xhr.onload = () => {
      if (xhr.status === 200) {
        resolve(xhr.responseText)
        return
      }
      reject(describeUploadFailure(xhr.status, xhr.responseText ?? ''))
    }
    xhr.onerror = () => reject(new UploadError(t('a conexão caiu durante o envio'), 0, true))
    xhr.ontimeout = () => reject(new UploadError(t('o envio demorou demais'), 0, true))
    xhr.onabort = () => reject(new UploadError(t('envio cancelado'), 0, false))

    request.signal?.addEventListener('abort', () => xhr.abort(), { once: true })
    // The body is the file itself. A multipart form would be uploaded as the
    // attachment: the server pipes the request body straight through without
    // looking at its content type, so the boundary lines would become the
    // file's contents and the recipient would get something unopenable, with
    // a 200 at every step.
    xhr.send(request.blob)
  })
}

async function viaFetch(url: string, request: UploadRequest): Promise<string> {
  const streaming = counted(request)
  try {
    return await post(url, request, streaming ?? request.blob, streaming !== null)
  } catch (err) {
    // A streamed request body is refused outright by some implementations, and
    // refused *before* anything is sent — so falling back to the whole blob is
    // safe here and would not be after a partial upload.
    if (streaming && err instanceof TypeError) {
      return await post(url, request, request.blob, false)
    }
    throw err
  }
}

async function post(
  url: string,
  request: UploadRequest,
  body: BodyInit,
  streaming: boolean,
): Promise<string> {
  const init: RequestInit & { duplex?: 'half' } = {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${request.token}`,
      'Content-Type': 'application/octet-stream',
    },
    body,
    signal: request.signal,
  }
  // Required whenever the body is a stream: it says the request will not read
  // the response until it has finished sending.
  if (streaming) init.duplex = 'half'

  const response = await fetch(url, init)
  const text = await response.text()
  if (!response.ok) throw describeUploadFailure(response.status, text)
  return text
}

/**
 * counted wraps the file in a stream that reports how much has gone.
 *
 * Only reached when there is no XMLHttpRequest, which in a real browser there
 * always is — Safari included. So this is the path the tests take, and the one
 * a future runtime without XHR would take, and it means the progress the bubble
 * draws is exercised rather than assumed.
 */
function counted(request: UploadRequest): ReadableStream<Uint8Array> | null {
  const report = request.onProgress
  if (!report) return null
  if (typeof ReadableStream !== 'function' || typeof TransformStream !== 'function') return null
  if (typeof request.blob.stream !== 'function') return null

  const total = request.blob.size
  let sent = 0
  return request.blob.stream().pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        sent += chunk.byteLength
        report({ sent, total })
        controller.enqueue(chunk)
      },
    }),
  )
}
