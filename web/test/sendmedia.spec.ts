import { afterEach, describe, expect, it, vi } from 'vitest'
import { WebSocketServer } from 'ws'
import http from 'node:http'
import type { AddressInfo } from 'node:net'

import * as P from '../src/api/protocol'
import { importArchiveKey } from '../src/crypto/hpke'
import { discardFailed, openChat, sendMedia, state, start, stop } from '../src/state/archive'
import { prepare } from '../src/media/prepare'
import { fromPastedKey } from '../src/state/session'

// The real MP4 codec path is exercised in browser media QA; this Node suite
// keeps the browser-only conversion at its boundary and verifies upload/send.
vi.mock('../src/media/videoPrepare', async importOriginal => ({
  ...await importOriginal<typeof import('../src/media/videoPrepare')>(),
  prepareVideo: async (file: File) => ({ blob: file, width: 640, height: 480, seconds: 2, hd: false }),
}))

// Sending an attachment, end to end, minus the parts only a browser has.
//
// Two legs and they fail differently: the bytes go over HTTP and the message
// that points at them over the websocket. So the fake here serves both from one
// origin — which it has to, since the client derives the websocket address from
// the server address and the upload address from the same place.
//
// The thing most worth guarding is the pair of type strings. The `?type=` on
// the upload picks the HKDF label the media key is derived from and the frame's
// `type` picks the protobuf field. Every step answers 200 when they disagree,
// and the attachment simply never opens again — for the recipient or for this
// archive.

const TENANT = '018f3a2b-3333-7000-8000-00000000bbbb'
const DEVICE = '018f3a2b-3333-7000-8000-00000000cccc'
const CHAT = '120363000000000000@g.us'
const OTHER = '5511999999999@s.whatsapp.net'

/** What POST /v1/upload answered with, as Go would render it: base64 strings. */
const UPLOADED = {
  type: 'document',
  url: 'https://mmg.whatsapp.net/d/f/AbC.enc',
  direct_path: '/v/t62.7118-24/1_2_3.enc',
  media_key: 'HyIlKCsuMTQ3Oj1AQ0ZJTE9SVVhbXmFkZ2ptcHN2eXw=',
  file_sha256: 'PkFER0pNUFNWWVxfYmVoa25xdHd6fYCDhomMj5KVmJs=',
  file_enc_sha256: 'XWBjZmlsb3J1eHt+gYSHio2Qk5aZnJ+ipairrrG0t7o=',
  file_length: 12,
} satisfies P.UploadRef

interface Upload {
  query: URLSearchParams
  contentType: string
  authorization: string
  body: Buffer
}

interface Fake {
  url: string
  sent: P.Frame[]
  uploads: Upload[]
  push: (frame: P.Frame) => void
  close: () => Promise<void>
  /** Set to make the upload leg fail, with this status. */
  refuseUpload: { status: number; body: string } | null
  /** Set to make the send frame fail. */
  refuseSend: boolean
  /** Set to answer the send with no uid: sent, and never archived. */
  dropArchive: boolean
  /** Set to hold the upload open, so the bubble can be looked at mid-flight. */
  holdUpload: boolean
  /** Lets a held upload finish. */
  release: () => void
}

const servers: Fake[] = []

async function serve(): Promise<Fake> {
  const sent: P.Frame[] = []
  const uploads: Upload[] = []
  const fake: Partial<Fake> = {
    refuseUpload: null,
    refuseSend: false,
    holdUpload: false,
    dropArchive: false,
  }
  let held: (() => void) | null = null
  // Whether release() was called before the upload arrived to be held.
  //
  // It routinely is, and the race is not obvious: a test releases after
  // watching the optimistic bubble appear, and that bubble is drawn from the
  // file in hand — it does not wait for the request to reach this server. So
  // release() finds nothing to let go, the request lands a moment later and
  // parks forever, and the send never settles. What that looks like from the
  // outside is one socket test in the suite hanging until the deadline, a
  // different one each run, with nothing wrong with any of them.
  let releasedEarly = false

  const server = http.createServer((req, res) => {
    if (req.method !== 'POST' || !req.url?.startsWith('/v1/upload')) {
      res.writeHead(404).end('não é aqui')
      return
    }
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('end', () => {
      uploads.push({
        query: new URL(req.url ?? '', 'http://x').searchParams,
        contentType: req.headers['content-type'] ?? '',
        authorization: req.headers.authorization ?? '',
        body: Buffer.concat(chunks),
      })
      const answer = () => {
        const refusal = fake.refuseUpload
        if (refusal) {
          res.writeHead(refusal.status, { 'Content-Type': 'text/plain' }).end(refusal.body)
          return
        }
        // The real endpoint echoes the kind it encrypted for, so the send can
      // be checked against it.
      const asked = new URL(req.url ?? '', 'http://x').searchParams.get('type')
      res
        .writeHead(200, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ ...UPLOADED, type: asked }))
      }
      // Held rather than answered, when asked to. An upload against a fake on
      // the loopback finishes before the next line of the test runs, so
      // without this there is no moment at which the bubble can be observed
      // mid-flight — and the assertion would be testing the scheduler.
      if (!fake.holdUpload || releasedEarly) {
        releasedEarly = false
        answer()
      } else {
        held = answer
      }
    })
  })

  // One HTTP server for both legs. A bare `new WebSocketServer({ port })`
  // stands up its own, and that one answers every non-upgrade request with 426
  // Upgrade Required — so the upload would fail with a status that means
  // nothing rather than with a body the client can read.
  const wss = new WebSocketServer({ server })
  let live: import('ws').WebSocket | null = null

  wss.on('connection', (socket) => {
    live = socket
    socket.on('message', (data) => {
      const frame = JSON.parse(String(data)) as P.Frame
      sent.push(frame)
      const send = (f: P.Frame) => socket.send(JSON.stringify(f))

      switch (frame.t) {
        case P.TypeHello:
          send({
            t: P.TypeWelcome,
            r: frame.r,
            p: { version: P.VERSION, tenant_id: TENANT, features: [], server_ts: 0 },
          })
          break
        case P.TypeDevicesList:
          send({
            t: P.TypeDevices,
            r: frame.r,
            p: {
              devices: [
                {
                  id: DEVICE,
                  label: 'test',
                  status: 'online',
                  receipt_mode: 'passive',
                  running: true,
                  created_at: new Date().toISOString(),
                },
              ],
            },
          })
          break
        // Both name lookups answer the same frame: contacts.list is the whole
        // directory at sign-in, contacts.resolve is "who are these particular
        // identifiers" from a row about to be drawn. A fake that answered only
        // the first would leave every resolve hanging until it timed out,
        // which is a slow test rather than a failing one — the worst kind.
        case P.TypeContacts:
        case P.TypeResolve:
          send({ t: P.TypeContactList, r: frame.r, p: { contacts: [] } })
          break
        case P.TypeChatsList:
          send({ t: P.TypeChats, r: frame.r, p: { chats: [] } })
          break
        case P.TypeKeysGet:
          send({ t: P.TypeKeys, r: frame.r, p: { device_id: DEVICE, keys: [] } })
          break
        case P.TypeChatPage:
          send({
            t: P.TypePage,
            r: frame.r,
            p: {
              chat_key: (frame.p as P.ChatPageRequest).chat_key,
              messages: [],
              has_more: false,
            },
          })
          break
        case P.TypeSubscribe:
          send({ t: P.TypeReplayEnd, r: frame.r, p: { last_seq: 0 } })
          break
        case P.TypeMessageGet:
          send({ t: P.TypeError, r: frame.r, p: { code: P.ErrNotFound, message: 'archive unavailable in this fixture' } })
          break
        case P.TypeSendMedia:
          if (fake.refuseSend) {
            send({ t: P.TypeError, r: frame.r, p: { code: 'internal', message: 'o aparelho recusou' } })
            break
          }
          send({
            t: P.TypeSendResult,
            r: frame.r,
            p: {
              id: (frame.p as P.SendMediaRequest).id,
              // Empty when the send reached WhatsApp and the row could not be
              // written. The server reports that as a success, because it is.
              uid: fake.dropArchive ? '' : '018f3a2b-3333-7000-8000-0000000000ee',
              timestamp: new Date().toISOString(),
            },
          })
          break
      }
    })
  })

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address() as AddressInfo

  Object.assign(fake, {
    url: `http://127.0.0.1:${port}`,
    sent,
    uploads,
    push: (frame: P.Frame) => live?.send(JSON.stringify(frame)),
    release: () => {
      const answer = held
      held = null
      if (answer) answer()
      else releasedEarly = true
    },
    close: () =>
      new Promise<void>((resolve) => {
        wss.clients.forEach((c) => c.terminate())
        wss.close(() => server.close(() => resolve()))
      }),
  })
  servers.push(fake as Fake)
  return fake as Fake
}

afterEach(async () => {
  stop()
  while (servers.length) {
    const server = servers.pop()!
    // Any upload deliberately held open is let go first. A failing test would
    // otherwise sit here until the request times out, turning one wrong
    // assertion into a slow suite.
    server.release()
    await server.close()
  }
})

async function openConversation(server: Fake, chat = CHAT) {
  await start(
    fromPastedKey({
      label: 'test',
      serverURL: server.url,
      apiKey: 'k',
      archive: await importArchiveKey(new Uint8Array(32).fill(7) as never),
    }),
  )
  await openChat(chat)
}

function pick(name: string, type: string, contents = 'doze bytes!!'): File {
  return new File([contents], name, { type })
}

function mediaFrames(server: Fake): P.SendMediaRequest[] {
  return server.sent.filter((f) => f.t === P.TypeSendMedia).map((f) => f.p as P.SendMediaRequest)
}

/** The archived row, as it comes back on the live subscription. */
function archived(waID: string, chat = CHAT): P.Frame {
  return {
    t: P.TypeMessage,
    p: {
      uid: '018f3a2b-3333-7000-8000-0000000000ff',
      seq: 42,
      device_id: DEVICE,
      wa_id: waID,
      chat_key: chat,
      ts: new Date().toISOString(),
      is_from_me: true,
      is_group: true,
      kind: 'message',
      type: 'document',
      source: 'live',
      content_key_id: 0,
      media: { media_type: 'document', download_status: 'pending' },
    } satisfies P.SealedMessage,
  }
}

async function waitFor(check: () => boolean): Promise<void> {
  for (let i = 0; i < 300; i++) {
    if (check()) return
    await new Promise((r) => setTimeout(r, 10))
  }
  throw new Error('condition never held')
}

describe('sending an attachment', () => {
  it('clears sending from the ACK even when the live archive event is missed', async () => {
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')
    await waitFor(() => server.sent.some(frame => frame.t === P.TypeMessageGet))
    expect(state.timeline[0].pending).toBeUndefined()
    expect(state.timeline[0].media?.upload).toBeUndefined()
    expect(state.timeline[0].media?.localURL).toBeTruthy()
    expect(mediaFrames(server)).toHaveLength(1)
    expect(server.uploads).toHaveLength(1)
  })

  it('shows it, with the file itself, while it is still uploading', async () => {
    const server = await serve()
    await openConversation(server)
    server.holdUpload = true

    const going = sendMedia(await prepare(pick('contrato.pdf', 'application/pdf'), 'file'), '')
    await waitFor(() => state.timeline.length === 1)

    const line = state.timeline[0]
    expect(line.pending).toBe('sending')
    expect(line.media?.fileName).toBe('contrato.pdf')
    // The preview is the file, not a placeholder: it is in this tab already.
    expect(line.media?.localURL).toBeTruthy()
    // And the bubble can say how far it has gone, which is the whole reason
    // this is a separate field from the download's own 'pending'.
    expect(line.media?.upload).toBeTruthy()

    server.release()
    await going
    // Once it has gone, the progress goes with it rather than sitting at 100%.
    expect(state.timeline[0].media?.upload).toBeUndefined()
  })

  it('reports how much of the file has gone, onto the line on screen', async () => {
    // The bar is drawn from the line the timeline holds, and the progress
    // callback fires from inside the upload — no redraw in between, because
    // rebuilding the conversation sixty times for one file would be absurd.
    // Writing to any object but that one leaves the bar at zero for the whole
    // upload with nothing to explain it.
    const server = await serve()
    await openConversation(server)
    server.holdUpload = true

    const going = sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')
    await waitFor(() => (state.timeline[0]?.media?.upload?.sent ?? 0) > 0)

    const progress = state.timeline[0].media!.upload!
    expect(progress.sent).toBe(progress.total)
    expect(progress.total).toBe(12)

    server.release()
    await going
    expect(state.timeline[0].media?.upload).toBeUndefined()
  })

  it('posts the raw bytes, never a multipart form', async () => {
    // The server pipes the request body straight into WhatsApp without looking
    // at its content type. A FormData would make the boundary lines the
    // attachment's contents — 200 at every step, and an unopenable file.
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')

    expect(server.uploads).toHaveLength(1)
    expect(server.uploads[0].body.toString()).toBe('doze bytes!!')
    expect(server.uploads[0].contentType).toBe('application/octet-stream')
    expect(server.uploads[0].authorization).toBe('Bearer k')
  })

  it('passes the same kind to the upload and to the frame', async () => {
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')

    const uploaded = server.uploads[0].query.get('type')
    expect(uploaded).toBe('document')
    expect(mediaFrames(server)[0].type).toBe(uploaded)
  })

  it('keeps the query the upload requires', async () => {
    // endpoint() clears the query, so building the URL by appending to the path
    // loses both parameters and the server answers "device is required" —
    // which reads like a broken device picker.
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')

    expect(server.uploads[0].query.get('device')).toBe(DEVICE)
  })

  it('carries the kind the upload encrypted for back into the frame', async () => {
    // The server refuses a send whose type disagrees with its upload, because
    // the two pick different encryption keys. Losing this field on the way
    // through would turn that guard off silently.
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')

    const frame = mediaFrames(server)[0]
    expect(frame.upload.type).toBe('document')
    expect(frame.upload.type).toBe(frame.type)
  })

  it('forwards the upload reference untouched', async () => {
    // Go renders []byte as base64 strings. Decoding these and re-serialising
    // them produces JSON the server cannot read, reported back as "upload is
    // required" — which points at the wrong thing entirely.
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')

    expect(mediaFrames(server)[0].upload).toEqual(UPLOADED)
    expect(typeof mediaFrames(server)[0].upload.media_key).toBe('string')
  })

  it('carries the file name, which a document has no download without', async () => {
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('contrato.pdf', 'application/pdf'), 'file'), '')

    expect(mediaFrames(server)[0].filename).toBe('contrato.pdf')
    expect(mediaFrames(server)[0].mimetype).toBe('application/pdf')
  })

  it('mints the id before uploading, so the archived row can be recognised', async () => {
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')

    const id = mediaFrames(server)[0].id
    expect(id).toMatch(/^[0-9A-F]{32}$/)
    expect(state.timeline[0].waID).toBe(id)
  })

  it('does not show the attachment twice when the archived row arrives', async () => {
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')

    const id = state.timeline[0].waID
    server.push(archived(id))

    await waitFor(() => state.timeline.length === 1 && !state.timeline[0].pending)
    expect(state.timeline).toHaveLength(1)
  })

  it('keeps showing the local copy after the archived row replaces the line', async () => {
    // The row arrives with download_status 'pending': the server has not
    // fetched the attachment back from WhatsApp's CDN yet, and until it does
    // /v1/media answers 409. Dropping the local copy here means watching a
    // photograph you just sent turn into a placeholder.
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('foto.png', 'image/png'), 'file'), '')

    const before = state.timeline[0].media?.localURL
    server.push(archived(state.timeline[0].waID))
    await waitFor(() => !state.timeline[0]?.pending)

    expect(state.timeline[0].media?.localURL).toBe(before)
  })

  it('says so when the upload was refused, and keeps the attachment on screen', async () => {
    const server = await serve()
    await openConversation(server)
    server.refuseUpload = { status: 409, body: '' }

    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')

    expect(state.timeline).toHaveLength(1)
    expect(state.timeline[0].pending).toBe('failed')
    expect(state.timeline[0].failure).toMatch(/não está conectado/)
    // And no frame was sent: there is nothing to point at.
    expect(mediaFrames(server)).toHaveLength(0)
  })

  it('does not mistake a refused upload for one still arriving', async () => {
    // 409 means opposite things on the two media endpoints: downloading it
    // means "come back later", uploading it means the device is offline and
    // nothing will change. Treating this one as pending is a spinner that
    // never resolves.
    const server = await serve()
    await openConversation(server)
    server.refuseUpload = { status: 409, body: '' }
    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')

    expect(state.timeline[0].media?.upload).toBeUndefined()
  })

  it('says so when the message itself was refused', async () => {
    const server = await serve()
    await openConversation(server)
    server.refuseSend = true

    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')

    expect(state.timeline[0].pending).toBe('failed')
    expect(state.timeline[0].failure).toMatch(/recusou/)
  })

  it('never sends a caption on a voice note', async () => {
    // The server refuses one outright rather than dropping it, because a
    // caption that vanishes looks like a delivery failure. The composer
    // refuses first; this is the second lock.
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('recado.ogg', 'audio/ogg'), 'voice'), 'escuta isso')

    expect(mediaFrames(server)[0].caption).toBeUndefined()
    expect(mediaFrames(server)[0].type).toBe('ptt')
  })

  it('sends a caption on a photo', async () => {
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('f.jpg', 'image/jpeg'), 'photo'), '  olha isso  ')

    expect(mediaFrames(server)[0].caption).toBe('olha isso')
  })

  it('marks a video as a GIF only when that is what was chosen', async () => {
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('m.mp4', 'video/mp4'), 'gif'), '')
    await sendMedia(await prepare(pick('m.mp4', 'video/mp4'), 'video'), '')

    expect(mediaFrames(server)[0].is_gif).toBe(true)
    expect(mediaFrames(server)[1].is_gif).toBeUndefined()
  })

  it('carries the forwarded flag, and floors the score the server needs', async () => {
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '', undefined, {
      forwarded: true,
      score: 0,
      viewOnce: false,
    })

    expect(mediaFrames(server)[0].forwarded).toBe(true)
    expect(mediaFrames(server)[0].forwarding_score).toBe(1)
    expect(state.timeline[0].forwarded).toBe(true)
  })

  it('does not offer view-once on a document, where it is half-expressible', async () => {
    // The disappearing wrapper is applied for any type but the inner flag is
    // set only for image, video and audio — and a message marked on one and
    // not the other is what made clients disagree in the first place.
    const server = await serve()
    await openConversation(server)
    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '', undefined, {
      forwarded: false,
      score: 0,
      viewOnce: true,
    })

    expect(mediaFrames(server)[0].view_once).toBeUndefined()
  })

  it('lets a failed attachment be thrown away', async () => {
    // A line that never went is still holding the whole file. Without a way out
    // of it the only remedy is reloading the tab.
    const server = await serve()
    await openConversation(server)
    server.refuseUpload = { status: 400, body: 'não deu' }
    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')
    expect(state.timeline[0].pending).toBe('failed')

    await discardFailed(state.timeline[0].waID)
    expect(state.timeline).toHaveLength(0)
  })

  it('says when a message went but was never archived', async () => {
    // The server answers with no uid: it reached WhatsApp and the row could not
    // be written. Nothing will ever arrive to reap this line, so leaving it at
    // "enviando…" would read as a message that never went — the opposite of
    // what happened.
    const server = await serve()
    await openConversation(server)
    server.dropArchive = true

    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')

    expect(state.timeline[0].pending).toBe('unarchived')
    expect(state.timeline[0].media?.upload).toBeUndefined()
  })

  it('does not follow the reader into another conversation', async () => {
    const server = await serve()
    await openConversation(server)
    server.refuseUpload = { status: 502, body: 'o whatsapp recusou' }
    await sendMedia(await prepare(pick('nota.txt', 'text/plain'), 'file'), '')
    expect(state.timeline).toHaveLength(1)

    await openChat(OTHER)
    // An upload in flight rendering into a chat it has nothing to do with is
    // how somebody sends a photograph to the wrong person.
    expect(state.timeline).toHaveLength(0)

    await openChat(CHAT)
    expect(state.timeline).toHaveLength(1)
  })
})
