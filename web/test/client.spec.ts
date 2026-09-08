import { afterEach, describe, expect, it } from 'vitest'
import { WebSocketServer, type WebSocket as ServerSocket } from 'ws'
import type { AddressInfo } from 'node:net'

import { Connection } from '../src/api/client'
import * as P from '../src/api/protocol'

// The client multiplexes one socket between request/response calls and a push
// stream, and the interesting failures are all about frames going to the wrong
// place: a reply routed to the stream and lost, or a live message swallowed by
// a request that happened to be waiting. Both are silent — the caller just
// hangs, or a message never appears — so they are worth a real socket.

interface Fake {
  url: string
  close: () => Promise<void>
  /** The frames the server received, in order. */
  received: P.Frame[]
  /** Pushes a frame at whichever client is connected. */
  push: (frame: P.Frame) => void
}

const servers: Fake[] = []

/**
 * serve stands up a websocket that answers a hello and then hands every
 * subsequent frame to `answer`.
 */
async function serve(answer: (frame: P.Frame, send: (f: P.Frame) => void) => void): Promise<Fake> {
  const wss = new WebSocketServer({ port: 0 })
  const received: P.Frame[] = []
  let live: ServerSocket | null = null

  wss.on('connection', (socket) => {
    live = socket
    socket.on('message', (data) => {
      const frame = JSON.parse(String(data)) as P.Frame
      received.push(frame)
      const send = (f: P.Frame) => socket.send(JSON.stringify(f))

      if (frame.t === P.TypeHello) {
        const hello = frame.p as P.Hello
        if (hello.api_key === 'wrong') {
          send({ t: P.TypeError, r: frame.r, p: { code: P.ErrUnauthorized, message: 'invalid api key' } })
          return
        }
        if (hello.version !== P.VERSION) {
          send({ t: P.TypeError, r: frame.r, p: { code: P.ErrVersionMismatch, message: 'version' } })
          return
        }
        send({
          t: P.TypeWelcome,
          r: frame.r,
          p: { version: P.VERSION, tenant_id: 't', features: [], server_ts: 0 },
        })
        return
      }
      answer(frame, send)
    })
  })

  await new Promise<void>((resolve) => wss.on('listening', resolve))
  const { port } = wss.address() as AddressInfo

  const fake: Fake = {
    url: `http://127.0.0.1:${port}`,
    received,
    push: (frame) => live?.send(JSON.stringify(frame)),
    close: () =>
      new Promise<void>((resolve) => {
        wss.clients.forEach((c) => c.terminate())
        wss.close(() => resolve())
      }),
  }
  servers.push(fake)
  return fake
}

afterEach(async () => {
  while (servers.length) await servers.pop()!.close()
})

describe('the handshake', () => {
  it('sends hello first and waits for welcome', async () => {
    const server = await serve(() => {})
    const conn = await Connection.connect({ serverURL: server.url, credential: { kind: 'api_key', token: 'k' } })

    expect(server.received[0].t).toBe(P.TypeHello)
    expect((server.received[0].p as P.Hello).version).toBe(P.VERSION)
    expect(conn.welcome.tenant_id).toBe('t')
    conn.close()
  })

  it('reports a rejected key rather than hanging', async () => {
    const server = await serve(() => {})
    await expect(
      Connection.connect({ serverURL: server.url, credential: { kind: 'api_key', token: 'wrong' } }),
    ).rejects.toMatchObject({ code: P.ErrUnauthorized })
  })

  it('does not call a server that is down a rejected key', async () => {
    // The two need different codes because a caller retries one and must not
    // retry the other. Labelling every pre-welcome failure as unauthorized made
    // a restarting server look like a bad key, and the client gave up instead
    // of waiting four seconds.
    const server = await serve(() => {})
    const url = server.url
    await server.close()

    await expect(Connection.connect({ serverURL: url, credential: { kind: 'api_key', token: 'k' } })).rejects.toMatchObject({
      code: P.ErrInternal,
    })
  })
})

describe('requests and pushes on one socket', () => {
  it('routes a reply to the caller that asked for it', async () => {
    const server = await serve((frame, send) => {
      if (frame.t === P.TypeKeysGet) {
        send({ t: P.TypeKeys, r: frame.r, p: { keys: [{ id: 7, sealed: 'AA==' }] } })
      }
    })
    const conn = await Connection.connect({ serverURL: server.url, credential: { kind: 'api_key', token: 'k' } })

    const keys = await conn.request<P.Keys>(P.TypeKeysGet, { ids: [7] }, P.TypeKeys)
    expect(keys.keys[0].id).toBe(7)
    conn.close()
  })

  it('turns an error frame into a rejection, not a timeout', async () => {
    const server = await serve((frame, send) => {
      send({ t: P.TypeError, r: frame.r, p: { code: P.ErrNotFound, message: 'no such device' } })
    })
    const conn = await Connection.connect({ serverURL: server.url, credential: { kind: 'api_key', token: 'k' } })

    await expect(
      conn.request(P.TypeChatsList, { device_id: 'x' }, P.TypeChats),
    ).rejects.toMatchObject({ code: P.ErrNotFound })
    conn.close()
  })

  it('does not lose a push that arrives while a request is waiting', async () => {
    // The bug this prevents: a reader that consumes frames on behalf of one
    // request swallows the live traffic that arrives in the meantime, and the
    // stream silently stops.
    const pushed: P.Frame[] = []
    const server = await serve((frame, send) => {
      if (frame.t !== P.TypeKeysGet) return
      send({ t: P.TypeMessage, p: { uid: 'live-1' } })
      send({ t: P.TypeKeys, r: frame.r, p: { keys: [] } })
      send({ t: P.TypeMessage, p: { uid: 'live-2' } })
    })
    const conn = await Connection.connect({
      serverURL: server.url,
      credential: { kind: 'api_key', token: 'k' },
      onFrame: (f) => pushed.push(f),
    })

    await conn.request<P.Keys>(P.TypeKeysGet, { ids: [1] }, P.TypeKeys)
    await new Promise((r) => setTimeout(r, 40))

    expect(pushed.map((f) => (f.p as { uid: string }).uid)).toEqual(['live-1', 'live-2'])
    conn.close()
  })

  it('keeps two requests in flight apart', async () => {
    const server = await serve((frame, send) => {
      // Answered out of order on purpose: correlation is by request id, not by
      // arrival, and a client that assumed otherwise would swap the answers.
      if (frame.t === P.TypeChatsList) {
        setTimeout(() => send({ t: P.TypeChats, r: frame.r, p: { device_id: 'a', chats: [] } }), 30)
      }
      if (frame.t === P.TypeContacts) {
        send({ t: P.TypeContactList, r: frame.r, p: { device_id: 'b', contacts: [] } })
      }
    })
    const conn = await Connection.connect({ serverURL: server.url, credential: { kind: 'api_key', token: 'k' } })

    const [chats, contacts] = await Promise.all([
      conn.request<P.Chats>(P.TypeChatsList, {}, P.TypeChats),
      conn.request<P.Contacts>(P.TypeContacts, {}, P.TypeContactList),
    ])
    expect(chats.device_id).toBe('a')
    expect(contacts.device_id).toBe('b')
    conn.close()
  })

  it('rejects everything in flight when the connection drops', async () => {
    const server = await serve(() => {})
    let closedWith = ''
    const conn = await Connection.connect({
      serverURL: server.url,
      credential: { kind: 'api_key', token: 'k' },
      onClose: (reason) => {
        closedWith = reason
      },
    })

    const pending = conn.request(P.TypeChatsList, {}, P.TypeChats)
    await server.close()

    // A caller left waiting forever on a dead socket is the worst of the
    // options: nothing on screen and nothing in the log.
    await expect(pending).rejects.toThrow(/fechou/)
    expect(closedWith).not.toBe('')
  })
})
