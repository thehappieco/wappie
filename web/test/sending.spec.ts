import { afterEach, describe, expect, it } from 'vitest'
import { WebSocketServer, type WebSocket as ServerSocket } from 'ws'
import type { AddressInfo } from 'node:net'

import * as P from '../src/api/protocol'
import { importArchiveKey } from '../src/crypto/hpke'
import { openChat, sendText, state, start, stop } from '../src/state/archive'
import { edit, react } from '../src/state/actions'
import { fromPastedKey } from '../src/state/session'

// A sent message has to appear before the server has confirmed it, and then
// stop being a second copy of itself when the archived row arrives.
//
// The ordering is the trap. The server publishes the archived row to the live
// subscription inside the same call that answers the send, so the `message`
// frame regularly arrives BEFORE the reply — there is no moment where the
// client can say "now swap the placeholder for the real one". The two are
// matched on the WhatsApp id instead, which is why the client mints it.

const TENANT = '018f3a2b-2222-7000-8000-00000000bbbb'
const DEVICE = '018f3a2b-2222-7000-8000-00000000cccc'
const CHAT = '120363000000000000@g.us'

interface Fake {
  url: string
  sent: P.Frame[]
  push: (frame: P.Frame) => void
  close: () => Promise<void>
  /** Set to make the server refuse the next send. */
  refuse: { on: boolean }
}

const servers: Fake[] = []

async function serve(): Promise<Fake> {
  const wss = new WebSocketServer({ port: 0 })
  const sent: P.Frame[] = []
  const refuse = { on: false }
  let live: ServerSocket | null = null

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
          send({ t: P.TypePage, r: frame.r, p: { chat_key: CHAT, messages: [], has_more: false } })
          break
        case P.TypeReact:
        case P.TypeEdit:
        case P.TypeRevoke:
          send({
            t: P.TypeSendResult,
            r: frame.r,
            p: { id: 'ack', timestamp: new Date().toISOString() },
          })
          break
        case P.TypeSend:
          if (refuse.on) {
            send({ t: P.TypeError, r: frame.r, p: { code: 'internal', message: 'o aparelho recusou' } })
            break
          }
          send({
            t: P.TypeSendResult,
            r: frame.r,
            p: {
              id: (frame.p as P.SendRequest).id,
              // A real server answers with the archived row's uid. An empty one
              // means the message went and could not be written down, which the
              // client has to say rather than leave at "enviando…".
              uid: '018f3a2b-2222-7000-8000-0000000000ee',
              timestamp: new Date().toISOString(),
            },
          })
          break
      }
    })
  })

  await new Promise<void>((resolve) => wss.on('listening', resolve))
  const { port } = wss.address() as AddressInfo
  const fake: Fake = {
    url: `http://127.0.0.1:${port}`,
    sent,
    refuse,
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
  stop()
  while (servers.length) await servers.pop()!.close()
})

async function openConversation(server: Fake) {
  await start(
    fromPastedKey({
      label: 'test',
      serverURL: server.url,
      apiKey: 'k',
      archive: await importArchiveKey(new Uint8Array(32).fill(9) as never),
    }),
  )
  await openChat(CHAT)
}

/** The archived row, as it comes back over the live subscription. */
function archived(waID: string): P.Frame {
  return {
    t: P.TypeMessage,
    p: {
      uid: '018f3a2b-2222-7000-8000-0000000000ff',
      seq: 42,
      device_id: DEVICE,
      wa_id: waID,
      chat_key: CHAT,
      ts: new Date().toISOString(),
      is_from_me: true,
      is_group: true,
      kind: 'message',
      type: 'text',
      source: 'live',
      content_key_id: 0,
    } satisfies P.SealedMessage,
  }
}

async function waitFor(check: () => boolean): Promise<void> {
  for (let i = 0; i < 200; i++) {
    if (check()) return
    await new Promise((r) => setTimeout(r, 10))
  }
  throw new Error('condition never held')
}

describe('sending a message', () => {
  it('shows it before the server has answered', async () => {
    const server = await serve()
    await openConversation(server)

    const sending = sendText('olá')
    await waitFor(() => state.timeline.length === 1)

    const line = state.timeline[0]
    expect(line.body).toBe('olá')
    expect(line.fromMe).toBe(true)
    expect(line.pending).toBe('sending')
    await sending
  })

  it('mints the id itself, so the archived row can be recognised', async () => {
    const server = await serve()
    await openConversation(server)
    await sendText('olá')

    const request = server.sent.find((f) => f.t === P.TypeSend)?.p as P.SendRequest
    expect(request.id, 'the client must choose the id before sending').toBeTruthy()
    expect(state.timeline[0].waID).toBe(request.id)
  })

  it('does not show the message twice when the archived row arrives', async () => {
    const server = await serve()
    await openConversation(server)
    await sendText('olá')

    const id = state.timeline[0].waID
    server.push(archived(id))

    // The archived row replaces the optimistic one rather than joining it.
    await waitFor(() => state.timeline.length === 1 && !state.timeline[0].pending)
    expect(state.timeline).toHaveLength(1)
    expect(state.timeline[0].waID).toBe(id)
  })

  it('survives the archived row arriving before the reply', async () => {
    // Which is the ordinary case, not the exotic one: the server publishes to
    // the bus inside the call that answers the request.
    const server = await serve()
    await openConversation(server)

    const sending = sendText('olá')
    await waitFor(() => state.timeline.length === 1)
    server.push(archived(state.timeline[0].waID))
    await sending

    await waitFor(() => !state.timeline[0]?.pending)
    expect(state.timeline).toHaveLength(1)
  })

  it('says so when the message did not go', async () => {
    const server = await serve()
    await openConversation(server)
    server.refuse.on = true

    await sendText('olá')

    expect(state.timeline).toHaveLength(1)
    expect(state.timeline[0].pending).toBe('failed')
    expect(state.timeline[0].failure).toContain('recusou')
    // And it stays on screen: silently dropping what somebody typed is worse
    // than leaving it there marked as failed.
    expect(state.timeline[0].body).toBe('olá')
  })

  it('withdraws a reaction by sending an empty emoji', async () => {
    // WhatsApp has no separate "unreact": tapping the emoji already on a
    // message sends a reaction whose emoji is the empty string, and the archive
    // records that as a withdrawal rather than as an empty reaction.
    const server = await serve()
    await openConversation(server)
    await sendText('olá')
    const line = state.timeline[0]

    await react(line, '👍')
    let sent = server.sent.filter((f) => f.t === P.TypeReact).map((f) => f.p as P.ReactRequest)
    expect(sent.at(-1)?.emoji).toBe('👍')

    // Now the same emoji is already ours, so the next tap has to remove it.
    line.reactions = [{ emoji: '👍', who: 'você', fromMe: true }]
    await react(line, '👍')
    sent = server.sent.filter((f) => f.t === P.TypeReact).map((f) => f.p as P.ReactRequest)
    expect(sent.at(-1)?.emoji, 'tapping the same emoji must remove it').toBe('')

    // A different emoji replaces rather than removes.
    await react(line, '❤️')
    sent = server.sent.filter((f) => f.t === P.TypeReact).map((f) => f.p as P.ReactRequest)
    expect(sent.at(-1)?.emoji).toBe('❤️')
  })

  it('refuses an edit whose window has closed, without a round trip', async () => {
    const server = await serve()
    await openConversation(server)
    await sendText('olá')

    const line = state.timeline[0]
    line.ts = new Date(Date.now() - 21 * 60 * 1000)
    line.pending = undefined

    await edit(line, 'corrigido')
    expect(server.sent.some((f) => f.t === P.TypeEdit)).toBe(false)
    expect(state.actionError).toContain('vinte minutos')
  })

  it('marks a message as forwarded when asked to', async () => {
    const server = await serve()
    await openConversation(server)
    await sendText('olha isso', undefined, { forwarded: true, score: 5, viewOnce: false })

    const request = server.sent.find((f) => f.t === P.TypeSend)?.p as P.SendRequest
    expect(request.forwarded).toBe(true)
    expect(request.forwarding_score).toBe(5)
    // And the bubble says so before the archive does, like everything else on
    // an optimistic line.
    expect(state.timeline[0].forwarded).toBe(true)
    expect(state.timeline[0].forwardingScore).toBe(5)
  })

  it('turns a bare score into a real forward', async () => {
    // The server reads the score only inside `if forwarded`. A score on its own
    // evaporates and the message arrives with no badge at all.
    const server = await serve()
    await openConversation(server)
    await sendText('olha', undefined, { forwarded: false, score: 7, viewOnce: false })

    const request = server.sent.find((f) => f.t === P.TypeSend)?.p as P.SendRequest
    expect(request.forwarded).toBe(true)
    expect(request.forwarding_score).toBe(7)
  })

  it('says nothing about forwarding on an ordinary message', async () => {
    const server = await serve()
    await openConversation(server)
    await sendText('oi')

    const request = server.sent.find((f) => f.t === P.TypeSend)?.p as P.SendRequest
    expect(request.forwarded).toBeUndefined()
    expect(request.forwarding_score).toBeUndefined()
  })

  it('sends nothing for an empty message', async () => {
    const server = await serve()
    await openConversation(server)

    await sendText('   ')
    expect(server.sent.some((f) => f.t === P.TypeSend)).toBe(false)
    expect(state.timeline).toHaveLength(0)
  })
})
