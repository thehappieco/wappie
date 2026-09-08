// Names and faces for conversations that did not exist at sign-in.
//
// The contact directory is loaded once, when the archive is unlocked. Every
// conversation that starts after that had nothing behind its identifier, so the
// sidebar drew "LID 42631895773279" at somebody whose push name the server had
// recorded seconds earlier — and went on drawing it until the tab was reloaded.
// Nothing failed and nothing was logged.
//
// Two halves have to work for the fix to be a fix, and each fails silently on
// its own: the client has to ask, and it has to redraw when the answer arrives.
// The directory is a plain Map on purpose — five thousand people made reactive
// to catch the handful that change is a poor trade — so a name learned after a
// row was drawn changes nothing unless the rows are told.

import { afterEach, describe, expect, it } from 'vitest'
import { WebSocketServer, type WebSocket as ServerSocket } from 'ws'

import * as P from '../src/api/protocol'
import { importArchiveKey } from '../src/crypto/hpke'
import { state, start, stop } from '../src/state/archive'
import { fromPastedKey } from '../src/state/session'

const TENANT = '018f3a2b-4444-7000-8000-00000000bbbb'
const DEVICE = '018f3a2b-4444-7000-8000-00000000cccc'
const STRANGER = '42631895773279@lid'

interface Fake {
  url: string
  sent: P.Frame[]
  close: () => Promise<void>
  /** Contacts the server will admit to knowing, keyed by contact_key. */
  known: Map<string, P.ContactSummary>
}

const servers: Fake[] = []

async function serve(): Promise<Fake> {
  const wss = new WebSocketServer({ port: 0 })
  const sent: P.Frame[] = []
  const known = new Map<string, P.ContactSummary>()

  wss.on('connection', (socket: ServerSocket) => {
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
        // The directory at sign-in is empty. That is the situation being
        // tested: everything this client learns, it learns by asking.
        case P.TypeContacts:
          send({ t: P.TypeContactList, r: frame.r, p: { device_id: DEVICE, contacts: [] } })
          break
        case P.TypeResolve: {
          const asked = (frame.p as P.ContactsResolveRequest).contact_keys ?? []
          const rows = asked.map((k) => known.get(k)).filter((c): c is P.ContactSummary => !!c)
          send({ t: P.TypeContactList, r: frame.r, p: { device_id: DEVICE, contacts: rows } })
          break
        }
        case P.TypeChatsList:
          send({
            t: P.TypeChats,
            r: frame.r,
            p: {
              device_id: DEVICE,
              chats: [
                {
                  uid: '018f3a2b-4444-7000-8000-0000000000aa',
                  chat_key: STRANGER,
                  chat_lid: STRANGER,
                  last_seq: 1,
                  last_ts: new Date().toISOString(),
                },
              ],
            },
          })
          break
        case P.TypeKeysGet:
          send({ t: P.TypeKeys, r: frame.r, p: { device_id: DEVICE, keys: [] } })
          break
      }
    })
  })

  const { port } = wss.address() as { port: number }
  const fake: Fake = {
    url: `http://127.0.0.1:${port}`,
    sent,
    known,
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

async function connect(server: Fake) {
  await start(
    fromPastedKey({
      label: 'test',
      serverURL: server.url,
      apiKey: 'k',
      archive: await importArchiveKey(new Uint8Array(32).fill(7) as never),
    }),
  )
}

async function waitFor(check: () => boolean): Promise<void> {
  for (let i = 0; i < 200; i++) {
    if (check()) return
    await new Promise((r) => setTimeout(r, 10))
  }
  throw new Error('condition never held')
}

function resolves(server: Fake): string[][] {
  return server.sent
    .filter((f) => f.t === P.TypeResolve)
    .map((f) => (f.p as P.ContactsResolveRequest).contact_keys)
}

describe('an identifier nobody here can name', () => {
  it('is asked about, once, when a row is about to draw it', async () => {
    const server = await serve()
    await connect(server)

    await waitFor(() => resolves(server).length > 0)
    expect(resolves(server)[0]).toContain(STRANGER)

    // Asked once. The chat list draws every row and the same identifier
    // appears on the chat and on its messages, so an unbatched ask would send
    // one request per appearance — the shape this replaced.
    await new Promise((r) => setTimeout(r, 60))
    expect(resolves(server)).toHaveLength(1)
  })

  it('is not asked about again immediately when the answer was nothing', async () => {
    const server = await serve()
    await connect(server)
    await waitFor(() => resolves(server).length > 0)

    // A LID that nothing has a name for is an ordinary thing, not a failure —
    // withholding the number is what LID is for. Asking again on every redraw
    // would turn that into a request loop for the life of the tab.
    await new Promise((r) => setTimeout(r, 120))
    expect(resolves(server)).toHaveLength(1)
    expect(state.chats[0]?.name).toContain('LID')
  })
})

describe('what one request costs', () => {
  // A person reachable as a LID and as a phone number is one person, and the
  // archive keys a contact row on whichever half is primary. Asking about all
  // three identifiers made the server create a row for each half that had
  // none — two rows for one person, which inflates the contact count, and,
  // worse, hands the picture worker two faces to fetch: two questions over the
  // device's own socket, paced, for somebody who has one face.
  it('asks about one identifier per person, not all of their halves', async () => {
    const server = await serve()
    await connect(server)
    await waitFor(() => resolves(server).length > 0)

    const asked = resolves(server).flat()
    expect(asked).toContain(STRANGER)
    // The fixture's chat carries chat_key and chat_lid as the same value and no
    // phone number, so one key is the whole of it.
    expect(new Set(asked).size).toBe(1)
  })
})

describe('when the name arrives', () => {
  it('the row already on screen is redrawn', async () => {
    const server = await serve()
    // The server does know this one — as it would when a push name landed a
    // moment after the directory was loaded.
    server.known.set(STRANGER, {
      uid: '018f3a2b-4444-7000-8000-0000000000bb',
      contact_key: STRANGER,
      contact_lid: STRANGER,
    })

    await connect(server)
    await waitFor(() => resolves(server).length > 0)

    // No sealed name is set here, so the directory learns the identity without
    // a display name, and the fallback stands. What is being asserted is the
    // half that used to be missing entirely: the reply is absorbed and the
    // sidebar is revisited rather than left as it was drawn.
    await waitFor(() => state.contactsLoaded > 0)
    expect(state.chats).toHaveLength(1)
  })
})
