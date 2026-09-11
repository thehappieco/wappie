// Looking again at messages the archive could not classify when they arrived.
//
// The split of labour is the whole design: this tab holds the archive key and
// opens each stored protobuf, the server holds the classifier and re-seals with
// the public half. So the failure modes are on both sides of a round trip, and
// the one that matters most is silent — a run that reports nothing changed
// looks identical whether it found nothing to change or never asked.

import { afterEach, describe, expect, it } from 'vitest'
import { WebSocketServer, type WebSocket as ServerSocket } from 'ws'

import * as P from '../src/api/protocol'
import { importArchiveKey } from '../src/crypto/hpke'
import { start, state, stop } from '../src/state/archive'
import { reproject, sweepDone, sweepUnsupported } from '../src/state/reproject'
import { fromPastedKey } from '../src/state/session'

const TENANT = '018f3a2b-5555-7000-8000-00000000bbbb'
const DEVICE = '018f3a2b-5555-7000-8000-00000000cccc'

interface Fake {
  url: string
  sent: P.Frame[]
  rows: P.UnsupportedRow[]
  applied: P.ReprojectRequest[]
  close: () => Promise<void>
}

const servers: Fake[] = []

async function serve(): Promise<Fake> {
  const wss = new WebSocketServer({ port: 0 })
  const sent: P.Frame[] = []
  const rows: P.UnsupportedRow[] = []
  const applied: P.ReprojectRequest[] = []

  wss.on('connection', (socket: ServerSocket) => {
    socket.on('message', (data) => {
      const frame = JSON.parse(String(data)) as P.Frame
      sent.push(frame)
      const send = (f: P.Frame) => socket.send(JSON.stringify(f))
      switch (frame.t) {
        case P.TypeHello:
          send({
            t: P.TypeWelcome, r: frame.r,
            p: { version: P.VERSION, tenant_id: TENANT, features: [], server_ts: 0 },
          })
          break
        case P.TypeSubscribe:
          send({ t: P.TypeReplayEnd, r: frame.r, p: { last_seq: 0, count: 0 } })
          break
        case P.TypeDevicesList:
          send({
            t: P.TypeDevices, r: frame.r,
            p: {
              devices: [{
                id: DEVICE, label: 'test', status: 'online',
                receipt_mode: 'passive', running: true,
                created_at: new Date().toISOString(),
              }],
            },
          })
          break
        case P.TypeContacts:
        case P.TypeResolve:
          send({ t: P.TypeContactList, r: frame.r, p: { device_id: DEVICE, contacts: [] } })
          break
        case P.TypeChatsList:
          send({ t: P.TypeChats, r: frame.r, p: { device_id: DEVICE, chats: [] } })
          break
        case P.TypeKeysGet:
          send({ t: P.TypeKeys, r: frame.r, p: { device_id: DEVICE, keys: [] } })
          break
        case P.TypeReprojectGet: {
          // Honour the cursor. A fake that ignores it hands the same page back
          // for ever, which is exactly the bug the cursor exists to prevent —
          // and a test against such a fake would pass while the product spun.
          const before = (frame.p as P.ReprojectRequest).before_seq ?? 0
          const page = before ? rows.filter((r) => r.seq < before) : rows
          send({ t: P.TypeUnsupportedRows, r: frame.r, p: { device_id: DEVICE, rows: page } })
          break
        }
        case P.TypeReprojectPut:
          applied.push(frame.p as P.ReprojectRequest)
          send({
            t: P.TypeReprojected, r: frame.r,
            p: { uid: (frame.p as P.ReprojectRequest).uid, type: 'group_invite', changed: true },
          })
          break
      }
    })
  })

  const { port } = wss.address() as { port: number }
  const fake: Fake = {
    url: `http://127.0.0.1:${port}`,
    sent, rows, applied,
    close: () => new Promise<void>((resolve) => {
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
  // start() kicks off the automatic pass. The tests below drive reproject()
  // by hand and count what it sent, so the pass has to be over first.
  await sweepDone()
}

describe('reprojecting stored messages', () => {
  it('asks for the list, and says so when there is nothing to do', async () => {
    const server = await serve()
    await connect(server)

    const out = await reproject()
    expect(out.error).toBeUndefined()
    expect(out.total).toBe(0)
    expect(out.done).toBe(true)
    // The request went. A run that never asks reports "nothing to do" in
    // exactly the same words as one that asked and was told nothing, which is
    // the failure this asserts against.
    expect(server.sent.some((f) => f.t === P.TypeReprojectGet)).toBe(true)
  })

  // A row this tab cannot open is counted, not retried and not reported as a
  // failure of the feature. A key this account was never granted and a row that
  // really was tampered with both land here.
  it('counts a row it cannot open rather than sending nothing back', async () => {
    const server = await serve()
    server.rows.push({
      uid: '018f3a2b-5555-7000-8000-0000000000aa',
      seq: 42,
      wa_id: 'OLD1',
      field: 'groupInviteMessage',
      content_key_id: 319,
      raw_sealed: 'bm90IGEgcmVhbCBlbnZlbG9wZQ==',
    })
    await connect(server)

    const out = await reproject()
    expect(out.total).toBe(1)
    expect(out.unreadable).toBe(1)
    expect(out.opened).toBe(0)
    expect(server.applied).toHaveLength(0)
  })

  it('reports the archive being locked rather than doing nothing quietly', async () => {
    const out = await reproject()
    expect(out.error).toBeTruthy()
    expect(out.done).toBe(true)
  })
})

describe('sweeping the whole archive', () => {
  // A page-at-a-time button hands back the same unconvertible rows and never
  // reaches what is behind them, because most rows stay unsupported: they are
  // types this build still does not understand. On the real archive that left
  // a message somebody had asked about at position 748 of 750.
  it('follows the cursor past rows it cannot convert', async () => {
    const server = await serve()
    for (let i = 0; i < 5; i++) {
      server.rows.push({
        uid: `018f3a2b-5555-7000-8000-00000000${(0xa0 + i).toString(16)}`,
        seq: 100 - i,
        wa_id: `OLD${i}`,
        content_key_id: 1,
        raw_sealed: 'bm90IGEgcmVhbCBlbnZlbG9wZQ==',
      })
    }
    await connect(server)
    // Only the frames this run sends. The automatic pass already asked once.
    const from = server.sent.length

    const out = await reproject(undefined, 2)
    // Every row was reached, across pages, rather than the first page being
    // fetched again and again.
    expect(out.total).toBe(5)
    expect(out.done).toBe(true)

    const asked = server.sent
      .slice(from)
      .filter((f) => f.t === P.TypeReprojectGet)
      .map((f) => (f.p as P.ReprojectRequest).before_seq ?? 0)
    expect(asked.length).toBeGreaterThan(1)
    // The cursor moved every round. One that did not would spin.
    expect(new Set(asked).size).toBe(asked.length)
  })
})

describe('the automatic pass', () => {
  // The button had become a chore that never ended: rows the classifier could
  // not name were offered again on every press. The pass now runs when the
  // archive opens, and what it cannot convert is counted rather than queued.
  it('runs when the archive opens and counts what is left, by field', async () => {
    const server = await serve()
    for (const [i, field] of ['interactiveMessage', 'interactiveMessage', 'listMessage'].entries()) {
      server.rows.push({
        uid: `018f3a2b-5555-7000-8000-00000000${(0xb0 + i).toString(16)}`,
        seq: 50 - i,
        wa_id: `LEFT${i}`,
        field,
        content_key_id: 1,
        raw_sealed: 'bm90IGEgcmVhbCBlbnZlbG9wZQ==',
      })
    }
    await connect(server)

    expect(state.unsupported.running).toBe(false)
    expect(state.unsupported.sweptAt).toBeInstanceOf(Date)
    expect(state.unsupported.total).toBe(3)
    expect(state.unsupported.byField).toEqual({ interactiveMessage: 2, listMessage: 1 })
    // It asked without anybody pressing anything.
    expect(server.sent.some((f) => f.t === P.TypeReprojectGet)).toBe(true)
  })

  it('does not run twice at once', async () => {
    // A device switched twice in quick succession would otherwise double-open
    // every row for nothing. One pass is one list request plus one survey.
    const server = await serve()
    await connect(server)
    const from = server.sent.length

    await Promise.all([sweepUnsupported(), sweepUnsupported()])

    const asked = server.sent.slice(from).filter((f) => f.t === P.TypeReprojectGet)
    expect(asked).toHaveLength(2)
  })
})
