import { afterEach, describe, expect, it, vi } from 'vitest'
import { WebSocketServer, type WebSocket as ServerSocket } from 'ws'
import type { AddressInfo } from 'node:net'

import * as P from '../src/api/protocol'
import { generateAccountKeys } from '../src/crypto/account'
import { fromBase64, parseUUID, toBase64 } from '../src/crypto/bytes'
import { importArchiveKey, publicFromPrivate } from '../src/crypto/hpke'
import { grantRow, Kind, openDirect } from '../src/crypto/seal'
import { admin, cancelPairing, load, pair } from '../src/state/admin'
import { connection, start, state, stop } from '../src/state/archive'
import { fromPastedKey } from '../src/state/session'

// Pairing is the one place this client produces key material instead of
// consuming it, and the failure mode is silent: a device pairs, messages
// arrive, and the archive turns out to be unreadable by anybody. Nothing in the
// UI can show that, because the server cannot check it either.
//
// So the assertions here are about the material, not the screen. The private
// key must not leave, and the grant that did leave must open to exactly the key
// whose public half the server was given.

const TENANT = '018f3a2b-1111-7000-8000-00000000aaaa'

interface Fake {
  url: string
  sent: P.Frame[]
  holdDevices: boolean
  deviceError: boolean
  heldDevices: (() => void)[]
  close: () => Promise<void>
  push: (frame: P.Frame) => void
}

const servers: Fake[] = []

async function serve(accounts: P.UserSummary[]): Promise<Fake> {
  const wss = new WebSocketServer({ port: 0 })
  const sent: P.Frame[] = []
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
            p: {
              version: P.VERSION,
              tenant_id: TENANT,
              features: [],
              account: 'owner@acme.test',
              role: 'owner',
              server_ts: 0,
            } satisfies P.Welcome,
          })
          break
        case P.TypeSubscribe:
          send({ t: P.TypeReplayEnd, r: frame.r, p: { last_seq: 0, count: 0 } })
          break
        case P.TypeDevicesList:
          if (fake.deviceError) send({ t: P.TypeError, r: frame.r, p: { code: P.ErrInternal, message: 'synthetic refresh failure' } })
          else if (fake.holdDevices) fake.heldDevices.push(() => send({ t: P.TypeDevices, r: frame.r, p: { devices: [] } }))
          else send({ t: P.TypeDevices, r: frame.r, p: { devices: [] } })
          break
        case P.TypeUsersList:
          send({ t: P.TypeUsers, r: frame.r, p: { users: accounts } })
          break
        case P.TypeDevicesStats:
          send({ t: P.TypeDeviceStats, r: frame.r, p: { stats: [] } })
          break
        case P.TypeKeysList:
          send({ t: P.TypeAPIKeys, r: frame.r, p: { keys: [] } })
          break
        case P.TypePair:
          // Answer the way the server does: a code now, more frames later,
          // all under the same request id.
          send({
            t: P.TypePairCode,
            r: frame.r,
            p: {
              device_id: (frame.p as P.PairRequest).device_id,
              code: 'ABCD-1234',
              expires: new Date(Date.now() + 60_000).toISOString(),
            } satisfies P.PairCode,
          })
          break
      }
    })
  })

  await new Promise<void>((resolve) => wss.on('listening', resolve))
  const { port } = wss.address() as AddressInfo
  const fake: Fake = {
    url: `http://127.0.0.1:${port}`,
    sent, holdDevices: false, deviceError: false, heldDevices: [],
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
  vi.restoreAllMocks()
})

/** An account as the server reports it: an address and a public key. */
async function account(email: string) {
  const keys = await generateAccountKeys()
  return {
    summary: {
      id: crypto.randomUUID(),
      email,
      role: 'owner',
      public_key: toBase64(keys.publicKey),
    } satisfies P.UserSummary,
    privateKey: keys.privateKey,
  }
}

async function open(server: Fake) {
  await start(
    fromPastedKey({
      label: 'test',
      serverURL: server.url,
      apiKey: 'k',
      archive: await importArchiveKey(new Uint8Array(32).fill(7) as never),
    }),
  )
  await load()
}

function pairRequest(server: Fake): P.PairRequest {
  const frame = server.sent.find((f) => f.t === P.TypePair)
  if (!frame) throw new Error('nothing was sent to pair')
  return frame.p as P.PairRequest
}

/** waitFor polls, because pairing answers over several frames and some time. */
async function waitFor(check: () => boolean): Promise<void> {
  for (let i = 0; i < 200; i++) {
    if (check()) return
    await new Promise((r) => setTimeout(r, 10))
  }
  throw new Error('condition never held')
}

describe('pairing from the browser', () => {
  it('seals the device key to each account chosen, and sends nothing else', async () => {
    const alice = await account('alice@acme.test')
    const bob = await account('bob@acme.test')
    const server = await serve([alice.summary, bob.summary])
    await open(server)

    await pair({
      method: 'code',
      phone: '+5511999999999',
      label: 'comercial',
      grantTo: [alice.summary.id, bob.summary.id],
      receiptMode: 'passive',
    })
    await waitFor(() => server.sent.some((f) => f.t === P.TypePair))

    const request = pairRequest(server)
    expect(request.grants).toHaveLength(2)
    expect(fromBase64(request.archive_public_key)).toHaveLength(32)

    const tenant = parseUUID(TENANT)
    const device = parseUUID(request.device_id)

    for (const holder of [alice, bob]) {
      const grant = request.grants.find((g) => g.user_id === holder.summary.id)
      expect(grant, `no grant for ${holder.summary.email}`).toBeTruthy()

      const row = await grantRow(tenant, device, parseUUID(holder.summary.id), 1)
      const deviceKey = await openDirect(
        await importArchiveKey(holder.privateKey),
        Kind.DeviceGrant,
        tenant,
        row,
        fromBase64(grant!.sealed_dsk),
      )

      // The point of the whole exchange: what this account can open is the
      // private half of the key the server was handed the public half of.
      const derived = await publicFromPrivate(deviceKey)
      expect(toBase64(derived)).toBe(request.archive_public_key)
    }
  })

  it('never puts the private key on the wire', async () => {
    const alice = await account('alice@acme.test')
    const server = await serve([alice.summary])
    await open(server)

    await pair({
      method: 'code',
      phone: '+5511999999999',
      label: '',
      grantTo: [alice.summary.id],
      receiptMode: 'passive',
    })
    await waitFor(() => server.sent.some((f) => f.t === P.TypePair))

    const request = pairRequest(server)
    const tenant = parseUUID(TENANT)
    const device = parseUUID(request.device_id)
    const row = await grantRow(tenant, device, parseUUID(alice.summary.id), 1)
    const deviceKey = await openDirect(
      await importArchiveKey(alice.privateKey),
      Kind.DeviceGrant,
      tenant,
      row,
      fromBase64(request.grants[0].sealed_dsk),
    )

    // Everything this client said, as one string. The device private key must
    // not be findable in it — that is the difference between an archive the
    // server cannot read and one it merely promises not to.
    const everything = JSON.stringify(server.sent)
    expect(everything).not.toContain(toBase64(deviceKey))
    expect(everything).not.toContain(Buffer.from(deviceKey).toString('base64url'))
    expect(everything).not.toContain(Buffer.from(deviceKey).toString('hex'))
  })

  it('refuses to pair a device nobody can read', async () => {
    const alice = await account('alice@acme.test')
    const server = await serve([alice.summary])
    await open(server)

    await pair({ method: 'code', phone: '+5511999999999', label: '', grantTo: [], receiptMode: 'passive' })

    expect(admin.pairing.phase).toBe('failed')
    expect(admin.pairing.error).toMatch(/membro/)
    // And nothing was started: a device row created here would be one nobody
    // could ever open.
    expect(server.sent.some((f) => f.t === P.TypePair)).toBe(false)
  })

  it('follows the several frames one pairing answers with', async () => {
    const alice = await account('alice@acme.test')
    const server = await serve([alice.summary])
    await open(server)

    await pair({
      method: 'code',
      phone: '+5511999999999',
      label: '',
      grantTo: [alice.summary.id],
      receiptMode: 'passive',
    })

    // The code arrives first...
    await waitFor(() => admin.pairing.code !== '')
    expect(admin.pairing.code).toBe('ABCD-1234')
    expect(admin.pairing.phase).toBe('waiting')
    expect(admin.pairing.grantedTo).toEqual(['alice@acme.test'])

    // ...and success arrives later, under the same request id. A client that
    // routed only the first reply would sit on the code forever.
    const reqID = server.sent.find((f) => f.t === P.TypePair)!.r
    server.push({
      t: P.TypePairSuccess,
      r: reqID,
      p: { device_id: pairRequest(server).device_id },
    })
    await waitFor(() => admin.pairing.phase === 'done')
    expect(admin.pairing.code).toBe('')
  })

  it('asks for a QR without a number, and shows the newest one', async () => {
    const alice = await account('alice@acme.test')
    const server = await serve([alice.summary])
    await open(server)

    await pair({ method: 'qr', phone: '', label: 'sala', grantTo: [alice.summary.id], receiptMode: 'passive' })
    await waitFor(() => server.sent.some((f) => f.t === P.TypePair))

    const request = pairRequest(server)
    expect(request.method).toBe('qr')
    expect(request.phone).toBe('')

    const reqID = server.sent.find((f) => f.t === P.TypePair)!.r
    const push = (code: string) =>
      server.push({
        t: P.TypePairQR,
        r: reqID,
        p: { device_id: request.device_id, code, expires: new Date().toISOString() },
      })

    push('first-payload')
    await waitFor(() => admin.pairing.qr === 'first-payload')

    // Codes rotate every twenty seconds or so. The stale one has to go: a QR
    // that no longer works looks exactly like one that does.
    push('second-payload')
    await waitFor(() => admin.pairing.qr === 'second-payload')
  })

  it('reports a pairing the server refuses', async () => {
    const alice = await account('alice@acme.test')
    const server = await serve([alice.summary])
    await open(server)

    await pair({
      method: 'code',
      phone: '+5511999999999',
      label: '',
      grantTo: [alice.summary.id],
      receiptMode: 'passive',
    })
    await waitFor(() => server.sent.some((f) => f.t === P.TypePair))

    const reqID = server.sent.find((f) => f.t === P.TypePair)!.r
    server.push({
      t: P.TypeError,
      r: reqID,
      p: { code: P.ErrConflict, message: 'esse aparelho já está supervisionado' },
    })
    await waitFor(() => admin.pairing.phase === 'failed')
    expect(admin.pairing.error).toContain('supervisionado')
  })
})


async function waitingPair() {
  const alice = await account('alice@acme.test')
  const server = await serve([alice.summary])
  await open(server)
  await pair({ method: 'qr', phone: '', label: 'test', grantTo: [alice.summary.id], receiptMode: 'passive' })
  await waitFor(() => admin.pairing.code !== '')
  return server
}

describe('pairing work during logout and refresh failures', () => {
  it('does not request another device list when logout closes the pairing stream', async () => {
    await waitingPair()
    const request = vi.spyOn(connection()!, 'request')
    stop()
    await Promise.resolve(); await Promise.resolve()
    expect(request).not.toHaveBeenCalled()
    expect(state.phase).toBe('locked')
    expect(admin.pairing.phase).toBe('idle')
    expect(admin.error).toBe('')
  })
  it('ignores a rejected post-success refresh after logout without requesting stats on another session', async () => {
    const server = await waitingPair()
    server.holdDevices = true
    const reqID = server.sent.find(frame => frame.t === P.TypePair)!.r
    server.push({ t: P.TypePairSuccess, r: reqID, p: { device_id: pairRequest(server).device_id } })
    await waitFor(() => server.heldDevices.length === 1)
    expect(admin.pairing.phase).toBe('done')
    const requests = vi.spyOn(connection()!, 'request')
    stop()
    await Promise.resolve(); await Promise.resolve(); await Promise.resolve()
    expect(requests).not.toHaveBeenCalled()
    expect(admin.pairing.phase).toBe('idle'); expect(admin.error).toBe('')
  })
  it('keeps a confirmed pairing result when the following device refresh fails', async () => {
    const server = await waitingPair()
    server.deviceError = true
    const reqID = server.sent.find(frame => frame.t === P.TypePair)!.r
    server.push({ t: P.TypePairSuccess, r: reqID, p: { device_id: pairRequest(server).device_id } })
    await waitFor(() => admin.error === 'synthetic refresh failure')
    expect(admin.pairing.phase).toBe('done')
  })
  it('handles a refresh failure after canceling a pairing without restarting it', async () => {
    const server = await waitingPair()
    server.deviceError = true
    cancelPairing()
    await waitFor(() => admin.error === 'synthetic refresh failure')
    expect(admin.pairing.phase).toBe('idle')
    expect(server.sent.filter(frame => frame.t === P.TypePairCancel)).toHaveLength(1)
  })
})
