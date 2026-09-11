import { afterEach, describe, expect, it } from 'vitest'
import { WebSocketServer } from 'ws'
import type { AddressInfo } from 'node:net'
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL } from 'node:url'

import * as P from '../src/api/protocol'
import { importArchiveKey } from '../src/crypto/hpke'
import { state, start, stop, setReceiptMode, refreshDevices, refreshCurrentAccess, readableDevices, archiveOpener } from '../src/state/archive'
import { readReceiptsEnabled } from '../src/state/reading'
import { fromPastedKey } from '../src/state/session'

// The posture at start-up.
//
// `quiet` begins true, so that a device whose posture is not yet known emits
// nothing — the right default. But the flag was never corrected once the
// device WAS known: start() chose a device and moved on, and only the switch
// (which read the device row directly) and a later toggle ever touched it. So
// a loud device booted with a dark palette, a bell in the corner saying the
// opposite, and read-receipt gates that agreed with neither.
//
// One source now — the flag — and this is the test that the flag is set from
// the server's answer at the moment the device is chosen.

const encrypted = JSON.parse(readFileSync(fileURLToPath(new URL('../../internal/wsapi/testdata/frames.json', import.meta.url)), 'utf8')) as {
  tenant: string; device: string; private_key: string; content_key: { id: number; sealed: string }
  message: P.SealedMessage; expected: { body: string }
}
const TENANT = encrypted.tenant
const DEVICE = encrypted.device

const servers: { close: () => Promise<void> }[] = []

async function serve(mode: 'active' | 'passive', personal?: 'active' | 'passive', commands: string[] = []): Promise<string> {
  const wss = new WebSocketServer({ port: 0 })
  wss.on('connection', (socket) => {
    socket.on('message', (data) => {
      const frame = JSON.parse(String(data)) as P.Frame
      commands.push(frame.t)
      const send = (f: P.Frame) => socket.send(JSON.stringify(f))
      switch (frame.t) {
        case P.TypeHello:
          send({
            t: P.TypeWelcome,
            r: frame.r,
            p: { version: P.VERSION, tenant_id: TENANT, features: [], server_ts: 0 },
          })
          break
        case P.TypeSubscribe:
          send({ t: P.TypeReplayEnd, r: frame.r, p: { last_seq: 0, count: 0 } })
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
                  receipt_mode: mode,
                  reader_receipt_mode: personal,
                  running: true,
                  created_at: new Date().toISOString(),
                },
              ],
            },
          })
          break
        case P.TypeContacts:
          send({ t: P.TypeContactList, r: frame.r, p: { contacts: [] } })
          break
        case P.TypeChatsList:
          send({ t: P.TypeChats, r: frame.r, p: { chats: [] } })
          break
        case P.TypeReaderMode:
          personal = (frame.p as P.DeviceModeRequest).receipt_mode as 'active' | 'passive'
          send({ t: P.TypeReaderMode, r: frame.r, p: { device_id: DEVICE, receipt_mode: personal } })
          break
        case P.TypeKeysGet:
          send({ t: P.TypeKeys, r: frame.r, p: { keys: [encrypted.content_key] } })
          break
      }
    })
  })
  await new Promise<void>((resolve) => wss.on('listening', resolve))
  const { port } = wss.address() as AddressInfo
  servers.push({
    close: () =>
      new Promise<void>((resolve) => {
        wss.clients.forEach((c) => c.terminate())
        wss.close(() => resolve())
      }),
  })
  return `http://127.0.0.1:${port}`
}

async function boot(mode: 'active' | 'passive') {
  await start(
    fromPastedKey({
      label: 'test',
      serverURL: await serve(mode),
      apiKey: 'k',
      archive: await importArchiveKey(new Uint8Array(32).fill(9) as never),
    }),
  )
}

afterEach(async () => {
  stop()
  while (servers.length) await servers.pop()!.close()
})

describe('the posture at start-up', () => {
  it('follows the device the server described, when it is loud', async () => {
    await boot('active')
    expect(state.phase).toBe('ready')
    // The flag the palette, the switch and the gates all read.
    expect(state.quiet).toBe(false)
    expect(readReceiptsEnabled()).toBe(true)
  })

  it('follows the device the server described, when it is quiet', async () => {
    await boot('passive')
    expect(state.phase).toBe('ready')
    expect(state.quiet).toBe(true)
    expect(readReceiptsEnabled()).toBe(false)
  })
})

describe('a user’s preference on a shared number', () => {
  async function bootPerson(shared: 'active' | 'passive', personal?: 'active' | 'passive', commands: string[] = []) {
    const legacy = fromPastedKey({ label: 'test', serverURL: await serve(shared, personal, commands),
      apiKey: 'k', archive: await importArchiveKey(new Uint8Array(32).fill(9) as never) })
    const open = { ...legacy, credential: { kind: 'session' as const, token: 'test-user' },
      readable: [{ deviceID: DEVICE, label: 'test' }],
      account: { email: 'reader@example.test', userID: '018f3a2b-2222-7000-8000-00000000aaaa', tenantID: TENANT, hasRecovery: true } }
    await start(open)
    return open
  }

  it('defaults to discreet even when the shared number is active', async () => {
    await bootPerson('active')
    expect(state.phase).toBe('ready')
    expect(state.quiet).toBe(true)
    expect(readReceiptsEnabled()).toBe(false)
  })

  it('restores the personal preference independently of the shared transport', async () => {
    await bootPerson('passive', 'active')
    expect(state.quiet).toBe(false)
    expect(readReceiptsEnabled()).toBe(true)
  })

  it('changes only reader.mode and keeps that preference after refreshing numbers', async () => {
    const commands: string[] = []
    await bootPerson('passive', 'passive', commands)
    expect(await setReceiptMode('active')).toBe(true)
    expect(state.quiet).toBe(false)
    expect(state.devices[0]?.receipt_mode).toBe('passive')
    expect(commands).toContain(P.TypeReaderMode)
    expect(commands).not.toContain(P.TypeDeviceMode)
    await refreshDevices()
    expect(state.quiet).toBe(false)
    expect(state.devices[0]?.reader_receipt_mode).toBe('active')
  })

  it('drops the opened archive and outgoing receipts when its key is revoked', async () => {
    const open = await bootPerson('passive', 'active')
    open.refreshAccess = async () => { open.readable.splice(0); open.archiveFor = () => undefined }
    expect(await refreshCurrentAccess()).toBe(true)
    expect(readableDevices().size).toBe(0)
    expect(state.unreadable).toBe(true)
    expect(state.quiet).toBe(true)
    expect(readReceiptsEnabled()).toBe(false)
  })

  it('does not apply a late access refresh to a replacement session', async () => {
    const old = await bootPerson('passive', 'passive')
    let complete!: () => void
    old.refreshAccess = () => new Promise<void>(resolve => { complete = resolve })
    const pending = refreshCurrentAccess()
    stop()
    await bootPerson('passive', 'active')
    const revision = state.accessRevision
    complete()
    expect(await pending).toBe(false)
    expect(state.accessRevision).toBe(revision)
    expect(state.quiet).toBe(false)
    expect(readableDevices().has(DEVICE)).toBe(true)
  })

  it('opens real encrypted content after replacing the key of the same number', async () => {
    const open = await bootPerson('passive', 'passive')
    expect((await archiveOpener()!.body(encrypted.message)).state).toBe('locked')
    const fresh = await importArchiveKey(Uint8Array.from(Buffer.from(encrypted.private_key, 'base64')) as Uint8Array<ArrayBuffer>)
    open.refreshAccess = async () => { open.archiveFor = () => fresh }
    expect(await refreshCurrentAccess()).toBe(true)
    expect(await archiveOpener()!.body(encrypted.message)).toEqual({ state: 'ok', value: encrypted.expected.body })
  })
})
