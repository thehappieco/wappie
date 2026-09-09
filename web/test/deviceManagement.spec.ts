import { beforeEach, describe, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({
  request: vi.fn(), send: vi.fn(), stream: vi.fn(), refresh: vi.fn(), generate: vi.fn(),
  state: { tenantID: '0194d4a0-0000-7000-8000-000000000001', role: 'owner', account: 'owner@example.test', devices: [] as unknown[] },
}))
vi.mock('../src/state/archive', async () => { const { reactive } = await import('vue'); return ({ state: reactive(mocks.state), connection: () => ({ request: mocks.request, send: mocks.send, stream: mocks.stream }), refreshDevices: mocks.refresh, credential: vi.fn() }) })
vi.mock('../src/api/auth', () => ({ withDeviceKey: vi.fn() }))
vi.mock('../src/crypto/hpke', () => ({ generateKeyPair: mocks.generate }))
vi.mock('../src/crypto/seal', () => ({ grantRow: vi.fn(async () => new Uint8Array(16)), Kind: { DeviceGrant: 8 }, sealDirect: vi.fn(async () => new Uint8Array(32)) }))
import { admin, cancelPairing, pair, removeDevice, openDetail, closeDetail } from '../src/state/admin'
import * as P from '../src/api/protocol'
import { state } from '../src/state/archive'
const device = '0194d4a0-0000-7000-8000-000000000002'
const input = { method: 'qr' as const, phone: '', label: 'Test', grantTo: ['0194d4a0-0000-7000-8000-000000000003'], receiptMode: 'passive' as const }
beforeEach(() => {
  state.account = 'owner@example.test'; state.phase = 'ready'
  cancelPairing(); vi.clearAllMocks()
  admin.deviceBusy = false; admin.detailError = ''; admin.removed = null
  admin.accounts = [{ id: input.grantTo[0]!, email: mocks.state.account, role: 'owner', public_key: btoa(String.fromCharCode(...new Uint8Array(32))) }]
  mocks.refresh.mockResolvedValue(undefined)
  mocks.stream.mockReturnValue(vi.fn())
})
describe('device lifecycle', () => {
  it('does not pair after cancellation while generating the encryption key', async () => {
    let release!: (value: {privateKey: Uint8Array; publicKey: Uint8Array}) => void
    mocks.generate.mockReturnValue(new Promise(resolve => { release = resolve }))
    const pending = pair(input)
    cancelPairing()
    const privateKey = new Uint8Array(32).fill(7)
    release({privateKey, publicKey: new Uint8Array(32)})
    await pending
    expect(mocks.stream).not.toHaveBeenCalled()
    expect(privateKey.every(x => x === 0)).toBe(true)
    expect(admin.pairing.phase).toBe('idle')
  })
  it('retries a pending row without generating or replacing its encryption key', async () => {
    await pair({...input, existingDeviceID: device})
    expect(mocks.generate).not.toHaveBeenCalled()
    expect(mocks.stream).toHaveBeenCalledWith(P.TypePair, expect.objectContaining({device_id: device, resume: true}), expect.any(Function))
    const payload = mocks.stream.mock.calls[0]![1]
    expect(payload).not.toHaveProperty('archive_public_key')
    expect(payload).not.toHaveProperty('grants')
  })
  it('ignores a QR update from a cancelled attempt', async () => {
    await pair({...input, existingDeviceID: device})
    const update = mocks.stream.mock.calls[0]![2]
    cancelPairing()
    update({t: P.TypePairQR, p: {code: 'obsolete', expires: new Date().toISOString()}})
    expect(admin.pairing.qr).toBe('')
  })
  it('requests WhatsApp logout by default when permanently deleting', async () => {
    mocks.request.mockResolvedValue({device_id: device, chats:0,messages:0,media:0,unlinked:true})
    expect(await removeDevice(device)).toBe(true)
    expect(mocks.request).toHaveBeenCalledWith(P.TypeDeviceDelete, {device_id:device,confirm:device,unlink:true},P.TypeDeviceGone)
  })
  it('keeps the confirmation dialog and exposes a failed deletion for retry', async () => {
    const detail = { device: {id:device} } as P.DeviceDetail
    admin.detail = detail
    mocks.request.mockRejectedValue(new Error('Temporarily unavailable'))
    expect(await removeDevice(device)).toBe(false)
    expect(admin.detail?.device.id).toBe(device)
    expect(admin.detailError).toBe('Temporarily unavailable')
    expect(admin.deviceBusy).toBe(false)
  })
})

function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done }); return {promise, resolve} }
describe('late device responses', () => {
  it('does not replace a newer device detail with an earlier response', async () => {
    const old = deferred<P.DeviceDetail>(); const latest = deferred<P.DeviceDetail>()
    mocks.request.mockReturnValueOnce(old.promise).mockReturnValueOnce(latest.promise)
    const first = openDetail(device); const secondID = '0194d4a0-0000-7000-8000-000000000009'
    const second = openDetail(secondID)
    latest.resolve({device:{id:secondID}} as P.DeviceDetail); await second
    old.resolve({device:{id:device}} as P.DeviceDetail); await first
    expect(admin.detail?.device.id).toBe(secondID)
  })
  it('does not reopen a closed detail', async () => {
    const response = deferred<P.DeviceDetail>(); mocks.request.mockReturnValueOnce(response.promise)
    const pending = openDetail(device); closeDetail()
    response.resolve({device:{id:device}} as P.DeviceDetail); await pending
    expect(admin.detail).toBeNull(); expect(admin.detailLoading).toBe(false)
  })
  it('does not publish a previous user’s device after signout', async () => {
    const response = deferred<P.DeviceDetail>(); mocks.request.mockReturnValueOnce(response.promise)
    const pending = openDetail(device); state.account = ''; state.phase = 'locked'
    response.resolve({device:{id:device}} as P.DeviceDetail); await pending
    expect(admin.detail).toBeNull(); expect(admin.detailLoading).toBe(false)
  })
})
