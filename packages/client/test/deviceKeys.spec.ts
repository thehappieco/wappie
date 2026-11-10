import { afterEach, beforeAll, beforeEach, expect, it, vi } from 'vitest'
import { withDeviceKey, withDeviceKeys } from '../src/api/auth.js'
import { fromBase64, parseUUID, toBase64, type Bytes } from '../src/crypto/bytes.js'
import { generateKeyPair } from '../src/crypto/hpke.js'
import { grantRow, Kind, sealDirect } from '../src/crypto/seal.js'
import { derive, freshSalt, wrapPrivateKey } from '../src/crypto/account.js'

// Counts derivations without changing them: a content consent for N numbers
// must cost the owner one Argon2id run, not N.
const spy = vi.hoisted(() => ({ derivations: 0 }))
vi.mock('../src/crypto/account.js', async importOriginal => {
  const real = await importOriginal<typeof import('../src/crypto/account.js')>()
  return { ...real, derive: async (...args: Parameters<typeof real.derive>) => { spy.derivations++; return real.derive(...args) } }
})

const tenant = '018f3a2b-2222-7000-8000-00000000bbbb'
const userID = '018f3a2b-2222-7000-8000-00000000aaaa'
const email = 'owner@example.test', password = 'synthetic archive password'
const devices = ['018f3a2b-2222-7000-8000-000000000d01', '018f3a2b-2222-7000-8000-000000000d02', '018f3a2b-2222-7000-8000-000000000d03']
const params = { alg: 'argon2id' as const, m: 32, t: 1, p: 1 }
let salt: Uint8Array, reply: Record<string, unknown>, dsks: Bytes[]
let calls: string[]

beforeAll(async () => {
  salt = freshSalt()
  const proof = await derive(password, salt, params)
  const owner = await generateKeyPair()
  dsks = devices.map((_, index) => new Uint8Array(32).fill(index + 1))
  const ns = parseUUID(tenant)
  const grants = await Promise.all(devices.map(async (device, index) => ({
    device_id: device, epoch: index + 2,
    sealed_dsk: toBase64(await sealDirect(owner.publicKey, Kind.DeviceGrant, ns, await grantRow(ns, parseUUID(device), parseUUID(userID), index + 2), index + 2, dsks[index]!)),
  })))
  reply = { user: { id: userID, tenant_id: tenant, email, public_key: toBase64(owner.publicKey), wrapped_usk: toBase64(await wrapPrivateKey(owner.privateKey, proof.wrapKey, email)) }, grants }
})
beforeEach(() => {
  spy.derivations = 0; calls = []
  vi.stubGlobal('fetch', vi.fn(async (url: string | URL) => {
    const path = new URL(url).pathname
    calls.push(path)
    return new Response(JSON.stringify(path.endsWith('/challenge') ? { salt: toBase64(salt), params } : reply), { status: 200 })
  }))
})
afterEach(() => vi.unstubAllGlobals())
const input = { serverURL: 'https://example.test', token: 'session', email, password }

it('opens N devices with one challenge, one derivation and one /auth/me, in order, zeroing each key after its use', async () => {
  const lent: { device: string; key: Bytes; copy: Bytes; live: number }[] = []
  let live = 0
  const results = await withDeviceKeys({ ...input, deviceIDs: [devices[2]!, devices[0]!, devices[1]!] }, async (device, key, epoch, archiveTenantID) => {
    live++
    lent.push({ device, key, copy: new Uint8Array(key), live })
    expect(archiveTenantID).toBe(tenant)
    live--
    return `${device}:${epoch}`
  })
  expect(results).toEqual([`${devices[2]}:4`, `${devices[0]}:2`, `${devices[1]}:3`])
  expect(lent.map(item => item.device)).toEqual([devices[2], devices[0], devices[1]])
  expect(lent.map(item => toBase64(item.copy))).toEqual([toBase64(dsks[2]!), toBase64(dsks[0]!), toBase64(dsks[1]!)])
  // Only one device key existed at a time, and none survives.
  expect(lent.every(item => item.live === 1)).toBe(true)
  for (const item of lent) expect(item.key.every(byte => byte === 0)).toBe(true)
  expect(spy.derivations).toBe(1)
  expect(calls).toEqual(['/v1/auth/challenge', '/v1/auth/me'])
})

it('refuses before any key is lent when one device has no grant', async () => {
  const use = vi.fn(async () => 'never')
  await expect(withDeviceKeys({ ...input, deviceIDs: [devices[0]!, '018f3a2b-2222-7000-8000-000000000dff'] }, use)).rejects.toMatchObject({ code: 'no_grant' })
  expect(use).not.toHaveBeenCalled()
  expect(spy.derivations).toBe(1)
})

it('refuses an empty, oversized or repeated device list before any network or derivation', async () => {
  const use = vi.fn(async () => 'never')
  const many = Array.from({ length: 101 }, (_, index) => `018f3a2b-2222-7000-8000-${index.toString(16).padStart(12, '0')}`)
  for (const deviceIDs of [[], many, [devices[0]!, devices[0]!], [''], 'not-a-list' as unknown as string[]]) {
    await expect(withDeviceKeys({ ...input, deviceIDs }, use)).rejects.toMatchObject({ code: 'invalid_devices' })
  }
  expect(calls).toEqual([]); expect(spy.derivations).toBe(0); expect(use).not.toHaveBeenCalled()
})

it('stops at the first failing use, with the keys lent so far already zeroed', async () => {
  const lent: Bytes[] = []
  await expect(withDeviceKeys({ ...input, deviceIDs: devices }, async (device, key) => {
    lent.push(key)
    if (device === devices[1]) throw new Error('grant refused')
    return device
  })).rejects.toThrow('grant refused')
  expect(lent).toHaveLength(2)
  for (const key of lent) expect(key.every(byte => byte === 0)).toBe(true)
})

it('keeps withDeviceKey as the one-device form of the same exchange', async () => {
  const opened = await withDeviceKey({ ...input, deviceID: devices[1]! }, async (key, epoch, archiveTenantID) => ({ key: toBase64(key), epoch, archiveTenantID }))
  expect(opened).toEqual({ key: toBase64(dsks[1]!), epoch: 3, archiveTenantID: tenant })
  expect(spy.derivations).toBe(1)
  expect(fromBase64(opened.key)).toHaveLength(32)
})
