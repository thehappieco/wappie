import { afterEach, expect, it, vi } from 'vitest'
import { generateAccountKeys } from '../src/crypto/account'
import { importArchiveKey } from '../src/crypto/hpke'
import { parseUUID, toBase64 } from '../src/crypto/bytes'
import { grantRow, Kind, sealDirect } from '../src/crypto/seal'
import { fromAccount } from '../src/state/session'

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

async function fixture() {
  const userID = crypto.randomUUID(), tenantID = crypto.randomUUID(), deviceID = crypto.randomUUID()
  const generated = await generateAccountKeys()
  const accountKey = await importArchiveKey(generated.privateKey)
  generated.privateKey.fill(0)
  const signed = { token: 'synthetic-token', expiresAt: new Date(Date.now() + 60_000), email: 'test@example.test', role: 'owner', userID, tenantID, hasRecovery: true, readable: [], accountKey }
  const deviceRaw = crypto.getRandomValues(new Uint8Array(32))
  const sealed = await sealDirect(generated.publicKey, Kind.DeviceGrant, parseUUID(tenantID), await grantRow(parseUUID(tenantID), parseUUID(deviceID), parseUUID(userID), 1), 1, deviceRaw)
  deviceRaw.fill(0)
  const me = { user: { id: userID, tenant_id: tenantID, email: signed.email, role: 'owner', public_key: toBase64(generated.publicKey), wrapped_usk: '', has_recovery: true }, grants: [{ device_id: deviceID, label: 'New number', epoch: 1, sealed_dsk: toBase64(sealed) }] }
  vi.stubGlobal('location', new URL('https://selfhost.example.test'))
  return { session: fromAccount(signed, 'https://selfhost.example.test'), me, deviceID }
}

it('opens a newly granted number without another password and coalesces concurrent refreshes', async () => {
  const { session, me, deviceID } = await fixture()
  expect(session.archiveFor(deviceID)).toBeUndefined()
  const request = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(me)))
  await Promise.all([session.refreshAccess!(), session.refreshAccess!()])
  expect(request).toHaveBeenCalledTimes(1)
  expect(session.archiveFor(deviceID)?.key.extractable).toBe(false)
  expect(session.readable).toEqual([{ deviceID, label: 'New number' }])
  const liveKey = session.archiveFor(deviceID)
  request.mockResolvedValueOnce(new Response(JSON.stringify(me)))
  await session.refreshAccess!()
  expect(session.archiveFor(deviceID)).toBe(liveKey)
  request.mockResolvedValueOnce(new Response(JSON.stringify({ ...me, grants: [] })))
  await session.refreshAccess!()
  expect(session.archiveFor(deviceID)).toBeUndefined()
  expect(session.readable).toEqual([])
  session.dispose!()
})

it('rejects foreign workspace metadata and drops late results after logout/navigation', async () => {
  const { session, me, deviceID } = await fixture()
  const request = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({ ...me, user: { ...me.user, tenant_id: crypto.randomUUID() } })))
  await expect(session.refreshAccess!()).rejects.toMatchObject({ code: 'unauthorized' })
  expect(session.archiveFor(deviceID)).toBeUndefined()
  let respond!: (r: Response) => void
  request.mockImplementationOnce(() => new Promise(resolve => { respond = resolve }))
  const pending = session.refreshAccess!()
  session.dispose!()
  respond(new Response(JSON.stringify(me)))
  await pending
  expect(session.archiveFor(deviceID)).toBeUndefined()
  expect(session.readable).toEqual([])
})
