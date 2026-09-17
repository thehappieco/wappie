import { afterEach, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { refreshAccountAccess, withDeviceKey } from '../src/api/auth.js'
import { Opener } from '../src/api/opener.js'
import { fromBase64, parseUUID, toBase64 } from '../src/crypto/bytes.js'
import { generateKeyPair, importArchiveKey } from '../src/crypto/hpke.js'
import { grantRow, Kind, openDirect, sealDirect } from '../src/crypto/seal.js'
import { derive, freshSalt, wrapPrivateKey } from '../src/crypto/account.js'

const personal = '018f3a2b-2222-7000-8000-00000000bbbb'
const userID = '018f3a2b-2222-7000-8000-00000000aaaa'
const vector = JSON.parse(readFileSync(new URL('../../../internal/crypto/seal/testdata/vectors.json', import.meta.url), 'utf8'))
afterEach(() => vi.unstubAllGlobals())

it('opens a grant sealed before moving the number to Personal', async () => {
  const userKeys = await generateKeyPair()
  const userKey = await importArchiveKey(userKeys.privateKey)
  const row = await grantRow(parseUUID(vector.tenant), parseUUID(vector.device), parseUUID(userID), 1)
  const sealed = await sealDirect(userKeys.publicKey, Kind.DeviceGrant, parseUUID(vector.tenant), row, 1, fromBase64(vector.private_key))
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
    user: { id: userID, tenant_id: personal, email: 'owner@example.test', role: 'owner', public_key: toBase64(userKeys.publicKey), has_recovery: true },
    grants: [{ device_id: vector.device, archive_tenant_id: vector.tenant, label: 'Transferred number', epoch: 1, sealed_dsk: toBase64(sealed) }],
  }), { status: 200 })))
  const signed = await refreshAccountAccess('https://example.test', 'session', userKey, userID, personal)
  expect(signed.tenantID).toBe(personal)
  expect(signed.readable).toHaveLength(1)
  expect(signed.readable[0].archiveTenantID).toBe(vector.tenant)
  expect(toBase64(signed.readable[0].archive.publicRaw)).toBe(vector.public_key)
})

it('opens historical Go ciphertext with key-response namespace after a move', async () => {
  const request = vi.fn(async () => ({ device_id: vector.device, archive_tenant_id: vector.tenant, keys: [vector.content_key] }))
  const opener = new Opener({ request }, parseUUID(personal), parseUUID(vector.device), vector.device, await importArchiveKey(fromBase64(vector.private_key)))
  const body = vector.batch.find((item: { kind: number }) => item.kind === Kind.Body)
  expect(await opener.raw(vector.content_key.id, body.row, Kind.Body, body.sealed)).toEqual({ state: 'ok', value: fromBase64(body.plaintext) })
})

it('grants access after transfer using the original archive namespace', async () => {
  const email = 'owner@example.test', password = 'test archive password'
  const salt = freshSalt(), params = { alg: 'argon2id' as const, m: 32, t: 1, p: 1 }
  const proof = await derive(password, salt, params)
  const owner = await generateKeyPair(), recipient = await generateKeyPair()
  const originalTenant = parseUUID(vector.tenant), device = parseUUID(vector.device)
  const original = await sealDirect(owner.publicKey, Kind.DeviceGrant, originalTenant,
    await grantRow(originalTenant, device, parseUUID(userID), 1), 1, fromBase64(vector.private_key))
  const wrapped = await wrapPrivateKey(owner.privateKey, proof.wrapKey, email)
  vi.stubGlobal('fetch', vi.fn(async (url: string | URL) => new Response(JSON.stringify(new URL(url).pathname.endsWith('/challenge')
    ? { salt: toBase64(salt), params }
    : { user: { id: userID, tenant_id: personal, email, public_key: toBase64(owner.publicKey), wrapped_usk: toBase64(wrapped) },
        grants: [{ device_id: vector.device, archive_tenant_id: vector.tenant, epoch: 1, sealed_dsk: toBase64(original) }] }), { status: 200 })))
  const recipientID = parseUUID('018f3a2b-2222-7000-8000-00000000cccc')
  const sealed = await withDeviceKey({ serverURL: 'https://example.test', token: 'session', email, password, deviceID: vector.device }, async (raw, epoch, archiveTenantID) => {
    expect(archiveTenantID).toBe(vector.tenant)
    const namespace = parseUUID(archiveTenantID)
    return sealDirect(recipient.publicKey, Kind.DeviceGrant, namespace, await grantRow(namespace, device, recipientID, epoch), epoch, raw)
  })
  const opened = await openDirect(await importArchiveKey(recipient.privateKey), Kind.DeviceGrant, originalTenant,
    await grantRow(originalTenant, device, recipientID, 1), sealed)
  expect(toBase64(opened)).toBe(vector.private_key)
})
