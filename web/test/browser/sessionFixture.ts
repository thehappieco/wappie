// Synthetic identity only. No production account or credential is used.
import { derive, freshSalt, generateAccountKeys, wrapPrivateKey } from '../../src/crypto/account'
import { parseUUID, toBase64 } from '../../src/crypto/bytes'
import { grantRow, Kind, sealDirect } from '../../src/crypto/seal'

Object.assign(window, { async prepareLoginFixture() {
  const password = 'QA synthetic password only'
  const email = 'browser@example.test'
  const salt = freshSalt()
  const params = { alg: 'argon2id', m: 64 * 1024, t: 3, p: 1 }
  const keys = await generateAccountKeys()
  const derived = await derive(password, salt, params)
  const wrapped = await wrapPrivateKey(keys.privateKey, derived.wrapKey, email)
  keys.privateKey.fill(0)
  const user = { id: '018f3a2b-2222-7000-8000-00000000aaaa', tenant_id: '018f3a2b-2222-7000-8000-00000000bbbb',
    email, role: 'owner', has_recovery: true, public_key: toBase64(keys.publicKey), wrapped_usk: toBase64(wrapped) }
  const deviceID = '018f3a2b-2222-7000-8000-00000000dddd'
  const deviceKey = crypto.getRandomValues(new Uint8Array(32))
  const row = await grantRow(parseUUID(user.tenant_id), parseUUID(deviceID), parseUUID(user.id), 1)
  const sealed = await sealDirect(keys.publicKey, Kind.DeviceGrant, parseUUID(user.tenant_id), row, 1, deviceKey)
  deviceKey.fill(0)
  // Only synthetic authentication material, public metadata and ciphertext
  // reach the driver. Account/archive private keys are never returned.
  return { password, email, authKey: derived.authKey, challenge: { salt: toBase64(salt), params },
    reply: { user, token: 'synthetic-browser-QA-token', expires_at: new Date(Date.now() + 3600_000).toISOString() },
    grants: [{ device_id: deviceID, label: 'Test number', epoch: 1, sealed_dsk: toBase64(sealed) }] }
} })
