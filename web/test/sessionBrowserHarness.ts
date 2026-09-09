// Bundled only by the isolated browser regression harness; never shipped by Vite.
import { generateAccountKeys } from '../src/crypto/account'
import { importArchiveKey } from '../src/crypto/hpke'
import { parseUUID, toBase64 } from '../src/crypto/bytes'
import { grantRow, Kind, sealDirect } from '../src/crypto/seal'
import { fromAccount, restoreAccountSession, type Session } from '../src/state/session'
import type { SignedIn } from '../src/api/auth'

const userID = '018f3a2b-2222-7000-8000-00000000aaaa'
const tenantID = '018f3a2b-2222-7000-8000-00000000bbbb'
const deviceID = '018f3a2b-2222-7000-8000-00000000dddd'
let signed: SignedIn | undefined
let active: Session | null = null

Object.assign(window, { wappieSessionQA: {
  async prepare() {
    const pair = await generateAccountKeys()
    const accountKey = await importArchiveKey(pair.privateKey)
    pair.privateKey.fill(0)
    const device = crypto.getRandomValues(new Uint8Array(32))
    const row = await grantRow(parseUUID(tenantID), parseUUID(deviceID), parseUUID(userID), 1)
    const sealed = await sealDirect(pair.publicKey, Kind.DeviceGrant, parseUUID(tenantID), row, 1, device)
    device.fill(0)
    const expiresAt = new Date(Date.now() + 60_000)
    signed = { token: 'synthetic-browser-regression-token', expiresAt, email: 'browser@example.test', role: 'owner', tenantID, userID,
      hasRecovery: true, readable: [], accountKey }
    // Only public metadata and ciphertext leave the test page.
    return { user: { id: userID, tenant_id: tenantID, email: signed.email, role: 'owner', has_recovery: true,
      public_key: toBase64(pair.publicKey), wrapped_usk: 'opaque-test-wrap' }, expires_at: expiresAt.toISOString(),
      grants: [{ device_id: deviceID, label: 'Test number', epoch: 1, sealed_dsk: toBase64(sealed) }] }
  },
  async remember() {
    if (!signed) throw new Error('prepare first')
    active = fromAccount(signed, '')
    await active.remember?.()
    return true
  },
  async restore() {
    active = await restoreAccountSession()
    return { authenticated: Boolean(active), readable: active?.readable.length ?? 0,
      nonExtractable: active?.archiveFor(deviceID)?.key.extractable === false }
  },
  async logout() { await active?.close(); active = null },
} })
