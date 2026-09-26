import { test } from 'node:test'
import assert from 'node:assert/strict'
import { bundleSchema, contentBundleSchema, validateBundle, validateContentBundle, CONTENT_CONSENT_VERSION } from '../bundle.mjs'

const workspace = '018f3a2b-2222-7000-8000-00000000bbbb'
const device = '018f3a2b-2222-7000-8000-00000000dddd'
const token = `a1b2c3d4.${Buffer.alloc(32, 42).toString('base64url')}`
const linkSecret = Buffer.alloc(32, 7).toString('base64url')
const bundle = () => ({ version: 1, server_url: 'https://archive.example.test', workspace_id: workspace, device_ids: [device], token, allow_plaintext: false })

test('the shared bundle schema accepts an optional hosted link secret and maps to a file-mode config', async () => {
  const plain = await validateBundle(bundle())
  assert.equal(plain.bundle.link_secret, undefined)
  assert.deepEqual(plain.output, { server: 'https://archive.example.test', workspace, device_ids: [device], token_file: './token.txt', allow_plaintext: false })
  const hosted = await validateBundle({ ...bundle(), link_secret: linkSecret, timezone: 'America/Sao_Paulo' })
  assert.equal(hosted.bundle.link_secret, linkSecret)
  assert.equal(hosted.output.timezone, 'America/Sao_Paulo')
  assert.equal('link_secret' in hosted.output, false)
  assert.equal(bundleSchema.safeParse({ ...bundle(), link_secret: linkSecret }).success, true)
  for (const bad of ['', linkSecret.slice(1), linkSecret + 'A', linkSecret.slice(0, 42) + '=', linkSecret.slice(0, 42) + '+', 7]) {
    await assert.rejects(validateBundle({ ...bundle(), link_secret: bad }), { code: 'invalid_bundle' })
  }
  await assert.rejects(validateBundle({ ...bundle(), allow_plaintext: true }), { code: 'invalid_bundle' })
  await assert.rejects(validateBundle({ ...bundle(), token: token.slice(0, 51) + '=' }), { code: 'invalid_bundle' })
  await assert.rejects(validateBundle({ ...bundle(), server_url: 'http://remote.example.test' }), { code: 'invalid_server' })
})

const now = Date.parse('2026-09-26T12:00:00.000Z')
const service = '018f3a2b-2222-7000-8000-00000000aaaa'
const connection = '0190a0e0-0000-7000-8000-000000000001'
const day = 24 * 60 * 60 * 1000
const consent = () => ({ version: 2, kind: 'content', purpose: 'consent', server_url: 'https://mcp.wappie.thehappie.co',
  workspace_id: workspace, service_user_id: service, device_ids: [device], token, key_mode: 'ephemeral',
  consent_version: 1, expires_at: new Date(now + 30 * day).toISOString(), timezone: 'America/Sao_Paulo', link_secret: linkSecret })
const renewal = () => { const value = { ...consent(), purpose: 'renewal', connection_id: connection }; delete value.link_secret; return value }

test('content bundle v2 accepts a consent and a renewal and returns them frozen', () => {
  assert.equal(CONTENT_CONSENT_VERSION, 1)
  const accepted = validateContentBundle(consent(), now)
  assert.ok(Object.isFrozen(accepted) && Object.isFrozen(accepted.device_ids))
  assert.equal(accepted.link_secret, linkSecret)
  assert.equal(accepted.connection_id, undefined)
  const renewed = validateContentBundle(renewal(), now)
  assert.equal(renewed.connection_id, connection)
  assert.equal(renewed.link_secret, undefined)
  const upper = validateContentBundle({ ...consent(), workspace_id: workspace.toUpperCase(), service_user_id: service.toUpperCase(), device_ids: [device.toUpperCase()] }, now)
  assert.deepEqual([upper.workspace_id, upper.service_user_id, upper.device_ids[0]], [workspace, service, device])
  const untimed = consent(); delete untimed.timezone
  assert.equal(validateContentBundle(untimed, now).timezone, undefined)
  // The limits: 100 numbers, 90 days and an hour ahead, 40 characters.
  const many = Array.from({ length: 100 }, (_, index) => `018f3a2b-2222-7000-8000-${String(index).padStart(12, '0')}`)
  assert.equal(validateContentBundle({ ...consent(), device_ids: many }, now).device_ids.length, 100)
  assert.ok(validateContentBundle({ ...consent(), expires_at: new Date(now + 90 * day + 60 * 60 * 1000).toISOString() }, now))
  assert.ok(validateContentBundle({ ...consent(), expires_at: '2026-10-26T12:00:00.123456789Z' }, now))
})

test('content bundle v2 never carries a service key, contacts or a plaintext flag, and refuses every other deviation', () => {
  const invalid = (value, label) => assert.throws(() => validateContentBundle(value, now), error => error.code === 'invalid_bundle' && !error.message.includes(token), label)
  for (const extra of [{ service_private_key: Buffer.alloc(32, 9).toString('base64url') }, { contacts: { version: 1 } }, { contacts: null },
    { allow_plaintext: true }, { allow_plaintext: false }, { key: 'value' }]) invalid({ ...consent(), ...extra }, Object.keys(extra)[0])
  const many = Array.from({ length: 101 }, (_, index) => `018f3a2b-2222-7000-8000-${String(index).padStart(12, '0')}`)
  for (const [label, override] of Object.entries({
    v1: { version: 1 }, v3: { version: 3 }, metadata: { kind: 'metadata' }, purpose: { purpose: 'upgrade' },
    persisted: { key_mode: 'persisted' }, consent_version: { consent_version: 2 }, consent_string: { consent_version: '1' },
    http: { server_url: 'http://mcp.wappie.thehappie.co' }, localhost: { server_url: 'http://localhost:8080' }, path: { server_url: 'https://mcp.wappie.thehappie.co/mcp' },
    slash: { server_url: 'https://mcp.wappie.thehappie.co/' }, userinfo: { server_url: 'https://user@mcp.wappie.thehappie.co' },
    workspace: { workspace_id: 'not-a-uuid' }, service: { service_user_id: undefined }, no_devices: { device_ids: [] }, too_many: { device_ids: many },
    duplicate: { device_ids: [device, device.toUpperCase()] }, token_short: { token: token.slice(0, 51) }, token_prefix: { token: `A1B2C3D4.${token.slice(9)}` },
    token_noncanonical: { token: token.slice(0, 51) + 'r' }, past: { expires_at: new Date(now - 1000).toISOString() }, now: { expires_at: new Date(now).toISOString() },
    too_far: { expires_at: new Date(now + 90 * day + 60 * 60 * 1000 + 1000).toISOString() }, offset: { expires_at: '2026-10-26T12:00:00+00:00' },
    local_time: { expires_at: '2026-10-26T12:00:00' }, impossible: { expires_at: '2026-02-30T12:00:00Z' }, long: { expires_at: '2026-10-26T12:00:00.1234567890123456789012345Z' },
    timezone: { timezone: 'Mars/Olympus' }, timezone_long: { timezone: 'x'.repeat(101) }, timezone_empty: { timezone: '' },
    no_link_secret: { link_secret: undefined }, link_secret_short: { link_secret: linkSecret.slice(1) }, link_secret_noncanonical: { link_secret: linkSecret.slice(0, 42) + 'B' },
    consent_with_connection: { connection_id: connection },
  })) invalid({ ...consent(), ...override }, label)
  invalid({ ...renewal(), link_secret: linkSecret }, 'renewal with a link secret')
  invalid({ ...renewal(), connection_id: undefined }, 'renewal without a connection')
  invalid({ ...renewal(), connection_id: 'not-a-uuid' }, 'renewal with a bad connection')
  for (const bad of [null, [], 'bundle', 2]) invalid(bad, String(bad))
})

test('v1 and v2 never accept each other: no v1 path can open a content bundle', async () => {
  await assert.rejects(validateBundle(consent()), { code: 'invalid_bundle' })
  await assert.rejects(validateBundle({ ...consent(), version: 1 }), { code: 'invalid_bundle' })
  assert.equal(bundleSchema.safeParse(consent()).success, false)
  assert.equal(contentBundleSchema.safeParse(bundle()).success, false)
  assert.equal(contentBundleSchema.safeParse({ ...bundle(), version: 2 }).success, false)
  assert.throws(() => validateContentBundle({ ...bundle(), link_secret: linkSecret }, now), { code: 'invalid_bundle' })
})
