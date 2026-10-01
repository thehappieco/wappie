import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { canonicalJSON } from '@whatserver2/client/crypto/jcs'
import {
  bundleSchema, contentBundleSchema, deviceCheck, deviceScope, formatAddress, inNetwork, parseAddress, parseCIDR, validateBundle, validateContentBundle,
  validateLinkBundleV2, validateTokenBundle, CONSOLE_TOKEN_CLIENT_ID, CONTENT_CONSENT_VERSIONS, SEND_MODES,
} from '../bundle.mjs'

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
  assert.deepEqual(CONTENT_CONSENT_VERSIONS, [1, 2, 3, 4])
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
    persisted: { key_mode: 'persisted' }, consent_v3_without_send: { consent_version: 3 }, consent_v4: { consent_version: 4 }, consent_zero: { consent_version: 0 }, consent_string: { consent_version: '1' },
    media_v1: { media: true }, media_string: { consent_version: 2, media: 'true' }, media_null: { consent_version: 2, media: null },
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

test('consent version 2 (docs/mcp-enclave.md §16.2): with or without media, and media never on version 1', () => {
  const text = validateContentBundle({ ...consent(), consent_version: 2 }, now)
  assert.equal(text.consent_version, 2)
  assert.equal(text.media, undefined, 'absent means a text connection')
  const media = validateContentBundle({ ...consent(), consent_version: 2, media: true }, now)
  assert.equal(media.media, true)
  assert.equal(validateContentBundle({ ...consent(), consent_version: 2, media: false }, now).media, false)
  assert.equal(validateContentBundle({ ...consent(), media: false }, now).media, false, 'a version-1 bundle may say false')
  assert.equal(validateContentBundle({ ...renewal(), consent_version: 2, media: true }, now).media, true, 'a renewal seals the consent again')
  for (const bad of [{ media: true }, { consent_version: 1, media: true }]) {
    assert.throws(() => validateContentBundle({ ...consent(), ...bad }, now), { code: 'invalid_bundle' }, JSON.stringify(bad))
    assert.equal(contentBundleSchema.safeParse({ ...consent(), ...bad }).success, false)
  }
})

// ---- Consent version 3: sending (docs/mcp-enclave.md §17.2) ----------------------------

const check = Buffer.alloc(32, 5).toString('base64url')
const sending = (fields = {}) => ({ ...consent(), consent_version: 3, send: 'draft', device_checks: { [device]: check }, ...fields })

test('consent version 3 carries drafts, and may add the own chat, groups and attachments', () => {
  assert.deepEqual(SEND_MODES, ['draft'])
  const drafts = validateContentBundle(sending(), now)
  assert.deepEqual([drafts.consent_version, drafts.send, drafts.send_self, drafts.send_groups, drafts.media], [3, 'draft', undefined, undefined, undefined])
  assert.ok(Object.isFrozen(drafts.device_checks))
  assert.deepEqual(drafts.device_checks, { [device]: check })
  const all = validateContentBundle(sending({ send_self: true, send_groups: true, media: true }), now)
  assert.deepEqual([all.send_self, all.send_groups, all.media], [true, true, true])
  assert.equal(validateContentBundle(sending({ send_self: false, send_groups: false }), now).send_self, false)
  assert.equal(validateContentBundle({ ...renewal(), consent_version: 3, send: 'draft', send_self: true, device_checks: { [device]: check } }, now).send_self, true, 'a renewal seals the send fields again')
  const two = '018f3a2b-2222-7000-8000-0000000000d2'
  assert.ok(validateContentBundle(sending({ device_ids: [device, two], device_checks: { [two]: check, [device]: Buffer.alloc(32, 6).toString('base64url') } }), now))
})

test('the version 3 matrix: sending and its checks come with version 3 and only with it, and 0.5.0 refuses direct send', () => {
  const invalid = (value, label) => assert.throws(() => validateContentBundle(value, now), error => error.code === 'invalid_bundle', label)
  const two = '018f3a2b-2222-7000-8000-0000000000d2'
  for (const [label, value] of Object.entries({
    v3_without_send: { ...sending(), send: undefined },
    v3_without_checks: { ...sending(), device_checks: undefined },
    v3_with_neither: { ...sending(), send: undefined, device_checks: undefined },
    send_on_v2: sending({ consent_version: 2 }), send_on_v1: sending({ consent_version: 1 }),
    checks_on_v2: { ...consent(), consent_version: 2, device_checks: { [device]: check } },
    send_self_without_send: { ...consent(), consent_version: 2, send_self: true },
    send_groups_without_send: { ...consent(), send_groups: false },
    send_self_on_v3_without_send: { ...sending(), send: undefined, send_self: true },
    direct: sending({ send: 'direct' }), none: sending({ send: 'none' }), send_true: sending({ send: true }),
    send_chats: sending({ send_chats: [{ device_id: device, chat_key: '5511999990000@s.whatsapp.net' }] }),
    send_chats_empty: sending({ send_chats: [] }),
    send_signature: sending({ send_signature: '— enviado pelo assistente de Ana' }),
    send_self_string: sending({ send_self: 'true' }), send_groups_null: sending({ send_groups: null }),
    check_missing: sending({ device_ids: [device, two] }),
    check_extra: sending({ device_checks: { [device]: check, [two]: check } }),
    check_other_number: sending({ device_checks: { [two]: check } }),
    check_upper_key: sending({ device_checks: { [device.toUpperCase()]: check } }),
    check_short: sending({ device_checks: { [device]: check.slice(1) } }),
    check_long: sending({ device_checks: { [device]: check + 'A' } }),
    check_noncanonical: sending({ device_checks: { [device]: check.slice(0, 42) + 'B' } }),
    check_padded: sending({ device_checks: { [device]: Buffer.alloc(32, 5).toString('base64') } }),
    check_not_string: sending({ device_checks: { [device]: 7 } }),
    checks_array: sending({ device_checks: [check] }),
  })) invalid(value, label)
})

const shared = JSON.parse(await readFile(new URL('../../mcp-http/enclave/test/device-check-vectors.json', import.meta.url), 'utf8'))
/** Version 3's vectors, then version 4's (§19.15), which the file keeps apart. */
const vectors = [...shared.vectors, ...shared.version_4]

test('the device check reproduces the shared vectors, scope and HMAC (§17.2 rule 3)', () => {
  assert.ok(vectors.length >= 3)
  for (const v of vectors) {
    const scope = deviceScope(v.bundle, { deviceID: v.device_id, epoch: v.epoch, request: v.request, kid: v.kid })
    assert.equal(canonicalJSON(scope), v.scope_jcs, v.name)
    const dsk = Buffer.from(v.dsk, 'base64url')
    assert.equal(deviceCheck(dsk, { namespace: v.namespace, deviceID: v.device_id, epoch: v.epoch, scope }), v.check, v.name)
    assert.deepEqual([...dsk], [...Buffer.from(v.dsk, 'base64url')], 'the DSK is the caller\'s and is left as it was')
  }
})

test('the device check changes with every field of the scope, the key, the namespace and the epoch', () => {
  const v = vectors[0]
  const dsk = Buffer.from(v.dsk, 'base64url')
  const at = { deviceID: v.device_id, epoch: v.epoch, request: v.request, kid: v.kid }
  const of = (bundle, where = at, { namespace = v.namespace, key = dsk } = {}) => deviceCheck(key, { namespace, deviceID: where.deviceID, epoch: where.epoch, scope: deviceScope(bundle, where) })
  assert.equal(of(v.bundle), v.check)
  const changed = {
    expiry: of({ ...v.bundle, expires_at: '2026-10-28T12:00:01.000Z' }), media: of({ ...v.bundle, media: true }),
    devices: of({ ...v.bundle, device_ids: [v.device_id] }), self: of({ ...v.bundle, send_self: true }), groups: of({ ...v.bundle, send_groups: true }),
    service: of({ ...v.bundle, service_user_id: '0199b3c4-0000-7000-8000-00000000beef' }), workspace: of({ ...v.bundle, workspace_id: '0199b3c4-0000-7000-8000-00000000f00d' }),
    request: of(v.bundle, { ...at, request: 'BBECAwQFBgcICQoLDA0ODw' }), kid: of(v.bundle, { ...at, kid: '0000000000000000' }),
    epoch: of(v.bundle, { ...at, epoch: v.epoch + 1 }), namespace: of(v.bundle, at, { namespace: '0199b3c4-aaaa-7bbb-8ccc-ddddeeeeffff' }),
    key: of(v.bundle, at, { key: Buffer.alloc(32, 1) }),
    direct_fields: of({ ...v.bundle, send_chats: [{ device_id: v.device_id, chat_key: 'x@s.whatsapp.net' }] }),
    signature: of({ ...v.bundle, send_signature: 'x' }),
  }
  for (const [label, value] of Object.entries(changed)) assert.notEqual(value, v.check, label)
  assert.equal(new Set(Object.values(changed)).size, Object.keys(changed).length)
  // Another number's chats are not this number's scope.
  assert.equal(of({ ...v.bundle, send_chats: [{ device_id: '0199b3c4-0000-7000-8000-000000000001', chat_key: 'x@s.whatsapp.net' }] }), v.check)
  for (const bad of [Buffer.alloc(31), 'x'.repeat(32), null]) assert.throws(() => deviceCheck(bad, { namespace: v.namespace, deviceID: v.device_id, epoch: v.epoch, scope: deviceScope(v.bundle, at) }), { code: 'invalid_bundle' })
  for (const epoch of [0, 65536, 1.5]) assert.throws(() => deviceCheck(dsk, { namespace: v.namespace, deviceID: v.device_id, epoch, scope: deviceScope(v.bundle, at) }), { code: 'invalid_bundle' })
})

// ---- Consent version 4, link bundle v2 and the console token (docs/mcp-enclave.md §19.15, §19.18) ----

const bearer = 'a60aed65d2620a197e14f253c6406048e638b0cc9d9e437b01fd7476bf167966'
const tested = (fields = {}) => ({ ...consent(), consent_version: 4, device_checks: { [device]: check }, client_id: 'https://claude.ai/oauth/mcp-oauth-client-metadata',
  client_kind: 'cimd', client_local: false, trust: 'tested', started_ack: true, unknown_ack: false, history_days: null, ...fields })
const unknown = (fields = {}) => tested({ client_id: 'https://agent.example.com/oauth/client.json', client_local: true, trust: 'unknown', unknown_ack: true, history_days: 30, ...fields })
const tokenConsent = (fields = {}) => {
  const { link_secret: _secret, ...base } = unknown({ client_id: CONSOLE_TOKEN_CLIENT_ID, client_kind: 'token', client_local: false, history_days: 7 })
  return { ...base, purpose: 'token', bearer_sha256: bearer, allowed_networks: ['198.51.100.0/24', '2001:db8::/48'], ...fields }
}

test('consent version 4 (§19.15): the client it was given to, the tier, the ticks, the window and the device checks', () => {
  const web = validateContentBundle(tested({ send: 'draft', send_self: true, media: true }), now)
  assert.deepEqual([web.consent_version, web.trust, web.client_kind, web.started_ack, web.unknown_ack, web.history_days, web.send], [4, 'tested', 'cimd', true, false, null, 'draft'])
  assert.equal(validateContentBundle(tested(), now).send, undefined, 'text alone still carries the device checks')
  const text = validateContentBundle(unknown({ media: true }), now)
  assert.deepEqual([text.trust, text.unknown_ack, text.history_days, text.client_local], ['unknown', true, 30, true])
  const renewed = validateContentBundle({ ...unknown(), purpose: 'renewal', connection_id: connection, link_secret: undefined }, now)
  assert.equal(renewed.purpose, 'renewal')
  const token = validateContentBundle(tokenConsent(), now)
  assert.deepEqual([token.purpose, token.client_id, token.bearer_sha256, token.allowed_networks], ['token', CONSOLE_TOKEN_CLIENT_ID, bearer, ['198.51.100.0/24', '2001:db8::/48']])
  assert.ok(Object.isFrozen(token.allowed_networks))
  assert.equal(validateContentBundle(tokenConsent({ allowed_networks: [] }), now).allowed_networks.length, 0, 'no networks: any network')
})

test('the version 4 matrix: every member with version 4 only, sending for a tested web client only, the second tick and the window for an unknown one, a token as §19.18 has it', () => {
  const invalid = (value, label) => assert.throws(() => validateContentBundle(value, now), error => error.code === 'invalid_bundle', label)
  for (const name of ['client_id', 'client_kind', 'client_local', 'trust', 'started_ack', 'unknown_ack', 'history_days']) {
    invalid(tested({ [name]: undefined }), `version 4 without ${name}`)
    invalid({ ...sending(), [name]: tested()[name] }, `${name} on version 3`)
  }
  for (const [label, value] of Object.entries({
    without_checks: tested({ device_checks: undefined }),
    started_false: tested({ started_ack: false }),
    send_unknown: unknown({ send: 'draft' }), send_local: tested({ client_local: true, send: 'draft' }),
    send_token: tokenConsent({ send: 'draft' }), self_without_send: tested({ send_self: true }),
    unknown_without_tick: unknown({ unknown_ack: false }), unknown_whole_history: unknown({ history_days: null }),
    tested_window: tested({ history_days: 30 }), window_zero: unknown({ history_days: 0 }), window_long: unknown({ history_days: 367 }), window_float: unknown({ history_days: 7.5 }),
    kind_other: tested({ client_kind: 'legacy' }), trust_other: tested({ trust: 'trusted' }),
    token_kind_other_id: tested({ client_kind: 'token' }), token_id_other_kind: tested({ client_id: CONSOLE_TOKEN_CLIENT_ID }),
    client_id_long: tested({ client_id: 'https://example.com/' + 'é'.repeat(250) }), client_id_empty: tested({ client_id: '' }),
    bearer_on_consent: tested({ bearer_sha256: bearer }), networks_on_consent: tested({ allowed_networks: [] }),
    token_without_bearer: tokenConsent({ bearer_sha256: undefined }), token_without_networks: tokenConsent({ allowed_networks: undefined }),
    token_bearer_upper: tokenConsent({ bearer_sha256: bearer.toUpperCase() }), token_link_secret: tokenConsent({ link_secret: linkSecret }),
    token_connection: tokenConsent({ connection_id: connection }), token_tested: tokenConsent({ trust: 'tested', unknown_ack: false, history_days: null }),
    token_local: tokenConsent({ client_local: true }), token_version_3: { ...tokenConsent(), consent_version: 3, send: 'draft' },
    token_other_client: tokenConsent({ client_id: 'https://agent.example.com/oauth/client.json', client_kind: 'cimd' }),
    networks_unsorted: tokenConsent({ allowed_networks: ['2001:db8::/48', '198.51.100.0/24'] }), networks_twice: tokenConsent({ allowed_networks: ['198.51.100.0/24', '198.51.100.0/24'] }),
    networks_eleven: tokenConsent({ allowed_networks: Array.from({ length: 11 }, (_, n) => `10.${n}.0.0/16`).sort() }),
    network_host_bits: tokenConsent({ allowed_networks: ['198.51.100.1/24'] }), network_not_canonical: tokenConsent({ allowed_networks: ['2001:0db8::/48'] }),
    network_no_prefix: tokenConsent({ allowed_networks: ['198.51.100.0'] }), network_mapped: tokenConsent({ allowed_networks: ['::ffff:198.51.100.0/120'] }),
  })) invalid(value, label)
})

test('the version-4 device scope adds the client, the tier, the ticks, the window and a token\'s hash and networks, each null when absent, and each changes the check', () => {
  const v4 = shared.version_4
  assert.equal(v4.length, 3)
  assert.ok(v4.every(v => v.bundle.consent_version === 4) && shared.vectors.every(v => v.bundle.consent_version === 3))
  const v = v4[0], dsk = Buffer.from(v.dsk, 'base64url')
  const at = { deviceID: v.device_id, epoch: v.epoch, request: v.request, kid: v.kid }
  const scope = deviceScope(v.bundle, at)
  assert.deepEqual([scope.consent_version, scope.bearer_sha256, scope.allowed_networks], [4, null, null])
  assert.equal(deviceScope({ ...v.bundle, send: undefined }, at).send, null, 'no sending is null on version 4')
  const of = bundle => deviceCheck(dsk, { namespace: v.namespace, deviceID: v.device_id, epoch: v.epoch, scope: deviceScope(bundle, at) })
  assert.equal(of(v.bundle), v.check)
  const changed = ['client_id', 'client_kind', 'client_local', 'trust', 'started_ack', 'unknown_ack', 'history_days', 'bearer_sha256', 'allowed_networks', 'send', 'consent_version']
    .map(name => of({ ...v.bundle, [name]: { client_id: 'https://claude.ai/other', client_kind: 'dcr', client_local: true, trust: 'unknown', started_ack: null, unknown_ack: true,
      history_days: 30, bearer_sha256: bearer, allowed_networks: [], send: undefined, consent_version: 3 }[name] }))
  for (const value of changed) assert.notEqual(value, v.check)
  assert.equal(new Set(changed).size, changed.length)
})

test('link bundle v2 (§19.15): a metadata consent to 0.6.0 names its client, tier, tick and window, and no 0.5.0 path opens one', async () => {
  const link = (fields = {}) => ({ version: 2, kind: 'metadata', server_url: 'https://archive.example.test', workspace_id: workspace, device_ids: [device], token,
    allow_plaintext: false, link_secret: linkSecret, client_id: 'https://agent.example.com/oauth/client.json', trust: 'unknown', started_ack: true, history_days: 30, ...fields })
  const accepted = validateLinkBundleV2(link({ timezone: 'America/Sao_Paulo' }))
  assert.deepEqual([accepted.version, accepted.trust, accepted.history_days, accepted.timezone], [2, 'unknown', 30, 'America/Sao_Paulo'])
  assert.ok(Object.isFrozen(accepted) && Object.isFrozen(accepted.device_ids))
  assert.equal(validateLinkBundleV2(link({ trust: 'tested', history_days: null })).history_days, null)
  for (const [label, value] of Object.entries({
    version_1: link({ version: 1 }), content: link({ kind: 'content' }), no_kind: link({ kind: undefined }), started_false: link({ started_ack: false }), no_tick: link({ started_ack: undefined }),
    plaintext: link({ allow_plaintext: true }), no_client: link({ client_id: undefined }), long_client: link({ client_id: 'x'.repeat(513) }), trust_other: link({ trust: 'token' }),
    no_window: link({ history_days: undefined }), bad_token: link({ token: token.slice(0, 51) + '=' }), bad_secret: link({ link_secret: linkSecret.slice(1) }),
    service_key: link({ service_private_key: linkSecret }), extra: link({ unknown_ack: true }), twice: link({ device_ids: [device, device] }), timezone: link({ timezone: 'Mars/Olympus' }),
  })) assert.throws(() => validateLinkBundleV2(JSON.parse(JSON.stringify(value))), { code: 'invalid_bundle' }, label)
  await assert.rejects(validateBundle(link()), { code: 'invalid_bundle' })
})

test('the token\'s metadata bundle (§19.18 step 4): its expiry, window, networks and hash, and no link secret', () => {
  const metadata = (fields = {}) => ({ version: 1, kind: 'metadata', purpose: 'token', server_url: 'https://mcp.wappie.thehappie.co', workspace_id: workspace, device_ids: [device],
    token, expires_at: new Date(now + 30 * day).toISOString(), history_days: 30, allowed_networks: [], bearer_sha256: bearer, ...fields })
  const accepted = validateTokenBundle(metadata({ timezone: 'UTC', allowed_networks: ['203.0.113.0/24'] }), now)
  assert.deepEqual([accepted.history_days, accepted.allowed_networks, accepted.bearer_sha256], [30, ['203.0.113.0/24'], bearer])
  for (const [label, value] of Object.entries({
    link_secret: metadata({ link_secret: linkSecret }), consent_purpose: metadata({ purpose: 'consent' }), content: metadata({ kind: 'content' }), version_2: metadata({ version: 2 }),
    no_bearer: metadata({ bearer_sha256: undefined }), no_networks: metadata({ allowed_networks: undefined }), no_window: metadata({ history_days: undefined }),
    past: metadata({ expires_at: new Date(now - 1000).toISOString() }), too_far: metadata({ expires_at: new Date(now + 91 * day).toISOString() }),
    http: metadata({ server_url: 'http://mcp.wappie.thehappie.co' }), connection: metadata({ connection_id: connection }), plaintext: metadata({ allow_plaintext: false }),
    networks_unsorted: metadata({ allowed_networks: ['203.0.113.0/24', '198.51.100.0/24'] }),
  })) assert.throws(() => validateTokenBundle(value, now), { code: 'invalid_bundle' }, label)
})

test('networks (§19.15): canonical CIDRs only, RFC 5952 for IPv6, no host bit set, and membership never across families', () => {
  for (const text of ['198.51.100.0/24', '0.0.0.0/0', '203.0.113.7/32', '2001:db8::/48', '::/0', '2001:db8:0:1::/64', 'fe80::/10', '2001:db8::1:0:0:1/128']) assert.ok(parseCIDR(text), text)
  for (const text of ['198.51.100.1/24', '198.51.100.0/33', '198.51.100.0/024', '198.051.100.0/24', '2001:DB8::/48', '2001:0db8::/48', '2001:db8:0:0:0:0:0:0/48',
    '2001:db8::0:1/128', '::ffff:198.51.100.0/120', '198.51.100.0', '/24', '198.51.100.0/', 'example.com/24', '2001:db8::/129']) assert.equal(parseCIDR(text), null, text)
  assert.equal(formatAddress(parseAddress('2001:0DB8:0:0:1:0:0:1')), '2001:db8::1:0:0:1', 'the first longest run of zeros')
  assert.equal(formatAddress(parseAddress('2001:db8:0:1:1:1:1:1')), '2001:db8:0:1:1:1:1:1', 'a single zero group is not compressed')
  assert.deepEqual(parseAddress('::ffff:203.0.113.9'), { family: 4, bytes: Uint8Array.from([203, 0, 113, 9]) }, 'an IPv4-mapped address is IPv4')
  assert.equal(inNetwork(parseAddress('198.51.100.77'), parseCIDR('198.51.100.0/24')), true)
  assert.equal(inNetwork(parseAddress('::ffff:198.51.100.77'), parseCIDR('198.51.100.0/24')), true)
  assert.equal(inNetwork(parseAddress('198.51.101.77'), parseCIDR('198.51.100.0/24')), false)
  assert.equal(inNetwork(parseAddress('2001:db8:0:ffff::1'), parseCIDR('2001:db8::/48')), true)
  assert.equal(inNetwork(parseAddress('2001:db9::1'), parseCIDR('2001:db8::/48')), false)
  assert.equal(inNetwork(parseAddress('198.51.100.77'), parseCIDR('::/0')), false, 'never across families')
  assert.equal(inNetwork(parseAddress('not an address'), parseCIDR('0.0.0.0/0')), false)
})
