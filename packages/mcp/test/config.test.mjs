import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { validateConfig, readPrivateFile, loadCredential } from '../config.mjs'
const base = { server: 'https://example.test', workspace: '11111111-1111-4111-8111-111111111111', token_file: 'token' }
const service = { ...base, allow_plaintext: true, service_key_file: 'key', service_user_id: '22222222-2222-4222-8222-222222222222', device_ids: ['33333333-3333-4333-8333-333333333333'] }
test('contact packs require explicit plaintext service credentials and an exact device allowlist', () => {
  const configured = validateConfig({ ...service, contacts_file: 'contacts.enc.json', timezone: 'America/Sao_Paulo' }, '/private')
  assert.equal(configured.contacts_file, '/private/contacts.enc.json')
  assert.equal(configured.timezone, 'America/Sao_Paulo')
  for (const value of [{ ...base, contacts_file: 'pack' }, { ...service, device_ids: undefined, contacts_file: 'pack' }, { ...service, timezone: 'Mars/Olympus' }, { ...service, max_scan_messages: 2001 }]) assert.throws(() => validateConfig(value))
  assert.equal(validateConfig(base).timezone, 'UTC')
  assert.equal(validateConfig(base).max_scan_messages, 500)
})
test('large encrypted snapshots have an explicit file bound while credentials retain their smaller bound', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wappie-config-'))
  try {
    const path = join(directory, 'pack')
    await writeFile(path, Buffer.alloc(1024 * 1024 + 1), { mode: 0o600 })
    await assert.rejects(readPrivateFile(path), /private_file_required/)
    const data = await readPrivateFile(path, { maxBytes: 8 * 1024 * 1024 })
    assert.equal(data.length, 1024 * 1024 + 1)
    data.fill(0)
    for (const maxBytes of [0, NaN, 8 * 1024 * 1024 + 1]) await assert.rejects(readPrivateFile(path, { maxBytes }))
  } finally { await rm(directory, { recursive: true, force: true }) }
})
const provided = { server: base.server, workspace: base.workspace, credential_source: 'provided', device_ids: ['33333333-3333-4333-8333-333333333333'] }
test('provided credentials carry no files and no plaintext opt-in, while file-mode codes are unchanged', async () => {
  const configured = validateConfig(provided, '/private')
  assert.equal(configured.credential_source, 'provided')
  assert.equal(configured.allow_plaintext, false)
  assert.equal(configured.token_file, undefined)
  assert.equal(validateConfig(base).credential_source, 'files')
  for (const override of [{ token_file: 'token' }, { session_file: 'session.json' }, { password_file: 'password' }, { service_key_file: 'key' },
    { contacts_file: 'contacts.enc.json' }, { allow_plaintext: true }, { allow_plaintext: true, service_key_file: 'key', service_user_id: service.service_user_id }]) {
    assert.throws(() => validateConfig({ ...provided, ...override }), { code: 'provided_credentials_metadata_only' })
  }
  assert.throws(() => validateConfig({ ...provided, credential_source: 'network' }), { code: 'invalid_config' })
  assert.throws(() => validateConfig({ ...base, token_file: undefined }), { code: 'choose_one_credential' })
  assert.throws(() => validateConfig({ ...base, session_file: 'session.json' }), { code: 'choose_one_credential' })
  assert.throws(() => validateConfig({ ...base, credential_source: 'files', token_file: undefined }), { code: 'choose_one_credential' })
  assert.throws(() => validateConfig({ ...base, password_file: 'password' }), { code: 'mixed_credentials' })
  assert.throws(() => validateConfig({ ...base, allow_plaintext: true }), { code: 'unlock_file_required' })
  assert.throws(() => validateConfig({ ...base, service_key_file: 'key', service_user_id: service.service_user_id }), { code: 'plaintext_opt_in_required' })
  assert.throws(() => validateConfig({ ...base, contacts_file: 'pack' }), { code: 'contact_pack_requires_service_scope' })
})
test('a provider supplies the token in provided mode and is never consulted for file-mode configs', async () => {
  const token = 'synthetic-provided-credential-never-returned'
  let calls = 0
  const provider = { token: async () => { calls++; return { token, kind: 'api_key' } } }
  assert.deepEqual(await loadCredential(validateConfig(provided), provider), { token, kind: 'api_key' })
  assert.equal(calls, 1)
  await assert.rejects(loadCredential(validateConfig(provided)), { code: 'credential_provider_required' })
  await assert.rejects(loadCredential(validateConfig(provided), {}), { code: 'credential_provider_required' })
  for (const bad of [{ token: '', kind: 'api_key' }, { token: 'two words', kind: 'api_key' }, { token, kind: 'session' }, null, { token: 42, kind: 'api_key' }]) {
    await assert.rejects(loadCredential(validateConfig(provided), { token: async () => bad }), { code: 'invalid_token_file' })
  }
  await assert.rejects(loadCredential(validateConfig(provided), { token: async () => { throw new Error('provider failure') } }), /provider failure/)
  // File mode ignores the provider: the missing token file is what fails.
  await assert.rejects(loadCredential(validateConfig({ ...base, token_file: '/nonexistent/wappie-token' }), provider), { code: 'private_file_unavailable' })
  assert.equal(calls, 1)
})
