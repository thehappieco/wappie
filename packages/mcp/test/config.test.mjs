import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { validateConfig, readPrivateFile } from '../config.mjs'
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
