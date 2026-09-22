import { test } from 'node:test'
import assert from 'node:assert/strict'
import { bundleSchema, validateBundle } from '../bundle.mjs'

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
