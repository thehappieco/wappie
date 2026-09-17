import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { mkdtemp, mkdir, readFile, writeFile, rm, chmod, symlink, stat, lstat, readdir, realpath } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Client } from '@modelcontextprotocol/client'
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio'
import { loadConfig, loadCredential, readPrivateFile } from '../config.mjs'

const run = promisify(execFile)
const setup = fileURLToPath(new URL('../setup.mjs', import.meta.url))
const workspace = '018f3a2b-2222-7000-8000-00000000bbbb'
const device = '018f3a2b-2222-7000-8000-00000000dddd'
const user = '018f3a2b-2222-7000-8000-00000000aaaa'
const key = Buffer.alloc(32, 17).toString('base64url')
const token = `a1b2c3d4.${Buffer.alloc(32, 42).toString('base64url')}`
const bundle = () => ({ version: 1, server_url: 'https://archive.example.test', workspace_id: workspace,
  device_ids: [device], token, allow_plaintext: false })
async function fixture(t, data = bundle()) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'wappie-mcp-setup-')))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const input = join(directory, 'download.json'), output = join(directory, 'private')
  await writeFile(input, JSON.stringify(data), { mode: 0o644 })
  return { directory, input, output }
}
async function invoke(input, output, extra = []) {
  try { return { status: 0, ...await run(process.execPath, [setup, '--bundle', input, '--output', output, ...extra]) } }
  catch (error) { return { status: error.code, stdout: error.stdout, stderr: error.stderr } }
}
function secretsAbsent(result) {
  for (const secret of [token, key]) assert.equal(`${result.stdout}${result.stderr}`.includes(secret), false)
}

test('imports a browser download into private files usable by the existing MCP loader', async t => {
  const f = await fixture(t)
  const result = await invoke(f.input, f.output)
  assert.equal(result.status, 0, result.stderr)
  assert.equal((await stat(f.output)).mode & 0o777, 0o700)
  assert.deepEqual((await readdir(f.output)).sort(), ['config.json', 'token.txt'])
  for (const name of ['config.json', 'token.txt']) assert.equal((await stat(join(f.output, name))).mode & 0o777, 0o600)
  const config = await loadConfig(join(f.output, 'config.json'))
  assert.equal(config.server, 'https://archive.example.test')
  assert.equal(config.workspace, workspace)
  assert.deepEqual(config.device_ids, [device])
  assert.equal(config.allow_plaintext, false)
  assert.deepEqual(await loadCredential(config), { kind: 'api_key', token })
  const client = new Client({ name: 'synthetic-setup-test', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } })
  const transport = new StdioClientTransport({ command: process.execPath,
    args: [fileURLToPath(new URL('../cli.mjs', import.meta.url)), '--config', join(f.output, 'config.json')], stderr: 'pipe' })
  try {
    await client.connect(transport)
    assert.equal((await client.listTools()).tools.length, 5, 'imported config starts the real MCP without any archive request')
  } finally { await client.close() }
  assert.equal((await stat(f.input)).mode & 0o777, 0o644, 'download is retained unchanged')
  assert.deepEqual(JSON.parse(await readFile(f.input, 'utf8')), bundle())
  assert.match(result.stdout, /delete.*original|remove.*original/i)
  secretsAbsent(result)
})

test('imports explicit plaintext service credentials without embedding secrets in config', async t => {
  const f = await fixture(t, { ...bundle(), allow_plaintext: true, service_user_id: user, service_private_key: key })
  const result = await invoke(f.input, f.output)
  assert.equal(result.status, 0, result.stderr)
  const configPath = join(f.output, 'config.json'), text = await readFile(configPath, 'utf8')
  assert.equal(text.includes(key), false); assert.equal(text.includes(token), false)
  const config = await loadConfig(configPath)
  assert.equal(config.service_user_id, user)
  assert.equal(config.allow_plaintext, true)
  const secret = await readPrivateFile(config.service_key_file)
  try { assert.equal(secret.toString().trim(), key) } finally { secret.fill(0) }
  secretsAbsent(result)
})

test('invalid origins, identities, tokens, keys and mixed bundle fields create no output', async t => {
  const f = await fixture(t)
  const invalid = [
    { version: 2 }, { unknown: 'ignored?' }, { server_url: 'http://remote.example.test' },
    { server_url: 'https://user:password@archive.example.test' }, { server_url: 'https://archive.example.test/v1' },
    { workspace_id: 'not-a-uuid' }, { device_ids: [] }, { device_ids: ['../messages'] },
    { device_ids: [device, device.toUpperCase()] }, { device_ids: Array(1001).fill(device) },
    { token: '' }, { token: 'bearer token' }, { token: 'token\n' }, { token: 'a1b2c3d4.short' }, // gitleaks:allow -- Synthetic malformed token, never an issued credential.
    { token: `a1b2c3d4.${'A'.repeat(42)}B` }, { token: `a1b2c3d4.${'A'.repeat(43)}\u0000` },
    { allow_plaintext: 'true' }, { allow_plaintext: true }, { service_private_key: key },
    { allow_plaintext: true, service_private_key: key },
    { allow_plaintext: true, service_user_id: user, service_private_key: 'invalid' },
    { allow_plaintext: true, service_user_id: 'bad', service_private_key: key },
    { allow_plaintext: true, service_user_id: user, service_private_key: `${'A'.repeat(42)}B` },
    { allow_plaintext: true, service_user_id: user, service_private_key: key + '=' },
    { session_file: '/private/session.json' }, { token_file: '/private/token.txt' },
  ]
  for (const override of invalid) {
    await writeFile(f.input, JSON.stringify({ ...bundle(), ...override }))
    const result = await invoke(f.input, f.output)
    assert.equal(result.status, 1, `accepted fields: ${Object.keys(override).join(',')}`)
    await assert.rejects(lstat(f.output), { code: 'ENOENT' })
    secretsAbsent(result)
    assert.doesNotMatch(result.stderr, /node:internal|SyntaxError|ZodError/)
  }
})

test('existing directories, files and destination symlinks are never overwritten', async t => {
  const f = await fixture(t)
  await mkdir(f.output, { mode: 0o700 })
  await writeFile(join(f.output, 'token.txt'), 'existing-secret', { mode: 0o600 })
  assert.equal((await invoke(f.input, f.output)).status, 1)
  assert.equal(await readFile(join(f.output, 'token.txt'), 'utf8'), 'existing-secret')
  const existingFile = join(f.directory, 'existing-file')
  await writeFile(existingFile, 'keep')
  assert.equal((await invoke(f.input, existingFile)).status, 1)
  assert.equal(await readFile(existingFile, 'utf8'), 'keep')
  const link = join(f.directory, 'link')
  await symlink(f.output, link)
  assert.equal((await invoke(f.input, link)).status, 1)
  assert.equal((await lstat(link)).isSymbolicLink(), true)
  assert.deepEqual(await readdir(f.output), ['token.txt'])
  const dangling = join(f.directory, 'dangling')
  await symlink(join(f.directory, 'missing'), dangling)
  assert.equal((await invoke(f.input, dangling)).status, 1)
  await assert.rejects(lstat(join(f.directory, 'missing')), { code: 'ENOENT' })
})

test('refuses symlink inputs, writable downloads, large bundles and unsafe output arguments', async t => {
  const f = await fixture(t)
  const link = join(f.directory, 'input-link')
  await symlink(f.input, link)
  assert.equal((await invoke(link, f.output)).status, 1)
  await chmod(f.input, 0o666)
  assert.equal((await invoke(f.input, f.output)).status, 1)
  await chmod(f.input, 0o644)
  await writeFile(f.input, 'x'.repeat(1024 * 1024 + 1))
  assert.equal((await invoke(f.input, f.output)).status, 1)
  await writeFile(f.input, '{invalid-json')
  assert.equal((await invoke(f.input, f.output)).status, 1)
  await writeFile(f.input, JSON.stringify(bundle()))
  assert.equal((await invoke(f.input, './relative')).status, 1)
  assert.equal((await invoke(f.input, f.output, ['--delete-original'])).status, 1)
  const shared = join(f.directory, 'shared')
  await mkdir(shared)
  await chmod(shared, 0o777)
  assert.equal((await invoke(f.input, join(shared, 'private'))).status, 1)
  await assert.rejects(lstat(f.output), { code: 'ENOENT' })
})

test('concurrent imports select one complete result and never replace credentials', async t => {
  const f = await fixture(t)
  const results = await Promise.all([invoke(f.input, f.output), invoke(f.input, f.output)])
  assert.deepEqual(results.map(value => value.status).sort(), [0, 1])
  const config = await loadConfig(join(f.output, 'config.json'))
  assert.equal((await loadCredential(config)).token, token)
  for (const result of results) secretsAbsent(result)
})

test('creates exactly owner-readable permissions even with an unusually restrictive umask', async t => {
  const f = await fixture(t)
  const code = `process.umask(0o777); process.argv = ${JSON.stringify([process.execPath, setup, '--bundle', f.input, '--output', f.output])}; await import(${JSON.stringify(new URL('../setup.mjs', import.meta.url).href)});`
  const result = await run(process.execPath, ['--input-type=module', '--eval', code])
  secretsAbsent(result)
  assert.equal((await stat(f.output)).mode & 0o777, 0o700)
  for (const name of ['config.json', 'token.txt']) assert.equal((await stat(join(f.output, name))).mode & 0o777, 0o600)
  assert.equal((await loadCredential(await loadConfig(join(f.output, 'config.json')))).token, token)
})
