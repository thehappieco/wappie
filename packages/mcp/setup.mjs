#!/usr/bin/env node
import { constants } from 'node:fs'
import { open, mkdir, realpath, stat, chmod } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, resolve } from 'node:path'
import * as z from 'zod/v4'
import { LocalConfigError, validateConfig } from './config.mjs'

const maxBundleBytes = 1024 * 1024
const id = z.string().uuid().transform(value => value.toLowerCase())
const bundleSchema = z.strictObject({
  version: z.literal(1),
  server_url: z.string().min(1).max(4096), workspace_id: id,
  device_ids: z.array(id).min(1).max(1000),
  token: z.string().length(52), allow_plaintext: z.boolean(),
  service_user_id: id.optional(), service_private_key: z.string().length(43).optional(),
})
const messages = {
  arguments_required: 'Use --bundle /path/to/download.json --output /absolute/new-directory.',
  bundle_unavailable: 'The setup bundle must be an owned regular file, not a symlink, and must not be writable by other users.',
  invalid_bundle: 'The setup bundle is invalid or unsupported. Download a new bundle from Wappie.',
  invalid_server: 'The bundle must use an HTTPS server origin, or HTTP on localhost for local testing.',
  unsafe_output: 'The output must be a new absolute directory inside an existing directory you own that other users cannot modify.',
  output_exists: 'The output already exists. Choose a new directory; existing files are never replaced.',
  unsupported_permissions: 'Setup requires a system with POSIX file ownership and permissions.',
  import_failed: 'Import failed. Any files already created remain private. Check the output directory before trying a new destination.',
}
function fail(code) { throw new LocalConfigError(code) }
function canonicalKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false
  const decoded = Buffer.from(value, 'base64url')
  try { return decoded.length === 32 && decoded.toString('base64url') === value }
  finally { decoded.fill(0) }
}
function validateBundle(value) {
  const parsed = bundleSchema.safeParse(value)
  if (!parsed.success) fail('invalid_bundle')
  const bundle = parsed.data
  if (new Set(bundle.device_ids).size !== bundle.device_ids.length ||
    !/^[a-f0-9]{8}\./.test(bundle.token) || !canonicalKey(bundle.token.slice(9)) ||
    (bundle.service_private_key !== undefined && !canonicalKey(bundle.service_private_key)) ||
    (bundle.allow_plaintext && (!bundle.service_user_id || !bundle.service_private_key)) ||
    (!bundle.allow_plaintext && bundle.service_private_key !== undefined)) fail('invalid_bundle')
  const output = {
    server: bundle.server_url, workspace: bundle.workspace_id, device_ids: bundle.device_ids,
    token_file: './token.txt', allow_plaintext: bundle.allow_plaintext,
    ...(bundle.service_user_id ? { service_user_id: bundle.service_user_id } : {}),
    ...(bundle.allow_plaintext ? { service_key_file: './service-key.txt' } : {}),
  }
  // Reuse the runtime's origin, identity and credential-mixing rules. Keep file
  // references relative in the saved config so the private directory is movable.
  const checked = validateConfig(output)
  output.server = checked.server
  return { bundle, output }
}
async function readBundle(path) {
  let handle, data
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    const info = await handle.stat()
    // Browser downloads commonly have mode 0644. Readability is allowed only
    // for this explicit import; runtime credentials still require private files.
    if (!info.isFile() || info.uid !== process.getuid() || (info.mode & 0o022) !== 0 || info.size > maxBundleBytes) fail('bundle_unavailable')
    data = Buffer.alloc(maxBundleBytes + 1)
    let length = 0
    while (length < data.length) {
      const { bytesRead } = await handle.read(data, length, data.length - length, null)
      if (bytesRead === 0) break
      length += bytesRead
    }
    if (length > maxBundleBytes) fail('invalid_bundle')
    let value
    try { value = JSON.parse(data.subarray(0, length).toString('utf8')) } catch { fail('invalid_bundle') }
    return validateBundle(value)
  } catch (error) {
    if (error instanceof LocalConfigError) throw error
    fail('bundle_unavailable')
  } finally { data?.fill(0); await handle?.close() }
}
async function createOutput(path) {
  if (!isAbsolute(path) || path.includes('\0')) fail('unsafe_output')
  const requested = resolve(path)
  let parent
  try {
    // Canonicalize existing ancestors (for example macOS /var -> /private/var).
    // The new final component is created exclusively and is never followed.
    parent = await realpath(dirname(requested))
    const info = await stat(parent)
    if (!info.isDirectory() || info.uid !== process.getuid() || (info.mode & 0o022) !== 0) fail('unsafe_output')
  } catch { fail('unsafe_output') }
  const output = join(parent, basename(requested))
  try { await mkdir(output, { mode: 0o700 }) }
  catch (error) { fail(error.code === 'EEXIST' ? 'output_exists' : 'unsafe_output') }
  await chmod(output, 0o700)
  return output
}
async function writePrivate(path, value) {
  let handle
  const data = Buffer.from(value, 'utf8')
  try {
    handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
    await handle.chmod(0o600)
    await handle.writeFile(data)
    await handle.sync()
  } finally { data.fill(0); await handle?.close() }
}
function argumentsFor(argv) {
  if (argv.length !== 4) fail('arguments_required')
  const options = new Map()
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index], value = argv[index + 1]
    if (!['--bundle', '--output'].includes(name) || options.has(name) || !value || value.startsWith('--')) fail('arguments_required')
    options.set(name, value)
  }
  return { bundle: options.get('--bundle'), output: options.get('--output') }
}

const argv = process.argv.slice(2)
if (argv.length === 1 && argv[0] === '--help') {
  process.stdout.write('wappie-mcp-setup --bundle /path/to/wappie-mcp-setup.json --output /absolute/new-directory\nImports a browser setup bundle into private local credential files. No network requests. Existing destinations are never replaced. The original download is not deleted.\n')
} else {
  try {
    const paths = argumentsFor(argv)
    if (typeof process.getuid !== 'function') fail('unsupported_permissions')
    const { bundle, output } = await readBundle(paths.bundle)
    const directory = await createOutput(paths.output)
    await writePrivate(join(directory, 'token.txt'), bundle.token + '\n')
    if (bundle.service_private_key) await writePrivate(join(directory, 'service-key.txt'), bundle.service_private_key + '\n')
    // Publish the runnable configuration last, after every credential is durable.
    await writePrivate(join(directory, 'config.json'), JSON.stringify(output, null, 2) + '\n')
    process.stdout.write('Wappie MCP setup imported. Start the MCP with --config pointing to config.json in the output directory.\nThe original download still contains credentials. After checking the import, delete the original bundle and remove it from the trash.\n')
  } catch (error) {
    const code = error instanceof LocalConfigError && messages[error.code] ? error.code : 'import_failed'
    process.stderr.write(`Wappie MCP setup: ${messages[code]}\n`)
    process.exitCode = 1
  }
}
