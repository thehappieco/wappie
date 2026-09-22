#!/usr/bin/env node
import { constants } from 'node:fs'
import { open, mkdir, realpath, stat, chmod } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, resolve } from 'node:path'
import { LocalConfigError } from './config.mjs'
import { validateBundle } from './bundle.mjs'
import { MAX_CONTACT_PACK_BYTES } from '@whatserver2/client/crypto/contactPack'

const maxBundleBytes = MAX_CONTACT_PACK_BYTES
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
    // A link secret marks a hosted-connector bundle; it never belongs on disk.
    if (value !== null && typeof value === 'object' && 'link_secret' in value) fail('invalid_bundle')
    return await validateBundle(value)
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
    if (bundle.contacts !== undefined) await writePrivate(join(directory, 'contacts.enc.json'), JSON.stringify(bundle.contacts) + '\n')
    // Publish the runnable configuration last, after every credential is durable.
    await writePrivate(join(directory, 'config.json'), JSON.stringify(output, null, 2) + '\n')
    process.stdout.write('Wappie MCP setup imported. Start the MCP with --config pointing to config.json in the output directory.\nThe original download still contains credentials. After checking the import, delete the original bundle and remove it from the trash.\n')
  } catch (error) {
    const code = error instanceof LocalConfigError && messages[error.code] ? error.code : 'import_failed'
    process.stderr.write(`Wappie MCP setup: ${messages[code]}\n`)
    process.exitCode = 1
  }
}
