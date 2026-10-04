// Copies the shared kit's vectors that test/kit.spec.ts runs through this
// client's wrappers into this directory, and the request HMAC cases Go wrote
// into packages/mcp-http/enclave/test/kit for the reader's own hmac.mjs, from
// the kit version the Go module requires (go.mod at the repository root),
// checked against the kit's own MANIFEST.sha256. The npm tarball carries no vectors, so this is how the
// TypeScript side gets the same files Go embeds; Go's
// internal/crypto/seal TestFixturesMatchTheKit fails if the copies and the
// kit version drift apart. They live under test/ so that neither the npm
// package nor the reader image (which prunes every test/ directory) carries
// them. Run it after bumping the kit:
//
//   node packages/client/test/kit/copy.mjs

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = fileURLToPath(new URL('.', import.meta.url))
const root = join(here, '..', '..', '..', '..')
const enclave = join(root, 'packages', 'mcp-http', 'enclave', 'test', 'kit')

// Where each file of the kit's vectors/wappie/golden goes.
const FILES = [
  ['seal-go.json', here], ['seal-ts.json', here], ['account-ts.json', here], ['passkey-ts.json', here], ['browser-account-ts.json', here],
  ['reqhmac-go.json', enclave],
]
const go = (...args) => JSON.parse(execFileSync('go', args, { cwd: root, encoding: 'utf8' }))

let kit = go('list', '-m', '-json', 'github.com/thehappieco/kit')
if (!kit.Dir) kit = go('mod', 'download', '-json', `github.com/thehappieco/kit@${kit.Version}`)
if (!kit.Dir) throw new Error('the kit module has no directory')
const vectors = join(kit.Dir, 'vectors')

const manifest = new Map()
for (const line of readFileSync(join(vectors, 'MANIFEST.sha256'), 'utf8').split('\n')) {
  const [sum, path] = line.split(/\s+/)
  if (path) manifest.set(path, sum)
}

for (const [name, dir] of FILES) {
  const path = `wappie/golden/${name}`
  const data = readFileSync(join(vectors, path))
  const sum = createHash('sha256').update(data).digest('hex')
  if (manifest.get(path) !== sum) throw new Error(`${path} does not match the kit's MANIFEST.sha256`)
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, name), data)
}
console.log(`copied ${FILES.length} vector files from github.com/thehappieco/kit ${kit.Version ?? '(local)'} (${kit.Dir})`)
