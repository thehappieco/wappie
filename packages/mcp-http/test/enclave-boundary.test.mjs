// The hosted reader on the pilot must never load enclave code: `enclave/` is
// left out of the pilot payload and of this package's files, and its
// dependencies are not installed there. This walks every relative import
// reachable from server.mjs.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

test('the pilot entry point never loads enclave code', async () => {
  const root = fileURLToPath(new URL('../', import.meta.url))
  const seen = new Set(), queue = ['server.mjs']
  while (queue.length) {
    const file = queue.shift()
    if (seen.has(file)) continue
    seen.add(file)
    const text = await readFile(join(root, file), 'utf8')
    for (const [, target] of text.matchAll(/^\s*(?:import|export)[^'"]*?from\s*['"]([^'"]+)['"]/gm)) {
      assert.equal(/(^|\/)enclave(\/|$)/.test(target), false, `${file} imports ${target}`)
      if (target.startsWith('./')) queue.push(target.slice(2))
    }
    assert.equal(/import\s*\(/.test(text), false, `${file} has a dynamic import`)
  }
  assert.ok(seen.has('attestation.mjs') && seen.has('internal.mjs') && seen.has('state.mjs'))
})

test('the published files leave enclave/ out', async () => {
  const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
  assert.equal(manifest.files.some(file => file.startsWith('enclave')), false)
  assert.ok(manifest.files.includes('attestation.mjs'), 'server.mjs imports attestation.mjs')
})
