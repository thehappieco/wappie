// The hosted reader on the pilot must never load enclave code, and must never
// be able to open content: `enclave/` is left out of the pilot payload and of
// this package's files, its dependencies are not installed there, nothing
// reachable from server.mjs names the enclave credential source, the key
// holder or the v2 bundle, the pilot's link refuses a v2 bundle, and a bundle
// relayed with `"kind": "content"` is a bad request. This walks every relative
// import reachable from server.mjs.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { auth } from '@modelcontextprotocol/client'
import { hpke } from '@whatserver2/client'
import { clientProvider, consent, harness, vector, workspace } from './harness.mjs'
import { aadFor, INFO, LinkError, openBundle } from '../link.mjs'
import { newRecipient } from '../state.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))

/** Every file reachable from server.mjs through relative imports, with its text. */
async function reachable() {
  const seen = new Map(), queue = ['server.mjs']
  while (queue.length) {
    const file = queue.shift()
    if (seen.has(file)) continue
    const text = await readFile(join(root, file), 'utf8')
    seen.set(file, text)
    for (const [, target] of text.matchAll(/^\s*(?:import|export)[^'"]*?from\s*['"]([^'"]+)['"]/gm)) {
      assert.equal(/(^|\/)enclave(\/|$)/.test(target), false, `${file} imports ${target}`)
      if (target.startsWith('./')) queue.push(target.slice(2))
    }
    assert.equal(/import\s*\(/.test(text), false, `${file} has a dynamic import`)
  }
  return seen
}

test('the pilot entry point never loads enclave code', async () => {
  const seen = await reachable()
  assert.ok(seen.has('attestation.mjs') && seen.has('internal.mjs') && seen.has('state.mjs'))
})

test('nothing the pilot reaches names the enclave credential source, the key holder or the v2 bundle', async () => {
  for (const [file, text] of await reachable()) {
    // Comments may describe the enclave; code may not name what only it can use.
    const code = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1')
    assert.equal(/['"`]enclave['"`]/.test(code), false, `${file} names the 'enclave' credential source`)
    assert.equal(/connkeys/i.test(text), false, `${file} names connkeys`)
    for (const name of ['validateContentBundle', 'contentBundleSchema', 'CONTENT_CONSENT_VERSION', 'wappie-mcp-connect/v2', 'wappie-mcp-renew/v1', 'mcp-connect\', 2']) {
      assert.equal(text.includes(name), false, `${file} names ${name}`)
    }
  }
  // The pilot's provider refuses every content-opening read.
  const provider = await readFile(join(root, 'provider.mjs'), 'utf8')
  assert.match(provider, /allow_plaintext: false, credential_source: 'provided'/)
})

test('the published files leave enclave/ out', async () => {
  const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
  assert.equal(manifest.files.some(file => file.startsWith('enclave')), false)
  assert.ok(manifest.files.includes('attestation.mjs'), 'server.mjs imports attestation.mjs')
})

/** A v2 content bundle as the console would build it for the attested reader. */
const contentBundle = () => ({
  version: 2, kind: 'content', purpose: 'consent', server_url: 'https://mcp.wappie.thehappie.co', workspace_id: workspace, service_user_id: randomUUID(),
  device_ids: [vector.device], token: `${'a'.repeat(8)}.${Buffer.alloc(32, 7).toString('base64url')}`, key_mode: 'ephemeral', consent_version: 1,
  expires_at: new Date(Date.now() + 86_400_000).toISOString(), link_secret: Buffer.alloc(32, 9).toString('base64url'),
})

test('link.openBundle refuses a v2 bundle, under v1 labels and under v2 labels', async () => {
  const recipient = await newRecipient()
  const resource = 'https://mcp.wappie.thehappie.co/mcp'
  const pending = { id: 'AAAAAAAAAAAAAAAAAAAAAA', resource, tenant_id: workspace }
  for (const [info, aad] of [
    [INFO, aadFor(pending.id, recipient.kid, resource)],
    [Buffer.from('wappie-mcp-connect/v2'), Buffer.from(JSON.stringify(['wappie/mcp-connect', 2, pending.id, recipient.kid, resource]))],
  ]) {
    const { enc, ciphertext } = await hpke.seal(new Uint8Array(recipient.publicKey), new Uint8Array(info), new Uint8Array(aad), new Uint8Array(Buffer.from(JSON.stringify(contentBundle()))))
    const sealed = Buffer.concat([Buffer.from(enc), Buffer.from(ciphertext)])
    await assert.rejects(openBundle({ recipient, previous: null }, pending, sealed, recipient.kid), error => error instanceof LinkError && error.code === 'invalid_bundle')
  }
})

test('the pilot reader: a relay labelled content is a bad request, a v2 bundle is invalid, there is no renewal route, and no content record survives a start', async t => {
  const h = await harness(t)
  const start = async () => { const provider = clientProvider(); assert.equal(await auth(provider, { serverUrl: h.resource }), 'REDIRECT'); return provider.store.authorizationUrl }
  const labelled = await consent(h, await start(), { until: 'bundle', relay: { kind: 'content' } })
  assert.equal(labelled.relayed.status, 400)
  assert.equal(labelled.relayed.json().code, 'bad_request')
  h.clock.advance(13_000)
  const v2 = await consent(h, await start(), { until: 'bundle', bundle: contentBundle(), omit: ['allow_plaintext'] })
  assert.equal(v2.relayed.status, 400)
  assert.equal(v2.relayed.json().code, 'invalid_bundle')
  assert.equal(h.reader.state.pending.get(v2.id).bundle, undefined)
  for (const path of [`/internal/connections/${randomUUID()}/renewal`, `/internal/connections/${randomUUID()}/renewal/${'A'.repeat(22)}/bundle`]) {
    assert.equal((await h.internal(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status, 404, path)
  }
  // A content record could only come from a tampered state file; the pilot drops it at start and never serves one.
  const id = randomUUID()
  h.reader.state.connections.set(id, { connection_id: id, kind: 'content', tenant_id: workspace, workspace_id: workspace, device_ids: [vector.device], timezone: 'UTC', api_key: h.apiKey, expires_at: new Date(Date.now() + 86_400_000).toISOString(), client_id: 'x', created_at: Date.now() })
  h.go.connections.set(id, { status: 'active', expires_at: new Date(Date.now() + 86_400_000).toISOString() })
  await h.reader.state.save()
  await h.restart()
  assert.equal(h.reader.state.connections.has(id), false)
})
