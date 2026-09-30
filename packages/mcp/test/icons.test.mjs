// The Wappie icon (icons.mjs, docs/mcp-enclave.md §5.4): the kit's files byte
// for byte, the ICO built from its PNGs, and serverInfo.icons with the data:
// icon on every reader and the URLs only on an https origin that serves them.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { Client } from '@modelcontextprotocol/client'
import { InMemoryTransport } from '@modelcontextprotocol/server'
import { validateConfig } from '../config.mjs'
import { ICON_FILES, serverIcons } from '../icons.mjs'
import { createServer } from '../server.mjs'

const file = name => readFileSync(new URL(`../icons/${name}`, import.meta.url))
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')

test('the icon files are the console\'s kit, byte for byte, and the ICO holds its two PNGs unchanged', () => {
  // wappie-cloud web/public favicon-light.svg, favicon-32.png and apple-touch-icon.png.
  assert.deepEqual(['favicon.svg', 'favicon-32.png', 'apple-touch-icon.png'].map(name => sha256(file(name))), [
    '0e935f072a411c886ff3740b7959f61347c2cb3b06964893cea3b69cad45903a',
    'fc1078e5fc0c6a828173dd66ab2f9e479f8e89d4f4936ebd3ecccaf6d3867f40',
    '1377eede3d14b3ec0c364329bd9424a8e1cc74e2e29092984e557cd7b2b850a6',
  ])
  assert.deepEqual(Object.keys(ICON_FILES), ['/favicon.ico', '/favicon.svg', '/apple-touch-icon.png'])
  assert.deepEqual(Object.values(ICON_FILES).map(item => item.type), ['image/x-icon', 'image/svg+xml', 'image/png'])
  assert.deepEqual(ICON_FILES['/favicon.svg'].bytes, file('favicon.svg'))
  assert.deepEqual(ICON_FILES['/apple-touch-icon.png'].bytes, file('apple-touch-icon.png'))
  assert.doesNotMatch(ICON_FILES['/favicon.svg'].bytes.toString('utf8'), /<script|on[a-z]+=|href=/i, 'an SVG that runs nothing and links nowhere')
  const ico = ICON_FILES['/favicon.ico'].bytes
  assert.deepEqual([ico.readUInt16LE(0), ico.readUInt16LE(2), ico.readUInt16LE(4)], [0, 1, 2])
  const pngs = [file('favicon-32.png'), file('apple-touch-icon.png')]
  let offset = 6 + 16 * 2
  pngs.forEach((png, index) => {
    const entry = 6 + 16 * index
    assert.deepEqual([ico[entry], ico[entry + 1], ico[entry + 2], ico[entry + 3], ico.readUInt16LE(entry + 4), ico.readUInt16LE(entry + 6)], [[32, 180][index], [32, 180][index], 0, 0, 1, 32])
    assert.deepEqual([ico.readUInt32LE(entry + 8), ico.readUInt32LE(entry + 12)], [png.length, offset])
    assert.deepEqual(ico.subarray(offset, offset + png.length), png)
    offset += png.length
  })
  assert.equal(ico.length, offset)
})

test('serverInfo.icons: the PNG as a data: URI everywhere, the URLs only on an https origin', async () => {
  const data = { src: `data:image/png;base64,${file('apple-touch-icon.png').toString('base64')}`, mimeType: 'image/png', sizes: ['180x180'] }
  assert.deepEqual(serverIcons(), [data])
  for (const origin of ['http://127.0.0.1:18093', 'https://mcp.wappie.thehappie.co/', 'https://mcp.wappie.thehappie.co/mcp', 'javascript:alert(1)']) assert.deepEqual(serverIcons(origin), [data], origin)
  const hosted = [data,
    { src: 'https://mcp.wappie.thehappie.co/favicon.svg', mimeType: 'image/svg+xml', sizes: ['any'] },
    { src: 'https://mcp.wappie.thehappie.co/apple-touch-icon.png', mimeType: 'image/png', sizes: ['180x180'] }]
  assert.deepEqual(serverIcons('https://mcp.wappie.thehappie.co'), hosted)
  // What a client reads in the initialize answer.
  const config = validateConfig({ server: 'http://127.0.0.1:1', workspace: '018f3a2b-0000-7000-8000-000000000001', device_ids: ['018f3a2b-2222-7000-8000-000000000001'], credential_source: 'provided' })
  for (const [options, icons] of [[undefined, [data]], [{ iconOrigin: 'https://mcp.wappie.thehappie.co' }, hosted]]) {
    const [serverSide, clientSide] = InMemoryTransport.createLinkedPair()
    await createServer(config, { token: async () => ({ token: 'x', kind: 'api_key' }) }, options).connect(serverSide)
    const client = new Client({ name: 'synthetic-icons-test', version: '1' }, { versionNegotiation: { mode: 'auto' } })
    await client.connect(clientSide)
    assert.deepEqual(client.getServerVersion(), { name: 'wappie-readonly', version: '0.1.0', icons })
    await client.close()
  }
})
