// The Wappie icon (icons.mjs, docs/mcp-enclave.md §5.4, §19.29): the kit's
// files byte for byte, the ICO built from its PNGs, and serverInfo.icons with
// the data: icon on every reader and the URLs only on an https origin that
// serves them.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { Client } from '@modelcontextprotocol/client'
import { InMemoryTransport } from '@modelcontextprotocol/server'
import { validateConfig } from '../config.mjs'
import { ICON_FILES, serverIcons } from '../icons.mjs'
import { createServer, PACKAGE_VERSION } from '../server.mjs'

const file = name => readFileSync(new URL(`../icons/${name}`, import.meta.url))
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')

test('the icon files are the console\'s and the site\'s kit, byte for byte, and the ICO holds its two PNGs unchanged', () => {
  // wappie-cloud web/public favicon-light.svg, favicon-32.png and apple-touch-icon.png;
  // thehappieco public/icons/wappie icon-192.png and icon-512.png (§19.29).
  assert.deepEqual(['favicon.svg', 'favicon-32.png', 'apple-touch-icon.png', 'icon-192.png', 'icon-512.png'].map(name => sha256(file(name))), [
    '0e935f072a411c886ff3740b7959f61347c2cb3b06964893cea3b69cad45903a',
    'fc1078e5fc0c6a828173dd66ab2f9e479f8e89d4f4936ebd3ecccaf6d3867f40',
    '1377eede3d14b3ec0c364329bd9424a8e1cc74e2e29092984e557cd7b2b850a6',
    'c4827c7ec30b2b508c438315b6a9e43b2717825bdc8e4fdeab3f4b440def9d35',
    'b6cd6bc77c53f075911d28844a87580dc048de19df6298090bdd809bec4153ce',
  ])
  assert.deepEqual(Object.keys(ICON_FILES), ['/favicon.ico', '/favicon.svg', '/apple-touch-icon.png', '/icon-192.png', '/icon-512.png'])
  assert.deepEqual(Object.values(ICON_FILES).map(item => item.type), ['image/x-icon', 'image/svg+xml', 'image/png', 'image/png', 'image/png'])
  assert.deepEqual(ICON_FILES['/favicon.svg'].bytes, file('favicon.svg'))
  assert.deepEqual(ICON_FILES['/apple-touch-icon.png'].bytes, file('apple-touch-icon.png'))
  for (const [name, side] of [['icon-192.png', 192], ['icon-512.png', 512]]) {
    const png = file(name)
    assert.deepEqual(ICON_FILES[`/${name}`].bytes, png, name)
    // A square raster of at least 48 pixels, as hosts that want a raster ask.
    assert.deepEqual([png.readUInt32BE(16), png.readUInt32BE(20)], [side, side], name)
  }
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
    { src: 'https://mcp.wappie.thehappie.co/apple-touch-icon.png', mimeType: 'image/png', sizes: ['180x180'] },
    { src: 'https://mcp.wappie.thehappie.co/icon-512.png', mimeType: 'image/png', sizes: ['512x512'] },
    { src: 'https://mcp.wappie.thehappie.co/icon-192.png', mimeType: 'image/png', sizes: ['192x192'] }]
  assert.deepEqual(serverIcons('https://mcp.wappie.thehappie.co'), hosted)
  // What a client reads in the initialize answer.
  const config = validateConfig({ server: 'http://127.0.0.1:1', workspace: '018f3a2b-0000-7000-8000-000000000001', device_ids: ['018f3a2b-2222-7000-8000-000000000001'], credential_source: 'provided' })
  const identity = { name: 'wappie', title: 'Wappie', description: 'The WhatsApp archive of one Wappie workspace, for the numbers its owner authorized.', websiteUrl: 'https://wappie.thehappie.co' }
  for (const [options, icons, version] of [[undefined, [data], PACKAGE_VERSION], [{ iconOrigin: 'https://mcp.wappie.thehappie.co', version: '0.6.0' }, hosted, '0.6.0']]) {
    const [serverSide, clientSide] = InMemoryTransport.createLinkedPair()
    await createServer(config, { token: async () => ({ token: 'x', kind: 'api_key' }) }, options).connect(serverSide)
    const client = new Client({ name: 'synthetic-icons-test', version: '1' }, { versionNegotiation: { mode: 'auto' } })
    await client.connect(clientSide)
    assert.deepEqual(client.getServerVersion(), { ...identity, version, icons })
    await client.close()
  }
})
