// The Wappie icon, for hosts that show one beside the connector
// (docs/mcp-enclave.md §5.4). The files in icons/ are the console's own
// (wappie-cloud web/public: favicon-light.svg, favicon-32.png and
// apple-touch-icon.png), byte for byte; favicon.ico is built from the two
// PNGs here, so nothing in it is new. In the enclave image they are measured
// into PCR0 like every other file.
//
// serverInfo.icons (MCP 2025-11-25, Implementation.icons) carries the PNG as a
// data: URI on every reader, since a host may render only what the initialize
// response holds, and, where the reader serves the files on its own https
// origin (the enclave), their URLs too: the spec asks a client to take icon
// URLs only from the server's own origin.
import { readFileSync } from 'node:fs'

const read = name => readFileSync(new URL(`./icons/${name}`, import.meta.url))
const svg = read('favicon.svg'), png32 = read('favicon-32.png'), png180 = read('apple-touch-icon.png')

/** A PNG's width and height, from its IHDR chunk. */
function pngSize(png) {
  if (png.length < 24 || png.readUInt32BE(0) !== 0x89504e47 || png.toString('latin1', 12, 16) !== 'IHDR') throw new Error('icon_invalid')
  return { width: png.readUInt32BE(16), height: png.readUInt32BE(20) }
}

/**
 * An ICO that holds PNG images unchanged (the format since Windows Vista,
 * which browsers and favicon crawlers read): a 6-byte directory, a 16-byte
 * entry per image (0 for 256 pixels), then the images in the same order.
 */
function ico(pngs) {
  const head = Buffer.alloc(6 + 16 * pngs.length)
  head.writeUInt16LE(0, 0); head.writeUInt16LE(1, 2); head.writeUInt16LE(pngs.length, 4)
  let offset = head.length
  pngs.forEach((png, index) => {
    const { width, height } = pngSize(png)
    if (width > 256 || height > 256) throw new Error('icon_invalid')
    const entry = 6 + 16 * index
    head.writeUInt8(width % 256, entry); head.writeUInt8(height % 256, entry + 1)
    head.writeUInt16LE(1, entry + 4); head.writeUInt16LE(32, entry + 6)
    head.writeUInt32LE(png.length, entry + 8); head.writeUInt32LE(offset, entry + 12)
    offset += png.length
  })
  return Buffer.concat([head, ...pngs])
}

const size = png => { const { width, height } = pngSize(png); return `${width}x${height}` }
// Built once: every MCP request builds its own server.
const data = `data:image/png;base64,${png180.toString('base64')}`, sizes180 = size(png180)

/** The icon routes of the enclave's public listener: path → {type, bytes}. */
export const ICON_FILES = Object.freeze({
  '/favicon.ico': Object.freeze({ type: 'image/x-icon', bytes: ico([png32, png180]) }),
  '/favicon.svg': Object.freeze({ type: 'image/svg+xml', bytes: svg }),
  '/apple-touch-icon.png': Object.freeze({ type: 'image/png', bytes: png180 }),
})

/**
 * serverInfo.icons: the 180-pixel PNG as a data: URI, then, with `origin`
 * (the https origin that serves ICON_FILES), the SVG and the PNG by URL. A
 * client refuses any other scheme, so an origin that is not https adds none.
 */
export function serverIcons(origin) {
  const icons = [{ src: data, mimeType: 'image/png', sizes: [sizes180] }]
  if (/^https:\/\/[^/?#]+$/.test(origin ?? '')) icons.push(
    { src: `${origin}/favicon.svg`, mimeType: 'image/svg+xml', sizes: ['any'] },
    { src: `${origin}/apple-touch-icon.png`, mimeType: 'image/png', sizes: [sizes180] },
  )
  return icons
}
