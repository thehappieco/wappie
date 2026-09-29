// Test material for attachments (docs/mcp-enclave.md §16): WhatsApp's media
// encryption (the sending side, written from the scheme and checked against
// Go's vectors), small JPEG and PNG files built byte by byte, worker frames,
// and a `spawn` that runs the fake media-jail (fake-jail.mjs) or a scripted
// worker in place of /usr/local/bin/media-jail. Nothing here is a real key.
import { spawn as spawnProcess } from 'node:child_process'
import { createCipheriv, createHash, createHmac, hkdfSync, randomBytes } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0 })
const crc32 = bytes => { let c = 0xffffffff; for (const byte of bytes) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0 }

export const goVectors = JSON.parse(readFileSync(new URL('../../../../internal/crypto/wamedia/testdata/vectors.json', import.meta.url), 'utf8')).vectors
export const LABELS = { image: 'WhatsApp Image Keys', sticker: 'WhatsApp Image Keys', video: 'WhatsApp Video Keys', ptv: 'WhatsApp Video Keys', audio: 'WhatsApp Audio Keys', ptt: 'WhatsApp Audio Keys', document: 'WhatsApp Document Keys' }

/**
 * The object the CDN serves for `plaintext`: AES-256-CBC with PKCS#7, then
 * the first ten bytes of HMAC-SHA256(iv ‖ ciphertext). `padding` replaces the
 * padding bytes for a negative case (the MAC and hash are still right).
 */
export function encryptMedia(plaintext, mediaKey, label, { padding } = {}) {
  const okm = Buffer.from(hkdfSync('sha256', mediaKey, Buffer.alloc(32), label, 112))
  const iv = okm.subarray(0, 16), key = okm.subarray(16, 48), macKey = okm.subarray(48, 80)
  const pad = 16 - (plaintext.length % 16)
  const padded = Buffer.concat([Buffer.from(plaintext), padding ?? Buffer.alloc(pad, pad)])
  const cipher = createCipheriv('aes-256-cbc', key, iv).setAutoPadding(false)
  const body = Buffer.concat([cipher.update(padded), cipher.final()])
  const mac = createHmac('sha256', macKey).update(iv).update(body).digest().subarray(0, 10)
  return Buffer.concat([body, mac])
}
export const sha256 = bytes => createHash('sha256').update(bytes).digest()
export const newMediaKey = () => randomBytes(32)

/** A JPEG that passes the reader's checks unless told otherwise: `app1` or `com` segments, a size to reach. */
export function jpeg({ width = 64, height = 48, app1 = false, com = false, size = 0, sof = 0xc0 } = {}) {
  const segment = (marker, body) => { const head = Buffer.from([0xff, marker, 0, 0]); head.writeUInt16BE(body.length + 2, 2); return Buffer.concat([head, body]) }
  const sofBody = Buffer.from([8, 0, 0, 0, 0, 3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1])
  sofBody.writeUInt16BE(height, 1); sofBody.writeUInt16BE(width, 3)
  const parts = [Buffer.from([0xff, 0xd8]), segment(0xe0, Buffer.from('JFIF\u0000\u0001\u0001\u0000\u0000\u0001\u0000\u0001\u0000\u0000', 'latin1'))]
  if (app1) parts.push(segment(0xe1, Buffer.from('Exif\u0000\u0000GPS', 'latin1')))
  if (com) parts.push(segment(0xfe, Buffer.from('camera', 'latin1')))
  parts.push(segment(0xdb, Buffer.alloc(65, 1)), segment(sof, sofBody), segment(0xda, Buffer.from([3, 1, 0, 2, 0x11, 3, 0x11, 0, 0x3f, 0])))
  const head = Buffer.concat(parts)
  return Buffer.concat([head, Buffer.alloc(Math.max(16, size - head.length - 2), 0x55), Buffer.from([0xff, 0xd9])])
}

/** A PNG with IHDR, IDAT and IEND, plus any `chunks` ([type, data]) before IDAT. */
export function png({ width = 64, height = 64, chunks = [], size = 0 } = {}) {
  const chunk = (type, data) => {
    const head = Buffer.alloc(8); head.writeUInt32BE(data.length, 0); head.write(type, 4, 'latin1')
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])) >>> 0)
    return Buffer.concat([head, data, crc])
  }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4); ihdr[8] = 8; ihdr[9] = 6
  const head = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), ...chunks.map(([type, data]) => chunk(type, Buffer.from(data)))])
  return Buffer.concat([head, chunk('IDAT', Buffer.alloc(Math.max(8, size - head.length - 24), 0x78)), chunk('IEND', Buffer.alloc(0))])
}

/** One stdout frame: `u32 len ‖ u8 type ‖ payload`. */
export function frame(type, payload = Buffer.alloc(0)) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload))
  const head = Buffer.alloc(5); head.writeUInt32BE(body.length, 0); head[4] = type
  return Buffer.concat([head, body])
}
export const imageFrame = (page, file) => { const head = Buffer.alloc(2); head.writeUInt16BE(page); return frame(4, Buffer.concat([head, file])) }

/** Plaintext a fake worker reads a scenario from: `magic`, then the scenario after a marker the sniff never looks at. */
export const withScenario = (magic, scenario) => Buffer.concat([Buffer.from(magic), Buffer.from(`\n@@SCENARIO@@${JSON.stringify(scenario)}`)])
export const JPEG_MAGIC = [0xff, 0xd8, 0xff, 0xe0]
export const PDF_MAGIC = Buffer.from('%PDF-1.7\n')
export const ZIP_MAGIC = [0x50, 0x4b, 0x03, 0x04]
export const WEBP_MAGIC = Buffer.concat([Buffer.from('RIFF'), Buffer.alloc(4), Buffer.from('WEBPVP8 ')])

const here = path => fileURLToPath(new URL(path, import.meta.url))
export const FAKE_JAIL = here('./media/fake-jail.mjs')
export const SCRIPTED_WORKER = here('./media/scripted-worker.mjs')

/**
 * A `spawn` for media-jail: the fake jail with its fake workers (§16.6's
 * command line, exit codes and signals), with `env` for it (FAKE_WALL_MS
 * shortens the wall; FAKE_SELF_CHECK and FAKE_TABLE change the boot check).
 * `calls` records every command line.
 */
export function fakeJailSpawn(env = {}, calls = []) {
  return (bin, args, options) => {
    calls.push({ bin, args, env: options.env })
    return spawnProcess(process.execPath, [FAKE_JAIL, ...args], { ...options, env: { ...env } })
  }
}

let scriptDir = null
const scripts = () => {
  if (!scriptDir) {
    scriptDir = mkdtempSync(join(tmpdir(), 'wappie-scripts-'))
    process.once('exit', () => rmSync(scriptDir, { recursive: true, force: true }))
  }
  return scriptDir
}
/** A `spawn` running a worker that writes exactly `stdout` and exits `exit` once it has read its stdin (no jail). */
export function scriptedSpawn({ stdout = Buffer.alloc(0), exit = 0, delayMs = 0, stdinFile, calls = [] } = {}) {
  // The script goes through a file: an environment this large is refused (E2BIG).
  const script = join(scripts(), `stdout-${randomBytes(8).toString('hex')}`)
  writeFileSync(script, stdout)
  return (bin, args, options) => {
    calls.push({ bin, args, options })
    return spawnProcess(process.execPath, [SCRIPTED_WORKER], { ...options, env: { SCRIPT_FILE: script, EXIT: String(exit), DELAY_MS: String(delayMs), ...(stdinFile ? { STDIN_FILE: stdinFile } : {}) } })
  }
}
