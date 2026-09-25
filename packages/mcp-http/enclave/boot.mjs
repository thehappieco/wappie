// What the parent hands the enclave at boot, over vsock through the local
// socat bridges: boot.json (7001) and the role credentials (7000). The parent
// is not trusted with anything here. boot.json carries only the relay secret
// as KMS ciphertext under the boot key, which only this image can open, and
// its schema is exact so the parent cannot slip a setting in beside it.
import { connect } from 'node:net'
import { decodeCiphertext } from '../internal.mjs'

export const MAX_BOOT_JSON = 16 * 1024

export class BootError extends Error {
  constructor(code) { super(code); this.name = 'BootError'; this.code = code }
}

/** Reads everything a parent vsock service sends on connect (via the local socat bridge). */
export function readLocal(port, { host = '127.0.0.1', limit = 64 * 1024, timeoutMs = 5000 } = {}) {
  return new Promise((resolve, reject) => {
    const socket = connect(port, host)
    const chunks = []
    let size = 0
    socket.setTimeout(timeoutMs, () => socket.destroy(new Error('local_timeout')))
    socket.on('data', chunk => {
      size += chunk.length
      if (size > limit) socket.destroy(new Error('local_too_large'))
      else chunks.push(chunk)
    })
    socket.on('end', () => resolve(Buffer.concat(chunks)))
    socket.on('error', reject)
  })
}

/**
 * `{relayCiphertext}` from boot.json bytes: an object with exactly the key
 * relay_secret_ciphertext, standard padded base64 of 1 to 6144 bytes, at most
 * 16 KiB in all. Anything else is BootError('boot_json_invalid').
 */
export function parseBootJson(bytes) {
  const invalid = () => { throw new BootError('boot_json_invalid') }
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_BOOT_JSON) invalid()
  let parsed
  try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) } catch { invalid() }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) invalid()
  const keys = Object.keys(parsed)
  if (keys.length !== 1 || keys[0] !== 'relay_secret_ciphertext') invalid()
  const relayCiphertext = decodeCiphertext(parsed.relay_secret_ciphertext)
  if (!relayCiphertext) invalid()
  return { relayCiphertext }
}
