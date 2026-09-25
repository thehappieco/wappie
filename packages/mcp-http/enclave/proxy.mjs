// PROXY protocol v2 on the enclave's HTTPS listeners (5443 public, 5444
// internal). The parent's haproxy runs in TCP mode and prepends a PROXY v2
// header, so the enclave learns the client address without the parent ever
// seeing inside TLS. Everything else is refused by closing the socket: v1
// text headers, LOCAL, UNIX, UNSPEC, DGRAM, a header over 536 bytes, a
// truncated one, garbage, or nothing within 5 s. TLVs are ignored.
//
// The address from the header becomes the TLS socket's remoteAddress, so the
// router and the limiter see the client and nothing ever trusts
// X-Forwarded-For here (the socket peer itself is socat on loopback).
import { createServer as createNetServer } from 'node:net'
import { Duplex } from 'node:stream'
import { TLSSocket } from 'node:tls'

export const SIGNATURE = Buffer.from('0d0a0d0a000d0a515549540a', 'hex')
export const MAX_HEADER = 536
export const HEADER_TIMEOUT_MS = 5000
export const HANDSHAKE_TIMEOUT_MS = 10_000
const FAMILIES = { 0x11: { size: 12, family: 'IPv4' }, 0x21: { size: 36, family: 'IPv6' } }

function ipv6(bytes) {
  // An IPv4-mapped source is the IPv4 client it maps (limits.mjs keys it so).
  if (bytes.subarray(0, 10).every(byte => byte === 0) && bytes[10] === 0xff && bytes[11] === 0xff) return [...bytes.subarray(12)].join('.')
  const groups = []
  for (let i = 0; i < 16; i += 2) groups.push(bytes.readUInt16BE(i).toString(16))
  return groups.join(':')
}

/**
 * Parses the start of a connection. Returns `{need}` while more bytes could
 * still make a valid header, `{error}` once they cannot, or
 * `{address, port, length}` with the header's total length.
 */
export function parseProxyV2(data) {
  const prefix = Math.min(data.length, SIGNATURE.length)
  if (!data.subarray(0, prefix).equals(SIGNATURE.subarray(0, prefix))) return { error: 'proxy_invalid' }
  if (data.length < 16) return { need: 16 - data.length }
  if (data[12] === 0x20) return { error: 'proxy_local' }
  if (data[12] !== 0x21) return { error: 'proxy_invalid' }
  const family = FAMILIES[data[13]]
  if (!family) return { error: 'proxy_family' }
  const length = 16 + data.readUInt16BE(14)
  if (length > MAX_HEADER || length - 16 < family.size) return { error: 'proxy_invalid' }
  if (data.length < length) return { need: length - data.length }
  const address = family.family === 'IPv4' ? [...data.subarray(16, 20)].join('.') : ipv6(data.subarray(16, 32))
  const port = family.family === 'IPv4' ? data.readUInt16BE(24) : data.readUInt16BE(48)
  return { address, port, length }
}

/**
 * A duplex over `socket` that first yields `head`: TLSSocket reads straight
 * from a net.Socket's handle and would never see bytes already read into
 * JavaScript, so anything past the PROXY header travels through this.
 */
function prepend(socket, head) {
  const duplex = new Duplex({
    read() { socket.resume() },
    write(chunk, encoding, callback) { socket.write(chunk, callback) },
    final(callback) { socket.end(); callback() },
    destroy(error, callback) { socket.destroy(); callback(error) },
  })
  duplex.push(head)
  socket.on('data', chunk => { if (!duplex.push(chunk)) socket.pause() })
  socket.on('end', () => duplex.push(null))
  socket.on('error', error => duplex.destroy(error))
  socket.on('close', () => duplex.destroy())
  return duplex
}

/**
 * Reads the PROXY v2 header from a raw socket, then calls
 * `onProxied(stream, {address, port})` with a paused stream positioned right
 * after the header. `onRejected(code)` hears every refusal (for counters).
 */
export function readProxyHeader(socket, { onProxied, onRejected = () => {}, timeoutMs = HEADER_TIMEOUT_MS }) {
  let buffered = Buffer.alloc(0), done = false
  const reject = code => { if (done) return; done = true; clearTimeout(timer); socket.destroy(); onRejected(code) }
  const timer = setTimeout(() => reject('proxy_timeout'), timeoutMs)
  timer.unref?.()
  socket.on('error', () => reject('proxy_socket_error'))
  const onData = chunk => {
    buffered = Buffer.concat([buffered, chunk])
    const parsed = parseProxyV2(buffered)
    if (parsed.need) return
    if (parsed.error) return reject(parsed.error)
    done = true
    clearTimeout(timer)
    socket.off('data', onData)
    socket.pause()
    const rest = buffered.subarray(parsed.length)
    onProxied(rest.length ? prepend(socket, rest) : socket, { address: parsed.address, port: parsed.port })
  }
  socket.on('data', onData)
  socket.once('end', () => reject('proxy_truncated'))
}

/**
 * A loopback listener that accepts PROXY v2, terminates TLS with the current
 * `secureContext()` and hands each TLS socket to `httpServer` (a node:http
 * Server that is never listening itself). `onRejected(code)` counts refusals.
 */
export function createProxiedTLSListener({ httpServer, secureContext, onRejected = () => {}, headerTimeoutMs = HEADER_TIMEOUT_MS, handshakeTimeoutMs = HANDSHAKE_TIMEOUT_MS }) {
  return createNetServer(socket => {
    readProxyHeader(socket, {
      timeoutMs: headerTimeoutMs, onRejected,
      onProxied(stream, source) {
        let tls
        try {
          tls = new TLSSocket(stream, { isServer: true, secureContext: secureContext(), ALPNProtocols: ['http/1.1'] })
        } catch { stream.destroy(); onRejected('tls_unavailable'); return }
        Object.defineProperty(tls, 'remoteAddress', { value: source.address, configurable: true })
        Object.defineProperty(tls, 'remotePort', { value: source.port, configurable: true })
        const handshake = setTimeout(() => { tls.destroy(); onRejected('tls_handshake_timeout') }, handshakeTimeoutMs)
        handshake.unref?.()
        tls.once('secure', () => clearTimeout(handshake))
        tls.on('error', () => { clearTimeout(handshake); tls.destroy() })
        tls.once('close', () => clearTimeout(handshake))
        httpServer.emit('connection', tls)
      },
    })
  })
}

/** A PROXY v2 header for tests and for the parent's own tooling. */
export function encodeProxyV2({ address, port, destination = '127.0.0.1', destinationPort = 443 }) {
  const v6 = address.includes(':')
  const body = Buffer.alloc(v6 ? 36 : 12)
  const put = (value, at) => {
    if (!v6) { value.split('.').forEach((part, i) => { body[at + i] = Number(part) }); return }
    const [head, tail = ''] = value.split('::')
    const left = head ? head.split(':') : [], right = tail ? tail.split(':') : []
    const groups = value.includes('::') ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left
    groups.forEach((group, i) => body.writeUInt16BE(parseInt(group, 16), at + i * 2))
  }
  put(address, 0)
  put(v6 && !destination.includes(':') ? '::1' : destination, v6 ? 16 : 4)
  body.writeUInt16BE(port, v6 ? 32 : 8)
  body.writeUInt16BE(destinationPort, v6 ? 34 : 10)
  const head = Buffer.alloc(16)
  SIGNATURE.copy(head)
  head[12] = 0x21
  head[13] = v6 ? 0x21 : 0x11
  head.writeUInt16BE(body.length, 14)
  return Buffer.concat([head, body])
}
