// The log sink writer (vsock 7002 through socat, a TCP socket here) and the
// health line with its clock probe.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer as createHTTPServer } from 'node:http'
import { connect, createServer as createNetServer } from 'node:net'
import { createLog } from '../../log.mjs'
import { clockSkew, createHealthLine, prefix } from '../health.mjs'
import { createSinkWriter, lineAllowed, MAX_LINE_BYTES, MAX_QUEUE } from '../logsink.mjs'

const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)))

test('sink writer: schema-checked lines only, queued while the parent is away, at most 1000, then delivered in order', async t => {
  const received = []
  let buffer = ''
  const server = createNetServer(socket => socket.on('data', chunk => { buffer += chunk; const parts = buffer.split('\n'); buffer = parts.pop(); received.push(...parts) }))
  const port = await listen(server)
  await new Promise(resolve => server.close(resolve)) // nobody listens yet
  const writer = createSinkWriter({ port })
  t.after(() => writer.close())
  const log = createLog(line => writer.write(line))
  log.event('first', { n: 1 })
  writer.write('{"ts":"2026-09-25T10:00:00.000Z","event":"x","query":"secret words"}')
  writer.write('plain text from somewhere')
  for (let i = 0; i < MAX_QUEUE + 5; i++) log.event('filler', { i })
  assert.equal(writer.queued(), MAX_QUEUE)
  assert.equal(writer.dropped(), 2 + 6)
  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve))
  t.after(() => new Promise(resolve => server.close(resolve)))
  const until = Date.now() + 5000
  while (received.length < MAX_QUEUE && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 50))
  assert.equal(received.length, MAX_QUEUE)
  assert.equal(JSON.parse(received[0]).event, 'first')
  assert.ok(received.every(lineAllowed))
  assert.equal(received.some(line => line.includes('secret words')), false)
  log.event('after', { ok: true })
  await writer.drain()
  await new Promise(resolve => setTimeout(resolve, 50))
  assert.equal(JSON.parse(received.at(-1)).event, 'after')
})

test('sink writer: a parent that accepts but stops reading holds memory at the cap, drops the excess, and gets everything kept once it reads again', async t => {
  const peers = []
  let received = 0, buffer = ''
  const server = createNetServer(socket => {
    peers.push(socket)
    socket.pause() // accepts, never reads (until resumed below)
    socket.on('data', chunk => { buffer += chunk; const parts = buffer.split('\n'); buffer = parts.pop(); received += parts.length })
  })
  const port = await listen(server)
  t.after(() => new Promise(resolve => { for (const peer of peers) peer.destroy(); server.close(resolve) }))
  let socket = null
  const writer = createSinkWriter({ port, connectTo: options => (socket = connect(options)) })
  t.after(() => writer.close())
  // Lines close to the 2048-byte limit, so the kernel buffers fill quickly.
  const big = i => JSON.stringify({ ts: '2026-09-25T10:00:00.000Z', event: 'filler', i, ...Object.fromEntries(Array.from({ length: 70 }, (_, k) => [`field_${k}`, 1234567890 + k])) })
  assert.ok(lineAllowed(big(0)) && Buffer.byteLength(big(0)) > MAX_LINE_BYTES - 600, `line of ${Buffer.byteLength(big(0))} bytes`)
  writer.write(big(0))
  const until = Date.now() + 5000
  while (!socket?.readyState?.startsWith('open') && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 10))
  let written = 1, peak = 0
  for (let round = 0; round < 40; round++) {
    for (let i = 0; i < 500; i++) writer.write(big(written++))
    await new Promise(resolve => setImmediate(resolve))
    await new Promise(resolve => setTimeout(resolve, 5))
    assert.ok(writer.queued() + writer.held() <= MAX_QUEUE, `queued ${writer.queued()} + held ${writer.held()}`)
    peak = Math.max(peak, socket.writableLength)
  }
  assert.ok(peak <= MAX_QUEUE * MAX_LINE_BYTES, `writableLength peaked at ${peak}`)
  assert.ok(writer.dropped() > 0, 'the excess is dropped')
  const droppedWhileStuck = writer.dropped()
  writer.write(big(written++))
  assert.equal(writer.dropped(), droppedWhileStuck + 1, 'still full: one more line is one more drop')
  // The parent reads again: the socket drains, the queue follows, drain() resolves empty.
  for (const peer of peers) peer.resume()
  await writer.drain(10_000)
  assert.equal(writer.queued(), 0)
  assert.equal(socket.writableLength, 0)
  const settle = Date.now() + 5000
  while (received < written - writer.dropped() && Date.now() < settle) await new Promise(resolve => setTimeout(resolve, 20))
  assert.equal(received, written - writer.dropped(), 'every line not dropped arrives')
  // Normal delivery afterwards.
  createLog(line => writer.write(line)).event('after', { ok: true })
  await writer.drain()
  const last = Date.now() + 2000
  while (received < written - writer.dropped() + 1 && Date.now() < last) await new Promise(resolve => setTimeout(resolve, 20))
  assert.equal(received, written - writer.dropped() + 1)
})

test('health line: process figures, the reader fields, the clock skew against a Date header, unknown fields omitted', async t => {
  const offset = -3000 // the server's clock is 3 s behind ours
  const http = createHTTPServer((req, res) => { res.writeHead(400, { date: new Date(Date.now() + offset).toUTCString() }); res.end() })
  const port = await listen(http)
  t.after(() => new Promise(resolve => http.close(resolve)))
  const skew = await clockSkew({ url: `http://127.0.0.1:${port}/` })
  assert.ok(skew >= 2000 && skew <= 4100, `skew ${skew}`) // Date has 1 s resolution
  assert.equal(await clockSkew({ url: 'http://127.0.0.1:1/' }), null)
  const lines = []
  const line = createHealthLine({ log: createLog(entry => lines.push(entry)), probe: async () => 1234, fields: () => ({ connections: 2, pcr0: prefix('ab'.repeat(48)), spki: prefix(null), cert_days_left: undefined, policy_ok: false }) })
  const entry = await line.tick()
  assert.equal(entry.clock_skew_ms, 1234)
  assert.equal(entry.pcr0, 'abababababab')
  assert.equal('spki' in entry, false)
  assert.equal('cert_days_left' in entry, false)
  assert.ok(Number.isInteger(entry.rss_mb) && Number.isInteger(entry.uptime_s))
  assert.equal(lineAllowed(lines[0]), true)
  assert.equal(JSON.parse(lines[0]).event, 'health')
})
