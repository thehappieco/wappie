// The only way anything leaves the enclave as a log: lines from createLog,
// checked here against the same schema the parent's receiver (log-sink.py)
// enforces, and written to vsock 7002 through the local socat bridge. Node's
// stdout and stderr go to /dev/null (entrypoint.sh), so a stray console.log,
// a stack trace or SDK output never reaches the parent. A line that fails the
// schema is dropped and counted, never repaired: repairing is how a secret
// slips through a filter.
import { connect } from 'node:net'

export const MAX_LINE_BYTES = 2048
export const MAX_QUEUE = 1000
const RULES = {
  ts: value => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value),
  route: value => typeof value === 'string' && (['public', 'internal', 'unmatched'].includes(value) || /^(GET|POST|PUT|DELETE|HEAD|OPTIONS) \/[a-z0-9/{}._-]{0,80}$/.test(value)),
  status: value => Number.isInteger(value) && value >= 100 && value <= 599,
  ms: value => Number.isInteger(value) && value >= 0,
  event: value => typeof value === 'string' && /^[a-z][a-z0-9_]{0,47}$/.test(value),
  code: value => typeof value === 'string' && /^[a-z][a-z0-9_]{0,47}$/.test(value),
}
for (const key of ['conn', 'client', 'policy', 'spki', 'pcr0']) RULES[key] = value => typeof value === 'string' && /^[0-9a-f]{12}$/.test(value)
const otherKey = /^[a-z][a-z0-9_]{0,31}$/

/** Whether a line (without its newline) is one the parent's receiver accepts. */
export function lineAllowed(line) {
  if (typeof line !== 'string' || Buffer.byteLength(line, 'utf8') > MAX_LINE_BYTES) return false
  let entry
  try { entry = JSON.parse(line) } catch { return false }
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false
  for (const [key, value] of Object.entries(entry)) {
    const rule = RULES[key]
    if (rule ? !rule(value) : !(otherKey.test(key) && ((typeof value === 'number' && Number.isFinite(value)) || typeof value === 'boolean'))) return false
  }
  return typeof entry.ts === 'string'
}

/**
 * A reconnecting writer to `host:port`. `write(line)` is the createLog sink.
 * At most 1000 lines wait, counting both the queue and the lines the socket
 * still buffers, whether the parent is away or connected but not reading; the
 * excess is dropped and counted, like a line that fails the schema. The
 * socket's backpressure is respected: once `socket.write` returns false,
 * nothing more is handed to it until 'drain'.
 */
export function createSinkWriter({ host = '127.0.0.1', port, connectTo = connect }) {
  const queue = []
  let socket = null, connecting = false, dropped = 0, backoff = 1000, timer = null, closed = false
  // Lines handed to the current socket that it has not yet passed to the
  // kernel, and whether it asked us to wait for 'drain'.
  let held = 0, blocked = false
  function open() {
    if (socket || connecting || closed) return
    connecting = true
    const next = connectTo({ host, port })
    next.setNoDelay?.(true)
    next.once('connect', () => { connecting = false; socket = next; held = 0; blocked = false; backoff = 1000; flush() })
    next.on('drain', () => { if (socket === next) { blocked = false; flush() } })
    next.on('error', () => {})
    next.once('close', () => {
      connecting = false
      if (socket === next) { socket = null; held = 0; blocked = false }
      if (!closed && !timer) { timer = setTimeout(() => { timer = null; open() }, backoff); timer.unref?.(); backoff = Math.min(backoff * 2, 30_000) }
    })
  }
  function flush() {
    while (socket && !blocked && queue.length) {
      const target = socket
      held++
      if (!target.write(queue.shift(), () => { if (socket === target) held-- })) blocked = true
    }
  }
  function full() {
    return queue.length + held >= MAX_QUEUE || (socket?.writableLength ?? 0) > MAX_QUEUE * MAX_LINE_BYTES
  }
  return {
    write(line) {
      if (!lineAllowed(line) || full()) { dropped++; return }
      queue.push(line + '\n')
      if (socket) flush(); else open()
    },
    dropped: () => dropped,
    queued: () => queue.length,
    /** Lines the socket still buffers (handed to it, not yet passed to the kernel). */
    held: () => held,
    /** Resolves once the queue is written (or after `timeoutMs`): the fatal path's last line. */
    async drain(timeoutMs = 1000) {
      const until = Date.now() + timeoutMs
      open()
      while ((queue.length || (socket && socket.writableLength)) && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 20))
    },
    close() { closed = true; if (timer) clearTimeout(timer); socket?.end(); socket = null },
  }
}
