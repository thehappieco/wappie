// node:http <-> web Request/Response. The SDK's HTTP handler and middleware
// speak fetch-standard objects; this is the whole bridge, kept dependency-free
// so the reader holds exactly one MCP SDK instance (see @whatserver2/mcp/sdk).
import { Readable } from 'node:stream'

/**
 * Builds a web `Request` for a node:http request, buffering the body up to
 * `maxBytes`. Returns null when the body is larger (the caller answers 413);
 * every route on this server handles small bodies, so buffering is simpler
 * and safer than streaming an unbounded one into a parser.
 */
export async function toWebRequest(req, origin, maxBytes) {
  const method = req.method.toUpperCase()
  const url = new URL(req.url, origin)
  const headers = new Headers()
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue
    headers.set(name, Array.isArray(value) ? value.join(', ') : value)
  }
  let body
  if (method !== 'GET' && method !== 'HEAD') {
    const declared = Number(req.headers['content-length'])
    if (Number.isFinite(declared) && declared > maxBytes) return null
    const chunks = []
    let size = 0
    for await (const chunk of req) {
      size += chunk.length
      if (size > maxBytes) return null
      chunks.push(chunk)
    }
    body = Buffer.concat(chunks, size)
  }
  return new Request(url, { method, headers, body })
}

/** Writes a web `Response` to a node:http response, streaming its body. */
export async function sendWebResponse(res, response) {
  const headers = {}
  for (const [name, value] of response.headers) headers[name] = value
  res.writeHead(response.status, headers)
  if (!response.body) { res.end(); return }
  await new Promise((resolve, reject) => {
    const stream = Readable.fromWeb(response.body)
    stream.once('error', reject)
    res.once('close', resolve)
    res.once('error', reject)
    stream.pipe(res)
  }).catch(() => { res.destroy() })
}
