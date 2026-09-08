// Where the server is.
//
// An empty address means this page's own origin, which is what the development
// proxy sets up and what a deployment serving the client from the same server
// gets for free. That matters beyond convenience: the websocket handler accepts
// same-origin connections only, so pointing the client at another port would be
// refused at the upgrade, before any error the app could report.

/** origin resolves a configured address, defaulting to the page it runs in. */
export function origin(serverURL: string): URL {
  // Guarded because the protocol layer is exercised in Node, where there is no
  // page to be relative to.
  const here = typeof location === 'undefined' ? undefined : location.href
  if (typeof location !== 'undefined' && ['app.wappie.thehappie.co', 'console.wappie.thehappie.co'].includes(location.hostname)) return new URL(location.origin)
  const raw = serverURL.trim()
  if (raw) return new URL(raw, here)
  if (!here) throw new Error('sem endereço de servidor e sem página para herdar um')
  return new URL(here)
}

/**
 * endpoint builds an absolute URL for a path on the server.
 *
 * The query is cleared rather than inherited, because the page's own address
 * has nothing to do with the server's. Anything the endpoint needs is passed as
 * `params` — the upload refuses a request without device and type, and building
 * that query by hand into `path` used to lose it silently here, which reads as
 * a broken type picker rather than a broken URL.
 */
export function endpoint(
  serverURL: string,
  path: string,
  params?: Record<string, string>,
): string {
  const url = origin(serverURL)
  url.pathname = path
  url.search = ''
  url.hash = ''
  for (const [key, value] of Object.entries(params ?? {})) {
    url.searchParams.set(key, value)
  }
  return url.toString()
}

/** websocketURL is the same, switched to the websocket scheme. */
export function websocketURL(serverURL: string): string {
  const url = origin(serverURL)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  url.pathname = '/v1/ws'
  url.search = ''
  url.hash = ''
  return url.toString()
}
