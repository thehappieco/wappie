#!/usr/bin/env node
// The hosted Wappie MCP reader: one node:http listener on loopback behind the
// reverse proxy, serving the metadata-only MCP resource server and its
// in-process authorization server. Configuration comes from the environment;
// the only secret (the relay secret shared with Go) comes from a private file.
import { createServer as createHTTPServer } from 'node:http'
import { realpathSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { archiveOrigin } from '@whatserver2/client'
import { readPrivateFile } from '@whatserver2/mcp/config'
import { createAuthorizationServer } from './as.mjs'
import { createCIMD } from './cimd.mjs'
import { createClients } from './clients.mjs'
import { createRelay, internalRoutes, RelayError } from './internal.mjs'
import { createLimiter, isLoopback } from './limits.mjs'
import { createLog } from './log.mjs'
import { createMetadata } from './metadata.mjs'
import { sendWebResponse, toWebRequest } from './node-adapter.mjs'
import { bodyLimitFor, createRouter } from './router.mjs'
import { openState, StateError } from './state.mjs'
import { createTokens } from './tokens.mjs'
import { createStatusCheck, createVerifier } from './verifier.mjs'

export class ConfigError extends Error {
  constructor(code) { super(code); this.name = 'ConfigError'; this.code = code }
}
const hostShape = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/
const loopbackHost = hostname => hostname === 'localhost' || isLoopback(hostname) || hostname === '[::1]'

function origin(value, code) {
  let url
  try { url = new URL(value) } catch { throw new ConfigError(code) }
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new ConfigError(code)
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopbackHost(url.hostname))) throw new ConfigError(code)
  return url.origin
}

/** Reads and validates the WAPPIE_MCP_* environment; the relay secret file is read separately. */
export function readEnv(env = process.env) {
  const listen = env.WAPPIE_MCP_LISTEN || '127.0.0.1:18093'
  const separator = listen.lastIndexOf(':')
  const host = separator > 0 ? listen.slice(0, separator) : '', port = Number(listen.slice(separator + 1))
  if (!host || !Number.isInteger(port) || port < 0 || port > 65535) throw new ConfigError('invalid_listen')
  const publicOrigin = env.WAPPIE_MCP_PUBLIC_ORIGIN ? origin(env.WAPPIE_MCP_PUBLIC_ORIGIN, 'invalid_public_origin') : null
  if (!publicOrigin && !loopbackHost(host.replace(/^\[|\]$/g, ''))) throw new ConfigError('public_origin_required')
  if (!env.WAPPIE_MCP_CONSOLE_URL) throw new ConfigError('console_url_required')
  let consoleURL
  try { consoleURL = new URL(env.WAPPIE_MCP_CONSOLE_URL) } catch { throw new ConfigError('invalid_console_url') }
  if (consoleURL.username || consoleURL.password || consoleURL.hash || (consoleURL.protocol !== 'https:' && !(consoleURL.protocol === 'http:' && loopbackHost(consoleURL.hostname)))) throw new ConfigError('invalid_console_url')
  if (!env.WAPPIE_MCP_RELAY_SECRET_FILE) throw new ConfigError('relay_secret_file_required')
  let archive
  try { archive = archiveOrigin(env.WAPPIE_MCP_ARCHIVE_URL || 'http://127.0.0.1:18090') } catch { throw new ConfigError('invalid_archive_url') }
  const hosts = (env.WAPPIE_MCP_REDIRECT_HOSTS || 'claude.ai,chatgpt.com').split(',').map(item => item.trim().toLowerCase()).filter(Boolean)
  if (hosts.length === 0 || hosts.some(item => !hostShape.test(item))) throw new ConfigError('invalid_redirect_hosts')
  const cimd = env.WAPPIE_MCP_CIMD || 'on'
  if (cimd !== 'on' && cimd !== 'off') throw new ConfigError('invalid_cimd')
  const pendingTTL = Number(env.WAPPIE_MCP_PENDING_TTL_SECONDS || 1200)
  if (!Number.isInteger(pendingTTL) || pendingTTL < 60 || pendingTTL > 86400) throw new ConfigError('invalid_pending_ttl')
  return {
    listen: { host: host.replace(/^\[|\]$/g, ''), port }, publicOrigin, consoleURL: consoleURL.href,
    stateDir: env.WAPPIE_MCP_STATE_DIR || '/var/lib/wappie-mcp', relaySecretFile: env.WAPPIE_MCP_RELAY_SECRET_FILE,
    archive, hosts: [...new Set(hosts)], cimd: cimd === 'on', pendingTTLMs: pendingTTL * 1000,
  }
}

async function readRelaySecret(path) {
  let data
  try { data = await readPrivateFile(path, { maxBytes: 4096 }) } catch { throw new ConfigError('relay_secret_unavailable') }
  try {
    const secret = data.toString('utf8').trim()
    if (secret.length < 32 || /\s/.test(secret)) throw new ConfigError('relay_secret_invalid')
    return secret
  } finally { data.fill(0) }
}

/**
 * Starts the reader. `options.env` replaces process.env, `options.now` the
 * clock, `options.logSink` the log line writer; tests use all three.
 */
export async function startReader(options = {}) {
  const config = readEnv(options.env ?? process.env)
  const now = options.now ?? Date.now
  const log = createLog(options.logSink, now)
  const secret = await readRelaySecret(config.relaySecretFile)
  const state = await openState(config.stateDir)
  const relay = createRelay({ archive: config.archive, secret })
  // Go is the authority on connections: anything it no longer serves is dropped
  // before the first request. An unreachable Go keeps the state as it was; the
  // per-request check catches up within a minute.
  let dropped = 0
  for (const id of [...state.connections.keys()]) {
    try {
      const status = await relay.status(id)
      if (!status || status.status !== 'active') { state.wipeConnection(id); dropped++ }
    } catch (error) { if (!(error instanceof RelayError)) throw error; log.event('reconcile_skipped'); break }
  }
  if (dropped) { await state.save(); log.event('reconcile_dropped', { connections: dropped }) }

  const server = createHTTPServer({ maxHeaderSize: 16 * 1024 })
  server.headersTimeout = 10_000
  server.requestTimeout = 60_000
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(config.listen.port, config.listen.host, () => { server.off('error', reject); resolve() }) })
  const address = server.address()
  const publicOrigin = config.publicOrigin ?? `http://${address.family === 'IPv6' ? `[${address.address}]` : address.address}:${address.port}`

  const limiter = createLimiter(now)
  const metadata = createMetadata({ publicOrigin, cimd: config.cimd })
  const onWiped = async id => { await relay.revoke(id) }
  const checkActive = createStatusCheck({ state, relay, now })
  const tokens = createTokens(state, { now, checkActive, onFamilyRevoked: onWiped })
  const verifier = createVerifier({ tokens, state, resource: metadata.resource, checkActive })
  const clients = createClients(state, { now, hosts: config.hosts })
  const cimd = createCIMD(state, { relay, now, enabled: config.cimd, hosts: config.hosts })
  const as = createAuthorizationServer({ state, clients, cimd, tokens, limiter, relay, log, now, publicOrigin, consoleURL: config.consoleURL, resource: metadata.resource, pendingTTLMs: config.pendingTTLMs })
  const internal = internalRoutes({ state, secret, now, pendingFor: as.pendingFor })
  const router = createRouter({ state, metadata, as, internal, verifier, limiter, log, archive: config.archive, publicHost: new URL(publicOrigin).hostname })

  server.on('request', async (req, res) => {
    const started = now(), meta = {}
    let response
    try {
      const request = await toWebRequest(req, publicOrigin, bodyLimitFor(req.url.split('?')[0]))
      if (!request) { meta.route = 'public'; meta.code = 'body_too_large'; response = Response.json({ code: 'body_too_large' }, { status: 413, headers: { Connection: 'close' } }) }
      else response = await router.handle(request, { remoteAddress: req.socket.remoteAddress }, meta)
    } catch {
      meta.code = 'internal_error'
      response = Response.json({ code: 'internal_error' }, { status: 500, headers: { 'Cache-Control': 'no-store' } })
    }
    try { await sendWebResponse(res, response) } catch { /* the peer went away */ }
    log.request({ route: meta.route ?? 'unmatched', status: response.status, ms: now() - started, connection: meta.connection, client: meta.client, code: meta.code })
  })

  async function sweep() {
    as.sweepPending()
    let changed = tokens.sweep() | clients.sweep()
    for (const [id, connection] of state.connections) if (Date.parse(connection.expires_at) <= now()) { state.wipeConnection(id); changed = 1 }
    if (changed) await state.save()
  }
  const timer = setInterval(() => { sweep().catch(() => {}) }, 30_000)
  timer.unref()
  log.event('listening', { port: address.port, cimd: config.cimd })
  return {
    port: address.port, publicOrigin, resource: metadata.resource, state, config, sweep,
    async close() {
      clearInterval(timer)
      await router.close()
      await new Promise(resolve => server.close(resolve))
      server.closeAllConnections?.()
      await state.close()
    },
  }
}

const invokedDirectly = process.argv[1] && (() => { try { return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href } catch { return false } })()
if (invokedDirectly) {
  try {
    const reader = await startReader()
    const stop = () => { void reader.close().finally(() => { process.exitCode = 0 }) }
    process.once('SIGINT', stop); process.once('SIGTERM', stop)
  } catch (error) {
    const code = error instanceof ConfigError || error instanceof StateError ? error.code : 'startup_failed'
    process.stderr.write(`Wappie MCP HTTP: ${code}.\n`)
    process.exitCode = 1
  }
}
