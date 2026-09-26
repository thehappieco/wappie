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
import { AttestationError, createAttestor } from './attestation.mjs'
import { createCIMD } from './cimd.mjs'
import { createClients } from './clients.mjs'
import { createRelay, internalRoutes, RelayError } from './internal.mjs'
import { createLimiter, isLoopback } from './limits.mjs'
import { createLog, fingerprint } from './log.mjs'
import { descriptor } from './link.mjs'
import { createMetadata } from './metadata.mjs'
import { sendWebResponse, toWebRequest } from './node-adapter.mjs'
import { bodyLimitFor, createRouter } from './router.mjs'
import { newRecipient, openState, StateError } from './state.mjs'
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

/** How long a consented connection may wait for its code to be exchanged; the code itself lives a minute. */
export const UNCLAIMED_CONNECTION_MS = 5 * 60_000
/** How often every content connection is checked with Go, whether or not a token arrives. */
export const CONTENT_SWEEP_MS = 60_000

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
 * clock, `options.logSink` the log line writer; tests use all three, and with
 * only those the reader is the hosted one, exactly as before.
 *
 * The enclave (enclave/main.mjs) injects the rest; nothing here imports it:
 * - `config` replaces readEnv (the image's constants, plus `readerId`,
 *   `readerVersion`, `listenerHosts` ({public, internal} exact Host values),
 *   and the `spki()`, `policy()` and `health()` getters);
 * - `secrets` (the relay secret holder, enclave/secrets.mjs) replaces the
 *   relay secret file, and its `rotate` adds POST /internal/relay-secret;
 * - `state` (openSealedState), `relay` (createSignedRelay) and
 *   `internalAuth(request, info)` (the HMAC guard) replace their hosted forms;
 * - `servers` ({public, internal}) are created but not listening: handlers
 *   are attached here, after reconciling, replacing whatever answered before;
 * - `keys: 'per-request'` mints a key for every pending request;
 * - `attest({publicKey, nonce, userData})` returns a raw NSM document and turns
 *   on prepare and the public /attestation route;
 * - `content` (enclave/content.mjs) makes content connections possible: it
 *   accepts their bundles, proofs and renewals, decides their status, holds
 *   their keys and builds their readers. Without it (the pilot) a bundle
 *   labelled `content` is a bad request and no such connection can exist.
 */
export async function startReader(options = {}) {
  const config = options.config ?? readEnv(options.env ?? process.env)
  const now = options.now ?? Date.now
  const log = createLog(options.logSink, now)
  // Without a relay secret file there is no bearer: both directions must be replaced.
  if (options.secrets && (!options.relay || !options.internalAuth)) throw new ConfigError('injection_incomplete')
  const secret = options.secrets ? null : await readRelaySecret(config.relaySecretFile)
  const state = options.state ?? await openState(config.stateDir)
  const relay = options.relay ?? createRelay({ archive: config.archive, secret })
  const content = options.content
  // Go is the authority on connections: anything it no longer serves is dropped
  // before the first request. An unreachable Go keeps the state as it was; the
  // per-request check catches up within a minute.
  let dropped = 0
  const withContent = []
  for (const id of [...state.connections.keys()]) {
    if (state.connections.get(id).kind === 'content') { withContent.push(id); continue }
    try {
      const status = await relay.status(id)
      if (!status || status.status !== 'active') { state.wipeConnection(id); dropped++ }
    } catch (error) { if (!(error instanceof RelayError)) throw error; log.event('reconcile_skipped'); break }
  }
  // No content connection has a key after a start. Each is kept, as `reseal`
  // in Go, until its owner renews it; `onBoot` asks Go (retrying in the
  // background while Go is away) and says which ones Go no longer has.
  for (const id of withContent) {
    const record = state.connections.get(id)
    if (record && (!content || (await content.onBoot(record)) === 'wipe')) { state.wipeConnection(id); dropped++ }
  }
  if (dropped) { await state.save(); log.event('reconcile_dropped', { connections: dropped }) }

  const injected = options.servers
  const server = injected?.public ?? createHTTPServer({ maxHeaderSize: 16 * 1024 })
  if (!injected) {
    server.headersTimeout = 10_000
    server.requestTimeout = 60_000
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(config.listen.port, config.listen.host, () => { server.off('error', reject); resolve() }) })
  }
  const address = injected ? null : server.address()
  const publicOrigin = injected ? config.publicOrigin : config.publicOrigin ?? `http://${address.family === 'IPv6' ? `[${address.address}]` : address.address}:${address.port}`

  const limiter = createLimiter(now)
  const metadata = createMetadata({ publicOrigin, cimd: config.cimd })
  const onWiped = async (id, reason) => {
    if (reason) log.event('family_reuse', { conn: fingerprint(id) })
    await relay.revoke(id, reason)
  }
  // A connection the status check wipes (a service mismatch above all) is
  // revoked in Go too, so Go never keeps serving a row this reader dropped.
  const checkActive = createStatusCheck({ state, relay, now, content, onWiped: id => onWiped(id) })
  const tokens = createTokens(state, { now, checkActive, onFamilyRevoked: onWiped })
  const verifier = createVerifier({ tokens, state, resource: metadata.resource, checkActive })
  const clients = createClients(state, { now, hosts: config.hosts })
  const cimd = createCIMD(state, { relay, now, enabled: config.cimd, hosts: config.hosts })
  const as = createAuthorizationServer({ state, clients, cimd, tokens, limiter, relay, log, now, publicOrigin, consoleURL: config.consoleURL, resource: metadata.resource, pendingTTLMs: config.pendingTTLMs,
    newRecipient: options.keys === 'per-request' ? newRecipient : undefined, content })
  const attestor = options.attest ? createAttestor({ attest: options.attest, readerId: config.readerId, readerVersion: config.readerVersion, resource: metadata.resource, spki: config.spki, policy: config.policy }) : null
  const prepare = attestor && (async (pending, nonce) => {
    if (!pending.recipient) throw new AttestationError('attest_failed')
    return { ...descriptor(pending, state), attestation: await attestor.attestation({ requestId: pending.id, publicKey: pending.recipient.publicKey, nonce }) }
  })
  const internal = internalRoutes({ state, secret, now, pendingFor: as.pendingFor, auth: options.internalAuth, health: config.health, prepare, rotateSecret: options.secrets?.rotate, content })
  const router = createRouter({ state, metadata, as, internal, verifier, limiter, log, archive: config.archive, publicHost: new URL(publicOrigin).hostname,
    listenerHosts: injected ? config.listenerHosts : undefined, trustForwarded: !injected,
    attestation: attestor && (({ nonce }) => attestor.attestation({ requestId: '', publicKey: null, nonce })), content })

  const handlerFor = listener => async (req, res) => {
    const started = now(), meta = {}
    let response
    try {
      const request = await toWebRequest(req, publicOrigin, bodyLimitFor(req.url.split('?')[0]))
      if (!request) { meta.route = 'public'; meta.code = 'body_too_large'; response = Response.json({ code: 'body_too_large' }, { status: 413, headers: { Connection: 'close' } }) }
      else response = await router.handle(request, { remoteAddress: req.socket.remoteAddress, listener, target: req.url }, meta)
    } catch {
      meta.code = 'internal_error'
      response = Response.json({ code: 'internal_error' }, { status: 500, headers: { 'Cache-Control': 'no-store' } })
    }
    try { await sendWebResponse(res, response) } catch { /* the peer went away */ }
    log.request({ route: meta.route ?? 'unmatched', status: response.status, ms: now() - started, connection: meta.connection, client: meta.client, code: meta.code })
  }
  const servers = injected ? [[injected.public, 'public'], ...(injected.internal ? [[injected.internal, 'internal']] : [])] : [[server, undefined]]
  for (const [target, listener] of servers) {
    // In the enclave something answered 503 `starting` until now.
    if (injected) target.removeAllListeners('request')
    target.on('request', handlerFor(listener))
  }

  async function sweep() {
    as.sweepPending()
    let changed = tokens.sweep() | clients.sweep()
    for (const [id, connection] of state.connections) {
      if (Date.parse(connection.expires_at) <= now()) { state.wipeConnection(id); changed = 1; continue }
      // A consent whose code was never exchanged leaves a connection no token
      // will ever reach: a native app's loopback listener had closed by the
      // time the owner approved, or the browser never made the last hop. Go
      // counts it against the workspace's five live connections for its whole
      // lifetime, so it is revoked there first and forgotten here only once Go
      // agrees; a failed revoke is retried on the next sweep. The exchange is
      // what sets family_id, so its absence is the whole test.
      if (!connection.family_id && now() - connection.created_at > UNCLAIMED_CONNECTION_MS && await relay.revoke(id)) {
        state.wipeConnection(id); changed = 1
        log.event('unclaimed_connection_revoked')
      }
    }
    if (changed) await state.save()
  }
  const timer = setInterval(() => { sweep().catch(() => {}) }, 30_000)
  timer.unref()

  /**
   * Asks Go about every content connection, used or idle, so a revocation
   * reaches an idle key within a minute. Go being away wipes nothing: the
   * cached answers lapse and the verifier answers 503 until Go is back.
   */
  async function contentSweep() {
    let checked = 0, wiped = 0, unreachable = 0
    for (const [id, record] of [...state.connections]) {
      if (record.kind !== 'content') continue
      checked++
      const held = content.holds(id)
      try {
        const answer = await checkActive(id, { force: true })
        if (held && answer !== 'serve') wiped++
      } catch (error) { if (!(error instanceof RelayError)) throw error; unreachable++ }
    }
    content.sweep()
    log.event('content_sweep', { checked, wiped, unreachable })
    return { checked, wiped, unreachable }
  }
  const contentTimer = content ? setInterval(() => { contentSweep().catch(() => {}) }, CONTENT_SWEEP_MS) : null
  contentTimer?.unref()
  log.event('listening', { ...(address ? { port: address.port } : {}), cimd: config.cimd })
  return {
    port: address?.port, publicOrigin, resource: metadata.resource, state, config, sweep, log, checkActive,
    ...(content ? { contentSweep } : {}),
    async close() {
      clearInterval(timer)
      if (contentTimer) clearInterval(contentTimer)
      content?.close()
      await router.close()
      for (const [target] of servers) {
        await new Promise(resolve => { if (target.listening) target.close(() => resolve()); else resolve() })
        target.closeAllConnections?.()
      }
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
