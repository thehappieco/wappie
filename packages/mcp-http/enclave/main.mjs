#!/usr/bin/env node
// The attested MCP reader inside the Nitro Enclave (docs/mcp-enclave.md §10).
// It is the hosted reader (../server.mjs startReader) with every piece that
// the parent could otherwise influence replaced: configuration is image
// constants, TLS terminates here with a per-boot key, the OAuth state is
// sealed under a KMS key only this image can use and stored by Go as opaque
// bytes, the relay secret arrives as boot-key ciphertext, both directions with
// Go are HMAC-signed over WebPKI, every consent request gets its own key and a
// fresh attestation, and logs leave only through the schema-checked sink.
// Content connections (content.mjs, §15) keep their keys in this process's
// memory only; after any restart they wait in `reseal` for a renewal.
//
// Boot order (§10.2): boot.json; credentials and the RSA recipient key; the
// relay secret; the key policy hash (not fatal); the sealed state; the ACME
// account; the challenge listener, then the certificate; the HTTPS listeners;
// reconciliation with Go. A fatal boot error writes boot_failed and exits 78;
// entrypoint.sh restarts Node with backoff. Invalid image constants take the
// same path, with code constants_invalid, before anything else starts.
import { createServer as createHTTPServer } from 'node:http'
import { realpathSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { createAttestor, decodeAttestationDocument } from '../attestation.mjs'
import { createLog } from '../log.mjs'
import { startReader } from '../server.mjs'
import { openSealedState, sealedCollection, StateError } from '../state.mjs'
import { accountId, createAcmeClient, createChallenges, newAccountKey } from './acme.mjs'
import { attest as nsmAttest } from './attest.mjs'
import { parseBootJson, readLocal as readLocalPort } from './boot.mjs'
import { imageConstants, PORTS } from './constants.mjs'
import { createContent } from './content.mjs'
import { createHealthLine, clockSkew, prefix } from './health.mjs'
import { createHmacGuard } from './hmac.mjs'
import { codeOf, createKms, kmsClient, recipientKeys, roleCredentials } from './kms.mjs'
import { createSinkWriter } from './logsink.mjs'
import { createPolicyWatch } from './policy.mjs'
import { createProxiedTLSListener } from './proxy.mjs'
import { createSignedRelay, relayStore } from './relay.mjs'
import { createSealer } from './sealer.mjs'
import { createSecrets, secretFrom } from './secrets.mjs'
import { bootMaterial, createCertificates } from './tls.mjs'

export const EXIT_BOOT_FAILED = 78
export const EXIT_FATAL = 70
export const EXIT_STATE_CONFLICT = 75
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

export class BootFailure extends Error {
  constructor(code) { super(code); this.name = 'BootFailure'; this.code = code }
}

/** Runs `step`; any failure becomes BootFailure(code) with a code safe to log. */
async function step(code, fn) {
  try { return await fn() } catch (error) {
    if (error instanceof BootFailure) throw error
    const detail = error?.code && /^[a-z][a-z0-9_]{0,47}$/.test(error.code) ? error.code : codeOf(error)
    throw new BootFailure(detail === 'error' ? code : detail)
  }
}

/** The infra plaintext's ACME part, or StateError('state_auth_failed'). */
function acmeFrom(plain) {
  let parsed
  try { parsed = JSON.parse(plain.toString('utf8')) } catch { throw new StateError('state_auth_failed') } finally { plain.fill(0) }
  const acme = parsed?.acme
  if (!parsed || parsed.version !== 1 || parsed.name !== 'infra' || Object.keys(parsed).length !== 3 || !acme || typeof acme !== 'object' ||
    (acme.account_uri !== null && typeof acme.account_uri !== 'string') || acme.account_key?.kty !== 'EC' || acme.account_key?.crv !== 'P-256' || typeof acme.account_key?.d !== 'string') throw new StateError('state_auth_failed')
  return acme
}

/** Saves a collection and waits until Go holds it (the ACME key must never exist only in memory). */
async function persist(collection, wait) {
  for (let attempt = 0; ; attempt++) {
    await collection.save()
    if (!collection.dirty) return
    await wait(Math.min(60_000, 1000 * 2 ** Math.min(attempt, 6)))
  }
}

/**
 * Boots the reader. Production passes nothing. Tests inject: `constants`,
 * `sink` (a writer), `readLocal(port)`, `kms` (decrypt/dataKey/keyPolicy),
 * `attest` (NSM), `fetch`, `exit(code)`, `wait`, and `overrides` for the
 * archive URL, ACME directory, run directory, ports and clock URL.
 */
export async function startEnclave(options = {}) {
  // An image that still carries a build marker (or a bad ARN) is a boot
  // failure like any other: it must reach the sink and exit 78, so the
  // constants are checked only once the sink and the log exist.
  let c = null
  try { c = options.constants ?? imageConstants() } catch { /* reported below as constants_invalid */ }
  const overrides = options.overrides ?? {}
  const now = options.now ?? Date.now
  const wait = options.wait ?? sleep
  const exit = options.exit ?? (code => process.exit(code))
  const ports = { ...(c?.PORTS ?? PORTS), ...overrides.ports }
  const host = '127.0.0.1'
  const sink = options.sink ?? createSinkWriter({ port: ports.logSink })
  const logSink = line => sink.write(line)
  const log = createLog(logSink, now)
  if (!c) {
    log.event('boot_failed', { code: 'constants_invalid' })
    await sink.drain?.()
    exit(EXIT_BOOT_FAILED)
    throw new BootFailure('constants_invalid')
  }
  const readLocal = options.readLocal ?? (port => readLocalPort(port))
  const counters = { proxyRejected: 0 }
  const facts = { pcr0: null, state: null, secrets: null, certificates: null, policy: null, acmeUri: null, content: null, ready: false }

  // Every document the NSM signs carries PCR0; the first one tells the reader its own.
  const attest = async fields => {
    const document = await (options.attest ?? nsmAttest)(fields)
    if (!facts.pcr0) { try { facts.pcr0 = decodeAttestationDocument(document).pcrs[0] ?? null } catch { /* reported as unknown */ } }
    return document
  }

  const health = createHealthLine({
    log, now, started: now(),
    probe: () => clockSkew({ url: overrides.clockUrl, fetch: options.fetch, now }),
    fields: () => ({
      cert_days_left: facts.certificates?.daysLeft() ?? undefined,
      connections: facts.state?.connections.size, pending: facts.state?.pending.size, state_dirty: facts.state?.dirty(),
      relay_secrets: facts.secrets?.count(), acme_account_id: accountId(facts.acmeUri) ?? undefined,
      policy_ok: facts.policy ? facts.policy.current() !== null : undefined, policy: prefix(facts.policy?.current()),
      pcr0: prefix(facts.pcr0), spki: prefix(facts.certificates?.spkiSha256()),
      log_dropped: sink.dropped?.(), proxy_rejected: counters.proxyRejected,
      content_connections: facts.content?.counts().connections, content_keys: facts.content?.counts().keys,
    }),
  })
  health.start()

  try {
    // 1. boot.json
    const boot = await step('boot_json_unavailable', async () => {
      for (let attempt = 1; ; attempt++) {
        let bytes
        try { bytes = await readLocal(ports.boot) } catch (error) { if (attempt >= 5) throw error; await wait(2000); continue }
        return parseBootJson(bytes)
      }
    })

    // 2. Role credentials and the per-boot RSA recipient key.
    const kms = options.kms ?? createKms({
      client: kmsClient(roleCredentials(async () => (await readLocal(ports.credentials)).toString('utf8'))),
      keys: recipientKeys(), attest,
      log: (op, fields) => log.event(op, fields),
    })

    // PCR0 for the health object and line: KMS calls already carry a document,
    // but one document with no fields settles it even before the first of them.
    if (!facts.pcr0) await attest({}).catch(() => log.event('attest_failed'))

    // 3. The relay secret, under the boot key.
    const relayContext = { purpose: 'wappie-mcp-relay', reader_id: c.READER_ID }
    const openRelaySecret = ciphertext => kms.decrypt(c.KMS_BOOT_KEY_ARN, ciphertext, relayContext)
    const secrets = await step('relay_secret_failed', async () => createSecrets({ current: secretFrom(await openRelaySecret(boot.relayCiphertext)), open: openRelaySecret, log }))
    facts.secrets = secrets

    // 4. The reader key's policy hash; a failure here only means policy_unknown for now.
    const policy = createPolicyWatch({ read: () => kms.keyPolicy(c.KMS_READER_KEY_ARN), now, log })
    facts.policy = policy
    await policy.refresh()
    policy.start()

    // 5. Sealed state, all four names (each load retries while Go is away).
    const archive = overrides.archive ?? c.ARCHIVE
    const relay = createSignedRelay({ base: archive, readerId: c.READER_ID, secrets, fetch: options.fetch, now })
    const store = relayStore(relay)
    const sealer = createSealer({ kms, keyArn: c.KMS_READER_KEY_ARN, readerId: c.READER_ID, origin: c.PUBLIC_ORIGIN })
    // A second writer or a tampered store: stop, and let entrypoint.sh reload from what Go holds.
    const onConflict = () => { void Promise.resolve(sink.drain?.()).finally(() => exit(EXIT_STATE_CONFLICT)) }
    const infra = sealedCollection({ store, sealer, name: 'infra', log, onConflict, wait })
    const infraPlain = await step('state_load_failed', () => infra.load())
    let acmeState = infraPlain ? await step('state_auth_failed', () => acmeFrom(infraPlain)) : null
    const state = await step('state_load_failed', () => openSealedState({ store, sealer, log, onConflict, wait }))
    facts.state = state

    // 6. The ACME account: its key is sealed before the account exists, so a
    // crash in between re-registers the same key (ACME returns the same account).
    infra.bind(() => Buffer.from(JSON.stringify({ version: 1, name: 'infra', acme: acmeState })))
    if (!acmeState) { acmeState = { account_uri: null, account_key: newAccountKey() }; await persist(infra, wait) }
    const challenges = createChallenges()
    const acme = createAcmeClient({ directory: overrides.acmeDirectory ?? c.ACME_DIRECTORY, accountKey: acmeState.account_key, accountUri: acmeState.account_uri, challenges, fetch: options.fetch, wait })
    await step('acme_account_failed', async () => {
      for (let attempt = 0; ; attempt++) {
        try { await acme.ensureAccount(); break } catch (error) {
          log.event('acme_account_retry', { attempt: attempt + 1, code: error?.code })
          await wait(Math.min(30 * 60_000, 60_000 * 2 ** Math.min(attempt, 5)))
        }
      }
      if (acmeState.account_uri !== acme.accountUri) { acmeState = { ...acmeState, account_uri: acme.accountUri }; await persist(infra, wait) }
    })
    facts.acmeUri = acmeState.account_uri

    // 7. The challenge listener, then the per-boot key and the certificate.
    const challengeServer = challenges.server()
    await listen(challengeServer, ports.challenge, host)
    const runDir = overrides.runDir ?? c.RUN_DIR
    const material = await step('tls_key_failed', () => bootMaterial(runDir))
    const names = [c.PUBLIC_HOST, `${material.bootId}${c.BOOT_NAME_SUFFIX}`]
    const certificates = createCertificates({ dir: runDir, material, names, acme, log, now, wait })
    facts.certificates = certificates
    await certificates.ready()
    certificates.start()

    // 8. The HTTPS listeners, answering 503 `starting` until the reader takes over.
    const servers = { public: httpServer(), internal: httpServer() }
    const listeners = {}
    for (const [name, port] of [['internal', ports.internal], ['public', ports.public]]) {
      listeners[name] = createProxiedTLSListener({ httpServer: servers[name], secureContext: certificates.secureContext, onRejected: () => { counters.proxyRejected++ } })
      await listen(listeners[name], port, host)
    }

    // 9. The reader: reconciles with Go, then serves.
    const config = {
      publicOrigin: c.PUBLIC_ORIGIN, consoleURL: c.CONSOLE_URL, archive, hosts: [...c.REDIRECT_HOSTS], cimd: c.CIMD, pendingTTLMs: c.PENDING_TTL_MS,
      readerId: c.READER_ID, readerVersion: c.READER_VERSION,
      listenerHosts: { public: c.PUBLIC_LISTENER_HOST, internal: c.INTERNAL_LISTENER_HOST },
      spki: () => certificates.spkiSha256(), policy: () => policy.current(),
      health: () => ({
        ok: true, reader_id: c.READER_ID, reader_version: c.READER_VERSION, boot_id: material.bootId, state: facts.ready ? 'ready' : 'loading',
        pcr0: facts.pcr0, tls_spki_sha256: certificates.spkiSha256(), cert_not_after: certificates.notAfter() ? new Date(certificates.notAfter()).toISOString().replace(/\.\d{3}Z$/, 'Z') : null,
        policy_sha256: policy.current(), acme_account_uri: facts.acmeUri, relay_secrets: secrets.count(),
      }),
    }
    const resource = `${c.PUBLIC_ORIGIN}/mcp`
    const content = createContent({
      state, relay, log, now, archive, consoleURL: c.CONSOLE_URL, resource, fetch: options.fetch,
      attestor: createAttestor({ attest, readerId: c.READER_ID, readerVersion: c.READER_VERSION, resource, spki: config.spki, policy: config.policy }),
    })
    facts.content = content
    const reader = await startReader({
      config, now, logSink, secrets, state, relay, servers, keys: 'per-request', attest, content,
      internalAuth: createHmacGuard({ readerId: c.READER_ID, secrets, now }),
    })
    facts.ready = true
    log.event('enclave_ready', { ...(facts.pcr0 ? { pcr0: prefix(facts.pcr0) } : {}), ...(certificates.spkiSha256() ? { spki: prefix(certificates.spkiSha256()) } : {}) })
    return {
      reader, ports: Object.fromEntries(Object.entries(listeners).map(([name, server]) => [name, server.address().port]).concat([['challenge', challengeServer.address().port]])),
      material, names, secrets, state, certificates, policy, health, facts,
      async close() {
        health.stop(); policy.stop(); certificates.stop()
        await reader.close()
        for (const server of [...Object.values(listeners), challengeServer]) await new Promise(resolve => server.close(() => resolve()))
        await infra.close()
      },
    }
  } catch (error) {
    health.stop()
    const code = error instanceof BootFailure ? error.code : 'boot_failed'
    log.event('boot_failed', { code })
    await sink.drain?.()
    exit(EXIT_BOOT_FAILED)
    throw error
  }
}

/** A node:http server that never listens itself; TLS sockets are handed to it. */
function httpServer() {
  const server = createHTTPServer({ maxHeaderSize: 16 * 1024 })
  server.headersTimeout = 10_000
  server.requestTimeout = 60_000
  server.on('request', (req, res) => { res.writeHead(503, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end('{"code":"starting"}') })
  return server
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, () => { server.off('error', reject); resolve() }) })
}

const invokedDirectly = process.argv[1] && (() => { try { return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href } catch { return false } })()
if (invokedDirectly) {
  // Nothing but a fixed code may describe a crash: an exception message or a
  // stack can quote request data.
  const sink = createSinkWriter({ port: PORTS.logSink })
  const fatal = () => {
    try { sink.write(JSON.stringify({ ts: new Date().toISOString(), event: 'fatal', code: 'uncaught' })) } catch { /* nothing left to try */ }
    void sink.drain().finally(() => process.exit(EXIT_FATAL))
  }
  process.on('uncaughtException', fatal)
  process.on('unhandledRejection', fatal)
  try { await startEnclave({ sink }) } catch { /* startEnclave logged boot_failed and is exiting */ }
}
