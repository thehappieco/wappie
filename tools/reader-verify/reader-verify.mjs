#!/usr/bin/env node
// Checks from anywhere that https://mcp.wappie.thehappie.co is served by a
// released reader image inside a Nitro Enclave (plan 2a.25).
//
// It asks the reader's public GET /attestation for a document bound to a fresh
// random nonce, and verifies it with the same verifier the console runs
// (packages/client attestation) against the measurements.json of a public
// release: the AWS chain, PCR0/1/2, the version, the published KMS key policy
// hash and the nonce. It then compares the SPKI of the TLS certificate that
// answered with the tls_spki_sha256 the document commits to, which is what
// ties this very connection to the enclave: a certificate whose key lives
// outside the enclave fails here even when the document is genuine.
//
// Prints one JSON line and exits 0 when everything holds, 1 otherwise.
import { X509Certificate, createHash, randomBytes } from 'node:crypto'
import { appendFileSync, readFileSync, realpathSync } from 'node:fs'
import { request } from 'node:https'
import { pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'
import { AttestationError, verifyAttestation } from '@whatserver2/client/crypto/attestation'

export const DEFAULT_HOST = 'mcp.wappie.thehappie.co'
const SCHEMA = 'wappie-reader-measurements/v1'
const TIMEOUT_MS = 10_000
const MAX_MEASUREMENTS_BYTES = 256 * 1024
const MAX_RESPONSE_BYTES = 64 * 1024
const NONCE_BYTES = 32

const PCR_HEX = /^[0-9a-f]{96}$/
const SHA256_HEX = /^[0-9a-f]{64}$/
const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+$/
// A DNS name with an optional port; no scheme, path or userinfo.
const HOST = /^(?=.{1,253}(?::|$))[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+(?::[0-9]{1,5})?$/

/** A failure the CLI reports by code. Codes are snake_case, never a message or a stack. */
export class VerifyError extends Error {
  constructor(code) { super(code); this.name = 'VerifyError'; this.code = code }
}
const fail = code => { throw new VerifyError(code) }

// ---- measurements.json ----------------------------------------------------------

/**
 * Validates a release's measurements.json (docs/mcp-enclave.md section 9) and
 * returns what the verifier needs: one allowlist entry and the policy hashes.
 */
export function parseMeasurements(bytes) {
  let m
  try { m = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) } catch { fail('measurements_invalid') }
  if (!m || typeof m !== 'object' || m.schema !== SCHEMA || m.reader_id !== 'enclave') fail('measurements_invalid')
  if (typeof m.version !== 'string' || !VERSION.test(m.version)) fail('measurements_invalid')
  if (typeof m.resource !== 'string' || !m.resource.startsWith('https://')) fail('measurements_invalid')
  const pcrs = m.pcrs
  if (!pcrs || typeof pcrs !== 'object' || !['0', '1', '2'].every(i => typeof pcrs[i] === 'string' && PCR_HEX.test(pcrs[i]))) fail('measurements_invalid')
  if (!Array.isArray(m.policies) || m.policies.length === 0) fail('measurements_invalid')
  const policies = m.policies.map(p => {
    if (!p || typeof p.phase !== 'string' || typeof p.sha256 !== 'string' || !SHA256_HEX.test(p.sha256)) fail('measurements_invalid')
    return { phase: p.phase, sha256: p.sha256 }
  })
  return { version: m.version, resource: m.resource, entry: { version: m.version, pcrs: { 0: pcrs['0'], 1: pcrs['1'], 2: pcrs['2'] } }, policies }
}

// A URL is fetched over verified HTTPS (GitHub release assets redirect to their
// CDN, so redirects are followed); anything else is a local file.
async function loadMeasurementsBytes(source, fetchBytes) {
  if (/^https:\/\//.test(source)) return fetchBytes(source)
  if (/^[a-z]+:\/\//i.test(source)) fail('measurements_url')
  try { return readFileSync(source) } catch { return fail('measurements_unreadable') }
}

async function fetchMeasurements(url) {
  let response
  try { response = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(TIMEOUT_MS) }) } catch { return fail('measurements_fetch') }
  if (!response.ok) fail('measurements_fetch')
  const body = Buffer.from(await response.arrayBuffer())
  if (body.length > MAX_MEASUREMENTS_BYTES) fail('measurements_invalid')
  return body
}

/**
 * Loads every --measurements source. --sha256 values, when given, pin the files
 * in order, so the check can follow the console's reader-releases.json exactly.
 */
export async function loadReleases(sources, pins, fetchBytes = fetchMeasurements) {
  if (pins.length && pins.length !== sources.length) fail('usage')
  const releases = []
  for (const [i, source] of sources.entries()) {
    // The pin is over the bytes as published, before any decoding.
    const bytes = await loadMeasurementsBytes(source, fetchBytes)
    if (pins.length && createHash('sha256').update(bytes).digest('hex') !== pins[i].toLowerCase()) fail('measurements_sha256')
    releases.push(parseMeasurements(bytes))
  }
  // One resource for the whole check: the verifier binds the document to it.
  if (new Set(releases.map(r => r.resource)).size !== 1) fail('measurements_invalid')
  return releases
}

// ---- GET /attestation -------------------------------------------------------------

/**
 * GET https://<host>/attestation?nonce=… with WebPKI verification. Returns the
 * status, the body and the SHA-256 of the SPKI of the certificate that served it.
 */
export function requestAttestation(host, nonce) {
  return new Promise((resolve, reject) => {
    const url = new URL(`https://${host}/attestation`)
    url.searchParams.set('nonce', nonce)
    const req = request(url, { method: 'GET', headers: { accept: 'application/json' }, timeout: TIMEOUT_MS, agent: false }, res => {
      let spkiSha256 = null
      try {
        const raw = res.socket.getPeerCertificate()?.raw
        if (raw) spkiSha256 = createHash('sha256').update(new X509Certificate(raw).publicKey.export({ type: 'spki', format: 'der' })).digest('hex')
      } catch { spkiSha256 = null }
      const chunks = []
      let size = 0
      res.on('data', chunk => {
        size += chunk.length
        if (size > MAX_RESPONSE_BYTES) { req.destroy(); reject(new VerifyError('response_too_large')) } else chunks.push(chunk)
      })
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8'), spkiSha256 }))
      res.on('error', () => reject(new VerifyError('fetch_failed')))
    })
    req.on('timeout', () => req.destroy(new VerifyError('fetch_timeout')))
    req.on('error', error => reject(error instanceof VerifyError ? error : new VerifyError('fetch_failed')))
    req.end()
  })
}

function readAttestation(response) {
  if (response.status !== 200) fail(`http_${response.status}`)
  let body
  try { body = JSON.parse(response.body) } catch { fail('response_invalid') }
  const a = body?.attestation
  if (!a || typeof a !== 'object' || a.format !== 'aws-nitro-v1' || typeof a.document !== 'string') fail('response_invalid')
  if (!/^[A-Za-z0-9_-]+$/.test(a.document)) fail('response_invalid')
  return { attestation: a, document: new Uint8Array(Buffer.from(a.document, 'base64url')) }
}

// ---- the check ------------------------------------------------------------------

/**
 * Runs the whole check and returns the one-line result object. `deps` exists for
 * tests: fetchBytes, requestAttestation, now and rootDer.
 */
export async function check({ host = DEFAULT_HOST, measurements, sha256 = [], record }, deps = {}) {
  host = typeof host === 'string' ? host.toLowerCase() : host
  if (typeof host !== 'string' || !HOST.test(host)) fail('usage')
  if (!Array.isArray(measurements) || measurements.length === 0) fail('usage')
  const releases = await loadReleases(measurements, sha256, deps.fetchBytes)
  const nonce = randomBytes(NONCE_BYTES)
  const response = await (deps.requestAttestation ?? requestAttestation)(host, nonce.toString('base64url'))
  const { attestation, document } = readAttestation(response)
  const policies = [...new Set(releases.flatMap(r => r.policies.map(p => p.sha256)))]
  const result = await verifyAttestation(document, attestation, {
    nonce,
    allow: releases.map(r => r.entry),
    policies,
    requestId: '',
    resource: releases[0].resource,
    requirePublicKey: false,
    ...(deps.now !== undefined && { now: deps.now }),
    ...(deps.rootDer !== undefined && { rootDer: deps.rootDer }),
  })
  // The document is genuine; now it has to be about the key this connection used.
  if (!response.spkiSha256) fail('tls_spki_unknown')
  if (response.spkiSha256 !== result.fields.tls_spki_sha256) fail('tls_spki_mismatch')
  const release = releases.find(r => r.version === result.entry.version)
  if (record) recordSpki(record, result.fields.tls_spki_sha256)
  return {
    ok: true,
    host,
    reader_version: result.entry.version,
    pcr0: result.pcrs[0],
    policy_sha256: result.fields.policy_sha256,
    policy_phase: release.policies.find(p => p.sha256 === result.fields.policy_sha256)?.phase ?? null,
    tls_spki_sha256: result.fields.tls_spki_sha256,
    module_id: result.moduleId,
    timestamp: result.timestamp,
    document_sha256: result.documentSha256,
  }
}

// Appends the attested SPKI to the list tools/ct-watch reads, once per key.
function recordSpki(path, spki) {
  let known = ''
  try { known = readFileSync(path, 'utf8') } catch {}
  if (!known.split(/\s+/).includes(spki)) appendFileSync(path, `${spki}\n`)
}

// ---- CLI --------------------------------------------------------------------------

const USAGE = `usage: reader-verify --measurements <url|file> [--measurements …] [--sha256 <hex> …] [--host ${DEFAULT_HOST}] [--record <file>]`

export async function main(argv, deps = {}, out = line => console.log(line)) {
  try {
    const { values } = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        host: { type: 'string' },
        measurements: { type: 'string', multiple: true },
        sha256: { type: 'string', multiple: true },
        record: { type: 'string' },
        help: { type: 'boolean' },
      },
    })
    if (values.help) { out(USAGE); return 0 }
    const result = await check({ host: values.host, measurements: values.measurements, sha256: values.sha256 ?? [], record: values.record }, deps)
    out(JSON.stringify(result))
    return 0
  } catch (error) {
    out(JSON.stringify({ ok: false, code: codeOf(error) }))
    return 1
  }
}

function codeOf(error) {
  if (error instanceof AttestationError || error instanceof VerifyError) return error.code
  if (String(error?.code ?? '').startsWith('ERR_PARSE_ARGS')) return 'usage'
  return 'internal'
}

// Run as a script, not on import. realpath because /tmp is a symlink on macOS.
function invokedDirectly() {
  try { return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href } catch { return false }
}
if (invokedDirectly()) process.exitCode = await main(process.argv.slice(2))
