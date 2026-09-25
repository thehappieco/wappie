#!/usr/bin/env node
// The KMS key policy hash: the one implementation (docs/mcp-enclave.md §7).
// The enclave reads its reader key's live policy with GetKeyPolicy at boot and
// every 10 minutes and puts the hash in every attestation, so a browser
// refuses a reader whose key answers to a policy nobody published. The release
// build hashes the rendered policy files with this same file:
//   node policy.mjs < policy.json              prints the lowercase hex SHA-256
//   node policy.mjs --canonical < policy.json  prints the canonical bytes
//
// Canonical form: RFC 8785 JSON Canonicalization Scheme over the parsed
// document. Object keys sorted by UTF-16 code units, arrays in their order,
// numbers and strings as ECMAScript serializes them. Nothing else is
// normalized: a one-element array and a bare string hash differently, which is
// why the owner applies the release's rendered file unchanged.
import { createHash } from 'node:crypto'
import { realpathSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

export const POLICY_REFRESH_MS = 10 * 60_000
export const POLICY_MAX_AGE_MS = 20 * 60_000

export class PolicyError extends Error {
  constructor(code) { super(code); this.name = 'PolicyError'; this.code = code }
}

function canonicalValue(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new PolicyError('policy_invalid')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalValue).join(',')}]`
  if (typeof value === 'object') {
    // Default sort compares UTF-16 code units, which is exactly what JCS asks.
    const keys = Object.keys(value).sort()
    return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalValue(value[key])}`).join(',')}}`
  }
  throw new PolicyError('policy_invalid')
}

/** The canonical UTF-8 bytes of a policy document given as JSON text. */
export function canonicalPolicy(text) {
  let parsed
  try { parsed = JSON.parse(text) } catch { throw new PolicyError('policy_invalid') }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new PolicyError('policy_invalid')
  return Buffer.from(canonicalValue(parsed), 'utf8')
}

/** policy_sha256: lowercase hex SHA-256 of the canonical bytes. */
export const policySha256 = text => createHash('sha256').update(canonicalPolicy(text)).digest('hex')

/**
 * Keeps the live policy hash fresh. `read()` resolves to the policy text
 * (GetKeyPolicy with the role credentials). `current()` is the hash, or null
 * when the last successful read is older than 20 minutes (or there was none):
 * an attestation must never carry a hash the key may no longer answer to.
 */
export function createPolicyWatch({ read, now = Date.now, log = { event() {} }, refreshMs = POLICY_REFRESH_MS, maxAgeMs = POLICY_MAX_AGE_MS }) {
  let hash = null, at = 0, timer = null
  async function refresh() {
    try {
      hash = policySha256(await read())
      at = now()
      return true
    } catch {
      log.event('policy_read_failed')
      return false
    }
  }
  return {
    refresh,
    current: () => (hash && now() - at <= maxAgeMs ? hash : null),
    start() { timer = setInterval(() => { void refresh() }, refreshMs); timer.unref?.() },
    stop() { if (timer) clearInterval(timer); timer = null },
  }
}

const invokedDirectly = process.argv[1] && (() => { try { return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href } catch { return false } })()
if (invokedDirectly) {
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  try {
    const text = Buffer.concat(chunks).toString('utf8')
    if (process.argv.includes('--canonical')) process.stdout.write(canonicalPolicy(text))
    else process.stdout.write(policySha256(text) + '\n')
  } catch (error) {
    process.stderr.write(`policy.mjs: ${error.code ?? 'failed'}\n`)
    process.exitCode = 1
  }
}
