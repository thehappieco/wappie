#!/usr/bin/env node
// Certificate Transparency watch for the attested reader (plan 2a.25).
//
// Why: the enclave's TLS key never leaves it, so the only way to put a
// "mcp.wappie.thehappie.co" certificate on a key outside the enclave is to get
// a new one issued, and every publicly trusted certificate lands in CT logs.
// This script asks crt.sh for every certificate that could serve that name
// (mcp.wappie.thehappie.co, *.mcp.wappie.thehappie.co including the per-boot
// names, and a *.wappie.thehappie.co wildcard) and flags any whose public key
// (SPKI) is not one an enclave attested. The attested list comes from
// reader-verify --record, which only records keys it verified end to end.
//
// Prints one JSON line. Exit 0: nothing flagged. 1: at least one certificate
// with an unattested key. 2: the check could not be completed (crt.sh down, a
// certificate that could not be fetched); a monitor should alarm on 2 as well,
// since an incomplete check is not a clean one.
import { X509Certificate, createHash } from 'node:crypto'
import { readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'

const CRT_SH = 'https://crt.sh/'
// The crt.sh identity queries; % is its wildcard. The third covers the other two,
// but crt.sh answers the narrow ones even when the broad one times out.
export const QUERIES = ['mcp.wappie.thehappie.co', '%.mcp.wappie.thehappie.co', '%.wappie.thehappie.co']
const TIMEOUT_MS = 30_000
const MAX_LISTING_BYTES = 8 * 1024 * 1024
const MAX_CERT_BYTES = 64 * 1024
const MAX_DOWNLOADS = 200
const SHA256_HEX = /^[0-9a-f]{64}$/

export class WatchError extends Error {
  constructor(code) { super(code); this.name = 'WatchError'; this.code = code }
}
const fail = code => { throw new WatchError(code) }

/**
 * Whether a certificate name can serve the reader: the name itself, anything
 * under it (the boot names and *.mcp.), or the one wildcard one level up that
 * covers it. *.thehappie.co does not: a wildcard matches a single label.
 */
export function coversReader(name) {
  const n = String(name).trim().toLowerCase().replace(/\.$/, '')
  return n === 'mcp.wappie.thehappie.co' || n.endsWith('.mcp.wappie.thehappie.co') || n === '*.wappie.thehappie.co'
}

// ---- crt.sh ---------------------------------------------------------------------

async function httpGet(url, max, fetchImpl) {
  let response
  try { response = await fetchImpl(url, { signal: AbortSignal.timeout(TIMEOUT_MS), headers: { accept: 'application/json, application/x-pem-file' } }) } catch { return fail('crtsh_unavailable') }
  if (!response.ok) fail('crtsh_unavailable')
  const body = Buffer.from(await response.arrayBuffer())
  if (body.length > max) fail('crtsh_too_large')
  return body
}

/** The crt.sh entries for one identity query, as returned by ?output=json. */
export async function listCertificates(query, fetchImpl = fetch) {
  const url = new URL(CRT_SH)
  url.searchParams.set('q', query)
  url.searchParams.set('output', 'json')
  let rows
  try { rows = JSON.parse((await httpGet(url, MAX_LISTING_BYTES, fetchImpl)).toString('utf8')) } catch (error) { throw error instanceof WatchError ? error : new WatchError('crtsh_invalid') }
  if (!Array.isArray(rows)) fail('crtsh_invalid')
  return rows
}

// A precertificate and its final certificate are two crt.sh entries with the
// same serial and issuer, and the same key: one download is enough.
function relevantEntries(rows, since) {
  const byCert = new Map()
  for (const row of rows) {
    if (!row || !Number.isSafeInteger(row.id) || typeof row.name_value !== 'string') continue
    const names = [...new Set([row.common_name, ...row.name_value.split('\n')].filter(Boolean).map(n => n.trim().toLowerCase()))]
    if (!names.some(coversReader)) continue
    if (since !== undefined && Date.parse(`${row.not_before}Z`) < since) continue
    const key = `${row.issuer_ca_id}/${String(row.serial_number ?? row.id).toLowerCase()}`
    const seen = byCert.get(key)
    if (!seen || row.id < seen.id) byCert.set(key, { id: row.id, serial: row.serial_number ?? null, issuer: row.issuer_name ?? null, not_before: row.not_before ?? null, not_after: row.not_after ?? null, names: names.filter(coversReader) })
  }
  return [...byCert.values()].sort((a, b) => a.id - b.id)
}

/**
 * SHA-256 of the DER SubjectPublicKeyInfo, the same value the enclave attests.
 * Takes PEM or DER bytes: crt.sh's ?d= download is PEM, but nothing depends on it.
 */
export function spkiSha256(certificate) {
  let cert
  try { cert = new X509Certificate(certificate) } catch { return fail('certificate_invalid') }
  return { spki: createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('hex'), serial: cert.serialNumber }
}

const sameSerial = (a, b) => String(a).toLowerCase().replace(/^0+/, '') === String(b).toLowerCase().replace(/^0+/, '')

async function certificateSpki(entry, fetchImpl) {
  const url = new URL(CRT_SH)
  url.searchParams.set('d', String(entry.id))
  const { spki, serial } = spkiSha256(await httpGet(url, MAX_CERT_BYTES, fetchImpl))
  // The listing and the download are separate requests; they must be one certificate.
  if (entry.serial && !sameSerial(serial, entry.serial)) fail('certificate_mismatch')
  return spki
}

// ---- the watch ------------------------------------------------------------------

/** Reads attested SPKI hashes: a JSON array of strings, or one per line (# comments allowed). */
export function readAttested(text) {
  const trimmed = text.trim()
  let list
  if (trimmed.startsWith('[')) {
    try { list = JSON.parse(trimmed) } catch { fail('attested_invalid') }
  } else {
    list = trimmed.split('\n').map(line => line.replace(/#.*/, '').trim()).filter(Boolean)
  }
  if (!Array.isArray(list) || !list.every(s => typeof s === 'string' && SHA256_HEX.test(s.toLowerCase()))) fail('attested_invalid')
  return new Set(list.map(s => s.toLowerCase()))
}

/**
 * Runs the watch. `cache` maps crt.sh ids to SPKI hashes already fetched, so an
 * hourly run downloads only new certificates; it is updated in place.
 */
export async function watch({ attested, since, cache = {} }, fetchImpl = fetch) {
  const rows = []
  for (const query of QUERIES) rows.push(...await listCertificates(query, fetchImpl))
  const entries = relevantEntries(rows, since)
  const flagged = []
  const unchecked = []
  let downloads = 0
  for (const entry of entries) {
    let spki = cache[entry.id]
    if (!spki) {
      if (downloads >= MAX_DOWNLOADS) { unchecked.push({ id: entry.id, code: 'download_limit' }); continue }
      downloads++
      try {
        spki = await certificateSpki(entry, fetchImpl)
        cache[entry.id] = spki
      } catch (error) {
        unchecked.push({ id: entry.id, code: error instanceof WatchError ? error.code : 'internal' })
        continue
      }
    }
    if (!attested.has(spki)) flagged.push({ ...entry, spki_sha256: spki, url: `${CRT_SH}?id=${entry.id}` })
  }
  return { ok: flagged.length === 0 && unchecked.length === 0, checked: entries.length - unchecked.length, flagged, unchecked }
}

// ---- CLI ------------------------------------------------------------------------

const USAGE = 'usage: ct-watch --attested <file> [--spki <hex> …] [--since <ISO date>] [--cache <file>]'

export async function main(argv, fetchImpl = fetch, out = line => console.log(line)) {
  try {
    const { values } = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        attested: { type: 'string' },
        spki: { type: 'string', multiple: true },
        since: { type: 'string' },
        cache: { type: 'string' },
        help: { type: 'boolean' },
      },
    })
    if (values.help) { out(USAGE); return 0 }
    if (!values.attested && !values.spki) fail('usage')
    const attested = new Set()
    if (values.attested) {
      let text
      try { text = readFileSync(values.attested, 'utf8') } catch { fail('attested_unreadable') }
      for (const s of readAttested(text)) attested.add(s)
    }
    for (const s of readAttested((values.spki ?? []).join('\n'))) attested.add(s)
    let since
    if (values.since !== undefined) {
      since = Date.parse(values.since)
      if (!Number.isFinite(since)) fail('usage')
    }
    const cache = readCache(values.cache)
    const result = await watch({ attested, since, cache }, fetchImpl)
    if (values.cache) writeFileSync(values.cache, JSON.stringify(cache) + '\n')
    out(JSON.stringify(result))
    return result.flagged.length ? 1 : result.unchecked.length ? 2 : 0
  } catch (error) {
    const code = error instanceof WatchError ? error.code : String(error?.code ?? '').startsWith('ERR_PARSE_ARGS') ? 'usage' : 'internal'
    out(JSON.stringify({ ok: false, code }))
    return 2
  }
}

// A missing cache is an empty one; a malformed one is ignored rather than trusted.
function readCache(path) {
  if (!path) return {}
  try {
    const cache = JSON.parse(readFileSync(path, 'utf8'))
    const valid = cache && typeof cache === 'object' && !Array.isArray(cache) && Object.values(cache).every(v => typeof v === 'string' && SHA256_HEX.test(v))
    return valid ? cache : {}
  } catch {
    return {}
  }
}

function invokedDirectly() {
  try { return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href } catch { return false }
}
if (invokedDirectly()) process.exitCode = await main(process.argv.slice(2))
