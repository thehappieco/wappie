// The enclave's serving certificate. The TLS key (ECDSA P-256) is made once
// per enclave boot in /run/wappie (tmpfs, 0700): it survives a Node restart
// and never an enclave boot, and it is never sealed anywhere. So even a KMS
// policy change that opened every sealed blob could not yield it: a
// man-in-the-middle would need a new certificate, which Certificate
// Transparency records and CAA restricts to this enclave's ACME account.
//
// The certificate names {mcp.…, <boot_id>.boot.mcp.…}: a distinct set per boot
// keeps restarts clear of Let's Encrypt's limit of 5 certificates per exact
// set per week. It is renewed with the same key when fewer than 30 days
// remain; failed orders back off from 1 to 30 minutes to stay under the
// failed-validation limit.
import { X509Certificate, createPrivateKey, generateKeyPairSync, randomBytes } from 'node:crypto'
import { mkdir, readFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { createSecureContext } from 'node:tls'
import { writePrivate } from '../state.mjs'
import { certificationRequest, spkiOf, spkiSha256 } from './x509.mjs'

export const RENEW_BEFORE_MS = 30 * 86_400_000
export const RETRY_START_MS = 60_000
export const RETRY_MAX_MS = 30 * 60_000
export const CHECK_EVERY_MS = 3_600_000
const bootIdShape = /^[0-9a-f]{16}$/

async function privateDirectory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 })
  const info = await stat(path)
  if (!info.isDirectory() || (info.mode & 0o077) !== 0) throw new Error('run_dir_unsafe')
}
async function readOptional(path) { try { return await readFile(path, 'utf8') } catch (error) { if (error.code === 'ENOENT') return null; throw error } }

/**
 * `{bootId, privateKey, spki}` for this enclave boot, created on first use.
 * `boot_id` is 8 random bytes as 16 hex characters; the key is PKCS#8 PEM.
 */
export async function bootMaterial(dir) {
  await privateDirectory(dir)
  let bootId = (await readOptional(join(dir, 'boot_id')))?.trim()
  if (!bootId || !bootIdShape.test(bootId)) {
    bootId = randomBytes(8).toString('hex')
    await writePrivate(join(dir, 'boot_id'), bootId + '\n')
  }
  let keyPem = await readOptional(join(dir, 'tls-key.pem'))
  if (!keyPem) {
    keyPem = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' })
    await writePrivate(join(dir, 'tls-key.pem'), keyPem)
  }
  const privateKey = createPrivateKey(keyPem)
  return { bootId, privateKey, keyPem, spki: spkiOf(privateKey) }
}

/**
 * The PEM chain's leaf if it is usable with `spki` for every name, else null:
 * same public key, every name covered, not yet expired.
 */
export function usableLeaf(chainPem, spki, names, now = Date.now()) {
  let leaf
  try { leaf = new X509Certificate(chainPem) } catch { return null }
  if (!leaf.publicKey.export({ type: 'spki', format: 'der' }).equals(spki)) return null
  if (!names.every(name => leaf.checkHost(name, { wildcards: false, subject: 'never' }) === name)) return null
  const notAfter = Date.parse(leaf.validTo)
  if (!(notAfter > now)) return null
  return { notAfter }
}

/**
 * Holds the serving certificate. `acme.issue(names, csr)` returns a PEM
 * chain. `secureContext()` is what the listeners use for each new
 * connection; `spkiSha256()` is null until a certificate exists, which makes
 * every attestation answer tls_not_ready rather than name a key no client sees.
 */
export function createCertificates({ dir, material, names, acme, log = { event() {} }, now = Date.now, wait = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  let context = null, notAfter = null, timer = null, failures = 0, ordering = null
  const chainFile = join(dir, 'tls-chain.pem')
  function install(chainPem, leaf) {
    context = createSecureContext({ key: material.keyPem, cert: chainPem, minVersion: 'TLSv1.2' })
    notAfter = leaf.notAfter
  }
  async function order() {
    const chain = await acme.issue(names, certificationRequest(names, material.privateKey))
    const leaf = usableLeaf(chain, material.spki, names, now())
    if (!leaf) throw new Error('certificate_mismatch')
    await writePrivate(chainFile, chain)
    install(chain, leaf)
    log.event('certificate_issued', { days_left: Math.floor((notAfter - now()) / 86_400_000) })
  }
  /** Orders until one succeeds, backing off from 1 to 30 minutes. */
  async function orderWithRetry() {
    ordering ??= (async () => {
      for (;;) {
        try { await order(); failures = 0; return } catch (error) {
          failures++
          log.event('certificate_order_failed', { failures, code: error?.code ?? error?.message })
          await wait(Math.min(RETRY_MAX_MS, RETRY_START_MS * 2 ** Math.min(failures - 1, 10)))
        }
      }
    })().finally(() => { ordering = null })
    return ordering
  }
  const due = () => !notAfter || notAfter - now() < RENEW_BEFORE_MS
  return {
    secureContext: () => context,
    spkiSha256: () => (context ? spkiSha256(material.spki) : null),
    notAfter: () => notAfter,
    daysLeft: () => (notAfter ? Math.floor((notAfter - now()) / 86_400_000) : null),
    /** Uses the certificate a previous Node process of this boot left, or orders one. Resolves once one is installed. */
    async ready() {
      const saved = await readOptional(chainFile)
      const leaf = saved && usableLeaf(saved, material.spki, names, now())
      if (leaf) install(saved, leaf)
      // Without a certificate nothing can be served, so boot waits; with one
      // that is merely due, renewal runs in the background.
      if (!context) await orderWithRetry()
      else if (due()) void orderWithRetry()
    },
    /** Hourly renewal check; a renewal keeps serving the current certificate until the new one is in. */
    start() {
      timer = setInterval(() => { if (due() && !ordering) void orderWithRetry() }, CHECK_EVERY_MS)
      timer.unref?.()
    },
    stop() { if (timer) clearInterval(timer); timer = null },
  }
}
