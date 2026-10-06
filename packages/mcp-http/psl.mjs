// The Public Suffix List, as the snapshot in psl/ holds it (docs/mcp-enclave.md
// §19.5): a CIMD host's registrable domain (its public suffix plus one label),
// and whether that suffix comes from the List's private section (`github.io`),
// which the consent card names as shared hosting. The enclave image carries
// the snapshot, so it is measured; Go embeds a byte-identical copy for its own
// checks, and both test suites pin its SHA-256, so the reader, the egress
// proxy and Go's create() never disagree about a host. No other source is
// read: the snapshot is refreshed with each release (psl/generate.mjs).
import { readFileSync } from 'node:fs'

export const PSL_FILE = new URL('./psl/psl-2026-09-24.json', import.meta.url)

/** The snapshot in psl/, parsed; read once per process by whoever asks for it. */
export function loadPSL(file = PSL_FILE) {
  return createPSL(JSON.parse(readFileSync(file, 'utf8')))
}

/**
 * The List's algorithm over a snapshot object (`{format: 'wappie-psl/v1',
 * list_date, list_revision, icann, private}`, each section a list of rules:
 * `a.b`, `*.b`, `!a.b`). Hosts are lower-case ASCII labels joined by dots,
 * which is all §19.5 step 4 lets through to here.
 */
export function createPSL(snapshot) {
  if (!snapshot || snapshot.format !== 'wappie-psl/v1' || !Array.isArray(snapshot.icann) || !Array.isArray(snapshot.private)) throw new Error('psl_invalid')
  const rules = new Map(), wildcards = new Map(), exceptions = new Map()
  for (const section of ['icann', 'private']) {
    for (const rule of snapshot[section]) {
      if (typeof rule !== 'string') throw new Error('psl_invalid')
      if (rule.startsWith('!')) exceptions.set(rule.slice(1), section)
      else if (rule.startsWith('*.')) wildcards.set(rule.slice(2), section)
      else rules.set(rule, section)
    }
  }
  /**
   * `{suffix, section}`: the public suffix of `host` and the section of the
   * rule that gave it (`icann`, `private`, or null for the default rule `*`,
   * which makes an unlisted top-level label the suffix).
   */
  function suffixOf(host) {
    const labels = host.split('.')
    // An exception rule prevails over every other: the suffix is the rule without its first label.
    for (let i = 0; i < labels.length; i++) {
      const candidate = labels.slice(i).join('.')
      if (exceptions.has(candidate)) return { suffix: labels.slice(i + 1).join('.'), section: exceptions.get(candidate) }
    }
    // Otherwise the rule with the most labels, longest candidate first.
    for (let i = 0; i < labels.length; i++) {
      const candidate = labels.slice(i).join('.')
      if (rules.has(candidate)) return { suffix: candidate, section: rules.get(candidate) }
      const parent = labels.slice(i + 1).join('.')
      if (i < labels.length - 1 && wildcards.has(parent)) return { suffix: candidate, section: wildcards.get(parent) }
    }
    return { suffix: labels.at(-1), section: null }
  }
  return {
    version: snapshot.list_date,
    suffixOf,
    /**
     * `{registrable, shared_suffix}` for `host`, or null when the host is
     * itself a public suffix (it has no registrable domain to show).
     * `shared_suffix` is the suffix when its rule is in the private section.
     */
    registrable(host) {
      const { suffix, section } = suffixOf(host)
      if (suffix === host) return null
      const labels = host.split('.'), size = suffix.split('.').length + 1
      return { registrable: labels.slice(-size).join('.'), shared_suffix: section === 'private' ? suffix : null }
    },
  }
}
