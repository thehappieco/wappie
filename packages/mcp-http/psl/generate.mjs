#!/usr/bin/env node
// Turns a copy of the Public Suffix List (https://publicsuffix.org/list/
// public_suffix_list.dat) into the snapshot the reader and Go read
// (docs/mcp-enclave.md §19.5): a JSON object with the list's date and git
// revision and its rules by section, each in its lower-case ASCII (xn--) form,
// since a CIMD host is checked in that form only, deduplicated and sorted, one
// rule per line, so a refresh reads as a diff of rules.
//
//   node packages/mcp-http/psl/generate.mjs <date> <revision> < public_suffix_list.dat > packages/mcp-http/psl/psl-<date>.json
//
// Go's generator (internal/netguard/pslgen) writes the same bytes from the
// same list; the snapshot is committed twice, here and at
// internal/netguard/psl/ (go:embed cannot reach outside its package), and both
// test suites pin its SHA-256. It is refreshed with each release.
import { readFileSync } from 'node:fs'
import { domainToASCII } from 'node:url'

export const FORMAT = 'wappie-psl/v1'
const rulePattern = /^(?:\*\.|!)?[a-z0-9-]+(?:\.[a-z0-9-]+)*$/

/** A rule in its lower-case ASCII form, its `*.` or `!` prefix kept; throws when it is not a domain. */
function ascii(rule) {
  const prefix = rule.startsWith('*.') ? '*.' : rule.startsWith('!') ? '!' : ''
  const name = rule.slice(prefix.length)
  // Only a name with non-ASCII characters goes through IDNA: domainToASCII
  // would read an ASCII label such as a lone `0` as an IPv4 address.
  const converted = /^[\x00-\x7f]*$/.test(name) ? name.toLowerCase() : domainToASCII(name)
  const out = prefix + converted
  if (!converted || !rulePattern.test(out)) throw new Error(`${JSON.stringify(rule)} is not a rule`)
  return out
}

/** The snapshot's bytes for the List's text, dated `date` (YYYY-MM-DD) at git revision `revision`. */
export function snapshotOf(text, { date, revision }) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date ?? '') || !/^[0-9a-f]{40}$/.test(revision ?? '')) throw new Error('a date YYYY-MM-DD and a 40-hex revision are required')
  const sections = { icann: [], private: [] }
  const seen = new Set()
  let section = null
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line.includes('===BEGIN ICANN DOMAINS===')) { section = 'icann'; continue }
    if (line.includes('===BEGIN PRIVATE DOMAINS===')) { section = 'private'; continue }
    if (line.includes('===END ICANN DOMAINS===') || line.includes('===END PRIVATE DOMAINS===')) { section = null; continue }
    if (!line || line.startsWith('//')) continue
    // A rule ends at the first white space; the rest of the line is not part of it.
    const rule = ascii(line.split(/\s/)[0])
    if (!section) throw new Error(`${JSON.stringify(line)} is outside both sections`)
    if (seen.has(rule)) continue
    seen.add(rule)
    sections[section].push(rule)
  }
  if (!sections.icann.length || !sections.private.length) throw new Error('a section is empty; this is not the List')
  // By byte, as Go's sort compares strings: every rule is ASCII, so code units are bytes.
  const byByte = (a, b) => (a < b ? -1 : a > b ? 1 : 0)
  const list = (name, rules, last) => `${JSON.stringify(name)}: [\n${rules.sort(byByte).map(rule => JSON.stringify(rule)).join(',\n')}\n]${last ? '' : ','}\n`
  return `{\n"format": ${JSON.stringify(FORMAT)},\n"list_date": ${JSON.stringify(date)},\n"list_revision": ${JSON.stringify(revision)},\n` +
    list('icann', sections.icann, false) + list('private', sections.private, true) + '}\n'
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.stdout.write(snapshotOf(readFileSync(0, 'utf8'), { date: process.argv[2], revision: process.argv[3] }))
}
