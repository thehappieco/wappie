/** Text matching is lexical and accent-insensitive; it is not semantic search. */
export function normalizeText(value) {
  return value.normalize('NFD').replace(/\p{M}/gu, '').toLocaleLowerCase('en').replace(/\s+/g, ' ').trim()
}
export function matchesText(value, query) {
  const text = normalizeText(value)
  return normalizeText(query).split(' ').filter(Boolean).every(term => text.includes(term))
}
export function phoneFromIdentity(value) {
  const match = typeof value === 'string' && /^([1-9]\d{6,14})@s\.whatsapp\.net$/.exec(value)
  return match ? `+${match[1]}` : null
}
/**
 * Whether a resolve_contact query is a phone number (docs/mcp-enclave.md
 * §19.32): 7 to 15 digits, as E.164 has, written with nothing but digits,
 * one leading +, spaces, dots, dashes and parentheses. Fewer digits are part
 * of a number at most, not a number the user gave.
 */
export function isPhoneQuery(query) {
  if (typeof query !== 'string' || !/^\+?[\d\s().-]+$/.test(query.trim())) return false
  const digits = query.replace(/\D/g, '').length
  return digits >= 7 && digits <= 15
}
/**
 * The candidates a query matches. Matching reads every name, phone and
 * identifier; a candidate carries `phones` only with `{phones: true}`
 * (§19.32: a phone query, or the user asked for the number).
 */
export function contactCandidates(archived, personal, query, limit, { phones: withPhones = false } = {}) {
  const candidates = []
  const represented = new Set()
  const byPhone = new Map()
  for (const contact of personal) for (const phone of contact.phones) {
    const existing = byPhone.get(phone) || []
    existing.push(contact); byPhone.set(phone, existing)
  }
  for (const contact of archived) {
    const identifiers = [...new Set([contact.contact_key, contact.contact_pn, contact.contact_lid].filter(Boolean))]
    const phones = contact.is_group ? [] : [...new Set(identifiers.map(phoneFromIdentity).filter(Boolean))]
    const local = [...new Set(phones.flatMap(phone => byPhone.get(phone) || []))]
    const names = [...contact.names, ...local.map(item => ({ name: item.name, source: 'personal_snapshot' }))]
    if (!matchesText([...names.map(item => item.name), ...phones, ...identifiers].join(' '), query)) continue
    for (const item of local) represented.add(item)
    candidates.push({ identifiers, ...(withPhones ? { phones } : {}), names,
      name_conflict: new Set(local.map(item => item.name)).size > 1, is_group: contact.is_group === true,
      identity_basis: 'Explicit archive aliases and exact phone matches only.' })
  }
  for (const contact of personal) {
    if (represented.has(contact) || !matchesText([contact.name, ...contact.phones].join(' '), query)) continue
    candidates.push({ identifiers: contact.phones.map(phone => `${phone.slice(1)}@s.whatsapp.net`), ...(withPhones ? { phones: contact.phones } : {}),
      names: [{ name: contact.name, source: 'personal_snapshot' }], is_group: false,
      name_conflict: contact.phones.some(phone => new Set((byPhone.get(phone) || []).map(item => item.name)).size > 1),
      identity_basis: 'Phone numbers from the authorized personal snapshot; no LID association is known.' })
  }
  const ambiguous = candidates.length > 1 || candidates.some(item => item.name_conflict)
  return { candidates: candidates.slice(0, limit), omitted_candidates: Math.max(0, candidates.length - limit),
    ambiguous,
    instruction: ambiguous ? 'Ask which person or number is intended before choosing an identity.' : 'Use only the returned explicit identifiers. Do not guess a LID from a phone number.' }
}
export function excerpt(value, query, maximum) {
  if (value.length <= maximum) return { state: 'ok', value, truncated: false }
  // Normalization can change offsets. Locate terms in original words to keep a
  // bounded excerpt near the hit rather than assuming normalized byte offsets.
  const terms = normalizeText(query).split(' ').filter(Boolean)
  let position = 0
  for (const match of value.matchAll(/\S+/gu)) {
    if (terms.some(term => normalizeText(match[0]).includes(term))) { position = match.index; break }
  }
  const start = Math.max(0, position - Math.floor(maximum / 4))
  return { state: 'ok', value: value.slice(start, start + maximum), truncated: true, offset: start }
}
