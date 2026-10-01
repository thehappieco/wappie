// RFC 7591 dynamic client registration. Registration is open (any caller can
// register), so the redirect allowlist, the caps and the TTLs are what bound
// it: a client somebody consented to (`authorized_at`) lives thirty days
// unused, one nobody ever consented to is a cache entry at best and lives an
// hour, and at a cap the oldest of those makes room rather than the caller
// being refused. The authentication method is assigned by this server: every
// client is public (`none`), whatever it asked for.
//
// Reader 0.6.0 (docs/mcp-enclave.md §19) takes a policy object: `{mode:
// 'allowlist', hosts}` is 0.5.0's rule, kept for the hosted reader and the
// tests; `{mode: 'any', tested, …}` admits a registration only when every
// redirect is pinned by one `dcr` entry of the measured TESTED_CLIENTS
// (§19.8), and adds what every request is classified by: the tested entries
// (§19.4), the redirect classes of a client document (§19.6) and the claimed
// name's rules.
import { randomBytes } from 'node:crypto'

export const MAX_CLIENTS = 500
export const MAX_CLIENTS_PER_HOST = 200
export const CLIENT_IDLE_MS = 30 * 24 * 3_600_000
export const CLIENT_UNUSED_MS = 3_600_000
/** Fetched documents of clients Wappie has not tested, in all and per registrable domain (§19.10). */
export const UNKNOWN_CLIENTS_MAX = 300
export const UNKNOWN_CLIENTS_PER_DOMAIN = 20
/** A redirect URI's longest form, in bytes (§19.6). */
export const REDIRECT_MAX_BYTES = 2048
const grants = ['authorization_code', 'refresh_token']
const printable = /^[\x20-\x7E\u00A0-\uFFFF]{1,100}$/u

export class RegistrationError extends Error {
  constructor(code, description) { super(description); this.name = 'RegistrationError'; this.code = code; this.description = description }
}

/** The host of an acceptable redirect URI (https, default port, no userinfo or fragment, host in the allowlist), or null. */
export function redirectHost(value, hosts) {
  if (typeof value !== 'string' || value.length > 2048) return null
  let url
  try { url = new URL(value) } catch { return null }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.hash || url.href !== value) return null
  const host = url.hostname.toLowerCase()
  return hosts.includes(host) ? host : null
}

const loopbackHosts = ['127.0.0.1', '[::1]', 'localhost']

/**
 * A native app's loopback redirect (RFC 8252 §7.3): plain http to a loopback
 * address, no userinfo, query or fragment. The app picks a free port when the
 * flow starts, so the port is not part of the identity: `{ host, path }`, or
 * null.
 *
 * `localhost` counts. RFC 8252 §8.3 advises clients to prefer an IP literal,
 * because a name can be made to resolve elsewhere; but Claude Code asks for
 * http://localhost:<port>/callback, and an authorization server that refuses
 * it simply locks that client out. What is admitted is only what a vouching
 * document declares, browsers resolve localhost to loopback without asking
 * DNS, and a machine whose resolver sends it elsewhere is already compromised
 * where the code lands.
 */
export function loopbackRedirect(value) {
  if (typeof value !== 'string' || value.length > 2048) return null
  let url
  try { url = new URL(value) } catch { return null }
  if (url.protocol !== 'http:' || url.username || url.password || url.search || url.hash) return null
  return loopbackHosts.includes(url.hostname) ? { host: url.hostname, path: url.pathname } : null
}

/**
 * Validates a redirect_uris list the way both DCR and CIMD documents require.
 *
 * `vouchedBy` is set only for a CIMD document, and names the allowed host that
 * served it. Such a document may instead list loopback redirects for a native
 * app — ChatGPT's Codex does — because its identity is the https document, not
 * the redirect: the code goes to a listener on the consenting person's own
 * machine, and PKCE keeps it useless to anything but the app that started the
 * flow. The client's redirect_host is then the vouching host, which is what
 * the consent card names and what the API's allowlist checks. Open
 * registration never gets loopback: nobody vouches for it.
 */
export function validateRedirectURIs(list, hosts, { vouchedBy } = {}) {
  if (!Array.isArray(list) || list.length < 1 || list.length > 5) throw new RegistrationError('invalid_redirect_uri', 'redirect_uris must list one to five HTTPS URIs')
  const uris = [], seen = new Set()
  let host, loopback = false, https = false
  for (const value of list) {
    const found = redirectHost(value, hosts)
    if (found) {
      if (host && host !== found) throw new RegistrationError('invalid_redirect_uri', 'redirect_uris must share one host')
      host = found; https = true
    } else if (vouchedBy && loopbackRedirect(value) && !new URL(value).port) {
      loopback = true
    } else {
      throw new RegistrationError('invalid_redirect_uri', 'redirect_uris must be HTTPS URIs on an allowed host')
    }
    if (!seen.has(value)) { seen.add(value); uris.push(value) }
  }
  if (loopback && https) throw new RegistrationError('invalid_redirect_uri', 'redirect_uris must be either HTTPS or loopback, not both')
  return loopback ? { uris, host: vouchedBy, loopback } : { uris, host, loopback }
}

/**
 * Whether `requested` is one of the client's redirect URIs. Exact, except for
 * a loopback client, whose registered URIs carry no port: RFC 8252 §7.3 says
 * any port must be accepted there, and the host and path must still match.
 */
export function redirectAllowed(client, requested) {
  if (typeof requested !== 'string') return false
  if (client.redirect_uris.includes(requested)) return true
  // A 0.5.0 record says it is a native app's; a 0.6.0 document record
  // (§19.6, `client_host` set) lists its loopback entries among the usable
  // ones, with or without a port, beside its https ones.
  if (!client.loopback && client.client_host === undefined) return false
  const asked = loopbackRedirect(requested)
  return Boolean(asked) && client.redirect_uris.some(registered => {
    const known = loopbackRedirect(registered)
    return known && known.host === asked.host && known.path === asked.path
  })
}

export function validateClientName(value) {
  if (value === undefined) return 'MCP client'
  if (typeof value !== 'string' || !printable.test(value)) throw new RegistrationError('invalid_client_metadata', 'client_name must be up to 100 printable characters')
  return value
}

// ---- Reader 0.6.0: tested entries, document redirects, names (§19.4 to §19.8) ----

/**
 * A redirect of a client document, classified (§19.6 step 2): 'https' (the
 * canonical form, no userinfo, port or fragment, a query allowed, on exactly
 * the document's host `host`), 'loopback' (plain http to 127.0.0.1, [::1] or
 * localhost, any port or none, no userinfo, query or fragment) or null for
 * anything else, which the document keeps but nobody may ask for.
 */
export function classifyRedirect(value, host) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > REDIRECT_MAX_BYTES) return null
  let url
  try { url = new URL(value) } catch { return null }
  if (url.protocol === 'https:') return url.href === value && !url.username && !url.password && !url.port && !url.hash && !value.includes('#') && url.hostname === host ? 'https' : null
  return loopbackRedirect(value) ? 'loopback' : null
}

/** `template` with its one `{cb}` filled, or the `{cb}` value that makes it equal `value` (matching `pattern`), or null. */
function callbackOf(template, value, pattern) {
  const parts = template.split('{cb}')
  if (parts.length !== 2 || typeof value !== 'string') return null
  const [head, tail] = parts
  if (value.length <= head.length + tail.length || !value.startsWith(head) || !value.endsWith(tail)) return null
  const cb = value.slice(head.length, value.length - tail.length)
  return typeof pattern === 'string' && new RegExp(pattern).test(cb) ? cb : null
}

/**
 * Whether a tested entry pins `uri`: an https redirect exactly, or with the
 * `{cb}` of the request (`cb`, for a `cimd_pattern` entry; a `dcr` entry
 * takes any value its pattern allows), or a loopback one by hostname and path
 * with any port (no 127.0.0.1/localhost equivalence).
 */
export function pins(entry, uri, cb = null) {
  if (typeof uri !== 'string') return false
  for (const template of entry.redirect_uris ?? []) {
    if (!template.includes('{cb}')) { if (template === uri) return true; continue }
    if (cb !== null ? template.split('{cb}').join(cb) === uri : callbackOf(template, uri, entry.cb) !== null) return true
  }
  const asked = loopbackRedirect(uri)
  return Boolean(asked) && (entry.loopback ?? []).some(([hostname, path]) => hostname === asked.host && path === asked.path)
}

/**
 * The tested CIMD entry a `client_id` names, with the request's `{cb}` and
 * whether its redirect is pinned, or null. Exact entries first, so a callback
 * id never shadows one of them (`…/oauth/codex/client.json` is Codex).
 */
export function testedFor(tested, clientID, redirectURI) {
  if (typeof clientID !== 'string') return null
  for (const entry of tested) if (entry.kind === 'cimd' && entry.client_id === clientID) return { entry, cb: null, pinned: pins(entry, redirectURI) }
  for (const entry of tested) {
    if (entry.kind !== 'cimd_pattern') continue
    const cb = callbackOf(entry.client_id, clientID, entry.cb)
    if (cb !== null) return { entry, cb, pinned: pins(entry, redirectURI, cb) }
  }
  return null
}

/** The `dcr` entry that pins every one of `uris`, or null (§19.8). */
export const dcrEntryFor = (tested, uris) => tested.find(entry => entry.kind === 'dcr' && uris.length > 0 && uris.every(uri => pins(entry, uri))) ?? null

/** The limits tier of a request or record (§19.6): token, else by trust and whether it is local. */
export const limitsTierOf = ({ trust, client_local, client_kind }) => (client_kind === 'token' ? 'token' : trust === 'tested' ? (client_local ? 'local_tested' : 'web_tested') : 'unknown')

// UTS #39 "Highly Restrictive" over Script_Extensions (§19.6 step 3): every
// script V8 knows, compiled once; one this Node does not know is left out,
// and its characters then read as unassigned, which neither side tests.
const SCRIPTS = ('Adlm Aghb Ahom Arab Armi Armn Avst Bali Bamu Bass Batk Beng Bhks Bopo Brah Brai Bugi Buhd Cakm Cans Cari Cham Cher Chrs Copt Cpmn ' +
  'Cprt Cyrl Deva Diak Dogr Dsrt Dupl Egyp Elba Elym Ethi Gara Geor Glag Gong Gonm Goth Gran Grek Gujr Gukh Guru Hang Hani Hano Hatr Hebr Hira Hluw ' +
  'Hmng Hmnp Hung Ital Java Kali Kana Kawi Khar Khmr Khoj Kits Knda Krai Kthi Lana Laoo Latn Lepc Limb Lina Linb Lisu Lyci Lydi Mahj Maka Mand Mani ' +
  'Marc Medf Mend Merc Mero Mlym Modi Mong Mroo Mtei Mult Mymr Nagm Nand Narb Nbat Newa Nkoo Nshu Ogam Olck Onao Orkh Orya Osge Osma Ougr Palm Pauc ' +
  'Perm Phag Phli Phlp Phnx Plrd Prti Rjng Rohg Runr Samr Sarb Saur Sgnw Shaw Shrd Sidd Sind Sinh Sogd Sogo Sora Soyo Sund Sunu Sylo Syrc Tagb Takr ' +
  'Tale Talu Taml Tang Tavt Telu Tfng Tglg Thaa Thai Tibt Tirh Tnsa Todr Toto Tutg Ugar Vaii Vith Wara Wcho Xpeo Xsux Yezi Yiii Zanb').split(' ')
  .flatMap(script => { try { return [[script, new RegExp(`^\\p{scx=${script}}$`, 'u')]] } catch { return [] } })
const COMMON = /^[\p{scx=Zyyy}\p{scx=Zinh}]$/u
/** Han's, Kana's, Hangul's and Bopomofo's writing systems, as UTS #39 §5.1 augments them. */
const AUGMENT = { Hani: ['Jpan', 'Kore', 'Hanb'], Hira: ['Jpan'], Kana: ['Jpan'], Hang: ['Kore'], Bopo: ['Hanb'] }
function scriptsOf(character) {
  if (COMMON.test(character)) return null
  const found = new Set()
  for (const [script, pattern] of SCRIPTS) if (pattern.test(character)) { found.add(script); for (const extra of AUGMENT[script] ?? []) found.add(extra) }
  return found.size ? found : null
}
/** The resolved script set of `characters`, leaving out those whose set holds `without`; null stands for every script. */
function resolved(characters, without) {
  let set = null
  for (const character of characters) {
    const scripts = scriptsOf(character)
    if (!scripts || (without && scripts.has(without))) continue
    set = set ? new Set([...set].filter(script => scripts.has(script))) : scripts
  }
  return set
}
/** Single-script, or Latin with Han and Kana, Han and Bopomofo, or Han and Hangul (UTS #39 §5.2). */
export function highlyRestrictive(text) {
  const characters = [...text]
  const all = resolved(characters)
  if (all === null || all.size > 0) return true
  const rest = resolved(characters, 'Latn')
  return rest !== null && ['Jpan', 'Kore', 'Hanb'].some(script => rest.has(script))
}

/**
 * The name a document or a registration declares (§19.6 step 3): NFC, 1 to
 * 100 code points, no leading, trailing or doubled white space, no control,
 * format, separator, private-use or surrogate code point, and scripts that
 * UTS #39 calls highly restrictive. A name that fails is dropped, never
 * fatal. `{claimed_name, name_dropped}`; a missing name is null, not dropped.
 */
export function claimedName(value) {
  if (value === undefined) return { claimed_name: null, name_dropped: false }
  const dropped = { claimed_name: null, name_dropped: true }
  if (typeof value !== 'string') return dropped
  const name = value.normalize('NFC')
  const length = [...name].length
  if (length < 1 || length > 100 || /^\p{White_Space}|\p{White_Space}$|\p{White_Space}{2}/u.test(name) ||
    /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cs}]/u.test(name) || !highlyRestrictive(name)) return dropped
  return { claimed_name: name, name_dropped: false }
}

/**
 * Room for one more fetched document of a client nobody tested, under
 * `registrable` (§19.10): at a cap, the oldest record no live connection
 * names makes way, one nobody consented to before one somebody did; false
 * only when every record under the cap serves a live connection.
 */
export function makeRoomUnknown(state, registrable) {
  for (;;) {
    const unknown = [...state.clients.values()].filter(client => client.source === 'cimd' && client.client_host !== undefined)
    const mine = unknown.filter(client => client.registrable === registrable)
    const crowded = mine.length >= UNKNOWN_CLIENTS_PER_DOMAIN ? mine : unknown.length >= UNKNOWN_CLIENTS_MAX ? unknown : null
    if (!crowded) return true
    if (!evictOne(state, crowded)) return false
  }
}

/**
 * Forgets the oldest of `crowded` that no live connection names, one nobody
 * consented to before one somebody did (§19.10); false when each of them
 * serves a live connection.
 */
function evictOne(state, crowded) {
  const named = new Set([...state.connections.values()].map(connection => connection.client_id))
  const evictable = crowded.filter(client => !named.has(client.client_id))
  if (evictable.length === 0) return false
  const rank = client => [client.authorized_at ? 1 : 0, client.last_used_at]
  state.clients.delete(evictable.reduce((oldest, client) => {
    const [a, b] = [rank(client), rank(oldest)]
    return a[0] < b[0] || (a[0] === b[0] && a[1] < b[1]) ? client : oldest
  }).client_id)
  return true
}

/**
 * Room for one more registration on `host` under reader 0.6.0's rule
 * (§19.10): MAX_CLIENTS registrations and MAX_CLIENTS_PER_HOST per host, DCR
 * records only (fetched documents have caps of their own). At a cap the
 * oldest record no live connection names makes way, one nobody consented to
 * before one somebody did; a consent alone no longer protects a record. False
 * only when every record under the cap serves a live connection.
 */
export function makeRoomRegistered(state, host) {
  for (;;) {
    const all = [...state.clients.values()].filter(client => client.source === 'dcr'), mine = all.filter(client => client.redirect_host === host)
    const crowded = mine.length >= MAX_CLIENTS_PER_HOST ? mine : all.length >= MAX_CLIENTS ? all : null
    if (!crowded) return true
    if (!evictOne(state, crowded)) return false
  }
}

/**
 * Room for one more client on `host`: true under the caps, or once the oldest
 * client nobody consented to has been forgotten; false only when the cap is
 * made of consented clients.
 */
export function makeRoom(state, host) {
  for (;;) {
    const all = [...state.clients.values()], mine = all.filter(client => client.redirect_host === host)
    const crowded = mine.length >= MAX_CLIENTS_PER_HOST ? mine : all.length >= MAX_CLIENTS ? all : null
    if (!crowded) return true
    const evictable = crowded.filter(client => !client.authorized_at)
    if (evictable.length === 0) return false
    state.clients.delete(evictable.reduce((oldest, client) => (client.last_used_at < oldest.last_used_at ? client : oldest)).client_id)
  }
}

export function createClients(state, { now = Date.now, hosts, policy }) {
  const live = () => [...state.clients.values()]
  const pinned = policy?.mode === 'any'
  /**
   * §19.8: every redirect must be one a single `dcr` entry pins, else
   * `invalid_redirect_uri`; the record is tested, with that entry's id. A
   * name that fails §19.6's rules is dropped, never fatal: `claimed_name` is
   * null. The grant and response types are checked as before.
   */
  function registerPinned(metadata) {
    const list = metadata.redirect_uris
    if (!Array.isArray(list) || list.length < 1 || list.length > 5 || list.some(value => typeof value !== 'string')) throw new RegistrationError('invalid_redirect_uri', 'redirect_uris must list one to five URIs')
    const uris = [...new Set(list)]
    const entry = dcrEntryFor(policy.tested, uris)
    if (!entry) throw new RegistrationError('invalid_redirect_uri', 'redirect_uris must be redirects this server pins for dynamic registration')
    const { claimed_name, name_dropped } = claimedName(metadata.client_name)
    const requested = metadata.grant_types === undefined ? ['authorization_code'] : metadata.grant_types
    if (!Array.isArray(requested) || requested.length === 0 || requested.some(grant => !grants.includes(grant))) throw new RegistrationError('invalid_client_metadata', 'grant_types may only contain authorization_code and refresh_token')
    if (metadata.response_types !== undefined && (!Array.isArray(metadata.response_types) || metadata.response_types.join(' ') !== 'code')) throw new RegistrationError('invalid_client_metadata', 'response_types must be ["code"]')
    if (metadata.token_endpoint_auth_method !== undefined && typeof metadata.token_endpoint_auth_method !== 'string') throw new RegistrationError('invalid_client_metadata', 'token_endpoint_auth_method must be a string')
    const key = uris.slice().sort().join(' ')
    const existing = live().find(client => client.source === 'dcr' && client.tested_id === entry.id && client.claimed_name === claimed_name && client.redirect_uris.slice().sort().join(' ') === key)
    if (existing) { existing.last_used_at = now(); return existing }
    const host = new URL(uris[0]).hostname
    if (!makeRoomRegistered(state, host)) {
      const error = new RegistrationError('too_many_clients', 'client registrations are full; try again later')
      error.status = 429
      throw error
    }
    const record = {
      client_id: randomBytes(16).toString('base64url'), redirect_uris: uris, client_name: entry.name, claimed_name, name_dropped, redirect_host: host, tested_id: entry.id,
      grant_types: [...new Set(['authorization_code', ...requested])], source: 'dcr', created_at: now(), last_used_at: now(),
    }
    state.clients.set(record.client_id, record)
    return record
  }
  return {
    /** Registers or returns the equivalent existing client; throws RegistrationError or {code:'too_many_clients'}. */
    register(metadata) {
      if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) throw new RegistrationError('invalid_client_metadata', 'the registration must be a JSON object')
      if (pinned) return registerPinned(metadata)
      const { uris, host } = validateRedirectURIs(metadata.redirect_uris, hosts)
      const name = validateClientName(metadata.client_name)
      const requested = metadata.grant_types === undefined ? ['authorization_code'] : metadata.grant_types
      if (!Array.isArray(requested) || requested.length === 0 || requested.some(grant => !grants.includes(grant))) throw new RegistrationError('invalid_client_metadata', 'grant_types may only contain authorization_code and refresh_token')
      if (metadata.response_types !== undefined && (!Array.isArray(metadata.response_types) || metadata.response_types.join(' ') !== 'code')) throw new RegistrationError('invalid_client_metadata', 'response_types must be ["code"]')
      if (metadata.token_endpoint_auth_method !== undefined && typeof metadata.token_endpoint_auth_method !== 'string') throw new RegistrationError('invalid_client_metadata', 'token_endpoint_auth_method must be a string')
      const key = uris.slice().sort().join(' ')
      const existing = live().find(client => client.source === 'dcr' && client.client_name === name && client.redirect_uris.slice().sort().join(' ') === key)
      if (existing) { existing.last_used_at = now(); return existing }
      if (!makeRoom(state, host)) {
        const error = new RegistrationError('too_many_clients', 'client registrations are full; try again later')
        error.status = 429
        throw error
      }
      const record = {
        client_id: randomBytes(16).toString('base64url'), redirect_uris: uris, client_name: name, redirect_host: host,
        grant_types: [...new Set(['authorization_code', ...requested])], source: 'dcr', created_at: now(), last_used_at: now(),
      }
      state.clients.set(record.client_id, record)
      return record
    },
    /** The RFC 7591 response body for a stored client. */
    describe(record) {
      return {
        client_id: record.client_id, client_id_issued_at: Math.floor(record.created_at / 1000),
        // A pinned registration answers the name it was given, or none when it was dropped.
        ...(record.tested_id !== undefined ? (record.claimed_name ? { client_name: record.claimed_name } : {}) : { client_name: record.client_name }),
        redirect_uris: record.redirect_uris, token_endpoint_auth_method: 'none', grant_types: record.grant_types,
        response_types: ['code'], scope: 'wappie:read',
      }
    },
    /** Looks a registered client up and records the use that keeps it alive; CIMD clients go through cimd.resolve. */
    get(clientID) {
      const record = typeof clientID === 'string' ? state.clients.get(clientID) : undefined
      if (!record || record.source !== 'dcr') return undefined
      record.last_used_at = now()
      return record
    },
    /** Records that a user consented to this client, which is what earns it the long TTL. */
    consented(clientID) {
      const record = state.clients.get(clientID)
      if (record) record.authorized_at = now()
    },
    /** Forgets clients unused for thirty days, or an hour when nobody ever consented; returns whether anything changed. */
    sweep() {
      const at = now()
      let changed = false
      for (const [id, client] of state.clients) if (at - client.last_used_at > (client.authorized_at ? CLIENT_IDLE_MS : CLIENT_UNUSED_MS)) { state.clients.delete(id); changed = true }
      return changed
    },
  }
}
