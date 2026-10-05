// What a content connection hands the shared reader inside the enclave
// (docs/mcp-enclave.md §15.5). The pilot's ../provider.mjs is the metadata-only
// one and stays untouched; this file is reachable from enclave/main.mjs only.
//
// The key is never given out as bytes: `serviceKey()` returns the
// non-extractable CryptoKey handle with a fresh copy of the public half. The
// reader zeroes nothing it is handed; the copy is there because connkeys
// zeroes its stored public half when the key is wiped (a revoke, a reseal, a
// renewal commit), and a read already in flight must keep the bytes it was
// given rather than see them turn to zeros under it, while nothing handed out
// can ever write into the stored copy. Without a held key (after a restart, a
// `reseal`, or any wipe) a content connection still reads metadata with its
// own read-only API key, and every read that needs the key is refused with
// `reconsent_required` (docs/mcp-enclave.md §19.29): `keyHeld()` tells the
// reader which. An AI authorization (§18) reads nothing at all without its
// key: its token is refused, as every connection's was before 0.6.0.
import { LocalConfigError, validateConfig } from '@whatserver2/mcp/config'
import { tierOf } from '../provider.mjs'

/** The scan budget per text-search call: the REST sequence depends on it, never on what matched. */
export const CONTENT_MAX_SCAN = 500

/**
 * A record without `media` (every 0.3.0 record included) is a text
 * connection; one without `send` (every record before 0.5.0) never drafts or
 * sends (docs/mcp-enclave.md §17.8): the tools a connection has are the
 * sealed consent's, the same on every request. An `ai` record (§18.12) has
 * neither: its reader only opens content for its own jobs, never as an MCP
 * server.
 */
export function contentConfigFor(record, archive) {
  const send = record.send === 'draft' || record.send === 'direct' ? record.send : null
  return validateConfig({
    server: archive, workspace: record.workspace_id, device_ids: record.device_ids, timezone: record.timezone,
    allow_plaintext: true, credential_source: 'enclave', service_user_id: record.service_user_id, max_scan_messages: CONTENT_MAX_SCAN,
    media: record.media === true, send, send_self: send !== null && record.send_self === true,
    // The history window the person chose (§19.19), for a client Wappie has not tested or a token.
    history_days: record.history_days ?? null,
  })
}

/** The console link where the creator renews this connection with their password. */
export function renewalURL(consoleURL, connectionID) {
  const url = new URL(consoleURL)
  url.searchParams.set('mcp_renew', connectionID)
  return url.href
}

const uuidShape = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
/**
 * The console link that opens one message (docs/mcp-enclave.md §16.7, the
 * link contract): `${consoleURL}?workspace=<tenant>&open_device=<number>&open_message=<uid>`,
 * the ids in lower case. The person's browser opens the original there with
 * their own keys; the link carries ids the reader already returns and
 * nothing secret. Null when an id is not a UUID, so nothing else ever
 * reaches the URL.
 */
export function messageURL(consoleURL, tenantID, deviceID, uid) {
  return consoleLinkOf(consoleURL, [['workspace', tenantID], ['open_device', deviceID], ['open_message', uid]])
}

/**
 * The console link where an AI authorization's creator renews it
 * (docs/mcp-enclave.md §18.7 step 7, §18.12):
 * `${consoleURL}?workspace=<tenant>&ai_renew=<authorization>`, built like
 * messageURL, or null.
 */
export function aiRenewURL(consoleURL, tenantID, authorizationID) {
  return consoleLinkOf(consoleURL, [['workspace', tenantID], ['ai_renew', authorizationID]])
}

/** `${consoleURL}?name=id&…` in the order given, every id a UUID in lower case, or null. */
function consoleLinkOf(consoleURL, params) {
  if (!params.every(([, id]) => typeof id === 'string' && uuidShape.test(id))) return null
  const url = new URL(consoleURL)
  for (const [name, id] of params) url.searchParams.set(name, id.toLowerCase())
  return url.href
}

/**
 * The console links of a workspace's sending (§17.8, the shared link
 * contract with §16.7's): a sent message (`open_message`), one draft to
 * review (`mcp_draft`, with the number it goes out from) and a connection's
 * pending drafts (`mcp_drafts`). Each is null unless every id is a UUID.
 */
export function messageURLs(consoleURL, tenantID) {
  return {
    message: (deviceID, uid) => messageURL(consoleURL, tenantID, deviceID, uid),
    draft: (deviceID, draftID) => consoleLinkOf(consoleURL, [['workspace', tenantID], ['open_device', deviceID], ['mcp_draft', draftID]]),
    drafts: connectionID => consoleLinkOf(consoleURL, [['workspace', tenantID], ['mcp_drafts', connectionID]]),
  }
}

/**
 * `onStaleGrant()` (optional) is called, with nothing, each time the reader
 * refuses one of this connection's grants as `stale_grant`; the enclave logs
 * the event. The reader neither awaits it nor lets it throw into the tool.
 * `media` (media/service.mjs forConnection, docs/mcp-enclave.md §16.5) is
 * given only to a record whose sealed consent includes attachments, and
 * `send` (send/service.mjs forConnection, §17.8) only to one whose sealed
 * consent includes sending. `limits` (budgets.mjs forConnection, §19.19) only
 * to one whose tier has reading limits.
 */
export function contentProviderFor(record, connkeys, consoleURL, { onStaleGrant, media, send, limits } = {}) {
  const id = record.connection_id
  const held = () => {
    const stored = connkeys.get(id)
    if (!stored) throw new LocalConfigError('reconsent_required')
    return stored
  }
  return {
    token: async () => { if (record.kind === 'ai') held(); return { token: record.api_key, kind: 'api_key' } },
    keyHeld: () => connkeys.has(id),
    connection: () => ({ tier: tierOf(record), expires_at: record.expires_at }),
    serviceKey: async () => { const stored = held(); return { key: stored.key, publicRaw: new Uint8Array(stored.publicRaw) } },
    expectedEpoch: device => (record.epochs && Object.hasOwn(record.epochs, device) ? record.epochs[device] : undefined),
    renewalURL: () => renewalURL(consoleURL, id),
    // The personal contacts snapshot is out of 2b: nothing is ever asked for or opened.
    contactPack: async () => null,
    // What the reader passes (the number) stays here: the event names the connection only.
    onStaleGrant: () => { onStaleGrant?.() },
    ...(media ? { media } : {}),
    ...(send ? { send } : {}),
    ...(limits ? { limits } : {}),
  }
}
