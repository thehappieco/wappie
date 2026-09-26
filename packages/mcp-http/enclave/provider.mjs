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
// `reseal`, or any wipe) the token itself is refused with
// `reconsent_required`, so no archive call is made at all.
import { LocalConfigError, validateConfig } from '@whatserver2/mcp/config'

/** The scan budget per text-search call: the REST sequence depends on it, never on what matched. */
export const CONTENT_MAX_SCAN = 500

export function contentConfigFor(record, archive) {
  return validateConfig({
    server: archive, workspace: record.workspace_id, device_ids: record.device_ids, timezone: record.timezone,
    allow_plaintext: true, credential_source: 'enclave', service_user_id: record.service_user_id, max_scan_messages: CONTENT_MAX_SCAN,
  })
}

/** The console link where the creator renews this connection with their password. */
export function renewalURL(consoleURL, connectionID) {
  const url = new URL(consoleURL)
  url.searchParams.set('mcp_renew', connectionID)
  return url.href
}

/**
 * `onStaleGrant()` (optional) is called, with nothing, each time the reader
 * refuses one of this connection's grants as `stale_grant`; the enclave logs
 * the event. The reader neither awaits it nor lets it throw into the tool.
 */
export function contentProviderFor(record, connkeys, consoleURL, { onStaleGrant } = {}) {
  const id = record.connection_id
  const held = () => {
    const stored = connkeys.get(id)
    if (!stored) throw new LocalConfigError('reconsent_required')
    return stored
  }
  return {
    token: async () => { held(); return { token: record.api_key, kind: 'api_key' } },
    serviceKey: async () => { const stored = held(); return { key: stored.key, publicRaw: new Uint8Array(stored.publicRaw) } },
    expectedEpoch: device => (record.epochs && Object.hasOwn(record.epochs, device) ? record.epochs[device] : undefined),
    renewalURL: () => renewalURL(consoleURL, id),
    // The personal contacts snapshot is out of 2b: nothing is ever asked for or opened.
    contactPack: async () => null,
    // What the reader passes (the number) stays here: the event names the connection only.
    onStaleGrant: () => { onStaleGrant?.() },
  }
}
