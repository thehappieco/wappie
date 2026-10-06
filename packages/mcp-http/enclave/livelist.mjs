// The attested live list (docs/mcp-enclave.md §19.22, `live_list_v1`). The
// console's list of connections and its new-assistant banner come from Go's
// ledger, so a compromised Go could hide a row; this process is the only
// party that knows every live connection without trusting Go. The console
// asks, through Go, for a workspace's live connection ids with a nonce of its
// own, and compares the attested answer with Go's list: an id here that Go's
// list lacks raises a red banner. Detection, not removal.
//
// AI authorizations are left out, as Go's list leaves them out. The document
// carries the console's nonce and no public key, and binds the whole answer
// (user_data v2 with request_id ''); its `nonce` member is the console's, as
// it sent it.
import { LinkError } from '../link.mjs'

/** Lists a workspace may ask for in a minute, so an untrusted Go cannot turn this into a stream of NSM signatures (Go allows 10 too). */
export const LIVE_LISTS_PER_MINUTE = 10
const MINUTE_MS = 60_000

/** `attestor` is createAttestor's (the enclave's). */
export function createLiveList({ state, attestor, now = Date.now, perMinute = LIVE_LISTS_PER_MINUTE }) {
  // workspace -> the times of its lists in the last minute; in memory only.
  const recent = new Map()
  function take(workspace) {
    const at = now()
    const times = (recent.get(workspace) ?? []).filter(time => at - time < MINUTE_MS)
    if (times.length >= perMinute) { recent.set(workspace, times); return false }
    times.push(at)
    recent.set(workspace, times)
    if (recent.size > 10_000) for (const [key, list] of recent) if (list.every(time => at - time >= MINUTE_MS)) recent.delete(key)
    return true
  }
  return {
    /**
     * `{descriptor_version: 2, kind: 'live_list', workspace_id, nonce,
     * connection_ids, at, attestation}`: the workspace's live ids, sorted.
     * `nonce` is the decoded bytes, `nonceText` the console's base64url.
     */
    async list(workspaceID, nonce, nonceText) {
      if (!nonce) throw new LinkError('bad_request')
      if (!take(workspaceID)) throw new LinkError('rate_limited', 429)
      const ids = []
      for (const record of state.connections.values()) if (record.tenant_id === workspaceID && record.kind !== 'ai') ids.push(record.connection_id)
      const descriptor = { descriptor_version: 2, kind: 'live_list', workspace_id: workspaceID, nonce: nonceText, connection_ids: ids.sort(), at: new Date(now()).toISOString() }
      return { ...descriptor, attestation: await attestor.attestation({ requestId: '', publicKey: null, nonce, descriptor }) }
    },
  }
}
