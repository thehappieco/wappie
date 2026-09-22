// What a connection hands the shared reader: a provided-mode configuration and
// a credential provider that can produce the API key and nothing else. Both
// content-opening reads refuse, so a hosted reader cannot decrypt anything
// even if a bundle ever tried to give it the means.
import { LocalConfigError, validateConfig } from '@whatserver2/mcp/config'

export function configFor(connection, archive) {
  return validateConfig({
    server: archive, workspace: connection.workspace_id, device_ids: connection.device_ids, timezone: connection.timezone,
    allow_plaintext: false, credential_source: 'provided', max_scan_messages: 500,
  })
}

export function providerFor(connection) {
  return {
    token: async () => ({ token: connection.api_key, kind: 'api_key' }),
    serviceKey: () => { throw new LocalConfigError('plaintext_opt_in_required') },
    contactPack: () => { throw new LocalConfigError('plaintext_opt_in_required') },
  }
}
