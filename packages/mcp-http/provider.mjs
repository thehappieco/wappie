// What a connection hands the shared reader: a provided-mode configuration and
// a credential provider that can produce the API key and nothing else. Both
// content-opening reads refuse, so a hosted reader cannot decrypt anything
// even if a bundle ever tried to give it the means.
import { LocalConfigError, validateConfig } from '@whatserver2/mcp/config'

// From reader 0.6.0 (docs/mcp-enclave.md §19.19) a connection may carry a
// history window, which the configuration hands the reader, and reading
// limits, which the provider hands it (`limits`, the enclave's budgets).
export function configFor(connection, archive) {
  return validateConfig({
    server: archive, workspace: connection.workspace_id, device_ids: connection.device_ids, timezone: connection.timezone,
    allow_plaintext: false, credential_source: 'provided', max_scan_messages: 500, history_days: connection.history_days ?? null,
  })
}

/** A record's limits tier (docs/mcp-enclave.md §19.6); a record 0.5.0 wrote is tested web. */
export const tierOf = record => (typeof record?.limits_tier === 'string' ? record.limits_tier : 'web_tested')

export function providerFor(connection, { limits } = {}) {
  return {
    token: async () => ({ token: connection.api_key, kind: 'api_key' }),
    // The tier and deadline list_numbers' connection block names (§19.29).
    connection: () => ({ tier: tierOf(connection), expires_at: connection.expires_at }),
    serviceKey: () => { throw new LocalConfigError('plaintext_opt_in_required') },
    contactPack: () => { throw new LocalConfigError('plaintext_opt_in_required') },
    ...(limits ? { limits } : {}),
  }
}
