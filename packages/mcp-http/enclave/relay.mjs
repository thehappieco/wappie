// The enclave's relay to Go: `https://api.wappie.thehappie.co/v1/mcp/enclave/*`,
// WebPKI-verified inside the enclave (the parent only pipes bytes), every
// request HMAC-signed `to-go` with the current relay secret. Same interface as
// the hosted relay (status, activate, revoke, cimd) plus the sealed-state
// store (stateGet, statePut) that openSealedState uses.
import { createRelay, RelayError } from '../internal.mjs'
import { StateError } from '../state.mjs'
import { signedHeaders } from './hmac.mjs'

export const STATE_TIMEOUT_MS = 30_000
export const STATE_MAX_BYTES = 12 * 1024 * 1024
const generationShape = /^[1-9][0-9]{0,15}$/
const names = new Set(['as-clients', 'as-connections', 'as-tokens', 'infra'])

export function createSignedRelay({ base, readerId, secrets, fetch = globalThis.fetch, timeoutMs = 10_000, now = Date.now }) {
  const headersFor = (method, target, body) => signedHeaders({ secret: secrets.current, direction: 'to-go', readerId, method, target, body, now })
  const relay = createRelay({ archive: base, fetch, timeoutMs, prefix: '/v1/mcp/enclave', headersFor })
  const statePath = name => {
    if (!names.has(name)) throw new StateError('state_name_invalid')
    return `/state/${name}`
  }
  return {
    status: relay.status, activate: relay.activate, revoke: relay.revoke, cimd: relay.cimd,

    /** `{generation, blob}` for a stored collection, or null when Go never had it. */
    async stateGet(name) {
      const response = await relay.call('GET', statePath(name), null, { timeout: STATE_TIMEOUT_MS, headers: { accept: 'application/octet-stream' } })
      const blob = await relay.body(response, STATE_MAX_BYTES)
      if (response.status === 404) return null
      const generation = response.headers.get('x-wappie-generation') ?? ''
      if (response.status !== 200 || !generationShape.test(generation)) throw new RelayError('relay_failed', response.status)
      return { generation: Number(generation), blob }
    },

    /** Writes `blob` if `ifGeneration` is still current; resolves to the new generation. */
    async statePut(name, ifGeneration, blob) {
      if (!Number.isSafeInteger(ifGeneration) || ifGeneration < 0) throw new StateError('state_generation_invalid')
      const response = await relay.call('PUT', statePath(name), { if_generation: String(ifGeneration) },
        { body: blob, timeout: STATE_TIMEOUT_MS, headers: { 'content-type': 'application/octet-stream' } })
      const data = await relay.body(response)
      if (response.status === 409) throw new StateError('state_conflict')
      if (response.status !== 200) throw new RelayError('relay_failed', response.status)
      let parsed
      try { parsed = JSON.parse(data.toString('utf8')) } catch { throw new RelayError('relay_failed', response.status) }
      if (parsed?.generation !== ifGeneration + 1) throw new RelayError('relay_failed', response.status)
      return parsed.generation
    },
  }
}

/** The store openSealedState expects, over this relay. */
export const relayStore = relay => ({ get: name => relay.stateGet(name), put: (name, ifGeneration, blob) => relay.statePut(name, ifGeneration, blob) })
