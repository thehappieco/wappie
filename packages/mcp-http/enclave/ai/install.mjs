// Installing an AI authorization (docs/mcp-enclave.md §18.7 steps 5 to 7):
// the relayed bundle is opened with its request's key, validated, bound to
// the request, proven against the grants Go serves (each number's
// configuration tag recomputed from the DSK its grant opens, I3), and its
// keys and models checked with each provider's own list; only then is the
// row activated and anything kept. A renewal (step 7) runs the same checks
// under its own labels. Each failure answers before anything is kept.
import { timingSafeEqual } from 'node:crypto'
import { ArchiveClient, bytes, hpke, seal } from '@whatserver2/client'
import { keysSHA256, validateAIBundle } from '@whatserver2/mcp/bundle'
import { LocalConfigError } from '@whatserver2/mcp/config'
import { bundleBody, LinkError } from '../../link.mjs'
import { classify, errorFacts } from './egress.mjs'
import { AI_MODELS_PAGES_MAX, AI_MODELS_TIMEOUT_MS } from './policy.mjs'
import * as anthropic from './providers/anthropic.mjs'
import * as google from './providers/google.mjs'
import * as openai from './providers/openai.mjs'
import { configTag } from './tags.mjs'

export const PROVIDERS = Object.freeze({ anthropic, openai, google })
export const AI_CONNECT_INFO = Buffer.from('wappie-ai-connect/v1')
export const AI_RENEW_INFO = Buffer.from('wappie-ai-renew/v1')
/** Consent: one AI request, one attested key, one resource. */
export const aiConnectAAD = (requestID, kid, resource) => Buffer.from(JSON.stringify(['wappie/ai-connect', 1, requestID, kid, resource]))
/** Renewal: one renewal, one authorization, one attested key, one resource. */
export const aiRenewAAD = (renewalID, connectionID, kid, resource) => Buffer.from(JSON.stringify(['wappie/ai-renew', 1, renewalID, connectionID, kid, resource]))
/** An authorization lasts at most 90 days; Go's expiry may carry an hour of slack. */
export const MAX_AI_MS = (90 * 24 + 1) * 3_600_000
/** The grant proof's archive call gives up before Go's 30 s relay wait. */
export const AI_PROOF_TIMEOUT_MS = 8_000
const ENC_LEN = 32, TAG_LEN = 16

/** The relayed body: BundleRelay plus `"kind": "ai"` (strict), for a consent or a renewal. */
export function parseAIRelay(body, { now }) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || body.kind !== 'ai') throw new LinkError('bad_request')
  const { kind: _kind, ...rest } = body
  const parsed = bundleBody.safeParse(rest)
  if (!parsed.success) throw new LinkError('bad_request')
  const { connection_id, tenant_id, kid, sealed: encoded, expires_at } = parsed.data
  const sealed = Buffer.from(encoded, 'base64url')
  if (sealed.toString('base64url') !== encoded || sealed.length < ENC_LEN + TAG_LEN) throw new LinkError('bad_request')
  const expiry = Date.parse(expires_at)
  if (!Number.isFinite(expiry) || expiry <= now() || expiry > now() + MAX_AI_MS) throw new LinkError('bad_request')
  return { connection_id, tenant_id, kid, sealed, expiry }
}

/**
 * Opens an AI bundle sealed to `recipient` under `info` and `aad` and checks
 * what binds it to this route: `purpose`, `server_url` the resource's
 * origin, `workspace_id` the relayed tenant, and a renewal's own
 * authorization. Throws LinkError('invalid_bundle'); the plaintext is zeroed.
 */
export async function openAIBundle(recipient, sealed, { info, aad, purpose, origin, tenant, connectionID, now }) {
  let plain
  try {
    plain = await hpke.open(recipient.privateKey, new Uint8Array(sealed.subarray(0, ENC_LEN)), new Uint8Array(info), new Uint8Array(aad), new Uint8Array(sealed.subarray(ENC_LEN)))
  } catch { throw new LinkError('invalid_bundle') }
  try {
    let value
    try { value = JSON.parse(Buffer.from(plain).toString('utf8')) } catch { throw new LinkError('invalid_bundle') }
    let bundle
    try { bundle = validateAIBundle(value, now()) } catch (error) {
      if (error instanceof LocalConfigError) throw new LinkError('invalid_bundle')
      throw error
    }
    if (bundle.purpose !== purpose || bundle.server_url !== origin || bundle.workspace_id !== tenant ||
      (purpose === 'renewal' ? bundle.connection_id !== connectionID : bundle.connection_id !== undefined)) throw new LinkError('invalid_bundle')
    return bundle
  } finally { plain.fill(0) }
}

/** The fields a bundle's configuration tags cover (tags.mjs), from the bundle itself. */
export const bundleTagFields = bundle => ({
  workspace_id: bundle.workspace_id, service_user_id: bundle.service_user_id, device_ids: bundle.device_ids, keys_sha256: keysSHA256(bundle.keys),
  functions: bundle.functions, features: bundle.features, budget: bundle.budget, expires_at: bundle.expires_at, key_mode: bundle.key_mode,
})

/**
 * The grant proof (§15.4 step 4) with the configuration tags (§18.7 step 6.4):
 * the grants Go serves belong to the bundle's service, name exactly its
 * numbers and open with `privateKey`; for each number, after its grant opens
 * and before its DSK is zeroed, `cfg_tags[d]` is recomputed and compared in
 * constant time. A proof failure is LinkError('grant_proof_failed'); a tag
 * that does not hold is LinkError('invalid_bundle') with `tagMismatch`.
 * Resolves to `{epochs, ns}`.
 */
export async function proveAIGrants(privateKey, bundle, { archive, fetch, timeoutMS = AI_PROOF_TIMEOUT_MS, request, kid }) {
  const failed = () => new LinkError('grant_proof_failed')
  let grants
  try { grants = await new ArchiveClient({ serverURL: archive, workspaceID: bundle.workspace_id, token: bundle.token, timeoutMS, ...(fetch ? { fetch } : {}) }).grants() } catch { throw failed() }
  if (grants.user_id?.toLowerCase() !== bundle.service_user_id) throw failed()
  const devices = grants.grants.map(grant => grant.device_id.toLowerCase())
  if (new Set(devices).size !== devices.length || devices.length !== bundle.device_ids.length || !bundle.device_ids.every(device => devices.includes(device))) throw failed()
  const fields = bundleTagFields(bundle)
  const service = bytes.parseUUID(bundle.service_user_id)
  const epochs = {}, ns = {}
  for (const grant of grants.grants) {
    if (!Number.isSafeInteger(grant.epoch) || grant.epoch < 1 || grant.epoch > 65535) throw failed()
    const device = grant.device_id.toLowerCase()
    const namespace = (grant.archive_tenant_id || bundle.workspace_id).toLowerCase()
    let dsk, mismatch = false
    try {
      const nsBytes = bytes.parseUUID(namespace)
      const row = await seal.grantRow(nsBytes, bytes.parseUUID(device), service, grant.epoch)
      dsk = await seal.openDirect(privateKey, seal.Kind.DeviceGrant, nsBytes, row, bytes.fromBase64(grant.sealed_dsk))
      if (dsk.length !== 32) throw failed()
      const expected = Buffer.from(configTag(dsk, fields, { device, namespace, epoch: grant.epoch, request, kid }))
      const given = Buffer.from(typeof bundle.cfg_tags[device] === 'string' ? bundle.cfg_tags[device] : '')
      mismatch = expected.length !== given.length || !timingSafeEqual(expected, given)
    } catch { throw failed() } finally { dsk?.fill(0) }
    if (mismatch) throw Object.assign(new LinkError('invalid_bundle'), { tagMismatch: true })
    epochs[device] = grant.epoch
    ns[device] = namespace
  }
  return { epochs, ns }
}

/**
 * One provider's model list, every page (§18.9), within one
 * AI_MODELS_TIMEOUT_MS: `{state: 'ok', ids}`, `{state: 'rejected'}` (the
 * error map says `ai_key_rejected`) or `{state: 'failed'}` (anything else,
 * a list with more than AI_MODELS_PAGES_MAX pages included).
 */
export async function listModels(egress, provider, key) {
  const module = PROVIDERS[provider]
  const deadline = AbortSignal.timeout(AI_MODELS_TIMEOUT_MS)
  const ids = new Set()
  let cursor = null
  for (let page = 0; page < AI_MODELS_PAGES_MAX; page++) {
    let response
    try { response = await egress.request(provider, key, { ...module.modelsPage(cursor), signal: deadline, timeoutMs: AI_MODELS_TIMEOUT_MS }) } catch { return { state: 'failed' } }
    if (response.status !== 200) return { state: classify(provider, 'models', response.status, errorFacts(provider, response.json)) === 'ai_key_rejected' ? 'rejected' : 'failed' }
    const read = module.readModels(response.json)
    if (!read) return { state: 'failed' }
    for (const id of read.ids) ids.add(id)
    if (!read.next) return { state: 'ok', ids }
    cursor = read.next
  }
  return { state: 'failed' }
}

/**
 * Step 6.5: every key's list, in parallel. A key the provider rejects is
 * 400 `ai_key_rejected`; a function whose model is on no page of its
 * provider's list, 400 `ai_model_unavailable`; any other failure, 502
 * `ai_provider_failed`. Only the verdict is kept, never the list.
 */
export async function checkKeys(egress, bundle, keys) {
  const providers = Object.keys(bundle.keys)
  const lists = Object.fromEntries(await Promise.all(providers.map(async provider => [provider, await listModels(egress, provider, keys[provider])])))
  if (providers.some(provider => lists[provider].state === 'rejected')) throw new LinkError('ai_key_rejected')
  for (const entry of Object.values(bundle.functions)) {
    const list = lists[entry.provider]
    if (list.state === 'ok' && !list.ids.has(entry.model)) throw new LinkError('ai_model_unavailable')
  }
  if (providers.some(provider => lists[provider].state !== 'ok')) throw new LinkError('ai_provider_failed', 502)
}
