// AI integrations in the attested reader (docs/mcp-enclave.md §18): the one
// object content.mjs builds, which installs and renews AI authorizations,
// holds their provider keys (`aikeys`, in memory beside `connkeys`, wiped
// with it), their pauses and their budgets, runs their jobs, and gives media
// connections what open_attachment needs to answer with a transcript
// (§18.12).
//
// An `ai` record never has a token family and never serves /mcp: no
// assistant speaks for it. Its status follows §15.8's rules, with `aikeys`
// wiped wherever `connkeys` is; an AI job opens content through a reader
// built for the record alone (I2).
import { canonicalJSON } from '@whatserver2/client/crypto/jcs'
import { keysSHA256 } from '@whatserver2/mcp/bundle'
import { createReader, derivedBytes, openDerived } from '@whatserver2/mcp/reader'
import { RelayError } from '../../internal.mjs'
import { connectionTaken, LinkError } from '../../link.mjs'
import { fingerprint } from '../../log.mjs'
import { contentConfigFor, contentProviderFor } from '../provider.mjs'
import { contentDeadline } from '../renew.mjs'
import { createBudgets } from './budget.mjs'
import { createEgress, providerKey } from './egress.mjs'
import { AI_CONNECT_INFO, AI_RENEW_INFO, aiConnectAAD, aiRenewAAD, checkKeys, openAIBundle, parseAIRelay, proveAIGrants } from './install.mjs'
import { aiRefusal, createQueue, functionOf, jobCode, runJob } from './jobs.mjs'
import { AI_ERROR_EFFECTS, AI_FUNCTIONS } from './policy.mjs'
import { createAIRequests } from './requests.mjs'

const uuidShape = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const sameSet = (a, b) => a.length === b.length && a.every(item => b.includes(item))
/** An error a job's caller may see, and the log may carry. */
const codeOf = jobCode

/**
 * `state`, `relay` (the signed relay, with `ai(...)`), `connkeys` and
 * `newRecipient` are content.mjs's; `attestor` attests AI requests;
 * `transport` replaces the global fetch for the providers (tests only);
 * `fetch` reaches the archive; `media()` returns the media service (its
 * slot and jail, for images and documents).
 */
export function createAIService({ state, relay, log, now = Date.now, archive, consoleURL, resource, attestor, readerVersion, pendingTTLMs, newRecipient, connkeys, fetch, transport, media }) {
  const origin = new URL(resource).origin
  const egress = createEgress({ ...(transport ? { transport } : {}), log })
  const requests = createAIRequests({ now, ttlMs: pendingTTLMs, newRecipient, attestor, resource, readerVersion })
  const budgets = createBudgets({ now })
  const queue = createQueue({ now })
  const aikeys = new Map()
  // id -> { providers: Map(provider -> code), functions: Map(feature -> code) }: paused by the error map until a renewal.
  const pauses = new Map()
  // id -> the last `serve` status of the record ({ai_off, media_off}).
  const statuses = new Map()
  let statusCheck = null
  // provider -> whether its host answered the last reach probe over verified TLS (null before the first).
  const reached = { anthropic: null, openai: null, google: null }
  const conn = id => ({ conn: fingerprint(id) })

  /** The provider keys of a bundle, each bound to its provider. */
  const keyring = keys => Object.freeze(Object.fromEntries(Object.entries(keys).map(([provider, secret]) => [provider, providerKey(provider, secret)])))
  const pausesOf = id => { let entry = pauses.get(id); if (!entry) pauses.set(id, entry = { providers: new Map(), functions: new Map() }); return entry }

  /** A reader for an `ai` record, never an MCP server: every open uses the record's own grants (I2). */
  const readerFor = record => createReader(contentConfigFor(record, archive), contentProviderFor(record, connkeys, consoleURL))

  /** Go's usage for the month, best effort: the budget keeps the larger of it and its own. */
  async function readUsage(record) {
    try {
      const answer = await relay.ai(record.connection_id, record.api_key, 'GET', 'ai/usage', { query: { month: new Date(now()).toISOString().slice(0, 7) } })
      if (answer.status === 200) budgets.fromGo(record.connection_id, answer.data)
    } catch { /* the enclave's own count stands */ }
  }
  /** Counts one call, reuse or failure at Go (§18.11), best effort. */
  function usage(record, job, counts) {
    const entry = record.functions[job.feature]
    const body = { device_id: job.device_id, feature: job.feature, provider: entry.provider, model: entry.model, origin: job.origin, requester_id: job.requester_id,
      items: 0, reused: 0, failures: 0, input_tokens: 0, output_tokens: 0, seconds: 0, cost_microcents: 0, ...counts }
    void relay.ai(record.connection_id, record.api_key, 'POST', 'ai/usage', { body }).catch(() => {})
  }
  /** The error map's effect (§18.9): the provider or the function pauses until a renewal, Go is told for the console, the log says which code. */
  function pause(record, code, { provider, feature }, except) {
    const id = record.connection_id
    const effect = AI_ERROR_EFFECTS[code]
    if (!effect) return
    const entry = pausesOf(id)
    if (effect === 'provider') entry.providers.set(provider, code)
    else entry.functions.set(feature, code)
    log.event('ai_paused', { ...conn(id), code })
    void relay.ai(id, record.api_key, 'POST', 'ai/alerts', { body: effect === 'provider' ? { code, provider } : { code, feature } }).catch(() => {})
    queue.abortWhere(id, job => job !== except && (effect === 'provider' ? record.functions[job.feature]?.provider === provider : job.feature === feature), aiRefusal('ai_paused'))
  }
  /**
   * What Go stores of `feature` for (`device`, `uid`): `{read, record}`,
   * where `read` says Go answered the list and `record` is the first stored
   * record `keys` (the record's grant's DSK) opens, or null. A record of
   * another epoch is skipped: no key this grant holds opens it.
   */
  async function storedOf(record, device, uid, feature, keys) {
    let answer
    try { answer = await relay.ai(record.connection_id, record.api_key, 'GET', 'ai/derived', { query: { device_id: device, uid } }) } catch { return { read: false, record: null } }
    if (answer.status !== 200 || !Array.isArray(answer.data?.items)) return { read: false, record: null }
    for (const item of answer.data.items) {
      const sealed = derivedBytes(item?.sealed)
      if (!sealed || item.feature !== feature || item.device_id !== device || item.message_uid !== uid || item.epoch !== keys.epoch) continue
      try { return { read: true, record: openDerived(keys.dsk, { namespace: keys.namespace, device_id: device, message_uid: uid, feature, epoch: item.epoch }, sealed) } } catch { /* another key's */ } finally { sealed.fill(0) }
    }
    return { read: true, record: null }
  }
  /** The stored record of `feature` for (`device`, `uid`) that `keys` opens, or null. */
  const readStored = async (...args) => (await storedOf(...args)).record

  /**
   * Step 1 and 2 (§18.10): the record is held with keys and serves; its
   * status's `ai_off` covers neither the function nor its provider and is
   * not paused, nor has the error map paused either; the number has the
   * function; the origin is allowed; the budget has room.
   */
  async function gate(record, { device_id, feature, origin }) {
    const id = record.connection_id
    if (!connkeys.has(id) || !aikeys.has(id)) throw aiRefusal('ai_paused')
    const entry = record.functions[feature]
    const wanted = record.features[device_id]?.[feature]
    if (!entry || !wanted) throw aiRefusal('ai_not_enabled')
    const status = statusCheck ? await statusCheck.aiStatus(id) : { answer: false }
    if (status.answer !== 'serve') throw aiRefusal('ai_paused')
    statuses.set(id, status)
    const off = status.ai_off ?? { functions: [], providers: [], paused: false }
    const paused = pauses.get(id)
    if (off.paused || off.functions.includes(feature) || off.providers.includes(entry.provider) || paused?.providers.has(entry.provider) || paused?.functions.has(feature) ||
      (wanted.requesters === 'console' && origin !== 'console')) throw aiRefusal('ai_paused')
    const limit = budgets.limit(record, status)
    if (limit) { log.event('ai_budget_reached', conn(id)); throw aiRefusal('ai_budget_reached', { limit }) }
    return status
  }

  /** A job's work once it is picked: the gate again, then runJob. */
  async function execute(job) {
    const record = state.connections.get(job.authorization_id)
    const id = job.authorization_id
    try {
      if (!record || record.kind !== 'ai') throw aiRefusal('ai_paused')
      await gate(record, job)
      const reader = await readerFor(record)
      const outcome = await runJob({
        log, now, relay, egress, budgets, reader, archive, fetch, media: media(),
        keys: item => aikeys.get(item.connection_id), status: item => statuses.get(item.connection_id),
        pause: (item, code, where) => pause(item, code, where, job), usage, readStored, storedOf,
      }, record, job)
      log.event('ai_job_done', conn(id))
      return outcome
    } catch (error) {
      const code = codeOf(error)
      log.event('ai_job_failed', { ...conn(id), code })
      throw error?.code === code ? error : aiRefusal(code)
    }
  }
  /** Queues a job (or joins the one in flight for the same key). */
  function submit(record, spec) {
    return queue.submit({ ...spec, key: `${record.connection_id}|${spec.device_id}|${spec.uid}|${spec.feature}`, authorization_id: record.connection_id }, execute)
  }

  /** Everything of a record's AI: its keys, jobs, pauses and, when it ended, its budget. */
  function wipe(id, reason = 'revoked') {
    aikeys.delete(id)
    pauses.delete(id)
    statuses.delete(id)
    queue.abort(id, aiRefusal('ai_paused'))
    if (reason === 'revoked') budgets.forget(id)
  }

  // ---- Renewal (§18.7 step 7), through renew.mjs --------------------------------
  const renewalHooks = {
    /** The descriptor's AI fields: not attested; a wrong value only fails the renewal. */
    describe: record => ({ kind: 'ai', consent_version: 1, media: false, functions: record.functions, features: record.features, budget: record.budget }),
    /**
     * Opens and checks a renewal's AI bundle (§18.7 step 7): the same
     * workspace, numbers, features, monthly cap, daily items and each
     * function's provider; a key may rotate within its provider and a model
     * change within it (the rates following); fresh tags and the models
     * checked again. Resolves to the stage renew.mjs commits.
     */
    async accept({ record, renewal, body, renewalID, connectionID }) {
      const relayed = parseAIRelay(body, { now })
      if (relayed.connection_id !== connectionID || relayed.tenant_id !== record.tenant_id) throw new LinkError('bad_request')
      if (relayed.kid !== renewal.recipient.kid) throw new LinkError('unknown_kid')
      const bundle = await openAIBundle(renewal.recipient, relayed.sealed, {
        info: AI_RENEW_INFO, aad: aiRenewAAD(renewalID, connectionID, relayed.kid, resource), purpose: 'renewal', origin, tenant: relayed.tenant_id, connectionID, now,
      })
      const functions = Object.keys(bundle.functions)
      if (bundle.service_user_id === record.service_user_id || bundle.workspace_id !== record.workspace_id || !sameSet(bundle.device_ids, record.device_ids) ||
        canonicalJSON(bundle.features) !== canonicalJSON(record.features) || bundle.budget.monthly_usd_cents !== record.budget.monthly_usd_cents ||
        bundle.budget.request_items_per_day !== record.budget.request_items_per_day || !sameSet(functions, Object.keys(record.functions)) ||
        functions.some(name => bundle.functions[name].provider !== record.functions[name].provider) ||
        Math.min(Date.parse(bundle.expires_at), relayed.expiry) !== Date.parse(contentDeadline(record))) throw new LinkError('invalid_bundle')
      let proven
      try { proven = await proveAIGrants(renewal.recipient.privateKey, bundle, { archive, fetch, request: renewalID, kid: relayed.kid }) } catch (error) {
        log.event(error?.tagMismatch ? 'ai_tag_mismatch' : 'grant_proof_failed', conn(connectionID))
        throw error
      }
      const keys = keyring(bundle.keys)
      await checkKeys(egress, bundle, keys)
      return {
        key: renewal.recipient.privateKey, api_key: bundle.token, service_user_id: bundle.service_user_id, epochs: proven.epochs, expires_at: contentDeadline(record),
        ai: { keys, ns: proven.ns, request: renewalID, kid: relayed.kid, keys_sha256: keysSHA256(bundle.keys), functions: bundle.functions, budget: bundle.budget,
          cfg_tags: bundle.cfg_tags, bundle_expires_at: bundle.expires_at },
      }
    },
    /** At commit: the new keys, and what the renewed bundle changed; the error map's pauses end. */
    apply(record, stage) {
      const { keys, ...fields } = stage
      aikeys.set(record.connection_id, keys)
      Object.assign(record, structuredClone(fields))
      pauses.delete(record.connection_id)
      void readUsage(record)
    },
  }

  return {
    renewalHooks,
    useStatusCheck(check) { statusCheck = check },
    /** Whether this process holds the record's keys (connection key and provider keys). */
    holds: id => connkeys.has(id) && aikeys.has(id),
    wipe,

    /** POST /internal/ai/requests: a fresh attested AI request (§18.7 step 1). */
    request(nonce) {
      if (!nonce) throw new LinkError('bad_request')
      return requests.create(nonce)
    },

    /**
     * POST /internal/ai/requests/{id}/bundle (§18.7 steps 5 and 6): 204 only
     * once the grants and tags are proven, the keys and models checked and
     * the row activated; nothing is kept before.
     */
    async acceptBundle(requestID, body) {
      const request = requests.get(requestID)
      if (!request) throw new LinkError('not_found', 404)
      const relayed = parseAIRelay(body, { now })
      if (request.accepting || request.connection_id) throw new LinkError('bundle_exists', 409)
      if (connectionTaken(state, null, relayed.connection_id) || requests.names(relayed.connection_id, request)) throw new LinkError('bad_request')
      if (relayed.kid !== request.recipient.kid) throw new LinkError('unknown_kid')
      const id = relayed.connection_id
      // Reserved from here to the install (or its failure): no other consent or AI request may name it meanwhile.
      state.activating ??= new Set()
      state.activating.add(id)
      request.accepting = id
      try {
        const bundle = await openAIBundle(request.recipient, relayed.sealed, {
          info: AI_CONNECT_INFO, aad: aiConnectAAD(request.id, relayed.kid, request.resource), purpose: 'consent', origin, tenant: relayed.tenant_id, now,
        })
        const expiry = Math.min(Date.parse(bundle.expires_at), relayed.expiry)
        let proven
        try { proven = await proveAIGrants(request.recipient.privateKey, bundle, { archive, fetch, request: request.id, kid: relayed.kid }) } catch (error) {
          if (error?.tagMismatch) log.event('ai_tag_mismatch', conn(id))
          throw error
        }
        const keys = keyring(bundle.keys)
        await checkKeys(egress, bundle, keys)
        // Step 6 and 7: activation, then the keys and the record kept.
        try { await relay.activate(id) } catch (error) {
          if (error instanceof RelayError) throw new LinkError('relay_failed', 502)
          throw error
        }
        const expires = new Date(expiry).toISOString()
        const record = {
          kind: 'ai', connection_id: id, tenant_id: relayed.tenant_id, workspace_id: bundle.workspace_id, service_user_id: bundle.service_user_id,
          key_mode: bundle.key_mode, consent_version: 1, api_key: bundle.token, device_ids: [...bundle.device_ids], epochs: proven.epochs, ns: proven.ns,
          request: request.id, kid: relayed.kid, keys_sha256: keysSHA256(bundle.keys), functions: structuredClone(bundle.functions),
          features: structuredClone(bundle.features), budget: structuredClone(bundle.budget), cfg_tags: { ...bundle.cfg_tags },
          ...(bundle.timezone ? { timezone: bundle.timezone } : {}), bundle_expires_at: bundle.expires_at, expires_at: expires, consented_expires_at: expires,
          redirect_host: 'console', created_at: now(),
        }
        connkeys.set(id, request.recipient.privateKey)
        aikeys.set(id, keys)
        state.connections.set(id, record)
        requests.delete(request.id)
        request.connection_id = id
        await state.save().catch(() => {})
        await readUsage(record)
        log.event('ai_installed', conn(id))
      } catch (error) {
        log.event('ai_install_failed', { ...conn(id), code: error instanceof LinkError ? error.code : 'install_failed' })
        throw error
      } finally { state.activating.delete(id); delete request.accepting }
    },

    /**
     * The status rules for an `ai` record that serves (content.mjs decides
     * the rest): what Go's `ai_off` now switches off aborts the jobs it
     * covers, and Go's usage is read for the budget.
     */
    narrow(record, status) {
      const id = record.connection_id
      const off = status.ai_off ?? { functions: [], providers: [], paused: false }
      if (off.paused) queue.abort(id, aiRefusal('ai_paused'))
      else queue.abortWhere(id, job => off.functions.includes(job.feature) || off.providers.includes(record.functions[job.feature]?.provider), aiRefusal('ai_paused'))
      void readUsage(record)
    },

    /**
     * POST /internal/ai/jobs (§18.11): a console job. `{status: 200, body:
     * {stored: true}}` when a record is stored and this is no redo, else
     * `{status: 202, body: {job}}`; LinkError otherwise.
     */
    async submit(body) {
      const names = body && typeof body === 'object' && !Array.isArray(body) ? Object.keys(body) : []
      const fields = ['authorization_id', 'device_id', 'uid', 'feature', 'origin', 'requester_id', 'redo']
      if (names.length !== fields.length || !fields.every(name => names.includes(name)) || !['authorization_id', 'device_id', 'uid', 'requester_id'].every(name => uuidShape.test(body[name] ?? '')) ||
        !AI_FUNCTIONS.includes(body.feature) || body.origin !== 'console' || typeof body.redo !== 'boolean') throw new LinkError('bad_request')
      const record = state.connections.get(body.authorization_id)
      if (!record || record.kind !== 'ai') throw new LinkError('not_found', 404)
      try { await gate(record, body) } catch (error) { throw Object.assign(new LinkError(codeOf(error), 409), error?.limit ? { limit: error.limit } : {}) }
      if (!body.redo) {
        let answer = null
        try { answer = await relay.ai(record.connection_id, record.api_key, 'GET', 'ai/derived', { query: { device_id: body.device_id, uid: body.uid } }) } catch { /* no stored answer known */ }
        if (answer?.status === 200 && Array.isArray(answer.data?.items) && answer.data.items.some(item => item?.feature === body.feature && item?.message_uid === body.uid)) return { status: 200, body: { stored: true } }
      }
      let job
      try { job = submit(record, { device_id: body.device_id, uid: body.uid, feature: body.feature, origin: 'console', requester_id: body.requester_id, redo: body.redo }) } catch (error) {
        throw Object.assign(new LinkError('ai_busy', 429), { retry_after_s: error?.retry_after_s ?? 20 })
      }
      return { status: 202, body: { job: job.id } }
    },

    /** GET /internal/ai/jobs/{job}?requester_id= (§18.11): `{state, code?}` for one of the job's requesters, else null. */
    jobState(id, requester) {
      const job = queue.get(id)
      if (!job || !job.requesters.has(requester)) return null
      if (job.state === 'done' && job.outcome?.unstored) return { state: 'failed', code: job.outcome.unstored }
      if (job.state === 'failed') return { state: 'failed', code: codeOf(job.outcome.error), ...(job.outcome.error?.limit ? { limit: job.outcome.error.limit } : {}) }
      return { state: job.state }
    },

    /**
     * What a media connection's open_attachment asks (§18.12), bound to the
     * connection's record: the stored record its own grant opens, the
     * authorization Go picks for it, an interactive job on that
     * authorization, and the functions stored for get_message.
     */
    connectorFor(connection) {
      const id = connection.connection_id
      const items = async (device, uid) => {
        const answer = await relay.ai(id, connection.api_key, 'GET', 'ai/derived', { query: { device_id: device, uid } })
        return answer.status === 200 && Array.isArray(answer.data?.items) ? answer.data.items : []
      }
      return {
        /** Step 1: the first stored record of `feature` this connection's own grant opens (`access.derived`), or null. */
        async stored(row, feature, access) {
          let found
          try { found = (await items(row.device_id, row.uid)).filter(item => item?.feature === feature) } catch { return null }
          return found.length ? access.derived(row, found) : null
        },
        /** Step 2: Go's pick for this connection's creator, `{authorization_id, requester_id, state}`, or null (404). */
        async pick(device, feature) {
          let answer
          try { answer = await relay.ai(id, connection.api_key, 'GET', 'ai', { query: { device_id: device, feature } }) } catch { throw aiRefusal('read_failed') }
          if (answer.status === 404) return null
          const data = answer.data
          if (answer.status !== 200 || !uuidShape.test(data?.authorization_id ?? '') || !uuidShape.test(data?.requester_id ?? '') || !['active', 'reseal'].includes(data?.state)) throw aiRefusal('read_failed')
          return { authorization_id: data.authorization_id, requester_id: data.requester_id, state: data.state }
        },
        /** An interactive job on the picked authorization: the job (its `settled` resolves to its outcome), or the gate's refusal. */
        async run(pick, { device_id, uid, feature }) {
          const record = state.connections.get(pick.authorization_id)
          if (!record || record.kind !== 'ai' || record.tenant_id !== connection.tenant_id) throw aiRefusal('ai_paused')
          await gate(record, { device_id, feature, origin: 'connector' })
          return submit(record, { device_id, uid, feature, origin: 'connector', requester_id: pick.requester_id, redo: false })
        },
        retryOf: job => queue.retryOf(job),
        /** get_message's `derived` (§18.12): the audio or video function whose record is stored for this row, from one read. */
        async derivedOf(row) {
          const feature = functionOf(row)
          if (feature !== 'audio' && feature !== 'video') return []
          const found = await items(row.device_id, row.uid)
          return found.some(item => item?.feature === feature && item?.message_uid === row.uid) ? [feature] : []
        },
      }
    },

    /** Records, records holding keys, jobs and failures since the last call, queued and running now (the health line, §18.15). */
    counts() {
      let records = 0
      for (const record of state.connections.values()) if (record.kind === 'ai') records++
      const jobs = queue.counts()
      return { ai_records: records, ai_keys: aikeys.size, ai_jobs: jobs.jobs, ai_failed: jobs.failed, ai_queue: jobs.queue, ai_in_flight: jobs.in_flight }
    },
    sweep() { requests.sweep() },
    /** Probes each provider's host (§18.16: the egress proven before any switch is on); `reach()` answers the last results. */
    async probe() { await Promise.all(Object.keys(reached).map(async provider => { reached[provider] = await egress.reach(provider) })) },
    reach: () => ({ ...reached }),
    close() { queue.clear(); aikeys.clear(); pauses.clear(); budgets.clear(); requests.clear() },
    /** For tests. */
    get egress() { return egress },
    get aikeys() { return aikeys },
    get budgets() { return budgets },
  }
}
