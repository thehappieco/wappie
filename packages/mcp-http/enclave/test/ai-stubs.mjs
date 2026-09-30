// Local stubs of the three AI providers, for the enclave's tests: the
// `transport` the egress is given in place of the global fetch (the URL it
// is handed is always the real host's: the stub answers for it, and nothing
// leaves the process). Every call is recorded with its method, path, query,
// headers and body, and which key it carried, so a test can say what reached
// which provider. No real provider, key or model is involved.

const HOSTS = { 'api.anthropic.com': 'anthropic', 'api.openai.com': 'openai', 'generativelanguage.googleapis.com': 'google' }
const json = (value, status = 200, headers = {}) => new Response(value === undefined ? null : typeof value === 'string' ? value : JSON.stringify(value), { status, headers: { 'content-type': 'application/json', ...headers } })

/** A key a stub accepts: fixture material, one per provider, belonging to nothing. */
export const STUB_KEYS = Object.freeze({
  anthropic: 'wappie-test-key-anthropic-bbbbbbbbbbbbbbbb',
  openai: 'wappie-test-key-openai-cccccccccccccccc',
  google: 'wappie-test-key-google-aaaaaaaaaaaaaaaa',
})

/** The key a request carried, by the header its provider uses. */
function keyOf(headers) {
  if (headers['x-api-key']) return headers['x-api-key']
  if (headers['x-goog-api-key']) return headers['x-goog-api-key']
  if (headers.authorization?.startsWith('Bearer ')) return headers.authorization.slice(7)
  return null
}

/**
 * `stubs.models[provider]` are the model ids each key's list holds, served
 * in pages of `stubs.pageSize` (Anthropic and Google page; OpenAI does not);
 * `stubs.answer(call)` answers a generation call with `{status, body, delayMs,
 * headers}` (the default is a 200 transcript in each provider's shape);
 * `stubs.keys[provider]` is the key each accepts (else 401 as B0's bodies).
 */
export function createProviderStubs() {
  const stubs = {
    calls: [], pageSize: 1000, keys: { ...STUB_KEYS },
    models: { anthropic: ['claude-synthetic-5'], openai: ['gpt-synthetic-mini', 'gpt-synthetic-transcribe', 'whisper-synthetic'], google: ['gemini-synthetic-flash'] },
    answer: null,
    text: 'Oi, aqui é uma nota de voz sintética. A reunião ficou para quinta-feira às 15:30.',
    usage: { anthropic: { input_tokens: 100, output_tokens: 50 }, openai: { type: 'tokens', input_tokens: 144, output_tokens: 52 }, google: { promptTokenCount: 424, candidatesTokenCount: 56, thoughtsTokenCount: 685, promptTokensDetails: [{ modality: 'TEXT', tokenCount: 62 }, { modality: 'AUDIO', tokenCount: 362 }] } },
    /** Every call that carried a key: the health route's reach probes carry none. */
    keyed() { return stubs.calls.filter(call => call.key !== null) },
    /** Calls of `provider` to a generation route (never the model lists). */
    generations(provider) { return stubs.calls.filter(call => (!provider || call.provider === provider) && call.route !== 'models') },
  }
  /** A 200 answer in each provider's shape, from `stubs.text` and `stubs.usage`. */
  stubs.ok = (provider, route, text = stubs.text) => {
    if (provider === 'anthropic') return { status: 200, body: { model: 'claude-synthetic-5', id: 'msg_synthetic', type: 'message', role: 'assistant', content: [{ type: 'text', text }], stop_reason: 'end_turn', usage: stubs.usage.anthropic } }
    if (provider === 'openai' && route === 'transcriptions') return { status: 200, body: { text, usage: stubs.usage.openai } }
    if (provider === 'openai') return { status: 200, body: { id: 'resp_synthetic', object: 'response', status: 'completed', output: [{ type: 'message', content: [{ type: 'output_text', text }] }], store: false, usage: { input_tokens: 400, output_tokens: 80 } } }
    return { status: 200, body: { candidates: [{ content: { parts: [{ text }], role: 'model' }, finishReason: 'STOP', index: 0 }], usageMetadata: stubs.usage.google, modelVersion: 'gemini-synthetic-flash' } }
  }
  function modelsPage(provider, url) {
    const ids = stubs.models[provider]
    if (provider === 'openai') return { status: 200, body: { object: 'list', data: ids.map(id => ({ id, object: 'model', created: 1790000000, owned_by: 'system' })) } }
    const cursor = url.searchParams.get(provider === 'anthropic' ? 'after_id' : 'pageToken')
    const from = cursor ? Number(cursor.replace(/^\D+/, '')) : 0
    const page = ids.slice(from, from + stubs.pageSize)
    const next = from + stubs.pageSize < ids.length ? from + stubs.pageSize : null
    if (provider === 'anthropic') return { status: 200, body: { data: page.map(id => ({ type: 'model', id, display_name: id, created_at: '2026-01-01T00:00:00Z' })), has_more: next !== null, first_id: page[0] ?? null, last_id: next !== null ? `cursor${next}` : page.at(-1) ?? null } }
    return { status: 200, body: { models: page.map(id => ({ name: `models/${id}`, supportedGenerationMethods: ['generateContent', 'countTokens'] })), ...(next !== null ? { nextPageToken: `token${next}` } : {}) } }
  }
  const rejected = provider => (provider === 'anthropic' ? { status: 401, body: { type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' }, request_id: 'req_synthetic' } }
    : provider === 'openai' ? { status: 401, body: { error: { message: 'Incorrect API key provided.', type: 'invalid_request_error', param: null, code: 'invalid_api_key' } } }
      : { status: 400, body: { error: { code: 400, message: 'API key not valid. Please pass a valid API key.', status: 'INVALID_ARGUMENT', details: [{ '@type': 'type.googleapis.com/google.rpc.ErrorInfo', reason: 'API_KEY_INVALID', domain: 'googleapis.com' }] } } })
  stubs.transport = async (input, init = {}) => {
    const url = new URL(String(input))
    const provider = HOSTS[url.host] ?? null
    const headers = Object.fromEntries(Object.entries(init.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]))
    let body = null
    if (init.body instanceof FormData) body = Object.fromEntries([...init.body].map(([name, value]) => [name, typeof value === 'string' ? value : { size: value.size, type: value.type, name: value.name }]))
    else if (init.body) { try { body = JSON.parse(Buffer.from(init.body).toString('utf8')) } catch { body = String(init.body) } }
    const route = !provider ? null : url.pathname.endsWith('/models') ? 'models' : url.pathname.endsWith(':generateContent') ? 'generate' : url.pathname.endsWith('/messages') ? 'messages' : url.pathname.endsWith('/responses') ? 'responses' : url.pathname.endsWith('/transcriptions') ? 'transcriptions' : 'other'
    const call = { provider, route, url: url.href, method: init.method, path: url.pathname, search: url.search, headers, body, key: keyOf(headers), redirect: init.redirect }
    stubs.calls.push(call)
    if (!provider) throw new TypeError('fetch failed')
    if (call.key === null && route === 'models') return json({ error: 'no key' }, 401)
    if (call.key !== stubs.keys[provider]) { const answer = rejected(provider); return json(answer.body, answer.status) }
    const answer = route === 'models' ? (stubs.modelsAnswer?.(call) ?? modelsPage(provider, url)) : (stubs.answer?.(call) ?? stubs.ok(provider, route))
    if (answer.delayMs || answer.until) {
      await new Promise((resolve, reject) => {
        const timer = answer.delayMs ? setTimeout(resolve, answer.delayMs) : null
        answer.until?.then(resolve)
        init.signal?.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('aborted', 'AbortError')) }, { once: true })
      })
    }
    if (answer.network) throw new TypeError('fetch failed')
    return json(answer.body, answer.status, answer.headers)
  }
  return stubs
}
