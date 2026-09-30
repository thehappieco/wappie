// Anthropic's Messages API (docs/mcp-enclave.md §18.9): images and
// documents only, since the API takes no audio or video (§18.3). The body
// is pinned byte for byte in ../test/provider-shapes.json, from the bodies
// B0 sent and Anthropic accepted (§18.19).
import { AI_OUTPUT_MAX_TOKENS, systemPrompt, userText } from '../policy.mjs'

export const NAME = 'anthropic'

/** One page of the model list: `GET /v1/models?limit=1000[&after_id=<id>]`. */
export const modelsPage = cursor => ({ method: 'GET', path: '/v1/models', query: [['limit', '1000'], ...(cursor ? [['after_id', cursor]] : [])] })

/** A page's ids and the next page's cursor (`last_id` while `has_more`), or null for an answer of another shape. */
export function readModels(json) {
  if (!json || !Array.isArray(json.data)) return null
  const ids = json.data.map(model => model?.id).filter(id => typeof id === 'string')
  const next = json.has_more === true ? json.last_id : null
  if (json.has_more === true && (typeof next !== 'string' || !next)) return null
  return { ids, next }
}

/**
 * `POST /v1/messages` for `image` or `document`: the system prompt, then one
 * user turn of up to 4 images (`{mimeType, data}`) and the text part.
 */
export function build(feature, { model, lang, images = [], documentText }) {
  return {
    method: 'POST', path: '/v1/messages',
    body: {
      model,
      max_tokens: AI_OUTPUT_MAX_TOKENS[feature],
      system: systemPrompt(feature, lang),
      messages: [{
        role: 'user',
        content: [
          ...images.map(image => ({ type: 'image', source: { type: 'base64', media_type: image.mimeType, data: Buffer.from(image.data).toString('base64') } })),
          { type: 'text', text: userText(feature, documentText) },
        ],
      }],
    },
  }
}

/**
 * A 200 answer: the `text` blocks joined, the stop (`refusal`, `max_tokens`
 * or null), and the usage (§18.10: `input_tokens`, `output_tokens`, the
 * thinking included).
 */
export function answer(json) {
  const blocks = Array.isArray(json?.content) ? json.content : []
  const text = blocks.filter(block => block?.type === 'text' && typeof block.text === 'string').map(block => block.text).join('')
  const stop = json?.stop_reason === 'refusal' ? 'refusal' : json?.stop_reason === 'max_tokens' ? 'max_tokens' : null
  const usage = {}
  if (Number.isSafeInteger(json?.usage?.input_tokens) && json.usage.input_tokens >= 0) usage.input_tokens = json.usage.input_tokens
  if (Number.isSafeInteger(json?.usage?.output_tokens) && json.usage.output_tokens >= 0) usage.output_tokens = json.usage.output_tokens
  return { text, stop, usage }
}
