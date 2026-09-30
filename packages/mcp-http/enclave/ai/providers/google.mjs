// Google's Gemini API (docs/mcp-enclave.md §18.9): every function through
// `generateContent`, the media inline (never Files or cachedContents), the
// key in `x-goog-api-key`, never in the URL. The body is pinned in
// ../test/provider-shapes.json from those B0 sent (§18.19).
import { AI_GOOGLE_AUDIO_TOKENS_PER_SECOND, AI_OUTPUT_MAX_TOKENS, GOOGLE_SAFETY_STOPS, systemPrompt, userText } from '../policy.mjs'

export const NAME = 'google'

/** One page of the model list: `GET /v1beta/models?pageSize=1000[&pageToken=<token>]`. */
export const modelsPage = cursor => ({ method: 'GET', path: '/v1beta/models', query: [['pageSize', '1000'], ...(cursor ? [['pageToken', cursor]] : [])] })

/**
 * A page's ids (`models/<id>` taken as `<id>`, only those whose
 * `supportedGenerationMethods` hold `generateContent`) and `nextPageToken`,
 * or null for an answer of another shape.
 */
export function readModels(json) {
  if (!json || (json.models !== undefined && !Array.isArray(json.models))) return null
  const ids = (json.models ?? [])
    .filter(model => typeof model?.name === 'string' && model.name.startsWith('models/') && Array.isArray(model.supportedGenerationMethods) && model.supportedGenerationMethods.includes('generateContent'))
    .map(model => model.name.slice('models/'.length))
  const next = typeof json.nextPageToken === 'string' && json.nextPageToken ? json.nextPageToken : null
  return { ids, next }
}

/**
 * `POST /v1beta/models/{model}:generateContent` for any function: the
 * system instruction, one user turn of the inline media (the audio, the
 * video or the images, `{mimeType, data}`) and the text part, and the output
 * limit.
 */
export function build(feature, { model, lang, media = [], documentText }) {
  return {
    method: 'POST', path: `/v1beta/models/${model}:generateContent`,
    body: {
      systemInstruction: { parts: [{ text: systemPrompt(feature, lang) }] },
      contents: [{ role: 'user', parts: [...media.map(item => ({ inlineData: { mimeType: item.mimeType, data: Buffer.from(item.data).toString('base64') } })), { text: userText(feature, documentText) }] }],
      generationConfig: { maxOutputTokens: AI_OUTPUT_MAX_TOKENS[feature] },
    },
  }
}

const count = value => (Number.isSafeInteger(value) && value >= 0 ? value : undefined)

/**
 * A 200 answer: the first candidate's text parts that are not thoughts,
 * joined; a safety stop (a finish reason of GOOGLE_SAFETY_STOPS, or any
 * `promptFeedback.blockReason`), the output limit (`MAX_TOKENS`), or any
 * other finish reason but `STOP` (`failed`). Usage: `promptTokenCount` in,
 * `candidatesTokenCount` and `thoughtsTokenCount` out, and the seconds its
 * AUDIO tokens measure (AI_GOOGLE_AUDIO_TOKENS_PER_SECOND).
 */
export function answer(json) {
  const candidate = Array.isArray(json?.candidates) ? json.candidates[0] : undefined
  const parts = Array.isArray(candidate?.content?.parts) ? candidate.content.parts : []
  const text = parts.filter(part => typeof part?.text === 'string' && part.thought !== true).map(part => part.text).join('')
  const finish = typeof candidate?.finishReason === 'string' ? candidate.finishReason : null
  const blocked = typeof json?.promptFeedback?.blockReason === 'string' && json.promptFeedback.blockReason !== ''
  const stop = blocked || GOOGLE_SAFETY_STOPS.includes(finish) ? 'refusal' : finish === 'MAX_TOKENS' ? 'max_tokens' : finish === null || finish === 'STOP' ? null : 'failed'
  const meta = json?.usageMetadata ?? {}
  const usage = {}
  if (count(meta.promptTokenCount) !== undefined) usage.input_tokens = meta.promptTokenCount
  if (count(meta.candidatesTokenCount) !== undefined || count(meta.thoughtsTokenCount) !== undefined) usage.output_tokens = (count(meta.candidatesTokenCount) ?? 0) + (count(meta.thoughtsTokenCount) ?? 0)
  const audio = (Array.isArray(meta.promptTokensDetails) ? meta.promptTokensDetails : []).filter(detail => detail?.modality === 'AUDIO' && count(detail.tokenCount) !== undefined)
  if (audio.length) usage.seconds = Math.ceil(audio.reduce((sum, detail) => sum + detail.tokenCount, 0) / AI_GOOGLE_AUDIO_TOKENS_PER_SECOND)
  return { text, stop, usage }
}
