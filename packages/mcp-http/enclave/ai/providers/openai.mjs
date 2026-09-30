// OpenAI (docs/mcp-enclave.md §18.9): audio through the transcription
// route, images and documents through Responses with `store: false`, never
// video in B1 (B0 found no model that takes an mp4, §18.19). Never used:
// Assistants, Files, Batch, and a stored or chained response. The bodies are
// pinned in ../test/provider-shapes.json from those B0 sent.
import { AI_OUTPUT_MAX_TOKENS, systemPrompt, userText } from '../policy.mjs'

export const NAME = 'openai'

/** The model list: one unpaged call, `GET /v1/models`. */
export const modelsPage = () => ({ method: 'GET', path: '/v1/models' })

/** The ids of the list (it says nothing of a model's inputs), or null for an answer of another shape. */
export function readModels(json) {
  if (!json || !Array.isArray(json.data)) return null
  return { ids: json.data.map(model => model?.id).filter(id => typeof id === 'string'), next: null }
}

/**
 * The transcription's file name, by the container the enclave sniffed
 * (§18.9): ogg, mp4, m4a, mp3, wav or webm, else the audio is refused.
 */
export const TRANSCRIPTION_FILENAMES = Object.freeze({ ogg: 'audio.ogg', mp4: 'audio.mp4', m4a: 'audio.m4a', mp3: 'audio.mp3', wav: 'audio.wav', webm: 'audio.webm' })

/**
 * `POST /v1/audio/transcriptions`: multipart `file`, `model`,
 * `response_format=json`, and `language` (the primary subtag of `lang`) when
 * set; never `prompt`, and no text part.
 */
export function buildTranscription({ model, lang, audio }) {
  const filename = TRANSCRIPTION_FILENAMES[audio.container]
  if (!filename) return null
  const form = new FormData()
  form.append('file', new Blob([audio.data], { type: audio.mimeType }), filename)
  form.append('model', model)
  form.append('response_format', 'json')
  if (lang) form.append('language', lang.split('-')[0])
  return { method: 'POST', path: '/v1/audio/transcriptions', form }
}

/**
 * `POST /v1/responses` for `image` or `document`: instructions, one user
 * input of up to 4 images as data URLs and the text part, the output limit,
 * and `store: false` last, which the egress checks before sending.
 */
export function buildResponses(feature, { model, lang, images = [], documentText }) {
  return {
    method: 'POST', path: '/v1/responses',
    body: {
      model,
      instructions: systemPrompt(feature, lang),
      input: [{
        role: 'user',
        content: [
          ...images.map(image => ({ type: 'input_image', image_url: `data:${image.mimeType};base64,${Buffer.from(image.data).toString('base64')}` })),
          { type: 'input_text', text: userText(feature, documentText) },
        ],
      }],
      max_output_tokens: AI_OUTPUT_MAX_TOKENS[feature],
      store: false,
    },
  }
}

export function build(feature, input) {
  if (feature === 'audio') return buildTranscription(input)
  if (feature === 'image' || feature === 'document') return buildResponses(feature, input)
  return null
}

const count = value => (Number.isSafeInteger(value) && value >= 0 ? value : undefined)

/**
 * A 200 answer. Transcription: `text`, and its usage (`tokens` with input
 * and output, or `duration` with `seconds`, B0). Responses: the
 * `output_text` parts joined; a `refusal` part, or `incomplete` for
 * `content_filter`, is a safety stop, `incomplete` for `max_output_tokens` the
 * output limit.
 */
export function answer(json, route) {
  const usage = {}
  if (route === 'transcriptions') {
    const text = typeof json?.text === 'string' ? json.text : ''
    const measured = json?.usage
    if (measured?.type === 'tokens') {
      if (count(measured.input_tokens) !== undefined) usage.input_tokens = measured.input_tokens
      if (count(measured.output_tokens) !== undefined) usage.output_tokens = measured.output_tokens
    } else if (measured?.type === 'duration' && typeof measured.seconds === 'number' && Number.isFinite(measured.seconds) && measured.seconds >= 0) {
      usage.seconds = Math.ceil(measured.seconds)
    }
    return { text, stop: null, usage, transcription: true }
  }
  const parts = (Array.isArray(json?.output) ? json.output : []).flatMap(item => (item?.type === 'message' && Array.isArray(item.content) ? item.content : []))
  const text = parts.filter(part => part?.type === 'output_text' && typeof part.text === 'string').map(part => part.text).join('')
  const reason = json?.status === 'incomplete' ? json?.incomplete_details?.reason : null
  const stop = parts.some(part => part?.type === 'refusal') || reason === 'content_filter' ? 'refusal' : reason === 'max_output_tokens' ? 'max_tokens' : null
  if (count(json?.usage?.input_tokens) !== undefined) usage.input_tokens = json.usage.input_tokens
  if (count(json?.usage?.output_tokens) !== undefined) usage.output_tokens = json.usage.output_tokens
  return { text, stop, usage }
}
