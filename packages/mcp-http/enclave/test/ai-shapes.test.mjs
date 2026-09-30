// What the enclave sends each AI provider and how it reads the answers
// (docs/mcp-enclave.md §18.9), against ai/test/provider-shapes.json, pinned
// from the calls B0 made and the providers accepted (§18.19): every body
// byte for byte, every row of the error map with B0's real bodies where it
// has one (N-AI-14), and every stop of "Answers".
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { classify, errorFacts, ruleOf } from '../ai/egress.mjs'
import { interpret } from '../ai/jobs.mjs'
import { AI_ERROR_RULES } from '../ai/policy.mjs'
import * as anthropic from '../ai/providers/anthropic.mjs'
import * as google from '../ai/providers/google.mjs'
import * as openai from '../ai/providers/openai.mjs'

const shapes = JSON.parse(readFileSync(new URL('../ai/test/provider-shapes.json', import.meta.url), 'utf8'))
const PROVIDERS = { anthropic, openai, google }
const SMALL = { 'image/png': Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex'), 'audio/ogg': Buffer.from('4f67675300020000000000000000', 'hex'), 'video/mp4': Buffer.from('000000186674797069736f6d', 'hex') }
const small = mimeType => SMALL[mimeType] ?? SMALL[mimeType.startsWith('audio/') ? 'audio/ogg' : 'image/png']

/** B0's media elision (its lib/providers/common.mjs), to compare with what B0 sent. */
function elide(value) {
  if (Array.isArray(value)) return value.map(elide)
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, elide(item)]))
  if (typeof value === 'string' && value.length > 1000) {
    const data = /^data:([^;,]+);base64,/.exec(value)
    if (data) return `data:${data[1]};base64,<base64 ${Math.floor(((value.length - data[0].length) * 3) / 4)} bytes>`
    if (/^[A-Za-z0-9+/]+=*$/.test(value)) return `<base64 ${Math.floor((value.length * 3) / 4)} bytes>`
  }
  return value
}
const formSummary = form => Object.fromEntries([...form].map(([name, value]) => [name, typeof value === 'string' ? value : `<file ${value.size} bytes, ${value.type}${value.name ? `, ${value.name}` : ''}>`]))
const inputFor = (entry, media) => (entry.provider === 'google'
  ? { model: entry.model, lang: entry.lang, media, documentText: entry.document_text }
  : { model: entry.model, lang: entry.lang, images: media, documentText: entry.document_text })

test('bodies: what B0 sent and the provider accepted, byte for byte but the media, and the exact JSON with the synthetic media', () => {
  assert.equal(shapes.bodies.length, 27)
  for (const entry of shapes.bodies) {
    const module = PROVIDERS[entry.provider]
    if (entry.b0_form) {
      const [item] = entry.media
      const built = module.build('audio', { model: entry.model, lang: entry.lang, audio: { container: item.container, mimeType: item.mimeType, data: Buffer.alloc(item.bytes) } })
      assert.equal(built.path, '/v1/audio/transcriptions', entry.id)
      assert.deepEqual(formSummary(built.form), entry.b0_form, entry.id)
      const sent = module.build('audio', { model: entry.model, lang: entry.lang, audio: { container: item.container, mimeType: item.mimeType, data: SMALL['audio/ogg'] } })
      assert.deepEqual(formSummary(sent.form), entry.form, entry.id)
      assert.deepEqual(Object.keys(entry.form), ['file', 'model', 'response_format', 'language'], `${entry.id}: never prompt, and no text part`)
      continue
    }
    const b0 = module.build(entry.feature, inputFor(entry, entry.b0_media.map(item => ({ mimeType: item.mimeType, data: Buffer.alloc(item.bytes) }))))
    assert.equal(JSON.stringify(elide(b0.body)), JSON.stringify(entry.b0_request), entry.id)
    const sent = module.build(entry.feature, inputFor(entry, entry.media.map(item => ({ mimeType: item.mimeType, data: small(item.mimeType) }))))
    assert.equal(JSON.stringify(sent.body), entry.body, entry.id)
    assert.equal(`${sent.method} ${entry.provider === 'google' ? sent.path.replace(entry.model, '{model}') : sent.path}`, entry.route, entry.id)
    // No reasoning or thinking control in any body (§18.9); OpenAI's ends with store: false.
    assert.doesNotMatch(entry.body, /reasoning|thinking|previous_response_id/, entry.id)
    if (entry.provider === 'openai') assert.equal(Object.keys(JSON.parse(entry.body)).at(-1), 'store', entry.id)
  }
  // The key never goes in a body or a URL: the builders never see one.
  assert.doesNotMatch(JSON.stringify(shapes.bodies), /x-api-key|x-goog-api-key|Bearer/)
})

test('N-AI-14: every row of the error map, with B0\'s real bodies and the documented codes, each to its verdict', () => {
  const rowsHit = new Set()
  for (const entry of shapes.errors) {
    const facts = errorFacts(entry.provider, entry.body)
    assert.equal(classify(entry.provider, entry.route, entry.status, facts), entry.expect, `${entry.id} (${entry.source})`)
    rowsHit.add(`${entry.provider}:${ruleOf(entry.provider, entry.route, entry.status, facts)}`)
  }
  // One body per row at least: every row of every provider's map is the first match of some body.
  for (const provider of ['anthropic', 'openai', 'google']) {
    AI_ERROR_RULES[provider].forEach((rule, index) => assert.ok(rowsHit.has(`${provider}:${index}`), `${provider} row ${index} (${rule.result}) has no body`))
  }
  // B0's own bodies are there, first (§18.19's table).
  const fromB0 = shapes.errors.filter(entry => entry.source !== 'documented').map(entry => entry.id)
  for (const id of ['openai.401', 'openai.429.insufficient_quota', 'openai.404.invalid_url', 'openai.400.audio_duration', 'openai.400.input_mime', 'google.400.api_key_invalid', 'google.404.not_found', 'google.400.modality', 'anthropic.401', 'anthropic.404.not_found_error', 'anthropic.400.block_type']) {
    assert.ok(fromB0.includes(id), id)
  }
  // The duration row is matched by its message before the model row's invalid_value would take it.
  const duration = shapes.errors.find(entry => entry.id === 'openai.400.audio_duration')
  assert.equal(duration.body.error.code, 'invalid_value')
  assert.equal(classify('openai', 'transcriptions', 400, errorFacts('openai', duration.body)), 'ai_too_large')
  // Anything no row covers (a redirect answer) fails, never retried.
  assert.equal(classify('openai', 'responses', 302, errorFacts('openai', null)), 'ai_provider_failed')
  assert.equal(classify('google', 'generate', 418, errorFacts('google', 'not json')), 'ai_provider_failed')
})

test('Answers (§18.9): text, safety stops stored as refused, Google\'s other stops failed, empty text as no_speech, ai_output_limit or failed, partial at the limit', () => {
  for (const entry of shapes.answers) {
    const read = interpret(entry.provider, entry.route, entry.body)
    if (entry.expect.code) {
      assert.equal(read.code, entry.expect.code, entry.id)
      continue
    }
    assert.equal(read.code, undefined, entry.id)
    assert.equal(read.text, entry.expect.text, entry.id)
    assert.deepEqual(read.flags, entry.expect.flags, entry.id)
    if (entry.expect.usage) assert.deepEqual(read.usage, entry.expect.usage, entry.id)
  }
  // Control characters go (§16.11), white space is trimmed, and the text is cut at 200,000 code units (cut).
  const long = interpret('anthropic', 'messages', { content: [{ type: 'text', text: `  a\u0000b\u0007c\r\nd  ${'x'.repeat(200_010)}` }], stop_reason: 'end_turn' })
  assert.equal(long.text.length, 200_000)
  assert.ok(long.text.startsWith('abc\nd  x'))
  assert.deepEqual(long.flags, ['cut'])
  const cutAndPartial = interpret('google', 'generate', { candidates: [{ content: { parts: [{ text: 'y'.repeat(200_001) }] }, finishReason: 'MAX_TOKENS' }] })
  assert.deepEqual(cutAndPartial.flags, ['cut', 'partial'])
  // A 200 that is not JSON, or of another shape, is a failure (and charged, §18.9).
  assert.equal(interpret('openai', 'responses', null).code, 'ai_provider_failed')
  assert.equal(interpret('google', 'generate', { candidates: [] }).code, 'ai_provider_failed')
})
