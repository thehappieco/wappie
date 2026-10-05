// The pages a person's browser can be shown (pages.mjs, docs/mcp-enclave.md
// §19.29): a refusal for every browser-facing code in the five languages,
// the person's first, each with a next step; the human page at `/` in one
// language with a strict CSP and nothing loaded from elsewhere; robots.txt;
// and the discovery documents' links to the documentation, privacy policy
// and terms.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { askedLanguages, escapeHTML, HOME, homeLanguage, homePage, PAGE_CODES, PAGE_LANGUAGES, pageLanguages, refusalPage, robotsResponse, ROBOTS, SENTENCES } from '../pages.mjs'
import { createMetadata } from '../metadata.mjs'

const hashOf = text => `'sha256-${createHash('sha256').update(text, 'utf8').digest('base64')}'`
const styleOf = body => /<style>([^<]*)<\/style>/.exec(body)[1]

test('languages: Accept-Language by q-value, unknown and refused tags skipped, then the console\'s order', () => {
  assert.deepEqual(PAGE_LANGUAGES, ['pt', 'en', 'es', 'fr', 'de'])
  assert.deepEqual(pageLanguages('en-GB,en;q=0.9,pt;q=0.5'), ['en', 'pt', 'es', 'fr', 'de'])
  assert.deepEqual(pageLanguages('de;q=0.1, fr'), ['fr', 'de', 'pt', 'en', 'es'], 'a lower q comes later whatever its place')
  assert.deepEqual(pageLanguages('ja, es;q=0.8, en;q=0'), ['es', 'pt', 'en', 'fr', 'de'], 'q=0 is not wanted')
  assert.deepEqual(pageLanguages('FR-ca'), ['fr', 'pt', 'en', 'es', 'de'])
  for (const header of [null, undefined, '', 'xx', '*', ';;;', 'q=1']) assert.deepEqual(pageLanguages(header), PAGE_LANGUAGES, String(header))
  assert.deepEqual(askedLanguages('x'.repeat(5000) + ',de'), [], 'only the first kilobyte is read')
  assert.equal(homeLanguage('https://mcp.example/?lang=de', 'pt-BR'), 'de', '?lang wins')
  assert.equal(homeLanguage('https://mcp.example/?lang=xx', 'pt-BR'), 'pt')
  assert.equal(homeLanguage('https://mcp.example/', 'ja,ko'), 'en', 'English when none of the five is asked for')
  assert.equal(homeLanguage('https://mcp.example/', null), 'en')
})

test('every browser-facing code has a page: five sentences with a next step, the person\'s first, the way back and the code, under a strict CSP', async () => {
  // Every code as.mjs puts on a page is one of PAGE_CODES (the origin codes reach it as meta.code).
  const source = await readFile(new URL('../as.mjs', import.meta.url), 'utf8')
  const used = new Set([...source.matchAll(/page\(\d{3}, '([a-z_]+)'/g), ...source.matchAll(/refusalPage\(\d{3}, '([a-z_]+)'/g)].map(match => match[1]))
  for (const code of used) assert.ok(PAGE_CODES.includes(code), code)
  for (const code of ['origin_missing', 'opaque_origin', 'invalid_origin']) assert.ok(source.includes(`'${code}'`), code)
  const nextStep = { pt: /assistente|console|suporte/, en: /assistant|console|support/, es: /asistente|consola|soporte/, fr: /assistant|console|assistance/, de: /Assistent|Konsole|Support/ }
  for (const sentences of Object.values(SENTENCES)) {
    assert.deepEqual(Object.keys(sentences), PAGE_LANGUAGES)
    for (const [tag, sentence] of Object.entries(sentences)) {
      assert.ok(sentence.length > 40 && !/[<>]/.test(sentence), `${tag}: ${sentence}`)
      assert.match(sentence, nextStep[tag], `${tag} names where to go next: ${sentence}`)
    }
  }
  for (const code of PAGE_CODES) {
    const response = refusalPage(400, code, { back: 'https://console.example.test/console?x=1&y="2"', acceptLanguage: 'es-MX,es;q=0.9,en;q=0.8' })
    const body = await response.text()
    assert.equal(response.status, 400, code)
    assert.deepEqual([...body.matchAll(/<p lang="([a-z]{2})">/g)].map(match => match[1]), ['es', 'en', 'pt', 'fr', 'de'], code)
    assert.ok(body.endsWith(`<p><small>Wappie MCP: ${code}</small></p>`), code)
    assert.ok(body.includes('<a href="https://console.example.test/console?x=1&amp;y=&quot;2&quot;">'), `${code}: the way back, escaped`)
    assert.equal(response.headers.get('content-type'), 'text/html; charset=utf-8')
    assert.equal(response.headers.get('cache-control'), 'no-store')
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff')
    assert.equal(response.headers.get('x-frame-options'), 'DENY')
    assert.equal(response.headers.get('content-security-policy'), `default-src 'none'; style-src ${hashOf(styleOf(body))}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`)
    assert.doesNotMatch(body, /<script|<img|<link|https?:\/\/(?!console\.example\.test)/, code)
  }
  // The three origin codes share a sentence; invalid_client of the 0.5.0 policy has its own, without the token the hosted reader cannot make.
  const of = async (code, options = {}) => (await refusalPage(400, code, { acceptLanguage: 'en', ...options }).text()).match(/<p lang="en">([^<]*)<\/p>/)[1]
  assert.equal(await of('origin_missing'), await of('invalid_origin'))
  assert.equal(await of('opaque_origin'), escapeHTML(SENTENCES.origin.en))
  assert.match(await of('invalid_client'), /connection token/)
  assert.doesNotMatch(await of('invalid_client', { allowlist: true }), /token/)
  assert.ok((await refusalPage(429, 'too_many_requests').text()).includes('<p><small>Wappie MCP: too_many_requests</small></p>'))
  assert.doesNotMatch(await refusalPage(429, 'too_many_requests').text(), /<a href/, 'no way back unless one is given')
  assert.throws(() => refusalPage(400, 'not_a_code'), /no sentence/)
})

test('the page at /: one language, what the address is for, the console and the documentation, nothing loaded from elsewhere', async () => {
  const site = { resource: 'https://mcp.wappie.thehappie.co/mcp', console: 'https://app.wappie.thehappie.co/console', documentation: 'https://wappie.thehappie.co/docs/' }
  for (const [header, query, tag, lang] of [['pt-BR,pt;q=0.9', '', 'pt', 'pt-BR'], ['fr', '', 'fr', 'fr'], ['ja', '', 'en', 'en'], ['pt', '?lang=de', 'de', 'de'], [null, '', 'en', 'en']]) {
    const response = homePage(new Request(`https://mcp.wappie.thehappie.co/${query}`, { headers: header ? { 'accept-language': header } : {} }), site)
    const body = await response.text()
    assert.equal(response.status, 200)
    assert.ok(body.startsWith(`<!doctype html><html lang="${lang}">`), tag)
    assert.equal(response.headers.get('content-language'), lang)
    assert.ok(body.includes(`<title>${HOME[tag].title}</title>`), tag)
    for (const field of ['lead', 'address', 'console', 'docs']) assert.ok(body.includes(escapeHTML(HOME[tag][field])), `${tag}.${field}`)
    assert.ok(body.includes('<code>https://mcp.wappie.thehappie.co/mcp</code>'))
    assert.ok(body.includes(`<a href="${site.console}">`) && body.includes(`<a href="${site.documentation}">`))
    // Every other language is one link away, on this page.
    for (const other of PAGE_LANGUAGES.filter(item => item !== tag)) assert.ok(body.includes(`<a lang="${other}" href="/?lang=${other}">${HOME[other].name}</a>`), other)
    // The icon and every resource are this origin's own; no script, no frame, no form.
    for (const [, url] of body.matchAll(/(?:src|href)="([^"]*)"/g)) assert.ok(url.startsWith('/') || url === site.console || url === site.documentation, url)
    assert.doesNotMatch(body, /<script|<iframe|<form|style="/)
    assert.equal(response.headers.get('content-security-policy'), `default-src 'none'; img-src 'self'; style-src ${hashOf(styleOf(body))}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`)
    assert.deepEqual(['x-content-type-options', 'referrer-policy', 'x-frame-options', 'vary', 'cache-control'].map(name => response.headers.get(name)),
      ['nosniff', 'no-referrer', 'DENY', 'Accept-Language', 'public, max-age=300'])
    assert.equal(response.headers.get('content-length'), String(Buffer.byteLength(body)))
  }
  for (const tag of PAGE_LANGUAGES) assert.deepEqual(Object.keys(HOME[tag]), ['title', 'lead', 'address', 'console', 'docs', 'name'], tag)
  const head = homePage(new Request('https://mcp.wappie.thehappie.co/', { method: 'HEAD' }), site)
  assert.equal(head.status, 200)
  assert.equal(await head.text(), '')
  assert.ok(Number(head.headers.get('content-length')) > 1000)
  const posted = homePage(new Request('https://mcp.wappie.thehappie.co/', { method: 'POST' }), site)
  assert.deepEqual([posted.status, posted.headers.get('allow')], [405, 'GET, HEAD'])
  // A link that is not https is left out rather than shown.
  const bare = await homePage(new Request('https://mcp.example/'), { resource: 'https://mcp.example/<mcp>', console: 'javascript:alert(1)' }).text()
  assert.doesNotMatch(bare, /javascript:|<ul><li>/)
  assert.ok(bare.includes('<code>https://mcp.example/&lt;mcp&gt;</code>'))
  const robots = robotsResponse(new Request('https://mcp.wappie.thehappie.co/robots.txt'))
  assert.equal(await robots.text(), ROBOTS)
  assert.equal(ROBOTS, 'User-agent: *\nAllow: /\nDisallow: /mcp\nDisallow: /attestation\n')
  assert.equal(robots.headers.get('content-type'), 'text/plain; charset=utf-8')
  assert.equal(robotsResponse(new Request('https://mcp.wappie.thehappie.co/robots.txt', { method: 'PUT' })).status, 405)
})

test('discovery documents: the documentation, privacy policy and terms in both, only https links, the same body on every path', async () => {
  const links = { documentation: 'https://wappie.thehappie.co/docs/', privacy: 'https://wappie.thehappie.co/privacy/', terms: 'https://wappie.thehappie.co/terms/' }
  const metadata = createMetadata({ publicOrigin: 'https://mcp.example', cimd: true, links })
  const get = async (path, init) => { const response = metadata.respond(new Request(`https://mcp.example${path}`, init)); return { response, body: response.status === 204 ? '' : await response.text() } }
  const prm = await get('/.well-known/oauth-protected-resource')
  assert.equal(prm.response.status, 200)
  assert.equal(prm.response.headers.get('access-control-allow-origin'), '*')
  assert.deepEqual(JSON.parse(prm.body), { resource: 'https://mcp.example/mcp', authorization_servers: ['https://mcp.example'], scopes_supported: ['wappie:read'], resource_name: 'Wappie',
    resource_documentation: links.documentation, resource_policy_uri: links.privacy, resource_tos_uri: links.terms })
  for (const path of ['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource/']) assert.equal((await get(path)).body, prm.body, path)
  const as = JSON.parse((await get('/.well-known/oauth-authorization-server')).body)
  assert.deepEqual([as.service_documentation, as.op_policy_uri, as.op_tos_uri], [links.documentation, links.privacy, links.terms])
  assert.equal((await get('/.well-known/oauth-authorization-server/mcp')).body, JSON.stringify(as))
  // HEAD and the CORS preflight answer as the SDK's do.
  const head = await get('/.well-known/oauth-protected-resource', { method: 'HEAD' })
  assert.deepEqual([head.response.status, head.body], [200, ''])
  assert.equal((await get('/.well-known/oauth-protected-resource', { method: 'OPTIONS' })).response.status, 204)
  assert.equal((await get('/.well-known/oauth-protected-resource', { method: 'POST' })).response.status, 405)
  // No links (the hosted reader, a self-hosted container): none of the six fields; a link that is not https is dropped.
  for (const [given, label] of [[undefined, 'none'], [{ documentation: 'http://wappie.example/docs', privacy: 'javascript:alert(1)', terms: 42 }, 'not https']]) {
    const bare = createMetadata({ publicOrigin: 'https://mcp.example', cimd: false, links: given })
    const document = JSON.parse(await bare.respond(new Request('https://mcp.example/.well-known/oauth-protected-resource')).text())
    const server = JSON.parse(await bare.respond(new Request('https://mcp.example/.well-known/oauth-authorization-server')).text())
    for (const field of ['resource_documentation', 'resource_policy_uri', 'resource_tos_uri']) assert.equal(field in document, false, `${label}: ${field}`)
    for (const field of ['service_documentation', 'op_policy_uri', 'op_tos_uri']) assert.equal(field in server, false, `${label}: ${field}`)
  }
})
