import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import { describe, expect, it } from 'vitest'
const script = readFileSync(new URL('../../site/preferences.js', import.meta.url), 'utf8')
const html = readFileSync(new URL('../../site/index.html', import.meta.url), 'utf8')
const docsHTML = readFileSync(new URL('../../site/docs/index.html', import.meta.url), 'utf8')
const docsScript = readFileSync(new URL('../../site/docs/translations.js', import.meta.url), 'utf8')
function page(stored: Record<string, string> = {}, browserLanguages = ['en-US'], documentation = false) {
  const events = new Map<string, () => void>()
  const media = { matches: true, addEventListener: (_: string, callback: () => void) => { events.set('system-change', callback) } }
  const themePicker = { value: '', addEventListener: (_: string, callback: () => void) => { events.set('theme-change', callback) } }
  const languagePicker = { value: '', addEventListener: (_: string, callback: () => void) => { events.set('language-change', callback) } }
  const content = [...(documentation ? docsHTML : html).matchAll(/data-i18n="([^"]+)"/g)].map(match => ({ dataset: { i18n: match[1] }, tagName: match[1] === 'description' ? 'META' : 'DIV', content: '', textContent: '' }))
  const document = {
    cookie: Object.entries(stored).map(([key, value]) => `wappie_${key}=${value}`).join('; '), documentElement: { dataset: {} as Record<string, string>, lang: '' },
    addEventListener: (name: string, callback: () => void) => { events.set(name, callback) },
    querySelectorAll: (selector: string) => selector === '[data-i18n]' ? content : selector === '[data-theme-picker]' ? [themePicker] : selector === '[data-language-picker]' ? [languagePicker] : [],
  }
  const local = new Map<string, string>()
  runInNewContext((documentation ? docsScript : '') + script, { document, navigator: { languages: browserLanguages }, window: { addEventListener: () => {} }, location: { hostname: 'wappie.thehappie.co', protocol: 'https:' }, matchMedia: () => media, localStorage: { getItem: (key: string) => local.get(key) ?? null, setItem: (key: string, value: string) => { local.set(key, value) } } })
  return { document, content, media, themePicker, languagePicker, events, local }
}
describe('public website preferences', () => {
  it.each(['pt', 'en', 'es', 'fr', 'de'])('translates all documentation prose in %s while preserving protocol examples', (locale) => {
    const site = page({ locale }, ['en-US'], true); site.events.get('DOMContentLoaded')?.()
    expect(site.content.filter(node => !node.textContent && !node.content)).toEqual([])
    expect(docsHTML).toContain('<code>device.start</code>')
    expect(docsHTML).toContain('<code>device.rename</code>')
    expect(docsHTML).toContain('{"t":"hello","r":"connect","p":{"api_key":"SEU_TOKEN"}}')
    expect(docsHTML).not.toMatch(/<code>\s*<span data-i18n=/)
  })
  it('applies the saved palette before content is ready', () => {
    const site = page({ theme: 'light' }); expect(site.document.documentElement.dataset.theme).toBe('light')
    site.events.get('system-change')?.(); expect(site.document.documentElement.dataset.theme).toBe('light')
  })
  it.each([
    ['pt', 'Conecte o WhatsApp ao seu jeito de trabalhar.'], ['en', 'Connect WhatsApp to the way you work.'], ['es', 'Conecta WhatsApp con tu forma de trabajar.'], ['fr', 'Reliez WhatsApp à votre façon de travailler.'], ['de', 'Verbinden Sie WhatsApp mit Ihrer Arbeitsweise.'],
  ])('renders all landing text in %s', (locale, headline) => {
    const site = page({ locale }); site.events.get('DOMContentLoaded')?.()
    expect(site.content.find(node => node.dataset.i18n === 'heroTitle')?.textContent).toBe(headline)
    expect(site.content.filter(node => !node.textContent && !node.content)).toEqual([])
    expect(site.languagePicker.value).toBe(locale); expect(site.document.documentElement.lang).toBe(locale === 'pt' ? 'pt-BR' : locale)
  })
  it('uses the first supported browser language and remembers explicit choices', () => {
    const site = page({}, ['it-IT', 'de-DE', 'en-US']); site.events.get('DOMContentLoaded')?.(); expect(site.languagePicker.value).toBe('de')
    site.languagePicker.value = 'fr'; site.events.get('language-change')?.(); expect(site.local.get('wappie_locale')).toBe('fr'); expect(site.document.documentElement.lang).toBe('fr')
  })
  it('uses the same preference keys and cookie scope as app and console', () => {
    const site = page(); site.events.get('DOMContentLoaded')?.(); site.themePicker.value = 'dark'; site.events.get('theme-change')?.()
    expect(site.local.get('wappie_theme')).toBe('dark'); expect(site.document.cookie).toContain('Domain=wappie.thehappie.co; Secure')
  })
})
