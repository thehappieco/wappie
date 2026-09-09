import { afterEach, describe, expect, it, vi } from 'vitest'
import { computed } from 'vue'
import { initializeLocale, locale, setLocale, supportedLocale, t } from '../src/ui/i18n'
import { count, dayLabel, stamp } from '../src/ui/format'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const catalogs = import.meta.glob<Record<string, string[]>>('../src/ui/locales/*.json', { eager: true, import: 'default' })
const all: Record<string, string[]> = Object.assign({}, ...Object.values(catalogs))
afterEach(() => { locale.value = 'pt'; vi.unstubAllGlobals() })

describe('application languages', () => {
  it('recognizes regional language preferences and rejects unsupported values', () => {
    expect(supportedLocale('pt-PT')).toBe('pt')
    expect(supportedLocale('es-MX')).toBe('es')
    expect(supportedLocale('zh')).toBeUndefined()
    expect(supportedLocale('__proto__')).toBeUndefined()
  })
  it('uses a saved preference before the browser language without requiring storage access', () => {
    vi.stubGlobal('navigator', { languages: ['fr-CA', 'en'] })
    vi.stubGlobal('document', { cookie: 'wappie_locale=de', documentElement: { lang: '' } })
    initializeLocale()
    expect(locale.value).toBe('de')
    expect(document.documentElement.lang).toBe('de')
    vi.stubGlobal('document', { cookie: '', documentElement: { lang: '' } })
    vi.stubGlobal('localStorage', { getItem() { throw new Error('disabled') }, setItem() { throw new Error('disabled') } })
    initializeLocale()
    expect(locale.value).toBe('fr')
    setLocale('es')
    expect(locale.value).toBe('es')
  })
  it('reactively changes labels and locale-specific dates and numbers', () => {
    const label = computed(() => t('Espaço de trabalho'))
    const number = computed(() => count(1234))
    locale.value = 'pt'
    expect(number.value).toBe('1.234')
    locale.value = 'en'
    expect(label.value).toBe('Workspace')
    expect(number.value).toBe('1,234')
    locale.value = 'de'
    expect(label.value).toBe('Arbeitsbereich')
    expect(dayLabel(new Date())).toBe('heute')
    expect(stamp(new Date(2026, 8, 8, 12))).toContain('08.09.26')
  })
  it('interpolates values as plain text without modifying user content', () => {
    locale.value = 'en'
    const value = '<img src=x onerror=alert(1)>'
    expect(t('Gerencie as formas de entrar na conta {v0}.', { v0: value })).toBe(`Manage sign-in methods for ${value}.`)
    expect(t('A user-created workspace name')).toBe('A user-created workspace name')
  })
  it('provides all four translations and exactly preserves every interpolation placeholder', () => {
    const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort()
    for (const [source, translations] of Object.entries(all)) {
      expect(translations, source).toHaveLength(4)
      for (const value of translations) {
        expect(value.trim(), source).not.toBe('')
        expect(placeholders(value), source).toEqual(placeholders(source))
      }
    }
  })
  it('covers every literal translation key used by the shipped client', () => {
    const files: string[] = []
    function walk(path: string) {
      for (const entry of readdirSync(path, { withFileTypes: true })) {
        if (entry.isDirectory() && entry.name !== 'locales') walk(`${path}/${entry.name}`)
        else if (entry.isFile() && /\.(vue|ts)$/.test(entry.name)) files.push(`${path}/${entry.name}`)
      }
    }
    walk(fileURLToPath(new URL('../src', import.meta.url)))
    const missing = new Set<string>()
    for (const file of files) {
      const source = readFileSync(file, 'utf8')
      for (const match of source.matchAll(/\bt\(\s*('(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")/g)) {
        const literal = match[1]!
        const key = literal[0] === '"' ? JSON.parse(literal) : literal.slice(1, -1).replace(/\\'/g, "'").replace(/\\n/g, '\n').replace(/\\\\/g, '\\')
        if (!(key in all)) missing.add(key)
      }
    }
    expect([...missing]).toEqual([])
  })
})
