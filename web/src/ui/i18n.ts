import { ref } from 'vue'
import { readPreference, writePreference } from './preferences'
const catalogs = import.meta.glob<Record<string, string[]>>('./locales/*.json', { eager: true, import: 'default' })

export type Locale = 'pt' | 'en' | 'es' | 'fr' | 'de'
export type Translations = Record<string, [string, string, string, string]>
export const languageOptions: { value: Locale; label: string }[] = [
  { value: 'pt', label: 'Português' }, { value: 'en', label: 'English' },
  { value: 'es', label: 'Español' }, { value: 'fr', label: 'Français' },
  { value: 'de', label: 'Deutsch' },
]
export const locale = ref<Locale>('pt')
const columns: Record<Exclude<Locale, 'pt'>, number> = { en: 0, es: 1, fr: 2, de: 3 }
const catalog: Record<string, string[]> = Object.assign({}, ...Object.values(catalogs))

export function supportedLocale(value: string | null | undefined): Locale | undefined {
  const base = value?.toLowerCase().split(/[-_]/)[0]
  return languageOptions.find((item) => item.value === base)?.value
}

export function initializeLocale(): void {
  const saved = supportedLocale(readPreference('locale'))
  const languages = typeof navigator === 'undefined' ? [] : navigator.languages ?? [navigator.language]
  const detected = languages.map(supportedLocale).find(Boolean)
  applyLocale(saved ?? detected ?? 'en')
}

function applyLocale(value: Locale): void {
  locale.value = value
  if (typeof document !== 'undefined') document.documentElement.lang = value === 'pt' ? 'pt-BR' : value
}

export function setLocale(value: Locale): void {
  if (!supportedLocale(value)) return
  applyLocale(value)
  writePreference('locale', value)
}

/** Catalog values are text only. Vue escapes them; never insert translations as HTML. */
export function t(source: string, values?: Record<string, string | number | undefined>): string {
  const translated = locale.value === 'pt' ? source : catalog[source]?.[columns[locale.value]] ?? source
  return values ? translated.replace(/\{(\w+)\}/g, (match, key: string) =>
    values[key] === undefined ? match : String(values[key])) : translated
}

export function intlLocale(): string { return locale.value === 'pt' ? 'pt-BR' : locale.value }
