<script setup lang="ts">
import { ref, useId } from 'vue'
import { locale, setLocale, t, languageOptions } from '../ui/i18n'
import { theme, setTheme, type ThemePreference } from '../ui/preferences'

const dialog = ref<HTMLDialogElement | null>(null)
const titleID = useId()
const languageID = useId()
const themes: { value: ThemePreference; label: string; path: string }[] = [
  { value: 'light', label: 'Claro', path: 'M12 8a4 4 0 1 1 0 8 4 4 0 0 1 0-8Zm0-6v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5' },
  { value: 'dark', label: 'Escuro', path: 'M20.9 13A9 9 0 0 1 11 3.1 9 9 0 1 0 20.9 13Z' },
  { value: 'system', label: 'Dispositivo', path: 'M3 4h18v13H3zM8 21h8m-4-4v4' },
]
function changeLanguage(event: Event) {
  const selected = languageOptions.find(option => option.value === (event.target as HTMLSelectElement).value)
  if (selected) setLocale(selected.value)
}
</script>

<template>
  <button type="button" class="appearance-trigger" aria-haspopup="dialog" :aria-label="t('Aparência e idioma')" :title="t('Aparência e idioma')" @click="dialog?.showModal()">
    <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z"/></svg>
  </button>
  <Teleport to="body">
    <dialog ref="dialog" class="appearance-dialog" :aria-labelledby="titleID" @click="event => { if (event.target === dialog) dialog?.close() }">
      <div class="appearance-head">
        <h2 :id="titleID">{{ t('Aparência e idioma') }}</h2>
        <button type="button" class="appearance-close" :aria-label="t('Fechar')" @click="dialog?.close()"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="m6 6 12 12M6 18 18 6"/></svg></button>
      </div>
      <fieldset class="appearance-options">
        <legend>{{ t('Aparência') }}</legend>
        <div class="appearance-themes">
          <button v-for="option in themes" :key="option.value" type="button" :aria-pressed="theme === option.value" @click="setTheme(option.value)">
            <svg width="25" height="25" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path :d="option.path" /></svg>
            <span>{{ t(option.label) }}</span>
          </button>
        </div>
        <p>{{ t('Dispositivo acompanha a aparência do seu sistema.') }}</p>
      </fieldset>
      <div class="appearance-language">
        <label :for="languageID">{{ t('Idioma') }}</label>
        <select :id="languageID" :value="locale" @change="changeLanguage">
          <option v-for="language in languageOptions" :key="language.value" :value="language.value" :lang="language.value">{{ language.label }}</option>
        </select>
      </div>
    </dialog>
  </Teleport>
</template>

<style scoped>
.appearance-trigger, .appearance-close { display: inline-grid; place-items: center; min-width: 40px; min-height: 40px; flex-shrink: 0; color: var(--text-dim); padding: 8px; border-radius: 12px; }
.appearance-trigger:hover, .appearance-close:hover { background: var(--bg-hover); color: var(--text); }
.appearance-trigger:focus-visible, .appearance-close:focus-visible, .appearance-themes button:focus-visible, select:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
.appearance-dialog { width: min(390px, calc(100% - 32px)); max-height: calc(100dvh - 32px); overflow-y: auto; color: var(--text); background: var(--bg-panel); border: 1px solid var(--line); border-radius: 22px; padding: 23px; box-shadow: 0 24px 90px #0005; }
.appearance-dialog::backdrop { background: #0006; backdrop-filter: blur(3px); }
.appearance-head { display: flex; align-items: center; gap: 12px; margin-bottom: 24px; }
.appearance-head h2 { margin: 0; flex: 1; font-size: 19px; letter-spacing: -.4px; }
.appearance-close { margin: -6px -6px -6px 0; }
.appearance-options { padding: 0; margin: 0; border: 0; min-width: 0; }
.appearance-options legend, .appearance-language label { display: block; font-size: 13px; font-weight: 650; margin-bottom: 10px; }
.appearance-themes { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
.appearance-themes button { display: flex; flex-direction: column; align-items: center; gap: 11px; padding: 16px 3px; border: 1px solid var(--line); border-radius: 12px; background: var(--bg-raised); color: var(--text-dim); font-size: 12px; }
.appearance-themes button[aria-pressed='true'] { background: var(--accent-dim); border-color: var(--accent); color: var(--text); box-shadow: inset 0 0 0 1px var(--accent); }
.appearance-options p { margin: 11px 0 24px; color: var(--text-dim); font-size: 12px; line-height: 1.5; }
.appearance-language select { width: 100%; min-height: 46px; padding: 10px 12px; background: var(--bg-input); color: var(--text); border: 1px solid var(--line); border-radius: 10px; font: inherit; }
@media (max-width: 600px) { .appearance-trigger, .appearance-close { min-width: 44px; min-height: 44px; } .appearance-language select { font-size: 16px; } }
</style>
