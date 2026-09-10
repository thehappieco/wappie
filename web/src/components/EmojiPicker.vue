<script setup lang="ts">
import { computed, ref } from 'vue'
import { emojiGroups, normalizeReactionEmoji } from '../ui/emoji'
import { t } from '../ui/i18n'
import AppIcon from './AppIcon.vue'

const props = defineProps<{ current: string; disabled: boolean }>()
const emit = defineEmits<{ choose: [emoji: string]; back: [] }>()
const input = ref('')
const category = ref(0)
const visibleCount = ref(120)
const composing = ref(false)
const labels = ['Rostos e emoções', 'Pessoas e gestos', 'Animais e natureza', 'Comidas e bebidas', 'Viagens e lugares', 'Atividades', 'Objetos', 'Símbolos', 'Bandeiras']
const entries = computed(() => emojiGroups[category.value]?.emojis ?? [])
const visible = computed(() => entries.value.slice(0, visibleCount.value))
const chosen = computed(() => normalizeReactionEmoji(input.value.trim()))
const invalid = computed(() => !composing.value && input.value !== '' && (chosen.value === null || chosen.value === ''))
function choose(value: string) {
  if (!props.disabled && !composing.value && normalizeReactionEmoji(value) !== null) emit('choose', value)
}
function confirm() { if (chosen.value) choose(chosen.value) }
function enter(event: KeyboardEvent) {
  if (event.isComposing || composing.value) return
  event.preventDefault()
  confirm()
}
</script>

<template>
  <section class="emoji-picker" :aria-label="t('Escolher reação')">
    <button type="button" class="emoji-back" @click="emit('back')"><AppIcon name="back" :size="18" />{{ t('Reações rápidas') }}</button>
    <label class="emoji-input-label">{{ t('Digite ou cole um emoji') }}
      <span class="emoji-input-row"><input v-model="input" type="text" inputmode="text" autocomplete="off" autocapitalize="off" :spellcheck="false" :maxlength="128"
        :disabled="disabled" :aria-invalid="invalid" :placeholder="t('Um emoji, como 👩🏽‍💻')" @keydown.enter="enter"
        @compositionstart="composing = true" @compositionend="composing = false" />
        <button type="button" class="emoji-apply" :disabled="disabled || !chosen || invalid || composing" @click="confirm">{{ t('Reagir') }}</button>
      </span>
    </label>
    <p v-if="invalid" class="emoji-error" role="alert">{{ t('Escolha apenas um emoji completo.') }}</p>
    <p v-else class="emoji-hint">{{ t('Use o teclado de emojis do dispositivo ou escolha abaixo.') }}</p>
    <label class="emoji-category">{{ t('Categoria') }}<select v-model.number="category" @change="visibleCount = 120">
      <option v-for="(_, index) in emojiGroups" :key="index" :value="index">{{ t(labels[index]!) }}</option>
    </select></label>
    <div class="emoji-grid" :aria-label="t(labels[category]!)">
      <button v-for="variants in visible" :key="variants[0]" type="button" :disabled="disabled" :aria-label="t('Reagir com {v0}', { v0: variants[0] })"
        :aria-pressed="normalizeReactionEmoji(current) === variants[0]" :class="{ chosen: normalizeReactionEmoji(current) === variants[0] }" @click="choose(variants[0]!)">{{ variants[0] }}</button>
      <button v-if="visibleCount < entries.length" type="button" class="emoji-more" @click="visibleCount += 120">{{ t('Mostrar mais emojis') }}</button>
    </div>
    <button v-if="current" type="button" class="emoji-remove" :disabled="disabled" @click="choose('')"><AppIcon name="trash" :size="18" />{{ t('Remover minha reação') }} <span>{{ current }}</span></button>
  </section>
</template>

<style scoped>
.emoji-picker { padding: 0 5px 8px; }
.emoji-back, .emoji-remove { display: flex; align-items: center; gap: 8px; min-height: 42px; color: var(--text-dim); font-size: 13px; }
.emoji-input-label, .emoji-category { display: grid; gap: 7px; margin-top: 10px; font-size: 12px; color: var(--text-dim); }
.emoji-input-row { display: flex; gap: 8px; }
.emoji-input-row input { min-width: 0; flex: 1; height: 46px; background: var(--bg-input); border: 1px solid var(--line); border-radius: 11px; color: var(--text); font-size: 18px; padding: 8px 12px; }
.emoji-apply { padding: 8px 12px; min-height: 44px; border-radius: 11px; background: var(--accent); color: var(--on-accent); font-size: 13px; }
.emoji-error, .emoji-hint { font-size: 12px; line-height: 1.4; margin: 7px 0; }
.emoji-error { color: var(--danger); } .emoji-hint { color: var(--text-dim); }
.emoji-category { grid-template-columns: auto 1fr; align-items: center; }
.emoji-category select { min-width: 0; height: 42px; padding: 6px 10px; border-radius: 10px; background: var(--bg-input); color: var(--text); border: 1px solid var(--line); font-size: 14px; }
.emoji-grid { margin-top: 12px; display: grid; grid-template-columns: repeat(7, minmax(0, 1fr)); max-height: min(290px, 36dvh); overflow-y: auto; overscroll-behavior: contain; gap: 3px; padding: 2px; }
.emoji-grid button { display: grid; place-items: center; min-height: 43px; padding: 0; font-size: 27px; border-radius: 9px; }
.emoji-grid button:hover, .emoji-grid button.chosen { background: var(--bg-active); }
.emoji-grid button.chosen { box-shadow: inset 0 0 0 2px var(--accent); }
.emoji-grid .emoji-more { grid-column: 1 / -1; font-size: 13px; margin-top: 5px; background: var(--bg-hover); }
.emoji-remove { margin-top: 10px; padding: 6px 8px; border-top: 1px solid var(--line); width: 100%; color: var(--danger); }
.emoji-remove span { margin-inline-start: auto; font-size: 22px; }
button:disabled { opacity: .4; cursor: default; }
button:focus-visible, input:focus-visible, select:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
@media (max-width: 359px) { .emoji-grid { grid-template-columns: repeat(6, minmax(0, 1fr)); } }
</style>
