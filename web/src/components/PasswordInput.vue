<script setup lang="ts">
import { t } from '../ui/i18n'
import { ref } from 'vue'
import AppIcon from './AppIcon.vue'

defineOptions({ inheritAttrs: false })
const model = defineModel<string>({ default: '' })
const visible = ref(false)
const input = ref<HTMLInputElement | null>(null)

function sync() {
  if (input.value) model.value = input.value.value
}

function toggle() {
  // Some password managers fill the native input without dispatching input.
  // Preserve that value when Vue changes its type to reveal the password.
  sync()
  visible.value = !visible.value
  input.value?.focus({ preventScroll: true })
}
</script>

<template>
  <span class="password-control">
    <input ref="input" v-bind="$attrs" v-model="model" :type="visible ? 'text' : 'password'"
      autocapitalize="off" :spellcheck="false" @change="sync" />
    <button class="password-toggle" type="button" :aria-label="visible ? t('Ocultar senha') : t('Mostrar senha')"
      :aria-pressed="visible" :disabled="Boolean($attrs.disabled)" @click="toggle">
      <AppIcon :name="visible ? 'eye-off' : 'eye'" :size="20" />
    </button>
  </span>
</template>

<style scoped>
.password-control { position: relative; display: block; min-width: 0; width: 100%; }
.password-control input { width: 100%; padding-right: 48px; }
.password-toggle { position: absolute; inset: 0 4px 0 auto; margin: auto 0; height: 40px; width: 40px; display: grid; place-items: center; border: 0; border-radius: 8px; background: transparent; color: var(--text-dim); cursor: pointer; }
.password-toggle:hover { background: var(--bg-hover); color: var(--text); }
.password-toggle:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
input:autofill { color: var(--text); background: var(--bg-input); }
input:-webkit-autofill { -webkit-text-fill-color: var(--text); box-shadow: 0 0 0 1000px var(--bg-input) inset; caret-color: var(--text); }
</style>
