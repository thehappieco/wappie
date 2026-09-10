<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, useId, watch } from 'vue'
import { t } from '../ui/i18n'
import { mapLinks } from '../ui/mapLinks'
import AppIcon from './AppIcon.vue'

const props = defineProps<{ lat: number; lon: number; name?: string }>()
const links = computed(() => mapLinks(props.lat, props.lon, props.name?.trim() || t('Localização')))
const trigger = ref<HTMLButtonElement>()
const dialog = ref<HTMLDialogElement>()
const opened = ref(false)
const titleID = useId()
let disposed = false, backdropPressed = false

async function open() {
  if (disposed || opened.value || !links.value.length) return
  opened.value = true
  await nextTick()
  if (!disposed && opened.value) dialog.value?.showModal()
}
function close() {
  const wasOpen = opened.value
  backdropPressed = false
  dialog.value?.close()
  opened.value = false
  if (wasOpen && !disposed) trigger.value?.focus({ preventScroll: true })
}
watch(() => [props.lat, props.lon, props.name], close)
onBeforeUnmount(() => { disposed = true; close() })
</script>

<template>
  <button v-if="links.length" ref="trigger" type="button" class="map-trigger" aria-haspopup="dialog" :aria-expanded="opened" @click.stop="open">
    <AppIcon name="location" :size="17" />{{ t('Conferir no mapa') }}
  </button>
  <Teleport to="body">
    <dialog v-if="opened" ref="dialog" class="map-chooser" :aria-labelledby="titleID" @cancel.prevent.stop="close"
      @pointerdown="backdropPressed = $event.target === $event.currentTarget" @pointercancel="backdropPressed = false"
      @click.stop="backdropPressed && $event.target === $event.currentTarget && close()">
      <header><h2 :id="titleID">{{ t('Conferir no mapa') }}</h2><button type="button" class="icon-btn" :aria-label="t('Fechar')" @click="close"><AppIcon name="close" :size="21" /></button></header>
      <p>{{ t('Escolha onde abrir esta localização.') }}</p>
      <nav class="map-options" :aria-label="t('Abrir localização no mapa')">
        <a v-for="link in links" :key="link.provider" :href="link.href"
          :aria-label="t('Abrir no {provider} (nova aba)', { provider: link.label })"
          target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" @click="close">
          <AppIcon name="location" :size="21" /><span>{{ link.label }}</span><span class="map-external" aria-hidden="true">↗</span>
        </a>
      </nav>
    </dialog>
  </Teleport>
</template>

<style scoped>
.map-trigger { display: inline-flex; align-items: center; gap: 6px; min-height: 44px; max-width: 100%; padding: 6px 0; margin-top: 4px; color: var(--accent); font-size: 13px; text-align: start; }
.map-trigger svg { flex-shrink: 0; }
.map-chooser { width: min(360px, calc(100% - 28px)); max-height: calc(var(--app-height, 100dvh) - 28px); overflow-y: auto; overscroll-behavior: contain; padding: 18px; border: 1px solid var(--line); border-radius: 20px; background: var(--bg-panel); color: var(--text); box-shadow: 0 24px 90px #0006; }
.map-chooser::backdrop { background: #0007; backdrop-filter: blur(3px); }
header { display: flex; align-items: center; gap: 12px; } h2 { flex: 1; margin: 0; font-size: 18px; } header button { width: 40px; height: 40px; flex-shrink: 0; }
p { margin: 7px 0 16px; color: var(--text-dim); font-size: 13px; line-height: 1.5; }
.map-options { display: grid; gap: 8px; }
.map-options a { display: flex; align-items: center; gap: 12px; min-height: 52px; padding: 12px; border: 1px solid var(--line); border-radius: 12px; background: var(--bg-raised); color: var(--text); font-size: 14px; text-decoration: none; }
.map-options a > svg { flex-shrink: 0; color: var(--accent); }.map-options a > span:first-of-type { flex: 1; min-width: 0; overflow-wrap: anywhere; }.map-external { color: var(--text-dim); }
.map-trigger:focus-visible, .map-options a:focus-visible, header button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
@media (hover: hover) { .map-trigger:hover { text-decoration: underline; }.map-options a:hover { background: var(--bg-active); } }
</style>
