<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, useId } from 'vue'
import { t } from '../ui/i18n'
import AppIcon from './AppIcon.vue'
const props = withDefaults(defineProps<{ title: string; subtitle?: string; busy?: boolean; drawer?: boolean; anchor?: HTMLElement | null; wide?: boolean }>(), { busy: false })
const emit = defineEmits<{ close: [] }>()
const dialog = ref<HTMLDialogElement>()
const titleID = useId()
const placement = ref<Record<string, string>>({})
let origin: HTMLElement | null = null, disposed = false, backdrop = false
function close() { if (!props.busy) emit('close') }
function pointerDown(event: PointerEvent) { backdrop = event.target === event.currentTarget }
function backdropClick(event: MouseEvent) { if (backdrop && event.target === event.currentTarget) close(); backdrop = false }
onMounted(async () => {
  origin = document.activeElement instanceof HTMLElement ? document.activeElement : null
  if (props.anchor && window.innerWidth > 760) {
    const bounds = props.anchor.getBoundingClientRect()
    const width = Math.min(360, window.innerWidth - 32)
    placement.value = { left: `${Math.min(Math.max(16, bounds.left), window.innerWidth - width - 16)}px`, top: `${Math.min(bounds.bottom + 8, Math.max(16, window.innerHeight - 490))}px`, margin: '0', width: `${width}px` }
  }
  await nextTick()
  if (!disposed) dialog.value?.showModal()
})
onBeforeUnmount(() => { disposed = true; dialog.value?.close(); if (origin?.isConnected) origin.focus({ preventScroll: true }) })
</script>
<template>
  <Teleport to="body"><dialog ref="dialog" class="console-dialog" :class="{ 'is-drawer': drawer, 'is-popover': anchor, 'is-wide': wide }" :style="placement" :aria-labelledby="titleID" :aria-busy="busy"
    @cancel.prevent.stop="close" @pointerdown="pointerDown" @click="backdropClick">
    <div class="dialog-frame"><header><div class="grow"><h2 :id="titleID">{{ title }}</h2><p v-if="subtitle">{{ subtitle }}</p></div><button type="button" class="icon-btn" :disabled="busy" :aria-label="t('Fechar')" @click="close"><AppIcon name="close" :size="21" /></button></header><div class="dialog-content"><slot /></div></div>
  </dialog></Teleport>
</template>
<style scoped>
.console-dialog { width: min(520px, calc(100vw - 32px)); max-width: none; max-height: min(88dvh, 850px); padding: 0; border: 1px solid var(--line); border-radius: 20px; background: var(--bg-panel); color: var(--text); box-shadow: 0 24px 90px #0005; overflow: hidden; }
.console-dialog::backdrop { background: #0008; backdrop-filter: blur(3px); }.dialog-frame { display: flex; flex-direction: column; max-height: inherit; }.dialog-frame > header { display: flex; align-items: flex-start; gap: 14px; padding: 22px 22px 16px; flex: none; }.grow { min-width: 0; flex: 1; }h2 { margin: 0; font-size: 19px; letter-spacing: -.3px; }header p { color: var(--text-dim); font-size: 13px; line-height: 1.5; margin: 7px 0 0; }.dialog-content { padding: 0 22px 22px; overflow-y: auto; overscroll-behavior: contain; min-height: 0; }.is-wide { width: min(730px, calc(100vw - 32px)); }.is-popover { max-height: min(70dvh, 560px); }.is-popover .dialog-frame > header { padding: 16px 16px 12px; }.is-popover .dialog-content { padding: 0 12px 12px; }.is-popover h2 { font-size: 14px; color: var(--text-dim); }
:deep(input:not([type=checkbox]):not([type=radio])), :deep(select), :deep(textarea) { width: 100%; min-height: 44px; border: 1px solid var(--line); border-radius: 10px; background: var(--bg-input); color: var(--text); padding: 10px 12px; font: inherit; }:deep(input[type=checkbox]) { accent-color: var(--accent); }:deep(button) { min-height: 40px; }:deep(button:focus-visible), :deep(input:focus-visible), :deep(select:focus-visible) { outline: 2px solid var(--accent); outline-offset: 2px; }:deep(.form-stack) { display: grid; gap: 16px; }:deep(.form-stack label) { display: grid; gap: 8px; font-size: 13px; }:deep(.dialog-actions) { display: flex; justify-content: flex-end; flex-wrap: wrap; gap: 10px; margin-top: 6px; }:deep(.dim) { font-size: 13px; line-height: 1.55; }:deep(.alert) { margin-bottom: 12px; }
@media(max-width:760px) { .is-drawer { position: fixed; inset: 0 auto 0 0; margin: 0; height: 100dvh; max-height: 100dvh; width: min(340px, calc(100vw - 38px)); border-radius: 0 20px 20px 0; }.is-drawer .dialog-frame { height: 100%; }.is-drawer .dialog-content { flex: 1; }.console-dialog { max-height: 92dvh; } .is-popover { width: min(400px, calc(100vw - 28px)); } :deep(input), :deep(select), :deep(textarea) { font-size: 16px !important; }.dialog-content { padding-bottom: max(22px, env(safe-area-inset-bottom)); } }
</style>
