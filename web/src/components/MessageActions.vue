<script setup lang="ts">
import { t } from '../ui/i18n'
import { computed, nextTick, onBeforeUnmount, ref, useId } from 'vue'

import { canSend, type MessageView } from '../state/archive'
import { canDelete, canEdit, editableFor, myReaction, nowTick, react, revoke } from '../state/actions'
import { hasExpired, isEphemeral, timerLabel } from '../state/ephemeral'
import { forgetSeen } from '../state/reading'
import { stamp, typeLabel } from '../ui/format'
import AppIcon from './AppIcon.vue'

const props = defineProps<{ message: MessageView }>()
const emit = defineEmits<{
  reply: [waID: string]
  edit: [uid: string]
  info: []
  selectText: []
  opened: []
  closed: []
}>()

const m = computed(() => props.message)
const menu = ref<HTMLDialogElement | null>(null)
const menuOpen = ref(false)
const confirming = ref(false)
const copyError = ref('')
const titleID = useId()
let backdropPressed = false
const mutable = computed(() => !m.value.pending && !m.value.deleted && !m.value.isStatus)
const connected = computed(() => canSend())
const text = computed(() => m.value.bodyState === 'ok' ? m.value.body ?? '' : '')
const mine = computed(() => myReaction(m.value))
const minutesLeft = computed(() => Math.ceil(editableFor(m.value) / 60_000))
const QUICK = ['👍', '❤️', '😂', '😮', '😢', '🙏']

const timerNote = computed(() => {
  if (!isEphemeral(m.value)) return ''
  if (m.value.expiresAt) {
    return hasExpired(m.value, nowTick.value)
      ? t('Mensagem temporária expirada em {time}', { time: stamp(m.value.expiresAt) })
      : t('Mensagem temporária até {time}', { time: stamp(m.value.expiresAt) })
  }
  return m.value.expiration > 0 ? t('Temporária, prazo de {v0}', { v0: timerLabel(m.value.expiration) }) : t('Mensagem temporária')
})

async function open() {
  if (!menu.value || menu.value.open || menuOpen.value) return
  confirming.value = false
  copyError.value = ''
  forgetSeen()
  backdropPressed = false
  menuOpen.value = true
  await nextTick()
  if (!menu.value || !menuOpen.value) return
  menu.value.showModal()
  emit('opened')
}

function close() {
  if (menu.value?.open) menu.value.close()
  else if (menuOpen.value) closed()
}

function closed() {
  menuOpen.value = false
  confirming.value = false
  emit('closed')
}

function reply() { close(); emit('reply', m.value.waID) }
function edit() { close(); emit('edit', m.value.uid) }
function info() { close(); emit('info') }
function selectText() { close(); emit('selectText') }

async function copy() {
  try {
    await navigator.clipboard.writeText(text.value)
    close()
  } catch {
    copyError.value = t('Não foi possível copiar. Use Selecionar texto.')
  }
}

async function pick(emoji: string) {
  if (!mutable.value || !connected.value) return
  const message = m.value
  close()
  await react(message, emoji)
}

async function destroy() {
  if (!canDelete(m.value) || !connected.value) return
  const message = m.value
  close()
  await revoke(message)
}

defineExpose({ open, close })
onBeforeUnmount(close)
</script>

<template>
  <div class="message-actions" @pointerdown.stop @click.stop @keydown.stop @contextmenu.stop>
    <button class="action-trigger" type="button" :title="t('Ações da mensagem')" :aria-label="t('Ações da mensagem')"
      aria-haspopup="dialog" :aria-expanded="menuOpen" @click="open">
      <AppIcon name="chevron-down" :size="18" />
    </button>

    <dialog ref="menu" class="message-menu" :aria-labelledby="titleID" @close="closed"
      @pointerdown="backdropPressed = $event.target === $event.currentTarget"
      @pointercancel="backdropPressed = false"
      @click="backdropPressed && ($event.target === $event.currentTarget) && close()">
      <template v-if="menuOpen">
      <div class="menu-handle" aria-hidden="true" />
      <header class="menu-heading">
        <div>
          <h2 :id="titleID">{{ t('Ações da mensagem') }}</h2>
          <p :class="{ 'revoked-preview': m.deleted }">{{ text || typeLabel(m.type) }}</p>
        </div>
        <button class="menu-close" type="button" :aria-label="t('Fechar ações')" @click="close"><AppIcon name="close" :size="20" /></button>
      </header>

      <div v-if="mutable && !confirming" class="quick-reactions" :aria-label="t('Reações rápidas')">
        <button v-for="emoji in QUICK" :key="emoji" class="quick-reaction" type="button"
          :class="{ chosen: mine === emoji }" :aria-pressed="mine === emoji"
          :aria-label="mine === emoji ? t('Remover reação {v0}', { v0: emoji }) : t('Reagir com {v0}', { v0: emoji })"
          :disabled="!connected" @click="pick(emoji)">{{ emoji }}</button>
      </div>

      <div v-if="confirming" class="delete-confirmation">
        <p>{{ t('Apagar esta mensagem para todos?') }}</p>
        <p class="menu-note">{{ t('A cópia arquivada continuará disponível.') }}</p>
        <button class="menu-action danger" type="button" :disabled="!connected" @click="destroy"><AppIcon name="trash" /> {{ t('Apagar para todos') }}</button>
        <button class="menu-action" type="button" @click="confirming = false"><AppIcon name="back" /> {{ t('Voltar') }}</button>
      </div>
      <div v-else class="menu-options">
        <button v-if="mutable" class="menu-action" type="button" @click="reply">
          <AppIcon name="back" /><span class="action-copy"><strong>{{ t('Responder') }}</strong><small>{{ t('Citar esta mensagem na conversa') }}</small></span><span class="action-hint">{{ t('Deslize →') }}</span>
        </button>
        <button v-if="text" class="menu-action" type="button" @click="copy">
          <AppIcon name="copy" /><span class="action-copy"><strong>{{ t('Copiar texto') }}</strong><small>{{ t('Copiar o conteúdo da mensagem') }}</small></span>
        </button>
        <button v-if="text" class="menu-action" type="button" @click="selectText">
          <AppIcon name="select-text" /><span class="action-copy"><strong>{{ t('Selecionar texto') }}</strong><small>{{ t('Selecionar o conteúdo para copiar um trecho') }}</small></span>
        </button>
        <button v-if="canEdit(m)" class="menu-action" type="button" :disabled="!connected" @click="edit">
          <AppIcon name="pencil" /><span class="action-copy"><strong>{{ t('Editar') }}</strong><small>{{ t('Alterar o texto enviado') }}</small></span><span class="action-hint">{{ t('{v0} min', { v0: minutesLeft }) }}</span>
        </button>
        <button class="menu-action" type="button" @click="info">
          <AppIcon name="info" class="message-info-icon" /><span class="action-copy"><strong>{{ t('Info da mensagem') }}</strong><small>{{ t('Ver versões e confirmações de leitura') }}</small></span>
        </button>
        <button v-if="canDelete(m)" class="menu-action danger" type="button" :disabled="!connected" @click="confirming = true">
          <AppIcon name="trash" /><span class="action-copy"><strong>{{ t('Apagar para todos') }}</strong><small>{{ t('Remover a mensagem do WhatsApp') }}</small></span>
        </button>
      </div>
      <div v-if="m.viewOnce || timerNote || m.edited || m.deleted" class="message-facts">
        <p v-if="m.viewOnce" class="menu-note"><AppIcon name="view-once" :size="16" />{{ t('Mensagem de visualização única') }}</p>
        <p v-if="timerNote" class="menu-note"><AppIcon name="timer" :size="16" />{{ timerNote }}</p>
        <p v-if="m.edited" class="menu-note"><AppIcon name="pencil" :size="16" />{{ t('Mensagem editada · {count} versões', { count: m.versionCount }) }}</p>
        <p v-if="m.deleted" class="menu-note"><AppIcon name="trash" :size="16" />{{ t('Mensagem apagada') }}</p>
      </div>
      <p v-if="copyError" class="copy-error" role="alert">{{ copyError }}</p>
      </template>
    </dialog>
  </div>
</template>

<style scoped>
.message-actions { position: absolute; top: 2px; right: 2px; z-index: 2; }
.action-trigger { display: grid; place-items: center; width: 28px; height: 28px; padding: 0; border-radius: 8px; color: var(--text-dim); opacity: .5; }
.action-trigger:hover, .action-trigger:focus-visible { background: var(--bg-hover); opacity: 1; }
.action-trigger:focus-visible, .menu-action:focus-visible, .quick-reaction:focus-visible, .menu-close:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.message-menu { position: fixed; top: calc(var(--app-top, 0px) + var(--app-height, 100dvh) / 2); bottom: auto; inset-inline: 0; margin: 0 auto; transform: translateY(-50%); width: min(390px, calc(100% - 32px)); max-height: min(680px, calc(var(--app-height, 100dvh) - 24px)); overflow-y: auto; overscroll-behavior: contain; padding: 10px; border: 1px solid var(--line); border-radius: 20px; color: var(--text); background: var(--bg-panel); box-shadow: 0 20px 70px #0004; }
.message-menu[open] { animation: menu-appear 160ms ease-out; }
.message-menu::backdrop { background: #0005; }
.menu-handle { display: none; }
.menu-heading { display: flex; align-items: flex-start; gap: 12px; padding: 8px 6px 10px 10px; }
.menu-heading > div { flex: 1; min-width: 0; }
.menu-heading h2 { font-size: 16px; margin: 0; }
.menu-heading p { margin: 6px 0 0; color: var(--text-dim); font-size: 13px; line-height: 1.4; overflow: hidden; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; white-space: pre-wrap; overflow-wrap: anywhere; }
.menu-heading p.revoked-preview { opacity: .6; text-decoration: line-through; }
.menu-close { display: grid; place-items: center; width: 36px; height: 36px; flex-shrink: 0; border-radius: 50%; background: var(--bg-hover); }
.quick-reactions { display: flex; justify-content: space-between; gap: 3px; padding: 10px 2px 14px; border-bottom: 1px solid var(--line); }
.quick-reaction { display: grid; place-items: center; flex: 1; height: 44px; font-size: 28px; padding: 0; border-radius: 50%; transition: transform 120ms ease-out, background 120ms; }
.quick-reaction:hover { background: var(--bg-hover); transform: scale(1.13); }
.quick-reaction.chosen { background: var(--bg-active); box-shadow: inset 0 0 0 2px var(--accent); }
.menu-options { padding-top: 6px; }
.menu-action { display: flex; align-items: center; gap: 14px; width: 100%; min-height: 48px; padding: 10px 12px; border-radius: 11px; text-align: left; font-size: 15px; }
.menu-action:hover { background: var(--bg-hover); }
.menu-action svg { width: 22px; height: 22px; flex-shrink: 0; fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.menu-action > span:first-of-type { flex: 1; }
.action-copy { min-width: 0; }
.action-copy strong { display: block; font-size: 14px; font-weight: 550; }
.action-copy small { display: block; margin-top: 3px; color: var(--text-dim); font-size: 11px; line-height: 1.4; }
.action-hint { font-size: 12px; color: var(--text-dim); }
.menu-action.danger { color: var(--danger); background: transparent; border: 0; font-weight: inherit; }
.menu-action.danger:hover { background: color-mix(in srgb, var(--danger) 8%, transparent); }
.message-info-icon { color: var(--message-info); }
.menu-note { font-size: 12px; color: var(--text-dim); margin: 10px; }
.message-facts { border-top: 1px solid var(--line); margin: 6px 10px 2px; padding-top: 4px; }
.message-facts .menu-note { display: flex; gap: 8px; align-items: center; font-size: 11px; margin: 8px 0; }
.delete-confirmation > p:first-child { margin: 14px 10px 0; font-weight: 600; }
.copy-error { margin: 8px 10px; color: var(--danger); font-size: 13px; }
button:disabled { opacity: .4; cursor: default; }
@media (hover: hover) and (pointer: fine) {
  .action-trigger { opacity: 0; }
  :global(.bubble:hover) .action-trigger, :global(.bubble:focus-within) .action-trigger { opacity: 1; }
}
@media (max-width: 760px), (max-height: 500px) and (pointer: coarse) {
  .action-trigger { width: 32px; height: 32px; }
  .message-menu { width: 100%; max-width: 100%; top: calc(var(--app-top, 0px) + var(--app-height, 100dvh)); transform: translateY(-100%); border-radius: 22px 22px 0 0; padding: 8px 12px max(12px, env(safe-area-inset-bottom)); border-bottom: 0; max-height: calc(var(--app-height, 100dvh) - 16px); }
  .message-menu[open] { animation-name: sheet-appear; }
  .menu-handle { display: block; width: 34px; height: 4px; margin: 0 auto 12px; border-radius: 4px; background: var(--line); }
}
@keyframes menu-appear { from { opacity: 0; transform: translateY(calc(-50% + 8px)); } to { opacity: 1; transform: translateY(-50%); } }
@keyframes sheet-appear { from { opacity: 0; transform: translateY(calc(-100% + 16px)); } to { opacity: 1; transform: translateY(-100%); } }
@media (prefers-reduced-motion: reduce) { .message-menu[open] { animation: none; } .quick-reaction { transition: none; } }
</style>
