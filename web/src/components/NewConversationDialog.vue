<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as P from '../api/protocol'
import { state } from '../state/archive'
import { canConversationAction, createGroup, groupValidation, normalizePhone, participantsFromText, startConversation, type ActionOutcome } from '../state/conversationActions'
import { t } from '../ui/i18n'

const emit = defineEmits<{ close: [] }>()
const dialog = ref<HTMLDialogElement>()
const mode = ref<'chat' | 'group'>(canConversationAction(P.TypeChatStart) ? 'chat' : 'group')
const phone = ref('')
const name = ref('')
const participants = ref('')
const busy = ref(false)
const result = ref<ActionOutcome>()
let disposed = false
const allowed = computed(() => canConversationAction(mode.value === 'chat' ? P.TypeChatStart : P.TypeGroupCreate))
const validation = computed(() => mode.value === 'chat'
  ? normalizePhone(phone.value) ? '' : t('Use um número com código do país, como +5511999999999.')
  : groupValidation({ name: name.value, participants: participantsFromText(participants.value) }))
const locked = computed(() => busy.value || result.value?.uncertain || result.value?.ok)
function close() { if (!busy.value) { disposed = true; emit('close') } }
function setMode(value: 'chat' | 'group') { if (!locked.value) { mode.value = value; result.value = undefined } }
async function submit() {
  if (locked.value || !allowed.value) return
  if (validation.value) { result.value = { ok: false, error: validation.value }; return }
  busy.value = true; result.value = undefined
  try {
    const outcome = mode.value === 'chat' ? await startConversation(phone.value) : await createGroup({ name: name.value, participants: participantsFromText(participants.value) })
    if (disposed) return
    result.value = outcome
    if (outcome.stale || outcome.ok && !outcome.warning && !outcome.failed?.length) emit('close')
  } catch {
    if (!disposed) result.value = { ok: false, uncertain: true, error: t('A confirmação não chegou. A ação pode ter sido concluída no WhatsApp. Verifique antes de tentar novamente.') }
  } finally { busy.value = false }
}
watch(() => [state.deviceID, state.tenantID, state.connected, state.view], () => { disposed = true; emit('close') }, { flush: 'sync' })
onMounted(async () => { dialog.value?.showModal(); await nextTick(); dialog.value?.querySelector<HTMLInputElement>('input')?.focus() })
onBeforeUnmount(() => { disposed = true })
</script>

<template>
  <Teleport to="body">
    <dialog ref="dialog" class="new-conversation-dialog" aria-labelledby="new-conversation-title" @cancel.prevent="close" @click="event => { if (event.target === dialog) close() }">
      <header><h2 id="new-conversation-title">{{ t('Nova conversa') }}</h2><button type="button" class="icon-btn" :disabled="busy" :aria-label="t('Fechar')" @click="close">✕</button></header>
      <div class="new-conversation-tabs" role="tablist" :aria-label="t('Tipo de conversa')">
        <button v-if="canConversationAction(P.TypeChatStart)" type="button" role="tab" :aria-selected="mode === 'chat'" :disabled="locked" @click="setMode('chat')">{{ t('Contato') }}</button>
        <button v-if="canConversationAction(P.TypeGroupCreate)" type="button" role="tab" :aria-selected="mode === 'group'" :disabled="locked" @click="setMode('group')">{{ t('Novo grupo') }}</button>
      </div>
      <form @submit.prevent="submit">
        <template v-if="mode === 'chat'">
          <label for="new-chat-phone">{{ t('Número do WhatsApp') }}</label>
          <input id="new-chat-phone" v-model="phone" type="tel" inputmode="tel" autocomplete="tel" placeholder="+55 11 99999-9999" :disabled="locked" required />
          <p class="new-conversation-note">{{ t('Inclua o código do país. Nenhuma mensagem será enviada ao abrir a conversa.') }}</p>
        </template>
        <template v-else>
          <label for="new-group-name">{{ t('Nome do grupo') }}</label>
          <input id="new-group-name" v-model="name" autocomplete="off" :disabled="locked" required />
          <small>{{ [...name.trim()].length }}/100</small>
          <label for="new-group-people">{{ t('Participantes') }}</label>
          <textarea id="new-group-people" v-model="participants" rows="5" :placeholder="t('Um número com código do país por linha')" :disabled="locked" required />
          <p class="new-conversation-note">{{ t('Adicione até 32 participantes. O grupo será criado no WhatsApp e os participantes poderão receber uma notificação.') }}</p>
        </template>
        <p v-if="result?.error" class="alert" role="alert">{{ result.error }}</p>
        <div v-if="result?.ok" class="new-conversation-result" role="status">
          <strong>{{ mode === 'group' ? t('Grupo criado') : t('Conversa aberta') }}</strong>
          <p v-if="result.warning">{{ result.warning }}</p>
          <p v-if="result.failed?.length">{{ t('Não foi possível adicionar: {participants}.', { participants: result.failed.join(', ') }) }}</p>
          <p v-if="result.failed?.length">{{ t('Confira os participantes nas informações do grupo antes de tentar adicionar novamente.') }}</p>
        </div>
        <footer>
          <button type="button" class="ghost" :disabled="busy" @click="close">{{ result?.ok || result?.uncertain ? t('Fechar') : t('Cancelar') }}</button>
          <button v-if="!result?.ok && !result?.uncertain" type="submit" class="primary" :disabled="busy || !allowed">{{ busy ? t('Aguarde a confirmação…') : mode === 'group' ? t('Criar grupo') : t('Abrir conversa') }}</button>
        </footer>
      </form>
    </dialog>
  </Teleport>
</template>

<style scoped>
.new-conversation-dialog { width: min(480px, calc(100% - 28px)); max-height: calc(100dvh - 28px); overflow-y: auto; background: var(--bg-panel); color: var(--text); border: 1px solid var(--line); border-radius: 22px; padding: 24px; box-shadow: 0 24px 90px #0006; }
.new-conversation-dialog::backdrop { background: #0007; backdrop-filter: blur(3px); }
header { display: flex; align-items: center; gap: 12px; margin-bottom: 18px; } h2 { flex: 1; margin: 0; font-size: 22px; letter-spacing: -.5px; }
.new-conversation-tabs { display: flex; gap: 6px; padding: 4px; background: var(--bg-active); border-radius: 12px; margin-bottom: 24px; }
.new-conversation-tabs button { flex: 1; min-height: 42px; border-radius: 9px; color: var(--text-dim); }
.new-conversation-tabs button[aria-selected='true'] { background: var(--bg-panel); color: var(--text); box-shadow: 0 2px 6px #0001; }
form { display: grid; gap: 10px; } label { font-size: 13px; font-weight: 600; } input, textarea { min-height: 46px; border-radius: 11px; font-size: 16px; } textarea { resize: vertical; }
small { text-align: right; color: var(--text-dim); margin-bottom: 8px; } .new-conversation-note { margin: 2px 0 14px; color: var(--text-dim); font-size: 13px; line-height: 1.55; }
footer { display: flex; justify-content: flex-end; gap: 10px; margin-top: 14px; } footer button { min-height: 44px; padding-inline: 18px; border-radius: 11px; }
.new-conversation-result { border: 1px solid var(--line); border-radius: 12px; padding: 15px; line-height: 1.55; } .new-conversation-result p { font-size: 13px; margin: 8px 0 0; }
button:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
@media (max-width: 500px) { .new-conversation-dialog { padding: 20px; } }
</style>
