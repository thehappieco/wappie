<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import { connection, credential, people, state, type MessageView } from '../state/archive'
import { canForward, createForwarder, destinationJID, type ForwardMark, type ForwardOutcome } from '../state/forwarding'
import { normalizePhone } from '../state/conversationActions'
import { TypeChatStart } from '../api/protocol'
import { typeLabel } from '../ui/format'
import { t } from '../ui/i18n'
import AppIcon from './AppIcon.vue'
import AvatarBadge from './AvatarBadge.vue'

const props = defineProps<{ message: MessageView }>()
const emit = defineEmits<{ close: [] }>()
const titleID = useId()
const dialog = ref<HTMLDialogElement | null>(null)
const query = ref('')
const selected = ref('')
const selectedName = ref('')
const mark = ref<ForwardMark>(props.message.forwardingScore >= 5 ? 'many' : 'forwarded')
const busy = ref(false)
const result = ref<ForwardOutcome>()
const allowed = computed(() => canForward(props.message))
const locked = computed(() => busy.value || Boolean(result.value?.ok || result.value?.uncertain))
let sender = createForwarder(props.message)
let disposed = false
const backdropPressed = ref(false)
const initial = { tenant: state.tenantID, device: state.deviceID, chat: state.openChatKey, token: credential()?.token, view: state.view }

interface Recipient { key: string; name: string; group: boolean; avatar: string }
const recipients = computed<Recipient[]>(() => {
  // Directory itself is not reactive; the published count signals newly opened names.
  void state.contactsLoaded
  const rows: Recipient[] = []
  const seen = new Set<string>()
  function add(recipient: Recipient, aliases: (string | undefined)[]) {
    if (!destinationJID(recipient.key) || aliases.some(alias => alias && seen.has(alias))) return
    for (const alias of aliases) if (alias) seen.add(alias)
    rows.push(recipient)
  }
  for (const chat of state.chats) {
    if (chat.isStatus) continue
    const person = people().find(chat.key)
    add({ key: chat.key, name: chat.name, group: chat.isGroup, avatar: chat.avatarKey }, [chat.key, ...chat.keys, person?.pn, person?.lid])
  }
  for (const person of people().all()) {
    if (person.isGroup) continue
    const key = person.pn || person.lid || person.key
    add({ key, name: people().nameFor(key), group: false, avatar: person.key }, [person.key, person.pn, person.lid])
  }
  const term = query.value.trim().toLocaleLowerCase()
  return rows.filter(row => !term || row.name.toLocaleLowerCase().includes(term) || row.key.includes(term.replace(/[\s()+.-]/g, ''))).slice(0, 80)
})
const phone = computed(() => connection()?.welcome.features.includes(TypeChatStart) ? normalizePhone(query.value) : '')

function choose(key: string, name: string) {
  if (disposed || locked.value) return
  selected.value = key
  selectedName.value = name
  result.value = undefined
}
function close() {
  disposed = true
  sender.dispose()
  emit('close')
}
async function submit() {
  if (disposed || locked.value || !selected.value || !allowed.value) return
  busy.value = true
  result.value = undefined
  try {
    const outcome = await sender.forward(selected.value, mark.value)
    if (disposed || outcome.stale) return
    result.value = outcome
  } catch {
    if (!disposed) result.value = { ok: false, uncertain: true, error: t('A confirmação não chegou. Verifique a conversa de destino antes de reencaminhar novamente.') }
  } finally { if (!disposed) busy.value = false }
}
function anotherRecipient() {
  if (disposed || !result.value?.ok || busy.value) return
  sender.dispose()
  sender = createForwarder(props.message)
  result.value = undefined
  selected.value = ''; selectedName.value = ''; query.value = ''
}
watch(() => [state.tenantID, state.deviceID, state.openChatKey, state.view, state.connected, credential()?.token], () => {
  if (state.tenantID !== initial.tenant || state.deviceID !== initial.device || state.openChatKey !== initial.chat || state.view !== initial.view
    || !state.connected || credential()?.token !== initial.token) {
    disposed = true
    sender.dispose()
    emit('close')
  }
}, { flush: 'sync' })
onMounted(async () => { await nextTick(); if (!disposed) dialog.value?.showModal() })
onBeforeUnmount(() => { disposed = true; sender.dispose(); dialog.value?.close() })
</script>

<template>
  <Teleport to="body">
    <dialog ref="dialog" class="forward-dialog" :aria-labelledby="titleID" @cancel.prevent="close"
      @pointerdown="backdropPressed = $event.target === $event.currentTarget" @pointercancel="backdropPressed = false"
      @click="backdropPressed && $event.target === $event.currentTarget && close()">
      <header><AppIcon name="forward" /><h2 :id="titleID">{{ t('Reencaminhar mensagem') }}</h2><button type="button" class="icon-btn" :aria-label="t('Fechar')" @click="close"><AppIcon name="close" /></button></header>
      <div class="forward-preview">
        <img v-if="message.media?.thumbURL" :src="message.media.thumbURL" alt="" />
        <div><strong>{{ typeLabel(message.type) }}</strong><p v-if="message.body">{{ message.body }}</p></div>
      </div>
      <form @submit.prevent="submit">
        <template v-if="!result?.ok && !result?.uncertain">
          <label class="search"><AppIcon name="search" :size="19" /><input v-model="query" type="search" :disabled="busy" autocomplete="off"
            :aria-label="t('Buscar pessoa ou conversa')" :placeholder="t('Buscar pessoa ou conversa')" @input="selected = ''; selectedName = ''" /></label>
          <div class="recipients" role="group" :aria-label="t('Destinatário')">
            <button v-if="phone" class="recipient" type="button" :disabled="busy" :class="{ chosen: selected === phone }" :aria-pressed="selected === phone" @click="choose(phone, phone)">
              <span class="phone-icon"><AppIcon name="message" /></span><span><strong>{{ phone }}</strong><small>{{ t('Enviar para este número') }}</small></span><AppIcon v-if="selected === phone" name="check" />
            </button>
            <button v-for="recipient in recipients" :key="recipient.key" class="recipient" type="button" :disabled="busy" :class="{ chosen: selected === recipient.key }"
              :aria-pressed="selected === recipient.key" @click="choose(recipient.key, recipient.name)">
              <AvatarBadge :contact-key="recipient.avatar" :name="recipient.name" :is-group="recipient.group" small />
              <span><strong>{{ recipient.name }}</strong><small v-if="recipient.group">{{ t('Grupo') }}</small></span><AppIcon v-if="selected === recipient.key" name="check" />
            </button>
            <p v-if="!recipients.length && !phone" class="note">{{ t('Nenhuma conversa encontrada. Busque outro nome ou número.') }}</p>
          </div>
          <fieldset :disabled="busy"><legend>{{ t('Identificação da mensagem') }}</legend>
            <label><input v-model="mark" type="radio" value="forwarded" />{{ t('Encaminhada') }}</label>
            <label><input v-model="mark" type="radio" value="many" />{{ t('Encaminhada muitas vezes') }}</label>
            <label><input v-model="mark" type="radio" value="none" />{{ t('Sem marca de encaminhamento') }}</label>
          </fieldset>
          <p v-if="selectedName" class="destination">{{ t('Para: {name}', { name: selectedName }) }}</p>
          <p v-if="!allowed" class="note">{{ t('Seu acesso ou a conexão atual não permite esta ação.') }}</p>
        </template>
        <div v-if="result?.ok" class="forward-success" role="status"><AppIcon name="check" /><strong>{{ t('Mensagem reencaminhada para {name}.', { name: selectedName }) }}</strong></div>
        <p v-if="result?.warning" class="note" role="status">{{ result.warning }}</p>
        <p v-if="result?.error" class="error" role="alert">{{ result.error }}</p>
        <p v-if="busy" class="note" role="status">{{ t('Você pode fechar esta janela. Se o envio já começou, confira a conversa de destino.') }}</p>
        <footer>
          <button type="button" class="ghost" @click="close">{{ busy || result?.ok || result?.uncertain ? t('Fechar') : t('Cancelar') }}</button>
          <button v-if="result?.ok" type="button" class="primary" @click="anotherRecipient">{{ t('Escolher outro destinatário') }}</button>
          <button v-else-if="!result?.uncertain" type="submit" class="primary" :disabled="busy || !allowed || !selected"><AppIcon name="forward" :size="18" />{{ busy ? t('Reencaminhando…') : t('Reencaminhar') }}</button>
        </footer>
      </form>
    </dialog>
  </Teleport>
</template>

<style scoped>
.forward-dialog { width: min(460px, calc(100% - 28px)); max-height: calc(var(--app-height, 100dvh) - 28px); padding: 20px; border: 1px solid var(--line); border-radius: 22px; background: var(--bg-panel); color: var(--text); overflow-y: auto; overscroll-behavior: contain; box-shadow: 0 24px 90px #0006; }
.forward-dialog::backdrop { background: #0007; backdrop-filter: blur(3px); }
header { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; } h2 { flex: 1; font-size: 19px; margin: 0; }
.forward-preview { display: flex; align-items: center; gap: 12px; padding: 12px; border-left: 3px solid var(--accent); border-radius: 10px; background: var(--bg-hover); margin-bottom: 16px; }
.forward-preview img { width: 44px; height: 44px; border-radius: 6px; object-fit: cover; } .forward-preview > div { min-width: 0; } .forward-preview strong { font-size: 12px; color: var(--text-dim); }
.forward-preview p { margin: 5px 0 0; font-size: 13px; line-height: 1.4; white-space: pre-wrap; overflow-wrap: anywhere; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.search { display: flex; align-items: center; gap: 8px; padding-left: 12px; border: 1px solid var(--line); border-radius: 12px; background: var(--bg-input); color: var(--text-dim); }
.search input { width: 100%; min-width: 0; border: 0; background: transparent; font-size: 16px; min-height: 44px; color: var(--text); }
.recipients { max-height: min(280px, 31dvh); overflow-y: auto; overscroll-behavior: contain; margin: 10px -4px 16px; padding: 4px; }
.recipient { display: flex; width: 100%; align-items: center; gap: 12px; padding: 10px; border-radius: 12px; min-height: 58px; text-align: left; }
.recipient > span:not(.phone-icon) { flex: 1; min-width: 0; } .recipient strong { display: block; font-weight: 550; font-size: 14px; overflow-wrap: anywhere; } .recipient small { display: block; margin-top: 3px; color: var(--text-dim); font-size: 12px; }
.recipient:hover, .recipient.chosen { background: var(--bg-active); } .recipient.chosen > svg { color: var(--accent); }
.phone-icon { width: 34px; height: 34px; border-radius: 50%; background: var(--bg-hover); display: grid; place-items: center; }
fieldset { display: grid; gap: 6px; border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; } legend { padding: 0 6px; color: var(--text-dim); font-size: 12px; }
fieldset label { display: flex; align-items: center; gap: 10px; min-height: 30px; font-size: 13px; } input[type='radio'] { accent-color: var(--accent); width: 16px; height: 16px; }
.destination { font-size: 13px; margin: 14px 0 0; font-weight: 550; overflow-wrap: anywhere; } .note, .error { font-size: 13px; line-height: 1.5; } .note { color: var(--text-dim); } .error { color: var(--danger); }
.forward-success { display: flex; gap: 10px; line-height: 1.5; padding: 16px 0; } .forward-success > svg { color: var(--accent); flex-shrink: 0; }
footer { display: flex; gap: 10px; justify-content: flex-end; margin-top: 18px; } footer button { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 14px; min-height: 44px; border-radius: 11px; }
button:disabled { opacity: .45; cursor: default; } button:focus-visible, input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
@media (max-width: 500px) { .forward-dialog { padding: 16px; } }
</style>
