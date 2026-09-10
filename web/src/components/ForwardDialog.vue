<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import { connection, credential, people, state, type MessageView } from '../state/archive'
import { canForward, createForwardBatch, destinationJID, forwardRecipientResolver, MAX_FORWARD_RECIPIENTS, type ForwardMark, type ForwardBatchOutcome, type ForwardRecipient, type ForwardRecipientResult } from '../state/forwarding'
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
const selected = ref<ForwardRecipient[]>([])
const mark = ref<ForwardMark>(props.message.forwardingScore >= 5 ? 'many' : 'forwarded')
const busy = ref(false)
const result = ref<ForwardBatchOutcome>()
const results = ref<ForwardRecipientResult[]>([])
const allowed = computed(() => canForward(props.message))
const locked = computed(() => busy.value || Boolean(result.value && !result.value.error))
const uncertain = computed(() => results.value.some(row => row.state === 'uncertain'))
const identity = computed(() => { void state.contactsLoaded; return forwardRecipientResolver() })
let sender = createForwardBatch(props.message)
let disposed = false
const backdropPressed = ref(false)
const initial = { tenant: state.tenantID, device: state.deviceID, chat: state.openChatKey, token: credential()?.token, view: state.view }

interface Recipient { key: string; name: string; group: boolean; avatar: string }
const recipientDirectory = computed<Recipient[]>(() => {
  // Directory itself is not reactive; the published count signals newly opened names.
  void state.contactsLoaded
  const rows: Recipient[] = []
  const seen = new Set<string>()
  function add(recipient: Recipient, aliases: (string | undefined)[]) {
    const canonical = identity.value(recipient.key)
    if (!destinationJID(recipient.key) || seen.has(canonical)) return
    seen.add(canonical)
    for (const alias of aliases) if (alias) seen.add(identity.value(alias))
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
  return rows
})
const recipients = computed(() => {
  const term = query.value.trim().toLocaleLowerCase()
  return recipientDirectory.value.filter(row => !term || row.name.toLocaleLowerCase().includes(term) || row.key.includes(term.replace(/[\s()+.-]/g, ''))).slice(0, 80)
})
const selectedRecipients = computed<Recipient[]>(() => {
  const directory = new Map(recipientDirectory.value.map(row => [identity.value(row.key), row]))
  return selected.value.map(recipient => {
    const key = identity.value(recipient.key)
    const person = directory.get(key)
    return { ...recipient, avatar: person?.avatar || key, group: person?.group ?? key.endsWith('@g.us') }
  })
})
const phone = computed(() => connection()?.welcome.features.includes(TypeChatStart) ? normalizePhone(query.value) : '')

function isSelected(key: string): boolean {
  const canonical = identity.value(key)
  return Boolean(canonical && selected.value.some(recipient => identity.value(recipient.key) === canonical))
}
function choose(key: string, name: string) {
  if (disposed || locked.value) return
  const canonical = identity.value(key)
  if (!canonical) return
  const existing = selected.value.findIndex(recipient => identity.value(recipient.key) === canonical)
  if (existing >= 0) selected.value.splice(existing, 1)
  else if (selected.value.length < MAX_FORWARD_RECIPIENTS) selected.value.push({ key, name })
  result.value = undefined
}
function close() {
  disposed = true
  sender.dispose()
  emit('close')
}
async function submit() {
  if (disposed || locked.value || !selected.value.length || !allowed.value) return
  busy.value = true
  result.value = undefined
  try {
    const outcome = await sender.forward(selected.value, mark.value, update => { if (!disposed) results.value = update })
    if (disposed || outcome.stale) return
    results.value = outcome.results
    result.value = outcome
  } catch {
    if (!disposed) {
      // Preserve confirmed results; only the active recipient has ambiguous delivery.
      results.value = results.value.map(row => ({ ...row, state: row.state === 'sending' ? 'uncertain' : row.state === 'pending' ? 'cancelled' : row.state }))
      result.value = { results: results.value }
    }
  } finally { if (!disposed) busy.value = false }
}
function anotherRecipients() {
  if (disposed || busy.value || !result.value || uncertain.value) return
  sender.dispose()
  sender = createForwardBatch(props.message)
  result.value = undefined; results.value = []
  selected.value = []; query.value = ''
}
const resultGroups = computed(() => [
  { state: 'sent', title: t('Enviadas com confirmação') },
  { state: 'failed', title: t('Falha no envio') },
  { state: 'uncertain', title: t('Envio sem confirmação') },
  { state: 'duplicate', title: t('Destinatários repetidos') },
  { state: 'cancelled', title: t('Não enviadas') },
  { state: 'sending', title: t('Enviando agora') },
  { state: 'pending', title: t('Aguardando envio') },
].map(group => ({ ...group, rows: results.value.filter(row => row.state === group.state) })).filter(group => group.rows.length))
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
        <template v-if="!locked">
          <label class="search"><AppIcon name="search" :size="19" /><input v-model="query" type="search" autocomplete="off"
            :aria-label="t('Buscar pessoa ou conversa')" :placeholder="t('Buscar pessoa ou conversa')" /></label>
          <p class="selection-count" role="status">{{ t('{count} de {max} destinatários selecionados', { count: selected.length, max: MAX_FORWARD_RECIPIENTS }) }}</p>
          <div class="recipients" role="group" :aria-label="t('Destinatários')">
            <label v-if="phone" class="recipient" :class="{ chosen: isSelected(phone) }">
              <input type="checkbox" :checked="isSelected(phone)" :disabled="selected.length >= MAX_FORWARD_RECIPIENTS && !isSelected(phone)" @change="choose(phone, phone)" />
              <span class="phone-icon"><AppIcon name="message" /></span><span><strong>{{ phone }}</strong><small>{{ t('Enviar para este número') }}</small></span>
            </label>
            <label v-for="recipient in recipients" :key="recipient.key" class="recipient" :class="{ chosen: isSelected(recipient.key) }">
              <input type="checkbox" :checked="isSelected(recipient.key)" :disabled="selected.length >= MAX_FORWARD_RECIPIENTS && !isSelected(recipient.key)" @change="choose(recipient.key, recipient.name)" />
              <AvatarBadge :contact-key="recipient.avatar" :name="recipient.name" :is-group="recipient.group" small />
              <span><strong>{{ recipient.name }}</strong><small v-if="recipient.group">{{ t('Grupo') }}</small></span>
            </label>
            <p v-if="!recipients.length && !phone" class="note">{{ t('Nenhuma conversa encontrada. Busque outro nome ou número.') }}</p>
          </div>
          <fieldset><legend>{{ t('Identificação da mensagem') }}</legend>
            <label><input v-model="mark" type="radio" value="forwarded" />{{ t('Encaminhada') }}</label>
            <label><input v-model="mark" type="radio" value="many" />{{ t('Encaminhada muitas vezes') }}</label>
            <label><input v-model="mark" type="radio" value="none" />{{ t('Sem marca de encaminhamento') }}</label>
          </fieldset>
          <section v-if="selected.length" class="selected-list" :aria-label="t('Confirmar destinatários')">
            <strong>{{ t('Confirmar destinatários') }}</strong>
            <ul>
              <li v-for="recipient in selectedRecipients" :key="recipient.key">
                <AvatarBadge :contact-key="recipient.avatar" :name="recipient.name" :is-group="recipient.group" small />
                <span>{{ recipient.name }}</span>
                <button type="button" class="icon-btn" :aria-label="t('Remover {name}', { name: recipient.name })" @click="choose(recipient.key, recipient.name)"><AppIcon name="close" :size="16" /></button>
              </li>
            </ul>
          </section>
          <p v-if="!allowed" class="note">{{ t('Seu acesso ou a conexão atual não permite esta ação.') }}</p>
        </template>
        <div v-if="results.length" class="forward-results" aria-live="polite" :aria-label="t('Resultados por destinatário')">
          <section v-for="group in resultGroups" :key="group.state" :class="'result-' + group.state">
            <h3><AppIcon v-if="group.state === 'sent'" name="check" :size="17" />{{ group.title }} · {{ group.rows.length }}</h3>
            <ul><li v-for="row in group.rows" :key="row.recipient.key"><strong>{{ row.recipient.name }}</strong>
              <p v-if="row.outcome?.error || row.outcome?.warning">{{ row.outcome.error || row.outcome.warning }}</p>
              <p v-else-if="row.state === 'duplicate'">{{ t('Este destinatário foi incluído uma única vez.') }}</p>
            </li></ul>
          </section>
        </div>
        <p v-if="uncertain" class="note">{{ t('Verifique as conversas sem confirmação antes de tentar novamente.') }}</p>
        <p v-if="result?.error" class="error" role="alert">{{ result.error }}</p>
        <p v-if="busy" class="note" role="status">{{ t('Fechar interrompe os próximos envios. Uma mensagem já enviada pode chegar mesmo assim.') }}</p>
        <footer>
          <button type="button" class="ghost" @click="close">{{ locked ? t('Fechar') : t('Cancelar') }}</button>
          <button v-if="result && !result.error && !uncertain" type="button" class="primary" @click="anotherRecipients">{{ t('Escolher outros destinatários') }}</button>
          <button v-else-if="!result || result.error" type="submit" class="primary" :disabled="busy || !allowed || !selected.length"><AppIcon name="forward" :size="18" />{{ busy ? t('Reencaminhando…') : t('Reencaminhar para {count}', { count: selected.length }) }}</button>
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
.recipient > span:last-child { flex: 1; min-width: 0; } .recipient strong { display: block; font-weight: 550; font-size: 14px; overflow-wrap: anywhere; } .recipient small { display: block; margin-top: 3px; color: var(--text-dim); font-size: 12px; }
.recipient:hover, .recipient.chosen { background: var(--bg-active); } .recipient.chosen > svg { color: var(--accent); }
.phone-icon { width: 34px; height: 34px; border-radius: 50%; background: var(--bg-hover); display: grid; place-items: center; }
fieldset { display: grid; gap: 6px; border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; } legend { padding: 0 6px; color: var(--text-dim); font-size: 12px; }
fieldset label { display: flex; align-items: center; gap: 10px; min-height: 30px; font-size: 13px; } input[type='radio'] { accent-color: var(--accent); width: 16px; height: 16px; }
.destination { font-size: 13px; margin: 14px 0 0; font-weight: 550; overflow-wrap: anywhere; } .note, .error { font-size: 13px; line-height: 1.5; } .note { color: var(--text-dim); } .error { color: var(--danger); }
.forward-success { display: flex; gap: 10px; line-height: 1.5; padding: 16px 0; } .forward-success > svg { color: var(--accent); flex-shrink: 0; }
footer { display: flex; gap: 10px; justify-content: flex-end; margin-top: 18px; } footer button { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 14px; min-height: 44px; border-radius: 11px; }
button:disabled { opacity: .45; cursor: default; } button:focus-visible, input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.recipient { cursor: pointer; }
.recipient input[type='checkbox'] { width: 18px; height: 18px; flex: 0 0 18px; accent-color: var(--accent); }
.recipient:has(input:disabled) { opacity: .5; cursor: default; }
.selection-count { font-size: 12px; color: var(--text-dim); margin: 10px 0 0; }
.selected-list { margin-top: 16px; font-size: 13px; } .selected-list > strong { display: block; margin-bottom: 6px; }
.selected-list ul, .forward-results ul { list-style: none; padding: 0; margin: 0; }
.selected-list li { display: flex; align-items: center; gap: 10px; min-height: 46px; padding: 5px 0; border-bottom: 1px solid var(--line); }
.selected-list li > span { flex: 1; min-width: 0; overflow-wrap: anywhere; } .selected-list li button { width: 36px; height: 36px; flex-shrink: 0; }
.forward-results section + section { margin-top: 18px; } .forward-results h3 { display: flex; align-items: center; gap: 6px; font-size: 13px; margin: 0 0 8px; }
.forward-results li { padding: 9px 0; border-bottom: 1px solid var(--line); font-size: 13px; overflow-wrap: anywhere; }
.forward-results li p { color: var(--text-dim); font-size: 12px; line-height: 1.5; margin: 5px 0 0; }
.result-sent h3 { color: var(--accent); } .result-failed h3 { color: var(--danger); }
@media (max-width: 500px) { .forward-dialog { padding: 16px; } }
</style>
