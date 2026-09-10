<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import { connection, credential, state } from '../state/archive'
import { canConversationAction, createEvent, eventValidation, type EventInput } from '../state/conversationActions'
import { TypeEventCreate } from '../api/protocol'
import { t } from '../ui/i18n'
import AppIcon from './AppIcon.vue'

const emit = defineEmits<{ close: [] }>()
const dialog = ref<HTMLDialogElement>()
const nameInput = ref<HTMLInputElement>()
const id = useId()
const name = ref(''), description = ref(''), start = ref(''), end = ref(''), location = ref(''), link = ref('')
const hasEnd = ref(false), busy = ref(false), uncertain = ref(false), error = ref('')
const allowed = computed(() => canConversationAction(TypeEventCreate))
const locked = computed(() => busy.value || uncertain.value)
const initial = { device: state.deviceID, chat: state.openChatKey, tenant: state.tenantID, conn: connection(), token: credential()?.token, view: state.view }
let disposed = false, backdropPressed = false
const sameContext = () => !disposed && state.deviceID === initial.device && state.openChatKey === initial.chat && state.tenantID === initial.tenant
  && connection() === initial.conn && credential()?.token === initial.token && state.view === initial.view
const characters = (value: string) => Array.from(value.trim()).length

function localValue(date: Date): string {
  const pad = (value: number) => String(value).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}
function instant(value: string): string {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) return ''
  const date = new Date(value)
  // A local time in a daylight-saving gap must not silently move by an hour.
  return Number.isFinite(date.getTime()) && localValue(date) === value ? date.toISOString() : ''
}
const minimumStart = localValue(new Date())
const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
const zoneLabel = computed(() => {
  const date = new Date(instant(start.value) || Date.now())
  const offset = -date.getTimezoneOffset()
  const hours = String(Math.floor(Math.abs(offset) / 60)).padStart(2, '0')
  const minutes = String(Math.abs(offset) % 60).padStart(2, '0')
  return `${timeZone} · UTC${offset >= 0 ? '+' : '−'}${hours}:${minutes}`
})
const input = computed<EventInput>(() => ({
  name: name.value.trim(), description: description.value.trim() || undefined,
  start_time: instant(start.value), end_time: hasEnd.value ? instant(end.value) : undefined,
  location_name: location.value.trim() || undefined, join_link: link.value.trim() || undefined,
}))

function close() { if (disposed) return; disposed = true; emit('close') }
function dismiss() { if (!busy.value) close() }
function backdropClick(event: MouseEvent) {
  if (backdropPressed && event.target === event.currentTarget) dismiss()
  backdropPressed = false
}
function toggleEnd() {
  if (hasEnd.value && !end.value && instant(start.value)) end.value = localValue(new Date(Date.parse(instant(start.value)) + 3_600_000))
}
async function submit() {
  if (locked.value || !sameContext() || !allowed.value) return
  error.value = (start.value && !instant(start.value)) || (hasEnd.value && !instant(end.value))
    ? t('Escolha uma data e hora válidas no seu fuso horário.') : eventValidation(input.value)
  if (error.value) return
  busy.value = true
  try {
    const result = await createEvent(input.value)
    if (!sameContext()) return
    if (result.ok || result.stale) { close(); return }
    uncertain.value = Boolean(result.uncertain)
    error.value = result.error || (uncertain.value ? '' : t('Não foi possível criar o evento. Tente novamente.'))
  } catch {
    if (sameContext()) { uncertain.value = true; error.value = '' }
  } finally { busy.value = false }
}
watch(() => [state.deviceID, state.openChatKey, state.tenantID, state.view, state.connected, connection(), credential()?.token], () => {
  if (!sameContext() || !state.connected) close()
}, { flush: 'sync' })
watch([name, description, start, end, hasEnd, location, link], () => { if (!locked.value) error.value = '' }, { flush: 'sync' })
onMounted(() => { dialog.value?.showModal(); nameInput.value?.focus({ preventScroll: true }) })
onBeforeUnmount(() => { disposed = true; dialog.value?.close() })
</script>

<template>
  <dialog ref="dialog" class="event-backdrop" :aria-labelledby="`${id}-title`" :aria-describedby="`${id}-description`"
    @cancel.prevent="dismiss" @pointerdown="backdropPressed = $event.target === $event.currentTarget" @pointercancel="backdropPressed = false" @click="backdropClick">
    <form class="event-dialog" novalidate :aria-busy="busy" @submit.prevent="submit">
      <header>
        <span class="event-symbol" aria-hidden="true"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="16" rx="2" /><path d="M16 3v4M8 3v4M3 11h18m-13 5h3" /></svg></span>
        <div class="event-heading"><h2 :id="`${id}-title`">{{ t('Criar evento') }}</h2><p :id="`${id}-description`">{{ t('Combine uma data e compartilhe o evento na conversa.') }}</p></div>
        <button type="button" class="icon-btn" :disabled="busy" :aria-label="t('Fechar')" @click="dismiss"><AppIcon name="close" /></button>
      </header>
      <div class="event-scroll">
        <fieldset :disabled="locked">
          <div class="event-field">
            <div class="event-label"><label :for="`${id}-name`">{{ t('Nome do evento') }}</label><span :id="`${id}-name-count`" :class="{ over: characters(name) > 100 }">{{ characters(name) }}/100</span></div>
            <input :id="`${id}-name`" ref="nameInput" v-model="name" type="text" autocomplete="off" required :placeholder="t('Ex.: reunião da equipe')" :aria-describedby="`${id}-name-count`" :aria-invalid="characters(name) > 100" />
          </div>
          <section class="event-schedule" :aria-label="t('Data e horário')">
            <label :for="`${id}-start`">{{ t('Início') }}</label>
            <input :id="`${id}-start`" v-model="start" type="datetime-local" :min="minimumStart" required :aria-describedby="`${id}-zone`" />
            <p :id="`${id}-zone`" class="event-hint zone"><AppIcon name="clock" :size="15" />{{ t('Fuso horário: {zone}', { zone: zoneLabel }) }}</p>
            <label class="end-toggle"><span>{{ t('Definir término') }}</span><input v-model="hasEnd" type="checkbox" role="switch" @change="toggleEnd" /></label>
            <div v-if="hasEnd" class="event-field end-field"><label :for="`${id}-end`">{{ t('Término') }}</label><input :id="`${id}-end`" v-model="end" type="datetime-local" :min="start || minimumStart" required :aria-describedby="`${id}-zone`" /></div>
          </section>
          <div class="event-field"><div class="event-label"><label :for="`${id}-description-input`">{{ t('Descrição (opcional)') }}</label><span :id="`${id}-description-count`" :class="{ over: characters(description) > 2048 }">{{ characters(description) }}/2048</span></div><textarea :id="`${id}-description-input`" v-model="description" rows="2" :aria-describedby="`${id}-description-count`" :aria-invalid="characters(description) > 2048" /></div>
          <div class="event-field"><div class="event-label"><label :for="`${id}-location`">{{ t('Local (opcional)') }}</label><span :id="`${id}-location-count`" :class="{ over: characters(location) > 500 }">{{ characters(location) }}/500</span></div><input :id="`${id}-location`" v-model="location" type="text" autocomplete="off" :aria-describedby="`${id}-location-count`" :aria-invalid="characters(location) > 500" /></div>
          <div class="event-field"><label :for="`${id}-link`">{{ t('Link de chamada do WhatsApp (opcional)') }}</label><input :id="`${id}-link`" v-model="link" type="url" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="https://call.whatsapp.com/…" :aria-describedby="`${id}-link-hint`" /><p :id="`${id}-link-hint`" class="event-hint">{{ t('Cole um link de chamada existente. Outros links podem ser incluídos na descrição.') }}</p></div>
        </fieldset>
        <p v-if="error" class="alert" role="alert">{{ error }}</p>
        <div v-if="uncertain" class="event-pending" role="status"><strong>{{ t('Confirmação pendente') }}</strong><p>{{ t('O evento pode ter sido enviado. Feche esta janela e verifique a conversa antes de criar outro.') }}</p></div>
      </div>
      <footer>
        <p v-if="busy" class="event-hint" role="status">{{ t('Aguarde a confirmação do envio.') }}</p>
        <button class="ghost" type="button" :disabled="busy" @click="dismiss">{{ uncertain ? t('Fechar') : t('Cancelar') }}</button>
        <button class="primary" type="submit" :disabled="locked || !allowed">{{ busy ? t('Enviando evento…') : uncertain ? t('Confirmação pendente') : t('Enviar evento') }}</button>
      </footer>
    </form>
  </dialog>
</template>

<style scoped>
.event-backdrop { position: fixed; inset: 0; width: 100%; height: 100dvh; max-width: none; max-height: none; padding: 20px; margin: 0; border: 0; background: transparent; display: none; place-items: center; overflow: hidden; box-sizing: border-box; }
.event-backdrop[open] { display: grid; }.event-backdrop::backdrop { background: #0009; backdrop-filter: blur(5px); }
.event-dialog { display: flex; flex-direction: column; width: min(520px, 100%); max-height: min(90dvh, var(--app-height, 90dvh)); min-height: 0; overflow: hidden; background: var(--bg-panel); color: var(--text); border: 1px solid var(--line); border-radius: 22px; box-shadow: 0 24px 90px #0005; animation: event-appear 160ms ease-out; }
header { display: flex; align-items: center; gap: 12px; padding: 20px; border-bottom: 1px solid var(--line); }.event-symbol { display: grid; place-items: center; width: 44px; height: 44px; flex-shrink: 0; border-radius: 14px; color: var(--accent); background: var(--accent-dim); }.event-heading { flex: 1; min-width: 0; }.event-heading h2 { margin: 0 0 5px; font-size: 21px; }.event-heading p { margin: 0; color: var(--text-dim); font-size: 13px; line-height: 1.4; }header .icon-btn { flex-shrink: 0; min-width: 44px; min-height: 44px; }
.event-scroll { min-height: 0; overflow-y: auto; overscroll-behavior: contain; padding: 20px 22px; }.event-scroll fieldset { min-width: 0; border: 0; margin: 0; padding: 0; }.event-field { display: grid; gap: 8px; margin-top: 18px; }.event-field:first-child { margin-top: 0; }label { font-size: 14px; font-weight: 600; }.event-label { display: flex; justify-content: space-between; align-items: baseline; gap: 10px; }.event-label > span { font-size: 11px; color: var(--text-dim); font-variant-numeric: tabular-nums; }
.event-dialog input:not([type=checkbox]), textarea { width: 100%; min-width: 0; max-width: 100%; min-height: 46px; font-size: 16px; padding: 11px 12px; border: 1px solid var(--line-strong, var(--line)); border-radius: 11px; background: var(--bg-input); color: var(--text); box-sizing: border-box; }.event-dialog input[type=datetime-local] { display: block; min-inline-size: 0; }.event-dialog textarea { resize: vertical; min-height: 76px; max-height: 160px; }.event-dialog .over { color: var(--danger); }.event-hint { color: var(--text-dim); font-size: 12px; line-height: 1.5; margin: 0; }
.event-schedule { margin-top: 20px; padding: 16px; border: 1px solid var(--line); border-radius: 14px; background: var(--bg-hover); }.event-schedule > label:first-child { display: block; margin-bottom: 8px; }.zone { display: flex; align-items: flex-start; gap: 6px; margin-top: 9px; overflow-wrap: anywhere; }.zone > svg { margin-top: 2px; flex-shrink: 0; }.end-toggle { min-height: 44px; display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-top: 10px; cursor: pointer; }.end-toggle input { width: 22px; height: 22px; accent-color: var(--accent); flex-shrink: 0; }.end-field { margin-top: 8px; }.event-pending { margin-top: 18px; padding: 14px; border-radius: 12px; border: 1px solid var(--line); background: var(--bg-raised); }.event-pending p { margin: 6px 0 0; font-size: 13px; line-height: 1.5; color: var(--text-dim); }.event-scroll .alert { margin-top: 16px; }
footer { flex-shrink: 0; display: flex; flex-wrap: wrap; align-items: center; justify-content: flex-end; gap: 10px; border-top: 1px solid var(--line); padding: 16px 22px; background: var(--bg-raised); }footer > p { flex-basis: 100%; }footer button { min-height: 44px; padding: 10px 16px; border-radius: 10px; }button:disabled { cursor: default; opacity: .55; }button:focus-visible, input:focus-visible, textarea:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
@keyframes event-appear { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
@media (max-width: 600px) { .event-backdrop { padding: 0; align-items: end; height: var(--app-height, 100dvh); top: var(--app-top, 0px); bottom: auto; }.event-dialog { max-height: min(96dvh, var(--app-height, 96dvh)); border-radius: 22px 22px 0 0; }header { padding: 16px; }.event-scroll { padding: 18px 16px; }footer { padding: 14px 16px max(14px, env(safe-area-inset-bottom)); }.event-heading h2 { font-size: 19px; }.event-symbol { width: 38px; height: 38px; }.event-schedule { padding: 12px; } }
@media (prefers-reduced-motion: reduce) { .event-dialog { animation: none; } }
</style>
