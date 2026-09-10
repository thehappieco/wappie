<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import { connection, credential, state } from '../state/archive'
import { canConversationAction, locationValidation, sendLocation } from '../state/conversationActions'
import { TypeLocationSend } from '../api/protocol'
import { coordinate, readPosition } from '../ui/location'
import { t } from '../ui/i18n'
import AppIcon from './AppIcon.vue'
import MapLinks from './MapLinks.vue'

const emit = defineEmits<{ close: [] }>()
const dialog = ref<HTMLDialogElement>()
const titleID = useId()
const lat = ref(''), lon = ref(''), name = ref(''), address = ref('')
const accuracy = ref(0), locating = ref(false), busy = ref(false), uncertain = ref(false), error = ref('')
const allowed = computed(() => canConversationAction(TypeLocationSend))
const input = computed(() => ({ lat: coordinate(lat.value), lon: coordinate(lon.value), name: name.value, address: address.value, accuracy_m: accuracy.value || undefined }))
const valid = computed(() => !locationValidation(input.value))
const locked = computed(() => busy.value || uncertain.value)
const initial = { device: state.deviceID, chat: state.openChatKey, tenant: state.tenantID, conn: connection(), token: credential()?.token, view: state.view }
const backdropPressed = ref(false)
let disposed = false, positionRequest: AbortController | undefined
const sameContext = () => !disposed && state.deviceID === initial.device && state.openChatKey === initial.chat && state.tenantID === initial.tenant
  && connection() === initial.conn && credential()?.token === initial.token && state.view === initial.view

function close() { disposed = true; positionRequest?.abort(); emit('close') }
function editedCoordinates() { accuracy.value = 0; error.value = '' }
async function locate() {
  if (locked.value || locating.value || !sameContext()) return
  positionRequest?.abort()
  const controller = new AbortController(); positionRequest = controller
  locating.value = true; error.value = ''
  try {
    const result = await readPosition(controller.signal)
    if (!sameContext() || controller.signal.aborted) return
    lat.value = String(result.lat); lon.value = String(result.lon); accuracy.value = result.accuracy
  } catch (cause) {
    if (sameContext() && !controller.signal.aborted) error.value = cause instanceof Error ? cause.message : t('Não foi possível obter sua posição. Informe as coordenadas.')
  } finally { if (positionRequest === controller) locating.value = false }
}
async function submit() {
  if (locked.value || locating.value || !sameContext() || !allowed.value) return
  error.value = locationValidation(input.value)
  if (error.value) return
  busy.value = true
  try {
    const result = await sendLocation(input.value)
    if (!sameContext()) return
    if (result.ok || result.stale) { close(); return }
    uncertain.value = Boolean(result.uncertain)
    error.value = result.error || t('Não foi possível enviar a localização.')
  } catch {
    if (sameContext()) { uncertain.value = true; error.value = t('A confirmação não chegou. Verifique a conversa antes de enviar novamente.') }
  } finally { busy.value = false }
}
watch(() => [state.deviceID, state.openChatKey, state.tenantID, state.view, state.connected, connection(), credential()?.token], () => {
  if (!sameContext() || !state.connected) close()
}, { flush: 'sync' })
onMounted(() => dialog.value?.showModal())
onBeforeUnmount(() => { disposed = true; positionRequest?.abort(); dialog.value?.close() })
</script>

<template>
  <dialog ref="dialog" class="location-dialog" :aria-labelledby="titleID" @cancel.prevent="close"
    @pointerdown="backdropPressed = $event.target === $event.currentTarget" @pointercancel="backdropPressed = false"
    @click="backdropPressed && $event.target === $event.currentTarget && close()">
    <header><span class="location-symbol"><AppIcon name="location" :size="24" /></span><h2 :id="titleID">{{ t('Enviar localização') }}</h2><button type="button" class="icon-btn" :aria-label="t('Fechar')" @click="close"><AppIcon name="close" /></button></header>
    <p class="location-note">{{ t('Envie um ponto fixo. Use sua posição ou informe outro local pelas coordenadas.') }}</p>
    <button type="button" class="locate-button" :disabled="locked || locating || !allowed" @click="locate"><AppIcon name="location" :size="20" />{{ locating ? t('Buscando sua posição…') : t('Usar minha posição atual') }}</button>
    <form novalidate :aria-busy="busy || locating" @submit.prevent="submit">
      <fieldset :disabled="locked || locating">
        <div class="coordinates"><label>{{ t('Latitude') }}<input v-model="lat" type="text" autocomplete="off" placeholder="−23.55052" @input="editedCoordinates" /></label><label>{{ t('Longitude') }}<input v-model="lon" type="text" autocomplete="off" placeholder="−46.63331" @input="editedCoordinates" /></label></div>
        <p v-if="accuracy" class="location-note">{{ t('Precisão aproximada: ±{meters} m', { meters: accuracy }) }}</p>
        <label>{{ t('Nome do local (opcional)') }}<input v-model="name" type="text" maxlength="100" autocomplete="off" /></label>
        <label>{{ t('Endereço (opcional)') }}<textarea v-model="address" rows="2" maxlength="500" /></label>
      </fieldset>
      <div v-if="valid" class="location-confirmation">
        <AppIcon name="location" :size="22" />
        <div>
          <strong>{{ name.trim() || t('Localização') }}</strong>
          <span>{{ input.lat.toFixed(6) }}, {{ input.lon.toFixed(6) }}</span>
          <MapLinks :lat="input.lat" :lon="input.lon" :name="name" />
        </div>
      </div>
      <p v-if="error" class="alert" role="alert">{{ error }}</p>
      <p v-if="uncertain" class="location-note" role="status">{{ t('A localização pode ter sido enviada. Verifique a conversa antes de tentar novamente.') }}</p>
      <p v-if="busy" class="location-note" role="status">{{ t('Aguarde a confirmação do envio.') }}</p>
      <footer><button type="button" class="ghost" @click="close">{{ locked ? t('Fechar') : t('Cancelar') }}</button><button type="submit" class="primary" :disabled="locked || locating || !allowed || !valid">{{ busy ? t('Enviando…') : t('Enviar localização') }}</button></footer>
    </form>
  </dialog>
</template>

<style scoped>
.location-dialog { width: min(460px, calc(100% - 24px)); max-height: calc(var(--app-height, 100dvh) - 24px); overflow: auto; overscroll-behavior: contain; padding: 20px; border: 1px solid var(--line); border-radius: 22px; background: var(--bg-panel); color: var(--text); box-shadow: 0 24px 90px #0006; }.location-dialog::backdrop { background: #0007; backdrop-filter: blur(3px); }
header { display: flex; align-items: center; gap: 10px; } header h2 { flex: 1; min-width: 0; margin: 0; font-size: 19px; }.location-symbol { display: grid; place-items: center; color: var(--accent); }.location-note { color: var(--text-dim); font-size: 13px; line-height: 1.5; margin: 12px 0; }
.locate-button { display: flex; align-items: center; justify-content: center; gap: 9px; width: 100%; min-height: 48px; margin: 16px 0; background: var(--bg-active); color: var(--text); border: 1px solid var(--line); border-radius: 12px; }
fieldset { border: 0; padding: 0; margin: 0; min-width: 0; } label { display: grid; gap: 7px; margin-top: 13px; font-size: 13px; color: var(--text-dim); }.coordinates { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }.coordinates label { min-width: 0; }
input, textarea { width: 100%; min-width: 0; font-size: 16px; padding: 11px; border: 1px solid var(--line); border-radius: 10px; background: var(--bg-input); color: var(--text); } textarea { resize: vertical; max-height: 160px; }
.location-confirmation { display: flex; gap: 10px; margin-top: 18px; padding: 13px; border: 1px solid var(--line); border-radius: 12px; background: var(--bg-hover); }.location-confirmation > svg { flex-shrink: 0; color: var(--accent); }.location-confirmation > div { min-width: 0; }.location-confirmation > div > strong, .location-confirmation > div > span { display: block; overflow-wrap: anywhere; font-size: 13px; line-height: 1.6; }.location-confirmation > div > span { color: var(--text-dim); }
footer { display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px; } footer button { min-height: 44px; border-radius: 10px; padding: 10px 14px; }button:disabled { opacity: .45; cursor: default; }button:focus-visible, input:focus-visible, textarea:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
@media (max-width: 359px) { .location-dialog { padding: 16px; }.coordinates { grid-template-columns: 1fr; gap: 0; } }
</style>
