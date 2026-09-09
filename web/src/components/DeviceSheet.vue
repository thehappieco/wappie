<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { admin, canAdminister, closeDetail, grantAccess, removeDevice, revokeAccess, renameDevice, startDevice, stopDevice, preparePairing } from '../state/admin'
import { state } from '../state/archive'
import { bytes, count, since, stamp } from '../ui/format'
import { t } from '../ui/i18n'
import PasswordInput from './PasswordInput.vue'
import DeviceAvatar from './DeviceAvatar.vue'

const dialog = ref<HTMLDialogElement | null>(null)
const closeButton = ref<HTMLButtonElement | null>(null)
let disposed = false
let backdropPressed = false
onMounted(() => {
  dialog.value?.showModal()
  closeButton.value?.focus({ preventScroll: true })
})
onBeforeUnmount(() => {
  disposed = true
  dialog.value?.close()
})
function closed() { if (!disposed) closeDetail() }
function backdropClick(event: MouseEvent) {
  if (backdropPressed && event.target === event.currentTarget) dismiss()
  backdropPressed = false
}

const confirming = ref(false)
const typed = ref('')
const rename = ref('')
const device = computed(() => admin.detail?.device)
const canManage = computed(() => device.value?.can_manage ?? canAdminister())
const stats = computed(() => admin.detail?.stats)
const fragment = computed(() => device.value?.id.slice(0, 6) ?? '')
const armed = computed(() => !!fragment.value && typed.value.trim().toLowerCase() === fragment.value.toLowerCase())
const pending = computed(() => !!device.value && !device.value.pn && !device.value.lid && !device.value.last_connected_at)
watch(() => device.value?.id, () => { rename.value = device.value?.label ?? ''; confirming.value = false; typed.value = '' }, { immediate: true })
function when(iso: string | undefined) { return iso ? new Date(iso) : undefined }
async function destroy() {
  if (!device.value || !armed.value) return
  if (await removeDevice(device.value.id)) { confirming.value = false; typed.value = '' }
}
async function saveName() {
  if (device.value) await renameDevice(device.value.id, rename.value.trim())
}
const granting = ref(false)
const password = ref('')
const chosen = ref<string[]>([])
const revoking = ref('')
const readerIDs = computed(() => new Set(admin.detail?.readers?.map(r => r.user_id) ?? []))
const candidates = computed(() => admin.accounts.filter(a => !readerIDs.value.has(a.id)))
const myID = computed(() => admin.accounts.find(a => a.email === state.account)?.id ?? '')
const iCanGrant = computed(() => !!admin.detail && readerIDs.value.has(myID.value) && canAdminister())
function toggle(id: string) { chosen.value = chosen.value.includes(id) ? chosen.value.filter(x => x !== id) : [...chosen.value, id] }
async function grant() {
  if (!device.value) return
  await grantAccess(device.value.id, chosen.value, password.value)
  password.value = ''
  if (!admin.grantError) { granting.value = false; chosen.value = [] }
}
async function revoke(userID: string) {
  if (!device.value) return
  revoking.value = ''
  await revokeAccess(device.value.id, userID)
}
function dismiss() {
  if (admin.deviceBusy) return
  if (dialog.value?.open) dialog.value.close()
  else closeDetail()
}
</script>

<template>
  <dialog ref="dialog" class="device-backdrop" :aria-label="t('Detalhes do número')"
    @cancel.prevent="dismiss" @close="closed"
    @pointerdown="backdropPressed = $event.target === $event.currentTarget" @click="backdropClick">
    <section class="device-dialog">
      <header class="device-head">
        <DeviceAvatar v-if="device" :device="device" />
        <div class="grow"><h2>{{ device?.label || device?.push_name || t('Detalhes do número') }}</h2><p class="dim" v-if="device?.push_name">{{ device.push_name }}</p></div>
        <button ref="closeButton" class="icon-btn" autofocus :disabled="admin.deviceBusy" @click="dismiss" :title="t('Fechar')" :aria-label="t('Fechar')">✕</button>
      </header>
      <div class="device-scroll">
        <div class="alert" role="alert" v-if="admin.detailError">{{ admin.detailError }}</div>
        <template v-if="device">
          <section class="device-section">
            <form v-if="canManage" class="rename-form" @submit.prevent="saveName">
              <div class="field"><label for="device-name">{{ t('Nome interno') }}</label><input id="device-name" v-model="rename" maxlength="100" required :placeholder="device.push_name || t('Nome do número')" /><span class="hint">{{ t('Esse nome aparece no Wappie e não altera seu perfil no WhatsApp.') }}</span></div>
              <button class="primary small" :disabled="admin.deviceBusy || !rename.trim() || rename.trim() === device.label">{{ t('Salvar nome') }}</button>
            </form>
            <dl class="device-facts">
              <div><dt>{{ t('Número') }}</dt><dd>{{ device.pn?.split('@')[0]?.split(':')[0] || '—' }}</dd></div>
              <div><dt>{{ t('Nome no WhatsApp') }}</dt><dd>{{ device.push_name || '—' }}</dd></div>
              <div><dt>{{ t('Conexão') }}</dt><dd>{{ pending ? t('Aguardando conexão') : device.paused ? t('Sincronização pausada') : device.status === 'online' ? t('Conectado') : t('Desconectado') }}</dd></div>
              <div><dt>{{ t('Modo de leitura') }}</dt><dd>{{ device.receipt_mode === 'active' ? t('Confirmações ativadas') : t('Modo incógnito') }}</dd></div>
              <div><dt>{{ t('Conectado pela última vez') }}</dt><dd>{{ stamp(when(device.last_connected_at)) }}<span class="dim" v-if="device.last_connected_at"> · {{ since(when(device.last_connected_at)) }}</span></dd></div>
              <div><dt>{{ t('Histórico') }}</dt><dd>{{ t('{messages} mensagens · {chats} conversas · {media} anexos', { messages: count(stats?.messages), chats: count(stats?.chats), media: count(stats?.media) }) }}<span v-if="stats?.media_bytes"> · {{ bytes(stats.media_bytes) }}</span></dd></div>
            </dl>
            <template v-if="canManage">
              <div v-if="pending" class="connection-action"><p v-if="admin.detail?.epoch">{{ t('Este número ainda não foi vinculado. Gere um novo código para concluir a conexão ou exclua este cadastro.') }}</p><p v-else class="hint">{{ t('Este cadastro não possui a chave necessária para proteger as conversas. Um proprietário ou administrador deve excluí-lo e conectar o número novamente.') }}</p><button class="primary" :disabled="admin.deviceBusy || !admin.detail?.epoch" @click="preparePairing(device)">{{ t('Conectar número') }}</button></div>
              <div v-else class="connection-action"><p class="dim">{{ t('Pausar interrompe a sincronização e o envio pelo Wappie. O número continua em Aparelhos conectados no WhatsApp e o histórico permanece aqui.') }}</p><button v-if="device.running && !device.paused" class="ghost" :disabled="admin.deviceBusy" @click="stopDevice(device.id)">{{ t('Pausar sincronização') }}</button><button v-else-if="!['logged_out', 'banned'].includes(device.status)" class="primary" :disabled="admin.deviceBusy" @click="startDevice(device.id)">{{ t('Retomar sincronização') }}</button></div>
            </template>
          </section>
          <section v-if="canAdminister()" class="device-section">
            <h3>{{ t('Acesso às conversas') }}</h3><p class="dim">{{ t('Estes membros possuem a chave para abrir as conversas deste número. As permissões de enviar e gerenciar são ajustadas na seção Permissões.') }}</p>
            <div class="alert" v-if="admin.grantError">{{ admin.grantError }}</div>
            <ul class="readers" v-if="admin.detail?.readers?.length"><li v-for="r in admin.detail.readers" :key="r.user_id"><div class="grow"><strong>{{ r.email }}</strong><small class="dim">{{ t('Acesso desde {date}', { date: stamp(when(r.granted_at)) }) }}</small></div><div class="row-actions"><template v-if="revoking === r.user_id"><button class="danger small" :disabled="admin.grantBusy" @click="revoke(r.user_id)">{{ t('Remover acesso') }}</button><button class="ghost small" @click="revoking = ''">{{ t('Cancelar') }}</button></template><button v-else class="ghost small" @click="revoking = r.user_id">{{ t('Remover') }}</button></div></li></ul>
            <p v-else class="alert">{{ t('Nenhum membro possui acesso às conversas deste número.') }}</p>
            <p class="hint">{{ t('Revogar acesso impede novas consultas. Conteúdo já aberto ou salvo por esse membro não pode ser apagado remotamente.') }}</p>
            <template v-if="candidates.length">
              <button v-if="!granting" class="ghost" :disabled="!iCanGrant" @click="granting = true">{{ t('Dar acesso a um membro') }}</button>
              <form v-else class="grant-form" @submit.prevent="grant"><div class="choices"><label v-for="a in candidates" :key="a.id" class="choice"><input type="checkbox" :checked="chosen.includes(a.id)" @change="toggle(a.id)" /><span>{{ a.email }}</span></label></div><div class="field"><label for="grant-password">{{ t('Confirme sua senha') }}</label><PasswordInput id="grant-password" v-model="password" autocomplete="current-password" required /></div><div class="row-actions"><button class="primary" type="submit" :disabled="admin.grantBusy || !chosen.length">{{ admin.grantBusy ? t('Concedendo acesso…') : t('Conceder acesso') }}</button><button class="ghost" type="button" @click="granting = false">{{ t('Cancelar') }}</button></div></form>
            </template>
          </section>
          <section v-if="canAdminister()" class="device-section danger-zone"><h3>{{ t('Excluir número') }}</h3><p>{{ t('Remove este número do Wappie e apaga definitivamente suas conversas e anexos. A desconexão no WhatsApp é solicitada automaticamente.') }}</p><p class="hint">{{ t('Se o WhatsApp estiver indisponível, pode ser necessário remover a sessão também em Aparelhos conectados no celular.') }}</p><button v-if="!confirming" class="danger" @click="confirming = true">{{ t('Excluir número…') }}</button><div v-else class="field"><label for="confirm-id">{{ t('Digite {code} para confirmar a exclusão', { code: fragment }) }}</label><input id="confirm-id" v-model="typed" autocomplete="off" :spellcheck="false" autocapitalize="off" :placeholder="fragment" :disabled="admin.deviceBusy" /><p class="hint">{{ t('Esta ação não pode ser desfeita.') }}</p></div></section>
        </template>
        <p v-else-if="admin.detailLoading" class="dim">{{ t('Carregando…') }}</p>
      </div>
      <footer v-if="confirming && device" class="device-footer"><button class="ghost" :disabled="admin.deviceBusy" @click="confirming = false; typed = ''">{{ t('Cancelar') }}</button><button class="danger" :disabled="!armed || admin.deviceBusy" @click="destroy">{{ admin.deviceBusy ? t('Excluindo…') : t('Excluir definitivamente') }}</button></footer>
    </section>
  </dialog>
</template>

<style scoped>
.device-backdrop { position: fixed; inset: 0; z-index: 50; background: transparent; display: none; place-items: center; padding: 20px; margin: 0; width: 100%; height: 100dvh; max-width: none; max-height: none; border: 0; overflow: hidden; box-sizing: border-box; }
.device-backdrop[open] { display: grid; }
.device-backdrop::backdrop { background: #0009; backdrop-filter: blur(5px); }
.device-dialog { width: min(680px, 100%); max-height: min(90dvh, 950px); display: flex; flex-direction: column; min-height: 0; border: 1px solid var(--line); border-radius: 20px; background: var(--bg-panel); color: var(--text); box-shadow: 0 24px 90px #0005; overflow: hidden; }
.device-head { padding: 20px; display: flex; align-items: center; gap: 12px; border-bottom: 1px solid var(--line); }
.device-head h2 { margin: 0; font-size: 20px; overflow-wrap: anywhere; }.device-head p { margin: 4px 0 0; }.grow { flex: 1; min-width: 0; }
.device-scroll { min-height: 0; overflow-y: auto; overscroll-behavior: contain; padding: 0 22px 20px; }.device-section { padding: 20px 0; border-bottom: 1px solid var(--line); }.device-section:last-child { border: 0; }.device-section h3 { margin: 0 0 10px; }.device-section p { line-height: 1.55; }
.rename-form { display: flex; align-items: flex-start; gap: 10px; }.rename-form .field { flex: 1; margin: 0; }.rename-form button { margin-top: 28px; }
.device-facts { margin: 20px 0 0; display: grid; gap: 12px; }.device-facts div { display: grid; grid-template-columns: 150px 1fr; gap: 12px; }.device-facts dt { color: var(--text-dim); }.device-facts dd { margin: 0; overflow-wrap: anywhere; }.connection-action { margin-top: 18px; }
.readers { padding: 0; margin: 14px 0; list-style: none; }.readers li { padding: 12px 0; display: flex; gap: 8px; align-items: center; border-bottom: 1px solid var(--line); }.readers strong { overflow-wrap: anywhere; }.readers small { display: block; margin-top: 5px; }
.device-footer { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 10px; padding: 16px 22px; border-top: 1px solid var(--line); background: var(--bg-raised); flex-shrink: 0; }.danger-zone h3 { color: var(--danger); }
input:not([type=checkbox]), :deep(.password-control input) { color: var(--text); background: var(--bg-input); border: 1px solid var(--line-strong, var(--line)); border-radius: 10px; padding: 11px 12px; width: 100%; }.field { display: grid; gap: 8px; }.hint { color: var(--text-dim); line-height: 1.5; font-size: 12px; }.row-actions { flex-wrap: wrap; }
@media (max-width: 600px) { .device-backdrop { padding: 0; align-items: end; }.device-dialog { max-height: 96dvh; border-radius: 20px 20px 0 0; }.device-head { padding: 16px; }.device-scroll { padding: 0 16px 16px; }.device-facts div { grid-template-columns: 1fr; gap: 4px; }.rename-form { flex-direction: column; }.rename-form .field { width: 100%; }.rename-form button { margin-top: 0; }.readers li { align-items: flex-start; flex-wrap: wrap; }.device-footer { padding-bottom: max(16px, env(safe-area-inset-bottom)); } }
</style>
