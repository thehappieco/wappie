<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { workspaceRequest, type Member, type Permission } from '../api/workspaces'
import { credential, state } from '../state/archive'
import { admin, grantAccess, revokeAccess, load as loadAdmin } from '../state/admin'
import { loadWorkspaceMembers, workspaceChanged } from '../state/workspaces'
import { changeDevicePermission, PermissionChangeError } from '../state/devicePermissions'
import { useWorkspacePermissions } from '../state/workspacePermissions'
import { initials } from '../state/jid'
import { t } from '../ui/i18n'
import AppIcon from './AppIcon.vue'
import ConsoleDialog from './ConsoleDialog.vue'
import PasswordInput from './PasswordInput.vue'
const props = defineProps<{ deviceId: string }>()
const deviceID = computed(() => credential()?.kind === 'session' ? props.deviceId : '')
const { permissions, loading, error:loadError, refresh } = useWorkspacePermissions(deviceID)
const members = ref<Member[]>([]), error = ref(''), notice = ref(''), busy = ref(false)
const granting = ref<Permission | null>(null), password = ref('')
let generation = 0
const currentUser = computed(() => members.value.find(member => member.email === state.account))
const canShare = computed(() => !!currentUser.value && !!admin.detail?.readers.some(reader => reader.user_id === currentUser.value!.id))
function person(id:string) { return members.value.find(member => member.id === id) }
function name(id:string) { const member = person(id); return member?.name || member?.email || id }
function implicitManager(id:string) { return ['owner','admin'].includes(person(id)?.role ?? '') }
watch([deviceID, () => state.account], async () => {
  const current = ++generation; members.value = []; granting.value = null; password.value = ''; error.value = ''; notice.value = ''
  if (!deviceID.value) return
  try { const loaded = await loadWorkspaceMembers(); if (current === generation) members.value = loaded }
  catch(e) { if (current === generation) error.value = e instanceof Error ? e.message : String(e) }
}, {immediate:true})
onBeforeUnmount(() => { generation++; password.value = '' })
function requestSave(row:Permission) {
  error.value = ''; notice.value = ''
  if (row.read && !row.has_key) {
    if (!canShare.value) { error.value = t('Para conceder leitura, um membro que já tem a chave deste número precisa liberar o acesso.'); return }
    granting.value = {...row}; password.value = ''
  } else void save(row)
}
async function save(row:Permission, secret = '') {
  if (busy.value || admin.grantBusy || loading.value || row.device_id !== props.deviceId) return
  const current = generation, device = props.deviceId, who = state.account
  const valid = () => generation === current && props.deviceId === device && state.account === who
  busy.value = true; error.value = ''; notice.value = ''; admin.grantError = ''
  try {
    const complete = await changeDevicePermission(row, {
      current: valid,
      grant: async () => {
        await loadAdmin()
        if (!valid()) return
        const granted = await grantAccess(device,[row.user_id],secret)
        if (valid() && !granted) throw new Error(admin.grantError || t('Não foi possível alterar o acesso. Tente novamente.'))
      },
      revoke: async () => {
        const revoked = await revokeAccess(device,row.user_id)
        if (valid() && !revoked) throw new Error(admin.grantError || t('Não foi possível alterar o acesso. Tente novamente.'))
      },
      save: async () => { await workspaceRequest(`/devices/${device}/permissions`, 'PUT', {device_id:device,user_id:row.user_id,read:row.read,send:row.send,manage:row.manage}) },
    })
    if (!complete) return
    granting.value = null; notice.value = t('Permissões atualizadas.'); workspaceChanged()
  } catch(e) {
    if (valid()) error.value = (e instanceof PermissionChangeError && e.keyChanged ? t('A chave foi atualizada, mas a alteração das outras permissões não foi concluída. Confira os acessos e tente novamente.') + ' ' : '') + (e instanceof Error ? e.message : String(e))
  } finally { if (valid()) { busy.value = false; password.value = ''; refresh() } }
}
function submit(event:SubmitEvent) { const row = granting.value; if (row) void save(row,String(new FormData(event.currentTarget as HTMLFormElement).get('password') ?? '')) }
</script>
<template>
  <section class="device-permissions">
    <h3>{{ t('Membros e permissões') }}</h3><p class="dim">{{ t('Defina quem pode ler, enviar e gerenciar este número. Ao liberar leitura, a chave é entregue de forma protegida ao membro.') }}</p>
    <p v-if="credential()?.kind !== 'session'" class="dim">{{ t('Entre com sua conta para gerenciar os acessos dos membros.') }}</p>
    <template v-else>
      <p v-if="(error || loadError) && !granting" class="alert" role="alert">{{ error || loadError }}</p><p v-if="notice" class="access-notice" role="status">{{ notice }}</p>
      <div class="access-guide"><span><strong>{{ t('Ler') }}</strong> {{ t('Conversas e histórico') }}</span><span><strong>{{ t('Enviar') }}</strong> {{ t('Mensagens e interações') }}</span><span><strong>{{ t('Gerenciar') }}</strong> {{ t('Conexão e configurações') }}</span></div>
      <div class="permission-members" :aria-busy="loading || busy"><article v-for="row in permissions" :key="row.user_id" class="permission-member">
        <div class="person"><img v-if="person(row.user_id)?.avatar" :src="person(row.user_id)?.avatar" alt="" /><span v-else class="person-avatar">{{ initials(name(row.user_id)) }}</span><div><strong>{{ name(row.user_id) }}</strong><small>{{ person(row.user_id)?.email }}</small></div><span class="key-status" :class="{granted:row.has_key}"><AppIcon name="key" :size="12" />{{ row.has_key ? t('Com chave') : t('Sem chave') }}</span></div>
        <div class="permission-controls"><label><input v-model="row.read" type="checkbox" :disabled="busy || admin.grantBusy || loading || (!row.has_key && !canShare)" :aria-label="t('Permitir leitura para {name}',{name:name(row.user_id)})" /><span>{{ t('Ler') }}</span></label><label><input v-model="row.send" type="checkbox" :disabled="busy || admin.grantBusy || loading" :aria-label="t('Permitir envio para {name}',{name:name(row.user_id)})" /><span>{{ t('Enviar') }}</span></label><label><input v-model="row.manage" type="checkbox" :disabled="busy || admin.grantBusy || loading || implicitManager(row.user_id)" :aria-label="t('Permitir gerenciamento para {name}',{name:name(row.user_id)})" /><span>{{ t('Gerenciar') }}</span></label><button class="ghost small" type="button" :disabled="busy || admin.grantBusy || loading" @click="requestSave(row)">{{ t('Salvar') }}</button></div>
      </article><p v-if="!permissions.length" class="dim">{{ loading ? t('Carregando permissões…') : t('Nenhum membro disponível.') }}</p></div>
      <p v-if="!canShare && !loading" class="dim">{{ t('Para conceder leitura, um membro que já tem a chave deste número precisa liberar o acesso.') }}</p><p class="access-footnote">{{ t('Proprietários e administradores podem gerenciar o número. Para ler as conversas, também precisam da chave. O último membro ativo com acesso é protegido contra remoção.') }}</p><p class="access-footnote">{{ t('Revogar acesso impede novas consultas. Conteúdo já aberto ou salvo por esse membro não pode ser apagado remotamente.') }}</p>
      <ConsoleDialog v-if="granting" :title="t('Liberar leitura')" :busy="busy" @close="granting = null; password = ''"><form class="form-stack" name="wappie-grant-access" method="post" autocomplete="on" @submit.prevent="submit"><p>{{ t('A chave deste número será compartilhada com {name}.',{name:name(granting.user_id)}) }}</p><p v-if="error" class="alert" role="alert">{{ error }}</p><input name="username" :value="state.account" type="email" autocomplete="username" readonly tabindex="-1" aria-hidden="true" class="hidden-identifier" /><label for="permission-password">{{ t('Confirme sua senha') }}<PasswordInput id="permission-password" name="password" v-model="password" required autocomplete="current-password" :disabled="busy" /></label><div class="dialog-actions"><button class="ghost" type="button" :disabled="busy" @click="granting = null; password = ''">{{ t('Cancelar') }}</button><button class="primary" :disabled="busy">{{ busy ? t('Concedendo acesso…') : t('Conceder acesso') }}</button></div></form></ConsoleDialog>
    </template>
  </section>
</template>
<style scoped>
.device-permissions h3 { margin:0 0 10px; }.access-guide { display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;padding:14px;border-radius:10px;background:var(--bg-hover);margin:16px 0; }.access-guide span { font-size:11px;color:var(--text-dim);line-height:1.5; }.access-guide strong { display:block;font-size:12px;color:var(--text);margin-bottom:3px; }.permission-members { display:grid;gap:10px; }.permission-member { padding:15px;border:1px solid var(--line);border-radius:12px; }.person { display:flex;align-items:center;gap:10px; }.person>div { flex:1;min-width:0; }.person img,.person-avatar { width:36px;height:36px;object-fit:cover;border-radius:50%;flex:none; }.person-avatar { display:grid;place-items:center;background:var(--accent-dim);color:var(--accent);font-size:12px;font-weight:600; }.person strong,.person small { display:block;overflow-wrap:anywhere; }.person strong { font-size:13px; }.person small { font-size:11px;color:var(--text-dim);margin-top:4px; }.key-status { display:flex;align-items:center;gap:4px;font-size:10px;color:var(--text-dim);white-space:nowrap; }.key-status.granted { color:var(--accent); }.permission-controls { display:flex;align-items:center;gap:15px;margin-top:14px;flex-wrap:wrap; }.permission-controls label { display:flex;align-items:center;gap:6px;font-size:12px;min-height:36px; }.permission-controls input { width:18px;height:18px;margin:0;accent-color:var(--accent); }.permission-controls>button { margin-left:auto; }.access-footnote { color:var(--text-dim);font-size:11px;line-height:1.6; }.access-notice { color:var(--accent);font-size:13px; }.hidden-identifier { position:absolute !important;width:1px !important;height:1px !important;min-height:0 !important;opacity:0;pointer-events:none;padding:0 !important;border:0 !important; }
@media(max-width:460px) { .access-guide { grid-template-columns:1fr;gap:7px; }.access-guide strong { display:inline;margin-right:5px; }.permission-controls { gap:10px; }.key-status { font-size:0; }.key-status .app-icon { width:16px;height:16px; }.person small { font-size:10px; } }
</style>
