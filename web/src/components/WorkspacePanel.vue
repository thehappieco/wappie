<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { t } from '../ui/i18n'
import { workspaceAvatar } from '../ui/workspaceAvatar'
import AppIcon from './AppIcon.vue'
import { workspaceRequest, type Workspace, type Member, type Permission } from '../api/workspaces'
import { credential, state, stop } from '../state/archive'
import { useWorkspacePermissions } from '../state/workspacePermissions'

withDefaults(defineProps<{ section?: 'workspace' | 'members' | 'permissions' | 'all' }>(), { section: 'all' })
const emit = defineEmits<{ (event: 'workspace-name', name: string): void; (event: 'workspace-avatar', avatar: string): void }>()
const spaces = ref<Workspace[]>([])
const members = ref<Member[]>([])
const selected = ref(state.tenantID)
const device = ref('')
const { permissions, loading: permissionsLoading, error: permissionsError, refresh: refreshPermissions } = useWorkspacePermissions(device)
const email = ref('')
const role = ref('member')
const invitation = ref('')
const joinCode = ref('')
const error = ref('')
const notice = ref('')
const busy = ref(false)
const profileName = ref('')
const profileAvatar = ref('')
const profileReady = ref(false)
const currentSpace = computed(() => spaces.value.find(space => space.id === state.tenantID))
const profileChanged = computed(() => profileReady.value && (profileName.value.trim() !== currentSpace.value?.name || profileAvatar.value !== (currentSpace.value?.avatar || '')))
const memberOriginals = ref<Record<string, { role: string; status: string }>>({})
function canEditMember(member: Member) {
  const original = memberOriginals.value[member.id]
  return !member.last_owner && !!original && (state.role === 'owner' || !['owner', 'admin'].includes(original.role))
}
function memberChanged(member: Member) {
  const original = memberOriginals.value[member.id]
  return original && (original.role !== member.role || original.status !== member.status)
}
function roleLabel(role: string) { return t(labels[role] || role) }
async function chooseAvatar(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file || busy.value) return
  await run(async () => { profileAvatar.value = await workspaceAvatar(file) })
  input.value = ''
}
async function saveProfile() {
  if (!profileChanged.value || !manager.value) return
  await run(async () => {
    const profile = await workspaceRequest<Workspace>('/current', 'PUT', { name: profileName.value.trim(), avatar: profileAvatar.value })
    spaces.value = spaces.value.map(space => space.id === profile.id ? profile : space)
    profileName.value = profile.name; profileAvatar.value = profile.avatar || ''
    emit('workspace-name', profile.name); emit('workspace-avatar', profile.avatar || '')
    notice.value = t('Espaço de trabalho atualizado.')
  })
}
const manager = computed(() => ['owner', 'admin'].includes(state.role))
const roles = computed(() => state.role === 'owner' ? ['member', 'admin', 'owner'] : ['member'])
const labels: Record<string, string> = { owner: 'Proprietário', admin: 'Administrador', member: 'Membro', service: 'Integração' }
async function run(fn: () => Promise<void>) {
  if (busy.value) return
  busy.value = true; error.value = ''; notice.value = ''
  try { await fn() } catch (e) { error.value = e instanceof Error ? e.message : String(e) }
  finally { busy.value = false }
}
async function load() {
  spaces.value = (await workspaceRequest<{ workspaces: Workspace[] }>('')).workspaces || []
  profileName.value = currentSpace.value?.name || ''
  profileAvatar.value = currentSpace.value?.avatar || ''
  profileReady.value = !!currentSpace.value
  emit('workspace-name', profileName.value || t('Seu espaço de trabalho'))
  emit('workspace-avatar', profileAvatar.value)
  if (manager.value) {
    members.value = (await workspaceRequest<{ members: Member[] }>('/members')).members || []
    memberOriginals.value = Object.fromEntries(members.value.map(member => [member.id, { role: member.role, status: member.status }]))
  }
}
function switchSpace() {
  if (!selected.value || busy.value) return
  // A fresh document prevents any queued decryption or old response from
  // writing another workspace's content into the next session.
  const target = new URL('/console', location.origin)
  target.searchParams.set('workspace', selected.value)
  stop({ logout: false })
  location.assign(target.toString())
}
async function update(member: Member) {
  if (!canEditMember(member) || !memberChanged(member)) return
  await run(async () => {
    await workspaceRequest(`/members/${member.id}`, 'PUT', { role: member.role, status: member.status })
    notice.value = t('Acesso atualizado. Sessões anteriores deste membro foram encerradas.')
    await load()
  })
}
async function invite() {
  await run(async () => {
    invitation.value = (await workspaceRequest<{ invite: string }>('/invites', 'POST', { email: email.value, role: role.value })).invite
    notice.value = t('Convite de uso único, válido por sete dias. Copie e compartilhe com a pessoa.')
  })
}
async function join() {
  await run(async () => {
    const result = await workspaceRequest<{ tenant_id: string }>('/accept-invite', 'POST', { invite: joinCode.value })
    joinCode.value = ''; selected.value = result.tenant_id
    await load(); notice.value = t('Convite aceito. Selecione o espaço para abri-lo.')
  })
}
async function savePermission(p: Permission) {
  if (!device.value || p.device_id !== device.value || permissionsLoading.value) return
  await run(async () => {
    await workspaceRequest(`/devices/${device.value}/permissions`, 'PUT', p)
    notice.value = t('Permissões salvas. Para liberar leitura, conceda também a chave em Detalhes do número.')
  })
}
onMounted(() => { if (credential()?.kind === 'session') void run(load) })
</script>

<template>
  <section v-if="credential()?.kind === 'session'" class="console-panel workspace-panel">
    <div v-if="error" class="alert" role="alert">{{ error }}</div>
    <p v-if="notice" class="workspace-notice" role="status">{{ notice }}</p>

    <template v-if="section === 'workspace' || section === 'all'">
      <div class="workspace-heading"><h2>{{ t('Espaço de trabalho') }}</h2><p class="dim">{{ t('Um espaço reúne números do WhatsApp, pessoas e integrações. Sua conta pode participar de vários espaços.') }}</p></div>
      <form v-if="profileReady" class="workspace-profile" @submit.prevent="saveProfile">
        <div class="workspace-avatar" :aria-label="t('Avatar do espaço de trabalho')"><img v-if="profileAvatar" :src="profileAvatar" alt="" /><AppIcon v-else name="building" :size="30" /></div>
        <div class="profile-fields">
          <label>{{ t('Nome do espaço de trabalho') }}<input v-model="profileName" maxlength="80" required :readonly="!manager" :disabled="busy" autocomplete="organization" /></label>
          <div v-if="manager" class="avatar-actions">
            <label class="avatar-upload ghost"><AppIcon name="image" :size="16" />{{ t('Escolher avatar') }}<input type="file" accept="image/jpeg,image/png,image/webp" :disabled="busy" @change="chooseAvatar" /></label>
            <button v-if="profileAvatar" class="ghost small" type="button" :disabled="busy" @click="profileAvatar = ''">{{ t('Remover avatar') }}</button>
          </div>
          <p v-if="manager" class="dim avatar-hint">{{ t('JPG, PNG ou WebP. A imagem será ajustada ao formato quadrado.') }}</p>
        </div>
        <button v-if="manager" class="primary" :disabled="busy || !profileChanged">{{ t('Salvar alterações') }}</button>
      </form>
      <div class="workspace-divider" />
      <div class="workspace-heading"><h3>{{ t('Seus espaços de trabalho') }}</h3></div>
      <form class="workspace-form" @submit.prevent="switchSpace">
        <label>{{ t('Espaço de trabalho') }}<select v-model="selected" required :disabled="busy"><option value="" disabled>{{ t('Escolha um espaço') }}</option><option v-for="s in spaces" :key="s.id" :value="s.id" :disabled="s.status !== 'active'">{{ s.name }} · {{ roleLabel(s.role) }}</option></select></label>
        <button class="primary" :disabled="busy || selected === state.tenantID">{{ t('Abrir espaço') }}</button>
      </form>
      <p class="dim">{{ t('Ao trocar de espaço de trabalho, confirme sua entrada para acessar as conversas dele.') }}</p>
      <div class="workspace-divider" />
      <div class="workspace-heading"><h3>{{ t('Recebeu um convite?') }}</h3><p class="dim">{{ t('Cole o código recebido para participar de outro espaço de trabalho.') }}</p></div>
      <form class="workspace-form" @submit.prevent="join"><label>{{ t('Código de convite') }}<input v-model="joinCode" required autocomplete="off" :placeholder="t('Cole seu código de convite')" /></label><button class="ghost" :disabled="busy">{{ t('Aceitar convite') }}</button></form>
    </template>

    <template v-if="manager && (section === 'members' || section === 'all')">
      <div class="workspace-heading"><h2>{{ t('Membros do espaço de trabalho') }}</h2><p class="dim">{{ t('Membros são as pessoas que participam deste espaço. O papel define o que podem administrar; o acesso às conversas é definido em Permissões.') }}</p></div>
      <div class="role-guide">
        <div><AppIcon name="shield" :size="20" /><h3>{{ t('Proprietário') }}</h3><p>{{ t('Controla o espaço e pode definir outros proprietários e administradores. É necessário manter ao menos um proprietário ativo.') }}</p></div>
        <div><AppIcon name="settings" :size="20" /><h3>{{ t('Administrador') }}</h3><p>{{ t('Gerencia números, integrações, permissões e membros. Não pode alterar proprietários nem outros administradores.') }}</p></div>
        <div><AppIcon name="users" :size="20" /><h3>{{ t('Membro') }}</h3><p>{{ t('Usa os números e recursos liberados para sua conta. Não administra o espaço de trabalho.') }}</p></div>
      </div>
      <div class="workspace-table">
        <table class="grid"><thead><tr><th>{{ t('Conta') }}</th><th>{{ t('Papel') }}</th><th>{{ t('Acesso') }}</th><th><span class="table-action-label">{{ t('Ação') }}</span></th></tr></thead><tbody>
          <tr v-for="m in members" :key="m.id">
            <td :data-label="t('Conta')"><span class="member-email">{{ m.email }}</span><small v-if="m.last_owner" class="owner-protection">{{ t('Único proprietário ativo') }}</small></td>
            <td :data-label="t('Papel')"><select v-model="m.role" :disabled="busy || m.role === 'service' || !canEditMember(m)" :aria-label="t('Papel de {name}', { name: m.email })"><option v-if="m.role === 'service'" value="service">{{ t('Integração') }}</option><option v-for="r in ['member','admin','owner']" :key="r" :value="r" :disabled="!roles.includes(r)">{{ roleLabel(r) }}</option></select></td>
            <td :data-label="t('Acesso')"><select v-model="m.status" :disabled="busy || !canEditMember(m)" :aria-label="t('Acesso de {name}', { name: m.email })"><option value="active">{{ t('Ativo') }}</option><option value="disabled">{{ t('Desativado') }}</option></select></td>
            <td :data-label="t('Ação')" class="member-actions"><button class="ghost small" :disabled="busy || !canEditMember(m) || !memberChanged(m)" @click="update(m)">{{ t('Salvar') }}</button></td>
          </tr>
        </tbody></table>
        <p v-if="!members.length" class="dim table-empty">{{ busy ? t('Carregando membros…') : t('Nenhum membro encontrado.') }}</p>
      </div>
      <p v-if="members.some(member => member.last_owner)" class="permission-explanation">{{ t('Para desativar ou mudar o papel do último proprietário, primeiro convide outra pessoa e torne-a proprietária. Isso evita que o espaço fique sem alguém responsável.') }}</p>
      <div class="workspace-divider" />
      <div class="workspace-heading"><h3>{{ t('Convidar uma pessoa') }}</h3><p class="dim">{{ t('O convite poderá ser usado uma vez e será válido por sete dias.') }}</p></div>
      <form class="workspace-form" @submit.prevent="invite"><label>{{ t('Email') }}<input v-model="email" type="email" required autocomplete="email" :placeholder="t('pessoa@exemplo.com')" /></label><label class="compact-field">{{ t('Papel') }}<select v-model="role"><option v-for="r in roles" :key="r" :value="r">{{ roleLabel(r) }}</option></select></label><button class="primary" :disabled="busy">{{ t('Criar convite') }}</button></form>
      <label v-if="invitation" class="invitation-result">{{ t('Convite criado') }}<input :value="invitation" readonly @focus="($event.target as HTMLInputElement).select()" /><small>{{ t('Copie o código e compartilhe com a pessoa convidada.') }}</small></label>
    </template>

    <template v-if="manager && (section === 'permissions' || section === 'all')">
      <div class="workspace-heading"><h2>{{ t('Acessos por número') }}</h2><p class="dim">{{ t('Escolha um número e defina o que cada pessoa pode fazer.') }}</p></div>
      <label class="permission-device">{{ t('Número do WhatsApp') }}<select v-model="device" :disabled="busy || permissionsLoading"><option value="">{{ t('Escolha um número') }}</option><option v-for="d in state.devices" :key="d.id" :value="d.id">{{ d.label || d.pn || d.id }}</option></select></label>
      <div class="permission-guide"><p><strong>{{ t('Ler') }}</strong> {{ t('Acessar conversas. Exige também a chave concedida em Detalhes do número.') }}</p><p><strong>{{ t('Enviar') }}</strong> {{ t('Enviar mensagens por este número.') }}</p><p><strong>{{ t('Gerenciar') }}</strong> {{ t('Gerenciar o vínculo, a conexão e as configurações deste número. Proprietários e administradores já têm esse acesso.') }}</p></div>
      <p class="dim">{{ t('Revogar a leitura não apaga dados que a pessoa já recebeu.') }}</p>
      <div v-if="permissionsError" class="alert" role="alert">{{ permissionsError }} <button class="ghost small" type="button" :disabled="permissionsLoading" @click="refreshPermissions">{{ t('Tentar novamente') }}</button></div>
      <div v-if="device" class="workspace-table"><table v-if="permissions.length" class="grid permission-table"><thead><tr><th>{{ t('Conta') }}</th><th>{{ t('Ler') }}</th><th>{{ t('Enviar') }}</th><th>{{ t('Gerenciar') }}</th><th>{{ t('Chave') }}</th><th>{{ t('Ação') }}</th></tr></thead><tbody><tr v-for="p in permissions" :key="p.user_id"><td :data-label="t('Conta')"><span class="member-email">{{ members.find(m => m.id === p.user_id)?.email || p.user_id }}</span></td><td :data-label="t('Ler')"><input v-model="p.read" type="checkbox" :aria-label="t('Permitir leitura para {name}', { name: members.find(m => m.id === p.user_id)?.email || p.user_id })" /></td><td :data-label="t('Enviar')"><input v-model="p.send" type="checkbox" :aria-label="t('Permitir envio para {name}', { name: members.find(m => m.id === p.user_id)?.email || p.user_id })" /></td><td :data-label="t('Gerenciar')"><input v-model="p.manage" type="checkbox" :aria-label="t('Permitir gerenciamento para {name}', { name: members.find(m => m.id === p.user_id)?.email || p.user_id })" :disabled="['owner','admin'].includes(members.find(m => m.id === p.user_id)?.role || '')" /></td><td :data-label="t('Chave')"><span class="permission-key" :class="{ granted: p.has_key }">{{ p.has_key ? t('Concedida') : t('Pendente') }}</span></td><td :data-label="t('Ação')" class="member-actions"><button class="ghost small" :disabled="busy || permissionsLoading" @click="savePermission(p)">{{ t('Salvar') }}</button></td></tr></tbody></table><p v-else class="dim table-empty">{{ permissionsLoading ? t('Carregando permissões…') : t('Nenhuma permissão cadastrada para este número.') }}</p></div>
      <p v-else class="dim permission-empty">{{ t('As permissões aparecerão aqui depois de selecionar um número.') }}</p>
    </template>
  </section>
</template>

<style scoped>
.workspace-panel { min-width: 0; }
.workspace-profile { display: flex; gap: 20px; align-items: center; padding: 22px; background: var(--bg-hover); border: 1px solid var(--console-border, var(--line)); border-radius: 14px; }
.workspace-avatar { width: 76px; height: 76px; border-radius: 22px; flex-shrink: 0; display: grid; place-items: center; color: var(--console-accent, var(--accent)); background: var(--console-tint, var(--accent-dim)); overflow: hidden; }
.workspace-avatar img { width: 100%; height: 100%; object-fit: cover; }
.profile-fields { flex: 1; min-width: 0; display: grid; gap: 10px; }
.avatar-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.workspace-panel .avatar-upload { display: inline-flex; flex-direction: row; align-items: center; gap: 7px; cursor: pointer; position: relative; padding: 9px 12px; border-radius: 8px; }
.avatar-upload input { position: absolute; width: 1px !important; height: 1px; opacity: 0; overflow: hidden; padding: 0 !important; }
.avatar-upload:focus-within { outline: 2px solid var(--console-accent, var(--accent)); outline-offset: 2px; }
.avatar-hint { font-size: 11px; }
.role-guide { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
.role-guide > div { display: grid; align-content: start; gap: 10px; padding: 18px; border: 1px solid var(--console-border, var(--line)); border-radius: 12px; background: var(--bg-hover); }
.role-guide svg { color: var(--console-accent, var(--accent)); }
.role-guide h3 { font-size: 13px; margin: 0; }
.role-guide p, .permission-guide p { font-size: 12px; line-height: 1.6; margin: 0; color: var(--text-dim); }
.owner-protection { display: block; margin-top: 5px; font-size: 10px; color: var(--console-accent, var(--accent)); }
.permission-guide { display: grid; gap: 8px; padding: 16px; border-radius: 10px; background: var(--bg-hover); }
.permission-guide strong { color: var(--text); margin-right: 5px; }
.workspace-form { display: flex; flex-wrap: wrap; gap: 14px; align-items: end; margin: 0; }
.workspace-panel label { display: flex; flex-direction: column; gap: 8px; min-width: 0; font-size: 12px; font-weight: 500; }
.workspace-form label { flex: 1 1 200px; }
.workspace-form label.compact-field { flex: 0 1 200px; }
.workspace-form button { min-height: 42px; flex-shrink: 0; }
.workspace-panel select, .workspace-panel input:not([type=checkbox]) { width: 100%; padding: 10px 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--bg-input); color: var(--text); }
.workspace-heading { display: grid; gap: 8px; }
.workspace-heading h3 { margin: 0; font-size: 14px; }
.workspace-divider { height: 1px; background: var(--line); margin: 10px 0; }
.workspace-table { min-width: 0; overflow-x: auto; border: 1px solid var(--console-border, var(--line)); border-radius: 10px; }
.workspace-table .grid { min-width: 540px; }
.workspace-panel th { text-align: left; }
.workspace-table .grid th { white-space: nowrap; }
.workspace-table .grid td { vertical-align: middle; }
.workspace-table select { min-width: 115px; }
.member-email { font-size: 12px; overflow-wrap: anywhere; }
.table-action-label { font-size: 0; }
.table-empty { padding: 18px; }
.permission-device { max-width: 440px; }
.permission-explanation { color: var(--text-dim); font-size: 12px; padding: 14px 16px; background: var(--bg-hover); border-radius: 9px; }
.permission-explanation strong { color: var(--text); font-weight: 500; }
.permission-table input[type=checkbox] { width: 17px; height: 17px; margin: 0; accent-color: var(--console-accent, var(--accent)); }
.permission-key { font-size: 10px; padding: 4px 7px; border-radius: 5px; background: var(--bg-hover); color: var(--text-dim); }
.permission-key.granted { color: var(--console-accent, var(--accent)); background: var(--console-tint, var(--accent-dim)); }
.permission-empty { padding: 24px 0; text-align: center; }
.workspace-notice { font-size: 13px; padding: 12px 14px; background: var(--console-tint, var(--accent-dim)); color: var(--console-accent, var(--text)); border-radius: 8px; }
.invitation-result { padding: 16px; background: var(--bg-hover); border-radius: 10px; }
.invitation-result small { color: var(--text-dim); font-weight: 400; font-size: 11px; }
@media (max-width: 760px) { .role-guide { grid-template-columns: 1fr; } .workspace-profile { flex-wrap: wrap; padding: 16px; gap: 14px; } .profile-fields { flex-basis: calc(100% - 100px); } .workspace-profile > button { width: 100%; } .workspace-form label, .workspace-form label.compact-field { flex-basis: 100%; } .workspace-form button { width: 100%; } .workspace-panel input, .workspace-panel select { font-size: 16px; } }
@media (max-width: 600px) {
  .workspace-table { border: 0; border-radius: 0; overflow: visible; }
  .workspace-table .grid { display: block; min-width: 0; }
  .workspace-table thead { display: none; }
  .workspace-table tbody { display: grid; gap: 12px; }
  .workspace-table tr { display: block; min-width: 0; border: 1px solid var(--console-border, var(--line)); border-radius: 10px; padding: 10px 14px; }
  .workspace-panel .workspace-table .grid td { display: grid; grid-template-columns: 72px minmax(0, 1fr); align-items: center; gap: 12px; padding: 8px 0; border: 0; width: 100%; }
  .workspace-table td::before { content: attr(data-label); font-size: 11px; color: var(--text-dim); }
  .workspace-table .member-email { font-size: 12px; line-height: 1.5; }
  .workspace-table select { min-width: 0; font-size: 14px; }
  .workspace-table .member-actions button { width: 100%; }
  .workspace-table .permission-key { justify-self: start; }
  .workspace-table input[type=checkbox] { width: 20px; height: 20px; }
}
</style>
