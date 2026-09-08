<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { workspaceRequest, type Workspace, type Member, type Permission } from '../api/workspaces'
import { credential, state, stop } from '../state/archive'
import { useWorkspacePermissions } from '../state/workspacePermissions'

withDefaults(defineProps<{ section?: 'workspace' | 'members' | 'permissions' | 'all' }>(), { section: 'all' })
const emit = defineEmits<{ (event: 'workspace-name', name: string): void }>()
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
  emit('workspace-name', spaces.value.find((space) => space.id === state.tenantID)?.name || 'Seu espaço de trabalho')
  if (manager.value) members.value = (await workspaceRequest<{ members: Member[] }>('/members')).members || []
}
function switchSpace() {
  if (!selected.value || busy.value) return
  // A fresh document prevents any queued decryption or old response from
  // writing another workspace's content into the next session.
  const target = new URL('/console', location.origin)
  target.searchParams.set('workspace', selected.value)
  stop()
  location.assign(target.toString())
}
async function update(member: Member) {
  await run(async () => {
    await workspaceRequest(`/members/${member.id}`, 'PUT', { role: member.role, status: member.status })
    notice.value = 'Acesso atualizado. Sessões anteriores deste membro foram encerradas.'
    await load()
  })
}
async function invite() {
  await run(async () => {
    invitation.value = (await workspaceRequest<{ invite: string }>('/invites', 'POST', { email: email.value, role: role.value })).invite
    notice.value = 'Convite de uso único, válido por sete dias. Copie e compartilhe com a pessoa.'
  })
}
async function join() {
  await run(async () => {
    const result = await workspaceRequest<{ tenant_id: string }>('/accept-invite', 'POST', { invite: joinCode.value })
    joinCode.value = ''; selected.value = result.tenant_id
    await load(); notice.value = 'Convite aceito. Selecione o espaço e confirme sua senha para abri-lo.'
  })
}
async function savePermission(p: Permission) {
  if (!device.value || p.device_id !== device.value || permissionsLoading.value) return
  await run(async () => {
    await workspaceRequest(`/devices/${device.value}/permissions`, 'PUT', p)
    notice.value = 'Permissões salvas. Para liberar leitura, conceda também a chave em Detalhes do aparelho.'
  })
}
onMounted(() => { if (credential()?.kind === 'session') void run(load) })
</script>

<template>
  <section v-if="credential()?.kind === 'session'" class="console-panel workspace-panel">
    <div v-if="error" class="alert" role="alert">{{ error }}</div>
    <p v-if="notice" class="workspace-notice" role="status">{{ notice }}</p>

    <template v-if="section === 'workspace' || section === 'all'">
      <div class="workspace-heading"><h2>Espaço de trabalho</h2><p class="dim">Cada empresa tem seus números, membros e integrações. Sua conta pode participar de vários espaços.</p></div>
      <form class="workspace-form" @submit.prevent="switchSpace">
        <label>Empresa<select v-model="selected" required><option value="" disabled>Escolha um espaço</option><option v-for="s in spaces" :key="s.id" :value="s.id" :disabled="s.status !== 'active'">{{ s.name }} · {{ labels[s.role] || s.role }}</option></select></label>
        <button class="primary" :disabled="busy">Abrir espaço</button>
      </form>
      <p class="dim">Ao trocar de empresa, confirme sua entrada para acessar as conversas dela.</p>
      <div class="workspace-divider" />
      <div class="workspace-heading"><h3>Recebeu um convite?</h3><p class="dim">Cole o código recebido para participar de outra empresa.</p></div>
      <form class="workspace-form" @submit.prevent="join"><label>Código de convite<input v-model="joinCode" required autocomplete="off" placeholder="Cole seu código de convite" /></label><button class="ghost" :disabled="busy">Aceitar convite</button></form>
    </template>

    <template v-if="manager && (section === 'members' || section === 'all')">
      <div class="workspace-heading"><h2>Pessoas da empresa</h2><p class="dim">Defina o papel de cada pessoa. O acesso às conversas é configurado em Permissões.</p></div>
      <div class="workspace-table">
        <table class="grid"><thead><tr><th>Conta</th><th>Papel</th><th>Acesso</th><th><span class="table-action-label">Ação</span></th></tr></thead><tbody>
          <tr v-for="m in members" :key="m.id">
            <td data-label="Conta"><span class="member-email">{{ m.email }}</span></td>
            <td data-label="Papel"><select v-model="m.role" :disabled="m.role === 'service' || (state.role !== 'owner' && ['owner','admin'].includes(m.role))" :aria-label="`Papel de ${m.email}`"><option v-if="m.role === 'service'" value="service">Integração</option><option v-for="r in ['member','admin','owner']" :key="r" :value="r" :disabled="!roles.includes(r)">{{ labels[r] }}</option></select></td>
            <td data-label="Acesso"><select v-model="m.status" :aria-label="`Acesso de ${m.email}`"><option value="active">Ativo</option><option value="disabled">Desativado</option></select></td>
            <td data-label="Ação" class="member-actions"><button class="ghost small" :disabled="busy" @click="update(m)">Salvar</button></td>
          </tr>
        </tbody></table>
        <p v-if="!members.length" class="dim table-empty">{{ busy ? 'Carregando membros…' : 'Nenhum membro encontrado.' }}</p>
      </div>
      <div class="workspace-divider" />
      <div class="workspace-heading"><h3>Convidar uma pessoa</h3><p class="dim">O convite poderá ser usado uma vez e será válido por sete dias.</p></div>
      <form class="workspace-form" @submit.prevent="invite"><label>Email<input v-model="email" type="email" required autocomplete="email" placeholder="pessoa@empresa.com" /></label><label class="compact-field">Papel<select v-model="role"><option v-for="r in roles" :key="r" :value="r">{{ labels[r] }}</option></select></label><button class="primary" :disabled="busy">Criar convite</button></form>
      <label v-if="invitation" class="invitation-result">Convite criado<input :value="invitation" readonly @focus="($event.target as HTMLInputElement).select()" /><small>Copie o código e compartilhe com a pessoa convidada.</small></label>
    </template>

    <template v-if="manager && (section === 'permissions' || section === 'all')">
      <div class="workspace-heading"><h2>Acessos por número</h2><p class="dim">Escolha um número e defina o que cada pessoa pode fazer.</p></div>
      <label class="permission-device">Número do WhatsApp<select v-model="device" :disabled="busy || permissionsLoading"><option value="">Escolha um número</option><option v-for="d in state.devices" :key="d.id" :value="d.id">{{ d.label || d.pn || d.id }}</option></select></label>
      <p class="permission-explanation"><strong>Ler conversas</strong> exige permissão e uma chave concedida em Detalhes do número. Administradores já podem gerenciar os números. Revogar leitura não apaga dados que a pessoa já recebeu.</p>
      <div v-if="permissionsError" class="alert" role="alert">{{ permissionsError }} <button class="ghost small" type="button" :disabled="permissionsLoading" @click="refreshPermissions">Tentar novamente</button></div>
      <div v-if="device" class="workspace-table"><table v-if="permissions.length" class="grid permission-table"><thead><tr><th>Conta</th><th>Ler</th><th>Enviar</th><th>Gerenciar</th><th>Chave</th><th>Ação</th></tr></thead><tbody><tr v-for="p in permissions" :key="p.user_id"><td data-label="Conta"><span class="member-email">{{ members.find(m => m.id === p.user_id)?.email || p.user_id }}</span></td><td data-label="Ler"><input v-model="p.read" type="checkbox" :aria-label="`Permitir leitura para ${members.find(m => m.id === p.user_id)?.email || p.user_id}`" /></td><td data-label="Enviar"><input v-model="p.send" type="checkbox" :aria-label="`Permitir envio para ${members.find(m => m.id === p.user_id)?.email || p.user_id}`" /></td><td data-label="Gerenciar"><input v-model="p.manage" type="checkbox" :aria-label="`Permitir gerenciamento para ${members.find(m => m.id === p.user_id)?.email || p.user_id}`" :disabled="['owner','admin'].includes(members.find(m => m.id === p.user_id)?.role || '')" /></td><td data-label="Chave"><span class="permission-key" :class="{ granted: p.has_key }">{{ p.has_key ? 'Concedida' : 'Pendente' }}</span></td><td data-label="Ação" class="member-actions"><button class="ghost small" :disabled="busy || permissionsLoading" @click="savePermission(p)">Salvar</button></td></tr></tbody></table><p v-else class="dim table-empty">{{ permissionsLoading ? 'Carregando permissões…' : 'Nenhuma permissão cadastrada para este número.' }}</p></div>
      <p v-else class="dim permission-empty">As permissões aparecerão aqui depois de selecionar um número.</p>
    </template>
  </section>
</template>

<style scoped>
.workspace-panel { min-width: 0; }
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
@media (max-width: 760px) { .workspace-form label, .workspace-form label.compact-field { flex-basis: 100%; } .workspace-form button { width: 100%; } .workspace-panel input, .workspace-panel select { font-size: 16px; } }
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
