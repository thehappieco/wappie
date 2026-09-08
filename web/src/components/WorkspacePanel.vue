<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { workspaceRequest, type Workspace, type Member, type Permission } from '../api/workspaces'
import { credential, state, stop } from '../state/archive'

const spaces = ref<Workspace[]>([])
const members = ref<Member[]>([])
const permissions = ref<Permission[]>([])
const selected = ref(state.tenantID)
const device = ref('')
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
async function loadPermissions() {
  await run(async () => { permissions.value = device.value ? (await workspaceRequest<{ permissions: Permission[] }>(`/devices/${device.value}/permissions`)).permissions : [] })
}
async function savePermission(p: Permission) {
  await run(async () => {
    await workspaceRequest(`/devices/${device.value}/permissions`, 'PUT', p)
    notice.value = 'Permissões salvas. Para liberar leitura, conceda também a chave em Detalhes do aparelho.'
  })
}
onMounted(() => { void run(load) })
</script>

<template>
  <section v-if="credential()?.kind === 'session'" class="console-panel workspace-panel">
    <h2>Seu espaço de trabalho</h2>
    <p class="dim">Cada empresa tem seus números, membros e integrações. Sua conta pode participar de vários espaços. Ao trocar de empresa, confirme sua entrada para abrir as chaves dela.</p>
    <div v-if="error" class="alert" role="alert">{{ error }}</div>
    <p v-if="notice" role="status">{{ notice }}</p>
    <form class="workspace-form" @submit.prevent="switchSpace">
      <label>Empresa<select v-model="selected" required><option value="" disabled>Escolha um espaço</option><option v-for="s in spaces" :key="s.id" :value="s.id" :disabled="s.status !== 'active'">{{ s.name }} · {{ labels[s.role] || s.role }}</option></select></label>
      <button class="primary" :disabled="busy">Abrir espaço</button>
    </form>
    <details><summary>Entrar em outra empresa com um convite</summary><form class="workspace-form" @submit.prevent="join"><label>Código de convite<input v-model="joinCode" required autocomplete="off" /></label><button :disabled="busy">Aceitar convite</button></form></details>
    <template v-if="manager">
      <h2>Membros e acessos</h2>
      <div class="workspace-table"><table class="grid"><thead><tr><th>Conta</th><th>Papel</th><th>Acesso</th><th></th></tr></thead><tbody>
        <tr v-for="m in members" :key="m.id"><td>{{ m.email }}</td><td><select v-model="m.role" :disabled="m.role === 'service' || (state.role !== 'owner' && ['owner','admin'].includes(m.role))" :aria-label="`Papel de ${m.email}`"><option v-if="m.role === 'service'" value="service">Integração</option><option v-for="r in ['member','admin','owner']" :key="r" :value="r" :disabled="!roles.includes(r)">{{ labels[r] }}</option></select></td><td><select v-model="m.status" :aria-label="`Acesso de ${m.email}`"><option value="active">Ativo</option><option value="disabled">Desativado</option></select></td><td><button :disabled="busy" @click="update(m)">Salvar</button></td></tr>
      </tbody></table></div>
      <form class="workspace-form" @submit.prevent="invite"><label>Email<input v-model="email" type="email" required placeholder="pessoa@empresa.com" /></label><label>Papel<select v-model="role"><option v-for="r in roles" :key="r" :value="r">{{ labels[r] }}</option></select></label><button :disabled="busy">Criar convite</button></form>
      <label v-if="invitation">Convite criado<input :value="invitation" readonly @focus="($event.target as HTMLInputElement).select()" /></label>
      <h2>Permissões por número</h2>
      <label>Número<select v-model="device" @change="loadPermissions"><option value="">Escolha um aparelho</option><option v-for="d in state.devices" :key="d.id" :value="d.id">{{ d.label || d.id }}</option></select></label>
      <p class="dim">Administradores gerenciam os aparelhos. Ler conversas exige permissão e uma chave concedida. Revogar leitura não apaga dados já obtidos.</p>
      <div class="workspace-table"><table v-if="permissions.length" class="grid"><thead><tr><th>Conta</th><th>Ler</th><th>Enviar</th><th>Gerenciar</th><th>Chave</th><th></th></tr></thead><tbody><tr v-for="p in permissions" :key="p.user_id"><td>{{ members.find(m => m.id === p.user_id)?.email || p.user_id }}</td><td><input v-model="p.read" type="checkbox" aria-label="Ler" /></td><td><input v-model="p.send" type="checkbox" aria-label="Enviar" /></td><td><input v-model="p.manage" type="checkbox" aria-label="Gerenciar" :disabled="['owner','admin'].includes(members.find(m => m.id === p.user_id)?.role || '')" /></td><td>{{ p.has_key ? 'Concedida' : 'Pendente' }}</td><td><button :disabled="busy" @click="savePermission(p)">Salvar</button></td></tr></tbody></table></div>
    </template>
  </section>
</template>
<style scoped>
.workspace-form { display:flex; flex-wrap:wrap; gap:1rem; align-items:end; margin:1rem 0 1.5rem; }
.workspace-panel label { display:flex; flex-direction:column; gap:.4rem; min-width:12rem; }
.workspace-form label { flex:1; }
.workspace-panel select,.workspace-panel input:not([type=checkbox]) { width:100%; padding:.65rem; border:1px solid var(--line,#b9c5c1); border-radius:.5rem; background:var(--surface,#fff); color:inherit; }
.workspace-panel h2:not(:first-child) { margin-top:2rem; }
.workspace-table { overflow-x:auto; }
.workspace-panel th { text-align:left; }
.workspace-panel details { margin:1rem 0; }
</style>
