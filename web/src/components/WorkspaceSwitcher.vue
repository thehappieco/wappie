<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { credential, state, stop } from '../state/archive'
import { currentWorkspace, loadWorkspaceContext, workspaceChanged, workspaceState } from '../state/workspaces'
import { workspaceRequest, type Workspace } from '../api/workspaces'
import { workspaceAvatar } from '../ui/workspaceAvatar'
import { initials } from '../state/jid'
import { t } from '../ui/i18n'
import AppIcon from './AppIcon.vue'
import ConsoleDialog from './ConsoleDialog.vue'
const trigger = ref<HTMLButtonElement>()
const popup = ref(false), editor = ref<'create' | 'edit' | 'join' | null>(null)
const invitationEmail = ref('')
const emailMismatch = computed(() => !!invitationEmail.value && invitationEmail.value.trim().toLowerCase() !== state.account.trim().toLowerCase())
const name = ref(''), avatar = ref(''), code = ref(''), busy = ref(false), error = ref(''), notice = ref('')
const current = currentWorkspace
const manager = computed(() => ['owner', 'admin'].includes(current.value?.role ?? state.role))
const labels: Record<string, string> = { owner: 'Proprietário', admin: 'Administrador', member: 'Membro', service: 'Integração' }
function roleLabel(role: string) { return t(labels[role] ?? role) }
function switchSpace(space: Workspace, edit = false) {
  if (busy.value || space.status !== 'active') return
  if (space.id === state.tenantID) { popup.value = false; if (edit) open('edit'); return }
  const target = new URL('/console', location.origin)
  target.searchParams.set('workspace', space.id)
  if (edit) target.searchParams.set('workspaceEdit', '1')
  stop({ logout: false }); location.assign(target.toString())
}
function open(mode: 'create' | 'edit' | 'join') {
  popup.value = false; error.value = ''; notice.value = ''; code.value = ''; invitationEmail.value = ''
  name.value = mode === 'edit' ? current.value?.name ?? '' : ''
  avatar.value = mode === 'edit' ? current.value?.avatar ?? '' : ''
  editor.value = mode
}
async function chooseAvatar(event: Event) {
  const input = event.target as HTMLInputElement, file = input.files?.[0]
  if (!file || busy.value) return
  busy.value = true; error.value = ''
  try { avatar.value = await workspaceAvatar(file) } catch (e) { error.value = e instanceof Error ? e.message : String(e) }
  finally { busy.value = false; input.value = '' }
}
function changeAccount() {
  const target = new URL('/console?signup=1',location.origin)
  const fragment = new URLSearchParams({invite:code.value.trim()})
  if (invitationEmail.value) fragment.set('email',invitationEmail.value)
  target.hash = fragment.toString(); stop(); location.assign(target.toString())
}
async function submit() {
  if (busy.value || !editor.value) return
  if (editor.value === 'join' && emailMismatch.value) return
  const mode = editor.value, tenant = state.tenantID, account = state.account
  const valid = () => tenant === state.tenantID && account === state.account
  busy.value = true; error.value = ''
  try {
    if (mode === 'join') {
      const result = await workspaceRequest<{ tenant_id: string }>('/accept-invite', 'POST', { invite: code.value.trim() })
      if (!valid()) return
      code.value = ''; await loadWorkspaceContext(true)
      if (!valid()) return
      const added = workspaceState.spaces.find(space => space.id === result.tenant_id)
      editor.value = null; busy.value = false
      if (added) switchSpace(added)
      else notice.value = t('Convite aceito. Atualize a lista para abrir o workspace.')
    } else {
      const result = await workspaceRequest<Workspace>(mode === 'create' ? '' : '/current', mode === 'create' ? 'POST' : 'PUT', { name: name.value.trim(), avatar: avatar.value })
      if (!valid()) return
      workspaceState.spaces = mode === 'create' ? [...workspaceState.spaces, result] : workspaceState.spaces.map(space => space.id === result.id ? result : space)
      workspaceChanged(); editor.value = null; busy.value = false
      if (mode === 'create') switchSpace(result)
    }
  } catch (e) { if (valid()) error.value = e instanceof Error ? e.message : String(e) }
  finally { if (valid()) busy.value = false }
}
let disposed = false
function consumeInvitation() {
  const initialURL = new URL(location.href)
  const fragment = new URLSearchParams(initialURL.hash.slice(1))
  const invitation = fragment.get('invite'), invitedEmail = fragment.get('email') ?? ''
  const hasSecrets = ['invite','email','verification'].some(key => fragment.has(key))
  if (hasSecrets) {
    for (const key of ['invite','email','verification']) fragment.delete(key)
    initialURL.hash = fragment.toString(); initialURL.searchParams.delete('signup')
    history.replaceState(history.state, '', initialURL)
  }
  if (invitation) { open('join'); code.value = invitation; invitationEmail.value = invitedEmail }
}
onMounted(async () => {
  window.addEventListener('hashchange', consumeInvitation)
  consumeInvitation()
  await loadWorkspaceContext()
  if (disposed) return
  const url = new URL(location.href)
  if (url.searchParams.get('workspaceEdit') === '1' && manager.value) {
    url.searchParams.delete('workspaceEdit'); history.replaceState(history.state, '', url); open('edit')
  }
})
onBeforeUnmount(() => { disposed = true; window.removeEventListener('hashchange', consumeInvitation); code.value = '' })
</script>
<template>
  <div class="workspace-selector" v-if="credential()?.kind === 'session'">
    <span class="selector-label">{{ t('Workspace') }}</span>
    <button ref="trigger" type="button" class="workspace-trigger" aria-haspopup="dialog" :aria-expanded="popup" @click="popup = true; void loadWorkspaceContext(true)">
      <img v-if="current?.avatar" :src="current.avatar" alt="" /><span v-else class="workspace-initials">{{ initials(current?.name || state.account || 'Wappie') }}</span>
      <span class="workspace-trigger-text"><strong>{{ current?.name || t('Seu espaço de trabalho') }}</strong><small>{{ current?.kind === 'personal' ? t('Pessoal') : t('Team') }}</small></span><AppIcon name="chevron-down" :size="17" />
    </button>
    <ConsoleDialog v-if="popup" :title="t('Workspaces')" :anchor="trigger" @close="popup = false">
      <div class="workspace-popup">
        <p v-if="workspaceState.error" class="alert" role="alert">{{ workspaceState.error }}</p>
        <p v-if="notice" class="dim" role="status">{{ notice }}</p>
        <p v-if="workspaceState.loading && !workspaceState.spaces.length" class="dim">{{ t('Carregando…') }}</p>
        <ul class="workspace-list"><li v-for="space in workspaceState.spaces" :key="space.id" :class="{ selected: space.id === state.tenantID }">
          <button type="button" class="space-choice" :disabled="space.status !== 'active'" :aria-current="space.id === state.tenantID ? 'true' : undefined" @click="switchSpace(space)">
            <img v-if="space.avatar" :src="space.avatar" alt="" /><span v-else class="workspace-initials">{{ initials(space.name) }}</span><span class="space-name"><strong>{{ space.name }}</strong><small>{{ roleLabel(space.role) }}<template v-if="space.status !== 'active'"> · {{ t('Desativado') }}</template></small></span><span class="kind" :class="space.kind">{{ space.kind === 'personal' ? t('Pessoal') : t('Team') }}</span>
          </button>
          <button v-if="space.status === 'active' && ['owner','admin'].includes(space.role)" class="icon-btn edit-space" type="button" :aria-label="t('Editar {name}', { name: space.name })" @click="switchSpace(space, true)"><AppIcon name="pencil" :size="16" /></button>
        </li></ul>
        <button class="create-team" type="button" @click="open('create')"><AppIcon name="users" :size="19" />{{ t('Criar workspace Team') }}</button>
        <button class="join-workspace" type="button" @click="open('join')"><AppIcon name="plus" :size="21" /><span>{{ t('Entrar com código de convite') }}</span></button>
      </div>
    </ConsoleDialog>
    <ConsoleDialog v-if="editor" :title="editor === 'join' ? t('Entrar em um workspace') : editor === 'create' ? t('Criar workspace Team') : t('Editar workspace')" :busy="busy" @close="editor = null">
      <form class="form-stack" @submit.prevent="submit">
        <p v-if="error" class="alert" role="alert">{{ error }}</p>
        <template v-if="editor === 'join'"><p class="dim">{{ t('Use o código recebido no convite. Você precisa entrar com o mesmo email que foi convidado.') }}</p><label>{{ t('Código de convite') }}<input v-model="code" required autocomplete="off" autocapitalize="off" :spellcheck="false" :disabled="busy" /></label><p class="dim">{{ t('Conta atual: {email}',{email:state.account}) }}</p><p v-if="invitationEmail" class="dim">{{ t('Convite para: {email}',{email:invitationEmail}) }}</p><p v-if="emailMismatch" class="alert">{{ t('Este convite pertence a outro email. Entre com o email convidado. O convite continua válido.') }}</p><button v-if="emailMismatch" type="button" class="ghost" @click="changeAccount">{{ t('Entrar com outro email') }}</button></template>
        <template v-else>
          <label class="avatar-picker" :aria-label="t('Alterar avatar do workspace')"><img v-if="avatar" :src="avatar" alt="" /><span v-else>{{ initials(name || 'Wappie') }}</span><span class="avatar-edit"><AppIcon name="pencil" :size="15" /></span><input type="file" accept="image/jpeg,image/png,image/webp" :disabled="busy" @change="chooseAvatar" /></label>
          <button v-if="avatar" class="ghost small remove-avatar" type="button" :disabled="busy" @click="avatar = ''">{{ t('Remover avatar') }}</button>
          <label>{{ t('Nome do workspace') }}<input v-model="name" maxlength="80" required autocomplete="organization" :disabled="busy" /></label>
          <p class="dim">{{ editor === 'create' ? t('Um workspace Team reúne números, membros e uma assinatura própria. Seu workspace pessoal continua separado.') : t('O nome e a imagem aparecem para os membros deste workspace.') }}</p>
        </template>
        <div class="dialog-actions"><button class="ghost" type="button" :disabled="busy" @click="editor = null">{{ t('Cancelar') }}</button><button class="primary" :disabled="busy || (editor === 'join' ? !code.trim() || emailMismatch : !name.trim())">{{ busy ? t('Aguarde…') : editor === 'join' ? t('Aceitar convite') : editor === 'create' ? t('Criar workspace') : t('Salvar alterações') }}</button></div>
      </form>
    </ConsoleDialog>
  </div>
</template>
<style scoped>
.selector-label { display: block; padding: 0 12px 9px; color: var(--text-dim); font-size: 11px; font-weight: 600; }.workspace-trigger { display: flex; width: 100%; min-height: 68px; padding: 12px; gap: 10px; align-items: center; text-align: left; border: 1px solid var(--line); border-radius: 13px; background: var(--bg-raised); }.workspace-trigger:hover { background: var(--bg-hover); }.workspace-trigger-text { flex: 1; min-width: 0; }.workspace-trigger strong,.space-name strong { display: block; font-size: 13px; font-weight: 600; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }.workspace-trigger small,.space-name small { display: block; font-size: 11px; color: var(--text-dim); margin-top: 4px; }.workspace-trigger img,.workspace-initials,.space-choice img { width: 38px; height: 38px; flex: none; border-radius: 11px; object-fit: cover; }.workspace-initials { display: grid; place-items: center; color: var(--accent); background: var(--accent-dim); font-weight: 650; }.workspace-popup { display: grid; gap: 10px; }.workspace-list { list-style: none; padding: 0; margin: 0; display: grid; gap: 5px; }.workspace-list li { display: flex; gap: 0; border-radius: 12px; align-items: center; }.workspace-list li.selected { background: var(--bg-hover); }.space-choice { display: flex; min-width: 0; flex: 1; gap: 10px; padding: 12px 8px; align-items: center; text-align: left; }.space-name { flex: 1; min-width: 0; }.kind { padding: 4px 6px; background: var(--bg-active); border-radius: 5px; color: var(--text-dim); font-size: 10px; }.kind.team { background: var(--accent-dim); color: var(--accent); }.edit-space { flex: none; width: 32px; }.create-team,.join-workspace { display: flex; align-items: center; justify-content: center; gap: 9px; width: 100%; padding: 13px; font-size: 13px; border-radius: 10px; }.create-team { background: var(--text); color: var(--bg-panel); font-weight: 600; }.join-workspace { justify-content: flex-start; border-top: 1px solid var(--line); border-radius: 0; color: var(--text-dim); }.avatar-picker { position: relative; width: 88px; height: 88px; border-radius: 50%; margin: 0 auto; cursor: pointer; display: grid; place-items: center; background: var(--accent-dim); color: var(--accent); font-size: 25px; }.avatar-picker img { width: 100%; height: 100%; border-radius: inherit; object-fit: cover; }.avatar-picker input { position: absolute; inset: 0; opacity: 0; cursor: pointer; }.avatar-edit { position: absolute; right: 0; bottom: 0; background: var(--bg-panel); border: 1px solid var(--line); border-radius: 50%; width: 29px; height: 29px; display: grid; place-items: center; }.remove-avatar { justify-self: center; }
</style>
