<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { t, intlLocale } from '../ui/i18n'
import { initials } from '../state/jid'
import { workspaceRequest, type Member, type Invitation } from '../api/workspaces'
import { state } from '../state/archive'
import { currentWorkspace, loadWorkspaceContext, loadWorkspaceMembers, workspaceChanged, workspaceState } from '../state/workspaces'
import { admin, loadKeys, openDetail } from '../state/admin'
import AppIcon from './AppIcon.vue'
import ConsoleDialog from './ConsoleDialog.vue'
const members = ref<Member[]>([]), invites = ref<Invitation[]>([])
const email = ref(''), role = ref('member'), inviting = ref(false), busy = ref(false), error = ref(''), notice = ref('')
const originals = ref<Record<string, {role: string; status: string}>>({})
const shownCode = ref<{ code: string; invitation?: Invitation; emailSent?: boolean } | null>(null), revoking = ref<Invitation | null>(null)
const removing = ref<Member | null>(null)
const showHistory = ref(false), guide = ref(false)
const manager = computed(() => ['owner', 'admin'].includes(state.role))
const isTeam = computed(() => currentWorkspace.value?.kind !== 'personal')
const roles = computed(() => state.role === 'owner' ? ['member', 'admin', 'owner'] : ['member'])
const labels: Record<string,string> = {owner:'Proprietário',admin:'Administrador',member:'Membro',service:'Integração'}
const pending = computed(() => invites.value.filter(invitation => ['pending', 'expired'].includes(invitation.status)))
const history = computed(() => invites.value.filter(invitation => ['accepted', 'revoked'].includes(invitation.status)))
const inviteLink = computed(() => {
  if (!shownCode.value) return ''
  const url = new URL('/console?signup=1',location.origin)
  const fragment = new URLSearchParams({invite:shownCode.value.code})
  if (shownCode.value.invitation?.email) fragment.set('email',shownCode.value.invitation.email)
  url.hash = fragment.toString(); return url.toString()
})
let generation = 0
function roleLabel(value: string) { return t(labels[value] ?? value) }
function date(value: string) { return new Date(value).toLocaleString(intlLocale(), { dateStyle: 'short', timeStyle: 'short' }) }
function status(value: Invitation['status']) { return t({pending:'Pendente',expired:'Expirado',accepted:'Aceito',revoked:'Revogado'}[value]) }
function canEdit(member: Member) {
  const original = originals.value[member.id]
  return !member.last_owner && !!original && member.role !== 'service' && (state.role === 'owner' || !['owner','admin'].includes(original.role))
}
function canRemove(member: Member) {
  const original = originals.value[member.id]
  // The role selector may contain an unsaved change; authority comes from the
  // persisted role. Leaving one's own workspace is a separate account action.
  if (!original || member.last_owner || member.id === workspaceState.profile?.id || member.email.toLowerCase() === state.account.toLowerCase()) return false
  return state.role === 'owner' || (state.role === 'admin' && ['member', 'service'].includes(original.role))
}
function askRemove(member: Member) {
  if (busy.value || !canRemove(member)) return
  removing.value = { ...member, ...originals.value[member.id] }; error.value = ''; notice.value = ''
}
function cancelRemove() { if (!busy.value) { removing.value = null; error.value = '' } }
async function removeMember() {
  const member = removing.value
  if (!member || !canRemove(member)) return
  const current = generation
  await run(async () => {
    await workspaceRequest(`/members/${encodeURIComponent(member.id)}`, 'DELETE')
    if (current !== generation || removing.value?.id !== member.id) return
    removing.value = null
    members.value = members.value.filter(person => person.id !== member.id)
    workspaceState.members = workspaceState.members.filter(person => person.id !== member.id)
    admin.accounts = admin.accounts.filter(person => person.id !== member.id)
    if (admin.detail) admin.detail.readers = admin.detail.readers.filter(person => person.user_id !== member.id)
    delete originals.value[member.id]
    notice.value = t('{name} foi removido deste workspace.', {name:member.name || member.email})
    // The deletion has succeeded. A failed refresh must not turn it back into
    // a destructive retry; the local row is already gone.
    workspaceChanged()
    void loadKeys()
  })
}
function changed(member: Member) { const old = originals.value[member.id]; return !!old && (old.role !== member.role || old.status !== member.status) }
async function load() {
  const current = ++generation
  error.value = ''; busy.value = true
  try {
    await loadWorkspaceContext()
    if (current !== generation || !manager.value) return
    const replies = await Promise.all([loadWorkspaceMembers(), isTeam.value ? workspaceRequest<{invites: Invitation[]}>('/invites') : Promise.resolve({invites: []})])
    if (current !== generation) return
    members.value = replies[0].map(member => ({...member}))
    originals.value = Object.fromEntries(members.value.map(member => [member.id, {role:member.role,status:member.status}]))
    invites.value = replies[1].invites ?? []
  } catch(e) { if (current === generation) error.value = e instanceof Error ? e.message : String(e) }
  finally { if (current === generation) busy.value = false }
}
async function run(action: () => Promise<void>) {
  if (busy.value) return
  const current = generation
  busy.value = true; error.value = ''; notice.value = ''
  try { await action() } catch(e) { if (current === generation) error.value = e instanceof Error ? e.message : String(e) }
  finally { if (current === generation) busy.value = false }
}
async function update(member: Member) {
  if (!canEdit(member) || !changed(member)) return
  await run(async () => {
    await workspaceRequest(`/members/${member.id}`, 'PUT', {role:member.role,status:member.status})
    notice.value = t('Acesso atualizado. Sessões anteriores deste membro foram encerradas.')
    workspaceChanged()
  })
}
async function invite() {
  await run(async () => {
    const result = await workspaceRequest<{invite:string; invitation:Invitation; email_sent?:boolean}>('/invites', 'POST', {email:email.value.trim(),role:role.value})
    inviting.value = false; shownCode.value = { code:result.invite, invitation:result.invitation, emailSent:result.email_sent === true }; email.value = ''
    workspaceChanged()
  })
}
async function reveal(invitation: Invitation) {
  await run(async () => { const result = await workspaceRequest<{invite:string}>(`/invites/${invitation.id}/reveal`, 'POST'); shownCode.value = {code:result.invite,invitation} })
}
async function regenerate(invitation: Invitation) {
  await run(async () => {
    const result = await workspaceRequest<{invite:string;invitation:Invitation; email_sent?:boolean}>(`/invites/${invitation.id}/regenerate`, 'POST')
    shownCode.value = {code:result.invite,invitation:result.invitation,emailSent:result.email_sent === true}; workspaceChanged()
  })
}
async function revoke() {
  if (!revoking.value) return
  const invitation = revoking.value
  await run(async () => { await workspaceRequest(`/invites/${invitation.id}`, 'DELETE'); revoking.value = null; workspaceChanged() })
}
async function copy(value: string) {
  try { await navigator.clipboard.writeText(value); notice.value = t('Copiado.'); }
  catch { notice.value = t('Selecione e copie o código exibido.'); }
}
watch([() => state.tenantID, () => state.account], () => {
  generation++; removing.value = null; members.value = []; originals.value = {}; notice.value = ''; error.value = ''
}, { flush:'sync' })
watch([() => state.tenantID, () => state.account, () => workspaceState.revision], () => { void load() }, { immediate:true })
onBeforeUnmount(() => { generation++ })
</script>
<template>
  <section v-if="manager" class="console-panel members-panel">
    <header class="members-heading"><div><h2>{{ t('Membros') }}</h2><p class="dim">{{ t('Pessoas, convites e acesso aos números deste workspace.') }}</p></div><button v-if="isTeam" class="primary" type="button" @click="inviting = true; error = ''"><AppIcon name="plus" :size="18" />{{ t('Convidar pessoa') }}</button></header>
    <p v-if="error && !inviting && !revoking && !removing" class="alert" role="alert">{{ error }} <button class="ghost small" :disabled="busy" @click="load">{{ t('Tentar novamente') }}</button></p><p v-if="notice" class="member-notice" role="status">{{ notice }}</p>
    <p v-if="!isTeam" class="dim">{{ t('O workspace pessoal é exclusivo da sua conta. Crie um workspace Team para convidar pessoas.') }}</p>
    <button class="role-help" type="button" :aria-expanded="guide" @click="guide = !guide"><AppIcon name="info" :size="17" />{{ t('Entenda os papéis e acessos') }}<AppIcon :name="guide ? 'chevron-up' : 'chevron-down'" :size="15" /></button>
    <div v-if="guide" class="role-guide"><p><strong>{{ t('Proprietário') }}</strong>{{ t('Controla o workspace, a assinatura e os administradores. Sempre é necessário manter um proprietário ativo.') }}</p><p><strong>{{ t('Administrador') }}</strong>{{ t('Gerencia números, membros e integrações. Não altera proprietários nem outros administradores.') }}</p><p><strong>{{ t('Membro') }}</strong>{{ t('Usa somente os números e recursos que foram liberados. A leitura exige uma chave de acesso.') }}</p></div>
    <div class="member-list" :aria-busy="busy">
      <article v-for="member in members" :key="member.id" class="member-row" :class="{'member-disabled':member.status !== 'active'}">
        <div class="member-identity"><img v-if="member.avatar" :src="member.avatar" alt="" /><span v-else class="person-initials">{{ initials(member.name || member.email) }}</span><div><strong>{{ member.name || member.email }}</strong><small>{{ member.email }}</small><span v-if="member.last_owner" class="owner-note">{{ t('Único proprietário ativo') }}</span></div></div>
        <div class="member-devices"><span class="field-caption">{{ t('Números com chave') }}</span><div class="device-chips"><button v-for="device in (member.device_access || []).filter(access => access.has_key)" :key="device.device_id" type="button" class="device-chip" @click="openDetail(device.device_id)"><AppIcon name="devices" :size="13" />{{ device.label || device.pn?.split('@')[0] || device.device_id.slice(0,8) }}</button><span v-if="!(member.device_access || []).some(access => access.has_key)" class="dim">{{ t('Nenhum número') }}</span></div></div>
        <div class="member-controls"><label><span>{{ t('Papel') }}</span><select v-model="member.role" :disabled="busy || !canEdit(member)" :aria-label="t('Papel de {name}',{name:member.name || member.email})"><option v-if="member.role === 'service'" value="service">{{ t('Integração') }}</option><option v-for="value in ['member','admin','owner']" :key="value" :value="value" :disabled="!roles.includes(value)">{{ roleLabel(value) }}</option></select></label><label><span>{{ t('Status') }}</span><select v-model="member.status" :disabled="busy || !canEdit(member)" :aria-label="t('Acesso de {name}',{name:member.name || member.email})"><option value="active">{{ t('Ativo') }}</option><option value="disabled">{{ t('Desativado') }}</option></select></label><div class="member-row-actions"><button class="ghost small" type="button" :disabled="busy || !canEdit(member) || !changed(member)" @click="update(member)">{{ t('Salvar') }}</button><button v-if="canRemove(member)" class="ghost small remove-member" type="button" :disabled="busy" :aria-label="t('Remover {name} do workspace',{name:member.name || member.email})" @click="askRemove(member)"><AppIcon name="trash" :size="15" />{{ t('Remover membro') }}</button></div></div>
      </article>
      <article v-for="invitation in pending" :key="invitation.id" class="member-row pending-row"><div class="member-identity"><span class="person-initials"><AppIcon name="users" :size="21" /></span><div><strong>{{ invitation.email }}</strong><small>{{ roleLabel(invitation.role) }} · {{ t('Convite') }}</small></div></div><div class="invite-status"><span class="status-pill" :class="invitation.status">{{ status(invitation.status) }}</span><small>{{ t('Expira em {date}',{date:date(invitation.expires_at)}) }}</small></div><div class="invite-actions"><button v-if="invitation.status === 'pending' && invitation.can_reveal" type="button" class="ghost small" :disabled="busy" @click="reveal(invitation)"><AppIcon name="key" :size="15" />{{ t('Ver convite') }}</button><button v-if="invitation.status === 'expired' || !invitation.can_reveal" type="button" class="ghost small" :disabled="busy" @click="regenerate(invitation)">{{ t('Gerar novo convite') }}</button><button type="button" class="ghost small revoke-invite" :disabled="busy" @click="revoking = invitation; error = ''">{{ t('Revogar') }}</button></div></article>
      <p v-if="!members.length && !pending.length" class="dim empty-members">{{ busy ? t('Carregando membros…') : t('Nenhum membro encontrado.') }}</p>
    </div>
    <details v-if="history.length" class="invite-history" :open="showHistory" @toggle="showHistory = ($event.target as HTMLDetailsElement).open"><summary>{{ t('Histórico de convites') }} <span>{{ history.length }}</span></summary><div v-for="invitation in history" :key="invitation.id"><span>{{ invitation.email }}<small>{{ date(invitation.completed_at || invitation.revoked_at || invitation.created_at) }}</small></span><span class="status-pill">{{ status(invitation.status) }}</span></div></details>
    <ConsoleDialog v-if="inviting" :title="t('Convidar pessoa')" :busy="busy" @close="inviting = false"><form class="form-stack" @submit.prevent="invite"><p v-if="error" class="alert" role="alert">{{ error }}</p><p class="dim">{{ t('A pessoa entra com este email. Se ainda não tiver uma conta, poderá criá-la e receberá também um workspace pessoal.') }}</p><label>{{ t('Email') }}<input v-model="email" type="email" required autocomplete="email" :disabled="busy" /></label><label>{{ t('Papel') }}<select v-model="role" :disabled="busy"><option v-for="value in roles" :key="value" :value="value">{{ roleLabel(value) }}</option></select></label><p class="dim">{{ t('O convite poderá ser usado uma vez e será válido por sete dias.') }}</p><div class="dialog-actions"><button class="ghost" type="button" :disabled="busy" @click="inviting = false">{{ t('Cancelar') }}</button><button class="primary" :disabled="busy">{{ busy ? t('Aguarde…') : t('Criar convite') }}</button></div></form></ConsoleDialog>
    <ConsoleDialog v-if="shownCode" :title="t('Convite do workspace')" @close="shownCode = null"><div class="form-stack"><p class="dim">{{ shownCode.invitation?.email }}<br v-if="shownCode.invitation" />{{ shownCode.invitation ? t('Expira em {date}',{date:date(shownCode.invitation.expires_at)}) : '' }}</p><p v-if="shownCode.emailSent !== undefined" class="dim">{{ shownCode.emailSent ? t('Convite enviado por email. Você também pode compartilhar o link.') : t('O email não foi enviado. Copie o link ou o código e compartilhe com a pessoa convidada.') }}</p><label>{{ t('Código de convite') }}<input :value="shownCode.code" readonly @focus="($event.target as HTMLInputElement).select()" /></label><div class="dialog-actions"><button type="button" class="ghost" @click="copy(shownCode.code)"><AppIcon name="copy" :size="16" /> {{ t('Copiar código') }}</button><button type="button" class="primary" @click="copy(inviteLink)">{{ t('Copiar link') }}</button></div><p v-if="notice" class="dim" role="status">{{ notice }}</p></div></ConsoleDialog>
    <ConsoleDialog v-if="revoking" :title="t('Revogar convite')" :busy="busy" @close="revoking = null"><form class="form-stack" @submit.prevent="revoke"><p v-if="error" class="alert" role="alert">{{ error }}</p><p>{{ t('O convite para {email} deixará de funcionar.',{email:revoking.email}) }}</p><div class="dialog-actions"><button class="ghost" type="button" :disabled="busy" @click="revoking = null">{{ t('Cancelar') }}</button><button class="danger" :disabled="busy">{{ t('Revogar convite') }}</button></div></form></ConsoleDialog>
    <ConsoleDialog v-if="removing" :title="t('Remover membro')" :subtitle="currentWorkspace?.name" :busy="busy" @close="cancelRemove"><form class="form-stack member-removal" @submit.prevent="removeMember"><div class="member-identity"><img v-if="removing.avatar" :src="removing.avatar" alt="" /><span v-else class="person-initials">{{ initials(removing.name || removing.email) }}</span><div><strong>{{ removing.name || removing.email }}</strong><small>{{ removing.email }}</small></div></div><p v-if="error" class="alert" role="alert">{{ error }}</p><p>{{ t('Esta pessoa perderá o acesso a este workspace, incluindo as chaves dos números, sessões e tokens associados.') }}</p><p class="dim">{{ t('A conta, o workspace pessoal, os outros workspaces e o histórico de mensagens serão preservados.') }}</p><p class="dim">{{ t('Para voltar, será necessário um novo convite e liberar novamente o acesso aos números. Os convites pendentes enviados ou recebidos por este membro neste workspace serão revogados.') }}</p><div class="dialog-actions"><button class="ghost" type="button" :disabled="busy" @click="cancelRemove">{{ t('Cancelar') }}</button><button class="danger confirm-remove-member" type="submit" :disabled="busy">{{ busy ? t('Removendo…') : t('Remover do workspace') }}</button></div></form></ConsoleDialog>
  </section>
</template>
<style scoped>
.members-panel { display:grid;gap:20px; }.members-heading { display:flex;gap:14px;align-items:center;justify-content:space-between; }.members-heading h2 { margin:0 0 6px; }.members-heading button { display:flex;gap:7px;align-items:center;flex:none; }.role-help { display:flex;gap:7px;align-items:center;justify-self:start;color:var(--text-dim);font-size:12px; }.role-guide { display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;padding:16px;background:var(--bg-hover);border-radius:12px; }.role-guide p { font-size:12px;color:var(--text-dim); }.role-guide strong { display:block;color:var(--text);margin-bottom:7px; }.member-list { border:1px solid var(--line);border-radius:14px;overflow:hidden; }.member-row { display:grid;grid-template-columns:minmax(200px,1.2fr) minmax(150px,1fr);gap:18px;padding:20px;border-bottom:1px solid var(--line); }.member-row:last-child { border-bottom:0; }.member-identity { display:flex;gap:12px;align-items:center;min-width:0; }.member-identity>div { min-width:0; }.member-identity img,.person-initials { width:42px;height:42px;border-radius:50%;object-fit:cover;flex:none; }.person-initials { display:grid;place-items:center;color:var(--accent);background:var(--accent-dim);font-weight:600; }.member-identity strong { display:block;font-size:14px;overflow-wrap:anywhere; }.member-identity small,.owner-note { display:block;color:var(--text-dim);font-size:11px;line-height:1.4;margin-top:4px; }.owner-note { color:var(--accent); }.member-devices { min-width:0; }.field-caption { display:block;color:var(--text-dim);font-size:10px;margin-bottom:7px; }.device-chips { display:flex;flex-wrap:wrap;gap:5px; }.device-chip { display:flex;gap:5px;align-items:center;border:1px solid var(--line);border-radius:7px;padding:5px 7px;color:var(--text);background:var(--bg-raised);font-size:11px;max-width:100%;overflow-wrap:anywhere; }.device-chip:hover { background:var(--bg-hover); }.member-controls { grid-column:1/-1;display:flex;gap:10px;align-items:end; }.member-controls label { display:grid;gap:6px;flex:1;max-width:185px; }.member-controls label span { font-size:10px;color:var(--text-dim); }.member-controls select { width:100%; }.member-disabled .member-identity { opacity:.65; }.invite-status { display:flex;gap:8px;align-items:flex-start;justify-content:center;flex-direction:column; }.invite-status small { font-size:11px;color:var(--text-dim); }.status-pill { display:inline-flex;align-self:start;border-radius:99px;padding:4px 8px;font-size:10px;background:var(--bg-hover);color:var(--text-dim); }.status-pill.pending { color:var(--warn);background:color-mix(in srgb,var(--warn) 12%,var(--bg-panel)); }.status-pill.expired { color:var(--danger); }.invite-actions { display:flex;gap:8px;grid-column:1/-1; }.invite-actions button { display:flex;align-items:center;gap:6px; }.revoke-invite { color:var(--danger);margin-left:auto; }.pending-row { background:color-mix(in srgb,var(--bg-hover) 30%,var(--bg-panel)); }.member-notice { color:var(--accent);font-size:13px; }.empty-members { padding:20px; }.invite-history summary { display:flex;gap:8px;align-items:center;color:var(--text-dim);font-size:12px;cursor:pointer; }.invite-history>div { display:flex;justify-content:space-between;gap:10px;padding:13px 0;border-bottom:1px solid var(--line);font-size:12px; }.invite-history small { display:block;color:var(--text-dim);margin-top:4px; }
@media(min-width:1200px) { .member-row { grid-template-columns:minmax(200px,1fr) minmax(150px,1fr) minmax(280px,1fr);align-items:center; }.member-controls,.invite-actions { grid-column:auto; }.member-controls { gap:8px; }.member-controls label { max-width:140px; }.member-controls button { align-self:end; }.invite-actions { justify-content:flex-end; }.revoke-invite { margin:0; } }
@media(max-width:760px) { .members-heading { align-items:flex-start;flex-wrap:wrap; }.role-guide { grid-template-columns:1fr; }.member-row { grid-template-columns:1fr;padding:16px;gap:14px; }.member-controls { gap:8px;flex-wrap:wrap; }.member-controls label { max-width:none;min-width:110px; }.member-controls button { width:100%; }.member-devices { padding-left:54px; }.invite-actions { grid-column:auto;flex-wrap:wrap; }.invite-status { padding-left:54px; }.device-chip { min-height:34px; } }
.member-controls { flex-wrap:wrap; }.member-row-actions { display:flex;flex-basis:100%;gap:8px;align-items:center;justify-content:space-between; }.member-row-actions button { min-height:36px; }.member-row-actions .remove-member { display:flex;align-items:center;justify-content:center;gap:6px;color:var(--danger);margin-left:auto; }.member-removal>p { margin:0;font-size:13px;line-height:1.55; }.member-removal .member-identity { padding:14px;background:var(--bg-hover);border:1px solid var(--line);border-radius:12px; }
@media(max-width:760px) { .member-row-actions { flex-wrap:wrap; }.member-row-actions button { flex:1 1 auto;width:auto;min-height:42px; } }
</style>
