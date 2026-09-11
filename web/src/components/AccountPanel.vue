<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { t } from '../ui/i18n'
import { AuthError, changePassword, MinPassword, setRecovery } from '../api/auth'
import { credential, recoverySet, rotateCredential, state } from '../state/archive'
import { loadWorkspaceContext, saveUserProfile, workspaceState } from '../state/workspaces'
import { workspaceAvatar } from '../ui/workspaceAvatar'
import { initials } from '../state/jid'
import PasswordInput from './PasswordInput.vue'
import PasskeyPanel from './PasskeyPanel.vue'
import ConsoleDialog from './ConsoleDialog.vue'
import AppIcon from './AppIcon.vue'
const name = ref(''), avatar = ref(''), profileBusy = ref(false), profileError = ref(''), profileDone = ref('')
const profileChanged = computed(() => name.value.trim() !== (workspaceState.profile?.name ?? '') || avatar.value !== (workspaceState.profile?.avatar ?? ''))
watch(() => workspaceState.profile, profile => { name.value = profile?.name ?? ''; avatar.value = profile?.avatar ?? '' }, { immediate:true })
onMounted(() => { void loadWorkspaceContext() })
async function chooseAvatar(event: Event) {
  const input = event.target as HTMLInputElement, file = input.files?.[0]
  if (!file || profileBusy.value) return
  profileBusy.value = true; profileError.value = ''; profileDone.value = ''
  try { avatar.value = await workspaceAvatar(file) } catch(e) { profileError.value = describe(e) }
  finally { profileBusy.value = false; input.value = '' }
}
async function saveProfile() {
  if (profileBusy.value || !profileChanged.value) return
  profileBusy.value = true; profileError.value = ''; profileDone.value = ''
  try { await saveUserProfile(name.value.trim(),avatar.value); profileDone.value = t('Perfil atualizado.') }
  catch(e) { profileError.value = describe(e) } finally { profileBusy.value = false }
}
const current = ref(''), next = ref(''), confirm = ref(''), forCode = ref('')
const busy = ref(false), error = ref(''), done = ref(''), modal = ref<'password' | 'recovery' | null>(null)
const recoveryCode = ref(''), acknowledged = ref(false)
function describe(err: unknown): string { return err instanceof AuthError || err instanceof Error ? err.message : String(err) }
function open(kind:'password'|'recovery') { modal.value = kind; error.value = ''; done.value = ''; current.value = ''; next.value = ''; confirm.value = ''; forCode.value = '' }
function close() {
  if (busy.value || (recoveryCode.value && !acknowledged.value)) return
  modal.value = null; current.value = ''; next.value = ''; confirm.value = ''; forCode.value = ''; recoveryCode.value = ''
}
async function rotatePassword(event: SubmitEvent) {
  if (busy.value) return
  const fields = new FormData(event.currentTarget as HTMLFormElement)
  current.value = String(fields.get('password') ?? ''); next.value = String(fields.get('new-password') ?? ''); confirm.value = String(fields.get('confirm-password') ?? '')
  const cred = credential(); if (!cred) return
  error.value = ''; done.value = ''
  if (next.value !== confirm.value) { error.value = t('as senhas não conferem'); return }
  busy.value = true
  try {
    const fresh = await changePassword({serverURL:cred.serverURL,token:cred.token,email:state.account,current:current.value,next:next.value})
    await rotateCredential(fresh.token,fresh.expiresAt)
    current.value = ''; next.value = ''; confirm.value = ''; modal.value = null
    done.value = t('Senha trocada. Toda outra sessão desta conta foi encerrada.')
  } catch(e) { error.value = describe(e) } finally { busy.value = false }
}
async function generateCode(event: SubmitEvent) {
  if (busy.value) return
  forCode.value = String(new FormData(event.currentTarget as HTMLFormElement).get('password') ?? '')
  const cred = credential(); if (!cred) return
  error.value = ''; done.value = ''; busy.value = true
  try { recoveryCode.value = await setRecovery({serverURL:cred.serverURL,token:cred.token,email:state.account,password:forCode.value}); forCode.value = ''; acknowledged.value = false; recoverySet() }
  catch(e) { error.value = describe(e) } finally { busy.value = false }
}
async function copyCode() { try { await navigator.clipboard.writeText(recoveryCode.value) } catch { /* The visible code remains selectable. */ } }
</script>
<template>
  <section class="console-panel account-settings" v-if="state.account">
    <header><h2>{{ t('Minha conta') }}</h2><p class="dim">{{ t('Seu perfil e suas formas de acesso, em todos os workspaces.') }}</p></header>
    <form class="account-profile" @submit.prevent="saveProfile">
      <div class="avatar-column"><label class="account-avatar" :aria-label="t('Alterar sua foto')"><img v-if="avatar" :src="avatar" alt="" /><span v-else>{{ initials(name || state.account) }}</span><span class="avatar-edit"><AppIcon name="pencil" :size="16" /></span><input type="file" accept="image/jpeg,image/png,image/webp" :disabled="profileBusy" @change="chooseAvatar" /></label><button v-if="avatar" class="ghost small" type="button" :disabled="profileBusy" @click="avatar = ''">{{ t('Remover foto') }}</button></div>
      <div class="profile-fields"><label>{{ t('Seu nome') }}<input v-model="name" maxlength="80" autocomplete="name" :disabled="profileBusy" required /></label><div class="profile-email"><span>{{ t('Email') }}</span><strong>{{ workspaceState.profile?.email || state.account }}</strong></div><button class="primary small" :disabled="profileBusy || !profileChanged || !name.trim()">{{ profileBusy ? t('Salvando…') : t('Salvar perfil') }}</button></div>
    </form>
    <p v-if="profileError || workspaceState.error" class="alert" role="alert">{{ profileError || workspaceState.error }}</p><p v-if="profileDone || done" class="account-success" role="status">{{ profileDone || done }}</p>
    <div class="security-options"><button class="security-summary" type="button" aria-haspopup="dialog" @click="open('password')"><span class="summary-icon"><AppIcon name="shield" :size="22" /></span><span class="summary-text"><strong>{{ t('Senha') }}</strong><small>{{ t('Trocar sua senha de acesso') }}</small></span><AppIcon name="chevron-down" :size="18" /></button>
      <PasskeyPanel />
      <button class="security-summary" type="button" aria-haspopup="dialog" @click="open('recovery')"><span class="summary-icon"><AppIcon name="key" :size="22" /></span><span class="summary-text"><strong>{{ t('Chave de recuperação') }}</strong><small>{{ state.hasRecovery ? t('Proteção ativada · gerar uma nova chave') : t('Adicione uma forma de recuperar sua conta') }}</small></span><AppIcon name="chevron-down" :size="18" /></button>
    </div>
    <ConsoleDialog v-if="modal" :title="modal === 'password' ? t('Trocar senha') : t('Chave de recuperação')" :busy="busy || (!!recoveryCode && !acknowledged)" @close="close">
      <p v-if="error" class="alert" role="alert">{{ error }}</p>
      <form v-if="modal === 'password'" class="form-stack" name="wappie-password-change" method="post" autocomplete="on" @submit.prevent="rotatePassword">
        <p class="dim">{{ t('Use pelo menos {v0} caracteres. Ao trocar a senha, suas outras sessões serão encerradas. As passkeys cadastradas continuam válidas.', {v0:MinPassword}) }}</p>
        <input name="username" :value="state.account" type="email" autocomplete="username" class="account-identifier" readonly tabindex="-1" aria-hidden="true" />
        <label for="current-password">{{ t('Senha atual') }}<PasswordInput id="current-password" name="password" v-model="current" required autocomplete="current-password" :disabled="busy" /></label><label for="new-password">{{ t('Nova senha') }}<PasswordInput id="new-password" name="new-password" v-model="next" required :minlength="MinPassword" autocomplete="new-password" :disabled="busy" /></label><label for="confirm-password">{{ t('Repita a nova senha') }}<PasswordInput id="confirm-password" name="confirm-password" v-model="confirm" required autocomplete="new-password" :disabled="busy" /></label><div class="dialog-actions"><button class="ghost" type="button" :disabled="busy" @click="close">{{ t('Cancelar') }}</button><button class="primary" :disabled="busy">{{ busy ? t('Atualizando…') : t('Atualizar senha') }}</button></div>
      </form>
      <div v-else-if="recoveryCode" class="form-stack"><p>{{ t('Anote este código. Ele não será mostrado novamente.') }}</p><code class="recovery-secret">{{ recoveryCode }}</code><button class="ghost" type="button" @click="copyCode">{{ t('Copiar') }}</button><label class="acknowledge"><input type="checkbox" v-model="acknowledged" /><span>{{ t('Anotei em um lugar seguro') }}</span></label><div class="dialog-actions"><button class="primary" type="button" :disabled="!acknowledged" @click="close">{{ t('Concluir') }}</button></div></div>
      <form v-else class="form-stack" name="wappie-recovery" method="post" autocomplete="on" @submit.prevent="generateCode"><p class="dim">{{ t('Uma forma de recuperar o acesso caso você perca sua senha e suas passkeys. Guarde-o em um lugar seguro.') }}</p><p v-if="state.hasRecovery" class="dim">{{ t('Ao gerar uma nova chave, a anterior deixa de funcionar.') }}</p><input name="username" :value="state.account" type="email" autocomplete="username" class="account-identifier" readonly tabindex="-1" aria-hidden="true" /><label for="recovery-password">{{ t('Confirme sua senha atual') }}<PasswordInput id="recovery-password" name="password" v-model="forCode" required autocomplete="current-password" :disabled="busy" /></label><div class="dialog-actions"><button class="ghost" type="button" :disabled="busy" @click="close">{{ t('Cancelar') }}</button><button class="primary" :disabled="busy">{{ busy ? t('Aguarde…') : state.hasRecovery ? t('Gerar nova chave') : t('Gerar chave de recuperação') }}</button></div></form>
    </ConsoleDialog>
  </section>
</template>
<style scoped>
.account-settings { display:grid;gap:24px;max-width:850px; }.account-settings h2 { margin:0 0 8px; }.account-profile { display:flex;align-items:flex-start;gap:26px;padding:24px;border:1px solid var(--line);border-radius:16px;background:var(--bg-raised); }.avatar-column { flex:none;display:grid;gap:7px;justify-items:center; }.account-avatar { position:relative;width:92px;height:92px;border-radius:50%;cursor:pointer;display:grid;place-items:center;background:var(--accent-dim);color:var(--accent);font-size:27px;font-weight:600; }.account-avatar img { width:100%;height:100%;object-fit:cover;border-radius:inherit; }.account-avatar input { position:absolute;inset:0;opacity:0;cursor:pointer; }.avatar-edit { position:absolute;right:0;bottom:0;width:30px;height:30px;display:grid;place-items:center;background:var(--bg-panel);border:1px solid var(--line);border-radius:50%; }.profile-fields { display:grid;gap:18px;flex:1;min-width:0; }.profile-fields label { display:grid;gap:8px;font-size:12px; }.profile-email { display:grid;gap:7px; }.profile-email span { font-size:12px;color:var(--text-dim); }.profile-email strong { font-size:14px;font-weight:500;overflow-wrap:anywhere; }.profile-fields>button { justify-self:start; }.security-options { display:grid;gap:12px; }.security-summary { display:flex;align-items:center;gap:14px;width:100%;padding:18px;text-align:left;border:1px solid var(--line);border-radius:14px;background:var(--bg-panel); }.security-summary:hover { background:var(--bg-hover); }.summary-icon { display:grid;place-items:center;flex:none;width:42px;height:42px;border-radius:12px;color:var(--accent);background:var(--accent-dim); }.summary-text { flex:1;min-width:0; }.summary-text strong { display:block;font-size:14px; }.summary-text small { display:block;font-size:12px;color:var(--text-dim);margin-top:5px;line-height:1.5; }.account-success { color:var(--accent);font-size:13px; }.account-identifier { position:absolute !important;width:1px !important;height:1px !important;min-height:0 !important;opacity:0;pointer-events:none;padding:0 !important;border:0 !important; }.recovery-secret { display:block;overflow-wrap:anywhere;padding:18px;background:var(--bg-raised);border:1px solid var(--line);border-radius:12px;line-height:1.8;user-select:text; }.acknowledge { display:flex;align-items:center;gap:10px;font-size:13px; }.acknowledge input { width:18px;height:18px; }
@media(max-width:600px) { .account-profile { flex-direction:column;align-items:stretch;padding:18px;gap:20px; }.avatar-column { justify-self:center; }.profile-fields>button { width:100%; }.security-summary { padding:15px; } }
</style>
